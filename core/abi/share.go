package abi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"daal/bundle-go/bundle"
	"daal/bundle-go/importer"
	"daal/bundle-go/publisher"
	bundleshare "daal/bundle-go/share"
	"daal/bundle-go/uri"
	"daal/core/pathmanager"
	"daal/core/share"
)

// shareState lives on Core; init lazily because the manager needs an
// identity, which we generate (and persist) on first use.
type shareState struct {
	mu       sync.Mutex
	manager  *share.Manager
	fountain map[string]*share.FountainSession
	identity bundleshare.PublisherIdentity
}

var globalShare = &shareState{
	fountain: map[string]*share.FountainSession{},
}

// resetShareForShutdown clears the cached share manager.
func resetShareForShutdown() {
	globalShare.mu.Lock()
	globalShare.manager = nil
	globalShare.fountain = map[string]*share.FountainSession{}
	globalShare.mu.Unlock()
}

// initShare ensures the manager and per-device sharing identity exist.
// The identity (ed25519 keypair) is persisted under secrets_kv key
// "share/identity:v1" so it survives restarts and the publisher fingerprint
// is stable.
func initShare(c *Core) error {
	globalShare.mu.Lock()
	defer globalShare.mu.Unlock()
	if globalShare.manager != nil {
		return nil
	}
	ident, err := loadOrCreateIdentity(c)
	if err != nil {
		return err
	}
	globalShare.identity = ident
	globalShare.manager = share.NewManager(ident, func() time.Time { return time.Now().UTC() })
	return nil
}

func loadOrCreateIdentity(c *Core) (bundleshare.PublisherIdentity, error) {
	const k = "share/identity:v1"
	body, err := c.store.GetSecret(k)
	if err == nil && len(body) > 0 {
		var s storedIdentity
		if err := json.Unmarshal(body, &s); err == nil {
			pub, _ := base64.StdEncoding.DecodeString(s.PubB64)
			priv, _ := base64.StdEncoding.DecodeString(s.PrivB64)
			created, _ := time.Parse(time.RFC3339, s.Created)
			return bundleshare.PublisherIdentity{
				DisplayName: s.Name, PublicKey: pub, PrivateKey: priv,
				TrustClass: "tofu_friend", KeyCreatedAt: created,
			}, nil
		}
	}
	id, err := share.EnsureIdentity("My Daal", time.Now().UTC())
	if err != nil {
		return id, err
	}
	stored := storedIdentity{
		Name:    id.DisplayName,
		PubB64:  base64.StdEncoding.EncodeToString(id.PublicKey),
		PrivB64: base64.StdEncoding.EncodeToString(id.PrivateKey),
		Created: id.KeyCreatedAt.Format(time.RFC3339),
	}
	bs, _ := json.Marshal(stored)
	_ = c.store.PutSecret(k, bs)
	return id, nil
}

type storedIdentity struct {
	Name    string `json:"name"`
	PubB64  string `json:"pub_b64"`
	PrivB64 string `json:"priv_b64"`
	Created string `json:"created"`
}

// ShareBegin is engine_share_begin.
//
// route_ids is a comma-separated list of on-device route IDs. The manager
// pulls each route's encrypted profile from the secrets KV, builds a
// signed .sbp under this device's sharing identity, optionally starts the
// LAN listeners, and returns a JSON descriptor.
func ShareBegin(routeIDsCSV string, includeLAN bool, staticQRURI string) (string, error) {
	c := mustCore()
	if err := initShare(c); err != nil {
		return "", err
	}
	ids := splitCSV(routeIDsCSV)
	if len(ids) == 0 {
		return "", errors.New("share: no route ids")
	}
	var routes []bundleshare.ExportInput
	for _, id := range ids {
		row, err := c.store.GetRoute(id)
		if err != nil {
			return "", fmt.Errorf("share: route %s: %w", id, err)
		}
		profile, err := c.store.GetSecret("route:" + id)
		if err != nil {
			return "", fmt.Errorf("share: load profile %s: %w", id, err)
		}
		validUntil, _ := time.Parse(time.RFC3339, row.ExpiresAt)
		if validUntil.IsZero() {
			validUntil = time.Now().UTC().Add(7 * 24 * time.Hour)
		}
		routes = append(routes, bundleshare.ExportInput{
			RouteID:           row.RouteID,
			TransportFamily:   row.TransportFamily,
			ScarcityClass:     row.ScarcityClass,
			ProfileBytes:      profile,
			ValidFrom:         time.Now().UTC(),
			ValidUntil:        validUntil,
			AllowRedistribute: true, // V1 default; honored upstream by the importer
			// Phase 3F: forward the routestore-persisted
			// (policy, cap) onto the share so the friend's
			// engine sees the publisher's intent on import.
			// The receiver-side default for empty policy is
			// "none" (fail-closed); we forward verbatim.
			RedistributionPolicy: row.RedistributionPolicy,
			RedistributionCap:    row.RedistributionCap,
		})
	}
	sess, err := globalShare.manager.BeginShare(share.BeginInput{
		Routes:      routes,
		StartLAN:    includeLAN,
		StaticQRURI: staticQRURI,
		QRSizePx:    512,
	})
	if err != nil {
		return "", err
	}
	// Spin up a fountain encoder over the bundle, named by session ID.
	globalShare.mu.Lock()
	globalShare.fountain[sess.ID] = share.NewSenderSession(sess.ID, sess.BundleBytes, 256, time.Now().UnixNano())
	globalShare.mu.Unlock()

	resp := map[string]any{
		"session_id":          sess.ID,
		"pin":                 sess.Pin,
		"lan_urls":            sess.LANAddrs,
		"lan_uris":            sess.LANURIs,
		"lan_spki":            sess.LANSPKI,
		"qr_static_png_b64":   base64.StdEncoding.EncodeToString(sess.StaticQRBytes),
		"static_qr_uri":       sess.StaticQRURI,
		"fountain_session_id": sess.ID,
		"bundle_bytes_len":    len(sess.BundleBytes),
		"created_at_bucket":   hourBucket(time.Now().UTC()),
	}
	// Gap 5: announce the offline share onto the posture axis. The
	// transition is legal from NoRoute (offline-share without an
	// active connection) and ImportedActive (sharing while
	// connected); from other postures the transition is illegal and
	// silently ignored.
	if c.pm != nil {
		_ = c.pm.SetPosture(pathmanager.EventOfflineShareStart, pathmanager.PostureOfflineSharing)
	}
	out, _ := json.Marshal(resp)
	return string(out), nil
}

// ShareEnd is engine_share_end.
func ShareEnd(sessionID string) error {
	c := mustCore()
	if err := initShare(c); err != nil {
		return err
	}
	globalShare.mu.Lock()
	delete(globalShare.fountain, sessionID)
	globalShare.mu.Unlock()
	err := globalShare.manager.EndShare(sessionID)
	// Gap 5: announce the share end. From PostureOfflineSharing this
	// goes back to ImportedActive (the table's only outbound edge for
	// EventOfflineShareEnd); from any other posture it's illegal and
	// silently ignored.
	if c.pm != nil {
		_ = c.pm.SetPosture(pathmanager.EventOfflineShareEnd, pathmanager.PostureImportedActive)
	}
	return err
}

// ShareBrowse is engine_share_browse.
//
// The default Phase 1C build does not include a Go-side mDNS browser; the
// Android client uses NsdManager directly. This stub returns an empty list
// so the ABI surface is stable across platforms.
func ShareBrowse(timeoutMs int) (string, error) {
	resp := map[string]any{"services": []any{}}
	out, _ := json.Marshal(resp)
	return string(out), nil
}

// SharePull is engine_share_pull. Receives a bundle from a sender at
// host:port using PIN, then hands the bundle to the importer to produce a
// Verdict.
//
// expectedSPKI is the `spki=` value from the sender's mDNS TXT record. It
// is REQUIRED: an empty pin makes share.PullURL refuse the connection
// rather than fall back to trusting whatever cert answers. A caller that
// browsed a sender but did not read its TXT record has not found a sender
// it can safely talk to, and must not pretend otherwise.
func SharePull(host string, port int, pin, sessionID, expectedSPKI string) (string, error) {
	body, err := share.PullURL(host, port, pin, sessionID, expectedSPKI, 15000)
	if err != nil {
		return "", err
	}
	return importBytesAndPersistPending(body)
}

// SharePullURL is engine_share_pull_url (the QR-encoded fallback for
// mDNS-filtered networks). The pin travels inside the URI — either as the
// `p=` parameter of a `daalshare://lan?...` wrapper or as the `#spki=`
// fragment of a bare https URL — so this path cannot be entered unpinned
// either.
func SharePullURL(shareURI, pin, sessionID string) (string, error) {
	body, err := share.PullArbitraryURL(shareURI, pin, sessionID, 15000)
	if err != nil {
		return "", err
	}
	return importBytesAndPersistPending(body)
}

func importBytesAndPersistPending(body []byte) (string, error) {
	c := mustCore()
	v, err := importer.ImportBytes(body, c.adapter, publisher.DefaultWordlists(), time.Now().UTC())
	if v.Kind == importer.VerdictTrustPromptNeeded {
		c.mu.Lock()
		c.pending[v.Fingerprint] = &pendingPrompt{body: append([]byte(nil), body...)}
		c.mu.Unlock()
		_ = c.persistPendingPrompt(v.Fingerprint, body)
	}
	out, _ := json.Marshal(v)
	return string(out), err
}

// FountainNextFrame is engine_fountain_next_frame.
func FountainNextFrame(sessionID string) (string, error) {
	globalShare.mu.Lock()
	s, ok := globalShare.fountain[sessionID]
	globalShare.mu.Unlock()
	if !ok {
		return "", fmt.Errorf("fountain: unknown session %s", sessionID)
	}
	frame, err := s.NextFrame()
	if err != nil {
		return "", err
	}
	got, total := s.Progress()
	resp := map[string]any{
		"seq":            got,
		"total_estimate": total,
		"frame_b64":      base64.RawURLEncoding.EncodeToString(frame),
	}
	out, _ := json.Marshal(resp)
	return string(out), nil
}

// FountainFeedFrame is engine_fountain_feed_frame.
func FountainFeedFrame(sessionID, frameB64 string) (string, error) {
	globalShare.mu.Lock()
	s, ok := globalShare.fountain[sessionID]
	if !ok {
		s = share.NewReceiverSession(sessionID)
		globalShare.fountain[sessionID] = s
	}
	globalShare.mu.Unlock()
	frame, err := base64.RawURLEncoding.DecodeString(frameB64)
	if err != nil {
		return "", err
	}
	decoded, done, err := s.FeedFrame(frame)
	if err != nil {
		return "", err
	}
	got, total := s.Progress()
	resp := map[string]any{
		"progress":     got,
		"total":        total,
		"done":         done,
		"decoded_size": len(decoded),
	}
	if done {
		v, _ := importer.ImportBytes(decoded, mustCore().adapter, publisher.DefaultWordlists(), time.Now().UTC())
		if v.Kind == importer.VerdictTrustPromptNeeded {
			c := mustCore()
			c.mu.Lock()
			c.pending[v.Fingerprint] = &pendingPrompt{body: append([]byte(nil), decoded...)}
			c.mu.Unlock()
			_ = c.persistPendingPrompt(v.Fingerprint, decoded)
		}
		resp["verdict"] = v
	}
	out, _ := json.Marshal(resp)
	return string(out), nil
}

// URIDetect is engine_uri_detect.
func URIDetect(text string) (string, error) {
	hits := share.DetectURIs(text)
	out, _ := json.Marshal(map[string]any{"hits": hits})
	return string(out), nil
}

// URIImport is engine_uri_import.
//
// Wraps a single URI in a transient single-route .sbp signed by this
// device's sharing identity, then runs it through the importer. Because
// the URI's source is "pasted by user" rather than a real publisher, the
// trust-prompt UI surfaces a distinct badge ("Pasted by you").
func URIImport(rawURI string) (string, error) {
	c := mustCore()
	if err := initShare(c); err != nil {
		return "", err
	}
	prof, _, err := uri.ParseURI(strings.TrimSpace(rawURI))
	if err != nil {
		return "", err
	}
	body, err := uri.MarshalOutbound(prof)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	bundleBytes, err := bundleshare.BuildShareBundle([]bundleshare.ExportInput{{
		RouteID:           "pasted-" + now.Format("20060102T150405Z"),
		TransportFamily:   prof.TransportFamily,
		ScarcityClass:     "normal",
		ProfileBytes:      body,
		ValidFrom:         now,
		ValidUntil:        now.Add(7 * 24 * time.Hour),
		AllowRedistribute: true,
	}}, globalShare.identity, now)
	if err != nil {
		return "", err
	}
	return importBytesAndPersistPending(bundleBytes)
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// hourBucket and bundle imports are referenced for godoc/reachability;
// keep the explicit imports stable.
var _ = bundle.PublisherInfo{}

func hourBucket(t time.Time) string { return t.Truncate(time.Hour).Format("2006-01-02T15:04:05Z") }
