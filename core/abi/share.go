package abi

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	"daal/core/routestore"
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

// ownShareFingerprint is the publisher id of this phone's own sharing
// identity (the one pasted links are signed with), or "" when the phone
// has none yet. Read only: it never creates the identity.
func ownShareFingerprint(c *Core) string {
	globalShare.mu.Lock()
	pub := globalShare.identity.PublicKey
	globalShare.mu.Unlock()
	if len(pub) == 0 {
		body, err := c.store.GetSecret("share/identity:v1")
		if err != nil || len(body) == 0 {
			return ""
		}
		var s storedIdentity
		if json.Unmarshal(body, &s) != nil {
			return ""
		}
		pub, _ = base64.StdEncoding.DecodeString(s.PubB64)
		if len(pub) == 0 {
			return ""
		}
	}
	return bundle.PublisherFingerprint(pub).Hex
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
	if done && isSealedFile(decoded) {
		// A per-person file (.sbpx) is sealed to ONE phone's key and is
		// not a bundle the importer can read. The engine has no access
		// to the phone's recipient key, so it hands the bytes back and
		// the shell unseals them and runs the normal import, which
		// checks the signature, revocation and expiry as for any file.
		// No verdict here: a "bundle_corrupted" verdict for a perfectly
		// good sealed file is what this branch exists to stop.
		resp["sealed_b64"] = base64.StdEncoding.EncodeToString(decoded)
		out, _ := json.Marshal(resp)
		return string(out), nil
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

// sealedFileMagic opens every per-person sealed file (.sbpx); the
// shell's recipient_sbpx::SBPX_MAGIC is the same six bytes.
var sealedFileMagic = []byte{'D', 'S', 'B', 'P', 0x00, 0x01}

func isSealedFile(b []byte) bool {
	return len(b) >= len(sealedFileMagic) && string(b[:len(sealedFileMagic)]) == string(sealedFileMagic)
}

// URIDetect is engine_uri_detect.
func URIDetect(text string) (string, error) {
	hits := share.DetectURIs(text)
	out, _ := json.Marshal(map[string]any{"hits": hits})
	return string(out), nil
}

// URIImport is engine_uri_import.
//
// Wraps one pasted link (vless://, trojan://, …) or one pasted WireGuard
// conf ("[Interface]" …) in a transient single-route .sbp signed by this
// device's sharing identity, then runs it through the importer. Because
// the source is "pasted by user" rather than a real publisher, the
// trust-prompt UI surfaces a distinct badge ("Pasted by you").
//
// WHAT IS KEPT BESIDE THE ROUTE (routestore RouteMeta, encrypted,
// written BEFORE the import so whichever path finishes it — at once,
// after the trust prompt, after a restart — finds it):
//
//   - manual-only, for every WireGuard conf (plain, or AmneziaWG
//     downgraded to WireGuard: uri.Profile.ManualOnly): an automatic
//     attempt would send a WireGuard handshake, the shape Iran's
//     operators throttle and block, from the person's own address. The
//     automatic connect refuses such a route (chosen_only); the person
//     can still pick it. If the flag cannot be written the paste is
//     refused: it is never stored as an ordinary route.
//   - the link's own name (its #fragment, VMess `ps`), cleaned
//     (routestore.CleanRouteName: no control or bidi characters, at
//     most 48 characters), shown as the route's name instead of a
//     piece of its id. Display only.
//
// An AmneziaWG conf whose server would ignore plain WireGuard is
// refused (transport_unsupported): this build cannot dial it.
func URIImport(rawURI string) (string, error) {
	c := mustCore()
	if err := initShare(c); err != nil {
		return "", err
	}
	prof, prov, err := parsePasted(rawURI)
	if err != nil {
		return "", err
	}
	if prov.Notice == uri.NoticeAmneziaUnsupported || prof.TransportFamily == "amneziawg" {
		return "", fmt.Errorf("amneziawg: %w", uri.ErrTransportUnsupported)
	}
	manualOnly := prof.ManualOnly || prof.TransportFamily == "wireguard"
	body, err := uri.MarshalOutbound(prof)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	// The id is unique per link: two different links pasted in the same
	// second must not share a route id (routes.route_id is the primary
	// key, and the second would replace the first). The same link
	// twice in one second gets the same id, so it dedupes.
	sum := sha256.Sum256(body)
	routeID := "pasted-" + now.Format("20060102T150405Z") + "-" + hex.EncodeToString(sum[:4])
	_, _ = c.store.PruneRouteMeta(now)
	meta := routestore.RouteMeta{ManualOnly: manualOnly, Name: prof.Tag}
	if err := c.store.PutRouteMeta(routeID, meta, now); err != nil && manualOnly {
		return "", fmt.Errorf("uri import: keep manual-only: %w", err)
	}
	bundleBytes, err := bundleshare.BuildShareBundle([]bundleshare.ExportInput{{
		RouteID:           routeID,
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

// parsePasted reads one pasted item: a WireGuard conf (its first line
// is "[Interface]", in any case) through uri.ParseAny, anything else as
// one link through uri.ParseURI. A conf must hold exactly one route.
func parsePasted(raw string) (uri.Profile, uri.Provenance, error) {
	text := strings.TrimSpace(raw)
	if looksLikeWireGuardConf(text) {
		profs, prov, err := uri.ParseAny([]byte(text), "wireguard")
		if err != nil {
			// The conf parser's own errors carry no refusal token and
			// can quote a value of the conf; the host gets the class
			// only.
			if uri.RefusalCode(err) == "" {
				err = fmt.Errorf("wireguard: conf: %w", uri.ErrMalformed)
			}
			return uri.Profile{}, prov, err
		}
		if len(profs) != 1 {
			return uri.Profile{}, prov, fmt.Errorf("wireguard: %d routes in one conf: %w", len(profs), uri.ErrMalformed)
		}
		return profs[0], prov, nil
	}
	return uri.ParseURI(text)
}

// looksLikeWireGuardConf: the text opens with an [Interface] section
// (comment lines before it allowed), as wg-quick and AmneziaVPN write it.
func looksLikeWireGuardConf(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		return strings.EqualFold(line, "[Interface]")
	}
	return false
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
