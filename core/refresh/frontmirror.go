// frontmirror.go — the Google update channel on the recipient
// (optional add-on 3; docs/optional-addons-plan.md §3, work item G5;
// specs/relaypack-v1.md "Mirror provider appsscript" and "The
// daal-refresh-v2 container").
//
// An `appsscript` mirror is one slot of an Apps Script web app (one
// script per publisher's Google account, one slot per relay) that
// serves a small container — the signed freshness document, optionally
// the signed credential-less pack it names, optionally a standby key —
// instead of a bare document. This file is everything about it the walk
// needs:
//
//   - WHICH endpoints are Google mirrors: exactly those whose URL has
//     the one shape the spec fixes (an endpoint list carries URLs only,
//     so the shape is the test, never a label);
//   - WHEN they are walked: only by the two unscheduled kinds (the
//     engine's failure walk and the person's button), and only when
//     the walk dials direct — the C0 walk with the tunnel down. "On an
//     ordinary day a recipient's phone never touches the script" (plan
//     §3.1): the scheduled poll and anything riding the tunnel skip it.
//     They come LAST in the walk, after the ordinary mirrors in their
//     random order: a recipient whose ordinary mirrors answer never
//     spends the script's quota, and the name-revealing path is tried
//     only after the quiet ones failed on this network (plan §4);
//   - HOW they are fetched: through the Google front
//     (bootstrap.FetchAppsScript), after a random delay bounded by the
//     walk's own slack (the script's quota is 30 simultaneous
//     executions, and a relay-address block makes a whole publisher's
//     recipients walk at once), with at most two connections;
//   - WHAT is trusted: nothing in the container because of where it
//     came from. A container must name the slot the mirror URL asked
//     for (protocol daal-refresh-v2), so a script that mixed up two
//     relays' texts is "nothing here", not a document to weigh. The freshness document is verified by the very same
//     code as a document from any mirror; the pack is used only when its
//     SHA-256 is the verified document's current_bundle_sha256 and then
//     goes through the same applyBundle gate and importer swap as a
//     downloaded one; the standby key is only OFFERED to the engine's
//     store, which accepts it only if it opens a held route's signed
//     commitment.

package refresh

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"regexp"
	"strings"
	"time"

	"daal/bundle-go/bundle"
	"daal/core/bootstrap"
)

// ProviderAppsScript is the mirror provider label of the Google update
// channel. Mirrors publisher/deploy/freshness.ProviderAppsScript.
const ProviderAppsScript = "appsscript"

// The container, as specs/relaypack-v1.md fixes it. Mirrors
// publisher/deploy/freshness/backends/appsscript/container.go (core/
// cannot import publisher/). v1 (one script per relay, no slot) was
// never deployed and is not read.
const (
	refreshContainerKind  = "daal-refresh-v2"
	maxRefreshContainer   = 65536
	maxContainerFreshness = 16 << 10
	maxContainerPack      = 48 << 10
)

// MaxGoogleJitter is the most a walk waits before its first connection
// to Google (spec: 0–120 s). The wait actually drawn is bounded by the
// walk's remaining budget as well — see googleDelay.
const MaxGoogleJitter = 120 * time.Second

var (
	appsScriptIDRe    = regexp.MustCompile(`^[A-Za-z0-9_-]{20,120}$`)
	appsScriptSlotRe  = regexp.MustCompile(`^[A-Za-z0-9_-]{11}$`)
	appsScriptTokenRe = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)
	standbyKeyTextRe  = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{26}$`)
)

// IsAppsScriptMirrorURL reports whether raw has the one shape an
// appsscript mirror URL has:
// https://script.google.com/macros/s/<id>/exec?s=<slot>&k=<token>,
// <id> 20–120 of [A-Za-z0-9_-], <slot> 11 and <token> 22 base64url
// characters, exactly those two parameters in that order, no fragment,
// port or credentials. Mirrors
// publisher/deploy/freshness.ValidateAppsScriptURL. The single-relay
// shape of the first build (?k= alone) is not one.
func IsAppsScriptMirrorURL(raw string) bool {
	_, ok := appsScriptSlot(raw)
	return ok
}

// appsScriptSlot is the slot of an appsscript mirror URL, when raw is
// one.
func appsScriptSlot(raw string) (string, bool) {
	if raw == "" || len(raw) > maxFreshnessURLLen || raw != strings.TrimSpace(raw) {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host != bootstrap.AppsScriptHost || u.User != nil {
		return "", false
	}
	if u.Fragment != "" || u.RawFragment != "" || u.Opaque != "" {
		return "", false
	}
	const prefix, suffix = "/macros/s/", "/exec"
	p := u.EscapedPath()
	if !strings.HasPrefix(p, prefix) || !strings.HasSuffix(p, suffix) {
		return "", false
	}
	if !appsScriptIDRe.MatchString(strings.TrimSuffix(strings.TrimPrefix(p, prefix), suffix)) {
		return "", false
	}
	rest, ok := strings.CutPrefix(u.RawQuery, "s=")
	if !ok {
		return "", false
	}
	slot, k, ok := strings.Cut(rest, "&k=")
	if !ok || !appsScriptSlotRe.MatchString(slot) || !appsScriptTokenRe.MatchString(k) {
		return "", false
	}
	return slot, true
}

// MeetsMirrorFloor is the two-mirror rule with its one exception (owner
// decision D-3): a set whose only provider is appsscript is accepted
// with that one mirror. Mirrors publisher/deploy/freshness.MeetsMirrorFloor.
func MeetsMirrorFloor(providers []string) bool {
	if len(providers) >= MinMirrors {
		return true
	}
	return len(providers) == 1 && providers[0] == ProviderAppsScript
}

// refreshContainer is a parsed daal-refresh-v2 container. Shape only:
// every part is verified downstream.
type refreshContainer struct {
	freshness  []byte // nil: the empty container of a removed channel
	pack       []byte
	standbyKey string
}

// errChannelEmpty: the script serves the empty container — the
// publisher removed the channel. "Nothing new here", not a refusal: the
// walk moves on as it would past a mirror that has no document.
var errChannelEmpty = errors.New("freshness: the update channel holds nothing")

// parseRefreshContainer reads a container with the spec's limits. It
// must name slot, the slot the mirror URL asked for.
func parseRefreshContainer(body []byte, slot string) (*refreshContainer, error) {
	if len(body) > maxRefreshContainer {
		return nil, fmt.Errorf("freshness: container is %d bytes, at most %d", len(body), maxRefreshContainer)
	}
	var w struct {
		Kind       string `json:"kind"`
		Slot       string `json:"slot"`
		Freshness  string `json:"freshness"`
		Pack       string `json:"pack"`
		StandbyKey string `json:"standby_key"`
	}
	if err := json.Unmarshal(body, &w); err != nil {
		return nil, errors.New("freshness: the update channel did not answer with a container")
	}
	if w.Kind != refreshContainerKind {
		return nil, errors.New("freshness: not a daal-refresh-v2 container")
	}
	if slot == "" || w.Slot != slot {
		return nil, errors.New("freshness: the container is not this relay's slot")
	}
	c := &refreshContainer{}
	if w.Freshness == "" {
		if w.Pack != "" || w.StandbyKey != "" {
			return nil, errors.New("freshness: container parts without a freshness document")
		}
		return c, nil
	}
	var err error
	if c.freshness, err = decodeContainerPart(w.Freshness, maxContainerFreshness); err != nil {
		return nil, fmt.Errorf("freshness: container document: %w", err)
	}
	if w.Pack != "" {
		if c.pack, err = decodeContainerPart(w.Pack, maxContainerPack); err != nil {
			return nil, fmt.Errorf("freshness: container pack: %w", err)
		}
	}
	if w.StandbyKey != "" {
		if !standbyKeyTextRe.MatchString(w.StandbyKey) {
			return nil, errors.New("freshness: container standby key is malformed")
		}
		c.standbyKey = w.StandbyKey
	}
	return c, nil
}

func decodeContainerPart(s string, max int) ([]byte, error) {
	if base64.StdEncoding.DecodedLen(len(s)) > max+2 {
		return nil, fmt.Errorf("more than %d bytes", max)
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, errors.New("not base64")
	}
	if len(b) > max {
		return nil, fmt.Errorf("more than %d bytes", max)
	}
	return b, nil
}

// inlinePackFor returns the container's pack when — and only when — it
// is the bundle the verified document names. Anything else is ignored
// and the walk fetches current_signed_url as for any mirror.
func inlinePackFor(c *refreshContainer, doc *FreshnessDocument) []byte {
	if c == nil || len(c.pack) == 0 || doc == nil {
		return nil
	}
	sum := sha256.Sum256(c.pack)
	if !equalHex(hex.EncodeToString(sum[:]), doc.CurrentBundleSHA256) {
		return nil
	}
	return c.pack
}

// StandbyKeySink is the engine's standby key store, as the refresher
// sees it. core/abi implements it (abi.StandbyKeySink, lane L-ladder);
// this package only offers keys, and cannot import core/abi (which
// imports it).
//
// AcceptStandbyKey is called after a freshness document from the same
// container verified and after its pack, if any, was applied. relayPackID
// is the pack the key may belong to (the applied pack's id after a
// re-key); key is its 16 raw bytes. The store accepts it only for held
// routes of that pack whose signed `_standby` is sealed and whose
// commitment it opens, keeps it at bundle.StandbyKeyStoreKey(routeID),
// and returns how many routes it opened (0: refused, not an error).
//
// It is called from the unscheduled walks only (googleAllowed), which
// core/abi runs off its engine lock.
type StandbyKeySink interface {
	AcceptStandbyKey(relayPackID string, key []byte) (accepted int, err error)
}

// FrontFetchFn fetches an appsscript mirror. Tests inject one; nil
// means bootstrap.FetchAppsScript with production options.
type FrontFetchFn func(ctx context.Context, url string, dialer bootstrap.Dialer, timeout time.Duration) ([]byte, error)

func defaultFrontFetch(ctx context.Context, url string, dialer bootstrap.Dialer, timeout time.Duration) ([]byte, error) {
	res, err := bootstrap.FetchAppsScript(ctx, url, dialer, timeout, bootstrap.FrontOptions{})
	if err != nil {
		return nil, err
	}
	return res.Body, nil
}

// googleAllowed: the walks that may reach the script (see the file
// comment).
func googleAllowed(kind refreshKind, viaTunnel bool) bool {
	return kind.unscheduled() && !viaTunnel
}

// orderForWalk puts the endpoints in walk order: the ordinary mirrors
// shuffled, then the Google mirror(s) when allowed. skipped is how many
// Google mirrors were left out.
func orderForWalk(eps []string, allowGoogle bool) (order []string, skipped int) {
	var ordinary, google []string
	for _, e := range eps {
		if IsAppsScriptMirrorURL(e) {
			google = append(google, e)
		} else {
			ordinary = append(ordinary, e)
		}
	}
	order = ShuffleEndpoints(ordinary)
	if !allowGoogle {
		return order, len(google)
	}
	return append(order, ShuffleEndpoints(google)...), 0
}

// googleDelay is the random wait before the walk's first Google
// connection: uniform in [0, min(MaxGoogleJitter, what is left of the
// walk budget)). The fetch itself is not squeezed by it: it gets its
// own 2×perURL after the wait (bounded by the caller's context).
//
// The spec's 0–120 s does not fit in the engine's own walk (the dead
// route's instance is down for at most 45 s, core/abi recoverAutoBudget),
// so in practice the spread is the walk's slack: up to ~30 s when the
// ordinary mirrors failed fast, nothing when they ate the budget.
func (r *RelayPackRefresher) googleDelay(walkCtx context.Context) time.Duration {
	max := MaxGoogleJitter
	if r.MaxGoogleJitter > 0 && r.MaxGoogleJitter < max {
		max = r.MaxGoogleJitter
	}
	if dl, ok := walkCtx.Deadline(); ok {
		if left := time.Until(dl); left < max {
			max = left
		}
	}
	if max <= 0 {
		return 0
	}
	if r.GoogleJitter != nil {
		d := r.GoogleJitter(max)
		if d < 0 || d >= max {
			return 0
		}
		return d
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0
	}
	return time.Duration(n.Int64())
}

// sleepCtx waits d or until ctx ends; false when ctx ended.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// fetchGoogleMirror waits the jitter, fetches the container through the
// front and parses it. The context it fetches under comes from the
// caller's (parent) context, not the walk budget, so a walk whose
// ordinary mirrors timed out still gives Google its two attempts.
func (r *RelayPackRefresher) fetchGoogleMirror(parent, walkCtx context.Context, ep string,
	dialer bootstrap.Dialer, perURL time.Duration) (*refreshContainer, error) {

	if !sleepCtx(walkCtx, r.googleDelay(walkCtx)) && parent.Err() != nil {
		return nil, parent.Err()
	}
	fetch := r.FrontFetch
	if fetch == nil {
		fetch = defaultFrontFetch
	}
	gctx, cancel := context.WithTimeout(parent, 2*perURL)
	defer cancel()
	slot, ok := appsScriptSlot(ep)
	if !ok {
		return nil, errors.New("freshness: not an Apps Script mirror")
	}
	body, err := fetch(gctx, ep, dialer, perURL)
	if err != nil {
		return nil, err
	}
	c, err := parseRefreshContainer(body, slot)
	if err != nil {
		return nil, err
	}
	if c.freshness == nil {
		return nil, errChannelEmpty
	}
	return c, nil
}

// offerStandbyKey hands a verified container's standby key to the
// engine's store. false when there is no key, no store, or it opened
// nothing.
func (r *RelayPackRefresher) offerStandbyKey(relayPackID string, c *refreshContainer) bool {
	if c == nil || c.standbyKey == "" || r.StandbyKeys == nil {
		return false
	}
	k, err := bundle.ParseStandbyKeyText(c.standbyKey)
	if err != nil {
		return false
	}
	n, err := r.StandbyKeys.AcceptStandbyKey(relayPackID, k[:])
	return err == nil && n > 0
}
