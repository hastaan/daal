package abi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"daal/bundle-go/bundle"
	"daal/core/desync"
	"daal/core/diagnostics"
	"daal/core/engine"
	"daal/core/netmem"
	"daal/core/pathmanager"
	"daal/core/refresh"
	"daal/core/routestore"
	"daal/core/trust"
)

// The CONNECT LADDER — what the automatic pass does when a route's TLS
// first flight is stopped (docs/blackout-tier-plan.md T2/T5;
// docs/adaptive-cover-names-plan.md §1.3–§1.7). No new screen, no new
// call: it lives inside the pass (connect_auto.go, connect_race.go).
//
// THE TOOLS. A VARIANT of a route is the same route with its first
// flight changed, and nothing else:
//
//   - a desync preset (core/desync): the hello cut below uTLS/REALITY by
//     the daal-desync detour (engine.BuildSingBoxConfigWithDesync);
//   - a cover name: a JSON-patched copy of the route's outbound with
//     tls.server_name swapped for an entry of the route's SIGNED
//     `_cover_names` list (bundle/go/bundle cover_names.go). Offered only
//     where the relay is proved by its key and never by the name, and
//     that is CHECKED (coverNamesLocked): the route has a stored signed
//     endpoint, its publisher is trusted or TOFU-pinned, and its outbound
//     has REALITY on (vless-reality) or a certificate key pin with no
//     `insecure` (websocket-tls, anytls). The endpoint guard runs on the
//     route's own profile first; no pin and no signature check is
//     relaxed. Names are never resolved. Class `cdn` names are not
//     offered (no CDN-fronted family exists to send them to);
//   - both.
//
// WHEN. A TCP route whose attempt in this pass was stopped AT ITS HELLO
// (helloStopOf) gets its next variant, tried at once, alone, before
// anything else in the queue — and how much it gets depends on what
// stopped it:
//
//   - stopped by a reset or close that is not measured as the relay's
//     own (diagnostics ServerStop), a tls_sni_or_cert_block_suspected /
//     reset-in-the-handshake category, or a `name_blocked` refinement:
//     up to ladderPerRoute variants, cover names included;
//   - left unanswered (a timeout after the TCP connect — the signature
//     of an address default-denied or grey-listed as much as of a name):
//     at most ladderPerRouteSilent preset, and NO name;
//   - refined `address_blocked` (two names to the same address and port
//     stopped alike), a measured server-side stop, or anything else:
//     nothing — the route's ladder is done for the pass.
//
// When every TCP route the pass tried timed out at the hello (two
// routes or more), the ladder is off for the rest of the pass. The
// connected route that stopped carrying with a hello-shaped category (a
// fall-over pass) gets its variants first.
//
// THE ORDER (ladderList): the presets where engine.RouteDesyncReason says
// a cut can change what the censor sees — the pack's `_desync` offer
// first when there is one, then sni-cut, tlsrec-sni, chain — interleaved
// with the eligible cover names in the signed list's order, then the
// first preset combined with each name. A variant that carried here
// before moves to the front (by Confidence); one marked blocked here
// (netmem VariantBlockedAt: 72 h, and two failures in a row for one that
// had carried) is skipped, and so is one that could not be started in
// this build (in memory).
//
// THE BUDGET. At most ladderPerRoute variants per route per pass (the
// route's remembered first variant included), at most ladderPerPass
// variants the ladder adds per pass, each one counted against the
// network's hourly side-probe allowance (sideProbesPerHour,
// connect_race.go) and none tried once it is spent. A route's
// remembered first attempt (ladderPreferredLocked) is the route's own attempt,
// not an extra, and is not counted there. Cover names: at most
// ladderNamesPerRelay distinct names per (network, relay address) ever —
// counted in the network's snapshot (netmem CoverNamesShown, hashes
// only), which forgetting or re-minting a route does not reset — none
// for a route whose address is not known, none while two or more names
// to that relay carry a blocked mark here, and none on the shared
// bucket of a host that has reported no network. Sequential, always: a
// variant shares its route's address and port, and the race never puts
// two probes on one address and port (connect_race.go).
//
// MODES. In lifeline-strict, and in every pass the engine starts by
// itself (a fall-over, a re-check), only variants that carried on this
// network before are used: nothing new is shown to the network. The
// fall-over's own ladder keeps lifeline-strict's refusal of a
// bulk-capable route.
//
// THE MEMORY. Each variant's outcome is kept for THIS network under its
// own key (netmem variant.go: routeID#d:<preset>, #n:<id> with the
// entry's signed id, both). A variant that carried with confidence ≥
// ladderPreferConfidence is the route's FIRST attempt next time on the
// same network — and only there. Confidence halves per 24 h without a
// fresh success. Only what says something about the first flight is
// written: a variant's reset/close at the hello marks it; a silent
// failure, a server-side stop or a failure further on writes nothing; a
// variant that cannot start is set aside in memory for this run. When a
// route's signed endpoint changes (a refresh, a recovery to a new
// address — ladderRebindLocked), its variants' records and its variant
// in use are dropped: they describe another relay.
//
// THE RULE THAT MATTERS MOST. A variant's failure AT ITS HELLO is the
// variant's alone: no route cooldown, no family cooldown, no failure row,
// nothing remembered against the route — only its own key. A connected
// route whose variant fails a liveness check in any OTHER way is charged
// as a route (the relay may be what died). And when a variant CARRIES
// after the route's own hello was stopped in the same pass, the route's
// own charge is dropped, its cooldown lifted, and the family step that
// charge took is taken back — when no other route of the family failed
// in the pass.
//
// WHAT IS SAID. `tried[].variant` and `auto.variant` carry closed words
// only (routeVariant.suffix): a preset name and an entry id. No log line,
// report, published failure or diagnostic ever holds a cover name: the
// failure text of a name variant is dropped (it can quote the name).

// AutoWhyLadder is the `why` of an attempt the ladder added: the route's
// own first flight (or its last variant's) was stopped at the hello in
// this pass, and this is the same route with its first flight changed.
const AutoWhyLadder = "ladder"

const (
	// ladderPerRoute: variants per route per pass, the route's
	// remembered first variant included.
	ladderPerRoute = 2
	// ladderPerRouteSilent: the same, for a route whose hello went
	// unanswered in this pass (presets only).
	ladderPerRouteSilent = 1
	// ladderPerPass: variants the ladder adds to one pass, all routes
	// together. N stopped routes would otherwise be 2N more full
	// start-and-prove cycles, each a full hello timeout on a bad day.
	ladderPerPass = 3
	// ladderNamesPerRelay: distinct cover names ever shown to one relay
	// address from one network. Several names to one address in a short
	// time is a scanner; over months, a growing set is one too.
	ladderNamesPerRelay = 3
	// ladderNamesBlockedStop: blocked name variants to one relay on this
	// network at which no new name is shown to it — two different names
	// stopped alike say the name is not what the network reads.
	ladderNamesBlockedStop = 2
	// ladderPreferConfidence: a remembered variant at or above this
	// confidence (netmem RouteMemory.Confidence: halves per 24 h) is the
	// route's first attempt on the network; below it the plain route is
	// tried first and the variant is the ladder's first rung.
	ladderPreferConfidence = 0.5
	// ladderPackPrefix starts the variant word of the pack's own
	// `_desync` offer when it is not one of the named presets:
	// "pack-<6 hex>", the hex a digest of the normalised strategy, so a
	// pack that changes its offer starts a new record.
	ladderPackPrefix = "pack-"
	// ladderBindPrefix: the secrets_kv key (encrypted) of the digest of
	// what a route's variants were recorded against (ladderRebindLocked).
	ladderBindPrefix = "ladder_bind:"
)

// ladderPresets is the ladder's preset order after the pack's offer
// (core/desync Presets: sni-cut is the one that beats both rig censor
// models, tlsrec-sni the record split, chain the many-pieces shape that
// does not survive loss). split1 is not on it: a box that joins two
// packets reads it whole.
var ladderPresets = []string{"sni-cut", "tlsrec-sni", "chain"}

// routeVariant is what the ladder changes about one route's first
// flight. The zero value is the route as it is.
type routeVariant struct {
	// preset: a core/desync preset name, or a pack word
	// (ladderPackPrefix…); "" = no cut.
	preset string
	// name: the signed id of an entry of the route's `_cover_names`; 0
	// = the route's own name.
	name int
}

func (v routeVariant) zero() bool { return v.preset == "" && v.name == 0 }

// suffix is the variant's closed word: its netmem key suffix and what
// `tried[].variant` reports. "" for the zero variant.
func (v routeVariant) suffix() string {
	var parts []string
	if v.preset != "" {
		parts = append(parts, "d:"+v.preset)
	}
	if v.name > 0 {
		parts = append(parts, "n:"+strconv.Itoa(v.name))
	}
	return strings.Join(parts, netmem.VariantSep)
}

// logField is " variant=<suffix>" for a log line, "" for the zero
// variant.
func (v routeVariant) logField() string {
	if v.zero() {
		return ""
	}
	return " variant=" + v.suffix()
}

// isPackWord: "pack-" and six lower-case hex digits.
func isPackWord(p string) bool {
	h, ok := strings.CutPrefix(p, ladderPackPrefix)
	if !ok || len(h) != 6 {
		return false
	}
	for _, c := range h {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// parseVariantSuffix reads a suffix back; ok=false for one this build
// does not write.
func parseVariantSuffix(s string) (routeVariant, bool) {
	var v routeVariant
	if s == "" {
		return v, false
	}
	for _, part := range strings.Split(s, netmem.VariantSep) {
		switch {
		case strings.HasPrefix(part, "d:") && v.preset == "" && v.name == 0:
			p := part[2:]
			if _, ok := desync.Presets[p]; !ok && !isPackWord(p) {
				return routeVariant{}, false
			}
			v.preset = p
		case strings.HasPrefix(part, "n:") && v.name == 0:
			n, err := strconv.Atoi(part[2:])
			if err != nil || n < 1 || n > bundle.CoverNameIDMax || strconv.Itoa(n) != part[2:] {
				return routeVariant{}, false
			}
			v.name = n
		default:
			return routeVariant{}, false
		}
	}
	return v, true
}

// ---- what the ladder reads of a route ----------------------------------

// errVariantUnusable: the variant cannot be built for the route (its
// preset cannot cut this outbound, its name is not on the list or not
// eligible). Never carries the name.
var errVariantUnusable = errors.New("abi: route variant unusable")

// ladderRoute is a route as the ladder reads it. names / nameIDs: the
// cover names it may show, by signed id, in the list's order. In memory
// only, for one decision; never logged.
type ladderRoute struct {
	row     routestore.RouteRow
	profile []byte
	own     string
	names   map[int]string
	nameIDs []int
	// namesRefused: the list is there and was refused ("domestic",
	// "malformed"); for the log.
	namesRefused string
}

func (c *Core) ladderRouteOf(row routestore.RouteRow, profile []byte) ladderRoute {
	lr := ladderRoute{row: row, profile: profile}
	_, _, lr.own = profileRelay(profile)
	lr.names, lr.nameIDs, lr.namesRefused = c.coverNamesLocked(row, profile, lr.own)
	return lr
}

func (c *Core) ladderRouteByID(routeID string) (ladderRoute, bool) {
	row, profile, ok := c.routeRowProfile(routeID)
	if !ok {
		return ladderRoute{}, false
	}
	return c.ladderRouteOf(row, profile), true
}

// coverNameEligible: may this entry be shown for a route of this family?
// REALITY: only a name its relay answers for. A pinned TLS family: any
// name — except a CDN-hosted one, which no family of this build sends to
// that CDN (a CDN name to a VPS address is the mismatch a censor checks).
func coverNameEligible(family string, e bundle.CoverName) bool {
	if e.Class == bundle.CoverClassCDN {
		return false
	}
	switch family {
	case "vless-reality":
		return e.Reality
	case "websocket-tls", "anytls":
		return true
	}
	return false
}

// keyProvesRelay: the outbound authenticates its relay by a key, never
// by the TLS name — REALITY on with its public key (vless-reality), or a
// certificate key pin with no `insecure` (websocket-tls, anytls). The
// name can be swapped only then.
func keyProvesRelay(family string, profile []byte) bool {
	var ob struct {
		TLS *struct {
			Enabled  bool     `json:"enabled"`
			Insecure bool     `json:"insecure"`
			Pins     []string `json:"certificate_public_key_sha256"`
			Reality  *struct {
				Enabled   bool   `json:"enabled"`
				PublicKey string `json:"public_key"`
			} `json:"reality"`
		} `json:"tls"`
	}
	if json.Unmarshal(profile, &ob) != nil || ob.TLS == nil || !ob.TLS.Enabled {
		return false
	}
	switch family {
	case "vless-reality":
		return ob.TLS.Reality != nil && ob.TLS.Reality.Enabled && ob.TLS.Reality.PublicKey != ""
	case "websocket-tls", "anytls":
		return !ob.TLS.Insecure && len(ob.TLS.Pins) > 0 && (ob.TLS.Reality == nil || !ob.TLS.Reality.Enabled)
	}
	return false
}

// routeSignedLocked: the route has a stored signed endpoint (the guard,
// endpoint_guard.go, holds its outbound to it at every connect).
func (c *Core) routeSignedLocked(routeID string) bool {
	raw, err := c.store.GetSecret(trust.RouteEndpointKey(routeID))
	return err == nil && len(raw) > 0
}

// coverNamesLocked returns the cover names a route may show (see the top
// of this file), by id and in list order; none unless every condition
// holds. refused names why a list that is there is not used.
func (c *Core) coverNamesLocked(row routestore.RouteRow, profile []byte, own string) (map[int]string, []int, string) {
	if engine.IsUDPFamily(row.TransportFamily) {
		return nil, nil, ""
	}
	cn, err := bundle.CoverNamesFromFamilyConfig([]byte(row.FamilySpecificConfigJSON))
	switch {
	case errors.Is(err, bundle.ErrNoCoverNames):
		return nil, nil, ""
	case errors.Is(err, bundle.ErrCoverNameDomestic):
		return nil, nil, "domestic"
	case err != nil:
		return nil, nil, "malformed"
	}
	if row.TrustState != "trusted" && row.TrustState != "tofu" {
		return nil, nil, "untrusted"
	}
	if !keyProvesRelay(row.TransportFamily, profile) {
		return nil, nil, "not_key_proved"
	}
	if !c.routeSignedLocked(row.RouteID) {
		return nil, nil, "unsigned"
	}
	names := map[int]string{}
	var ids []int
	for _, e := range cn.Names {
		if coverNameEligible(row.TransportFamily, e) && e.Name != own {
			names[e.ID] = e.Name
			ids = append(ids, e.ID)
		}
	}
	if len(ids) == 0 {
		return nil, nil, ""
	}
	return names, ids, ""
}

// patchServerName is the route's outbound with tls.server_name swapped.
// Nothing else changes: the server, the port, the key pin, the REALITY
// key and short id are the route's own.
func patchServerName(profile []byte, name string) ([]byte, error) {
	var ob map[string]any
	if err := json.Unmarshal(profile, &ob); err != nil {
		return nil, errVariantUnusable
	}
	tls, _ := ob["tls"].(map[string]any)
	if tls == nil || tls["enabled"] != true {
		return nil, errVariantUnusable
	}
	tls["server_name"] = name
	return json.Marshal(ob)
}

// packPresetWord is the variant word of the pack's `_desync` offer: its
// preset's name when it names one alone, else "pack-<6 hex>" over the
// normalised strategy.
func packPresetWord(o desync.Offer) string {
	var p map[string]json.RawMessage
	if json.Unmarshal(o.Strategy, &p) == nil && len(p) == 1 {
		var name string
		if json.Unmarshal(p["preset"], &name) == nil {
			if _, ok := desync.Presets[name]; ok {
				return name
			}
		}
	}
	b, _ := json.Marshal(o.StrategyValue())
	sum := sha256.Sum256(b)
	return ladderPackPrefix + hex.EncodeToString(sum[:3])
}

// variantStrategy is the cut a variant's preset stands for. A pack word
// stands for the pack's CURRENT offer only while that offer is still the
// one the word was made from.
func variantStrategy(row routestore.RouteRow, preset string) (desync.Strategy, error) {
	if isPackWord(preset) {
		o, err := engine.PackDesyncOffer(row)
		if err != nil || packPresetWord(o) != preset {
			return desync.Off, errVariantUnusable
		}
		return o.StrategyValue(), nil
	}
	if _, ok := desync.Presets[preset]; !ok {
		return desync.Off, errVariantUnusable
	}
	return desync.Strategy{Preset: preset}, nil
}

// buildVariant is the engine config of one variant of a route (its own
// profile, already through every check of prepareRouteVariant).
//
// The zero variant is the route as the engine would start it
// (BuildSingBoxConfig: a remembered per-network desync choice or a
// pack's "always" applies, as for any connect). Every other variant is
// built with its strategy EXPLICIT — desync.Off for a name alone — so
// what is recorded under its key is exactly what was sent.
func buildVariant(lr ladderRoute, v routeVariant) ([]byte, error) {
	if v.zero() {
		cfg, err := engine.BuildSingBoxConfig(lr.row, lr.profile)
		if err != nil {
			return nil, err
		}
		return engine.MarshalSingBox(cfg)
	}
	profile := lr.profile
	if v.name > 0 {
		name, ok := lr.names[v.name]
		if !ok {
			return nil, errVariantUnusable
		}
		p, err := patchServerName(profile, name)
		if err != nil {
			return nil, err
		}
		profile = p
	}
	st := desync.Off
	if v.preset != "" {
		// BuildSingBoxConfigWithDesync builds an UNCUT config, and only
		// logs it, where the outbound cannot be cut: a variant that
		// would change nothing is refused here instead.
		if why := engine.RouteDesyncReason(lr.row, profile); why != "" {
			return nil, errVariantUnusable
		}
		s, err := variantStrategy(lr.row, v.preset)
		if err != nil {
			return nil, err
		}
		st = s
	}
	cfg, err := engine.BuildSingBoxConfigWithDesync(lr.row, profile, st)
	if err != nil {
		return nil, err
	}
	return engine.MarshalSingBox(cfg)
}

// variantBodyLocked is prepareRouteVariant's build step. v nil: the
// variant in use for the route on this network; one that cannot be
// built any more (a refreshed pack dropped its name) is forgotten and
// the plain route is built. v non-nil (every listing and every pass
// attempt): exactly that one, and nothing is written.
func (c *Core) variantBodyLocked(row routestore.RouteRow, profile []byte, v *routeVariant) ([]byte, error) {
	lr := c.ladderRouteOf(row, profile)
	if v != nil {
		return buildVariant(lr, *v)
	}
	inUse := c.variantInUse(row.RouteID)
	if !inUse.zero() {
		if body, err := buildVariant(lr, inUse); err == nil {
			return body, nil
		}
		c.setVariantInUse(row.RouteID, routeVariant{})
	}
	return buildVariant(lr, routeVariant{})
}

// ---- the variant in use, and what this build cannot start ---------------

// ladderInUse: per route, the variant that last carried on the network
// the device is on — what a reconnect of the route (a manual pick, the
// instance put back after a fall-over, a speed move) starts. In memory;
// tied to the Core that set it and to the network, so a new Core or
// another network starts from the plain route (the per-network memory
// picks the variant again at the next pass). unusable: variant keys
// (routeID#suffix) that failed to START in this run — a config this
// build cannot run says nothing about the network, and is not tried
// again until the engine restarts or the route's endpoint changes.
var ladderInUse = struct {
	mu       sync.Mutex
	core     *Core
	m        map[string]ladderUse
	unusable map[string]bool
}{}

type ladderUse struct {
	network string
	v       routeVariant
}

// ladderInUseOwnLocked makes the struct this Core's. ladderInUse.mu held.
func (c *Core) ladderInUseOwnLocked() {
	if ladderInUse.core != c {
		ladderInUse.core, ladderInUse.m, ladderInUse.unusable = c, map[string]ladderUse{}, map[string]bool{}
	}
}

func (c *Core) variantInUse(routeID string) routeVariant {
	ladderInUse.mu.Lock()
	defer ladderInUse.mu.Unlock()
	if ladderInUse.core != c {
		return routeVariant{}
	}
	u, ok := ladderInUse.m[routeID]
	if !ok || u.network != activeNetworkID() {
		return routeVariant{}
	}
	return u.v
}

func (c *Core) setVariantInUse(routeID string, v routeVariant) {
	ladderInUse.mu.Lock()
	defer ladderInUse.mu.Unlock()
	c.ladderInUseOwnLocked()
	if v.zero() {
		delete(ladderInUse.m, routeID)
		return
	}
	ladderInUse.m[routeID] = ladderUse{network: activeNetworkID(), v: v}
}

func (c *Core) variantUnusable(key string) bool {
	ladderInUse.mu.Lock()
	defer ladderInUse.mu.Unlock()
	return ladderInUse.core == c && ladderInUse.unusable[key]
}

func (c *Core) setVariantUnusable(key string) {
	ladderInUse.mu.Lock()
	defer ladderInUse.mu.Unlock()
	c.ladderInUseOwnLocked()
	ladderInUse.unusable[key] = true
}

// forgetRouteVariantsInMemory drops the route's variant in use and its
// "cannot start" marks.
func (c *Core) forgetRouteVariantsInMemory(routeID string) {
	ladderInUse.mu.Lock()
	defer ladderInUse.mu.Unlock()
	if ladderInUse.core != c {
		return
	}
	delete(ladderInUse.m, routeID)
	for k := range ladderInUse.unusable {
		if r, _ := netmem.SplitVariantKey(k); r == routeID {
			delete(ladderInUse.unusable, k)
		}
	}
}

// ---- what the variants were recorded against ---------------------------

// ladderBindOf is the digest of what a route's variants describe: its
// signed endpoint (address, port, name, key) when it has one, else its
// stored outbound. Kept encrypted (secrets_kv), never logged.
func (c *Core) ladderBindOf(routeID string, profile []byte) string {
	h := sha256.New()
	if raw, err := c.store.GetSecret(trust.RouteEndpointKey(routeID)); err == nil && len(raw) > 0 {
		h.Write([]byte("endpoint|"))
		h.Write(raw)
	} else {
		h.Write([]byte("profile|"))
		h.Write(profile)
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// ladderRebindLocked: when the route's signed endpoint (or, for a route
// without one, its outbound) is no longer what its variants were
// recorded against — a refresh, a recovery to a new address, a new file
// — every variant record of the route (all networks), its variant in use
// and its "cannot start" marks are dropped: a remembered name would
// otherwise be the first thing shown to a relay that may not answer for
// it. The route's own record stays. A route seen for the first time is
// only bound.
func (c *Core) ladderRebindLocked(routeID string) {
	if c.store == nil {
		return
	}
	profile, err := c.store.GetSecret("route:" + routeID)
	if err != nil {
		return
	}
	sum := c.ladderBindOf(routeID, profile)
	key := ladderBindPrefix + routeID
	prev, err := c.store.GetSecret(key)
	if err == nil && string(prev) == sum {
		return
	}
	if err == nil && len(prev) > 0 {
		if st := netmemStore(); st != nil {
			_ = st.ForgetVariants(routeID)
		}
		c.forgetRouteVariantsInMemory(routeID)
		engine.LogInfo(fmt.Sprintf("auto ladder route=%s forget=endpoint_changed", engine.LogID(routeID)))
	}
	_ = c.store.PutSecret(key, []byte(sum))
}

// ladderRebindAllLocked is ladderRebindLocked for every route: at the
// start of each automatic pass.
func (c *Core) ladderRebindAllLocked() {
	if c.store == nil || c.shuttingDown {
		return
	}
	rows, err := c.store.ListRoutes()
	if err != nil {
		return
	}
	for _, r := range rows {
		c.ladderRebindLocked(r.RouteID)
	}
}

// ---- one attempt -------------------------------------------------------

// prepareAttemptLocked is connectRouteLocked's prepare step: it settles
// which variant the attempt is (o.variant, made explicit) and builds it.
func (c *Core) prepareAttemptLocked(routeID string, o *connectOpts) (routestore.RouteRow, []byte, error) {
	if o.variant == nil {
		if !c.variantInUse(routeID).zero() {
			c.ladderRebindLocked(routeID)
		}
		v := c.variantInUse(routeID)
		row, body, err := c.prepareRouteVariant(routeID, o.record, o.ladder, &v)
		var rr *routeRefusal
		if err != nil && !v.zero() && errors.As(err, &rr) && errors.Is(err, errVariantUnusable) {
			c.setVariantInUse(routeID, routeVariant{})
			v = routeVariant{}
			row, body, err = c.prepareRouteVariant(routeID, o.record, o.ladder, &v)
		}
		o.variant = &v
		return row, body, err
	}
	return c.prepareRouteVariant(routeID, o.record, o.ladder, o.variant)
}

// attemptMemKey is the network-memory key of an attempt: the route's, or
// its variant's.
func attemptMemKey(routeID string, o connectOpts) string {
	if o.variant == nil {
		return routeID
	}
	return netmem.VariantKey(routeID, o.variant.suffix())
}

// variantReason is the failure text a variant may publish: a name
// variant's is dropped — an error can quote the name it presented.
func variantReason(v routeVariant, reason string) string {
	if v.name > 0 {
		return ""
	}
	return reason
}

// attemptStartFailedLocked records an attempt whose instance did not
// start: a route's failure as it always was, or a variant's — which
// charges nothing, and sets the variant aside for this run (a config
// this build cannot run says nothing about the network).
func (c *Core) attemptStartFailedLocked(routeID, family string, cat diagnostics.Category, reason string, o connectOpts) {
	if o.variant == nil || o.variant.zero() {
		c.routeDownOptsLocked(routeID, family, cat, reason, true, o.auto)
		return
	}
	v := *o.variant
	c.setVariantUnusable(netmem.VariantKey(routeID, v.suffix()))
	if c.variantInUse(routeID) == v {
		c.setVariantInUse(routeID, routeVariant{})
	}
	c.variantDownLocked(routeID, family, cat, variantReason(v, reason), true, v)
}

// attemptProofFailedLocked records an attempt whose connection check
// failed, and returns the failure text the caller may report: a route's
// failure as it always was (remembered for this network when it was not
// a candidate of a pass), or a variant's — which charges nothing to the
// route, its family or its relay. A variant picked by hand (or the
// variant in use, reconnected) is remembered as failed, and is no longer
// the one in use, only when it was stopped at its hello.
func (c *Core) attemptProofFailedLocked(routeID, family string, cat diagnostics.Category, res engine.ProofResult, o connectOpts) string {
	reason := proofFailureText(res)
	if o.variant == nil || o.variant.zero() {
		c.routeDownOptsLocked(routeID, family, cat, reason, true, o.auto)
		if !o.auto {
			c.rememberRoute(routeID, false, cat)
		}
		return reason
	}
	v := *o.variant
	reason = variantReason(v, reason)
	c.variantDownLocked(routeID, family, cat, reason, true, v)
	if !o.auto {
		ob := autoObs{result: AutoResultNotCarrying, category: cat, obs: res.Observation, udp: engine.IsUDPFamily(family)}
		if helloStopOf(ob, "") == stopReset {
			c.rememberOutcome(netmem.VariantKey(routeID, v.suffix()), netmem.RouteOutcome{Category: string(cat)})
			c.setVariantInUse(routeID, routeVariant{})
		}
	}
	return reason
}

// variantDownLocked is routeDownOptsLocked for a variant: the instance,
// the published failure and the engine's "last connect failed" record
// exactly as for any attempt — and NOTHING on the route, its family or
// its relay: no path-manager failure, no cooldown, no failure row. The
// path manager's attempt is closed without an outcome (EndAttempt), so
// it does not go on saying the route is being checked. The variant's
// own record is written by the pass (ladderSettleLocked) or by the
// caller.
func (c *Core) variantDownLocked(routeID, family string, cat diagnostics.Category, reason string, teardown bool, v routeVariant) {
	c.driver.PublishFailure(cat, reason)
	if teardown {
		_ = c.driver.Stop()
		refresh.SetTunnelRequired(false)
		c.setActiveLocked("", "")
	}
	engine.LogInfo(fmt.Sprintf("route down route=%s family=%s result=failed category=%s running=%t%s",
		engine.LogID(routeID), engine.LogID(family), engine.LogID(string(cat)), !teardown, v.logField()))
	c.pm.EndAttempt(routeID, "variant "+v.suffix()+" of "+routeID+" did not carry: "+string(cat))
	c.check.setFailed(cat, !teardown)
	if teardown {
		c.check.mu.Lock()
		c.check.failedRoute, c.check.failedFamily = routeID, family
		c.check.failedCooled = !pmCooldownUntil(c, routeID).IsZero()
		c.check.mu.Unlock()
	}
}

// variantCarriedLocked: an attempt carried. The variant it was is the
// one in use for the route on this network from now on (the zero one:
// the plain route).
func (c *Core) variantCarriedLocked(routeID string, o connectOpts) {
	if o.variant == nil {
		return
	}
	c.setVariantInUse(routeID, *o.variant)
	if !o.variant.zero() {
		engine.LogInfo(fmt.Sprintf("route variant route=%s%s", engine.LogID(routeID), o.variant.logField()))
	}
}

// runningMemKeyLocked is the memory key of the connected route's
// instance: its variant's, when one is in use.
func (c *Core) runningMemKeyLocked(routeID string) string {
	return netmem.VariantKey(routeID, c.variantInUse(routeID).suffix())
}

// liveVariantDownLocked: the connected route failed a liveness check
// while a variant is in use, with a category a changed first flight can
// answer (ladderLostShaped). The failure is the variant's (its record on
// this network), and nothing is charged to the route; the instance keeps
// running, as for any liveness failure. Any OTHER failure is the
// route's — the relay itself may be what died — and is left to the
// caller (false), with the variant's record untouched.
func (c *Core) liveVariantDownLocked(routeID, family string, cat diagnostics.Category, reason string) bool {
	v := c.variantInUse(routeID)
	if v.zero() || !ladderLostShaped(cat) {
		return false
	}
	c.variantDownLocked(routeID, family, cat, variantReason(v, reason), false, v)
	c.rememberOutcome(netmem.VariantKey(routeID, v.suffix()), netmem.RouteOutcome{Category: string(cat)})
	return true
}

// ---- what stopped a hello ----------------------------------------------

// helloStop is what a failed attempt says about its first flight.
type helloStop int

const (
	// stopNone: not stopped at the hello, or stopped by the relay itself
	// (a measured server-side stop) — no first flight would fare better.
	stopNone helloStop = iota
	// stopSilent: the hello went out on an open connection and nothing
	// came back. An address default-denied or grey-listed looks exactly
	// like this; so does a name blackholed. Presets at most, no names.
	stopSilent
	// stopReset: reset or closed at the hello, not measured as the
	// relay's own; or the pass has already shown the name is what is
	// read (name_blocked).
	stopReset
)

// helloStopOf classifies one failed attempt (refined: its refinement in
// the pass, "" when none is known).
func helloStopOf(o autoObs, refined string) helloStop {
	if o.udp || o.unplaced || o.result != AutoResultNotCarrying {
		return stopNone
	}
	if refined == AutoRefinedNameBlocked {
		return stopReset
	}
	if o.obs.ServerStop() {
		return stopNone
	}
	if o.obs.Timeout && !o.obs.Reset && !o.obs.Closed {
		// Silence, whatever the category says of it.
		if o.stoppedAtHello() {
			return stopSilent
		}
		return stopNone
	}
	switch {
	case o.stoppedAtHello() && (o.obs.Reset || o.obs.Closed):
		return stopReset
	case o.category == diagnostics.TLSSNIOrCertBlockSuspected:
		return stopReset
	case (o.category == diagnostics.TCPReset || o.category == diagnostics.TLSHandshakeFailed) &&
		o.obs.Phase == diagnostics.PhaseHandshake && o.obs.TLS:
		return stopReset
	}
	return stopNone
}

// ladderLostShaped: the connected route's liveness failure category is
// one a changed first flight can answer.
func ladderLostShaped(cat diagnostics.Category) bool {
	switch cat {
	case diagnostics.TLSSNIOrCertBlockSuspected, diagnostics.TCPReset, diagnostics.TLSHandshakeFailed:
		return true
	}
	return false
}

// ---- the ladder of one pass --------------------------------------------

// passLadder is the ladder's state for one pass.
type passLadder struct {
	routes map[string]*routeLadder
	// extra: attempts (variants and plain retries) the ladder added to
	// the pass's queue.
	extra int
	// variants: variants the ladder picked in this pass
	// (ladderPerPass).
	variants int
	// newNames: per relay address, the names (netmem.ShownKey) first
	// shown to it in this pass.
	newNames map[string]map[string]bool
	// failed: variant failures, remembered when the pass settles.
	failed []ladderFail
	// off: every TCP route of the pass timed out at its hello.
	off bool
	// lostCharged: the fall-over's lost route was charged as a route by
	// the liveness check (it was running plain).
	lostCharged bool
}

type routeLadder struct {
	base autoCandidate
	lr   ladderRoute
	list []routeVariant
	// built: lr and list were read.
	built bool
	// tried: variants started in this pass (the zero one included).
	tried map[routeVariant]bool
	// extras: non-zero variants started in this pass.
	extras int
	// silent: a hello of this route went unanswered in this pass.
	silent bool
	// stop: what stopped the route's last first flight that said
	// something (a variant that could not start says nothing).
	stop helloStop
	done bool
}

type ladderFail struct {
	key string
	cat diagnostics.Category
	// marks: the failure says something about the first flight (a
	// reset or close at the hello): it is written at settle.
	marks bool
}

func (p *autoPass) ladderState() *passLadder {
	if p.ladder == nil {
		p.ladder = &passLadder{routes: map[string]*routeLadder{}, newNames: map[string]map[string]bool{}}
	}
	return p.ladder
}

func (p *autoPass) ladderExtra() int {
	if p.ladder == nil {
		return 0
	}
	return p.ladder.extra
}

// ladderRestricted: only variants that carried on this network before
// may be used — in lifeline-strict, and in a pass the engine started by
// itself (nothing new is shown to a network without the person asking).
func (p *autoPass) ladderRestricted() bool {
	return p.background || p.c.mode == "lifeline-strict"
}

// routeLadderOf returns the route's ladder, starting it from the
// candidate that was its first attempt in this pass.
func (p *autoPass) routeLadderOf(cd autoCandidate) *routeLadder {
	l := p.ladderState()
	rl, ok := l.routes[cd.routeID]
	if !ok {
		base := cd
		base.variant, base.ladder, base.proved = routeVariant{}, false, false
		if !cd.variant.zero() {
			// The first attempt carried a variant's name: the plain
			// route's is its own.
			if b, ok := p.c.ladderBaseCandidateLocked(cd.routeID); ok {
				base.name = b.name
			}
		}
		rl = &routeLadder{base: base, tried: map[routeVariant]bool{cd.variant: true}}
		if !cd.variant.zero() {
			rl.extras = 1
		}
		l.routes[cd.routeID] = rl
	}
	return rl
}

// ladderSilentEverywhere: two routes or more were tried in this pass
// over TCP, and every TCP attempt that failed timed out at its hello.
func (p *autoPass) ladderSilentEverywhere() bool {
	ids := map[string]bool{}
	for _, o := range p.obs {
		if o.result != AutoResultNotCarrying || o.udp || o.unplaced || o.id == "" {
			continue
		}
		if !(o.stoppedAtHello() && o.obs.Timeout && !o.obs.Reset && !o.obs.Closed) {
			return false
		}
		ids[o.id] = true
	}
	return len(ids) >= 2
}

// ladderNext returns the next attempt for each route whose attempt
// recorded since obs index `mark` failed in a way the ladder answers.
func (p *autoPass) ladderNext(mark int) []autoCandidate {
	if mark >= len(p.obs) {
		return nil
	}
	_, refined := deriveAuto(p.obs)
	l := p.ladderState()
	if !l.off && p.ladderSilentEverywhere() {
		l.off = true
		engine.LogInfo("auto ladder stop=silent_everywhere")
	}
	addressBlocked := map[string]bool{}
	for i, o := range p.obs {
		if o.id != "" && i < len(refined) && refined[i] == AutoRefinedAddressBlocked {
			addressBlocked[o.id] = true
		}
	}
	var next []autoCandidate
	for i := mark; i < len(p.obs) && i < len(p.tried); i++ {
		o, t := p.obs[i], p.tried[i]
		if o.id == "" || o.unplaced {
			continue
		}
		var cd autoCandidate
		rl, ok := l.routes[o.id]
		if ok {
			cd = rl.base
		} else if c, found := p.candidateByID(o.id); found {
			// The route's first attempt of this pass: the variant it
			// was (its remembered one, or none).
			c.variant, _ = parseVariantSuffix(t.Variant)
			cd = c
			rl = p.routeLadderOf(c)
		} else {
			continue
		}
		if rl.done {
			continue
		}
		wasVariant := t.Variant != ""
		failed := o.failed() || (wasVariant && t.Result == AutoResultRefused)
		if !failed {
			continue
		}
		if wasVariant && !rl.tried[routeVariant{}] {
			// The route's remembered variant was its first attempt and
			// did not carry: the route as it is goes next — its own
			// attempt, charged as one.
			rl.tried[routeVariant{}] = true
			plain := rl.base
			plain.why = cd.why
			next = append(next, plain)
			continue
		}
		if addressBlocked[o.id] {
			// Two names to this address and port were stopped alike: the
			// name is not what the network reads. No other is shown.
			rl.done = true
			engine.LogInfo(fmt.Sprintf("auto ladder route=%s stop=address_blocked", engine.LogID(o.id)))
			continue
		}
		if l.off {
			rl.done = true
			continue
		}
		stop := helloStopOf(o, refined[i])
		if wasVariant && (t.Result == AutoResultStartFailed || t.Result == AutoResultRefused) {
			// A variant this build could not start or build says nothing
			// about the network: the route's last stop stands.
			stop = rl.stop
		}
		switch stop {
		case stopNone:
			// The route failed some other way (its address went silent,
			// or its relay refused it itself): no first flight would
			// fare better.
			rl.done = true
			continue
		case stopSilent:
			rl.silent = true
		}
		rl.stop = stop
		if v, ok := p.ladderPick(rl); ok {
			next = append(next, p.ladderCandidate(rl, v))
		}
	}
	p.ladderEnqueued(len(next))
	return next
}

// ladderLost: the first attempts of a fall-over pass for the route that
// stopped carrying, when its failure was at the hello: the route as it is
// when a variant was what had been running, else its next variant.
func (p *autoPass) ladderLost() []autoCandidate {
	if p.lost == nil || !ladderLostShaped(p.lost.cat) || p.c.ladderModeRefusedLocked(p.lost.routeID) {
		return nil
	}
	cd, ok := p.c.ladderBaseCandidateLocked(p.lost.routeID)
	if !ok {
		return nil
	}
	cd.why = AutoWhyWasConnected
	inUse := p.c.variantInUse(cd.routeID)
	rl := p.routeLadderOf(autoCandidate{routeID: cd.routeID})
	rl.base, rl.extras, rl.stop = cd, 0, stopReset
	rl.tried = map[routeVariant]bool{inUse: true}
	p.ladderState().lostCharged = inUse.zero()
	var out []autoCandidate
	if !inUse.zero() {
		rl.tried[routeVariant{}] = true
		plain := cd
		plain.ladder = true // the route's liveness failure may have cooled it
		out = append(out, plain)
	} else if v, ok := p.ladderPick(rl); ok {
		out = append(out, p.ladderCandidate(rl, v))
	}
	p.ladderEnqueued(len(out))
	return out
}

// ladderModeRefusedLocked: lifeline-strict refuses this route as a
// bulk-capable one (the same refusal autoCandidatesLocked makes).
func (c *Core) ladderModeRefusedLocked(routeID string) bool {
	if c.mode != "lifeline-strict" {
		return false
	}
	eng := budgetEngineIfPresent()
	if eng == nil || eng.AllowsBulkCapableThisSession() {
		return false
	}
	for _, b := range eng.Snapshot() {
		if b.RouteID == routeID {
			return b.BudgetTag == "bulk-capable"
		}
	}
	return false
}

// ladderLostWantedLocked: would a fall-over pass away from this route
// have a variant of it to try first (ladderLost)? Reads only; spends no
// budget. background: the pass is the engine's own (ladderRestricted).
func (c *Core) ladderLostWantedLocked(lost autoLost, background bool) bool {
	if !ladderLostShaped(lost.cat) || c.ladderModeRefusedLocked(lost.routeID) {
		return false
	}
	if !c.variantInUse(lost.routeID).zero() {
		return true
	}
	lr, ok := c.ladderRouteByID(lost.routeID)
	if !ok || !c.ladderBudgetLocked() {
		return false
	}
	restricted := background || c.mode == "lifeline-strict"
	mem, now := c.routeMemory(), nowUTC()
	for _, v := range ladderList(lr) {
		key := netmem.VariantKey(lost.routeID, v.suffix())
		m := mem[key]
		if m.VariantBlockedAt(now) || c.variantUnusable(key) || (restricted && m.Confidence(now) <= 0) {
			continue
		}
		if v.name > 0 && activeNetworkID() == netmem.SentinelUnset {
			continue
		}
		return true
	}
	return false
}

// ladderEnqueued accounts n added attempts in the pass's `total`.
func (p *autoPass) ladderEnqueued(n int) {
	if n == 0 {
		return
	}
	p.ladderState().extra += n
	p.total += n
	a := &p.c.auto
	if p.mine() {
		a.mu.Lock()
		a.total = p.total
		a.mu.Unlock()
	}
}

// ladderCandidate is the queue entry of one variant.
func (p *autoPass) ladderCandidate(rl *routeLadder, v routeVariant) autoCandidate {
	cd := rl.base
	cd.variant, cd.ladder, cd.why, cd.proved = v, true, AutoWhyLadder, false
	if v.name > 0 {
		if name, ok := rl.lr.names[v.name]; ok {
			cd.name = name
		}
	}
	return cd
}

// ladderPick chooses the route's next variant within the budget, and
// counts it.
func (p *autoPass) ladderPick(rl *routeLadder) (routeVariant, bool) {
	c, l := p.c, p.ladderState()
	limit := ladderPerRoute
	if rl.silent {
		limit = ladderPerRouteSilent
	}
	if rl.extras >= limit {
		rl.done = true
		engine.LogInfo(fmt.Sprintf("auto ladder route=%s stop=per_route", engine.LogID(rl.base.routeID)))
		return routeVariant{}, false
	}
	if l.variants >= ladderPerPass {
		rl.done = true
		engine.LogInfo(fmt.Sprintf("auto ladder route=%s stop=per_pass", engine.LogID(rl.base.routeID)))
		return routeVariant{}, false
	}
	mem := c.routeMemory()
	now := nowUTC()
	if !rl.built {
		rl.built = true
		if lr, ok := c.ladderRouteByID(rl.base.routeID); ok {
			rl.lr = lr
			rl.list = ladderOrder(ladderList(lr), mem, rl.base.routeID, now)
			if lr.namesRefused != "" {
				engine.LogInfo(fmt.Sprintf("auto ladder route=%s cover_names refused=%s", engine.LogID(rl.base.routeID), lr.namesRefused))
			}
		}
	}
	restricted := p.ladderRestricted()
	namesOK := !rl.silent && rl.base.relayHost != "" && activeNetworkID() != netmem.SentinelUnset
	for _, v := range rl.list {
		if rl.tried[v] {
			continue
		}
		key := netmem.VariantKey(rl.base.routeID, v.suffix())
		m := mem[key]
		if m.VariantBlockedAt(now) || c.variantUnusable(key) {
			continue
		}
		if restricted && m.Confidence(now) <= 0 {
			continue
		}
		if v.name > 0 && (!namesOK || !p.ladderNameAllowed(rl, v, mem, now)) {
			continue
		}
		if !c.ladderBudgetLocked() {
			rl.done = true
			engine.LogInfo(fmt.Sprintf("auto ladder route=%s stop=hourly", engine.LogID(rl.base.routeID)))
			return routeVariant{}, false
		}
		c.ladderNoteLocked()
		rl.tried[v] = true
		rl.extras++
		l.variants++
		if v.name > 0 {
			p.ladderNoteName(rl, v)
		}
		engine.LogInfo(fmt.Sprintf("auto ladder route=%s next%s", engine.LogID(rl.base.routeID), v.logField()))
		return v, true
	}
	rl.done = true
	return routeVariant{}, false
}

// namesShownLocked is the set of cover names (netmem.ShownKey) ever
// shown to relayHost from this network: the snapshot's count, and those
// first shown in this pass.
func (p *autoPass) namesShownLocked(relayHost string) map[string]bool {
	net := activeNetworkID()
	used := map[string]bool{}
	for k := range p.ladderState().newNames[relayHost] {
		used[k] = true
	}
	if st := netmemStore(); st != nil {
		for _, k := range st.CoverNamesShownTo(net, netmem.ShownKey(net, relayHost)) {
			used[k] = true
		}
	}
	return used
}

// ladderNameAllowed: may this name be shown to the route's relay from
// this network? One already shown there costs nothing new. A new one
// only while fewer than ladderNamesPerRelay were ever shown to that
// address here, and while fewer than ladderNamesBlockedStop names to it
// carry a blocked mark here.
func (p *autoPass) ladderNameAllowed(rl *routeLadder, v routeVariant, mem map[string]netmem.RouteMemory, now time.Time) bool {
	host := rl.base.relayHost
	name, ok := rl.lr.names[v.name]
	if host == "" || !ok {
		return false
	}
	used := p.namesShownLocked(host)
	if used[netmem.ShownKey(activeNetworkID(), name)] {
		return true
	}
	if len(used) >= ladderNamesPerRelay {
		engine.LogInfo(fmt.Sprintf("auto ladder route=%s skip=relay_names", engine.LogID(rl.base.routeID)))
		return false
	}
	if p.c.blockedNamesAt(host, mem, now) >= ladderNamesBlockedStop {
		engine.LogInfo(fmt.Sprintf("auto ladder route=%s skip=names_blocked", engine.LogID(rl.base.routeID)))
		return false
	}
	return true
}

// ladderNoteName counts a name as shown to the route's relay from this
// network — at once, so a pass that is abandoned still counts it.
func (p *autoPass) ladderNoteName(rl *routeLadder, v routeVariant) {
	host, name := rl.base.relayHost, rl.lr.names[v.name]
	net := activeNetworkID()
	nk := netmem.ShownKey(net, name)
	l := p.ladderState()
	if l.newNames[host] == nil {
		l.newNames[host] = map[string]bool{}
	}
	l.newNames[host][nk] = true
	if st := netmemStore(); st != nil {
		_ = st.RecordCoverNameShown(net, netmem.ShownKey(net, host), nk, nowUTC())
	}
}

// blockedNamesAt counts the name variants, of every route to relayHost,
// that carry a blocked mark on this network.
func (c *Core) blockedNamesAt(relayHost string, mem map[string]netmem.RouteMemory, now time.Time) int {
	hosts := c.routeHostsLocked()
	n := 0
	for k, m := range mem {
		routeID, suffix := netmem.SplitVariantKey(k)
		v, ok := parseVariantSuffix(suffix)
		if !ok || v.name == 0 || hosts[routeID] != relayHost || !m.VariantBlockedAt(now) {
			continue
		}
		n++
	}
	return n
}

// routeHostsLocked maps every route to its relay address (in memory,
// for the pass only; never logged).
func (c *Core) routeHostsLocked() map[string]string {
	out := map[string]string{}
	rows, err := c.store.ListRoutes()
	if err != nil {
		return out
	}
	for _, r := range rows {
		if profile, err := c.store.GetSecret("route:" + r.RouteID); err == nil {
			out[r.RouteID], _, _ = profileRelay(profile)
		}
	}
	return out
}

// ladderBudgetLocked: does this network's hourly allowance
// (sideProbesPerHour, shared with the race and the speed check) have room
// for one more variant?
func (c *Core) ladderBudgetLocked() bool {
	net, now := activeNetworkID(), nowUTC()
	n := 0
	for _, t := range c.side.perNet[net] {
		if now.Sub(t) < time.Hour {
			n++
		}
	}
	return n+1 <= sideProbesPerHour
}

// ladderNoteLocked counts one variant against the hourly allowance.
func (c *Core) ladderNoteLocked() {
	if c.side.perNet == nil {
		c.side.perNet, c.side.perRoute = map[string][]time.Time{}, map[string]time.Time{}
	}
	net := activeNetworkID()
	c.side.perNet[net] = append(c.side.perNet[net], nowUTC())
}

// candidateByID finds the pass candidate of a route among the ladder's
// routes or by reading it afresh.
func (p *autoPass) candidateByID(routeID string) (autoCandidate, bool) {
	return p.c.ladderBaseCandidateLocked(routeID)
}

// ladderBaseCandidateLocked builds the plain candidate of a route: where
// it goes and what its first flight is called (in memory only).
func (c *Core) ladderBaseCandidateLocked(routeID string) (autoCandidate, bool) {
	row, profile, ok := c.routeRowProfile(routeID)
	if !ok {
		return autoCandidate{}, false
	}
	cd := autoCandidate{routeID: routeID, family: row.TransportFamily, udp: engine.IsUDPFamily(row.TransportFamily)}
	cd.relayHost, cd.relayPort, cd.name = profileRelay(profile)
	return cd, true
}

func (c *Core) routeRowProfile(routeID string) (routestore.RouteRow, []byte, bool) {
	row, err := c.store.GetRoute(routeID)
	if err != nil {
		return routestore.RouteRow{}, nil, false
	}
	profile, err := c.store.GetSecret("route:" + routeID)
	if err != nil {
		return routestore.RouteRow{}, nil, false
	}
	return row, profile, true
}

// ladderList is every variant the route has, in the ladder's order (see
// the top of this file). Empty for a route nothing can change.
func ladderList(lr ladderRoute) []routeVariant {
	if engine.IsUDPFamily(lr.row.TransportFamily) {
		return nil
	}
	var presets []string
	if engine.RouteDesyncReason(lr.row, lr.profile) == "" {
		if o, err := engine.PackDesyncOffer(lr.row); err == nil {
			presets = append(presets, packPresetWord(o))
		}
		for _, p := range ladderPresets {
			if len(presets) == 0 || presets[0] != p {
				presets = append(presets, p)
			}
		}
	}
	names := lr.nameIDs
	var out []routeVariant
	for i := 0; i < len(presets) || i < len(names); i++ {
		if i < len(presets) {
			out = append(out, routeVariant{preset: presets[i]})
		}
		if i < len(names) {
			out = append(out, routeVariant{name: names[i]})
		}
	}
	if len(presets) > 0 {
		for _, n := range names {
			out = append(out, routeVariant{preset: presets[0], name: n})
		}
	}
	return out
}

// ladderOrder moves the variants that carried on this network before to
// the front, most confident first; the rest keep the ladder's order.
func ladderOrder(list []routeVariant, mem map[string]netmem.RouteMemory, routeID string, now time.Time) []routeVariant {
	conf := func(v routeVariant) float64 { return mem[netmem.VariantKey(routeID, v.suffix())].Confidence(now) }
	out := append([]routeVariant(nil), list...)
	sort.SliceStable(out, func(i, j int) bool { return conf(out[i]) > conf(out[j]) })
	return out
}

// ladderPreferredLocked: the variant that is the route's FIRST attempt on
// this network — one that carried here with confidence at or above
// ladderPreferConfidence, more recently than the plain route did, that
// this build could start, and that can still be built. Also returns the
// name its first flight carries (the route's own when it swaps none).
func (c *Core) ladderPreferredLocked(mem map[string]netmem.RouteMemory, lr ladderRoute, now time.Time) (routeVariant, string, bool) {
	routeID := lr.row.RouteID
	vars := netmem.VariantsOf(mem, routeID)
	if len(vars) == 0 {
		return routeVariant{}, "", false
	}
	base, baseOK := mem[routeID]
	var best routeVariant
	var bestM netmem.RouteMemory
	found := false
	for suffix, m := range vars {
		v, ok := parseVariantSuffix(suffix)
		if !ok || m.Confidence(now) < ladderPreferConfidence || c.variantUnusable(netmem.VariantKey(routeID, suffix)) {
			continue
		}
		if baseOK && base.CarriedLast() && base.CarriedSeq > m.CarriedSeq {
			continue
		}
		if !found || m.CarriedSeq > bestM.CarriedSeq {
			best, bestM, found = v, m, true
		}
	}
	if !found {
		return routeVariant{}, "", false
	}
	name, ok := variantUsable(lr, best)
	if !ok {
		return routeVariant{}, "", false
	}
	return best, name, true
}

// variantUsable: can the variant be built for the route as it is now
// (its preset can cut this outbound, its name is still on the signed
// list and eligible)? Also returns the name its first flight carries.
// No config is built: buildVariant has the final word at the attempt.
func variantUsable(lr ladderRoute, v routeVariant) (string, bool) {
	name := lr.own
	if v.name > 0 {
		n, ok := lr.names[v.name]
		if !ok {
			return "", false
		}
		name = n
	}
	if v.preset != "" {
		if engine.RouteDesyncReason(lr.row, lr.profile) != "" {
			return "", false
		}
		if _, err := variantStrategy(lr.row, v.preset); err != nil {
			return "", false
		}
	}
	return name, true
}

// routeMeasured is what the route listing says of a route on this
// network: the record of the route or of its variant, whichever was
// written last — a route that carries here only with its hello cut has
// carried here.
func routeMeasured(mem map[string]netmem.RouteMemory, routeID string) netmem.Measured {
	m := mem[routeID]
	last := func(r netmem.RouteMemory) uint64 { return max(r.CarriedSeq, r.FailedSeq) }
	for _, vm := range netmem.VariantsOf(mem, routeID) {
		if last(vm) > last(m) {
			m = vm
		}
	}
	return m.Measured()
}

// ladderCarried: a variant of a route carried (or the route as it is,
// tried again by the ladder). If the route's own attempt was charged in
// this pass, that charge is dropped and its cooldown lifted; the family
// step a family-class charge took is taken back too — unless another
// route of the family failed in this pass (that one's step stays).
func (p *autoPass) ladderCarried(cd autoCandidate) {
	if cd.variant.zero() && !cd.ladder {
		return
	}
	c := p.c
	kept := p.pending[:0]
	var own *autoCharge
	otherOfFamily := false
	for _, ch := range p.pending {
		if ch.routeID == cd.routeID {
			ch := ch
			own = &ch
			continue
		}
		if ch.family == cd.family {
			otherOfFamily = true
		}
		kept = append(kept, ch)
	}
	p.pending = kept
	var ownCat diagnostics.Category
	charged := false
	switch {
	case own != nil:
		charged, ownCat = true, own.cat
	case p.lost != nil && p.lost.routeID == cd.routeID && p.ladder != nil && p.ladder.lostCharged:
		charged, ownCat = true, p.lost.cat
	}
	if p.lost != nil && p.lost.routeID != cd.routeID && p.lost.family == cd.family {
		otherOfFamily = true
	}
	if charged {
		c.pm.Forgive(cd.routeID)
		if pathmanager.IsFamilyClass(ownCat) && !otherOfFamily {
			c.pm.ForgiveFamily(cd.family)
		}
	}
	engine.LogInfo(fmt.Sprintf("auto ladder route=%s carried%s", engine.LogID(cd.routeID), cd.variant.logField()))
}

// ladderFailed files a variant's failure for the pass to settle. Only a
// stop at the hello marks it (ladderFail.marks); a start failure has set
// the variant aside already (attemptStartFailedLocked).
func (p *autoPass) ladderFailed(cd autoCandidate, out connectOutcome) {
	l := p.ladderState()
	ob := autoObs{result: out.result, category: out.category, obs: out.obs, udp: cd.udp}
	l.failed = append(l.failed, ladderFail{
		key:   netmem.VariantKey(cd.routeID, cd.variant.suffix()),
		cat:   out.category,
		marks: helloStopOf(ob, "") == stopReset,
	})
}

// ladderSettleLocked writes the variants' failures that say something
// about the first flight to this network's memory — unless the pass
// forgave everything (nothing at all answered).
func (c *Core) ladderSettleLocked(p *autoPass, forgiven bool) {
	if p.ladder == nil || forgiven || c.shuttingDown {
		return
	}
	for _, f := range p.ladder.failed {
		if !f.marks {
			continue
		}
		c.rememberOutcome(f.key, netmem.RouteOutcome{Category: string(f.cat)})
		routeID, suffix := netmem.SplitVariantKey(f.key)
		// A variant in use that has just been stopped at its hello is
		// not what the route's next connect starts — unless the route is
		// the one this pass moved away from, whose instance is put back
		// as it was.
		if (p.lost == nil || p.lost.routeID != routeID) && routeID != p.connected &&
			c.variantInUse(routeID).suffix() == suffix {
			c.setVariantInUse(routeID, routeVariant{})
		}
	}
	p.ladder.failed = nil
}

// connectedVariant is the variant word of the route the pass connected.
func (p *autoPass) connectedVariant() string {
	if p.connected == "" {
		return ""
	}
	return p.c.variantInUse(p.connected).suffix()
}

func (p *autoPass) connectedVariantField() string {
	if w := p.connectedVariant(); w != "" {
		return " variant=" + w
	}
	return ""
}

// routeOwnNameLocked is the TLS name the route's own first flight
// presents (in memory only).
func (c *Core) routeOwnNameLocked(routeID string) (string, string) {
	cd, ok := c.ladderBaseCandidateLocked(routeID)
	if !ok {
		return "", ""
	}
	return cd.relayHost, cd.name
}
