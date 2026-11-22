// ladder.go — the update ladder after the ordinary mirrors
// (docs/update-ladder-v2.md §2 "Walk order after a route dies",
// specs/update-ladder-v2.md §4).
//
// THE WALK. 0 → 5 → 1 → 2 → 4 → 3 → (6 is not built) → the app asks
// the person for a file or a code.
//
//   - Rung 0 (a standby address or CDN route already in the pack) needs
//     no fetch: it is the engine's connect ladder (core/abi), not this
//     file.
//   - Rung 5 is today's walk (relaypack_refresh.go walkEndpoints): the
//     ordinary mirrors in random order, then the Apps Script mirror
//     through the Google front (door 1 of rung 2, frontmirror.go). It
//     is unchanged.
//   - Only when that walk produced no verified document does this file
//     run the carriers (carrier.go) in rung order 1 (git tag) → 2 (the
//     Google front doors) → 4 (the other readers of the same write) →
//     3 (DNS), each rung's carriers by name.
//
// WHEN. Only from the two unscheduled kinds (the engine's failure walk
// and the person's button), and only when the walk dials DIRECT — that
// is, with no route up (googleAllowed: the same rule as the Google
// door). Never from the scheduled poll, never through a tunnel. The
// dialer the carriers get is the walk's routeDownDialer, which refuses
// every dial once a route comes up; the ladder also asks RouteActive()
// before each host and stops (without a strike) when one is.
//
// LIMITS OF ONE LADDER WALK (per pack): at most ladderMaxTCP TCP
// connections and ladderMaxDNS DNS questions (a carrier whose declared
// Cost does not fit what is left is skipped), ladderBudget of time,
// one carrier per class, one reader of rung 4 (chosen by
// HKDF(u, device salt, UTC day): pickReader), at most two connections to
// Google's front counting the mirror walk's Apps Script door, 2–10 s
// between hosts, and it stops at the first note that verifies as newer.
// A micro-only carrier is not asked when every sealed route already
// keeps its key. A class that failed twice on this
// network is skipped for ladderStrikeHold. The walk's floors and
// per-network stamps (relaypack_recover.go) are untouched: the ladder
// runs inside the walk they already allowed.
//
// WHAT IS TRUSTED. Nothing, because of where it came from:
//   - a micro note is used only if the route's SIGNED sealed standby
//     Matches it, and then only offered to the engine's standby-key
//     store (StandbyKeySink), which checks it again against every held
//     route;
//   - a full note is a daal-refresh-v2 container: it must name the slot
//     a held secret gives for that carrier and epoch, then it goes
//     through parseRefreshContainer and verifyWalkDocument — the very
//     code a mirror's document goes through (signature chain, pinned
//     publisher, pack id, sequence high-water mark, not_after) — and
//     its pack and standby key through the same applyBundle gate and
//     sink as the Google door's.
//
// AN OLDER FILE. With no update secret or no carriers member held for
// the pack's routes, the ladder does nothing and the walk is exactly
// today's.
//
// WHAT IS RECORDED. Per class, one coarse word (reached / nothing_new /
// failed), in RelayPackResult.Ladder and as an audit row
// "update_ladder" "<class>:<word>". Never a carrier's host, a
// repository, a zone, a note name or an address.

package refresh

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math/big"
	"sort"
	"strconv"
	"sync"
	"time"

	"daal/bundle-go/bundle"
	"daal/core/bootstrap"
)

// Limits of one ladder walk (study §2).
const (
	ladderMaxTCP     = 8
	ladderMaxDNS     = 6
	ladderBudget     = 120 * time.Second
	ladderGapMin     = 2 * time.Second
	ladderGapMax     = 10 * time.Second
	ladderStrikes    = 2
	ladderStrikeHold = 6 * time.Hour
)

// Audit kind and the per-class words.
const (
	auditKindLadder = "update_ladder"

	// LadderReached: a note from this class verified as newer.
	LadderReached = "reached"
	// LadderNothingNew: the class answered, with nothing newer (filler,
	// no note yet, a note that did not verify or was not newer).
	LadderNothingNew = "nothing_new"
	// LadderFailed: the network failed (a strike against the class on
	// this network).
	LadderFailed = "failed"
)

// OutcomeFreshnessStandbyKey: no document verified, but a micro note
// from the ladder carried a standby key the engine's store kept for a
// held route (RelayPackResult.StandbyKeyAccepted is set).
const OutcomeFreshnessStandbyKey = "ok_standby_key"

// ladderStrikesKey is the secrets_kv key of the strike record. It is
// per device, not per pack: a class blocked on a network is blocked for
// every pack.
const ladderStrikesKey = "update-ladder:strikes"

// ladderRungOrder is the walk position of each rung; a rung missing
// here (6, not built) is never walked.
var ladderRungOrder = map[int]int{RungGitTag: 0, RungGoogle: 1, RungReaders: 2, RungDNS: 3}

// ladderAllowed: the walks that may run the ladder.
func ladderAllowed(kind refreshKind, viaTunnel bool) bool {
	return googleAllowed(kind, viaTunnel)
}

// ladderOrder filters cs to the walked rungs and sorts them in walk
// order, then by name.
func ladderOrder(cs []Carrier) []Carrier {
	out := make([]Carrier, 0, len(cs))
	for _, c := range cs {
		if c == nil {
			continue
		}
		if _, ok := ladderRungOrder[c.Info().Rung]; ok {
			out = append(out, c)
		}
	}
	sort.SliceStable(out, func(a, b int) bool {
		ia, ib := out[a].Info(), out[b].Info()
		if pa, pb := ladderRungOrder[ia.Rung], ladderRungOrder[ib.Rung]; pa != pb {
			return pa < pb
		}
		return ia.Name < ib.Name
	})
	return out
}

func (r *RelayPackRefresher) ladderCarriers() []Carrier {
	if r.LadderCarriers != nil {
		return r.LadderCarriers
	}
	return RegisteredCarriers()
}

func (r *RelayPackRefresher) ladderBudget() time.Duration {
	if r.LadderBudget > 0 {
		return r.LadderBudget
	}
	return ladderBudget
}

// ladderGap is the wait before the next host: uniform in [2 s, 10 s]
// from crypto/rand (a fixed gap is a fingerprint). A failed RNG gives
// the floor.
func (r *RelayPackRefresher) ladderGap() time.Duration {
	if r.LadderGap != nil {
		return r.LadderGap()
	}
	return drawLadderGap()
}

func drawLadderGap() time.Duration {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(ladderGapMax-ladderGapMin)+1))
	if err != nil {
		return ladderGapMin
	}
	return ladderGapMin + time.Duration(n.Int64())
}

// ---- what the device holds for a pack --------------------------------

// ladderHeld is what the pack's routes hold for the ladder.
type ladderHeld struct {
	secrets  []*bundle.UpdateSecret
	carriers *bundle.UpdateCarriers
	standby  *bundle.Standby
	// sealed: the routes with a sealed standby, by id (for "already held").
	sealed map[string]*bundle.Standby
}

// loadLadderHeld reads, for the pack's routes in id order, the held
// update secrets (deduplicated, newest first route by route), the first
// valid carriers member and the first sealed standby. nil when the pack
// holds no secret or no carriers member naming a carrier: an older file,
// and the ladder is a no-op.
func (r *RelayPackRefresher) loadLadderHeld(relayPackID string) *ladderHeld {
	if r.Store == nil || relayPackID == "" {
		return nil
	}
	rows, err := r.Store.ListRoutes()
	if err != nil {
		return nil
	}
	var ids []string
	for _, row := range rows {
		if row.RelayPackID == relayPackID && row.RouteID != "" {
			ids = append(ids, row.RouteID)
		}
	}
	sort.Strings(ids)
	h := &ladderHeld{sealed: map[string]*bundle.Standby{}}
	seen := map[[bundle.UpdateSecretLen]byte]bool{}
	for _, id := range ids {
		if raw, err := r.Store.GetSecret(bundle.UpdateSecretStoreKey(id)); err == nil && len(raw) > 0 {
			for _, u := range bundle.ParseHeldUpdateSecrets(raw) {
				if !seen[u.Secret] {
					seen[u.Secret] = true
					h.secrets = append(h.secrets, u)
				}
			}
		}
		if h.carriers == nil {
			if raw, err := r.Store.GetSecret(bundle.UpdateCarriersStoreKey(id)); err == nil && len(raw) > 0 {
				if c, err := bundle.ParseUpdateCarriersJSON(raw); err == nil && !c.Empty() {
					h.carriers = c
				}
			}
		}
		if raw, err := r.Store.GetSecret(bundle.StandbyStoreKey(id)); err == nil && len(raw) > 0 {
			if sb, err := bundle.ParseStandbyJSON(raw); err == nil && sb.Mode == bundle.StandbyModeSealed {
				h.sealed[id] = sb
				if h.standby == nil {
					h.standby = sb
				}
			}
		}
	}
	if len(h.secrets) == 0 || h.carriers == nil {
		return nil
	}
	return h
}

// LadderHeld reports whether the pack's routes hold what the ladder
// needs (an update secret and a carriers member naming a carrier), so a
// caller can give the walk the time the ladder takes. Reads the store
// only.
func (r *RelayPackRefresher) LadderHeld(relayPackID string) bool {
	return r.loadLadderHeld(relayPackID) != nil
}

// standbyKeyHeld: every held route whose sealed standby k opens already
// keeps exactly k (nothing new to offer). false when no route matches.
func (r *RelayPackRefresher) standbyKeyHeld(h *ladderHeld, k bundle.StandbyKeyBytes) bool {
	matched := 0
	for id, sb := range h.sealed {
		if !sb.Matches(k) {
			continue
		}
		matched++
		raw, err := r.Store.GetSecret(bundle.StandbyKeyStoreKey(id))
		if err != nil || subtle.ConstantTimeCompare(raw, k[:]) != 1 {
			return false
		}
	}
	return matched > 0
}

// ---- strikes ------------------------------------------------------------

// ladderStrike is one class's failures on one network.
type ladderStrike struct {
	N  int    `json:"n"`
	At string `json:"at"`
}

type ladderStrikeNet struct {
	Tag     string                  `json:"t"`
	Classes map[string]ladderStrike `json:"c"`
}

type ladderStrikeRecord struct {
	V    int               `json:"v"`
	Nets []ladderStrikeNet `json:"nets,omitempty"`
}

// ladderStrikeMu serialises the strike record's read-change-write: two
// packs may walk at once (each holds only its own pack lock).
var ladderStrikeMu sync.Mutex

func (r *RelayPackRefresher) loadStrikes() ladderStrikeRecord {
	rec := ladderStrikeRecord{V: 1}
	raw, err := r.Store.GetSecret(ladderStrikesKey)
	if err != nil || len(raw) == 0 {
		return rec
	}
	var got ladderStrikeRecord
	if json.Unmarshal(raw, &got) != nil {
		return rec
	}
	got.V = 1
	return got
}

func (r *RelayPackRefresher) saveStrikes(rec ladderStrikeRecord) {
	rec.V = 1
	if body, err := json.Marshal(rec); err == nil {
		_ = r.Store.PutSecret(ladderStrikesKey, body)
	}
}

// struck: the class failed ladderStrikes times on this network and the
// last failure is less than ladderStrikeHold ago. A stamp in the future
// (a clock that jumped back) holds nothing.
func (rec ladderStrikeRecord) struck(tag, class string, now time.Time) bool {
	for _, n := range rec.Nets {
		if n.Tag != tag {
			continue
		}
		s, ok := n.Classes[class]
		if !ok || s.N < ladderStrikes {
			return false
		}
		el, ok := sinceStamp(s.At, now)
		return ok && el < ladderStrikeHold
	}
	return false
}

// note records one class's result on a network: a failure adds a
// strike (and restarts the hold), anything that answered clears it. The
// network moves to the front; at most failureNetsMax are kept.
func (r *RelayPackRefresher) noteStrike(tag, class string, failed bool, now time.Time) {
	ladderStrikeMu.Lock()
	defer ladderStrikeMu.Unlock()
	rec := r.loadStrikes()
	cur := ladderStrikeNet{Tag: tag, Classes: map[string]ladderStrike{}}
	rest := rec.Nets[:0:0]
	for _, n := range rec.Nets {
		if n.Tag == tag {
			for k, v := range n.Classes {
				cur.Classes[k] = v
			}
			continue
		}
		rest = append(rest, n)
	}
	if failed {
		s := cur.Classes[class]
		s.N++
		s.At = now.UTC().Format(time.RFC3339)
		cur.Classes[class] = s
	} else {
		if _, had := cur.Classes[class]; !had {
			return // nothing to clear: no write
		}
		delete(cur.Classes, class)
	}
	nets := []ladderStrikeNet{}
	if len(cur.Classes) > 0 {
		nets = append(nets, cur)
	}
	nets = append(nets, rest...)
	if len(nets) > failureNetsMax {
		nets = nets[:failureNetsMax]
	}
	rec.Nets = nets
	r.saveStrikes(rec)
}

// ---- the walk -----------------------------------------------------------

// ladderResult is what one ladder walk found.
type ladderResult struct {
	// walk.doc is set when a full note verified: as newer, or (fallback)
	// as the publisher's current statement when nothing newer came.
	walk walkResult
	// standbyAccepted: a micro note's key was kept by the store.
	standbyAccepted bool
	// tried: how many carriers were fetched.
	tried int
	// classes: class → LadderReached / LadderNothingNew / LadderFailed.
	classes map[string]string
}

// runLadder walks the carriers for one pack (see the file comment). It
// is called by refresh() only when the mirror walk found no verified
// document and ladderAllowed holds; dialer is that walk's direct dialer
// and googleConns the connections it already made to Google's front.
func (r *RelayPackRefresher) runLadder(ctx context.Context, t RelayPackTarget, rec freshnessRecord,
	dialer bootstrap.Dialer, now time.Time, networkKey string, googleConns int) ladderResult {

	var out ladderResult
	if r.Store == nil || RouteActive() || ctx.Err() != nil {
		return out
	}
	held := r.loadLadderHeld(t.RelayPackID)
	if held == nil {
		return out
	}
	resolver := ""
	if r.Resolver != nil {
		resolver = r.Resolver()
	}
	env := &CarrierEnv{
		RelayPackID: t.RelayPackID,
		Secrets:     held.secrets,
		Carriers:    held.carriers,
		Standby:     held.standby,
		Now:         now,
		Dialer:      dialer,
		Resolver:    resolver,
	}
	tag := netTag(networkKey)
	strikes := r.loadStrikes()
	// A micro note can only yield the key matching the held commitment;
	// when every sealed route keeps it already, a micro-only carrier can
	// tell this phone nothing, and its questions would only go out.
	keyKept := r.sealedKeysKept(held)

	lctx, cancel := context.WithTimeout(ctx, r.ladderBudget())
	defer cancel()

	usedClass := map[string]bool{}
	tcp, dns := 0, 0
	// eligible: the carrier may be fetched now (no cost spent yet).
	eligible := func(c Carrier) bool {
		info := c.Info()
		if usedClass[info.Class] || strikes.struck(tag, info.Class, now) {
			return false
		}
		if info.Kinds == NoteMicro && keyKept {
			return false
		}
		if tcp+info.Cost.TCP > ladderMaxTCP || dns+info.Cost.DNS > ladderMaxDNS {
			return false
		}
		if info.Class == ClassGoogle && googleConns+info.Cost.TCP > ladderMaxGoogle {
			return false
		}
		return c.Usable(env)
	}
	order := ladderOrder(r.ladderCarriers())
	var readerPick Carrier
	readerPicked := false
	var fallback *walkResult
	stopped := false
	for _, c := range order {
		info := c.Info()
		if info.Rung == RungReaders {
			// One reader of rung 4 per walk, chosen per device and day
			// (study §4.4), so a phone does not always ask the same host.
			if !readerPicked {
				readerPicked = true
				var cands []Carrier
				for _, x := range order {
					if x.Info().Rung == RungReaders && eligible(x) {
						cands = append(cands, x)
					}
				}
				readerPick = r.pickReader(cands, held, now)
			}
			if c != readerPick {
				continue
			}
		} else if !eligible(c) {
			continue
		}
		if RouteActive() || lctx.Err() != nil {
			break
		}
		if !sleepCtx(lctx, r.ladderGap()) || RouteActive() {
			break
		}
		usedClass[info.Class] = true
		fctx := WithDNSQuestionBudget(lctx, ladderMaxDNS-dns)
		tcp += info.Cost.TCP
		dns += info.Cost.DNS
		if info.Class == ClassGoogle {
			googleConns += info.Cost.TCP
		}
		out.tried++
		var hint *DNSEpochHint
		if info.Label == bundle.NoteCarrierDNS {
			hint = r.loadDNSHint(t.RelayPackID, now)
			fctx = WithDNSEpochHint(fctx, hint)
		}
		notes, err := c.Fetch(fctx, env)
		if hint != nil && !errors.Is(err, ErrCarrierUnconfigured) {
			r.saveDNSHint(t.RelayPackID, hint)
		}
		switch {
		case errors.Is(err, ErrCarrierUnconfigured):
			// Not a try: nothing went out (the carrier's contract).
			usedClass[info.Class] = false
			tcp -= info.Cost.TCP
			dns -= info.Cost.DNS
			if info.Class == ClassGoogle {
				googleConns -= info.Cost.TCP
			}
			out.tried--
			continue
		case err != nil:
			if ctx.Err() != nil || lctx.Err() != nil || RouteActive() || errors.Is(err, ErrTunnelRequired) {
				// Cut off (the caller, the ladder's own time, a route
				// coming up): nothing was learned about the class.
				stopped = true
			} else {
				r.noteStrike(tag, info.Class, true, now)
				out.setClass(info.Class, LadderFailed)
			}
		default:
			r.noteStrike(tag, info.Class, false, now)
			newer, fb, accepted := r.weighNotes(notes, info, env, held, t, rec, now)
			if accepted {
				out.standbyAccepted = true
			}
			if newer != nil || accepted {
				out.setClass(info.Class, LadderReached)
				switch {
				case newer != nil:
					out.walk = *newer
				case fb != nil:
					out.walk = *fb
				case fallback != nil:
					out.walk = *fallback
				}
				return out
			}
			if fb != nil && fallback == nil {
				fallback = fb
			}
			out.setClass(info.Class, LadderNothingNew)
		}
		if stopped {
			break
		}
	}
	if fallback != nil {
		out.walk = *fallback
	}
	return out
}

// sealedKeysKept: every route of the pack with a sealed standby already
// keeps the key its commitment opens (so no micro note can be news).
// false when the pack holds no sealed standby.
func (r *RelayPackRefresher) sealedKeysKept(h *ladderHeld) bool {
	if len(h.sealed) == 0 {
		return false
	}
	for id, sb := range h.sealed {
		raw, err := r.Store.GetSecret(bundle.StandbyKeyStoreKey(id))
		if err != nil || len(raw) != len(bundle.StandbyKeyBytes{}) {
			return false
		}
		var k bundle.StandbyKeyBytes
		copy(k[:], raw)
		if !sb.Matches(k) {
			return false
		}
	}
	return true
}

// ---- the rung-4 reader of the walk ----------------------------------------

// ladderDeviceKey holds 16 random bytes made on first use, never sent:
// the device's part of the rung-4 choice.
const ladderDeviceKey = "update-ladder:device"

// ladderMaxGoogle: connections to Google's front in one walk, the Apps
// Script door's included (study §4.2).
const ladderMaxGoogle = 2

// ladderDay is the UTC day number of t, for the rung-4 choice. Tests
// may replace the clock the choice reads through r.Now.
func ladderDay(t time.Time) uint64 { return uint64(t.UTC().Unix() / 86400) }

// deviceSalt reads (or makes and keeps) the device's salt. nil when the
// store cannot keep one: the choice then falls back to the first reader.
func (r *RelayPackRefresher) deviceSalt() []byte {
	if raw, err := r.Store.GetSecret(ladderDeviceKey); err == nil && len(raw) == 16 {
		return raw
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil
	}
	if r.Store.PutSecret(ladderDeviceKey, salt) != nil {
		return nil
	}
	return salt
}

// pickReader chooses one of cands: HKDF(newest held secret,
// "ladder-reader" ‖ device salt ‖ UTC day) mod n.
func (r *RelayPackRefresher) pickReader(cands []Carrier, h *ladderHeld, now time.Time) Carrier {
	switch len(cands) {
	case 0:
		return nil
	case 1:
		return cands[0]
	}
	salt := r.deviceSalt()
	if salt == nil || len(h.secrets) == 0 {
		return cands[0]
	}
	return cands[readerIndex(h.secrets[0].Secret, salt, ladderDay(now), len(cands))]
}

func readerIndex(u [bundle.UpdateSecretLen]byte, salt []byte, day uint64, n int) int {
	info := make([]byte, 0, len("ladder-reader")+len(salt)+8)
	info = append(info, "ladder-reader"...)
	info = append(info, salt...)
	var d [8]byte
	binary.BigEndian.PutUint64(d[:], day)
	info = append(info, d[:]...)
	out := bundle.UpdateHKDF(u[:], info, 8)
	return int(binary.BigEndian.Uint64(out) % uint64(n))
}

// ---- the DNS epoch hint -----------------------------------------------------

// ladderDNSHintKey: per pack, the DNS epoch found absent at its first
// question (decimal). While it equals the current epoch the next walk
// asks e−1 first, so a reveal written before the weekly rollover stays
// readable within the walk's six questions.
func ladderDNSHintKey(relayPackID string) string { return "update-ladder:dns-absent:" + relayPackID }

func (r *RelayPackRefresher) loadDNSHint(relayPackID string, now time.Time) *DNSEpochHint {
	h := &DNSEpochHint{}
	e := bundle.NoteEpochAt(bundle.NoteCarrierDNS, now)
	if raw, err := r.Store.GetSecret(ladderDNSHintKey(relayPackID)); err == nil && len(raw) > 0 {
		if v, err := strconv.ParseUint(string(raw), 10, 64); err == nil && v == e && e > 0 {
			h.PreferOlder = true
		}
	}
	return h
}

// saveDNSHint: a walk that asked e−1 first clears the hint (the next
// walk returns to e); one that found e absent at its first question
// records it.
func (r *RelayPackRefresher) saveDNSHint(relayPackID string, h *DNSEpochHint) {
	switch {
	case h.PreferOlder:
		_ = r.Store.PutSecret(ladderDNSHintKey(relayPackID), []byte{})
	case h.Absent && h.AbsentEpoch > 0:
		_ = r.Store.PutSecret(ladderDNSHintKey(relayPackID), []byte(strconv.FormatUint(h.AbsentEpoch, 10)))
	}
}

func (l *ladderResult) setClass(class, word string) {
	if l.classes == nil {
		l.classes = map[string]string{}
	}
	l.classes[class] = word
}

// weighNotes checks what one carrier returned, in order. newer: a full
// note that verified and says something new (to be applied by the walk);
// fallback: one that verified and says nothing new; accepted: a micro
// note's key the store kept.
func (r *RelayPackRefresher) weighNotes(notes []Note, info CarrierInfo, env *CarrierEnv, held *ladderHeld,
	t RelayPackTarget, rec freshnessRecord, now time.Time) (newer, fallback *walkResult, accepted bool) {

	for _, n := range notes {
		switch n.Kind {
		case NoteMicro:
			if info.Kinds&NoteMicro != 0 && r.acceptMicro(n, env, held, t.RelayPackID) {
				return nil, fallback, true
			}
		case NoteFull:
			if info.Kinds&NoteFull == 0 {
				continue
			}
			w, isNew := r.verifyFullNote(n, info, env, held, t, rec, now)
			if w == nil {
				continue
			}
			if isNew {
				return w, fallback, false
			}
			if fallback == nil {
				fallback = w
			}
		}
	}
	return nil, fallback, false
}

// acceptMicro: the candidate opens the SIGNED sealed standby, is not
// already kept on every route it opens, and the engine's store kept it.
func (r *RelayPackRefresher) acceptMicro(n Note, env *CarrierEnv, held *ladderHeld, relayPackID string) bool {
	if env.Standby == nil || !env.Standby.Matches(n.StandbyKey) {
		return false
	}
	if r.StandbyKeys == nil || r.standbyKeyHeld(held, n.StandbyKey) {
		return false
	}
	k := n.StandbyKey
	got, err := r.StandbyKeys.AcceptStandbyKey(relayPackID, k[:])
	return err == nil && got > 0
}

// verifyFullNote: the slot is one a held secret gives for this label at
// a reader epoch, the container parses naming it, and its document
// verifies exactly as a mirror's. isNew: a higher sequence, another
// bundle, or a standby key the routes do not keep yet.
func (r *RelayPackRefresher) verifyFullNote(n Note, info CarrierInfo, env *CarrierEnv, held *ladderHeld,
	t RelayPackTarget, rec freshnessRecord, now time.Time) (*walkResult, bool) {

	if n.Slot == "" || len(n.Container) == 0 {
		return nil, false
	}
	slotOK := false
	for _, try := range env.Tries(info.Label, NoteFull) {
		if subtle.ConstantTimeCompare([]byte(try.Name), []byte(n.Slot)) == 1 {
			slotOK = true
		}
	}
	if !slotOK {
		return nil, false
	}
	c, err := parseRefreshContainer(n.Container, n.Slot)
	if err != nil || c.freshness == nil {
		return nil, false
	}
	doc, err := r.verifyWalkDocument(c.freshness, t, rec, now)
	if err != nil {
		return nil, false
	}
	w := &walkResult{doc: doc, raw: c.freshness, container: c, viaLadder: true}
	isNew := doc.Sequence > rec.HighWaterSequence || !equalHex(doc.CurrentBundleSHA256, rec.CurrentBundleSHA256)
	if !isNew && c.standbyKey != "" {
		if k, err := bundle.ParseStandbyKeyText(c.standbyKey); err == nil {
			isNew = held.standby != nil && held.standby.Matches(k) && !r.standbyKeyHeld(held, k)
		}
	}
	return w, isNew
}

// recordLadder writes one audit row per class the ladder reached.
func (r *RelayPackRefresher) recordLadder(relayPackID string, classes map[string]string, now time.Time) {
	names := make([]string, 0, len(classes))
	for c := range classes {
		names = append(names, c)
	}
	sort.Strings(names)
	for _, c := range names {
		recordAudit(r.Store, auditKindLadder, relayPackID, c+":"+classes[c], 0, false, now)
	}
}
