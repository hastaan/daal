package abi

// connect_standby.go — the ladder's ADDRESS VARIANT: a route dialled at
// its standby address (optional add-ons S7; docs/optional-addons-plan.md
// §1.5 and §4 position 3; specs/optional-addons-v1.md §3.3).
//
// WHAT IT IS. The same outbound with `server` swapped for the address
// routeStandbyAddress gives — the route's open `_standby`, or the
// address inside a held standby key that opens its sealed one. Nothing
// else changes: port, name, keys and credentials are the route's own,
// and the set-route guard runs on the moved outbound before it is
// dialled (variantBodyLocked), so it can only reach an address the
// publisher signed. Never for shadowsocks (the store holds no standby
// for it, and routeStandby refuses one) and never for a CDN-fronted
// route (it has no address to stand in for).
//
// WHEN. Only for an ADDRESS-SHAPED stop of the route in this pass:
//
//   - its TCP connect timed out (autoObs.synUnanswered);
//   - its attempt is refined `address_blocked` (two names to the same
//     address and port stopped alike);
//   - its hello went unanswered, and so did that of every other TCP
//     route to the same relay address the pass tried (relaySilent).
//
// A name-shaped stop (a reset at the hello, `name_blocked`) does not
// move the address: the hello ladder runs instead. And in a fall-over
// pass, the route that was connected and stopped carrying with
// tcp_connect_timeout gets it too (ladderLostStandby).
//
// WHERE IN THE QUEUE. After every direct route of the pass and before
// the first CDN-fronted one (ladderMerge): zero-fetch before fetch, and
// a path no third party sees before the one Cloudflare sees.
//
// HOW MUCH. One per route per pass; each counts against the ladder's
// per-pass limit (ladderPerPass) and the network's hourly side-probe
// allowance (sideProbesPerHour), and none is added once either is
// spent. Unlike a hello variant it is offered in a pass the engine
// started by itself (a fall-over): the address it shows the network is
// the same relay with the same handshake, and recovering from a
// blocked address without the person doing anything is the add-on's
// whole purpose. In lifeline-strict only a standby that carried here
// before is used.
//
// MEMORY. Like any variant (`a:standby`): remembered per network when
// it carried, marked blocked for 72 h when it failed at the hello. A
// new standby address — a refreshed `_standby`, or a key accepted for a
// sealed one — rebinds the route (ladderBindOf) and the old record goes.

import (
	"encoding/json"
	"fmt"

	"daal/core/diagnostics"
	"daal/core/engine"
	"daal/core/netmem"
)

// variantStandbyWord is the standby variant's closed word (its netmem
// key suffix and `tried[].variant`). Never an address.
const variantStandbyWord = "a:standby"

// patchServer is the route's outbound with `server` replaced; nothing
// else changes.
func patchServer(profile []byte, server string) ([]byte, error) {
	var ob map[string]any
	if err := json.Unmarshal(profile, &ob); err != nil {
		return nil, errVariantUnusable
	}
	if _, ok := ob["server"].(string); !ok {
		return nil, errVariantUnusable
	}
	ob["server"] = server
	return json.Marshal(ob)
}

// relaySilent: o went unanswered at its hello, and every other TCP
// attempt of this pass to the same relay address that failed went
// unanswered at the hello or at the TCP connect too.
func (p *autoPass) relaySilent(o autoObs) bool {
	silent := func(x autoObs) bool {
		return x.stoppedAtHello() && x.obs.Timeout && !x.obs.Reset && !x.obs.Closed
	}
	if o.host == "" || !silent(o) {
		return false
	}
	for _, x := range p.obs {
		if x.host != o.host || x.udp || x.unplaced || !x.failed() {
			continue
		}
		if !silent(x) && !x.synUnanswered() {
			return false
		}
	}
	return true
}

// standbyAllowedLocked: may the pass add one more standby attempt for
// this route? The per-pass and hourly limits, and lifeline-strict's
// "only what carried here before".
func (p *autoPass) standbyAllowedLocked(routeID string) bool {
	c, l := p.c, p.ladderState()
	if l.variants >= ladderPerPass {
		engine.LogInfo(fmt.Sprintf("auto ladder route=%s standby stop=per_pass", engine.LogID(routeID)))
		return false
	}
	key := netmem.VariantKey(routeID, variantStandbyWord)
	now := nowUTC()
	m := c.routeMemory()[key]
	if m.VariantBlockedAt(now) || c.variantUnusable(key) {
		return false
	}
	if c.mode == "lifeline-strict" && m.Confidence(now) <= 0 {
		return false
	}
	if !c.ladderBudgetLocked() {
		engine.LogInfo(fmt.Sprintf("auto ladder route=%s standby stop=hourly", engine.LogID(routeID)))
		return false
	}
	return true
}

// ladderStandby returns the standby attempt of a route whose attempt o
// failed in an address-shaped way, when it has a standby and the
// budget allows. Counted at once.
func (p *autoPass) ladderStandby(rl *routeLadder, o autoObs, addressBlocked bool) (autoCandidate, bool) {
	if rl.standbyTried {
		return autoCandidate{}, false
	}
	if !(o.synUnanswered() || addressBlocked || p.relaySilent(o)) {
		return autoCandidate{}, false
	}
	p.ladderBuild(rl, p.c.routeMemory(), nowUTC())
	if rl.lr.standby == "" {
		return autoCandidate{}, false
	}
	rl.standbyTried = true
	if !p.standbyAllowedLocked(rl.base.routeID) {
		return autoCandidate{}, false
	}
	v := routeVariant{standby: true}
	if _, ok := variantUsable(rl.lr, v); !ok {
		return autoCandidate{}, false
	}
	p.c.ladderNoteLocked()
	p.ladderState().variants++
	rl.tried[v] = true
	engine.LogInfo(fmt.Sprintf("auto ladder route=%s next%s", engine.LogID(rl.base.routeID), v.logField()))
	return p.ladderCandidate(rl, v), true
}

// standbyLostShaped: the connected route's liveness failure is an
// address-shaped one (its relay address stopped answering a connect).
func standbyLostShaped(cat diagnostics.Category) bool {
	return cat == diagnostics.TCPConnectTimeout
}

// ladderLostStandbyWantedLocked: would a fall-over pass away from this
// route have its standby to try? Reads only; spends nothing.
func (c *Core) ladderLostStandbyWantedLocked(lost autoLost) bool {
	if !standbyLostShaped(lost.cat) || c.variantInUse(lost.routeID).standby {
		return false
	}
	lr, ok := c.ladderRouteByID(lost.routeID)
	if !ok || lr.standby == "" || !c.ladderBudgetLocked() {
		return false
	}
	key := netmem.VariantKey(lost.routeID, variantStandbyWord)
	m := c.routeMemory()[key]
	now := nowUTC()
	if m.VariantBlockedAt(now) || c.variantUnusable(key) {
		return false
	}
	return c.mode != "lifeline-strict" || m.Confidence(now) > 0
}

// ladderLostStandby files the standby attempt of the route the
// fall-over moved away from, when its address stopped answering.
func (p *autoPass) ladderLostStandby() {
	if p.lost == nil || !p.c.ladderLostStandbyWantedLocked(*p.lost) {
		return
	}
	cd, ok := p.c.ladderBaseCandidateLocked(p.lost.routeID)
	if !ok {
		return
	}
	cd.why = AutoWhyWasConnected
	rl := p.routeLadderOf(autoCandidate{routeID: cd.routeID})
	rl.base = cd
	if c, ok := p.ladderStandby(rl, autoObs{result: AutoResultNotCarrying, category: diagnostics.TCPConnectTimeout}, false); ok {
		p.ladderState().standbyQ = append(p.ladderState().standbyQ, c)
	}
}

// ladderMerge puts what the ladder decided into the queue: `front` at
// the head (a hello variant goes at once, alone), and the standby
// attempts waiting in standbyQ after the last direct route — before the
// first CDN-fronted candidate, or at the end.
func (p *autoPass) ladderMerge(front, queue []autoCandidate) []autoCandidate {
	l := p.ladderState()
	sb := l.standbyQ
	l.standbyQ = nil
	p.ladderEnqueued(len(front) + len(sb))
	out := append(append([]autoCandidate(nil), front...), queue...)
	if len(sb) == 0 {
		return out
	}
	at := len(out)
	for i, cd := range out {
		if cd.cdn {
			at = i
			break
		}
	}
	merged := append(append(append([]autoCandidate(nil), out[:at]...), sb...), out[at:]...)
	return merged
}
