// relaypack_recover.go — the recovery trigger for a route that is
// "connected" and carries nothing (blackout plan §3, work item C0).
//
// THE TRAP. The relay's address is null-routed while the person is
// connected. Everything the engine did next kept them there:
//
//   - the liveness loop saw the route fail and the automatic connect
//     tried the others — all on the same dead address — and, finding
//     nothing, put the dead route's instance BACK and raised the tunnel
//     guard again (resumeFailedRouteLocked);
//   - with a route "active", the guard refused every freshness fetch
//     that was not tunnelled, and the tunnel was the dead route;
//   - each refusal doubled the scheduled poll's retry gap;
//   - nothing else ever asked for the walk.
//
// So the publisher could rotate the relay to a new address and publish
// it, and the device would never look.
//
// WHAT HAPPENS NOW. When the automatic connect is in charge of a route
// that is failed-but-running and nothing else carries — at the end of a
// fall-over pass, at the end of one that had NO other candidate (a
// one-route file; everything else cooling down), or on a later check of
// the dead route while the pass back-off still holds — and the lost
// route's pack may be walked (core/refresh FailureTriggeredDue: per pack
// and per network once per 10 min, doubling per walk that found
// nothing, capped at 1 h; a network not walked yet after 1 min; never
// more than 4 an hour or 12 a day):
//
//	1  the instance is stopped and the RECOVERY WINDOW opened: no route
//	   is active, but every ordinary fetcher (subscription, revocation,
//	   bootstrap, the scheduled freshness poll) still sees
//	   TunnelRequired() — the person has not disconnected — so the walk
//	   is the only thing that leaves the device directly;
//	2  ONE bounded direct walk of that pack's freshness mirrors runs
//	   (refresh.RefreshFailureTriggered), off the engine lock, within
//	   recoverAutoBudget. Any newer signed pack goes through the SAME
//	   verified path as a scheduled poll: publisher signature, pack id,
//	   monotonic sequence, endpoint commitment, the importer's atomic
//	   swap. Nothing is trusted because it arrived on this path;
//	3  the dead route's instance is put back and the window closed. If a
//	   new pack was applied, its routes are forgiven their cooldowns, the
//	   outage's pass back-off is reset and the route is checked at once —
//	   on its NEW endpoint. If it carries, the engine says connected; if
//	   not, the liveness loop falls over again straight away (the pass is
//	   restarted). If nothing new was found, the state is what it was
//	   before C0 — failed, running, healing by itself if the path comes
//	   back — and `relay_recovery` says what the walk found.
//
// Not in lifeline-strict: that mode is "nothing unless I ask", and only
// the person's button walks there.
//
// While the walk runs, `auto.state` is "trying" with verdict
// "looking_for_address" (the engine is still looking; a host must not
// read it as out of routes), `route_running` is false and
// `active_route` is "". engine_connect_auto returns at once with that
// verdict. Packets from other apps go into the TUN and nowhere else: the
// TUN is held, nothing reads it, so nothing leaks around it — the same
// as the seconds of any pass.
//
// THE PERSON'S BUTTON. engine_relaypack_refresh(id) runs the same walk
// on request (refresh.RefreshOnDemand: once a minute per pack, then 2,
// then 5 for presses that find nothing). With a dead route running it
// does steps 1–3 itself; with a healthy route it rides the tunnel or is
// refused (the guard, unchanged); with nothing running it dials direct.
// Every walk, the button's included, is registered here, so a
// disconnect, a route picked by hand, a newer pass or Shutdown cuts it
// off, and a second walk is never started beside it.

package abi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"daal/core/engine"
	"daal/core/refresh"
	"daal/core/routestore"
)

// recoverMaxPacks bounds one walk the person asked for: each pack costs
// up to the refresh walk budget (30 s) plus a pack download (25 s). The
// engine's own walk covers ONE pack, the lost route's.
const recoverMaxPacks = 3

// recoverAutoBudget bounds the engine's own walk end to end: the
// instance is down for all of it.
const recoverAutoBudget = 45 * time.Second

// recoverLadderBudget replaces it when the lost pack's routes hold the
// update ladder's secret and carriers member (refresh/ladder.go): the
// mirrors' 30 s, then the ladder's own 120 s. Without this the ladder
// would rarely get past its first rung on the engine's own walk.
const recoverLadderBudget = 30*time.Second + 120*time.Second

// recoverShutdownWait: how long Shutdown waits for a walk it cut off to
// let go of the store.
const recoverShutdownWait = 3 * time.Second

// relay_recovery.state / RelayPackRefreshResult.outcome — closed codes.
const (
	RecoverIdle           = "idle"
	RecoverLooking        = "looking"
	RecoverUpdated        = "updated"
	RecoverUnchanged      = "unchanged"
	RecoverUnreachable    = "unreachable"
	RecoverRejected       = "rejected"
	RecoverTunnelRequired = "tunnel_required"
	RecoverRateLimited    = "rate_limited"
	RecoverNoEndpoints    = "no_endpoints"
	RecoverUnknownPack    = "unknown_pack"
	RecoverInProgress     = "in_progress"
	RecoverCancelled      = "cancelled"
	// RecoverNotAvailable: a drill (relaypack_drill.go) of a file whose
	// routes hold no update secret or no carriers member. Nothing dialled.
	RecoverNotAvailable = "not_available"
)

// relay_recovery.trigger
const (
	RecoverTriggerFailure = "failure"
	RecoverTriggerUser    = "user"
	// RecoverTriggerDrill: the person's check of the backup routes.
	RecoverTriggerDrill = "drill"
)

// recoverState: seq / cancel / done / stops are guarded by Core.mu; the
// rest by mu, for the diagnostics readers.
type recoverState struct {
	seq    uint64
	cancel context.CancelFunc
	done   chan struct{}
	// stops counts walks ended by cancelRecoverLocked (a disconnect, a
	// route picked by hand, a newer pass, Shutdown).
	stops uint64
	// paused: the walk in flight stopped a dead route's instance and
	// opened the recovery window (refresh.SetRecoveryWindow).
	paused bool

	mu      sync.Mutex
	state   string
	trigger string
	packs   int
	outcome string
	at      time.Time
}

func (r *recoverState) block() map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	state := r.state
	if state == "" {
		state = RecoverIdle
	}
	bucket := ""
	if !r.at.IsZero() {
		bucket = routestore.HourBucket(r.at)
	}
	return map[string]any{
		// state: idle | looking | updated | unchanged | unreachable |
		// rejected | tunnel_required | rate_limited | cancelled.
		"state": state,
		// trigger: "failure" (the engine's own, the route went dead) or
		// "user" (engine_relaypack_refresh); "" when idle.
		"trigger": r.trigger,
		// packs: how many packs the walk covers.
		"packs": r.packs,
		// outcome: the core/refresh outcome code of the most telling
		// pack result ("" while looking).
		"outcome": r.outcome,
		// bucket: the hour the last walk started, hour-bucketed.
		"bucket": bucket,
	}
}

func (r *recoverState) set(state, trigger string, packs int, outcome string, at time.Time) {
	r.mu.Lock()
	r.state, r.trigger, r.packs, r.outcome = state, trigger, packs, outcome
	if !at.IsZero() {
		r.at = at
	}
	r.mu.Unlock()
}

func (r *recoverState) setResult(state, outcome string) {
	r.mu.Lock()
	r.state, r.outcome = state, outcome
	r.mu.Unlock()
}

// cancelRecoverLocked ends a walk in flight: its remaining dials are cut
// off and it puts nothing back. Called with Core.mu held, wherever the
// engine's state stops being the walk's to restore.
func (c *Core) cancelRecoverLocked() {
	if c.recover.cancel == nil {
		return
	}
	c.recover.cancel()
	c.recover.cancel = nil
	c.recover.stops++
	c.recover.setResult(RecoverCancelled, "")
	if c.recover.paused {
		// The walk is over as far as the guard is concerned. Whoever
		// stopped it decides what runs next; until they do the guard is
		// UP (a ClearRoute lowers it, a connect keeps it), so the walk's
		// remaining dials — and nothing else — are refused.
		c.recover.paused = false
		if !c.shuttingDown {
			refresh.SetTunnelRequired(true)
		}
		refresh.SetRecoveryWindow(false)
	}
}

// recoverPausedLocked: a walk in flight has stopped a dead route's
// instance for itself. Called with Core.mu held.
func (c *Core) recoverPausedLocked() bool { return c.recover.done != nil && c.recover.paused }

// autoNetworkMovedLocked: the device has been on a different network
// since the last engine-started pass of this outage ended, for long
// enough that this is not one flap — and this network has not had a
// pass of its own this outage whose back-off still holds (a phone
// flapping between two networks gets each network's own back-off, not a
// pass per flap). Called with Core.mu held.
func (c *Core) autoNetworkMovedLocked() bool {
	net := activeNetworkID()
	if c.auto.fallEndedAt.IsZero() || net == c.auto.fallNet {
		return false
	}
	if nowUTC().Sub(c.auto.fallEndedAt) < time.Minute {
		return false
	}
	if next, seen := c.auto.fallNets[net]; seen && nowUTC().Before(next) {
		return false
	}
	return true
}

// relayPackProbeLocked is a refresher bound to the store for reading
// stamps only: no dialer, no fetcher. Safe under Core.mu (unlike
// ensureRelayPackRefresh, which takes it).
func (c *Core) relayPackProbeLocked() *refresh.RelayPackRefresher {
	return &refresh.RelayPackRefresher{Store: relayPackStoreAdapter{S: c.store}, Now: nowUTC}
}

// recoverPacksLocked lists the packs a walk covers: the pack of route
// `first` first, then (for the person's button only) the others the
// device holds (only `only` when it is not ""), each with at least one
// freshness endpoint and a single pinned publisher, and only those whose
// own rate limit for this kind (failure, or the person's button) allows
// a walk now. The engine's own walk covers the lost route's pack and
// nothing else: the rest are the button's. known is how many packs there
// were before the rate limit; retryAfter the soonest a limited one may
// be walked. Called with Core.mu held; reads the store, writes nothing.
func (c *Core) recoverPacksLocked(first string, failure bool, only string) (packs []string, known int, retryAfter time.Duration) {
	if c.store == nil {
		return nil, 0, 0
	}
	probe := c.relayPackProbeLocked()
	targets, err := probe.Targets()
	if err != nil {
		return nil, 0, 0
	}
	ok := map[string]bool{}
	for _, t := range targets {
		if t.PublisherID != "" {
			ok[t.RelayPackID] = true
		}
	}
	rows, err := c.store.ListRoutes()
	if err != nil {
		return nil, 0, 0
	}
	var order []string
	seen := map[string]bool{}
	add := func(id string) {
		if id == "" || seen[id] || !ok[id] || (only != "" && id != only) {
			return
		}
		seen[id] = true
		order = append(order, id)
	}
	for _, row := range rows {
		if row.RouteID == first {
			add(row.RelayPackID)
		}
	}
	if !failure {
		for _, row := range rows {
			add(row.RelayPackID)
		}
	}
	netKey := activeNetworkID()
	for _, id := range order {
		var due bool
		var wait time.Duration
		if failure {
			due, wait = probe.FailureTriggeredDue(id, netKey)
		} else {
			due, wait = probe.OnDemandDue(id)
		}
		if !due {
			if retryAfter == 0 || wait < retryAfter {
				retryAfter = wait
			}
			continue
		}
		packs = append(packs, id)
		if len(packs) == recoverMaxPacks {
			break
		}
	}
	return packs, len(order), retryAfter
}

// recoverTicket is one walk, from the moment it was registered.
type recoverTicket struct {
	ctx     context.Context
	seq     uint64
	gen     uint64
	lost    autoLost
	packs   []string
	trigger string
	netKey  string
	done    chan struct{}
	// stops: recoverState.stops when the walk began; a different value
	// at the end means a stop ended it.
	stops uint64
	// paused: the walk stopped lost's instance (recoverBeginLocked).
	paused bool
	// verdict: the automatic connect's verdict before the walk said
	// looking_for_address; given back when the walk ends empty.
	verdict string
}

// recoverRegisterLocked registers a walk — cancellable by
// cancelRecoverLocked, visible as `in_progress` to the button and as
// `looking` in `relay_recovery` — without touching the instance. budget
// > 0 bounds the walk end to end. Called with Core.mu held and only when
// no walk is registered.
func (c *Core) recoverRegisterLocked(packs []string, trigger string, budget time.Duration) recoverTicket {
	ctx, cancel := context.WithCancel(context.Background())
	if budget > 0 {
		var cancelBudget context.CancelFunc
		ctx, cancelBudget = context.WithTimeout(ctx, budget)
		parent := cancel
		cancel = func() { cancelBudget(); parent() }
	}
	c.recover.seq++
	c.recover.cancel = cancel
	done := make(chan struct{})
	c.recover.done = done
	c.recover.paused = false
	c.recover.set(RecoverLooking, trigger, len(packs), "", nowUTC())
	return recoverTicket{ctx: ctx, seq: c.recover.seq, gen: c.auto.gen, packs: packs,
		trigger: trigger, netKey: activeNetworkID(), done: done, stops: c.recover.stops}
}

// recoverBeginLocked registers the walk, stops the instance (if any is
// running) and opens the recovery window. Called with Core.mu held.
func (c *Core) recoverBeginLocked(lost autoLost, packs []string, trigger string, budget time.Duration) recoverTicket {
	// The window first, so there is no instant in which TunnelRequired()
	// reads false while the person is still "connected".
	refresh.SetRecoveryWindow(true)
	if c.activeRoute != "" {
		c.check.abandon()
		c.routeEpoch++
		_ = c.driver.Stop()
		c.setActiveLocked("", "")
	}
	// No instance: no route is active (refresh.RouteActive false), which
	// is the one state in which the walk's own dialer may go direct.
	refresh.SetTunnelRequired(false)
	c.check.setFailed(lost.cat, false)
	t := c.recoverRegisterLocked(packs, trigger, budget)
	c.recover.paused = true
	t.lost, t.paused = lost, true
	engine.LogInfo(fmt.Sprintf("recover start route=%s trigger=%s packs=%d", engine.LogID(lost.routeID), trigger, len(packs)))
	return t
}

// autoRecoverBeginLocked is the automatic connect's call when the route
// it is in charge of is failed-but-running and nothing else carries
// (autoPassLocked, with or without other candidates; autoFallOver while
// the pass back-off holds). It starts the walk of the lost route's pack
// and reports true, or reports false and changes nothing. verdict is the
// automatic connect's verdict, given back if the walk finds nothing.
// Called with Core.mu held.
func (c *Core) autoRecoverBeginLocked(gen uint64, lost autoLost, verdict string) bool {
	if c.shuttingDown || lost.routeID == "" || c.recover.done != nil {
		// (A walk is in flight already: never a second beside it.)
		return false
	}
	if c.mode == "lifeline-strict" || hostFacts().noNetwork() {
		// lifeline-strict: nothing unless the person asks (the button
		// still works). No network at all: nothing would answer.
		return false
	}
	packs, _, _ := c.recoverPacksLocked(lost.routeID, true, "")
	if len(packs) == 0 {
		return false
	}
	budget := recoverAutoBudget
	if c.relayPackProbeLocked().LadderHeld(packs[0]) {
		budget = recoverLadderBudget
	}
	t := c.recoverBeginLocked(lost, packs, RecoverTriggerFailure, budget)
	t.gen, t.verdict = gen, verdict
	// The route the pass moved away from is still the one to put back,
	// for whoever takes over.
	c.auto.lost = lost
	a := &c.auto
	a.mu.Lock()
	a.state, a.mode, a.verdict = AutoStateTrying, true, AutoVerdictLookingForAddress
	a.trying, a.index, a.racing = "", 0, nil
	a.routeID, a.family = "", ""
	a.mu.Unlock()
	go func() {
		results := runRecoverWalk(t, true)
		c.mu.Lock()
		c.recoverFinishLocked(t, results)
		c.mu.Unlock()
		close(t.done)
	}()
	return true
}

// runRecoverWalk walks every pack of the ticket. Called WITHOUT Core.mu.
func runRecoverWalk(t recoverTicket, failure bool) []refresh.RelayPackResult {
	rp, err := ensureRelayPackRefresh()
	if err != nil {
		return nil
	}
	var out []refresh.RelayPackResult
	for _, id := range t.packs {
		if t.ctx.Err() != nil {
			break
		}
		var res refresh.RelayPackResult
		if failure {
			res, _ = rp.RefreshFailureTriggered(t.ctx, id, t.netKey)
		} else {
			res, _ = rp.RefreshOnDemand(t.ctx, id)
		}
		if res.RelayPackID == "" {
			res.RelayPackID = id
		}
		out = append(out, res)
	}
	return out
}

// recoverSummary boils a walk's per-pack results down to one closed
// code, and the refresh outcome that decided it.
func recoverSummary(results []refresh.RelayPackResult) (state, outcome string, retryAfterS int) {
	if len(results) == 0 {
		return RecoverNoEndpoints, "", 0
	}
	pick := func(st string, r refresh.RelayPackResult) (string, string, int) { return st, r.Outcome, r.RetryAfterS }
	for _, r := range results {
		// A standby key the walk brought (and the store kept) is a new
		// address for the route as much as a new pack is.
		if r.Applied || r.StandbyKeyAccepted {
			return pick(RecoverUpdated, r)
		}
	}
	for _, r := range results {
		if r.Outcome == refresh.OutcomeFreshnessUnchanged {
			return pick(RecoverUnchanged, r)
		}
	}
	for _, r := range results {
		switch r.Outcome {
		case refresh.OutcomeFreshnessRejected, refresh.OutcomeFreshnessBundleReject,
			refresh.OutcomeFreshnessRebind, refresh.OutcomeFreshnessImportFailed, refresh.OutcomeFreshnessAmbiguous:
			return pick(RecoverRejected, r)
		}
	}
	for _, r := range results {
		if r.Outcome == refresh.OutcomeFreshnessTunnel {
			return pick(RecoverTunnelRequired, r)
		}
	}
	allLimited := true
	soonest := 0
	for _, r := range results {
		if r.Outcome != refresh.OutcomeFreshnessRateLimited {
			allLimited = false
			break
		}
		if soonest == 0 || (r.RetryAfterS > 0 && r.RetryAfterS < soonest) {
			soonest = r.RetryAfterS
		}
	}
	if allLimited {
		return RecoverRateLimited, refresh.OutcomeFreshnessRateLimited, soonest
	}
	allCancelled := true
	for _, r := range results {
		if r.Outcome != refresh.OutcomeFreshnessCancelled {
			allCancelled = false
		}
	}
	if allCancelled {
		return RecoverCancelled, refresh.OutcomeFreshnessCancelled, 0
	}
	for _, r := range results {
		if r.Outcome == refresh.OutcomeFreshnessNoEndpoints {
			continue
		}
		if r.Outcome != refresh.OutcomeFreshnessRateLimited {
			return pick(RecoverUnreachable, r)
		}
	}
	return RecoverNoEndpoints, refresh.OutcomeFreshnessNoEndpoints, 0
}

// recoverFinishLocked is step 3: record what the walk found and put the
// route back — unless something else took the engine meanwhile — and
// close the recovery window. Reports whether the engine is checking the
// route on a newly applied pack. Called with Core.mu held.
func (c *Core) recoverFinishLocked(t recoverTicket, results []refresh.RelayPackResult) (rechecking bool) {
	stopped := c.recover.stops != t.stops
	mine := c.recover.seq == t.seq
	if mine {
		if c.recover.cancel != nil {
			c.recover.cancel()
		}
		c.recover.cancel, c.recover.done = nil, nil
	}
	// Whatever happens below, the window this walk opened closes when it
	// returns — AFTER the route is put back (which raises the guard), so
	// TunnelRequired() never reads false in between. A stop has closed
	// it already.
	if mine && t.paused && c.recover.paused {
		defer func() {
			c.recover.paused = false
			refresh.SetRecoveryWindow(false)
		}()
	}
	state, outcome, _ := recoverSummary(results)
	applied := map[string]bool{}
	for _, r := range results {
		if r.Applied || r.StandbyKeyAccepted {
			applied[r.RelayPackID] = true
		}
	}
	if c.shuttingDown {
		return false
	}
	if stopped && len(applied) == 0 {
		// Stopped from outside (cancelRecoverLocked already said so).
		engine.LogInfo(fmt.Sprintf("recover done route=%s result=cancelled", engine.LogID(t.lost.routeID)))
		return false
	}
	c.recover.setResult(state, outcome)
	engine.LogInfo(fmt.Sprintf("recover done route=%s result=%s outcome=%s packs_updated=%d",
		engine.LogID(t.lost.routeID), state, engine.LogID(outcome), len(applied)))

	if len(applied) > 0 && c.store != nil && c.pm != nil {
		// The failures these routes were charged with were failures of
		// the OLD endpoint. Their new one has not been tried.
		if rows, err := c.store.ListRoutes(); err == nil {
			for _, row := range rows {
				if applied[row.RelayPackID] || row.RouteID == t.lost.routeID {
					c.pm.Forgive(row.RouteID)
				}
			}
		}
	}
	if !t.paused || stopped || c.auto.gen != t.gen || c.activeRoute != "" || !mine {
		// Nothing was paused (the button beside a healthy route, or with
		// nothing running), or somebody else has the engine now; the
		// state is theirs. (A pack that was applied stays applied: it is
		// the publisher's verified word, whoever asked.)
		return false
	}
	c.auto.lost = autoLost{}
	_, mode := c.auto.snapshot()
	if len(applied) > 0 {
		// New information: this outage's pass back-off starts again.
		c.auto.resetFallLocked()
	}
	resumed := c.resumeFailedRouteLocked(t.lost.routeID, t.lost.cat)
	if mode {
		a := &c.auto
		a.mu.Lock()
		if a.state == AutoStateTrying {
			a.state = AutoStateFailed
		}
		if a.verdict == AutoVerdictLookingForAddress {
			a.verdict = t.verdict
			if a.verdict == "" {
				a.verdict = AutoVerdictAllFailed
			}
		}
		a.mu.Unlock()
	}
	switch {
	case resumed && len(applied) > 0:
		// Check it now, on its new endpoint, rather than at the next
		// recheck: a carry says connected within one round trip, and a
		// failure falls over at once (the back-off was just reset).
		c.kickLiveness()
		return true
	case !resumed && len(applied) > 0 && mode:
		// The route itself is gone (the new pack does not carry it).
		// Restart the pass over what the device holds now.
		c.autoPassLocked(nil, false)
	}
	return false
}

// RelayPackRefreshResult is what engine_relaypack_refresh returns.
type RelayPackRefreshResult struct {
	// Outcome: updated | unchanged | unreachable | rejected |
	// tunnel_required | rate_limited | no_endpoints | unknown_pack |
	// in_progress | cancelled.
	Outcome string `json:"outcome"`
	// RetryAfterS: for rate_limited, seconds until the button may walk
	// again. 0 otherwise.
	RetryAfterS int `json:"retry_after_s"`
	// RoutePaused: a route was running and carrying nothing, and its
	// instance was stopped for the walk (and put back after it).
	RoutePaused bool `json:"route_paused"`
	// Rechecking: a new pack was applied to the route that was put back
	// and the engine is checking it now; `route_check` and `auto` say
	// how that ends.
	Rechecking bool `json:"rechecking"`
	// Packs: one entry per pack walked (core/refresh RelayPackResult).
	Packs []refresh.RelayPackResult `json:"packs"`
	// Drill: for a drill only (relaypack_drill.go), per carrier class
	// {result, reason}. Absent otherwise.
	Drill map[string]refresh.DrillClass `json:"drill,omitempty"`
}

// RelayPackRefresh is engine_relaypack_refresh: look for a newer signed
// pack now. relayPackID "" means every pack the device holds that names
// a freshness endpoint (at most recoverMaxPacks).
//
// The argument may instead be a JSON object (it starts with "{"; a pack
// id never does): {"relay_pack_id":"…"} is the same as the plain id, and
// {"drill":true,"route_id":"…"} (or "relay_pack_id") is the person's
// check of that file's backup update routes (relaypack_drill.go).
//
// Blocking, bounded by the walk (≈ 55 s per pack at worst; a drill up to
// the ladder's 120 s and one pack download). The error is non-nil only
// when the engine is not initialised; everything else is in the JSON.
func RelayPackRefresh(relayPackID string) (string, error) {
	c := loadedCore()
	if c == nil {
		return "", errors.New("abi: not initialized")
	}
	var res RelayPackRefreshResult
	if req, ok, bad := parseRefreshRequest(relayPackID); bad {
		res = RelayPackRefreshResult{Outcome: RecoverUnknownPack}
	} else if ok && req.Drill {
		res = relayPackDrill(c, req.RelayPackID, req.RouteID)
	} else if ok && strings.TrimSpace(req.RelayPackID) == "" {
		// An object that names no pack (a misspelt drill key, "{}"): not
		// "every pack" — only the plain empty string means that.
		res = RelayPackRefreshResult{Outcome: RecoverUnknownPack}
	} else {
		if ok {
			relayPackID = req.RelayPackID
		}
		res = relayPackRefresh(c, relayPackID)
	}
	if res.Packs == nil {
		res.Packs = []refresh.RelayPackResult{}
	}
	body, _ := json.Marshal(res)
	return string(body), nil
}

func relayPackRefresh(c *Core, relayPackID string) RelayPackRefreshResult {
	c.mu.Lock()
	if c.shuttingDown {
		c.mu.Unlock()
		return RelayPackRefreshResult{Outcome: RecoverCancelled}
	}
	if as, _ := c.auto.snapshot(); c.recover.done != nil || as == AutoStateTrying {
		// The engine is walking already, or an automatic pass is between
		// routes (it releases the lock for each check): `relay_recovery`
		// and `auto` say how that ends. A second walk now would only
		// double what goes out — or stop an instance under the pass.
		c.mu.Unlock()
		return RelayPackRefreshResult{Outcome: RecoverInProgress}
	}
	packs, known, retryAfter := c.recoverPacksLocked(c.activeRoute, false, relayPackID)
	if len(packs) == 0 {
		c.mu.Unlock()
		switch {
		case known > 0:
			// Nothing is stopped or dialled for a press inside the
			// minute.
			return RelayPackRefreshResult{Outcome: RecoverRateLimited, RetryAfterS: int((retryAfter + time.Second - 1) / time.Second)}
		case relayPackID != "":
			return RelayPackRefreshResult{Outcome: RecoverUnknownPack}
		}
		return RelayPackRefreshResult{Outcome: RecoverNoEndpoints}
	}
	st, cat, running := c.check.snapshot()
	deadRunning := c.activeRoute != "" && running && st == RouteCheckFailed
	var t recoverTicket
	if !deadRunning {
		// Nothing running (direct is permitted), or a route that
		// carries (the tunnel, or nothing): the guard decides, as for
		// every other fetch. Registered all the same, so a disconnect or
		// a connect cuts it off and nothing else walks beside it.
		t = c.recoverRegisterLocked(packs, RecoverTriggerUser, 0)
	} else {
		// A route that carries nothing is running: it is what keeps the
		// guard up, and it is not protecting anything. Steps 1–3, as the
		// engine does them by itself.
		lost := autoLost{routeID: c.activeRoute, family: c.activeFamily, cat: cat}
		t = c.recoverBeginLocked(lost, packs, RecoverTriggerUser, 0)
		// The walk is the person's: the automatic connect, if it is in
		// charge, stays in charge, and is told the route it would put
		// back.
		if _, mode := c.auto.snapshot(); mode {
			c.auto.lost = lost
			a := &c.auto
			a.mu.Lock()
			t.verdict = a.verdict
			a.state, a.verdict = AutoStateTrying, AutoVerdictLookingForAddress
			a.mu.Unlock()
		}
	}
	c.mu.Unlock()
	results := runRecoverWalk(t, false)
	c.mu.Lock()
	stopped := c.recover.stops != t.stops
	rechecking := false
	if t.paused {
		rechecking = c.recoverFinishLocked(t, results)
	} else {
		if c.recover.seq == t.seq {
			if c.recover.cancel != nil {
				c.recover.cancel()
			}
			c.recover.cancel, c.recover.done = nil, nil
		}
		if !stopped && !c.shuttingDown {
			state, outcome, _ := recoverSummary(results)
			c.recover.setResult(state, outcome)
		}
	}
	c.mu.Unlock()
	close(t.done)
	state, _, retry := recoverSummary(results)
	if stopped && state != RecoverUpdated {
		state = RecoverCancelled
	}
	return RelayPackRefreshResult{Outcome: state, RetryAfterS: retry, RoutePaused: t.paused, Rechecking: rechecking, Packs: results}
}
