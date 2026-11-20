package abi

import (
	"context"
	"fmt"
	"time"

	"daal/core/diagnostics"
	"daal/core/engine"
	"daal/core/netmem"
)

// Moving for speed — the automatic connect leaving a route that still
// carries, because it has become slow and a better one is known.
//
// Until this file the engine moved only when a route STOPPED carrying.
// A route that crawls is kept for hours: its checks pass (slowly), and
// "degraded" is not a failure. The person sees pages that take half a
// minute and a button that says connected.
//
// Moving is not free either: the tunnel's instance is replaced, and
// every connection the person has open is reset. So the bar is high and
// every step is bounded:
//
//  1. Automatic mode only. A route picked by hand is never left.
//  2. The running route's own check has called it slow (route_check
//     "degraded", path_too_slow) speedSlowChecks times IN A ROW.
//  3. This network's memory holds another usable route that is graded
//     better than "slow" here (good / ok), or was never tried here and
//     has not failed here (unknown) — and whose remembered setup time,
//     if it has one, would pass rule 5. In the pass's own order; the
//     first.
//  4. That ONE route is proved in a side instance (connect_race.go for
//     the limits that apply: the hourly allowance, the per-route gap,
//     never on a metered network). The running route is not touched.
//     A family that cannot be side-probed is never moved to for speed.
//  5. The move is made only if the candidate proved, its own proof was
//     not slow, and its setup time — a whole fresh start, handshake
//     included — is at most speedMoveFactorPct percent of the time the
//     running route's last check took. Otherwise the engine stays.
//  6. After a probe that did not lead to a move: no further speed probe
//     for speedProbeBackoff. After a move: none for speedMoveHold, so a
//     network on which everything is slow cannot make the engine flap.
//
// A move is reported as the verdict "moved_faster" on the connected
// `auto` block. A candidate that fails its side probe is not cooled
// down (nothing was asked of it by the person and the tunnel is
// carrying); an answered failure is remembered for this network, a
// silent one is not.
//
// A MOVE THAT FAILS. The candidate proved beside the tunnel; the move
// proves it again THROUGH the tunnel, and that can fail. Then the route
// the person was on is put back exactly as a fall-over puts a route
// back — its instance started, no connection check in the way, state
// degraded, one liveness check asked for at once
// (resumeSlowRouteLocked). It is never charged for the detour.
const (
	speedSlowChecks = 2
	// speedMoveFactorPct: the candidate's setup time must be at most
	// this share of the running route's last (slow) check.
	speedMoveFactorPct = 50
	speedProbeBackoff  = 15 * time.Minute
	speedMoveHold      = 30 * time.Minute
)

// AutoVerdictMovedFaster: connected, on a route the engine moved to by
// itself because the one before had become slow and this one proved
// clearly faster.
const AutoVerdictMovedFaster = "moved_faster"

// speedState is the hold and the back-off. Guarded by Core.mu.
type speedState struct {
	nextProbeAt time.Time
	holdUntil   time.Time
	// lastCheck: how long the last check of the connected route took.
	lastCheck time.Duration
}

// speedLimitMs is the setup time a candidate must not exceed to be
// "clearly faster" than a running route whose last check took slowCheck.
func speedLimitMs(slowCheck time.Duration) int {
	return int(slowCheck/time.Millisecond) * speedMoveFactorPct / 100
}

// speedCandidateLocked picks the route to probe: see rule 3. A route
// already timed on this network at more than limitMs is not asked
// again — what is remembered already says it would not be moved to.
func (c *Core) speedCandidateLocked(current string, limitMs int) (autoCandidate, bool) {
	cands, _, _, err := c.autoCandidatesLocked(current)
	if err != nil {
		return autoCandidate{}, false
	}
	for _, cd := range cands {
		if !cd.side || c.sideRecentLocked(cd.routeID) {
			continue
		}
		if cd.samples > 0 && cd.measuredMs > limitMs {
			continue
		}
		if netmem.GradeRank(cd.grade) > netmem.GradeRank(netmem.GradeSlow) || cd.grade == netmem.GradeUnknown {
			return cd, true
		}
	}
	return autoCandidate{}, false
}

// autoSpeedMove is the liveness loop's call when the connected route
// has been slow speedSlowChecks times in a row. ctx is the loop's: a
// disconnect, a switch or a shutdown cancels the probe.
func (c *Core) autoSpeedMove(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ctx.Err() != nil || c.shuttingDown {
		return
	}
	if as, mode := c.auto.snapshot(); !mode || as == AutoStateTrying {
		// Not in charge — or a pass is in flight and the engine is its.
		return
	}
	st, _, running := c.check.snapshot()
	if st != RouteCheckDegraded || !running || c.activeRoute == "" {
		return
	}
	now := nowUTC()
	if now.Before(c.speed.holdUntil) || now.Before(c.speed.nextProbeAt) {
		return
	}
	prober := c.sideProber()
	if prober == nil || !c.sideBudgetLocked(1, true) {
		return
	}
	current, currentFamily, slowCheck := c.activeRoute, c.activeFamily, c.speed.lastCheck
	limit := speedLimitMs(slowCheck)
	cd, ok := c.speedCandidateLocked(current, limit)
	if !ok {
		c.speed.nextProbeAt = now.Add(speedProbeBackoff)
		return
	}
	_, body, err := c.prepareRouteOpts(cd.routeID, false, false)
	if err != nil {
		c.speed.nextProbeAt = now.Add(speedProbeBackoff)
		return
	}
	// Whatever this probe finds short of a move, the next one waits.
	c.speed.nextProbeAt = now.Add(speedProbeBackoff)
	// One engine-started side probe at a time: a survey in flight ends
	// here (survey.go).
	c.survey.stop("speed")
	c.sideNoteLocked(cd.routeID)
	gen, epoch := c.auto.gen, c.routeEpoch
	cfg := c.proofCfg
	cfg.StopAtUnreachedRelay = true
	engine.LogInfo(fmt.Sprintf("auto speed probe route=%s family=%s beside=%s", engine.LogID(cd.routeID), engine.LogID(cd.family), engine.LogID(current)))
	c.mu.Unlock()

	t0 := time.Now()
	res, perr := prober.SideProbe(ctx, body, cfg)
	took := time.Since(t0)

	c.mu.Lock()
	if ctx.Err() != nil || c.auto.gen != gen || c.routeEpoch != epoch || c.shuttingDown || res.Cancelled {
		return
	}
	if perr != nil || !res.OK {
		cat := diagnostics.Unknown
		if perr == nil {
			cat = res.Category()
			if !autoSilent(cat) {
				c.rememberRoute(cd.routeID, false, cat)
			}
		}
		engine.LogInfo(fmt.Sprintf("auto speed stay route=%s reason=candidate_failed category=%s", engine.LogID(current), engine.LogID(string(cat))))
		return
	}
	ms := setupOf(took, res)
	c.rememberOutcome(cd.routeID, netmem.RouteOutcome{Carried: true, HasSetup: true, SetupMs: ms, Slow: res.Slow})
	if res.Slow || ms > limit {
		engine.LogInfo(fmt.Sprintf("auto speed stay route=%s reason=not_clearly_faster candidate_ms=%d limit_ms=%d",
			engine.LogID(current), logMs(ms), logMs(limit)))
		return
	}

	// The move. From here the tunnel's instance is replaced.
	out := c.connectRouteLocked(cd.routeID, connectOpts{auto: true, noMemory: true})
	if c.auto.gen != gen || out.result == AutoResultCancelled {
		return
	}
	if out.result != AutoResultCarried {
		// It proved beside the tunnel and not through it. Charge it,
		// and go back to the route that was carrying.
		if out.result == AutoResultNotCarrying || out.result == AutoResultStartFailed {
			c.autoSettleLocked([]autoCharge{{routeID: cd.routeID, family: cd.family, cat: out.category}}, true, nil, false)
		}
		engine.LogInfo(fmt.Sprintf("auto speed back route=%s reason=move_failed category=%s", engine.LogID(current), engine.LogID(string(out.category))))
		// The way back is the way a fall-over takes: the instance is
		// started again with no pass/fail check in front of it. A fresh
		// connection check of a route KNOWN to be slow can run out its
		// budget, and that used to charge the route the person was
		// connected on with a failure the engine's own detour caused —
		// and leave nothing behind the tunnel at all.
		if c.resumeSlowRouteLocked(current) {
			return
		}
		// Its instance would not even start. The other routes are tried
		// with this one as the route to put back when nothing carries.
		c.autoPassLocked(&autoLost{routeID: current, family: currentFamily, cat: diagnostics.PathTooSlow}, false)
		return
	}
	c.speed.holdUntil = nowUTC().Add(speedMoveHold)
	a := &c.auto
	a.mu.Lock()
	a.state, a.mode = AutoStateConnected, true
	a.trying, a.index, a.racing = "", 0, nil
	a.routeID, a.family, a.verdict = cd.routeID, cd.family, AutoVerdictMovedFaster
	a.tried = []AutoTried{
		{RouteID: current, Family: currentFamily, Result: AutoResultCarried, Category: string(diagnostics.PathTooSlow), Why: AutoWhyWasConnected},
		{RouteID: cd.routeID, Family: cd.family, Result: AutoResultCarried, Why: cd.why, SetupMs: ms},
	}
	a.mu.Unlock()
	engine.LogInfo(fmt.Sprintf("auto moved_faster from=%s to=%s family=%s setup_ms=%d", engine.LogID(current), engine.LogID(cd.routeID), engine.LogID(cd.family), logMs(ms)))
}
