package abi

import (
	"context"
	"fmt"
	"time"

	"daal/core/diagnostics"
	"daal/core/engine"
	"daal/core/netmem"
)

// Moving to the best route — once, when the survey of this network ends.
//
// WHY. The automatic connect keeps the first route that proves: a race
// of two, the first to answer wins (connect_race.go). That is right for
// getting the person out quickly, and it is all a connect can know. The
// survey (survey.go) then checks the other routes beside the tunnel, so
// a minute or two later the engine knows how every route does here —
// and until this file nothing used that to choose. On the real phones:
// "It did not try all possible ways to pick the best. It just got the
// first one." The speed move (connect_speed.go) only leaves a route
// that has become slow; a route that is merely worse than another was
// kept for as long as it carried.
//
// THE RULES. When a survey of the network the device is on ends (it ran
// to the end; one that was stopped says nothing), the engine compares:
//
//  1. Automatic mode only. A route the person picked by hand is never
//     left, and nothing happens while a pass is in flight.
//  2. At most once per connect (one automatic pass that connected:
//     speedState.bestGen), and never inside the hold (speedMoveHold)
//     that any move — this one or the speed move — starts. A network on
//     which the routes trade places cannot make the engine flap.
//  3. A route is CLEARLY BETTER than the running one when it proved
//     now and either
//     a. its setup time is at most bestMoveFactorPct percent of the
//     running route's latest proof (speedState.lastCheck): the race
//     probe that won the connect — a side instance, timed exactly as
//     the survey times the others — or, for a route connected alone,
//     its connect's setup time; a liveness check once one has run; or
//     b. this network's memory grades the running route worse than it
//     (netmem.GradeRank: ok against good, slow against ok; a running
//     route whose own check calls it degraded counts as slow) — and its
//     setup time just now was no worse than the running route's (the
//     larger of its latest proof and its remembered setup time here).
//     Among the clearly better, the best grade, then the shortest setup.
//  4. "Proved now": a check of THIS survey that carried, not slow, within
//     bestProvedWithin. Nothing more is sent for it: the survey's probe
//     was the proof, and probing the same relay again a few seconds
//     later would be one connection more for nothing. A route whose
//     result here is older (the survey skipped it as fresh) and whose
//     remembered setup time would pass rule 3 is proved first, as the
//     speed move proves its candidate: ONE side probe, inside the hourly
//     allowance and the per-route gap, never on a metered network, and
//     the comparison is made again with what it measured.
//  5. The move is the speed move's (moveLocked): the hand-over proves the
//     route again through the tunnel; if that fails the route is charged
//     and the one the person was on is put back as it was, never charged
//     for the detour. Reported as the verdict "moved_faster" — the page
//     and the Android service already know it as "the engine moved by
//     itself to a better route", not a failure.
//
// METERED. Rule 4's side probe is refused on a metered network, as every
// background side probe is. A route the survey proved there (its once a
// day) may still be moved to: the move is one connect, which is what the
// person asked for when they pressed the button.
const (
	// bestMoveFactorPct: a route whose setup time is at most this share
	// of the running route's latest proof is clearly better (rule 3a).
	bestMoveFactorPct = 60
	// bestProvedWithin: a survey check at least this recent is "proved
	// now" (rule 4) — the per-route side-probe gap, inside which the
	// route could not be side-probed again anyway.
	bestProvedWithin = sideProbeRouteGap
)

// bestPick is one route rule 3 may move to.
type bestPick struct {
	cd       autoCandidate
	ms, rank int
	provedAt time.Time // zero: not proved now; a side probe is needed
}

// bestRunning is what the running route is compared with.
type bestRunning struct {
	latestMs int // its latest proof (rule 3a); 0: none known
	rank     int // its grade here (rule 3b); 0: none to compare
	setupMs  int // its remembered setup time here (0: never timed)
}

// clearlyBetter is rule 3 for one route that proved in ms and is graded
// rank here.
func (b bestRunning) clearlyBetter(ms, rank int) bool {
	if b.latestMs > 0 && ms*100 <= b.latestMs*bestMoveFactorPct {
		return true
	}
	return b.rank > 0 && rank > b.rank && ms <= max(b.latestMs, b.setupMs)
}

// bestRunningLocked reads the running route's side of the comparison.
func (c *Core) bestRunningLocked(mem map[string]netmem.RouteMemory, current string, degraded bool) bestRunning {
	m := mem[c.runningMemKeyLocked(current)]
	b := bestRunning{latestMs: int(c.speed.lastCheck / time.Millisecond), rank: netmem.GradeRank(m.Grade())}
	if m.Samples > 0 {
		b.setupMs = m.SetupMs
	}
	if degraded && b.rank > netmem.GradeRank(netmem.GradeSlow) {
		b.rank = netmem.GradeRank(netmem.GradeSlow)
	}
	return b
}

// bestPickLocked chooses the route to move to, if any (rule 3, 4).
func (c *Core) bestPickLocked(r *surveyRun, current string, run bestRunning, now time.Time) (bestPick, bool) {
	cands, _, _, err := c.autoCandidatesLocked(current)
	if err != nil {
		return bestPick{}, false
	}
	var best bestPick
	found := false
	for _, cd := range cands {
		if cd.grade == netmem.GradeFailing || cd.grade == netmem.GradeUnknown || cd.repick {
			continue
		}
		p := bestPick{cd: cd, rank: netmem.GradeRank(cd.grade)}
		if pr, ok := r.proved[cd.routeID]; ok && pr.variant == cd.variant.suffix() && now.Sub(pr.at) < bestProvedWithin {
			p.ms, p.provedAt = pr.ms, pr.at
		} else if cd.side && cd.samples > 0 && cd.variant.zero() {
			// Known here, not proved now: worth one probe only if what
			// is remembered would already pass.
			p.ms = cd.measuredMs
		} else {
			continue
		}
		if !run.clearlyBetter(p.ms, p.rank) {
			continue
		}
		if !found || p.rank > best.rank || (p.rank == best.rank && (p.ms < best.ms || (p.ms == best.ms && best.provedAt.IsZero() && !p.provedAt.IsZero()))) {
			best, found = p, true
		}
	}
	return best, found
}

// autoBestMove is the survey's last step (runSurvey) when it ran to its
// end. ctx is the context the survey was started on: it ends with the
// tunnel, so a disconnect, a switch or a shutdown cancels a probe.
func (c *Core) autoBestMove(ctx context.Context, r *surveyRun) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ctx == nil || ctx.Err() != nil || c.shuttingDown || activeNetworkID() != r.net {
		return
	}
	if as, mode := c.auto.snapshot(); !mode || as != AutoStateConnected {
		// Not in charge (a route picked by hand) — or a pass is in
		// flight and the engine is its.
		return
	}
	if c.race != nil || c.recover.done != nil {
		return
	}
	st, _, running := c.check.snapshot()
	if !running || (st != RouteCheckOK && st != RouteCheckDegraded) || c.activeRoute == "" {
		return
	}
	gen := c.auto.gen
	now := nowUTC()
	if c.speed.bestGen == gen || now.Before(c.speed.holdUntil) {
		return
	}
	current, currentFamily := c.activeRoute, c.activeFamily
	run := c.bestRunningLocked(c.routeMemory(), current, st == RouteCheckDegraded)
	p, ok := c.bestPickLocked(r, current, run, now)
	if !ok {
		engine.LogInfo(fmt.Sprintf("auto best stay route=%s reason=none_clearly_better latest_ms=%d", engine.LogID(current), logMs(run.latestMs)))
		return
	}
	cd, ms := p.cd, p.ms
	// The hand-over starts what was proved: the survey's variant, or —
	// after a probe of the route's variant in use — that one (nil).
	var variant *routeVariant
	if !p.provedAt.IsZero() {
		v := cd.variant
		variant = &v
	} else {
		// Rule 4: proved first, in a side instance, as the speed move
		// proves its candidate.
		prober := c.sideProber()
		if prober == nil || !c.sideBudgetLocked(1, true) || c.sideRecentLocked(cd.routeID) || now.Before(c.speed.nextProbeAt) {
			return
		}
		_, body, err := c.prepareRouteOpts(cd.routeID, false, false)
		if err != nil {
			return
		}
		c.speed.nextProbeAt = now.Add(speedProbeBackoff)
		c.sideNoteLocked(cd.routeID)
		epoch := c.routeEpoch
		cfg := c.proofCfg
		cfg.StopAtUnreachedRelay = true
		engine.LogInfo(fmt.Sprintf("auto best probe route=%s family=%s beside=%s", engine.LogID(cd.routeID), engine.LogID(cd.family), engine.LogID(current)))
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
			engine.LogInfo(fmt.Sprintf("auto best stay route=%s reason=candidate_failed category=%s", engine.LogID(current), engine.LogID(string(cat))))
			return
		}
		ms = setupOf(took, res)
		c.rememberOutcome(cd.routeID, netmem.RouteOutcome{Carried: true, HasSetup: true, SetupMs: ms, Slow: res.Slow})
		if res.Slow || !run.clearlyBetter(ms, p.rank) {
			engine.LogInfo(fmt.Sprintf("auto best stay route=%s reason=not_clearly_better candidate_ms=%d latest_ms=%d",
				engine.LogID(current), logMs(ms), logMs(run.latestMs)))
			return
		}
	}
	// Once per connect, whatever the hand-over comes to: a hand-over
	// that fails puts the route back, and a later survey of the same
	// connect does not try again.
	c.speed.bestGen = gen
	engine.LogInfo(fmt.Sprintf("auto best move from=%s to=%s candidate_ms=%d latest_ms=%d grade=%s",
		engine.LogID(current), engine.LogID(cd.routeID), logMs(ms), logMs(run.latestMs), engine.LogID(cd.grade)))
	c.moveLocked(gen, moveFrom{routeID: current, family: currentFamily, slow: st == RouteCheckDegraded}, cd, variant, ms, "best")
}
