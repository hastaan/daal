package abi

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"daal/core/diagnostics"
	"daal/core/engine"
	"daal/core/netmem"
	"daal/core/refresh"
)

// Racing — two candidates of an automatic pass checked beside each
// other.
//
// WHY ONLY TWO. Several dead routes in a row cost the person the sum of
// their timeouts (four dead routes: 29 s on the rig). Opening every
// route at the same moment would fix that and make something worse: one
// phone starting four different handshakes to one relay address in one
// second is a burst a censor can recognise, and every route in the file
// would be seen — and could be blocked — together. Two at a time halves
// the wait and looks like what any dual-stack client does.
//
// THE RULES (each a constant below, each with a test):
//
//   - At most raceMaxInFlight (2) probes in flight, ever. The driver
//     refuses a third regardless (engine.MaxSideProbes).
//   - Never two probes to the same relay address AND port number.
//     Preferred partner: the other transport kind (one stream, one
//     datagram) and another port; a route that failed here recently is
//     not pulled ahead of one that did not (pickRacePartner).
//   - The second probe starts raceDelayMin..raceDelayMax after the
//     first, at random: two first flights in the same millisecond is a
//     signature, and a first probe that proves inside the delay means
//     the second is never sent at all.
//   - The route that carried on this network last is tried ALONE first
//     (autoPassLocked). With one candidate left it is tried alone.
//   - A route side-probed within sideProbeRouteGap is not side-probed
//     again; a network that has had sideProbesPerHour side probes in the
//     last hour gets no more. Either way the pass goes on one route at a
//     time through the tunnel's own instance — it is never refused.
//   - On a network the host calls metered, the ENGINE starts no side
//     probe by itself (a fall-over pass is sequential there; the speed
//     move does not happen). A pass the person asked for may race.
//
// WHICH ROUTES RACE: those the driver can prove in a side instance —
// engine.SideProbeable: outbound types vless, vmess, trojan,
// shadowsocks, anytls, hysteria, hysteria2, tuic, http, socks, not
// detoured. In family terms: vless-reality, websocket-tls, hysteria2,
// tuic, shadowsocks, anytls race; naive, tor-bridge, wireguard,
// amneziawg and anything else never do and are tried alone, in order.
//
// THE HAND-OVER. A side instance holds no TUN, so the winner is then
// started as the tunnel's instance by the same connectRouteLocked every
// connect uses, and proved again through it. That second proof is the
// cost of racing: one more round trip on the route that just answered
// (its setup time again — 0.3 s on the phone pass). The alternative,
// promoting the side instance, would mean attaching a TUN inbound and
// the refresh inlet to a running sing-box, which it cannot do.
//
// WHAT A RACE RECORDS. Each route is charged at most once per pass: a
// side probe that failed is that route's failure (a candidate's: no
// family ladder, settled with the pass — autoSettleLocked); a probe
// that was STOPPED because the other proved first records nothing; a
// winner whose hand-over then fails is charged with that failure and
// nothing else.
const (
	raceMaxInFlight = engine.MaxSideProbes
	// raceDelayMin / raceDelayMax: the wait before the second probe of a
	// pair starts, drawn uniformly from [min, max).
	raceDelayMin = 150 * time.Millisecond
	raceDelayMax = 450 * time.Millisecond
	// sideProbesPerHour: side probes per network per hour, races and the
	// speed check together. In memory; a restart forgets the count.
	sideProbesPerHour = 12
	// sideProbeRouteGap: a route side-probed this recently is not
	// side-probed again.
	sideProbeRouteGap = 3 * time.Minute
)

// raceDelay draws the second probe's delay. A variable so a test can
// make a race deterministic.
var raceDelay = func() time.Duration {
	return raceDelayMin + rand.N(raceDelayMax-raceDelayMin)
}

// sideLimits is the accounting behind the two limits. Guarded by
// Core.mu.
type sideLimits struct {
	perNet   map[string][]time.Time
	perRoute map[string]time.Time
}

// sideProber is the driver's side-probe half, or nil when it has none.
func (c *Core) sideProber() engine.SideProber {
	p, _ := c.driver.(engine.SideProber)
	return p
}

// sideBudgetLocked: may n more side probes be started on this network
// now? background: the engine is starting them by itself.
func (c *Core) sideBudgetLocked(n int, background bool) bool {
	if c.sideProber() == nil || c.shuttingDown {
		return false
	}
	if background && hostFacts().metered == 1 {
		return false
	}
	net, now := activeNetworkID(), nowUTC()
	kept := c.side.perNet[net][:0]
	for _, t := range c.side.perNet[net] {
		if now.Sub(t) < time.Hour {
			kept = append(kept, t)
		}
	}
	if c.side.perNet != nil {
		c.side.perNet[net] = kept
	}
	return len(kept)+n <= sideProbesPerHour
}

// sideRecentLocked: was this route side-probed within sideProbeRouteGap?
func (c *Core) sideRecentLocked(routeID string) bool {
	t, ok := c.side.perRoute[routeID]
	return ok && nowUTC().Sub(t) < sideProbeRouteGap
}

// sideNoteLocked counts a side probe of each route against both limits.
func (c *Core) sideNoteLocked(routeIDs ...string) {
	if c.side.perNet == nil {
		c.side.perNet, c.side.perRoute = map[string][]time.Time{}, map[string]time.Time{}
	}
	net, now := activeNetworkID(), nowUTC()
	for _, id := range routeIDs {
		c.side.perNet[net] = append(c.side.perNet[net], now)
		c.side.perRoute[id] = now
	}
}

// raceHandle is the race in flight; Core.race points at it so whoever
// takes the engine can stop it.
type raceHandle struct{ cancel context.CancelFunc }

// cancelRaceLocked stops the race in flight, if any. Called with
// Core.mu held by everything that takes the engine away from a pass.
func (c *Core) cancelRaceLocked() {
	if c.race != nil {
		c.race.cancel()
		c.race = nil
	}
}

// racePartnerLocked returns the index in queue of the candidate to
// check beside queue[0], or -1 when queue[0] is to be tried alone.
func (c *Core) racePartnerLocked(queue []autoCandidate, background bool) int {
	if len(queue) < 2 || !queue[0].side || queue[0].relayHost == "" || c.sideRecentLocked(queue[0].routeID) {
		return -1
	}
	if !c.sideBudgetLocked(raceMaxInFlight, background) {
		return -1
	}
	return pickRacePartner(queue, c.sideRecentLocked)
}

// pickRacePartner chooses, among queue[1:], the route to check beside
// queue[0]: -1 when there is none.
//
// Never: a route that cannot be side-probed, one probed a moment ago,
// one whose server is not known, one to the SAME address and port
// number as queue[0]. Among the rest, in this order: a route that did
// not fail here recently before one that did; the other transport kind
// (2) and another port (1); the earlier in the pass's order.
func pickRacePartner(queue []autoCandidate, recent func(string) bool) int {
	a := queue[0]
	best, bestScore, bestFailed := -1, -1, false
	for j := 1; j < len(queue); j++ {
		b := queue[j]
		if !b.side || b.relayHost == "" || recent(b.routeID) {
			continue
		}
		if b.relayHost == a.relayHost && b.relayPort == a.relayPort {
			continue
		}
		score := 0
		if b.udp != a.udp {
			score += 2
		}
		if b.relayPort != a.relayPort {
			score++
		}
		failed := b.why == AutoWhyFailedHere && a.why != AutoWhyFailedHere
		if best < 0 || (bestFailed && !failed) || (failed == bestFailed && score > bestScore) {
			best, bestScore, bestFailed = j, score, failed
		}
	}
	return best
}

// setupOf is the setup time of one attempt: from starting the route to
// its first completed round trip.
func setupOf(took time.Duration, res engine.ProofResult) int {
	if res.Elapsed > took {
		took = res.Elapsed
	}
	return int(took / time.Millisecond)
}

// logMs rounds a duration for a log line.
func logMs(ms int) int { return (ms + 5) / 10 * 10 }

// routeRunningLocked: is an instance for routeID the tunnel's instance
// right now?
func (c *Core) routeRunningLocked(routeID string) bool {
	_, _, running := c.check.snapshot()
	return running && routeID != "" && c.activeRoute == routeID
}

// ---- one pass ---------------------------------------------------------

// autoPass is the state of one automatic pass (autoPassLocked). Every
// method is called with Core.mu held.
type autoPass struct {
	c          *Core
	gen        uint64
	lost       *autoLost
	total      int
	background bool
	relayNo    map[string]int

	obs     []autoObs
	tried   []AutoTried
	pending []autoCharge

	connected, connectedFamily string
	// answered: something carried a round trip in this pass, in a side
	// instance if nowhere else. A pass in which that happened did not
	// find "a device with no usable network" (autoSettleLocked).
	answered bool
	// cancelled: somebody else took the engine.
	cancelled bool
	// noRace: the driver refused a side probe; the rest of the pass is
	// one route at a time.
	noRace bool
}

func (p *autoPass) relayOf(cd autoCandidate) int {
	if cd.relayHost == "" {
		return 0
	}
	if n, ok := p.relayNo[cd.relayHost]; ok {
		return n
	}
	p.relayNo[cd.relayHost] = len(p.relayNo) + 1
	return p.relayNo[cd.relayHost]
}

// mine: is this pass still the one in charge?
func (p *autoPass) mine() bool { return p.c.auto.gen == p.gen && !p.c.shuttingDown }

// record adds one route's result to the pass and to the `auto` block.
func (p *autoPass) record(cd autoCandidate, t AutoTried, o autoObs) {
	t.RouteID, t.Family, t.Why, t.Relay = cd.routeID, cd.family, cd.why, p.relayOf(cd)
	o.result, o.udp, o.host, o.port, o.name = t.Result, cd.udp, cd.relayHost, cd.relayPort, cd.name
	o.id, o.racedWith = cd.routeID, t.RacedWith
	o.category = diagnostics.Category(t.Category)
	p.tried = append(p.tried, t)
	p.obs = append(p.obs, o)
	engine.LogInfo(fmt.Sprintf("auto result route=%s result=%s category=%s setup_ms=%d",
		engine.LogID(cd.routeID), t.Result, engine.LogID(t.Category), logMs(t.SetupMs)))
	if !p.mine() {
		return
	}
	a := &p.c.auto
	a.mu.Lock()
	a.tried = append([]AutoTried(nil), p.tried...)
	a.mu.Unlock()
}

// abandon: the pass is no longer in charge. The routes in flight are
// reported cancelled; nothing is written to the `auto` block.
func (p *autoPass) abandon(cds ...autoCandidate) {
	for _, cd := range cds {
		engine.LogInfo(fmt.Sprintf("auto result route=%s result=%s category=", engine.LogID(cd.routeID), AutoResultCancelled))
		p.tried = append(p.tried, AutoTried{RouteID: cd.routeID, Family: cd.family, Result: AutoResultCancelled, Why: cd.why, Relay: p.relayOf(cd)})
		p.obs = append(p.obs, autoObs{result: AutoResultCancelled})
	}
	p.cancelled = true
}

// outcome files what one attempt through the tunnel's own instance came
// to (seq, and the hand-over of a race's winner).
func (p *autoPass) outcome(cd autoCandidate, out connectOutcome, racedWith string, setupMs int) {
	t := AutoTried{Result: out.result, Category: string(out.category), Refused: out.refused, RacedWith: racedWith}
	if out.result == AutoResultCarried {
		t.SetupMs = setupMs
	}
	p.record(cd, t, autoObs{obs: out.obs})
	switch out.result {
	case AutoResultCarried:
		p.connected, p.connectedFamily, p.answered = cd.routeID, cd.family, true
	case AutoResultNotCarrying, AutoResultStartFailed:
		p.pending = append(p.pending, autoCharge{routeID: cd.routeID, family: cd.family, cat: out.category})
	}
}

// seq tries one candidate alone, through the tunnel's own instance.
func (p *autoPass) seq(cd autoCandidate, index int) {
	c, a := p.c, &p.c.auto
	a.mu.Lock()
	a.trying, a.index, a.racing = cd.routeID, index, nil
	a.mu.Unlock()
	engine.LogInfo(fmt.Sprintf("auto try route=%s family=%s index=%d total=%d",
		engine.LogID(cd.routeID), engine.LogID(cd.family), index, p.total))

	// cd.proved: a side probe of this very pass has already measured it.
	out := c.connectRouteLocked(cd.routeID, connectOpts{auto: true, noMemory: cd.proved})

	if c.auto.gen != p.gen || out.result == AutoResultCancelled {
		p.abandon(cd)
		return
	}
	p.outcome(cd, out, "", out.setupMs)
}

// sideDone is one probe of a race.
type sideDone struct {
	i    int
	res  engine.ProofResult
	err  error
	took time.Duration
}

// runRace runs the two probes and returns their results by index, and
// which one proved first (-1: neither). Called WITHOUT Core.mu.
//
// The first probe to prove ends the race: the context is cancelled and
// the other is stopped at once. A probe that fails ends nothing — the
// other one is waited for.
func runRace(ctx context.Context, cancel context.CancelFunc, prober engine.SideProber, bodies [2][]byte, cfg engine.ProofConfig, delay time.Duration) (out [2]sideDone, winner int) {
	ch := make(chan sideDone, 2)
	probe := func(i int) {
		t0 := time.Now()
		res, err := prober.SideProbe(ctx, bodies[i], cfg)
		ch <- sideDone{i: i, res: res, err: err, took: time.Since(t0)}
	}
	go probe(0)
	go func() {
		t := time.NewTimer(delay)
		defer t.Stop()
		select {
		case <-ctx.Done():
			// The first proved (or the pass was abandoned) before this
			// one was due: it is never sent.
			ch <- sideDone{i: 1, res: engine.ProofResult{Cancelled: true, Err: engine.ErrProofCancelled}}
		case <-t.C:
			probe(1)
		}
	}()
	winner = -1
	for n := 0; n < 2; n++ {
		d := <-ch
		out[d.i] = d
		if d.err == nil && d.res.OK && winner < 0 {
			winner = d.i
			cancel()
		}
	}
	return out, winner
}

// stopForRaceLocked stops whatever the tunnel's instance is doing for a
// route that is not this pass's (a connect by hand that was still being
// checked when the pass took over) — what the first candidate's own
// start did before a pass could begin with side probes.
func (c *Core) stopForRaceLocked() {
	c.check.abandon()
	c.routeEpoch++
	_ = c.driver.Stop()
	refresh.SetTunnelRequired(false)
	c.setActiveLocked("", "")
	c.check.set(RouteCheckNone, "")
}

// race checks a and b beside each other and, when one proves, starts
// the tunnel's instance on it. It returns the candidates that go back to
// the front of the queue: none, unless a probe was stopped or refused
// before it had an answer and the pass goes on — or the winner did not
// carry through the tunnel and the other one had proved too: that one
// is a route known to answer from here, and is tried next, alone.
func (p *autoPass) race(a, b autoCandidate, index int) (requeue []autoCandidate) {
	c := p.c
	prober := c.sideProber()
	cds := [2]autoCandidate{a, b}
	var bodies [2][]byte
	refused := false
	for i, cd := range cds {
		_, body, err := c.prepareRouteOpts(cd.routeID, false, false)
		if err != nil {
			// A cooldown tripped since the listing (the family's, by an
			// earlier candidate).
			code := ConnectRefusedOther
			var rr *routeRefusal
			if errors.As(err, &rr) {
				code = rr.code
			}
			p.record(cd, AutoTried{Result: AutoResultRefused, Refused: code}, autoObs{})
			refused = true
			continue
		}
		bodies[i] = body
	}
	if refused {
		for i, cd := range cds {
			if bodies[i] != nil {
				requeue = append(requeue, cd)
			}
		}
		return requeue
	}

	// The route this pass is moving away from, when its instance is
	// still the tunnel's: it is left exactly as it is while the others
	// are probed beside it.
	lostRunning := p.lost != nil && c.routeRunningLocked(p.lost.routeID)
	if !lostRunning && c.activeRoute != "" {
		c.stopForRaceLocked()
	}
	c.sideNoteLocked(a.routeID, b.routeID)
	ctx, cancel := context.WithCancel(context.Background())
	c.cancelRaceLocked()
	handle := &raceHandle{cancel: cancel}
	c.race = handle
	au := &c.auto
	au.mu.Lock()
	au.trying, au.index, au.racing = a.routeID, index, []string{a.routeID, b.routeID}
	au.mu.Unlock()
	engine.LogInfo(fmt.Sprintf("auto race first=%s second=%s index=%d total=%d",
		engine.LogID(a.routeID), engine.LogID(b.routeID), index, p.total))
	cfg := c.proofCfg
	cfg.StopAtUnreachedRelay = true
	delay := raceDelay()
	c.mu.Unlock()

	res, winner := runRace(ctx, cancel, prober, bodies, cfg, delay)
	cancel()

	c.mu.Lock()
	if c.race == handle {
		c.race = nil
	}
	if !p.mine() {
		p.abandon(a, b)
		return nil
	}
	au.mu.Lock()
	au.racing = nil
	au.mu.Unlock()
	if p.lost != nil && lostRunning {
		if st, _, running := c.check.snapshot(); running && c.activeRoute == p.lost.routeID && (st == RouteCheckOK || st == RouteCheckDegraded) {
			// The route this pass was moving away from carried again
			// while the others were being probed (its own liveness
			// check said so). It is the tunnel's instance and every
			// open connection is on it: stay.
			for i, cd := range cds {
				if res[i].err == nil && res[i].res.OK {
					c.rememberOutcome(cd.routeID, netmem.RouteOutcome{Carried: true, HasSetup: true, SetupMs: setupOf(res[i].took, res[i].res), Slow: res[i].res.Slow})
				}
			}
			p.record(autoCandidate{routeID: p.lost.routeID, family: p.lost.family, why: AutoWhyWasConnected},
				AutoTried{Result: AutoResultCarried}, autoObs{unplaced: true})
			p.connected, p.connectedFamily, p.answered = p.lost.routeID, p.lost.family, true
			return nil
		}
	}

	// What each probe found. Everything but the winner first, so `tried`
	// reads in the order things were learned.
	var stopped, alsoProved []autoCandidate
	alsoProvedMs := 0
	for i, cd := range cds {
		if i == winner {
			continue
		}
		other := cds[1-i].routeID
		d := res[i]
		switch {
		case errors.Is(d.err, engine.ErrSideProbeBusy) || errors.Is(d.err, engine.ErrSideProbeUnsupported):
			// The driver would not probe it. Nothing was tried; it is
			// tried alone, and so is everything after it.
			p.noRace = true
			stopped = append(stopped, cd)
		case d.err != nil:
			// No instance could be built or started for it.
			cat := diagnostics.Classify(d.err.Error())
			p.sideFailed(cd, cat, d.err.Error(), lostRunning)
			p.record(cd, AutoTried{Result: AutoResultStartFailed, Category: string(cat), RacedWith: other}, autoObs{second: i == 1})
			p.pending = append(p.pending, autoCharge{routeID: cd.routeID, family: cd.family, cat: cat})
		case d.res.Cancelled:
			stopped = append(stopped, cd)
		case d.res.OK:
			// It proved too, a moment after the winner. Its measurement
			// is kept now; what the pass SAYS of it waits for the
			// winner's hand-over (below).
			alsoProvedMs = setupOf(d.took, d.res)
			c.rememberOutcome(cd.routeID, netmem.RouteOutcome{Carried: true, HasSetup: true, SetupMs: alsoProvedMs, Slow: d.res.Slow})
			p.answered = true
			cd.proved = true
			alsoProved = append(alsoProved, cd)
		default:
			cat := d.res.Category()
			p.sideFailed(cd, cat, proofFailureText(d.res), lostRunning)
			p.record(cd, AutoTried{Result: AutoResultNotCarrying, Category: string(cat), RacedWith: other}, autoObs{obs: d.res.Observation, second: i == 1})
			p.pending = append(p.pending, autoCharge{routeID: cd.routeID, family: cd.family, cat: cat})
		}
	}
	if winner < 0 {
		return stopped
	}

	w, other := cds[winner], cds[1-winner]
	ms := setupOf(res[winner].took, res[winner].res)
	c.rememberOutcome(w.routeID, netmem.RouteOutcome{Carried: true, HasSetup: true, SetupMs: ms, Slow: res[winner].res.Slow})
	p.answered = true
	engine.LogInfo(fmt.Sprintf("auto race winner=%s family=%s setup_ms=%d", engine.LogID(w.routeID), engine.LogID(w.family), logMs(ms)))
	// The hand-over: the same attempt every connect makes, on the route
	// that just proved. Its measurement is already kept.
	out := c.connectRouteLocked(w.routeID, connectOpts{auto: true, noMemory: true})
	if c.auto.gen != p.gen || out.result == AutoResultCancelled {
		p.abandon(w)
		return nil
	}
	p.outcome(w, out, other.routeID, ms)
	if p.connected == "" {
		// Proved beside the tunnel and not through it. The route is
		// charged with that failure; a probe that was stopped for its
		// sake was never finished and is tried now. One that had PROVED
		// too goes first: it is the one route of this pass known to
		// answer from here, and dropping it left the person
		// disconnected with a working route untried (and a pass that
		// connected nothing reading "carried").
		return append(alsoProved, stopped...)
	}
	for _, cd := range alsoProved {
		// Not the route the tunnel runs on: it is not what connected.
		p.record(cd, AutoTried{Result: AutoResultCarried, RacedWith: w.routeID, SetupMs: alsoProvedMs}, autoObs{sideOnly: true})
	}
	for _, cd := range stopped {
		p.record(cd, AutoTried{Result: AutoResultStopped, RacedWith: w.routeID}, autoObs{})
	}
	return nil
}

// sideFailed charges a route with a failure seen in a side instance: the
// cooldown a failed candidate gets, never the family's ladder, and the
// durable row left to the pass (autoSettleLocked) — exactly what a
// candidate that failed through the tunnel's instance gets.
//
// lostRunning: the route the pass is moving away from is still the
// tunnel's instance. Then nothing about the tunnel's own state is
// touched — its check, its record, its place in the path manager.
func (p *autoPass) sideFailed(cd autoCandidate, cat diagnostics.Category, reason string, lostRunning bool) {
	c := p.c
	if !lostRunning {
		// Nothing is running: the engine's record of "the last connect
		// failed, and why" is this route's, as it would be had it been
		// tried through the tunnel's instance.
		c.routeDownOptsLocked(cd.routeID, cd.family, cat, reason, true, true)
		return
	}
	engine.LogInfo(fmt.Sprintf("route down route=%s family=%s result=failed category=%s running=false side=true",
		engine.LogID(cd.routeID), engine.LogID(cd.family), engine.LogID(string(cat))))
	c.pm.Resume(cd.routeID, cd.family)
	c.pm.FailedCandidate(cd.routeID, cd.family, cat)
	c.pm.Resume(p.lost.routeID, p.lost.family)
}
