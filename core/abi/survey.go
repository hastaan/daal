package abi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"daal/core/diagnostics"
	"daal/core/engine"
	"daal/core/netmem"
)

// The survey — checking the OTHER routes of the file, beside a running
// tunnel, so that every route has a result on this network.
//
// WHY. Until this file a route got a result on a network only when it
// carried the tunnel or lost a race. A person whose automatic connect
// carried on the first candidate saw a score for that one route and an
// empty slot for every other: "why did Daal not test them all?" The
// engine had no reason to — and no other way to find out short of
// connecting on each route by hand.
//
// WHAT. Once connected (automatically OR on a route picked by hand) the
// engine proves, one at a time, the routes of the file that have no
// fresh result on this network — each in a side instance
// (connect_race.go, engine.SideProber), exactly the connection check a
// connect makes. While it runs the tunnel is not touched: no Start, no
// Stop, no route switch. What it writes into this network's memory is
// what the moves read: when a survey of the network the device is on
// ENDS (state done, not stopped) and the automatic connect is in charge,
// the engine compares what it now knows and moves ONCE to a route that
// is clearly better than the one carrying (connect_best.go); a route
// that turns slow later is the speed rules' (connect_speed.go). A route
// picked by hand is never left.
//
// THE PACING IS THE POINT (see WHY ONLY TWO in connect_race.go). A
// phone opening every route of its file in one second is a burst a
// censor can recognise, and it shows every route of the file to the
// network together. So, by itself, the engine checks ONE route at a
// time: the first surveyFirstMin..surveyFirstMax after the connect, the
// next ones surveyGapMin..surveyGapMax apart, each wait drawn at random.
// Every survey probe counts against the hourly side-probe allowance
// (sideProbesPerHour) and the per-route gap (sideProbeRouteGap), and a
// background survey leaves surveyReserve of the allowance untouched for
// the passes that need it to fall over.
//
// WHY THESE WAITS (2026-11-22). They were 20–40 s, then 30–90 s apart:
// a file of four routes took two to five minutes to be known, and
// the move to the best route (connect_best.go) waits for the survey to
// end — a person who connected and looked at the page a minute later
// was still on whichever route proved first ("it did not try all the
// ways to pick the best; it just took the first one"). Now the first
// check comes 10–20 s after the connect (the tunnel has carried the
// person's first page loads; the connect's own probes are behind it)
// and the next ones 10–25 s apart, so three other routes are known in
// about 40–95 s and the survey is over within one to two minutes.
// What makes the survey quiet is not a long wait but the shape: one
// side connection at a time, beside a tunnel that is already carrying,
// at an irregular interval — each check is the same handshake and one
// round trip a connect makes, and ten to twenty-five seconds apart is
// already slower than a browser opening tabs. The other limits are
// unchanged and still bound it: the hourly allowance (a background
// survey stops at sideProbesPerHour − surveyReserve), the per-route
// gap, the once-a-day rule on a metered network, and the result kept
// for surveyFresh — a reconnect within the hour checks nothing again.
//
// WHAT IS SKIPPED. The route the tunnel runs on; a route whose result
// on this network is newer than surveyFresh (it already shows a score);
// a route side-probed within sideProbeRouteGap; a route the automatic
// connect would not try (cooling, manual-only, unsupported, experimental
// while the gate is off); a route the driver cannot prove in a side
// instance (tor, wireguard, amneziawg, anything detoured) — reported
// "when_used", and the route list says so
// (checked_when_used, d2_summaries.go) so the page names it instead of
// leaving an empty slot.
//
// METERED NETWORKS — A DECISION, AND WHY. Background side probes are
// refused on a network the host calls metered (sideBudgetLocked): a
// fall-over goes one route at a time there and the speed move does not
// happen. The survey makes ONE exception: one check per route per
// network per surveyMeteredEvery (24 h), by itself, on a metered
// network too. In Iran most people are on mobile data, so "never on
// metered" would mean the survey never runs for most of the people it
// is for; and one connection check is a handshake and one small round
// trip — a few kilobytes, not a speed test. A route is not checked
// there again within 24 h of the survey's last check of it, nor while
// this network's memory holds a result for it from the last 24 h (that
// part survives a restart; the in-memory note does not).
//
// THE PERSON'S BUTTON (engine_survey_routes, start=1). The same survey,
// now, at the person's request: two routes at a time (a pair, never to
// the same relay address AND port, the second started raceDelay after
// the first, as a race does), metered allowed, results not older than
// surveyFresh checked again (they asked), and the per-route gap still
// applies. Routes never checked at all (no result on this network, no
// success or failure on record: a link just pasted) go first, the rest
// in the automatic connect's order.
//
// THE ALLOWANCE AND THE CEILING (2026-11-22, owner-approved). The
// person's survey is NOT bound by the hourly side-probe allowance
// (sideProbesPerHour): a person who pasted thirty links and pressed
// "check" asked for thirty checks, and twelve an hour would leave most
// of them unchecked for hours. Its probes still COUNT against the
// allowance, so the engine's own side probes (races, the speed move,
// the background survey) stay inside it for the hour after. What
// bounds the button instead is surveyUserMax checks per press: twice
// the hourly allowance, more than any Daal file holds (a relay has
// three to six routes; a person has a few relays) and enough for a
// typical pasted list, while a paste of hundreds never becomes hundreds
// of handshakes to hundreds of servers in a few minutes from one
// address. The routes over the ceiling are reported skipped with reason
// "limit"; a second press checks them (they were never checked, so they
// go first). The pacing does not change: two at a time, raceDelay
// between the two, surveyUserGapMin..Max between pairs. The background
// survey keeps the allowance and its reserve exactly as before.
//
// It works while connected (side
// instances beside the tunnel) and while not connected — side instances
// then too: a side instance holds no TUN and needs none, which is how
// the first race of an automatic pass already proves routes with
// nothing running. The sequential path (the tunnel's own instance) is
// NOT used for it: starting the tunnel's instance is connecting, and on
// Android the VPN service the shell owns has to be up for that; a
// person who asked "check my routes" did not ask to be connected. A
// route the driver cannot side-probe (naive, tor, wireguard, amneziawg,
// anything detoured) is therefore "when_used" there too.
//
// NAIVE is proved by the survey (and only the survey) in a side
// instance — its own Cronet engine; engine/side.go says why that is
// safe beside a running tunnel and why races still do not do it. What
// stays "when_used": tor (a second tor process and minutes of
// bootstrap), wireguard and amneziawg (a second handshake with the same
// key moves the peer's session at the server — the way to break a
// tunnel that is carrying), anything detoured.
//
// WHAT A RESULT RECORDS — the same as a connect, minus the punishment:
//
//   - carried: this network's memory gets the outcome with its setup
//     time (rememberOutcome), and the route store its success hour
//     (RecordSuccess, or RecordDegraded when the check called it slow)
//     — exactly what routeUpLocked writes for a route that connected.
//     health_pct, `proven` and the score on the routes card read those
//     columns (d2_summaries.go observeRoute), so the score appears.
//   - an answered failure (anything autoSilent does not call silence):
//     remembered for this network (the grade and the red disc on the
//     card) — and nothing else. No cooldown, no family ladder, no
//     durable failure row (which would feed the network signals and the
//     selector: liveFailedRoutes), nothing in the path manager. The
//     person asked nothing of the route and the tunnel is carrying —
//     connect_speed.go treats a failed speed candidate the same way.
//   - a silent failure, an instance that could not be built, a probe
//     that was stopped: nothing at all.
//
// WHEN IT STOPS. When the tunnel stops or changes hands (every
// routeCheck.abandon: a disconnect, a switch, a connect, Shutdown), on a
// network change, when an automatic pass starts a race or the speed
// move a probe (the engine needs its side slots), and on Shutdown. A
// background survey also waits — without spending anything — while the
// connected route is failing its own check, while a pass is in flight,
// and while the host says there is no network.
const (
	surveyFirstMin = 10 * time.Second
	surveyFirstMax = 20 * time.Second
	surveyGapMin   = 10 * time.Second
	surveyGapMax   = 25 * time.Second
	// surveyUserGapMin / Max: between two pairs of a survey the person
	// asked for.
	surveyUserGapMin = 1500 * time.Millisecond
	surveyUserGapMax = 4 * time.Second
	// surveyFresh: a result on this network at least this recent (by its
	// hour bucket) is not checked again by the background survey.
	surveyFresh = time.Hour
	// surveyMeteredEvery: on a metered network, a route is checked by
	// the background survey at most once in this long.
	surveyMeteredEvery = 24 * time.Hour
	// surveyReserve: side probes of the hourly allowance a background
	// survey leaves for automatic passes (two races).
	surveyReserve = 2 * raceMaxInFlight
	// surveyUserMax: the most routes one press of the person's button
	// checks (see THE ALLOWANCE AND THE CEILING).
	surveyUserMax = 2 * sideProbesPerHour
)

// surveyWaitSet is how the waits are drawn: at random, in the bounds
// above. Swapped as a whole (atomically) so a test can shorten them
// while a survey goroutine reads them.
type surveyWaitSet struct{ first, gap, user func() time.Duration }

var surveyWaits atomic.Pointer[surveyWaitSet]

func init() {
	surveyWaits.Store(&surveyWaitSet{
		first: func() time.Duration { return between(surveyFirstMin, surveyFirstMax) },
		gap:   func() time.Duration { return between(surveyGapMin, surveyGapMax) },
		user:  func() time.Duration { return between(surveyUserGapMin, surveyUserGapMax) },
	})
}

func surveyFirstDelay() time.Duration { return surveyWaits.Load().first() }
func surveyGap() time.Duration        { return surveyWaits.Load().gap() }
func surveyUserGap() time.Duration    { return surveyWaits.Load().user() }

func between(lo, hi time.Duration) time.Duration {
	if hi <= lo {
		return lo
	}
	return lo + rand.N(hi-lo)
}

// Survey states and results (the `survey` block, engine_survey_routes).
const (
	SurveyIdle     = "idle"
	SurveyWaiting  = "waiting"
	SurveyChecking = "checking"
	SurveyDone     = "done"
	SurveyStopped  = "stopped"

	SurveyResultCarried     = "carried"
	SurveyResultNotCarrying = "not_carrying"
	SurveyResultStartFailed = "start_failed"
	SurveyResultSkipped     = "skipped"
	SurveyResultWhenUsed    = "when_used"
	SurveyResultCancelled   = "cancelled"

	// Why a route was skipped (Reason). A refused route carries the
	// connect's own refusal code instead (cooldown, revoked, …) or the
	// automatic connect's (manual_only, experimental_off, …).
	SurveySkipFresh   = "fresh"
	SurveySkipRecent  = "recent"
	SurveySkipMetered = "metered"
	SurveySkipBudget  = "budget"
	SurveySkipBusy    = "busy"
	// Over the person's survey's ceiling (surveyUserMax): not checked
	// by this press; the next press checks it first.
	SurveySkipLimit = "limit"

	// What engine_survey_routes says when it did not start one.
	SurveyRefusedBusy        = "busy"
	SurveyRefusedUnsupported = "unsupported"
	SurveyRefusedRunning     = "running"
)

// SurveyRoute is one route of a survey, as reported.
type SurveyRoute struct {
	RouteID  string `json:"route_id"`
	Family   string `json:"family"`
	Result   string `json:"result"`
	Reason   string `json:"reason,omitempty"`
	Category string `json:"category,omitempty"`
	SetupMs  int    `json:"setup_ms,omitempty"`
}

// surveyRun is one survey. Its report fields are guarded by
// surveyState.mu; queue and planned by Core.mu.
type surveyRun struct {
	id     uint64
	user   bool
	net    string
	cancel context.CancelFunc

	state      string
	stopReason string
	checking   []string
	total      int
	done       int
	results    []SurveyRoute

	queue   []autoCandidate
	planned bool

	// parent: the context the survey was started on (the liveness
	// loop's, or the person's survey's own): it outlives the survey and
	// ends with the tunnel, and the move to the best route that follows
	// the survey's end runs on it (connect_best.go).
	parent context.Context
	// proved: what this survey's checks that carried measured, by route
	// — the "proved now" the move to the best route reads. Guarded by
	// Core.mu.
	proved map[string]surveyProof
}

// surveyProof is one carried survey check: its setup time, the variant
// it was made with, and when it was filed.
type surveyProof struct {
	ms      int
	variant string
	at      time.Time
}

func (r *surveyRun) trigger() string {
	if r.user {
		return "user"
	}
	return "auto"
}

// surveyState is the survey in charge and the last one's report. Its own
// lock: the network change and the diagnostics poll take it without
// Core.mu.
type surveyState struct {
	mu   sync.Mutex
	run  *surveyRun // in charge; nil when none is
	last *surveyRun // the latest, in charge or not, for the block
	ids  uint64
	// seq counts the results that changed what is remembered (carried,
	// not_carrying). A page re-reads the route list when it moves.
	seq uint64
	// metered: network|route → the background survey's last check of the
	// route on a metered network.
	metered map[string]time.Time
}

func (s *surveyState) current(r *surveyRun) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.run == r
}

// stop ends the survey in charge, if any. Safe with or without Core.mu.
func (s *surveyState) stop(reason string) {
	s.mu.Lock()
	r := s.run
	if r != nil {
		s.run = nil
		if r.stopReason == "" {
			r.stopReason = reason
		}
	}
	s.mu.Unlock()
	if r != nil {
		r.cancel()
	}
}

func (s *surveyState) noteMetered(net, routeID string, now time.Time) {
	s.mu.Lock()
	if s.metered == nil {
		s.metered = map[string]time.Time{}
	}
	s.metered[net+"|"+routeID] = now
	s.mu.Unlock()
}

func (s *surveyState) meteredRecent(net, routeID string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.metered[net+"|"+routeID]
	return ok && now.Sub(t) < surveyMeteredEvery
}

func (s *surveyState) setResult(r *surveyRun, res SurveyRoute, counts bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if counts {
		s.seq++
	}
	for i := range r.results {
		if r.results[i].RouteID == res.RouteID {
			r.results[i] = res
			return
		}
	}
	r.results = append(r.results, res)
}

// block is `survey` in the diagnostics blob and the body of
// engine_survey_routes: {state, trigger, checking, total, done, seq,
// stop_reason, results:[{route_id, family, result, reason, category,
// setup_ms}]}. From memory only; no address, name or key.
func (s *surveyState) block() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]any{"state": SurveyIdle, "trigger": "", "checking": []string{}, "total": 0, "done": 0,
		"seq": s.seq, "stop_reason": "", "results": []SurveyRoute{}}
	if r := s.last; r != nil {
		out["state"], out["trigger"], out["total"], out["done"], out["stop_reason"] = r.state, r.trigger(), r.total, r.done, r.stopReason
		out["checking"] = append([]string{}, r.checking...)
		out["results"] = append([]SurveyRoute{}, r.results...)
	}
	return out
}

// startSurveyLocked starts a survey on ctx (the liveness loop's for the
// background one: it ends with the tunnel). Called with Core.mu held.
func (c *Core) startSurveyLocked(ctx context.Context, user bool) *surveyRun {
	if c.sideProber() == nil || c.shuttingDown {
		return nil
	}
	sctx, cancel := context.WithCancel(ctx)
	s := &c.survey
	s.mu.Lock()
	s.ids++
	r := &surveyRun{id: s.ids, user: user, net: activeNetworkID(), cancel: cancel, state: SurveyWaiting, parent: ctx}
	old := s.run
	if old != nil && old.stopReason == "" {
		old.stopReason = "replaced"
	}
	s.run, s.last = r, r
	s.mu.Unlock()
	if old != nil {
		old.cancel()
	}
	go c.runSurvey(sctx, r)
	return r
}

// surveyMineLocked: is run still the survey in charge, on the network it
// began on? Called with Core.mu held.
func (c *Core) surveyMineLocked(ctx context.Context, r *surveyRun) bool {
	return ctx.Err() == nil && !c.shuttingDown && c.survey.current(r) && activeNetworkID() == r.net
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// runSurvey is one survey's goroutine. A survey that ran to its end
// (not one that was stopped) is followed, on the same goroutine, by the
// move to the best route (connect_best.go), which decides for itself
// whether one is due.
func (c *Core) runSurvey(ctx context.Context, r *surveyRun) {
	c.surveyLoop(ctx, r)
	if c.finishSurvey(ctx, r) {
		c.autoBestMove(r.parent, r)
	}
}

func (c *Core) surveyLoop(ctx context.Context, r *surveyRun) {
	wait := time.Duration(0)
	if !r.user {
		wait = surveyFirstDelay()
	}
	for {
		if !sleepCtx(ctx, wait) {
			return
		}
		batch, cfg, more := c.surveyNext(ctx, r)
		if len(batch) == 0 {
			if !more {
				return
			}
			// Not now (a pass in flight, the tunnel's route failing, no
			// network): look again after one gap, having spent nothing.
			wait = surveyGap()
			continue
		}
		res := c.surveyProbe(ctx, batch, cfg)
		c.surveyFile(ctx, r, batch, res)
		if ctx.Err() != nil {
			return
		}
		if r.user {
			wait = surveyUserGap()
		} else {
			wait = surveyGap()
		}
	}
}

// finishSurvey files the survey's end; true when it ran to its end.
func (c *Core) finishSurvey(ctx context.Context, r *surveyRun) bool {
	s := &c.survey
	s.mu.Lock()
	if s.run == r {
		s.run = nil
	}
	stopped := ctx.Err() != nil || r.stopReason != ""
	if stopped && r.stopReason == "" {
		r.stopReason = "tunnel"
	}
	if stopped {
		r.state = SurveyStopped
	} else {
		r.state = SurveyDone
	}
	r.checking = nil
	if r.total > 0 || r.user {
		// Before the lock is let go: a reader that sees "done" finds
		// the line already written.
		engine.LogInfo(fmt.Sprintf("survey done trigger=%s checked=%d planned=%d stopped=%s", r.trigger(), r.done, r.total, engine.LogID(orDash(r.stopReason))))
	}
	s.mu.Unlock()
	r.cancel()
	return !stopped
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// surveyFreshLocked: does the route have a result on this network
// recent enough to show a score?
func surveyFreshLocked(mem map[string]netmem.RouteMemory, routeID string, now time.Time, within time.Duration) bool {
	m := routeMeasured(mem, routeID)
	return m.Last > 0 && m.Last >= now.Add(-within).UTC().Truncate(time.Hour).Unix()
}

// surveyPlanLocked lists what the survey will check. Called once per
// survey, with Core.mu held, after its first wait.
func (c *Core) surveyPlanLocked(r *surveyRun) {
	// The person's own "check all routes" checks ALL their routes, also
	// while "Connect with this file" limits the automatic connect to one
	// file (connect_auto_scope.go). The engine's own survey keeps the
	// scope: it feeds the automatic connect's choices.
	scope := c.auto.scope
	if r.user {
		c.auto.scope = nil
	}
	cands, left, _, err := c.autoCandidatesLocked(c.activeRoute)
	c.auto.scope = scope
	if err != nil {
		return
	}
	mem, now := c.routeMemory(), nowUTC()
	var listed []SurveyRoute
	if r.user {
		for _, l := range left {
			listed = append(listed, SurveyRoute{RouteID: l.RouteID, Family: l.Family, Result: SurveyResultSkipped, Reason: l.Refused})
		}
	}
	for _, cd := range cands {
		switch {
		case !cd.survey:
			listed = append(listed, SurveyRoute{RouteID: cd.routeID, Family: cd.family, Result: SurveyResultWhenUsed})
		case !r.user && surveyFreshLocked(mem, cd.routeID, now, surveyFresh):
			listed = append(listed, SurveyRoute{RouteID: cd.routeID, Family: cd.family, Result: SurveyResultSkipped, Reason: SurveySkipFresh})
		default:
			r.queue = append(r.queue, cd)
		}
	}
	if r.user {
		r.queue = c.neverCheckedFirstLocked(r.queue, mem)
		if len(r.queue) > surveyUserMax {
			for _, cd := range r.queue[surveyUserMax:] {
				listed = append(listed, SurveyRoute{RouteID: cd.routeID, Family: cd.family, Result: SurveyResultSkipped, Reason: SurveySkipLimit})
			}
			r.queue = r.queue[:surveyUserMax]
		}
	}
	s := &c.survey
	s.mu.Lock()
	r.total = len(r.queue)
	r.results = append(r.results, listed...)
	s.mu.Unlock()
	if len(r.queue) > 0 || r.user {
		engine.LogInfo(fmt.Sprintf("survey start trigger=%s candidates=%d planned=%d when_used=%d", r.trigger(), len(cands), len(r.queue), countResult(listed, SurveyResultWhenUsed)))
	}
}

// neverCheckedFirstLocked puts first the routes that were never
// checked: no result on this network and no success, failure or
// degraded hour on record (a link just pasted). Stable: each part keeps
// the automatic connect's order.
func (c *Core) neverCheckedFirstLocked(q []autoCandidate, mem map[string]netmem.RouteMemory) []autoCandidate {
	rows, err := c.store.ListRoutes()
	if err != nil {
		return q
	}
	onRecord := map[string]bool{}
	for _, row := range rows {
		onRecord[row.RouteID] = strings.TrimSpace(row.LastSuccessBucket) != "" ||
			strings.TrimSpace(row.LastFailureBucket) != "" || strings.TrimSpace(row.LastDegradedBucket) != ""
	}
	var fresh, rest []autoCandidate
	for _, cd := range q {
		if !onRecord[cd.routeID] && routeMeasured(mem, cd.routeID).Last == 0 {
			fresh = append(fresh, cd)
		} else {
			rest = append(rest, cd)
		}
	}
	return append(fresh, rest...)
}

func countResult(rs []SurveyRoute, result string) int {
	n := 0
	for _, x := range rs {
		if x.Result == result {
			n++
		}
	}
	return n
}

// surveyItem is one route of a batch, with the body its side instance is
// built from.
type surveyItem struct {
	cd   autoCandidate
	body []byte
}

// surveyNext takes the next batch off the queue: one route (background)
// or a pair (asked for). more=false: the survey is over.
func (c *Core) surveyNext(ctx context.Context, r *surveyRun) (batch []surveyItem, cfg engine.ProofConfig, more bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.surveyMineLocked(ctx, r) {
		return nil, cfg, false
	}
	if !r.planned {
		r.planned = true
		c.surveyPlanLocked(r)
	}
	if len(r.queue) == 0 {
		return nil, cfg, false
	}
	if as, _ := c.auto.snapshot(); as == AutoStateTrying || c.race != nil || c.recover.done != nil || hostFacts().noNetwork() {
		return nil, cfg, true
	}
	if !r.user {
		if st, _, running := c.check.snapshot(); !running || (st != RouteCheckOK && st != RouteCheckDegraded) {
			return nil, cfg, true
		}
	}
	reserve := surveyReserve
	now := nowUTC()
	metered := hostFacts().metered == 1
	mem := c.routeMemory()
	s := &c.survey
	skip := func(cd autoCandidate, reason string) {
		s.setResult(r, SurveyRoute{RouteID: cd.routeID, Family: cd.family, Result: SurveyResultSkipped, Reason: reason}, false)
		s.mu.Lock()
		r.done++
		s.mu.Unlock()
		engine.LogInfo(fmt.Sprintf("survey skip route=%s reason=%s", engine.LogID(cd.routeID), engine.LogID(reason)))
	}
	// take pulls off the queue the first route keep() accepts that may
	// be checked now. A route that may not be checked at all on the way
	// is dropped from the queue, reported skipped.
	take := func(keep func(autoCandidate) bool) (surveyItem, bool) {
		var rest []autoCandidate
		var got surveyItem
		found := false
		for _, cd := range r.queue {
			if found || !keep(cd) {
				rest = append(rest, cd)
				continue
			}
			if c.sideRecentLocked(cd.routeID) {
				// Side-probed a moment ago (a race may have noted it
				// without ever sending it). The background survey comes
				// back to it once the gap has passed; the person's is
				// not kept waiting minutes for it.
				if r.user {
					skip(cd, SurveySkipRecent)
				} else {
					rest = append(rest, cd)
				}
				continue
			}
			if metered && !r.user && (s.meteredRecent(r.net, cd.routeID, now) || surveyFreshLocked(mem, cd.routeID, now, surveyMeteredEvery)) {
				skip(cd, SurveySkipMetered)
				continue
			}
			v := cd.variant
			_, body, err := c.prepareRouteVariant(cd.routeID, false, false, &v)
			if err != nil {
				code := ConnectRefusedOther
				var rr *routeRefusal
				if errors.As(err, &rr) {
					code = rr.code
				}
				skip(cd, code)
				continue
			}
			got, found = surveyItem{cd: cd, body: body}, true
		}
		r.queue = rest
		return got, found
	}
	// The hourly allowance binds the background survey only (THE
	// ALLOWANCE AND THE CEILING); the person's is bounded by
	// surveyUserMax, applied when it was planned.
	if !r.user && !c.sideCountOKLocked(1+reserve) {
		for _, cd := range r.queue {
			skip(cd, SurveySkipBudget)
		}
		r.queue = nil
		return nil, cfg, false
	}
	first, ok := take(func(autoCandidate) bool { return true })
	if !ok {
		return nil, cfg, len(r.queue) > 0
	}
	batch = append(batch, first)
	if r.user {
		// The partner: never the same relay address and port; another
		// transport kind first, as a race chooses.
		a := first.cd
		pick := func(wantOtherKind bool) func(autoCandidate) bool {
			return func(b autoCandidate) bool {
				if a.relayHost == "" || b.relayHost == "" || (b.relayHost == a.relayHost && b.relayPort == a.relayPort) {
					return false
				}
				return !wantOtherKind || b.udp != a.udp
			}
		}
		if second, ok := take(pick(true)); ok {
			batch = append(batch, second)
		} else if second, ok := take(pick(false)); ok {
			batch = append(batch, second)
		}
	}
	ids := make([]string, 0, len(batch))
	for _, it := range batch {
		ids = append(ids, it.cd.routeID)
	}
	c.sideNoteLocked(ids...)
	s.mu.Lock()
	r.state, r.checking = SurveyChecking, ids
	index := r.done + 1
	s.mu.Unlock()
	for k, it := range batch {
		engine.LogInfo(fmt.Sprintf("survey try route=%s family=%s index=%d total=%d trigger=%s%s",
			engine.LogID(it.cd.routeID), engine.LogID(it.cd.family), index+k, r.total, r.trigger(), it.cd.variant.logField()))
	}
	cfg = c.proofCfg
	cfg.StopAtUnreachedRelay = true
	// The survey may prove a naive route beside the tunnel; a race may
	// not (engine/side.go, cronetSideTypes).
	cfg.SideCronet = true
	return batch, cfg, true
}

// surveyProbe proves the batch in side instances. Called WITHOUT
// Core.mu. A pair's second probe starts raceDelay after the first; both
// are waited for — the survey wants both answers, not a winner.
func (c *Core) surveyProbe(ctx context.Context, batch []surveyItem, cfg engine.ProofConfig) []sideDone {
	prober := c.sideProber()
	out := make([]sideDone, len(batch))
	var wg sync.WaitGroup
	for i := range batch {
		if i > 0 && (ctx.Err() != nil || !sleepCtx(ctx, raceDelay())) {
			out[i] = sideDone{i: i, res: engine.ProofResult{Cancelled: true, Err: engine.ErrProofCancelled}}
			continue
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			t0 := time.Now()
			res, err := prober.SideProbe(ctx, batch[i].body, cfg)
			out[i] = sideDone{i: i, res: res, err: err, took: time.Since(t0)}
		}(i)
	}
	wg.Wait()
	return out
}

// surveyFile records what the batch found. See WHAT A RESULT RECORDS.
func (c *Core) surveyFile(ctx context.Context, r *surveyRun, batch []surveyItem, res []sideDone) {
	c.mu.Lock()
	defer c.mu.Unlock()
	mine := c.surveyMineLocked(ctx, r)
	s := &c.survey
	now := nowUTC()
	metered := hostFacts().metered == 1
	for i, it := range batch {
		cd, d := it.cd, res[i]
		key := netmem.VariantKey(cd.routeID, cd.variant.suffix())
		sr := SurveyRoute{RouteID: cd.routeID, Family: cd.family}
		counts := false
		switch {
		case !mine || d.res.Cancelled || (d.err == nil && ctx.Err() != nil):
			sr.Result = SurveyResultCancelled
		case errors.Is(d.err, engine.ErrSideProbeBusy):
			sr.Result, sr.Reason = SurveyResultSkipped, SurveySkipBusy
		case errors.Is(d.err, engine.ErrSideProbeUnsupported):
			sr.Result = SurveyResultWhenUsed
		case d.err != nil:
			// No instance could be built or started: nothing was
			// learned about the network (connect_speed.go does the same).
			sr.Result, sr.Category = SurveyResultStartFailed, string(diagnostics.Classify(d.err.Error()))
		case d.res.OK:
			ms := setupOf(d.took, d.res)
			c.rememberOutcome(key, netmem.RouteOutcome{Carried: true, HasSetup: true, SetupMs: ms, Slow: d.res.Slow})
			// The route store's success hour — what routeUpLocked writes
			// for a route that connected, and what the score reads.
			if d.res.Slow {
				_ = c.store.RecordDegraded(cd.routeID, string(diagnostics.PathTooSlow), now)
			} else {
				_ = c.store.RecordSuccess(cd.routeID, now)
			}
			sr.Result, sr.SetupMs, counts = SurveyResultCarried, ms, true
			if mine && !d.res.Slow {
				if r.proved == nil {
					r.proved = map[string]surveyProof{}
				}
				r.proved[cd.routeID] = surveyProof{ms: ms, variant: cd.variant.suffix(), at: now}
			}
		default:
			cat := d.res.Category()
			if !autoSilent(cat) {
				// Answered: remembered for this network. Nothing else —
				// no cooldown, no durable failure row, no family step.
				c.rememberOutcome(key, netmem.RouteOutcome{Category: string(cat)})
				counts = true
			}
			sr.Result, sr.Category = SurveyResultNotCarrying, string(cat)
		}
		if mine && metered && !r.user && sr.Result != SurveyResultCancelled {
			s.noteMetered(r.net, cd.routeID, now)
		}
		s.setResult(r, sr, counts)
		engine.LogInfo(fmt.Sprintf("survey result route=%s result=%s category=%s setup_ms=%d%s",
			engine.LogID(cd.routeID), sr.Result, engine.LogID(sr.Category), logMs(sr.SetupMs), cd.variant.logField()))
	}
	s.mu.Lock()
	r.done += len(batch)
	r.checking = nil
	if r.state == SurveyChecking {
		r.state = SurveyWaiting
	}
	s.mu.Unlock()
}

// ---- the person's button --------------------------------------------

// SurveyRoutes is engine_survey_routes. start=false reads the survey's
// report; start=true starts the survey the person asked for (see THE
// PERSON'S BUTTON) and returns at once — the report says how far it is.
// The body is the `survey` block plus {started, refused}: refused is ""
// (it started, or nothing was asked), "running" (one the person asked
// for is already in flight), "busy" (an automatic pass is trying routes)
// or "unsupported" (this driver cannot prove a route beside another).
func SurveyRoutes(start bool) (string, error) {
	c := loadedCore()
	if c == nil {
		return "", errors.New("abi: not initialized")
	}
	started, refused := false, ""
	if start {
		c.mu.Lock()
		if c.shuttingDown {
			c.mu.Unlock()
			return "", errors.New("abi: shutting down")
		}
		c.survey.mu.Lock()
		running := c.survey.run != nil && c.survey.run.user
		c.survey.mu.Unlock()
		as, _ := c.auto.snapshot()
		switch {
		case c.sideProber() == nil:
			refused = SurveyRefusedUnsupported
		case running:
			refused = SurveyRefusedRunning
		case as == AutoStateTrying || c.race != nil:
			refused = SurveyRefusedBusy
		default:
			// Its own context, registered with the connection check: a
			// connect, a switch or a disconnect stops it (abandon).
			ctx, cancel := context.WithCancel(context.Background())
			if r := c.startSurveyLocked(ctx, true); r != nil {
				c.check.mu.Lock()
				prev := c.check.cancelSurvey
				c.check.cancelSurvey = cancel
				c.check.mu.Unlock()
				if prev != nil {
					prev()
				}
				started = true
			} else {
				cancel()
				refused = SurveyRefusedUnsupported
			}
		}
		c.mu.Unlock()
		if refused != "" {
			engine.LogInfo(fmt.Sprintf("survey refused trigger=user reason=%s", refused))
		}
	}
	out := c.survey.block()
	out["started"], out["refused"] = started, refused
	body, _ := json.Marshal(out)
	return string(body), nil
}

// checkedWhenUsed: the route cannot be proved beside a running tunnel
// (no side prober, or a family engine.SideProbeable refuses), so it is
// checked only when it is used. Read from the route's stored outbound;
// false when that cannot be read (nothing is claimed).
func (c *Core) checkedWhenUsed(routeID string) bool {
	p := c.sideProber()
	if p == nil {
		return true
	}
	profile, err := c.store.GetSecret("route:" + routeID)
	if err != nil {
		return false
	}
	var ob map[string]any
	if json.Unmarshal(profile, &ob) != nil || ob == nil {
		return false
	}
	ob["tag"] = "active"
	cfg, err := json.Marshal(map[string]any{"outbounds": []any{ob}})
	if err != nil {
		return false
	}
	return !p.CanSurveyProbe(cfg)
}
