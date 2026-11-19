package abi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"daal/core/diagnostics"
	"daal/core/engine"
	"daal/core/netmem"
	"daal/core/pathmanager"
	"daal/core/refresh"
	"daal/core/routestore"
)

// The automatic connect — engine_connect_auto.
//
// A person inside a hostile network holds a file with several routes
// and no idea what the words on them mean. Until this file existed the
// only way to connect was to pick one of those words: the engine could
// rank routes (core/pathmanager), remember networks (core/netmem), check
// that a route carries (route_check.go) and say why one failed
// (core/diagnostics), and nothing used the four together.
//
// ConnectAuto is that: it lists every route that may be tried, puts
// them in an order it can explain, and connects each in turn with the
// SAME attempt engine_set_route makes (connectRouteLocked) until one
// carries a round trip. Then it stays in charge ("mode"): when the
// connected route stops carrying, the liveness loop calls autoFallOver
// and the next candidate is tried without the host doing anything.
//
// The TUN has one reader: only one route at a time is the tunnel's
// instance. Where the driver can prove a route in a SIDE instance (no
// TUN, no way in: core/engine/side_singbox.go) a pass races the next TWO
// candidates there, never more, and starts the tunnel's instance on the
// one that proves first (connect_race.go). Everything else — a family
// that cannot be side-probed, the route that carried here last, the
// last candidate, a network whose hourly allowance is spent — is tried
// alone, in order, exactly as before.
//
// What it says afterwards — `verdict`, and `refined` on a route — is
// derived from the set of results by deriveAuto (connect_auto_verdict.go)
// and is held to one rule: only what the observations prove.

// `auto.state` in the diagnostics blob.
const (
	AutoStateIdle      = "idle"
	AutoStateTrying    = "trying"
	AutoStateConnected = "connected"
	AutoStateFailed    = "failed"
)

// `result` of one entry of `tried`.
const (
	AutoResultCarried     = "carried"
	AutoResultNotCarrying = "not_carrying"
	AutoResultStartFailed = "start_failed"
	AutoResultRefused     = "refused"
	AutoResultCancelled   = "cancelled"
	// AutoResultStopped: the route was being checked beside another one
	// (`raced_with`), the other proved first, and this check was stopped
	// before it had an answer. Nothing was learned about the route and
	// nothing is recorded about it.
	AutoResultStopped = "stopped"
)

// `why` of one entry: why the route stood where it did in the order.
const (
	// It carried on this network the last time it was tried here.
	AutoWhyCarriedHere = "carried_here"
	// Nothing is remembered about it on this network: the ranking's
	// order (core/pathmanager.RankWithExperimentalGate).
	AutoWhyRanked = "ranked"
	// The ranking leaves it out in the current mode; tried after every
	// route the mode prefers rather than not at all.
	AutoWhyModeOther = "mode_other"
	// It failed on this network within autoFailureMemory and has not
	// carried here since: last.
	AutoWhyFailedHere = "failed_here"
	// It was the connected route that stopped carrying; its instance
	// was put back after nothing else carried.
	AutoWhyWasConnected = "was_connected"
)

// Refusal codes the automatic connect adds to the connect_refused
// vocabulary for routes it leaves out by itself.
const (
	// An experimental family, and the person has not turned those on.
	AutoRefusedExperimentalOff = "experimental_off"
	// The current mode forbids the route outright (lifeline-strict and
	// a bulk-capable route).
	AutoRefusedMode = "mode"
)

// autoFailureMemory is how long a failure on a network keeps a route at
// the end of the order there. After it the failure is history and the
// route is ordered by the ranking again.
const autoFailureMemory = 24 * time.Hour

// autoRetryAfter / autoRetryMax bound how often the engine starts a
// pass BY ITSELF during one outage (the fall-over from a route that
// stopped carrying): after a pass in which nothing else carried, the
// next one waits autoRetryAfter, then twice that, and so on up to
// autoRetryMax (autoFallBackoff). Every such pass replaces the instance
// behind the tunnel for as long as it takes to try the others, so it is
// not something to do every few minutes for hours. A pass the person
// asks for is not held to it.
const (
	autoRetryAfter = 5 * time.Minute
	autoRetryMax   = time.Hour
)

// autoFallBackoff is the wait after the n-th engine-started pass of an
// outage (n >= 1).
func autoFallBackoff(n int) time.Duration {
	d := autoRetryAfter
	for i := 1; i < n && d < autoRetryMax; i++ {
		d *= 2
	}
	if d > autoRetryMax {
		d = autoRetryMax
	}
	return d
}

// autoLost is the route that was connected and stopped carrying, for
// the pass that tries the others.
type autoLost struct {
	routeID, family string
	cat             diagnostics.Category
}

// autoCharge is one candidate that failed in a pass, until the pass
// settles what its failure is charged with (autoSettleLocked).
type autoCharge struct {
	routeID, family string
	cat             diagnostics.Category
}

// autoSilent: the failure is silence — no answer from anything. A pass
// made only of these has learned nothing about any ROUTE: the same
// results come from a device whose network is not usable yet (Wi-Fi
// still associating, a captive portal, a shutdown the OS does not
// report).
func autoSilent(cat diagnostics.Category) bool {
	switch cat {
	case diagnostics.TCPConnectTimeout, diagnostics.UDPNoReply, diagnostics.DNSTimeout, diagnostics.NetworkOffline:
		return true
	}
	return false
}

// AutoTried is one route of an automatic pass, as reported.
type AutoTried struct {
	RouteID string `json:"route_id"`
	Family  string `json:"family"`
	// Result: carried | not_carrying | start_failed | refused |
	// cancelled.
	Result string `json:"result"`
	// Category: the failure-taxonomy category of a route that was tried
	// and did not carry — what THIS route alone could see. "" otherwise.
	Category string `json:"category"`
	// Refined: what the result of ANOTHER route of the same pass adds
	// to Category: "udp_blocked_here", "relay_unreachable",
	// "name_blocked", "address_blocked", or "" when one observation is
	// all there is. Category is never rewritten.
	Refined string `json:"refined"`
	// Refused: why a route was not tried — the connect_refused
	// vocabulary plus "experimental_off" and "mode". "" when it was.
	Refused string `json:"refused"`
	// Why: the route's place in the order (AutoWhy*). "" for a route
	// that was not a candidate.
	Why string `json:"why"`
	// Relay: routes with the same number go to the same server address
	// (1, 2, … in the order tried; 0 = not known). The address itself
	// is never reported.
	Relay int `json:"relay"`
	// RacedWith: the route this one was checked beside, "" when it was
	// tried alone.
	RacedWith string `json:"raced_with"`
	// SetupMs: for a route that carried, how long THIS attempt took from
	// starting the route to its first completed round trip. 0 otherwise.
	SetupMs int `json:"setup_ms"`
}

// AutoResult is what engine_connect_auto returns.
type AutoResult struct {
	Connected bool        `json:"connected"`
	RouteID   string      `json:"route_id"`
	Family    string      `json:"family"`
	Tried     []AutoTried `json:"tried"`
	Verdict   string      `json:"verdict"`
	// Candidates: how many routes could be tried when the pass began.
	Candidates int `json:"candidates"`
	// AlreadyConnected: the engine was connected when the call came and
	// nothing was done.
	AlreadyConnected bool `json:"already_connected"`
}

// autoState is the automatic connect's state. gen is guarded by Core.mu;
// everything else by mu, so the diagnostics blob reads it without
// waiting for a connect.
type autoState struct {
	// gen changes whenever the pass in flight stops being the one in
	// charge: a newer pass, a manual SetRoute, a ClearRoute.
	gen uint64
	// fallPasses / nextFallAt: how many passes the engine has started by
	// itself in the current outage, and when it may start the next
	// (autoFallBackoff). Guarded by Core.mu.
	fallPasses int
	nextFallAt time.Time
	// lost: the route a fall-over pass IN FLIGHT is moving away from
	// (routeID "" when none is). A newer pass that takes over inherits
	// it, so the route's instance is still put back when nothing else
	// carries. Guarded by Core.mu.
	lost autoLost

	mu      sync.Mutex
	state   string
	mode    bool
	trying  string
	racing  []string
	index   int
	total   int
	tried   []AutoTried
	verdict string
	routeID string
	family  string
}

func (a *autoState) block() map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	state := a.state
	if state == "" {
		state = AutoStateIdle
	}
	tried := make([]AutoTried, len(a.tried))
	copy(tried, a.tried)
	racing := append([]string{}, a.racing...)
	return map[string]any{
		"state": state,
		"mode":  a.mode,
		// trying / index / total: the candidate being checked right now
		// (1-based, of `total`); "" and 0 when none is.
		"trying": a.trying,
		"index":  a.index,
		"total":  a.total,
		// racing: the two routes being checked beside each other right
		// now; empty when one route (or none) is. `trying` is the first
		// of the pair.
		"racing": racing,
		// tried: the routes of the current or last pass, in the order
		// they were tried, then the routes that were left out.
		"tried":   tried,
		"verdict": a.verdict,
		// route_id / family: the route the automatic connect is
		// connected on; "" unless state is "connected".
		"route_id": a.routeID,
		"family":   a.family,
	}
}

func (a *autoState) snapshot() (state string, mode bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state == "" {
		return AutoStateIdle, a.mode
	}
	return a.state, a.mode
}

// reset: nothing to report, nobody in charge.
func (a *autoState) reset() {
	a.mu.Lock()
	a.clearLocked()
	a.mu.Unlock()
}

// clearLocked empties everything a reader sees. Called with mu held.
func (a *autoState) clearLocked() {
	a.state, a.mode = AutoStateIdle, false
	a.trying, a.index, a.total, a.racing = "", 0, 0, nil
	a.tried, a.verdict, a.routeID, a.family = nil, "", "", ""
}

// expireFailed drops the verdict of a failed pass whose routes may be
// tried again (expireFailedConnect).
func (a *autoState) expireFailed() {
	a.mu.Lock()
	if a.state == AutoStateFailed {
		mode := a.mode
		a.clearLocked()
		a.mode = mode
	}
	a.mu.Unlock()
}

// recovered: the connected route carried again after an outage.
func (a *autoState) recovered(routeID, family string) {
	a.mu.Lock()
	if a.mode && a.state == AutoStateFailed {
		a.state, a.verdict, a.trying, a.index = AutoStateConnected, "", "", 0
		a.routeID, a.family = routeID, family
	}
	a.mu.Unlock()
}

// autoStopLocked ends the automatic connect: a pass in flight is no
// longer in charge (it comes back "cancelled") and mode goes false.
// Reports whether a pass was in flight. Called with Core.mu held.
//
// keepFailedVerdict: leave the verdict of a pass that already failed
// for the page to read — a host that tears its plumbing down after a
// connect that did not come up calls ClearRoute before the page has
// polled once (see ClearRoute).
func (c *Core) autoStopLocked(keepFailedVerdict bool) (wasTrying bool) {
	c.auto.gen++
	c.cancelRaceLocked()
	c.auto.fallPasses, c.auto.nextFallAt = 0, time.Time{}
	c.auto.lost = autoLost{}
	a := &c.auto
	a.mu.Lock()
	defer a.mu.Unlock()
	wasTrying = a.state == AutoStateTrying
	if keepFailedVerdict && a.state == AutoStateFailed {
		a.mode = false
		return false
	}
	a.clearLocked()
	return wasTrying
}

// ConnectAuto is engine_connect_auto: connect on the first route that
// carries, the engine choosing.
//
// Blocking, like SetRoute, and it uses the TUN the host already handed
// over exactly as SetRoute does. It returns when a route carries or
// when every candidate has been tried; ClearRoute, a manual SetRoute or
// a newer ConnectAuto abandons it promptly, a connection check in
// flight included.
//
// If the engine is connected when the call comes it starts nothing and
// names the running route — and TAKES CHARGE of it: `auto.mode` goes
// true, so a route that was picked by hand is, from this call on,
// watched and moved away from like one the engine chose. The call is
// somebody asking the engine to choose; a host that then reported
// "automatic" over an engine that would never move was telling the
// person something untrue.
//
// The error is non-nil only when the engine is not initialised;
// everything else is in the JSON (AutoResult).
func ConnectAuto() (string, error) {
	c := loadedCore()
	if c == nil {
		return "", errors.New("abi: not initialized")
	}
	var res AutoResult
	if !dataPlaneLinked {
		// The build that cannot tunnel: say so, start nothing (see
		// SetRoute for why this is the only honest answer).
		res = AutoResult{Verdict: AutoVerdictNoDataPlane}
	} else {
		c.mu.Lock()
		st, cat, running := c.check.snapshot()
		switch {
		case c.shuttingDown:
			res = AutoResult{Verdict: AutoVerdictCancelled}
		case c.activeRoute != "" && running && (st == RouteCheckOK || st == RouteCheckDegraded):
			res = AutoResult{Connected: true, RouteID: c.activeRoute, Family: c.activeFamily, AlreadyConnected: true}
			c.autoTakeChargeLocked()
		case c.auto.lost.routeID != "":
			// A fall-over pass is in flight (the engine is between
			// routes, or checking one). This call takes over from it —
			// and takes over the route it was moving away from, which
			// is still the one to put back if nothing carries.
			lost := c.auto.lost
			res = c.autoPassLocked(&lost, true)
		case c.activeRoute != "" && running && st == RouteCheckFailed:
			// A route that was connected, has stopped carrying and is
			// still running is kept unless something else carries.
			res = c.autoPassLocked(&autoLost{routeID: c.activeRoute, family: c.activeFamily, cat: cat}, true)
		default:
			res = c.autoPassLocked(nil, true)
		}
		c.mu.Unlock()
	}
	if res.Tried == nil {
		res.Tried = []AutoTried{}
	}
	body, _ := json.Marshal(res)
	return string(body), nil
}

// autoFallOver is the liveness loop's call when the connected route has
// just failed a check (startLivenessLocked). When the automatic connect
// is in charge it tries the other routes; otherwise it does nothing and
// the route is re-checked as it always was.
func (c *Core) autoFallOver(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ctx.Err() != nil {
		// This loop's route has been replaced or disconnected.
		return
	}
	as, mode := c.auto.snapshot()
	if !mode {
		return
	}
	if as == AutoStateTrying {
		// A pass is in flight already — one that races beside this very
		// route and has left its instance, and so this loop, running
		// (connect_race.go). It is trying the other routes; starting a
		// second pass here would only cancel it, and the call that asked
		// for it (the person's, or the host's) would come back
		// "cancelled" while the engine was in fact still looking.
		return
	}
	st, cat, running := c.check.snapshot()
	if st != RouteCheckFailed || !running || c.activeRoute == "" {
		return
	}
	if !autoFallsOverFor(cat) {
		// The instance may still be carrying, or the device has no
		// network: see autoFallsOverFor.
		return
	}
	if nowUTC().Before(c.auto.nextFallAt) {
		// A pass of this outage found nothing a little while ago.
		return
	}
	if hostFacts().noNetwork() {
		// The host says the device is on no network at all. No other
		// route would fare better, and a pass would replace the instance
		// under every connection the person has open; the host's next
		// report (engine_network_facts) asks for a check at once.
		return
	}
	c.autoPassLocked(&autoLost{routeID: c.activeRoute, family: c.activeFamily, cat: cat}, false)
}

// autoTakeChargeLocked puts the automatic connect in charge of the
// route that is connected now (ConnectAuto finding the engine
// connected). Called with Core.mu held.
func (c *Core) autoTakeChargeLocked() {
	a := &c.auto
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.mode && a.state == AutoStateConnected && a.routeID == c.activeRoute {
		return
	}
	a.clearLocked()
	a.mode, a.state = true, AutoStateConnected
	a.routeID, a.family = c.activeRoute, c.activeFamily
	engine.LogInfo(fmt.Sprintf("auto took charge route=%s family=%s", engine.LogID(c.activeRoute), engine.LogID(c.activeFamily)))
}

// autoSettleLocked decides what the failures of one pass are charged
// with, once the pass knows what the whole set of results says.
//
// Every candidate that failed has already been given its route cooldown
// (routeDownOptsLocked) — so nothing in the pass is tried twice, and a
// pass that is abandoned half-way leaves the routes it did try resting.
//
// When NOTHING AT ALL ANSWERED — no route carried, and every failure was
// silence (autoSilent) — those cooldowns are lifted again and nothing
// durable is written: the pass saw a device with no usable network, not
// four broken routes. Charging them cost the person every route they
// hold for at least five minutes after a moment without an uplink
// (a manual pick was refused too), and across a long outage walked every
// family up the 5 min … 24 h ladder. If the route the pass was moving
// away from had gone silent too, it is forgiven with the rest.
//
// Otherwise each failure gets its durable row (with the cooldown it was
// given) and is remembered for this network.
//
// keepVerdict: the pass ended normally and the failed-connect record in
// routeCheck is its own (false when it was abandoned: the record belongs
// to whoever took over).
func (c *Core) autoSettleLocked(pending []autoCharge, carried bool, lost *autoLost, keepVerdict bool) (forgiven bool) {
	if len(pending) == 0 || c.shuttingDown {
		// (Shutdown has taken the core: its store is being closed, and
		// nothing more is written to it.)
		return false
	}
	silent := !carried
	for _, p := range pending {
		if !autoSilent(p.cat) {
			silent = false
		}
	}
	if silent {
		for _, p := range pending {
			c.pm.Forgive(p.routeID)
		}
		if lost != nil && autoSilent(lost.cat) {
			c.pm.Forgive(lost.routeID)
		}
		if keepVerdict {
			// Nothing is cooling down, so nothing about this verdict
			// changes with time (expireFailedConnect).
			c.check.mu.Lock()
			if c.check.state == RouteCheckFailed && !c.check.running {
				c.check.failedCooled = false
			}
			c.check.mu.Unlock()
		}
		engine.LogInfo(fmt.Sprintf("auto forgiven routes=%d reason=nothing_answered", len(pending)))
		return true
	}
	for _, p := range pending {
		if p.cat != diagnostics.PathTooSlow {
			_ = c.store.RecordFailure(p.routeID, string(p.cat), pmCooldownUntil(c, p.routeID), nowUTC())
		}
		c.rememberRoute(p.routeID, false, p.cat)
	}
	return false
}

// autoCandidate is one route of a pass. relayHost / relayPort / name
// are read from the route's profile to tell which routes share a
// server; they stay in memory for the length of the pass and are never
// logged, stored or reported.
type autoCandidate struct {
	routeID, family, why string
	udp                  bool
	relayHost, name      string
	relayPort            int
	// side: the driver can prove this route in a side instance
	// (engine.SideProber). grade: its grade on this network.
	side  bool
	grade string
	// measuredMs: its smoothed setup time on this network; 0 with
	// samples == 0 when it was never timed here.
	measuredMs, samples int
	// proved: a side probe of THIS pass proved it (beside a winner whose
	// hand-over then failed) and its measurement is already kept.
	proved bool
}

// autoPassLocked is one pass over the candidates. Called with Core.mu
// held; returns with it held (connectRouteLocked releases it for each
// connection check).
//
// explicit: the person asked (ConnectAuto), as opposed to the engine
// moving by itself (autoFallOver).
//
// fallOver: the connected route (still running) has stopped carrying.
// It is left out of the candidates; a pass that has nothing else to try
// changes nothing, and one in which nothing else carries puts its
// instance back, so the tunnel has something behind it that heals by
// itself when the path returns and is re-checked every RecheckInterval.
func (c *Core) autoPassLocked(lost *autoLost, explicit bool) AutoResult {
	fallOver := lost != nil
	current, currentFamily := "", ""
	var currentCat diagnostics.Category
	if fallOver {
		current, currentFamily, currentCat = lost.routeID, lost.family, lost.cat
	}
	cands, left, routes, err := c.autoCandidatesLocked(current)
	if err != nil {
		// The store could not be read. That is all that is known: it is
		// NOT "nothing imported" (the person may hold four routes), and
		// nothing running is touched.
		if explicit && !fallOver {
			a := &c.auto
			a.mu.Lock()
			a.clearLocked()
			a.state, a.verdict = AutoStateFailed, AutoVerdictStoreUnreadable
			a.mu.Unlock()
		}
		engine.LogInfo(fmt.Sprintf("auto done connected=false route=- verdict=%s", AutoVerdictStoreUnreadable))
		return AutoResult{Verdict: AutoVerdictStoreUnreadable}
	}
	if fallOver && len(cands) == 0 {
		// Nothing else to try (usually: everything else is cooling down
		// after the last pass). The instance that is running is left
		// alone. Said once, when the outage begins — and whenever the
		// person asks.
		verdict := AutoVerdictAllFailed
		if len(left) > 0 {
			verdict = verdictWithoutCandidates(len(left), left)
		}
		tried := append([]AutoTried{{RouteID: current, Family: currentFamily, Result: AutoResultNotCarrying,
			Category: string(currentCat), Why: AutoWhyWasConnected}}, left...)
		if st, _ := c.auto.snapshot(); (explicit && st != AutoStateTrying) || st == AutoStateConnected {
			a := &c.auto
			a.mu.Lock()
			a.state, a.verdict, a.tried = AutoStateFailed, verdict, tried
			a.trying, a.index, a.total = "", 0, 0
			a.routeID, a.family = "", ""
			if explicit {
				// The person asked the engine to choose: it goes on
				// watching, and moves when something can be tried.
				a.mode = true
			}
			a.mu.Unlock()
			engine.LogInfo(fmt.Sprintf("auto done connected=false route=- verdict=%s", verdict))
		}
		return AutoResult{Tried: tried, Verdict: verdict}
	}

	// This pass is in charge now.
	c.auto.gen++
	c.cancelRaceLocked()
	gen := c.auto.gen
	a := &c.auto
	if len(cands) == 0 {
		// Nothing can be tried. Nothing is started, nothing running is
		// touched, and the engine is not in charge of anything.
		verdict := verdictWithoutCandidates(routes, left)
		a.mu.Lock()
		a.clearLocked()
		a.state, a.verdict, a.tried = AutoStateFailed, verdict, left
		a.mu.Unlock()
		engine.LogInfo("auto start candidates=0")
		engine.LogInfo(fmt.Sprintf("auto done connected=false route=- verdict=%s", verdict))
		return AutoResult{Tried: left, Verdict: verdict}
	}
	a.mu.Lock()
	a.state, a.mode = AutoStateTrying, true
	a.trying, a.index, a.total, a.racing = "", 0, len(cands), nil
	a.tried, a.verdict, a.routeID, a.family = nil, "", "", ""
	a.mu.Unlock()
	c.check.setSwitchBack(SwitchBack{})
	if fallOver {
		c.auto.lost = *lost
	} else {
		c.auto.lost = autoLost{}
	}
	engine.LogInfo(fmt.Sprintf("auto start candidates=%d", len(cands)))

	p := &autoPass{c: c, gen: gen, lost: lost, total: len(cands), background: !explicit, relayNo: map[string]int{}}
	if fallOver {
		// The route that stopped carrying is the first observation of
		// this pass.
		p.tried = append(p.tried, AutoTried{RouteID: current, Family: currentFamily, Result: AutoResultNotCarrying,
			Category: string(currentCat), Why: AutoWhyWasConnected})
		p.obs = append(p.obs, autoObs{result: AutoResultNotCarrying, category: currentCat, unplaced: true})
	}
	queue := append([]autoCandidate(nil), cands...)
	for first := true; len(queue) > 0 && p.connected == "" && !p.cancelled; first = false {
		index := len(cands) - len(queue) + 1
		// The route that carried here last is tried ALONE: when it still
		// works — the usual press — the network sees one connection, the
		// one it saw yesterday.
		alone := first && queue[0].why == AutoWhyCarriedHere && queue[0].grade != netmem.GradeFailing
		partner := -1
		if !alone && !p.noRace {
			partner = c.racePartnerLocked(queue, p.background)
		}
		if partner < 0 {
			cd := queue[0]
			queue = queue[1:]
			p.seq(cd, index)
			continue
		}
		a, b := queue[0], queue[partner]
		rest := append(append([]autoCandidate{}, queue[1:partner]...), queue[partner+1:]...)
		queue = append(p.race(a, b, index), rest...)
	}
	if p.cancelled {
		// A disconnect, a route picked by hand or a newer pass took
		// over. The state — the engine's and the `auto` block's — is
		// theirs.
		engine.LogInfo(fmt.Sprintf("auto done connected=false route=- verdict=%s", AutoVerdictCancelled))
		c.autoSettleLocked(p.pending, p.answered, lost, false)
		return AutoResult{Tried: p.tried, Verdict: AutoVerdictCancelled, Candidates: len(cands)}
	}
	obs, tried := p.obs, p.tried
	connected, connectedFamily := p.connected, p.connectedFamily
	forgiven := c.autoSettleLocked(p.pending, connected != "" || p.answered, lost, true)
	c.auto.lost = autoLost{}
	if connected != "" {
		c.auto.fallPasses, c.auto.nextFallAt = 0, time.Time{}
	} else if fallOver {
		// Nothing else carried. The engine's own next pass of this
		// outage waits (autoFallBackoff).
		if !explicit || c.auto.fallPasses == 0 {
			c.auto.fallPasses++
		}
		c.auto.nextFallAt = nowUTC().Add(autoFallBackoff(c.auto.fallPasses))
	}

	verdict, refined := deriveAuto(obs)
	for i := range refined {
		tried[i].Refined = refined[i]
	}
	if connected == "" && forgiven && hostFacts().noNetwork() {
		// Nothing at all answered, and the HOST says why: the device is
		// on no network at all. No probe of the engine's own was made to
		// learn it. Without the host's word the same silence stays what
		// it was (relay_unreachable, all_failed) — and "the platform has
		// not VALIDATED this network" is not that word: a network that
		// filters the platform's own connectivity check is never
		// validated and carries traffic all the same, and telling a
		// person whose browser works that the phone has no internet
		// sends them to their Wi-Fi settings instead of to a new file.
		verdict = AutoVerdictNetworkDown
	}
	tried = append(tried, left...)

	if connected == "" && fallOver && !c.routeRunningLocked(current) {
		// Nothing else carried, and the instance of the route that was
		// connected was replaced on the way (a candidate tried through
		// the tunnel's own instance). Put it back: see the comment on
		// this function. A pass that only side-probed never took it
		// down.
		if !c.resumeFailedRouteLocked(current, currentCat) {
			engine.LogInfo(fmt.Sprintf("auto resume route=%s result=failed", engine.LogID(current)))
		}
	}

	a.mu.Lock()
	a.trying, a.index, a.racing = "", 0, nil
	a.tried, a.verdict = tried, verdict
	if connected != "" {
		a.state, a.routeID, a.family = AutoStateConnected, connected, connectedFamily
	} else {
		a.state = AutoStateFailed
	}
	a.mu.Unlock()
	logRoute := "-"
	if connected != "" {
		logRoute = engine.LogID(connected)
	}
	engine.LogInfo(fmt.Sprintf("auto done connected=%t route=%s verdict=%s", connected != "", logRoute, verdict))
	return AutoResult{Connected: connected != "", RouteID: connected, Family: connectedFamily,
		Tried: tried, Verdict: verdict, Candidates: len(cands)}
}

// restartInstanceLocked starts the tunnel's instance on a route WITHOUT a
// connection check and makes it the active route. It skips the route's
// cooldown (this is not a new attempt at it) and nothing else. The
// caller says what state the route is in and starts its liveness loop.
// Called with Core.mu held.
func (c *Core) restartInstanceLocked(routeID string) (family string, ok bool) {
	row, body, err := c.prepareRouteOpts(routeID, false, true)
	if err != nil || c.shuttingDown {
		return "", false
	}
	c.check.abandon()
	c.routeEpoch++
	if err := c.driver.Start(context.Background(), body); err != nil {
		return "", false
	}
	refresh.SetTunnelRequired(true)
	c.setActiveLocked(routeID, row.TransportFamily)
	return row.TransportFamily, true
}

// resumeFailedRouteLocked starts the instance of a route that was
// connected and stopped carrying, WITHOUT a connection check, and hands
// it back to the liveness loop in the state it was in: failed, running.
// Called with Core.mu held.
func (c *Core) resumeFailedRouteLocked(routeID string, cat diagnostics.Category) bool {
	family, ok := c.restartInstanceLocked(routeID)
	if !ok {
		return false
	}
	c.check.setFailed(cat, true)
	c.startLivenessLocked()
	// The same route id, a NEW instance with a new inlet: a host that
	// compares route ids sees nothing to do, so the engine re-points
	// tunnelled refresh itself.
	rearmTunnelRefresh()
	engine.LogInfo(fmt.Sprintf("auto resume route=%s family=%s result=running", engine.LogID(routeID), engine.LogID(family)))
	return true
}

// resumeSlowRouteLocked puts back the instance of a route that was
// carrying, slowly, when the engine left it for one that then did not
// carry (a move for speed whose hand-over failed: connect_speed.go). No
// pass/fail connection check stands between the person and the tunnel
// they had: the route is back in the state it was in — degraded,
// running — and the liveness loop is asked to check it at once, so what
// is shown is confirmed or corrected within one check. Nothing is
// charged to the route: the detour was the engine's own. Called with
// Core.mu held.
func (c *Core) resumeSlowRouteLocked(routeID string) bool {
	family, ok := c.restartInstanceLocked(routeID)
	if !ok {
		return false
	}
	c.routeUpLocked(routeID, family, engine.ProofResult{OK: true, Slow: true})
	c.startLivenessLocked()
	rearmTunnelRefresh()
	c.kickLiveness()
	engine.LogInfo(fmt.Sprintf("auto resume route=%s family=%s result=running state=degraded", engine.LogID(routeID), engine.LogID(family)))
	return true
}

// autoCandidatesLocked lists the routes a pass may try, in order, and
// the routes it leaves out (as `tried` entries with result "refused").
// routes is how many routes the person holds in all. exclude is left
// out of both lists. Called with Core.mu held; reads the store, writes
// nothing.
//
// THE ORDER, each step deterministic:
//
//  1. The ranking: pathmanager.RankWithExperimentalGate for the current
//     mode (experimental families out unless the person turned them on;
//     the mode's own filter and order). Routes the ranking leaves out
//     for the mode alone follow, by route id — a person who cannot get
//     out is better served by a route the mode disprefers than by none.
//     lifeline-strict's refusal of bulk-capable routes is the exception:
//     that one is a promise to the person, and such a route is not tried.
//  2. This network's memory (core/netmem RouteMemory, keyed by the
//     hashed network id the host last reported; one shared bucket when
//     it has reported none): routes whose last outcome HERE was a round
//     trip come first, most recent first; routes that failed here within
//     autoFailureMemory and have not carried since go last. Both keep
//     the ranking's order among themselves where the memory does not
//     decide.
func (c *Core) autoCandidatesLocked(exclude string) (cands []autoCandidate, left []AutoTried, routes int, err error) {
	rows, err := c.store.ListRoutes()
	if err != nil {
		return nil, nil, 0, err
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].RouteID < rows[j].RouteID })
	routes = len(rows)

	budgets := map[string][3]any{}
	allowBulk := false
	if eng := budgetEngineIfPresent(); eng != nil {
		for _, b := range eng.Snapshot() {
			budgets[b.RouteID] = [3]any{b.HourlyCap, b.Consumed, b.BudgetTag}
		}
		allowBulk = eng.AllowsBulkCapableThisSession()
	}

	prober := c.sideProber()
	byID := map[string]autoCandidate{}
	var usable []pathmanager.Route
	for _, row := range rows {
		if row.RouteID == exclude {
			continue
		}
		_, body, err := c.prepareRouteOpts(row.RouteID, false, false)
		if err != nil {
			code := ConnectRefusedOther
			var rr *routeRefusal
			if errors.As(err, &rr) {
				code = rr.code
			}
			left = append(left, AutoTried{RouteID: row.RouteID, Family: row.TransportFamily, Result: AutoResultRefused, Refused: code})
			continue
		}
		cd := autoCandidate{routeID: row.RouteID, family: row.TransportFamily, udp: engine.IsUDPFamily(row.TransportFamily),
			side: prober != nil && prober.CanSideProbe(body)}
		if profile, err := c.store.GetSecret("route:" + row.RouteID); err == nil {
			cd.relayHost, cd.relayPort, cd.name = profileRelay(profile)
		}
		byID[row.RouteID] = cd
		pr := pathmanager.Route{RouteID: row.RouteID, Family: row.TransportFamily, ModesAllowed: row.ModesAllowed}
		if b, ok := budgets[row.RouteID]; ok {
			pr.HourlyCap, pr.Consumed, pr.BudgetTag = b[0].(uint64), b[1].(uint64), b[2].(string)
		}
		usable = append(usable, pr)
	}

	// Step 1: the ranking.
	gateOpen := c.experimentalFamiliesEnabled
	ranked, skipped := pathmanager.RankWithExperimentalGate(usable, c.mode, autoRankView{allowBulk: allowBulk}, gateOpen, routestore.IsExperimentalFamily)
	c.experimentalRoutesSkipped = skipped
	type placed struct {
		cd  autoCandidate
		why string
	}
	var order []placed
	inRank := map[string]bool{}
	for _, r := range ranked {
		inRank[r.RouteID] = true
		order = append(order, placed{byID[r.RouteID], AutoWhyRanked})
	}
	for _, r := range usable { // route-id order
		switch {
		case inRank[r.RouteID]:
		case !gateOpen && routestore.IsExperimentalFamily(r.Family):
			left = append(left, AutoTried{RouteID: r.RouteID, Family: r.Family, Result: AutoResultRefused, Refused: AutoRefusedExperimentalOff})
		case c.mode == "lifeline-strict" && r.BudgetTag == "bulk-capable" && !allowBulk:
			left = append(left, AutoTried{RouteID: r.RouteID, Family: r.Family, Result: AutoResultRefused, Refused: AutoRefusedMode})
		default:
			order = append(order, placed{byID[r.RouteID], AutoWhyModeOther})
		}
	}
	sort.SliceStable(left, func(i, j int) bool { return left[i].RouteID < left[j].RouteID })

	// Step 2: this network's memory.
	mem := c.routeMemory()
	cutoff := nowUTC().Add(-autoFailureMemory)
	var first, middle, last []placed
	for _, p := range order {
		m, ok := mem[p.cd.routeID]
		p.cd.grade, p.cd.measuredMs, p.cd.samples = m.Grade(), m.SetupMs, m.Samples
		switch {
		case ok && m.CarriedLast():
			p.why = AutoWhyCarriedHere
			first = append(first, p)
		case ok && m.FailedSince(cutoff):
			p.why = AutoWhyFailedHere
			last = append(last, p)
		default:
			middle = append(middle, p)
		}
	}
	sort.SliceStable(first, func(i, j int) bool {
		return mem[first[i].cd.routeID].CarriedSeq > mem[first[j].cd.routeID].CarriedSeq
	})
	for _, group := range [][]placed{first, middle, last} {
		for _, p := range group {
			p.cd.why = p.why
			cands = append(cands, p.cd)
		}
	}
	return cands, left, routes, nil
}

// autoRankView is the ranking's view for the automatic connect: the
// per-session bulk opt-in, and no failure rates (the per-network memory
// orders the routes after the ranking has).
type autoRankView struct{ allowBulk bool }

func (autoRankView) FailureRate(string) float64           { return 0 }
func (v autoRankView) AllowsBulkCapableThisSession() bool { return v.allowBulk }

// profileRelay reads, from a route's stored outbound, where it goes:
// the server, its port, and the TLS name the first flight presents (""
// when there is none). Used only to tell which routes of one pass share
// a server or a name.
func profileRelay(profile []byte) (host string, port int, name string) {
	var p struct {
		Server     string `json:"server"`
		ServerPort int    `json:"server_port"`
		TLS        *struct {
			ServerName string `json:"server_name"`
		} `json:"tls"`
	}
	if json.Unmarshal(profile, &p) != nil {
		return "", 0, ""
	}
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(p.Server), "."))
	if p.TLS != nil {
		name = strings.ToLower(strings.TrimSpace(p.TLS.ServerName))
	}
	return host, p.ServerPort, name
}

// ---- this network's memory --------------------------------------------

// rememberRoute notes, for the network the device is on, that a route
// carried or failed. Best effort: a store that cannot be written never
// fails a connect. Called from connect outcomes and from a CHANGE in the
// liveness of the connected route — never from a read path.
//
// path_too_slow is not remembered as a failure: it is not one (see
// routeDownLocked).
func (c *Core) rememberRoute(routeID string, carried bool, cat diagnostics.Category) {
	c.rememberOutcome(routeID, netmem.RouteOutcome{Carried: carried, Category: string(cat)})
}

// rememberOutcome is rememberRoute with the measurement: how long a
// fresh start of the route took, and whether the check called it slow
// (core/netmem/measure.go). Same rules: best effort, never from a read
// path, path_too_slow is not a failure.
func (c *Core) rememberOutcome(routeID string, o netmem.RouteOutcome) {
	if !o.Carried && o.Category == string(diagnostics.PathTooSlow) {
		return
	}
	st := netmemStore()
	if st == nil {
		return
	}
	_ = st.RecordRouteOutcome(activeNetworkID(), routeID, o, nowUTC())
}

// routeMemory is what is remembered about the routes on the network the
// device is on. Empty when nothing is, or when the store cannot say.
func (c *Core) routeMemory() map[string]netmem.RouteMemory {
	st := netmemStore()
	if st == nil {
		return nil
	}
	return st.LookupRouteMemory(activeNetworkID())
}
