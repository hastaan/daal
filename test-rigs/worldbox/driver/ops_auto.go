package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

func init() {
	Ops["auto"] = opAuto
}

// The AUTOMATIC CONNECT: the main screen's one button, no route named
// (engine_connect_auto; labclient/auto.go is the host half). The second
// real-phone pass (2026-11-19) had four routes on the phone and a button
// that did not connect — a person had to pick among protocol names. The
// engine now picks, tries, moves on, remembers and says what it saw; this
// op is every one of those verbs on a real TUN against a real relay, with
// the censor doing something specific in between.
//
// In a world whose scenario blocks nothing, seven phones, each a fresh
// state directory (a fresh memory):
//
//	first      Connect. The route the ranking puts first carries: verdict
//	           "", one route carried — and, named `stopped`, the route the
//	           engine was checking beside it. The route list then says how
//	           the routes did on this network (`measured`). Connect again
//	           while connected: nothing happens. Disconnect: nothing
//	           running, nobody in charge.
//	blocked    The censor drops that first route's endpoint. Connect: the
//	           blocked route is checked FIRST, beside a second one; the
//	           second proves and the first's check is stopped — `stopped`,
//	           no category, no verdict, nothing remembered against it —
//	           and verified bytes travel on the endpoint of the route the
//	           engine says it is on. (Checked alone it would be
//	           `not_carrying` and the pass `moved_on`; both are accepted.)
//	           Disconnect, lift the block, Connect: the route that carried
//	           here is tried first (`why: carried_here`).
//	race       The censor drops BOTH routes of that first pair: see
//	           ops_auto_race.go.
//	memory     The person connects the LAST-ranked route by hand, once,
//	           and disconnects. Connect: that route is first, ahead of the
//	           whole ranking — the order is this network's memory and not
//	           an accident of a cooldown. (It is the QUIC route on purpose.)
//	udp        …then the censor drops every UDP datagram the client sends,
//	           to anyone. Connect: the QUIC route is tried first, is
//	           silent, and a TCP route to the SAME address carries. One
//	           route alone says `udp_no_reply` (FINDINGS CEN-4); the pass
//	           adds `refined: udp_blocked_here`. The other half of that
//	           distinction is in `all-blocked` below.
//	quic-only  The same start, and a censor that drops QUIC Initials only
//	           (plain UDP to the very same endpoint is delivered). The pass
//	           gives the same `udp_blocked_here`: it has no observation
//	           that separates the two, and that is the part of CEN-4 that
//	           is still open (the check is red, and known).
//	all-blocked  The relay's address is null-routed. Cancel 1.5 s into a
//	           Connect: the call comes back at once, `cancelled`. Connect
//	           and wait: connected=false, every candidate tried, verdict
//	           `relay_unreachable`, the QUIC route `refined:
//	           relay_unreachable` (a dead address, NOT blocked UDP),
//	           nothing running, the TUN released, no file of the app's
//	           closed, and the verdict still readable after the teardown.
//	           Connect again at once: every candidate is TRIED AGAIN and
//	           the verdict is the same — a pass in which nothing at all
//	           answered rests no route (it cannot tell a dead relay from
//	           a phone with no uplink for a moment, and resting every
//	           route for the second left the person with nothing to
//	           press for five minutes).
//	fall-over  Connected by the button (the engine is in charge). The
//	           censor starts dropping the running route's endpoint. The
//	           host does NOTHING — no call, no new TUN. The engine's own
//	           liveness check notices, the engine moves to another route
//	           in the same TUN, and verified bytes flow again.
//
// In a world whose scenario blocks something there is one phone: Connect
// under the scenario as it stands, the network reported as Android would
// report it, judged against what the scenario says of each family
// (underScenario). Every press, in every world, is also asked whether the
// censor ever saw more than two routes in flight (ops_auto_race.go).
//
// What the fall-over waits for: nothing on the host's clock. The engine's
// liveness loop (core/abi/route_check.go startLivenessLocked) re-checks
// the connected route every `liveness_interval_s` — 180 s ±25 % in
// production; this phone sets 3 s through the engine's own configuration
// file, the same knob an operator has — and after a failed check
// checks ONCE MORE (5 s later, or `recheck_interval_s` if that is
// shorter) before it calls autoFallOver: one lost round trip does not
// replace the instance. The product's clock is therefore NOT what is
// measured here; that the move happens without the host is.
func opAuto(rc *RunCtx) {
	const phase = "op:auto"
	a := &autoOp{rc: rc, phase: phase}
	if a.scenarioBlocks() {
		a.tap()
		a.underScenario()
		return
	}
	a.tap()
	first, partner, ok := a.first()
	if !ok {
		return
	}
	for _, ph := range []struct {
		name string
		run  func()
	}{
		{"blocked", func() { a.blockedFirst(first, partner) }},
		{"race", func() { a.race(first, partner) }},
		{"memory", func() { a.memoryThenUDP(first) }},
		{"quic-only", func() { a.quicOnly(first) }},
		{"all-blocked", a.allBlocked},
		{"fall-over", a.fallOver},
	} {
		if autoPhoneWanted(ph.name) {
			ph.run()
		}
	}
}

// autoPhoneWanted: WB_AUTO_ONLY=race,fall-over runs only those phones of
// an op (phone `first` always runs: the others are told what it saw).
// For working on one phone; a matrix run sets nothing.
func autoPhoneWanted(name string) bool {
	only := os.Getenv("WB_AUTO_ONLY")
	return only == "" || strings.Contains(","+only+",", ","+name+",")
}

type autoOp struct {
	rc    *RunCtx
	phase string
	// tapOK: the censor's packet log is running (flowtap.go).
	tapOK bool
}

// autoRoute is one route of the pack as the engine lists it.
type autoRoute struct {
	ID, Family   string
	Experimental bool
}

// autoPhone is one phone of the op.
type autoPhone struct {
	op     *autoOp
	label  string
	c      *Client
	routes []autoRoute // route-id order: the ranking's order on a fresh phone
	sw     *switchSession
}

func (a *autoOp) scenarioBlocks() bool {
	for _, name := range a.rc.Serve {
		if e, _ := a.rc.Scn.ExpectFor(name); e != Pass {
			return true
		}
	}
	return false
}

func (p *autoPhone) add(step, family, id, expect, gotV, detail string, ev map[string]any, t0 time.Time) bool {
	r := p.op.rc.R
	saved := r.prefix
	r.prefix = saved + p.label + "." + step + "."
	defer func() { r.prefix = saved }()
	return r.Add(family, p.op.phase, id, expect, gotV, detail, ev, t0)
}

// candidates: the routes a fresh phone's pass may try — every route of
// the pack whose family is not behind the experimental gate (which this
// op leaves off, as a person who changed nothing has it).
func (p *autoPhone) candidates() []autoRoute {
	var out []autoRoute
	for _, r := range p.routes {
		if !r.Experimental {
			out = append(out, r)
		}
	}
	return out
}

func (p *autoPhone) family(name string) Family { return p.op.rc.Fams[name] }

// start brings up a phone that holds the pack and has not connected.
func (a *autoOp) start(label string, o ClientOpts) *autoPhone {
	rc := a.rc
	p := &autoPhone{op: a, label: label}
	t0 := time.Now()
	o.Pack, o.Auto = rc.Pack, true
	c, err := StartClient(rc.P, "auto-"+label, o)
	if err != nil {
		p.add("phone", "", "ready", Pass, Fail, err.Error(), nil, t0)
		return nil
	}
	p.c = c
	if _, err := c.Wait(rc.Ctx, EngineConnectWait, "ready"); err != nil {
		detail := "the phone did not come up: " + err.Error()
		if c.Died() {
			detail = "the engine process died: " + c.CrashSignature()
		}
		c.Stop()
		p.add("phone", "", "ready", Pass, Fail, detail, map[string]any{"client_dir": c.Dir}, t0)
		return nil
	}
	if ev := c.Event("routes"); ev != nil {
		doc, _ := ev["routes"].(map[string]any)
		rows, _ := doc["routes"].([]any)
		for _, r := range rows {
			m, _ := r.(map[string]any)
			id, _ := m["route_id"].(string)
			fam, _ := m["family"].(string)
			p.routes = append(p.routes, autoRoute{ID: id, Family: fam, Experimental: m["family_maturity"] == "experimental"})
		}
	}
	sort.Slice(p.routes, func(i, j int) bool { return p.routes[i].ID < p.routes[j].ID })
	p.sw = &switchSession{rc: rc, phase: a.phase, label: label, c: c}
	pre := Probe(rc.Ctx, rc.P, false, 2*time.Second)
	p.add("phone", "", "control.before", Blocked, got(pre.OK, Pass, Blocked), pre.Error,
		map[string]any{"routes": len(p.routes), "candidates": len(p.candidates()), "client_dir": c.Dir}, t0)
	return p
}

// ask sends one command and waits for its answer event.
func (p *autoPhone) ask(step, cmd, want string, wait time.Duration, t0 time.Time) map[string]any {
	rc := p.op.rc
	if p.c.Died() {
		return nil
	}
	if err := p.c.Send(cmd); err != nil {
		p.add(step, "", "engine.survived", Pass, Fail, "could not send `"+cmd+"`: "+err.Error(), nil, t0)
		return nil
	}
	ev, err := p.c.Wait(rc.Ctx, wait, want)
	if err != nil {
		detail := "no answer to `" + cmd + "`: " + err.Error()
		if p.c.Died() {
			detail = "the engine process died during `" + cmd + "`: " + p.c.CrashSignature()
			ReapDeadVPN(rc.Ctx)
		}
		p.add(step, "", "engine.survived", Pass, Fail, detail, map[string]any{"client_dir": p.c.Dir}, t0)
		return nil
	}
	return ev
}

// AutoPassWait bounds one press of Connect: four dead routes cost about
// 30 s (4 s per silent address, 8 s for a swallowed first flight), and a
// loaded machine more.
const AutoPassWait = 150 * time.Second

// autoAnswer is the client's account of one press of Connect.
type autoAnswer struct {
	ev         map[string]any
	res        map[string]any
	connected  bool
	routeID    string
	family     string
	verdict    string
	candidates int
	tried      []map[string]any // the routes that were tried, in order
	left       []map[string]any // the routes that were left out (result "refused")
	// stopped: routes whose check beside another was stopped (or never
	// sent) because the other proved first. Nothing was learned about
	// them and nothing is recorded against them.
	stopped []map[string]any
	all     []map[string]any // every entry, in the engine's order
	// from / to: the press as the driver's clock saw it — what the
	// censor's packet log is asked about.
	from, to time.Time
	uses     []endpointUse
}

func (x *autoAnswer) triedText() string {
	var parts []string
	for _, t := range x.all {
		s := fmt.Sprintf("%v(%v)=%v", t["route_id"], t["family"], t["result"])
		for _, k := range []string{"category", "refined", "refused", "why", "raced_with"} {
			if v, _ := t[k].(string); v != "" {
				s += " " + k + "=" + v
			}
		}
		if ms, _ := t["setup_ms"].(float64); ms > 0 {
			s += fmt.Sprintf(" setup_ms=%d", int(ms))
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, "; ")
}

func (x *autoAnswer) evidence() map[string]any {
	return map[string]any{"connected": x.connected, "route_id": x.routeID, "family": x.family, "verdict": x.verdict,
		"candidates": x.candidates, "tried": x.triedText(), "auto_ms": x.ev["auto_ms"], "progress": x.ev["progress"]}
}

// press sends `auto` (or `auto-cancel`) and parses the answer. It records
// the checks every press shares: the store answered throughout and no
// file of the app's was closed.
func (p *autoPhone) press(step, cmd string, t0 time.Time) *autoAnswer {
	from := time.Now()
	ev := p.ask(step, cmd, "auto", AutoPassWait, t0)
	if ev == nil {
		return nil
	}
	x := &autoAnswer{ev: ev, from: from, to: time.Now()}
	x.res, _ = ev["result"].(map[string]any)
	if x.res == nil {
		p.add(step, "", "answered", Pass, Fail, fmt.Sprintf("engine_connect_auto gave no result: stage=%v error=%v", ev["stage"], ev["error"]), nil, t0)
		return nil
	}
	x.connected, _ = x.res["connected"].(bool)
	x.routeID, _ = x.res["route_id"].(string)
	x.family, _ = x.res["family"].(string)
	x.verdict, _ = x.res["verdict"].(string)
	if n, ok := x.res["candidates"].(float64); ok {
		x.candidates = int(n)
	}
	rows, _ := x.res["tried"].([]any)
	for _, r := range rows {
		m, _ := r.(map[string]any)
		x.all = append(x.all, m)
		switch m["result"] {
		case "refused":
			x.left = append(x.left, m)
		case "stopped":
			x.stopped = append(x.stopped, m)
		default:
			x.tried = append(x.tried, m)
		}
	}
	p.twoAtATime(step, x, t0)
	// The same two questions a switch is asked (ops_switch.go), over the
	// whole pass: up to one engine instance per route on one TUN.
	p.sw.storeAndFDs(step, Family{Name: x.family}, ev, t0)
	return x
}

// auto block of the diagnostics taken right after the press.
func autoBlock(diag map[string]any) map[string]any {
	b, _ := diag["auto"].(map[string]any)
	if b == nil {
		return map[string]any{}
	}
	return b
}

// connectedOn records what "connected on route R" must mean after a
// press: the engine says so in all three places a page reads, the
// automatic connect is in charge, and verified bytes travel on R's own
// endpoint.
func (p *autoPhone) connectedOn(step string, x *autoAnswer, t0 time.Time) bool {
	diag, explain := diagOf(x.ev), explainOf(x.ev)
	blk := autoBlock(diag)
	var wrong []string
	if !x.connected {
		wrong = append(wrong, "connected=false")
	}
	if diag["active_route"] != x.routeID || diag["active_route_family"] != x.family || diag["route_running"] != true {
		wrong = append(wrong, fmt.Sprintf("ExportDiagnostics active_route=%q family=%q route_running=%v", diag["active_route"], diag["active_route_family"], diag["route_running"]))
	}
	if explain["active_route"] != x.routeID {
		wrong = append(wrong, fmt.Sprintf("DiagnosticsExplain.active_route=%q", explain["active_route"]))
	}
	if blk["state"] != "connected" || blk["mode"] != true || blk["route_id"] != x.routeID {
		wrong = append(wrong, fmt.Sprintf("auto block state=%v mode=%v route_id=%v", blk["state"], blk["mode"], blk["route_id"]))
	}
	ok := p.add(step, x.family, "connected", Pass, got(len(wrong) == 0, Pass, got(x.connected, Fail, Blocked)),
		got(len(wrong) == 0, "", "the call names "+x.routeID+" ("+x.family+"): "+strings.Join(wrong, ", ")+" — tried: "+x.triedText()),
		map[string]any{"route_id": x.routeID, "verdict": x.verdict, "tried": x.triedText(), "auto_state": blk["state"], "auto_mode": blk["mode"],
			"active_route": diag["active_route"], "route_check": diag["route_check"], "auto_ms": x.ev["auto_ms"], "client_dir": p.c.Dir}, t0)
	if !ok || !x.connected {
		return false
	}
	f, known := p.op.rc.Fams[x.family]
	if !known {
		return p.add(step, x.family, "tunnel", Pass, Fail, "the engine connected on a family the rig has no declaration for", nil, t0)
	}
	return p.sw.carries(step, f, t0)
}

// disconnect is the person disconnecting; the phone stays.
func (p *autoPhone) disconnect(step, family string, t0 time.Time) {
	rc := p.op.rc
	ev := p.ask(step, "disconnect", "down", 20*time.Second, t0)
	if ev == nil {
		return
	}
	after, _ := ev["after"].(map[string]any)
	wrapped := map[string]any{"store": after, "sentinels_bad": after["sentinels_bad"]}
	p.sw.storeAndFDs(step, Family{Name: family}, wrapped, t0)
	diag := diagOf(wrapped)
	blk := autoBlock(diag)
	var wrong []string
	if e, _ := ev["error"].(string); e != "" {
		wrong = append(wrong, "clear_route: "+e)
	}
	if diag["active_route"] != "" || diag["route_running"] == true {
		wrong = append(wrong, fmt.Sprintf("active_route=%q route_running=%v", diag["active_route"], diag["route_running"]))
	}
	if blk["state"] != "idle" || blk["mode"] != false {
		wrong = append(wrong, fmt.Sprintf("auto block state=%v mode=%v: the engine still thinks it is in charge", blk["state"], blk["mode"]))
	}
	p.add(step, family, "clean", Pass, got(len(wrong) == 0, Pass, Fail), strings.Join(wrong, "; "),
		map[string]any{"auto_state": blk["state"], "auto_mode": blk["mode"], "active_route": diag["active_route"]}, t0)
	post := Probe(rc.Ctx, rc.P, false, 2*time.Second)
	p.add(step, family, "control.after", Blocked, got(post.OK, Pass, Blocked), post.Error, nil, t0)
}

// stop ends the phone. Its last store and fd checks are recorded.
func (p *autoPhone) stop() {
	rc := p.op.rc
	t0 := time.Now()
	if p.c.Died() {
		ReapDeadVPN(rc.Ctx)
		return
	}
	bye := p.c.Stop()
	if bye == nil {
		p.add("stop", "", "clean", Pass, Fail, "the client did not report a disconnect: "+p.c.StderrTail(), map[string]any{"client_dir": p.c.Dir}, t0)
		ReapDeadVPN(rc.Ctx)
		return
	}
	after, _ := bye["after"].(map[string]any)
	p.sw.storeAndFDs("stop", Family{}, map[string]any{"store": after, "sentinels_bad": after["sentinels_bad"]}, t0)
	post := Probe(rc.Ctx, rc.P, false, 2*time.Second)
	p.add("stop", "", "control.after", Blocked, got(post.OK, Pass, Blocked), post.Error, nil, t0)
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

// leftOutFor is why a route was left out of the pass ("" when it was not).
func (x *autoAnswer) leftOutFor(routeID string) (string, bool) {
	for _, t := range x.left {
		if t["route_id"] == routeID {
			return str(t, "refused"), true
		}
	}
	return "", false
}

func (x *autoAnswer) triedEntry(routeID string) map[string]any {
	for _, t := range x.tried {
		if t["route_id"] == routeID {
			return t
		}
	}
	return nil
}

// sawProgress: while the pass was in flight a page polling the
// diagnostics saw `trying` with every index from 1 to n of the right
// total. (The poll is every 40 ms; a candidate that carries in less is
// the one step that may be missed, so the LAST index is not required.)
func (x *autoAnswer) sawProgress(n, total int) (bool, string) {
	rows, _ := x.ev["progress"].([]any)
	seen := map[int]bool{}
	for _, r := range rows {
		m, _ := r.(map[string]any)
		idx, _ := m["index"].(float64)
		tot, _ := m["total"].(float64)
		if m["state"] != "trying" || idx == 0 {
			continue
		}
		if int(tot) != total {
			return false, fmt.Sprintf("while trying route %d the diagnostics said total=%d; the call says %d candidates", int(idx), int(tot), total)
		}
		if m["mode"] != true {
			return false, "auto.mode was false while a pass was in flight"
		}
		seen[int(idx)] = true
	}
	for i := 1; i < n; i++ {
		if !seen[i] {
			return false, fmt.Sprintf("the diagnostics never showed route %d of %d being tried", i, total)
		}
	}
	return true, ""
}

// ---- first: nothing in the way ------------------------------------------

// first returns the first-ranked route and the route the engine checked
// beside it ("" when it checked none): the pair a phone that remembers
// nothing starts with, which the phones after this one block.
func (a *autoOp) first() (autoRoute, string, bool) {
	p := a.start("first", ClientOpts{})
	if p == nil {
		return autoRoute{}, "", false
	}
	defer p.stop()
	cands := p.candidates()
	if len(cands) < 2 {
		p.add("connect", "", "candidates", Skipped, Skipped, "needs a pack with two routes that are not behind the experimental gate", nil, time.Now())
		return autoRoute{}, "", false
	}
	t0 := time.Now()
	x := p.press("connect", "auto", t0)
	if x == nil {
		return autoRoute{}, "", false
	}
	// On a phone that remembers nothing the order is the ranking's, and
	// the ranking of routes that have used none of their budget is the
	// route id. One route carried, no verdict to give. A second route
	// may have been checked BESIDE the first (connect_race.go): it was
	// stopped when the first proved, and is named as that and nothing
	// else — it is not a route that was tried and left.
	var wrong []string
	if len(x.tried) != 1 || x.tried[0]["route_id"] != cands[0].ID || x.tried[0]["result"] != "carried" {
		wrong = append(wrong, "want exactly "+cands[0].ID+" tried, and carried")
	}
	partner := ""
	if e := x.entry(cands[0].ID); e != nil {
		partner = str(e, "raced_with") // also when the other one was not stopped but proved too
	}
	switch {
	case len(x.stopped) > 1:
		wrong = append(wrong, fmt.Sprintf("%d routes were being checked beside the first", len(x.stopped)))
	case len(x.stopped) == 1:
		partner = str(x.stopped[0], "route_id")
		if str(x.stopped[0], "raced_with") != cands[0].ID || len(x.tried) == 1 && str(x.tried[0], "raced_with") != partner {
			wrong = append(wrong, fmt.Sprintf("%s was stopped beside %q and %s says it was checked beside %q: the two do not name each other",
				partner, str(x.stopped[0], "raced_with"), cands[0].ID, str(x.tried[0], "raced_with")))
		}
	}
	if x.verdict != "" {
		wrong = append(wrong, "verdict="+x.verdict+", want none")
	}
	if x.candidates != len(cands) {
		wrong = append(wrong, fmt.Sprintf("candidates=%d, the pack has %d routes outside the experimental gate", x.candidates, len(cands)))
	}
	for _, r := range p.routes {
		if why, out := x.leftOutFor(r.ID); r.Experimental && (!out || why != "experimental_off") {
			wrong = append(wrong, fmt.Sprintf("%s (%s) is experimental and the gate is off: want it left out as experimental_off, got out=%v %q", r.ID, r.Family, out, why))
		}
	}
	p.add("connect", cands[0].Family, "first_route_first_try", Pass, got(len(wrong) == 0, Pass, Fail), strings.Join(wrong, "; "), x.evidence(), t0)
	if !p.connectedOn("connect", x, t0) {
		return autoRoute{}, "", false
	}
	p.measuredAfterConnect("connect", x, cands, t0)
	// Pressing Connect while connected does nothing.
	t0 = time.Now()
	if y := p.press("again", "auto", t0); y != nil {
		noop := y.connected && y.routeID == x.routeID && y.res["already_connected"] == true && len(y.tried) == 0
		p.add("again", x.family, "already_connected_is_a_no_op", Pass, got(noop, Pass, Fail),
			got(noop, "", "a second Connect while connected did something: "+y.triedText()), y.evidence(), t0)
		p.connectedOn("again", y, t0)
	}
	p.disconnect("disconnect", x.family, time.Now())
	return cands[0], partner, true
}

// ---- blocked: the first-ranked route is dropped ---------------------------

func (a *autoOp) blockedFirst(first autoRoute, partner string) {
	rc := a.rc
	p := a.start("blocked", ClientOpts{})
	if p == nil {
		return
	}
	defer p.stop()
	t0 := time.Now()
	if err := blockEndpoint(rc.Ctx, rc.Fams[first.Family]); err != nil {
		p.add("connect", first.Family, "censor.block", Pass, Fail, err.Error(), nil, t0)
		return
	}
	defer unblockEndpoint(rc.Ctx)
	x := p.press("connect", "auto", t0)
	if x == nil {
		return
	}
	// Two things the engine may honestly say of the dropped route, and
	// which one depends on whether it had company:
	//
	//   checked alone      it was tried, it carried nothing: not_carrying,
	//                      a category, and the pass is `moved_on`.
	//   checked beside     the other route proved while the dropped one
	//   another            was still waiting for its first answer, and the
	//                      check was stopped there: `stopped`. Nothing was
	//                      learned about it — a stopped check is not a
	//                      failed one — so there is no verdict to give.
	//
	// Either way it is the first-ranked route that is checked first, it
	// is never the one the engine says it is on, and the last thing in
	// `tried` is the route that carried.
	var wrong []string
	wantVerdict := "moved_on"
	if s := x.entry(first.ID); s != nil && s["result"] == "stopped" {
		wantVerdict = ""
		if partner != "" && str(s, "raced_with") != partner {
			wrong = append(wrong, fmt.Sprintf("%s was checked beside %q; a phone that remembers nothing checks it beside %s", first.ID, str(s, "raced_with"), partner))
		}
		if str(s, "raced_with") != x.routeID {
			wrong = append(wrong, fmt.Sprintf("%s was stopped for %q, and the engine is on %q", first.ID, str(s, "raced_with"), x.routeID))
		}
		if str(s, "category") != "" {
			wrong = append(wrong, "a check that was stopped has a failure category: "+str(s, "category"))
		}
	} else if len(x.tried) < 2 || x.tried[0]["route_id"] != first.ID {
		wrong = append(wrong, "the blocked route "+first.ID+" was not the first one tried")
	} else if x.tried[0]["result"] != "not_carrying" || str(x.tried[0], "category") == "" {
		wrong = append(wrong, fmt.Sprintf("the blocked route is reported as result=%v category=%q, want not_carrying and a category", x.tried[0]["result"], x.tried[0]["category"]))
	}
	if x.connected && x.routeID == first.ID {
		wrong = append(wrong, "the engine says it is connected on the route the censor drops")
	}
	if n := len(x.tried); n > 0 && (x.tried[n-1]["result"] != "carried" || x.tried[n-1]["route_id"] != x.routeID) {
		wrong = append(wrong, "the last route tried is not the one the call says carried")
	}
	p.add("connect", first.Family, "blocked_route_tried_and_named", Pass, got(len(wrong) == 0, Pass, Fail), strings.Join(wrong, "; "), x.evidence(), t0)
	p.add("connect", x.family, "verdict", wantVerdict, x.verdict, got(wantVerdict == "", "the dropped route's check was stopped, not failed: nothing to report", ""), x.evidence(), t0)
	if wantVerdict == "" {
		// The dropped route was still in flight when the pass ended. What
		// the phone remembers of it must be nothing: not a failure.
		if rows, _, ok := p.listing("connect", t0); ok {
			m := rows[first.ID]
			clean := m.Present && m.Failed == 0 && m.Grade != "failing"
			p.add("connect", first.Family, "a_stopped_check_is_not_a_failure", Pass, got(clean, Pass, Fail),
				got(clean, "", "the route whose check was stopped is remembered as "+m.text()), map[string]any{"measured": m.text()}, t0)
		}
	}
	seen, why := x.sawProgress(len(x.tried), x.candidates)
	if wantVerdict == "" {
		seen, why = x.sawRacing(first.ID, x.routeID)
	}
	p.add("connect", x.family, "progress_visible", Pass, got(seen, Pass, Fail), why, map[string]any{"progress": x.ev["progress"]}, t0)
	if !p.connectedOn("connect", x, t0) {
		return
	}
	p.disconnect("disconnect", x.family, time.Now())
	unblockEndpoint(rc.Ctx)

	// The same network, the block gone. The route that carried here goes
	// first, and says why.
	t0 = time.Now()
	y := p.press("again", "auto", t0)
	if y == nil {
		return
	}
	wrong = nil
	if len(y.tried) == 0 || y.tried[0]["route_id"] != x.routeID {
		wrong = append(wrong, "the route that carried on this network ("+x.routeID+") was not tried first")
	} else if y.tried[0]["why"] != "carried_here" {
		wrong = append(wrong, fmt.Sprintf("it was first, but why=%q: not because it is remembered", y.tried[0]["why"]))
	}
	if t := y.triedEntry(first.ID); t != nil && len(y.tried) > 0 && y.tried[0]["route_id"] == first.ID {
		wrong = append(wrong, "the route that failed here minutes ago was tried first")
	}
	p.add("again", x.family, "remembered_route_first", Pass, got(len(wrong) == 0, Pass, Fail), strings.Join(wrong, "; "), y.evidence(), t0)
	p.add("again", x.family, "verdict", "", y.verdict, "", y.evidence(), t0)
	p.connectedOn("again", y, t0)
}

// ---- memory, then network-wide UDP loss -----------------------------------

func (a *autoOp) memoryThenUDP(first autoRoute) {
	rc := a.rc
	p := a.start("memory", ClientOpts{})
	if p == nil {
		return
	}
	defer p.stop()
	// The QUIC route, by hand: on a fresh phone it is not first in the
	// ranking, and after this it is the only thing the phone remembers.
	var quic *autoRoute
	for _, r := range p.candidates() {
		if rc.Fams[r.Family].Endpoint.Proto == "udp" && rc.Fams[r.Family].Skip == "" && r.ID != first.ID {
			r := r
			quic = &r
		}
	}
	if quic == nil {
		p.add("by-hand", "", "quic_route", Skipped, Skipped, "needs a QUIC/UDP route outside the experimental gate that is not the first-ranked one", nil, time.Now())
		return
	}
	t0 := time.Now()
	ev := p.ask("by-hand", "connect "+quic.Family, "set", EngineConnectWait+10*time.Second, t0)
	if ev == nil {
		return
	}
	blk := autoBlock(diagOf(ev))
	okHand := ev["error"] == nil && blk["mode"] == false
	if !p.add("by-hand", quic.Family, "connected", Pass, got(okHand, Pass, Fail),
		got(okHand, "", fmt.Sprintf("error=%v auto.mode=%v (a route picked by hand is the person's, not the engine's)", ev["error"], blk["mode"])),
		map[string]any{"route_id": ev["route_id"], "auto_mode": blk["mode"], "auto_state": blk["state"]}, t0) {
		return
	}
	p.sw.storeAndFDs("by-hand", rc.Fams[quic.Family], ev, t0)
	p.disconnect("by-hand", quic.Family, time.Now())

	t0 = time.Now()
	x := p.press("connect", "auto", t0)
	if x == nil {
		return
	}
	var wrong []string
	if len(x.tried) != 1 || x.tried[0]["route_id"] != quic.ID || x.tried[0]["why"] != "carried_here" || x.tried[0]["result"] != "carried" {
		wrong = append(wrong, fmt.Sprintf("want only %s tried, first because it carried here; the ranking alone would start with %s", quic.ID, first.ID))
	}
	p.add("connect", quic.Family, "remembered_route_ahead_of_the_ranking", Pass, got(len(wrong) == 0, Pass, Fail), strings.Join(wrong, "; "), x.evidence(), t0)
	// …and alone. This is the phone on which that can be told: nothing
	// has been side-probed, and the remembered route is one the engine
	// could check beside another (ops_auto_race.go aloneProblems).
	aloneWrong, aloneEv := p.aloneProblems(x, quic.ID)
	p.add("connect", quic.Family, "remembered_route_alone", Pass, got(len(aloneWrong) == 0, Pass, Fail), strings.Join(aloneWrong, "; "), aloneEv, t0)
	if !p.connectedOn("connect", x, t0) {
		return
	}
	p.disconnect("disconnect", x.family, time.Now())

	// --- every UDP datagram the client sends now vanishes, to anyone.
	t0 = time.Now()
	if err := censorRules(rc.Ctx, fmt.Sprintf("ip saddr %s meta l4proto udp drop", ClientIP)); err != nil {
		p.add("udp", quic.Family, "censor.block", Pass, Fail, err.Error(), nil, t0)
		return
	}
	defer censorRules(rc.Ctx)
	y := p.press("udp", "auto", t0)
	if y == nil {
		return
	}
	q := y.triedEntry(quic.ID)
	wrong = nil
	switch {
	case q == nil || len(y.tried) == 0 || y.tried[0]["route_id"] != quic.ID:
		wrong = append(wrong, "the remembered QUIC route was not tried first")
	case q["result"] != "not_carrying":
		wrong = append(wrong, fmt.Sprintf("with all UDP dropped the QUIC route is result=%v", q["result"]))
	}
	p.add("udp", quic.Family, "quic_route_tried_and_silent", Pass, got(len(wrong) == 0, Pass, Fail), strings.Join(wrong, "; "), y.evidence(), t0)
	if q != nil {
		// CEN-4's second observation: this route alone saw silence; a TCP
		// route to the same address carried.
		p.add("udp", quic.Family, "refined", "udp_blocked_here", got(str(q, "refined") == "", "none", str(q, "refined")),
			"one route's own category stays what one route can see: "+str(q, "category"),
			map[string]any{"category": q["category"], "refined": q["refined"], "relay": q["relay"], "tried": y.triedText()}, t0)
	}
	p.add("udp", y.family, "verdict", "moved_on", y.verdict, "", y.evidence(), t0)
	if p.connectedOn("udp", y, t0) && rc.Fams[y.family].Endpoint.Proto != "tcp" {
		p.add("udp", y.family, "carried_on_tcp", Pass, Fail, "all UDP is dropped and the engine says it is connected on a UDP route", nil, t0)
	}
}

// ---- quic-only: what the pass cannot tell from network-wide UDP loss --------

// AutoRefinedQUICOnly is what a pass would have to say of a silent QUIC
// route when plain UDP to the same endpoint is delivered: the taxonomy's
// quic_unavailable, as opposed to udp_unavailable. The engine has no such
// word for `refined` yet and no observation to base it on (it would take
// one non-QUIC datagram to the same endpoint); see FINDINGS CEN-4.
const AutoRefinedQUICOnly = "quic_blocked_here"

func (a *autoOp) quicOnly(first autoRoute) {
	rc := a.rc
	p := a.start("quic-only", ClientOpts{})
	if p == nil {
		return
	}
	defer p.stop()
	var quic *autoRoute
	for _, r := range p.candidates() {
		if rc.Fams[r.Family].Endpoint.Proto == "udp" && rc.Fams[r.Family].Skip == "" && r.ID != first.ID {
			r := r
			quic = &r
		}
	}
	if quic == nil {
		p.add("by-hand", "", "quic_route", Skipped, Skipped, "needs a QUIC/UDP route outside the experimental gate that is not the first-ranked one", nil, time.Now())
		return
	}
	t0 := time.Now()
	ev := p.ask("by-hand", "connect "+quic.Family, "set", EngineConnectWait+10*time.Second, t0)
	if ev == nil || !p.add("by-hand", quic.Family, "connected", Pass, got(ev["error"] == nil, Pass, Fail), fmt.Sprint(ev["error"]), nil, t0) {
		return
	}
	p.disconnect("by-hand", quic.Family, time.Now())
	// The scenario quic-drop's own rule: QUIC v1 long-header packets from
	// the client, any port, any destination. Nothing else.
	t0 = time.Now()
	if err := censorRules(rc.Ctx, fmt.Sprintf("ip saddr %s meta l4proto udp @th,64,4 0xc @th,72,32 0x00000001 drop", ClientIP)); err != nil {
		p.add("connect", quic.Family, "censor.block", Pass, Fail, err.Error(), nil, t0)
		return
	}
	defer censorRules(rc.Ctx)
	x := p.press("connect", "auto", t0)
	if x == nil {
		return
	}
	q := x.triedEntry(quic.ID)
	silent := q != nil && q["result"] == "not_carrying"
	p.add("connect", quic.Family, "quic_route_tried_and_silent", Pass, got(silent, Pass, Fail), "", x.evidence(), t0)
	if silent {
		p.add("connect", quic.Family, "refined", AutoRefinedQUICOnly, got(str(q, "refined") == "", "none", str(q, "refined")),
			"plain UDP to this endpoint is delivered (scenario quic-drop proves that of this rule); the pass has seen nothing that says so",
			map[string]any{"category": q["category"], "refined": q["refined"], "tried": x.triedText()}, t0)
	}
	p.add("connect", x.family, "verdict", "moved_on", x.verdict, "", x.evidence(), t0)
	p.connectedOn("connect", x, t0)
}

// ---- all-blocked: the relay's address is null-routed ------------------------

func (a *autoOp) allBlocked() {
	rc := a.rc
	p := a.start("all-blocked", ClientOpts{})
	if p == nil {
		return
	}
	defer p.stop()
	t0 := time.Now()
	if err := censorRules(rc.Ctx, fmt.Sprintf("ip saddr %s ip daddr %s drop", ClientIP, RelayPublicAddrSet())); err != nil {
		p.add("cancel", "", "censor.block", Pass, Fail, err.Error(), nil, t0)
		return
	}
	defer censorRules(rc.Ctx)

	// Cancel, 1.5 s into the first candidate's check.
	x := p.press("cancel", "auto-cancel 1500", t0)
	if x == nil {
		return
	}
	back, _ := x.ev["cancel_to_return_ms"].(float64)
	inFlight, _ := x.ev["cancelled_in_flight"].(bool)
	var wrong []string
	n := len(x.tried)
	switch {
	case !inFlight:
		wrong = append(wrong, "the pass was over before the cancel: nothing was cancelled")
	case x.connected || x.verdict != "cancelled" || n == 0 || x.tried[n-1]["result"] != "cancelled":
		wrong = append(wrong, "want connected=false, verdict=cancelled and the route in flight reported as cancelled")
	case back > 2000:
		wrong = append(wrong, fmt.Sprintf("the call came back %d ms after the cancel: not promptly", int(back)))
	}
	p.add("cancel", "", "cancelled_promptly", Pass, got(len(wrong) == 0, Pass, Fail), strings.Join(wrong, "; "),
		map[string]any{"cancel_to_return_ms": back, "clear_route_calls": x.ev["clear_route_calls"], "verdict": x.verdict, "tried": x.triedText()}, t0)
	p.nothingRunning("cancel", x, "", t0)

	// The whole pass.
	t0 = time.Now()
	x = p.press("connect", "auto", t0)
	if x == nil {
		return
	}
	cands := p.candidates()
	wrong = nil
	if x.connected {
		wrong = append(wrong, "connected on "+x.routeID+" with the relay's address null-routed")
	}
	if len(x.tried) != len(cands) {
		wrong = append(wrong, fmt.Sprintf("%d routes tried, %d could be", len(x.tried), len(cands)))
	}
	for _, t := range x.tried {
		if t["result"] != "not_carrying" && t["result"] != "start_failed" {
			wrong = append(wrong, fmt.Sprintf("%v: result=%v", t["route_id"], t["result"]))
		}
	}
	p.add("connect", "", "every_candidate_tried_none_connected", Pass, got(len(wrong) == 0, Pass, Fail), strings.Join(wrong, "; "), x.evidence(), t0)
	// Every route goes to one address and not one SYN to it is answered:
	// that is all the pass saw, and it is what it must say.
	p.add("connect", "", "verdict", "relay_unreachable", x.verdict, "", x.evidence(), t0)
	for _, t := range x.tried {
		fam := str(t, "family")
		if rc.Fams[fam].Endpoint.Proto != "udp" {
			continue
		}
		// The other half of CEN-4: a silent QUIC route beside TCP routes
		// to the same address that got no answer either is a dead
		// address, not blocked UDP.
		p.add("connect", fam, "refined", "relay_unreachable", got(str(t, "refined") == "", "none", str(t, "refined")),
			"one route's own category: "+str(t, "category"), map[string]any{"category": t["category"], "refined": t["refined"], "tried": x.triedText()}, t0)
	}
	seen, why := x.sawProgress(len(x.tried)+1, x.candidates)
	p.add("connect", "", "progress_visible", Pass, got(seen, Pass, Fail), why, map[string]any{"progress": x.ev["progress"]}, t0)
	p.nothingRunning("connect", x, "relay_unreachable", t0)

	// Again, at once. Nothing at all answered in that pass, so no route
	// is resting: the same routes are candidates again and are tried
	// again, and the pass says the same thing. (Until the review of
	// 2026-11-19 this press answered `all_cooling_down` with nothing
	// started — and so did the person's, for five minutes, after one
	// moment without an uplink.)
	t0 = time.Now()
	y := p.press("again", "auto", t0)
	if y == nil {
		return
	}
	again := !y.connected && y.candidates == len(cands) && len(y.tried) == len(cands)
	p.add("again", "", "every_candidate_tried_again", Pass, got(again, Pass, Fail),
		got(again, "", fmt.Sprintf("candidates=%d tried=%d of %d: %s", y.candidates, len(y.tried), len(cands), y.triedText())), y.evidence(), t0)
	p.add("again", "", "verdict", "relay_unreachable", y.verdict, "", y.evidence(), t0)
	p.nothingRunning("again", y, "relay_unreachable", t0)
}

// nothingRunning: after a press that did not connect the engine has no
// route up, the host released the TUN, and — when the pass had a verdict
// — the verdict is still there to read after the host's teardown
// (clear_route), with nobody in charge.
func (p *autoPhone) nothingRunning(step string, x *autoAnswer, verdictKept string, t0 time.Time) {
	rc := p.op.rc
	diag := diagOf(x.ev)
	after, _ := x.ev["after_teardown"].(map[string]any)
	afterDiag, _ := after["diag"].(map[string]any)
	blk := autoBlock(afterDiag)
	var wrong []string
	if diag["active_route"] != "" || diag["route_running"] == true {
		wrong = append(wrong, fmt.Sprintf("when the call returned: active_route=%q route_running=%v", diag["active_route"], diag["route_running"]))
	}
	if x.ev["torn_down"] != true {
		wrong = append(wrong, "the host kept the TUN")
	} else if afterDiag["active_route"] != "" || afterDiag["route_running"] == true {
		wrong = append(wrong, fmt.Sprintf("after the teardown: active_route=%q route_running=%v", afterDiag["active_route"], afterDiag["route_running"]))
	}
	if blk["mode"] == true {
		wrong = append(wrong, "after the teardown auto.mode is still true")
	}
	if verdictKept != "" && (blk["state"] != "failed" || blk["verdict"] != verdictKept) {
		wrong = append(wrong, fmt.Sprintf("after the teardown the diagnostics say state=%v verdict=%q: the page that polls next cannot say why (want failed / %s)", blk["state"], blk["verdict"], verdictKept))
	}
	if verdictKept == "" && blk["state"] != "idle" {
		wrong = append(wrong, fmt.Sprintf("after a cancel the auto block says state=%v", blk["state"]))
	}
	p.add(step, "", "nothing_left_running", Pass, got(len(wrong) == 0, Pass, Fail), strings.Join(wrong, "; "),
		map[string]any{"active_route": diag["active_route"], "route_running": diag["route_running"], "torn_down": x.ev["torn_down"],
			"auto_state_after": blk["state"], "auto_verdict_after": blk["verdict"], "auto_mode_after": blk["mode"]}, t0)
	if after != nil {
		p.sw.storeAndFDs(step+".teardown", Family{}, map[string]any{"store": after, "sentinels_bad": after["sentinels_bad"]}, t0)
	}
	post := Probe(rc.Ctx, rc.P, false, 2*time.Second)
	p.add(step, "", "control.after", Blocked, got(post.OK, Pass, Blocked), post.Error, nil, t0)
}

// ---- fall-over: the running route stops carrying ----------------------------

// AutoLivenessS / AutoRecheckS are the fall-over phone's liveness clocks
// (the engine's connection_check.liveness_interval_s / recheck_interval_s;
// production: 180 s ±25 % and 30 s). AutoFallOverWait bounds the wait for
// the engine to have moved: one interval, one failed check (up to ~12 s),
// one connect.
const (
	AutoLivenessS    = 3
	AutoRecheckS     = 3
	AutoFallOverWait = 90 * time.Second
)

func (a *autoOp) fallOver() {
	rc := a.rc
	p := a.start("fall-over", ClientOpts{LivenessS: AutoLivenessS, RecheckS: AutoRecheckS})
	if p == nil {
		return
	}
	defer p.stop()
	t0 := time.Now()
	x := p.press("connect", "auto", t0)
	if x == nil || !p.connectedOn("connect", x, t0) {
		return
	}
	tun, _ := x.ev["tun"].(string)

	// The censor starts dropping the running route. From here the host
	// only LOOKS (`diag` calls engine_export_diagnostics and nothing else).
	t0 = time.Now()
	if err := blockEndpoint(rc.Ctx, rc.Fams[x.family]); err != nil {
		p.add("moved", x.family, "censor.block", Pass, Fail, err.Error(), nil, t0)
		return
	}
	defer unblockEndpoint(rc.Ctx)
	var d map[string]any
	var states []string
	moved := false
	deadline := time.Now().Add(AutoFallOverWait)
	for time.Now().Before(deadline) && rc.Ctx.Err() == nil {
		d = p.ask("moved", "diag", "diag", 20*time.Second, t0)
		if d == nil {
			return
		}
		diag, _ := d["diag"].(map[string]any)
		blk := autoBlock(diag)
		s := fmt.Sprintf("%v/%v", blk["state"], diag["active_route"])
		if len(states) == 0 || states[len(states)-1] != s {
			states = append(states, s)
		}
		if blk["state"] == "connected" && blk["route_id"] != x.routeID && blk["route_id"] != "" && diag["active_route"] == blk["route_id"] {
			moved = true
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	diag, _ := d["diag"].(map[string]any)
	blk := autoBlock(diag)
	now, _ := blk["route_id"].(string)
	nowFam, _ := blk["family"].(string)
	ev := map[string]any{"was_on": x.routeID, "now_on": now, "family": nowFam, "waited_ms": time.Since(t0).Milliseconds(),
		"liveness_interval_s": AutoLivenessS, "seen": strings.Join(states, " → "), "verdict": blk["verdict"], "route_check": diag["route_check"]}
	if !p.add("moved", x.family, "engine_moved_by_itself", Pass, got(moved, Pass, Blocked),
		got(moved, "", fmt.Sprintf("%s after the censor began dropping %s the engine is still not connected on another route (seen: %s)",
			time.Since(t0).Round(time.Second), x.routeID, strings.Join(states, " → "))), ev, t0) {
		return
	}
	var wrong []string
	tried, _ := blk["tried"].([]any)
	if len(tried) == 0 {
		wrong = append(wrong, "auto.tried is empty")
	} else if f, _ := tried[0].(map[string]any); f["route_id"] != x.routeID || f["result"] != "not_carrying" || f["why"] != "was_connected" {
		wrong = append(wrong, fmt.Sprintf("the first entry is %v result=%v why=%v, want the route that stopped carrying", f["route_id"], f["result"], f["why"]))
	}
	if blk["verdict"] != "moved_on" {
		wrong = append(wrong, fmt.Sprintf("verdict=%q, want moved_on", blk["verdict"]))
	}
	if blk["mode"] != true {
		wrong = append(wrong, "auto.mode is false after the move")
	}
	if diag["active_route_family"] != nowFam || diag["route_running"] != true {
		wrong = append(wrong, fmt.Sprintf("active_route_family=%q route_running=%v", diag["active_route_family"], diag["route_running"]))
	}
	p.add("moved", nowFam, "says_what_happened", Pass, got(len(wrong) == 0, Pass, Fail), strings.Join(wrong, "; "), ev, t0)
	sameTun := d["tun"] == tun && tun != ""
	p.add("moved", nowFam, "same_tun", Pass, got(sameTun, Pass, Fail),
		got(sameTun, "", fmt.Sprintf("the phone held %q before and %q after", tun, d["tun"])), map[string]any{"tun": tun}, t0)
	bad := anyStrings(d["sentinels_bad"])
	p.add("moved", nowFam, "fds_intact", Pass, got(len(bad) == 0, Pass, Fail), strings.Join(bad, "; "), nil, t0)
	if f, known := rc.Fams[nowFam]; known {
		p.sw.carries("moved", f, t0)
	}
}

// ---- one phone under a scenario that blocks something -------------------------

// AutoVerdictUnder is the verdict a failed pass must give under the
// scenarios in which no route can carry: what the censor does there, and
// nothing narrower or wider.
var AutoVerdictUnder = map[string]string{
	// One address, every port, silent. TCP SYNs unanswered.
	"relay-ip-block": "relay_unreachable",
	// Nothing leaves the border at all — to the relay or to anyone. That
	// is what is TRUE there, and what this check asks for. The engine has
	// no probe outside its routes, and what Android says of such a
	// network — the link is up, the platform has not validated it — is
	// also what it says of a network that merely filters the platform's
	// own connectivity check, so the engine does not take it for "no
	// internet" (FINDINGS AUTO-1, open again; only kind `none` is taken
	// at its word: auto-deep `networks.down`). The check is red and
	// known.
	"total-blackout": "network_down",
}

func (a *autoOp) underScenario() {
	rc := a.rc
	// What Android would say of this network. Under total-blackout
	// nothing the phone sends gets anywhere, the platform's own check
	// included: connected to the access point, not validated. Everywhere
	// else the internet is there and only the relay (or part of it) is
	// not. The engine adds no traffic to learn this; it is told
	// (engine_network_facts).
	validated := 1
	if rc.Scn.Name == "total-blackout" {
		validated = 0
	}
	a.pressUnder("scenario", fmt.Sprintf("auto-net wifi %s %d 0", hostID("scn"), validated), AutoVerdictUnder[rc.Scn.Name])
	if rc.Scn.Name == "total-blackout" {
		// A host with nobody to tell it (the desktop shell has no network
		// observer): the same press, no fact. All the engine has is its
		// routes, all to one address, all silent.
		a.pressUnder("scenario-untold", "auto", "relay_unreachable")
	}
}

func (a *autoOp) pressUnder(label, cmd, wantVerdict string) {
	rc := a.rc
	p := a.start(label, ClientOpts{})
	if p == nil {
		return
	}
	defer p.stop()
	cands := p.candidates()
	canPass, degraded := 0, 0
	for _, r := range cands {
		switch e, _ := rc.Scn.ExpectFor(r.Family); {
		case rc.Fams[r.Family].Skip != "":
		case e == Pass:
			canPass++
		case rc.Scn.MustEstablish(r.Family):
			degraded++
		}
	}
	t0 := time.Now()
	x := p.press("connect", cmd, t0)
	if x == nil {
		return
	}
	// No route the scenario stops may be reported as carrying, whatever
	// else happens.
	var wrong []string
	for _, t := range x.tried {
		fam := str(t, "family")
		e, _ := rc.Scn.ExpectFor(fam)
		stopped := e != Pass && !rc.Scn.MustEstablish(fam)
		if t["result"] == "carried" && stopped {
			wrong = append(wrong, fmt.Sprintf("%v (%s) is reported as carrying; the scenario stops it", t["route_id"], fam))
		}
		if t["result"] != "carried" && e == Pass {
			wrong = append(wrong, fmt.Sprintf("%v (%s) is reported as %v; the scenario does not touch it", t["route_id"], fam, t["result"]))
		}
	}
	p.add("connect", "", "tried_agrees_with_the_censor", Pass, got(len(wrong) == 0, Pass, Fail), strings.Join(wrong, "; "), x.evidence(), t0)
	switch {
	case canPass > 0:
		if p.connectedOn("connect", x, t0) {
			e, _ := rc.Scn.ExpectFor(x.family)
			p.add("connect", x.family, "connected_on_a_route_the_censor_spares", Pass, got(e == Pass || rc.Scn.MustEstablish(x.family), Pass, Fail), "", x.evidence(), t0)
		}
	case degraded > 0:
		// A path the scenario degrades without cutting may or may not
		// carry the engine's round trip in its budget: recorded, not judged.
		p.add("connect", x.family, "connected", Skipped, Skipped,
			fmt.Sprintf("the scenario degrades every route without cutting it; this pass: connected=%v verdict=%q", x.connected, x.verdict), x.evidence(), t0)
		if !x.connected {
			p.nothingRunning("connect", x, x.verdict, t0)
		}
	default:
		p.add("connect", "", "not_connected", Blocked, got(x.connected, Pass, Blocked), "", x.evidence(), t0)
		if wantVerdict != "" {
			p.add("connect", "", "verdict", wantVerdict, x.verdict, "", x.evidence(), t0)
		} else {
			p.add("connect", "", "verdict", Skipped, Skipped, "no verdict is declared for this scenario (AutoVerdictUnder); the engine said "+x.verdict, x.evidence(), t0)
		}
		if !x.connected {
			p.nothingRunning("connect", x, x.verdict, t0)
		}
	}
}

// ---- the censor, for a moment ----------------------------------------------

const autoTable = "wb_auto"

// censorRules replaces this op's private table at the censor with the
// given forward-chain rules; with none, removes it. (blockEndpoint in
// ops_switch.go is the one-endpoint case and has its own table.)
func censorRules(ctx context.Context, rules ...string) error {
	body := fmt.Sprintf("add table inet %[1]s\ndelete table inet %[1]s\n", autoTable)
	if len(rules) > 0 {
		body += fmt.Sprintf("table inet %s {\n  chain forward { type filter hook forward priority -10; policy accept;\n", autoTable)
		for _, r := range rules {
			body += "    " + r + "\n"
		}
		body += "  }\n}\n"
	}
	cmd := exec.CommandContext(ctx, "ip", "netns", "exec", NSCensor, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(body)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("censor rules: nft: %v: %s", err, out)
	}
	return nil
}
