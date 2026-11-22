package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func init() {
	Ops["auto-deep"] = opAutoDeep
}

// The second slice of the automatic connect, the slow half (op `auto`
// has racing, the remembered route alone, and the `measured` block after
// a connect — ops_auto_race.go). Each phone here waits for something the
// engine does on its own clock or costs a whole failed pass, which is
// why it is its own op and runs in the full matrix only. A world whose
// scenario blocks nothing; five phones, each a fresh state directory:
//
//	slow      The person connects one route by hand: the route list grades
//	          it from that one connect. Then the censor delays that
//	          route's endpoint — every packet the client sends to it
//	          waits 2.5 s, nothing is dropped, no other endpoint is
//	          touched. Within a few of the engine's own checks the list
//	          says "slow" for it on this network, and still counts it as
//	          carrying.
//	speed     Connected by the button on the remembered route. The censor
//	          starts delaying it. The host does nothing. After two slow
//	          checks in a row the engine proves ANOTHER route beside the
//	          running one and moves to it: verdict `moved_faster`, the old
//	          route named with path_too_slow, the same TUN, verified bytes
//	          on the new endpoint, never more than two endpoints in use.
//	          Then the censor delays the NEW route and frees the old: the
//	          engine stays where it is and opens no connection to any
//	          other endpoint for as long as the rig watches (the hold) —
//	          bar the survey's own checks of the other routes, which the
//	          engine's `survey` block names (they move nothing).
//	metered   The same start on a network the host calls metered. The
//	          engine stays on the slow route and the censor sees no new
//	          connection to any other endpoint: no probe for a move is
//	          started by the engine itself on a network the person pays
//	          for. (The survey's one check of each route per day there is
//	          by design — core/abi survey.go METERED — and is told apart
//	          by its `survey` block.)
//	networks  engine_network_facts, as the Android service's callback
//	          calls it. A route that carried on network X is checked
//	          alone on X, is "unknown" on network Y and is NOT pulled
//	          ahead there, and is remembered again back on X. Kind `none`
//	          stops no press. With the relay's address null-routed and the
//	          host saying "no network at all" (kind `none`) the verdict is
//	          `network_down`; the same phone, the same block, and the host
//	          saying "a network, not validated" or "validated" is
//	          `relay_unreachable`: an unvalidated network is not proof of
//	          no internet (FINDINGS AUTO-1).
//	          The two ids the host sent are in no file the engine wrote.
//	leaks     A check that is stopped because the other route proved, and
//	          a pair cancelled in flight by the person, leave what the
//	          same number of connects by hand leave: no open file, no
//	          goroutine, none of a sing-box instance's. (A connect by hand
//	          itself leaves one open file behind — FINDINGS SW-3 — which
//	          is asked separately and is not the side instance's.)
func opAutoDeep(rc *RunCtx) {
	const phase = "op:auto-deep"
	a := &autoOp{rc: rc, phase: phase}
	if a.scenarioBlocks() || len(rc.Scn.Censor.TC) > 0 {
		rc.R.Add("", phase, "world", Skipped, Skipped, "op auto-deep needs a scenario that blocks nothing and shapes nothing: it brings its own censor, one endpoint at a time", nil, time.Now())
		return
	}
	a.tap()
	for _, ph := range []struct {
		name string
		run  func()
	}{
		{"slow", a.slowGrade},
		{"speed", func() { a.speedMove(false) }},
		{"metered", func() { a.speedMove(true) }},
		{"networks", a.networks},
		{"leaks", a.leaks},
	} {
		if autoPhoneWanted(ph.name) {
			ph.run()
		}
	}
}

// ---- the censor, slowing one endpoint -------------------------------------

const (
	slowTable = "wb_slow"
	// AutoSlowDelay: what every packet the client sends to the slowed
	// endpoint waits. A check of a connected route is one flight from
	// the client on the families that keep a session to the relay (the
	// far side's TLS handshake is done when its answer is back), so the
	// delay itself has to be over the engine's slow_after (2 s) and under
	// its attempt timeout (4 s): the check then passes, slowly.
	AutoSlowDelay = 2500 * time.Millisecond
	// AutoDeepLivenessS: the engine's liveness clock on these phones
	// (production: 180 s ±25 %; see AUTO-O1).
	AutoDeepLivenessS = 3
	// AutoSpeedWait bounds the wait for a grade or a move: two slow
	// checks (an interval and a slow check each), one probe, one connect.
	AutoSpeedWait = 90 * time.Second
	// AutoHoldWatch: how long the rig watches a route the engine must
	// stay on. Long enough for three more slow checks.
	AutoHoldWatch = 30 * time.Second
)

// slowEndpoint makes every packet the client sends to one family's
// endpoint wait `delay` at the censor. Nothing is dropped and no other
// endpoint is touched: a prio qdisc with one extra band that only marked
// packets enter, netem on that band, and an nft rule that marks.
func slowEndpoint(ctx context.Context, f Family, delay time.Duration) error {
	for _, argv := range [][]string{
		{"tc", "qdisc", "replace", "dev", CensorDevRelay, "root", "handle", "1:", "prio", "bands", "4",
			"priomap", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"},
		{"tc", "qdisc", "replace", "dev", CensorDevRelay, "parent", "1:4", "handle", "40:", "netem", "delay", fmt.Sprintf("%dms", delay.Milliseconds())},
	} {
		if _, err := sh(ctx, inNS(NSCensor, argv...)...); err != nil {
			return fmt.Errorf("slow %s: %w", f.Name, err)
		}
	}
	rules := fmt.Sprintf("add table inet %[1]s\ndelete table inet %[1]s\ntable inet %[1]s {\n  chain post { type filter hook postrouting priority 0; policy accept;\n"+
		"    oifname %q ip saddr %s ip daddr %s %s dport %d meta priority set 1:4\n  }\n}\n",
		slowTable, CensorDevRelay, ClientIP, RelayPublicAddrSet(), f.Endpoint.Proto, f.Endpoint.Port)
	cmd := exec.CommandContext(ctx, "ip", "netns", "exec", NSCensor, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("slow %s: nft: %v: %s", f.Name, err, out)
	}
	return nil
}

func unslowEndpoint(ctx context.Context) {
	cmd := exec.CommandContext(ctx, "ip", "netns", "exec", NSCensor, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(fmt.Sprintf("add table inet %[1]s\ndelete table inet %[1]s\n", slowTable))
	_ = cmd.Run()
	_, _ = sh(ctx, inNS(NSCensor, "tc", "qdisc", "del", "dev", CensorDevRelay, "root")...)
}

// hostID is an id the lab's "Android" reports for a network: random, so
// that finding it in a file can only mean somebody wrote it there.
func hostID(label string) string {
	// Lowercase letters only and under 24 characters, on purpose: the
	// engine's log scrubber removes anything that looks like a token or
	// an address, and an id it would remove could be logged carelessly
	// without this rig ever seeing it.
	b := make([]byte, 14)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = 'a' + b[i]%26
	}
	return "wb" + label + string(b)
}

// net sends one report of the service's network callback and returns the
// engine's answer.
func (p *autoPhone) net(step, kind, id string, validated, metered int, t0 time.Time) map[string]any {
	if id == "" {
		id = "-"
	}
	ev := p.ask(step, fmt.Sprintf("net %s %s %d %d", kind, id, validated, metered), "net", 20*time.Second, t0)
	if ev == nil {
		return nil
	}
	ans, _ := ev["answer"].(map[string]any)
	if e := str(ev, "error"); e != "" || ans == nil {
		p.add(step, "", "network_facts", Pass, Fail, "engine_network_facts: "+e, nil, t0)
		return nil
	}
	return ans
}

// byHand connects one family by hand and disconnects: what the phone
// then remembers of this network is that this route carried here.
func (p *autoPhone) byHand(step string, f Family, t0 time.Time) bool {
	ev := p.ask(step, "connect "+f.Name, "set", EngineConnectWait+10*time.Second, t0)
	if ev == nil {
		return false
	}
	if !p.add(step, f.Name, "connected", Pass, got(ev["error"] == nil, Pass, Fail), fmt.Sprint(ev["error"]), map[string]any{"set_route_ms": ev["set_route_ms"]}, t0) {
		return false
	}
	p.disconnect(step, f.Name, time.Now())
	return true
}

// watch polls the diagnostics until done says so or the time is up. It
// returns the last answer and every distinct (route_check/auto state/
// route) it saw.
func (p *autoPhone) watch(step string, limit time.Duration, t0 time.Time, done func(diag, blk map[string]any) bool) (last map[string]any, states []string, ok bool) {
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) && p.op.rc.Ctx.Err() == nil {
		d := p.ask(step, "diag", "diag", 20*time.Second, t0)
		if d == nil {
			return last, states, false
		}
		last = d
		diag, _ := d["diag"].(map[string]any)
		blk := autoBlock(diag)
		s := fmt.Sprintf("%v/%v/%v", diag["route_check"], blk["state"], diag["active_route"])
		if len(states) == 0 || states[len(states)-1] != s {
			states = append(states, s)
		}
		if done(diag, blk) {
			return last, states, true
		}
		time.Sleep(250 * time.Millisecond)
	}
	return last, states, false
}

func endpointOf(f Family) string { return fmt.Sprintf("%s/%d", f.Endpoint.Proto, f.Endpoint.Port) }

// surveyedEndpoints: the endpoints of the routes the engine's survey
// (core/abi survey.go: the other routes checked one at a time beside the
// tunnel, 10–20 s after a connect and 10–25 s apart) says it checked or
// is checking, read from the diagnostics blob's `survey` block. Those
// connections are the survey's — which checks a route once a day on a
// metered network too, by design — not a probe for a move: the hold and
// the metered phone judge everything else.
func (a *autoOp) surveyedEndpoints(diag map[string]any, routes []autoRoute) map[string]bool {
	out := map[string]bool{}
	sv, _ := diag["survey"].(map[string]any)
	if sv == nil {
		return out
	}
	add := func(family string) {
		if f, ok := a.rc.Fams[family]; ok {
			out[endpointOf(f)] = true
		}
	}
	results, _ := sv["results"].([]any)
	for _, x := range results {
		m, _ := x.(map[string]any)
		switch m["result"] {
		case "carried", "not_carrying", "start_failed", "cancelled":
			fam, _ := m["family"].(string)
			add(fam)
		}
	}
	if checking, _ := sv["checking"].([]any); len(checking) > 0 {
		// Only ids: the family is in the results once filed; a route in
		// flight at the last poll is matched by the phone's route list.
		for _, id := range checking {
			for _, r := range routes {
				if r.ID == id {
					add(r.Family)
				}
			}
		}
	}
	return out
}

func surveyedText(m map[string]bool) string {
	var out []string
	for e := range m {
		out = append(out, e)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// ---- slow: a route the censor delays is graded slow -----------------------

func (a *autoOp) slowGrade() {
	rc := a.rc
	p := a.start("slow", ClientOpts{LivenessS: AutoDeepLivenessS, RecheckS: AutoDeepLivenessS})
	if p == nil {
		return
	}
	defer p.stop()
	cands := p.candidates()
	if len(cands) == 0 {
		return
	}
	r := cands[0]
	f := rc.Fams[r.Family]
	t0 := time.Now()
	ev := p.ask("by-hand", "connect "+f.Name, "set", EngineConnectWait+10*time.Second, t0)
	if ev == nil {
		return
	}
	if !p.add("by-hand", f.Name, "connected", Pass, got(ev["error"] == nil, Pass, Fail), fmt.Sprint(ev["error"]), map[string]any{"set_route_ms": ev["set_route_ms"]}, t0) {
		return
	}
	// A connect by hand is measured like any other.
	before, _, ok := p.listing("by-hand", t0)
	if !ok {
		return
	}
	m0 := before[r.ID]
	fed := (m0.Grade == "good" || m0.Grade == "ok") && m0.Samples == 1 && m0.Carried >= 1
	p.add("by-hand", f.Name, "a_connect_by_hand_is_measured", Pass, got(fed, Pass, Fail), got(fed, "", m0.text()), map[string]any{"measured": measuredText(before)}, t0)

	// The censor starts delaying the route. The person does nothing.
	t0 = time.Now()
	if err := slowEndpoint(rc.Ctx, f, AutoSlowDelay); err != nil {
		p.add("by-hand", f.Name, "censor.slow", Pass, Fail, err.Error(), nil, t0)
		return
	}
	defer unslowEndpoint(rc.Ctx)
	// The engine's own checks, on its own clock, and the list a page
	// reads. Nothing else is asked of the engine.
	var rows map[string]measuredRow
	seen := []string{m0.Grade}
	deadline := time.Now().Add(AutoSpeedWait)
	graded := false
	for time.Now().Before(deadline) && rc.Ctx.Err() == nil {
		var ok bool
		if rows, _, ok = p.listing("by-hand", t0); !ok {
			return
		}
		if g := rows[r.ID].Grade; len(seen) == 0 || seen[len(seen)-1] != g {
			seen = append(seen, g)
		}
		if rows[r.ID].Grade == "slow" {
			graded = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	m := rows[r.ID]
	p.add("by-hand", f.Name, "graded_slow_here", Pass, got(graded, Pass, Fail),
		got(graded, "", fmt.Sprintf("%s after the censor began delaying every packet to a route connected by hand by %s, it is remembered as %s (grades seen: %s)",
			time.Since(t0).Round(time.Second), AutoSlowDelay, m.text(), strings.Join(seen, " → "))),
		map[string]any{"measured": measuredText(rows), "grade_seen": strings.Join(seen, " → "), "waited_ms": time.Since(t0).Milliseconds()}, t0)
	if graded {
		// Slow is not failing: the route carried every time.
		honest := m.Carried >= 1 && m.Failed == 0
		p.add("by-hand", f.Name, "slow_is_not_failing", Pass, got(honest, Pass, Fail), got(honest, "", m.text()), map[string]any{"measured": m.text()}, t0)
	}
	unslowEndpoint(rc.Ctx)
	p.disconnect("disconnect", f.Name, time.Now())
}

// ---- speed / metered: the running route becomes slow -----------------------

func (a *autoOp) speedMove(metered bool) {
	rc := a.rc
	label := got(metered, "metered", "speed")
	p := a.start(label, ClientOpts{LivenessS: AutoDeepLivenessS, RecheckS: AutoDeepLivenessS})
	if p == nil {
		return
	}
	defer p.stop()
	cands := p.candidates()
	if len(cands) < 3 {
		p.add("start", "", "candidates", Skipped, Skipped, "needs three candidates: the one that runs, one to move to, one that could be moved to next", nil, time.Now())
		return
	}
	first := cands[0]
	ff := rc.Fams[first.Family]
	t0 := time.Now()
	// The service's callback, before anything: this network, validated,
	// metered or not.
	meteredFact := 0
	if metered {
		meteredFact = 1
	}
	if p.net("start", "wifi", hostID(label), 1, meteredFact, t0) == nil {
		return
	}
	// By hand once, so the press below checks ONE route — the remembered
	// one — and nothing is side-probed before the censor starts: every
	// other route is still one the engine may probe (a route probed in
	// the last minutes is not probed again).
	if !p.byHand("by-hand", ff, t0) {
		return
	}
	t0 = time.Now()
	x := p.press("connect", "auto", t0)
	if x == nil || !p.connectedOn("connect", x, t0) {
		return
	}
	alone := x.routeID == first.ID && len(x.tried) == 1 && len(x.stopped) == 0
	if !p.add("connect", first.Family, "on_the_remembered_route_nothing_probed", Pass, got(alone, Pass, Fail), got(alone, "", x.triedText()), x.evidence(), t0) {
		return
	}
	tun, _ := x.ev["tun"].(string)

	// The censor starts delaying the running route. From here the host
	// only LOOKS.
	t0 = time.Now()
	slowFrom := time.Now()
	if err := slowEndpoint(rc.Ctx, ff, AutoSlowDelay); err != nil {
		p.add("slow", first.Family, "censor.slow", Pass, Fail, err.Error(), nil, t0)
		return
	}
	defer unslowEndpoint(rc.Ctx)

	if metered {
		a.staysOnMetered(p, first, ff, slowFrom, t0)
		return
	}

	d, states, moved := p.watch("moved", AutoSpeedWait, t0, func(diag, blk map[string]any) bool {
		return blk["state"] == "connected" && blk["route_id"] != first.ID && blk["route_id"] != "" && diag["active_route"] == blk["route_id"]
	})
	if d == nil {
		return
	}
	movedAt := time.Now()
	diag, _ := d["diag"].(map[string]any)
	blk := autoBlock(diag)
	now, nowFam := str(blk, "route_id"), str(blk, "family")
	ev := map[string]any{"was_on": first.ID, "now_on": now, "family": nowFam, "waited_ms": time.Since(t0).Milliseconds(),
		"liveness_interval_s": AutoDeepLivenessS, "delay_ms": AutoSlowDelay.Milliseconds(), "seen": strings.Join(states, " → "), "verdict": blk["verdict"]}
	if !p.add("moved", first.Family, "engine_moved_for_speed", Pass, got(moved, Pass, Blocked),
		got(moved, "", fmt.Sprintf("%s after the censor began delaying %s the engine is still on it (seen: %s)", time.Since(t0).Round(time.Second), first.ID, strings.Join(states, " → "))), ev, t0) {
		return
	}
	var wrong []string
	tried, _ := blk["tried"].([]any)
	if len(tried) != 2 {
		wrong = append(wrong, fmt.Sprintf("auto.tried has %d entries, want the route left and the route moved to", len(tried)))
	} else {
		old, _ := tried[0].(map[string]any)
		nu, _ := tried[1].(map[string]any)
		if old["route_id"] != first.ID || old["result"] != "carried" || old["category"] != "path_too_slow" || old["why"] != "was_connected" {
			wrong = append(wrong, fmt.Sprintf("the first entry is %v result=%v category=%v why=%v, want the route that was slow and still carried", old["route_id"], old["result"], old["category"], old["why"]))
		}
		if ms, _ := nu["setup_ms"].(float64); nu["route_id"] != now || nu["result"] != "carried" || ms <= 0 {
			wrong = append(wrong, fmt.Sprintf("the second entry is %v result=%v setup_ms=%v, want the route moved to and its time", nu["route_id"], nu["result"], nu["setup_ms"]))
		}
	}
	if blk["verdict"] != "moved_faster" {
		wrong = append(wrong, fmt.Sprintf("verdict=%q, want moved_faster", blk["verdict"]))
	}
	if blk["mode"] != true {
		wrong = append(wrong, "auto.mode is false after the move")
	}
	sawSlow := false
	for _, s := range states {
		sawSlow = sawSlow || strings.HasPrefix(s, "degraded/")
	}
	if !sawSlow {
		wrong = append(wrong, "the diagnostics never said the running route was degraded before the move")
	}
	p.add("moved", nowFam, "says_what_happened", Pass, got(len(wrong) == 0, Pass, Fail), strings.Join(wrong, "; "), ev, t0)
	sameTun := d["tun"] == tun && tun != ""
	p.add("moved", nowFam, "same_tun", Pass, got(sameTun, Pass, Fail), got(sameTun, "", fmt.Sprintf("the phone held %q before and %q after", tun, d["tun"])), map[string]any{"tun": tun}, t0)
	bad := anyStrings(d["sentinels_bad"])
	p.add("moved", nowFam, "fds_intact", Pass, got(len(bad) == 0, Pass, Fail), strings.Join(bad, "; "), nil, t0)
	if a.tapOK {
		if pkts, err := ReadFlowTap(rc.P); err == nil {
			uses := flowUses(pkts, slowFrom, movedAt)
			n, set := maxConcurrent(uses)
			two := n <= AutoMaxInFlight && len(uses) <= 2
			p.add("moved", nowFam, "one_route_probed_beside_the_running_one", Pass, got(two, Pass, Fail),
				got(two, "", fmt.Sprintf("the censor saw new connections to %d endpoints, %d at once (%s): %s", len(uses), n, strings.Join(set, ", "), flowText(uses, slowFrom))),
				map[string]any{"censor_saw": flowText(uses, slowFrom)}, t0)
		}
	}
	nf, known := rc.Fams[nowFam]
	if !known {
		return
	}
	p.sw.carries("moved", nf, t0)
	if rows, _, ok := p.listing("moved", t0); ok {
		m := rows[first.ID]
		p.add("moved", first.Family, "the_route_left_is_graded_slow", Pass, got(m.Grade == "slow", Pass, Fail), got(m.Grade == "slow", "", m.text()), map[string]any{"measured": measuredText(rows)}, t0)
	}

	// The hold. The NEW route is delayed now and the old one is free
	// again; a third route nothing has been asked of is there to move
	// to. The engine stays.
	t0 = time.Now()
	holdFrom := time.Now()
	if err := slowEndpoint(rc.Ctx, nf, AutoSlowDelay); err != nil {
		p.add("hold", nowFam, "censor.slow", Pass, Fail, err.Error(), nil, t0)
		return
	}
	d, states, _ = p.watch("hold", AutoHoldWatch, t0, func(diag, blk map[string]any) bool { return blk["route_id"] != now })
	if d == nil {
		return
	}
	diag, _ = d["diag"].(map[string]any)
	blk = autoBlock(diag)
	wrong = nil
	if blk["route_id"] != now || diag["active_route"] != now || blk["state"] != "connected" {
		wrong = append(wrong, fmt.Sprintf("the engine left %s: now route_id=%v state=%v verdict=%v", now, blk["route_id"], blk["state"], blk["verdict"]))
	}
	slowChecks := 0
	for _, s := range states {
		if strings.HasPrefix(s, "degraded/") {
			slowChecks++
		}
	}
	if slowChecks == 0 {
		wrong = append(wrong, "the engine never called the new route degraded while the censor delayed it: the hold was not put to the test")
	}
	ev = map[string]any{"on": now, "watched_ms": time.Since(t0).Milliseconds(), "seen": strings.Join(states, " → "), "verdict": blk["verdict"]}
	if a.tapOK {
		if pkts, err := ReadFlowTap(rc.P); err == nil {
			uses := flowUses(pkts, holdFrom, time.Now())
			ev["censor_saw"] = flowText(uses, holdFrom)
			surveyed := a.surveyedEndpoints(diag, p.routes)
			ev["surveyed"] = surveyedText(surveyed)
			for _, u := range uses {
				if u.Endpoint != endpointOf(nf) && !surveyed[u.Endpoint] {
					wrong = append(wrong, "the censor saw a new connection to "+u.Endpoint+" during the hold: something was probed")
				}
			}
		}
	}
	p.add("hold", nowFam, "stays_after_a_move_for_speed", Pass, got(len(wrong) == 0, Pass, Fail), strings.Join(wrong, "; "), ev, t0)
	unslowEndpoint(rc.Ctx)
	p.sw.carries("hold", nf, t0)
}

// staysOnMetered: on a network the host calls metered the engine starts
// no probe by itself, so it does not move for speed and the censor sees
// nothing new beside the running route.
func (a *autoOp) staysOnMetered(p *autoPhone, first autoRoute, ff Family, slowFrom, t0 time.Time) {
	rc := a.rc
	// First: the route IS slow, as the engine sees it.
	d, states, slow := p.watch("slow", AutoSpeedWait, t0, func(diag, blk map[string]any) bool { return diag["route_check"] == "degraded" })
	if d == nil {
		return
	}
	if !p.add("slow", first.Family, "engine_calls_it_degraded", Pass, got(slow, Pass, Fail), strings.Join(states, " → "), nil, t0) {
		return
	}
	d, more, _ := p.watch("slow", AutoHoldWatch, t0, func(diag, blk map[string]any) bool { return blk["route_id"] != first.ID })
	if d == nil {
		return
	}
	diag, _ := d["diag"].(map[string]any)
	blk := autoBlock(diag)
	net, _ := diag["network"].(map[string]any)
	var wrong []string
	if blk["route_id"] != first.ID || diag["active_route"] != first.ID || blk["verdict"] == "moved_faster" {
		wrong = append(wrong, fmt.Sprintf("the engine moved: route_id=%v verdict=%v", blk["route_id"], blk["verdict"]))
	}
	if m, _ := net["metered"].(float64); net["from_host"] != true || m != 1 {
		wrong = append(wrong, fmt.Sprintf("the diagnostics do not say the host called this network metered: %v", net))
	}
	ev := map[string]any{"on": first.ID, "watched_ms": time.Since(t0).Milliseconds(), "seen": strings.Join(append(states, more...), " → "), "network": net}
	if a.tapOK {
		if pkts, err := ReadFlowTap(rc.P); err == nil {
			uses := flowUses(pkts, slowFrom, time.Now())
			ev["censor_saw"] = flowText(uses, slowFrom)
			surveyed := a.surveyedEndpoints(diag, p.routes)
			ev["surveyed"] = surveyedText(surveyed)
			for _, u := range uses {
				if u.Endpoint != endpointOf(ff) && !surveyed[u.Endpoint] {
					wrong = append(wrong, "the censor saw a new connection to "+u.Endpoint+": the engine probed on a metered network")
				}
			}
		}
	}
	p.add("slow", first.Family, "no_probe_on_a_metered_network", Pass, got(len(wrong) == 0, Pass, Fail), strings.Join(wrong, "; "), ev, t0)
	unslowEndpoint(rc.Ctx)
	p.sw.carries("slow", ff, t0)
}

// ---- networks: what the host says about the network ------------------------

func (a *autoOp) networks() {
	rc := a.rc
	// The engine's log goes to the phone's stderr file on this phone, so
	// that the search for the ids at the end reads it too.
	p := a.start("networks", ClientOpts{EngineLog: true})
	if p == nil {
		return
	}
	defer p.stop()
	cands := p.candidates()
	if len(cands) < 2 {
		return
	}
	idX, idY := hostID("x"), hostID("y")

	// --- network X.
	t0 := time.Now()
	ansX := p.net("x", "wifi", idX, 1, 0, t0)
	if ansX == nil {
		return
	}
	hashX := str(ansX, "network_id")
	okAns := len(hashX) == 16 && !strings.Contains(fmt.Sprint(ansX), idX) && ansX["kind"] == "wifi"
	p.add("x", "", "facts_answered_with_a_hashed_id", Pass, got(okAns, Pass, Fail), got(okAns, "", fmt.Sprintf("answer: %v", ansX)), map[string]any{"answer": ansX}, t0)
	x := p.press("x", "auto", t0)
	if x == nil || !p.connectedOn("x", x, t0) {
		return
	}
	rows, _, ok := p.listing("x", t0)
	if !ok {
		return
	}
	onX := rows[x.routeID]
	d := p.ask("x", "diag", "diag", 20*time.Second, t0)
	if d != nil {
		diag, _ := d["diag"].(map[string]any)
		net, _ := diag["network"].(map[string]any)
		v, _ := net["validated"].(float64)
		said := net["from_host"] == true && net["kind"] == "wifi" && v == 1 && !strings.Contains(fmt.Sprint(diag), idX)
		p.add("x", "", "diagnostics_say_what_the_host_said", Pass, got(said, Pass, Fail), got(said, "", fmt.Sprintf("network block: %v", net)), map[string]any{"network": net}, t0)
	}
	p.disconnect("x", x.family, time.Now())

	// --- network Y: another id, the same kind.
	t0 = time.Now()
	ansY := p.net("y", "wifi", idY, 1, 0, t0)
	if ansY == nil {
		return
	}
	other := str(ansY, "network_id") != hashX && ansY["changed"] == true && ansY["fresh"] == true
	p.add("y", "", "another_id_is_another_network", Pass, got(other, Pass, Fail), got(other, "", fmt.Sprintf("X: %v  Y: %v", ansX, ansY)), map[string]any{"answer": ansY}, t0)
	if rows, _, ok = p.listing("y", t0); !ok {
		return
	}
	var wrong []string
	for id, m := range rows {
		if m.Grade != "unknown" || m.Samples != 0 || m.Carried != 0 || m.Failed != 0 {
			wrong = append(wrong, fmt.Sprintf("%s is remembered on a network the phone has never been on: %s", id, m.text()))
		}
	}
	p.add("y", "", "nothing_is_remembered_on_a_new_network", Pass, got(len(wrong) == 0, Pass, Fail), strings.Join(wrong, "; "),
		map[string]any{"measured": measuredText(rows), "on_x": onX.text()}, t0)
	y := p.press("y", "auto", t0)
	if y == nil {
		return
	}
	notRemembered := len(y.tried) > 0 && y.tried[0]["why"] != "carried_here"
	p.add("y", y.family, "the_route_remembered_elsewhere_is_not_pulled_ahead", Pass, got(notRemembered, Pass, Fail),
		got(notRemembered, "", "on network Y the first route tried says why=carried_here: that was network X"), y.evidence(), t0)
	if !p.connectedOn("y", y, t0) {
		return
	}
	p.disconnect("y", y.family, time.Now())

	// --- back on X.
	t0 = time.Now()
	back := p.net("x-again", "wifi", idX, 1, 0, t0)
	if back == nil {
		return
	}
	same := str(back, "network_id") == hashX && back["fresh"] == false
	p.add("x-again", "", "the_same_id_is_the_same_network", Pass, got(same, Pass, Fail), got(same, "", fmt.Sprintf("first: %v  now: %v", ansX, back)), map[string]any{"answer": back}, t0)
	z := p.press("x-again", "auto", t0)
	if z == nil {
		return
	}
	aloneWrong, aloneEv := p.aloneProblems(z, x.routeID)
	p.add("x-again", z.family, "remembered_route_alone", Pass, got(len(aloneWrong) == 0, Pass, Fail), strings.Join(aloneWrong, "; "), aloneEv, t0)
	if !p.connectedOn("x-again", z, t0) {
		return
	}
	p.disconnect("x-again", z.family, time.Now())

	// --- no network at all, says the host; the relay is in fact there.
	// The fact stops no press the person makes.
	t0 = time.Now()
	if p.net("none", "none", "", 0, -1, t0) == nil {
		return
	}
	n := p.press("none", "auto", t0)
	if n == nil {
		return
	}
	p.add("none", n.family, "a_press_is_never_refused_for_the_host_fact", Pass, got(n.connected, Pass, Fail), got(n.connected, "", "verdict="+n.verdict+" tried: "+n.triedText()), n.evidence(), t0)
	if n.connected {
		p.connectedOn("none", n, t0)
		p.disconnect("none", n.family, time.Now())
	}

	// --- the relay's address is null-routed. Same phone, same block,
	// three times; the one thing that differs is what the host says.
	// Only "no network at all" is taken for no internet: a network the
	// platform has not validated may be one that filters the platform's
	// own check, and the internet is in fact there in this world.
	t0 = time.Now()
	if err := censorRules(rc.Ctx, fmt.Sprintf("ip saddr %s ip daddr %s drop", ClientIP, RelayPublicAddrSet())); err != nil {
		p.add("down", "", "censor.block", Pass, Fail, err.Error(), nil, t0)
		return
	}
	defer censorRules(rc.Ctx)
	for _, c := range []struct {
		step, host string
		verdict    string
	}{
		{"down", "none - 0 -1", "network_down"},
		{"unvalidated", fmt.Sprintf("wifi %s 0 0", idX), "relay_unreachable"},
		{"dead-relay", fmt.Sprintf("wifi %s 1 0", idX), "relay_unreachable"},
	} {
		t0 = time.Now()
		v := p.press(c.step, "auto-net "+c.host, t0)
		if v == nil {
			return
		}
		nothing := !v.connected
		for _, t := range v.tried {
			nothing = nothing && (t["result"] == "not_carrying" || t["result"] == "start_failed")
		}
		p.add(c.step, "", "nothing_answered", Pass, got(nothing, Pass, Fail), got(nothing, "", v.triedText()), v.evidence(), t0)
		p.add(c.step, "", "verdict", c.verdict, v.verdict,
			fmt.Sprintf("the host said %q (kind, validated, metered; the id left out) while the connect was starting (its own thread, as the service's callback)", strings.Replace(c.host, idX, "<id>", 1)),
			map[string]any{"net": v.ev["net"], "tried": v.triedText(), "auto_ms": v.ev["auto_ms"]}, t0)
		p.nothingRunning(c.step, v, c.verdict, t0)
	}
	censorRules(rc.Ctx)

	// --- the ids the host sent, in anything this phone wrote.
	t0 = time.Now()
	state := filepath.Join("/run", "wb-state", filepath.Base(p.c.Dir))
	if os.Getenv("WB_STATE_ON_DISK") != "" {
		state = filepath.Join(p.c.Dir, "state")
	}
	found, files, size := grepTree([]string{state, p.c.Dir}, idX, idY)
	// The search is only worth what it read: the engine's own line about
	// each report must be there (it names the kind, never the id).
	logged, _, _ := grepTree([]string{p.c.Dir}, "network facts kind=")
	clean := len(found) == 0 && files > 0 && len(logged) > 0
	why := ""
	switch {
	case len(found) > 0:
		why = "found in: " + strings.Join(found, ", ")
	case files == 0 || len(logged) == 0:
		why = "the engine's log of the reports is not among the files read: the search looked at less than it claims"
	}
	p.add("ids", "", "the_clear_id_is_in_no_file", Pass, got(clean, Pass, Fail), why,
		map[string]any{"files": files, "bytes": size, "found": found, "engine_log_read": len(logged) > 0, "looked_in": []string{state, p.c.Dir}}, t0)
}

// grepTree looks for any of the needles in every regular file under the
// roots. It returns the files that hold one, and how much it read.
func grepTree(roots []string, needles ...string) (found []string, files int, size int64) {
	for _, root := range roots {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || !info.Mode().IsRegular() {
				return nil
			}
			body, rerr := os.ReadFile(path)
			if rerr != nil {
				return nil
			}
			files++
			size += int64(len(body))
			for _, n := range needles {
				if bytes.Contains(body, []byte(n)) {
					found = append(found, path)
					break
				}
			}
			return nil
		})
	}
	return found, files, size
}

// ---- leaks: what a side instance leaves ------------------------------------

// held asks the phone what it holds, waiting up to 3 s for it to be no
// more than base (goroutines of a closed instance take a moment to end).
func (p *autoPhone) held(step string, base map[string]any, t0 time.Time) map[string]any {
	var last map[string]any
	for i := 0; i < 15; i++ {
		ev := p.ask(step, "res", "res", 20*time.Second, t0)
		if ev == nil {
			return nil
		}
		last = ev
		if base == nil || !heldMore(base, ev) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	return last
}

var heldKeys = []string{"fds", "goroutines", "goroutines_box"}

func heldNum(m map[string]any, k string) int { f, _ := m[k].(float64); return int(f) }

// heldMore: does now hold more than base — open files, goroutines, or
// goroutines inside sing-box?
func heldMore(base, now map[string]any) bool {
	for _, k := range heldKeys {
		if heldNum(now, k) > heldNum(base, k) {
			return true
		}
	}
	return false
}

func heldText(m map[string]any) string {
	return fmt.Sprintf("fds=%d %v goroutines=%d of which sing-box=%d", heldNum(m, "fds"), m["fd_kinds"], heldNum(m, "goroutines"), heldNum(m, "goroutines_box"))
}

func (a *autoOp) leaks() {
	rc := a.rc
	for _, c := range []struct{ label, what string }{
		{"leak-stopped", "a check stopped because the other route proved"},
		{"leak-cancel", "a pair cancelled in flight"},
	} {
		func() {
			p := a.start(c.label, ClientOpts{})
			if p == nil {
				return
			}
			defer p.stop()
			cands := p.candidates()
			if len(cands) < 2 {
				return
			}
			first := cands[0]
			ff := rc.Fams[first.Family]
			// The baseline: what a connect by hand and a disconnect leave,
			// on a network of its own so that the press below still meets
			// a phone that remembers nothing HERE and checks two routes.
			t0 := time.Now()
			if p.net("base", "wifi", hostID("base"), 1, 0, t0) == nil {
				return
			}
			// Every route the press below can end up running, once each:
			// whatever a family starts for the life of the process is in
			// the baseline, and what is left over afterwards is the side
			// instance's.
			for i := 0; i < len(cands) && i < 3; i++ {
				if rc.Fams[cands[i].Family].Skip == "" && !p.byHand("base-"+cands[i].ID, rc.Fams[cands[i].Family], t0) {
					return
				}
			}
			before := p.held("base", nil, t0)
			if before == nil {
				return
			}
			// One more connect by hand and disconnect. It should leave
			// nothing; what it does leave (FINDINGS SW-3: one eventfd per
			// instance that had the TUN) is what ONE connect costs, and
			// the press below is allowed exactly as many as it makes.
			if !p.byHand("cycle", rc.Fams[cands[1].Family], t0) {
				return
			}
			base := p.held("cycle", before, t0)
			if base == nil {
				return
			}
			perConnect := map[string]int{}
			for _, k := range heldKeys {
				perConnect[k] = heldNum(base, k) - heldNum(before, k)
			}
			if c.label == "leak-stopped" { // asked once
				still := !heldMore(before, base)
				p.add("cycle", "", "a_connect_and_a_disconnect_leave_nothing", Pass, got(still, Pass, Fail),
					got(still, "", fmt.Sprintf("before: %s; after one more connect by hand and disconnect: %s", heldText(before), heldText(base))),
					map[string]any{"base": heldText(before), "now": heldText(base)}, t0)
			}
			if p.net("race", "wifi", hostID("race"), 1, 0, t0) == nil {
				return
			}
			t0 = time.Now()
			var x *autoAnswer
			connects := 0
			if c.label == "leak-stopped" {
				connects = 1
				// The first route is dropped: its check is still waiting
				// for an answer when the other proves, and is stopped.
				if err := blockEndpoint(rc.Ctx, ff); err != nil {
					p.add("race", first.Family, "censor.block", Pass, Fail, err.Error(), nil, t0)
					return
				}
				defer unblockEndpoint(rc.Ctx)
				if x = p.press("race", "auto", t0); x == nil {
					return
				}
				s := x.entry(first.ID)
				was := x.connected && s != nil && s["result"] == "stopped"
				if !p.add("race", first.Family, "a_check_in_flight_was_stopped", Pass, got(was, Pass, Fail), got(was, "", x.triedText()), x.evidence(), t0) {
					return
				}
				p.disconnect("race", x.family, time.Now())
			} else {
				if err := censorRules(rc.Ctx, fmt.Sprintf("ip saddr %s ip daddr %s drop", ClientIP, RelayPublicAddrSet())); err != nil {
					p.add("race", "", "censor.block", Pass, Fail, err.Error(), nil, t0)
					return
				}
				defer censorRules(rc.Ctx)
				if x = p.press("race", "auto-cancel 1500", t0); x == nil {
					return
				}
				pairs, _ := x.racingSeen()
				cancelled := 0
				for _, t := range x.tried {
					if t["result"] == "cancelled" {
						cancelled++
					}
				}
				was := len(pairs) == 1 && cancelled == 2 && x.verdict == "cancelled"
				if !p.add("race", "", "a_pair_in_flight_was_cancelled", Pass, got(was, Pass, Fail), got(was, "", fmt.Sprintf("racing seen: %v; tried: %s", pairs, x.triedText())), x.evidence(), t0) {
					return
				}
				p.nothingRunning("race", x, "", t0)
			}
			// What the press may leave: nothing more than the baseline,
			// plus one connect's worth for each instance it gave the TUN
			// to (the route it ended on; none when it was cancelled).
			allowed := map[string]any{}
			for _, k := range heldKeys {
				allowed[k] = float64(heldNum(base, k) + perConnect[k]*connects)
			}
			now := p.held("race", allowed, t0)
			if now == nil {
				return
			}
			same := !heldMore(allowed, now)
			p.add("race", "", "a_side_instance_leaves_nothing", Pass, got(same, Pass, Fail),
				got(same, "", fmt.Sprintf("after %s the process holds %s; %d connect(s) by hand more than the baseline would have left fds=%v goroutines=%v sing-box=%v",
					c.what, heldText(now), connects, allowed["fds"], allowed["goroutines"], allowed["goroutines_box"])),
				map[string]any{"base": heldText(base), "now": heldText(now), "connects_made_by_the_press": connects, "one_connect_leaves": perConnect}, t0)
		}()
	}
}
