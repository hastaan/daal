package main

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

func init() {
	Ops["switch"] = opSwitch
	Ops["switch-all"] = opSwitchAll
}

// The route SWITCH: one tap on another route's Connect while a route is
// up. Every other session in this rig is connect → fetch → disconnect on
// a fresh phone, and the first real-phone pass (2026-11-19) broke on the
// first thing a person did next: after one switch the tunnel still
// carried traffic while the Connection page said "No route selected" and
// the Network page said "unknown" — the engine had closed the old TUN's
// fd twice, and the second close hit the route store's database file,
// which had been given the freed number in between (FINDINGS SW-0).
//
// One wb-client stays up for the whole session and is told to switch
// (`switch <rotate|keep> <family>`, labclient/switch.go):
//
//	rotate  establish a NEW TUN → SetTunFD(new) → SetRoute(B), no
//	        ClearRoute first: what DaalVpnService did on that phone, and
//	        the only order in which the engine closes a TUN fd under a
//	        running instance
//	keep    RouteConnectPrecheck(B) → SetRoute(B) on the TUN already
//	        held: what vpn/StartSequence.kt does since
//
// After every switch, from the insider's seat:
//
//	accepted        the engine took route B
//	tunnel, wire    verified bytes reach the target from the relay, and at
//	                the censor they travelled on B's endpoint — not A's
//	store_survives  the calls the app's pages make (SubscriptionList,
//	                AvailableRoutes, RouteSummary, DiagnosticsExplain) all
//	                answer, and so did every one of them polled every
//	                25 ms while the switch was in flight
//	active_route    ExportDiagnostics.active_route / _family and
//	                DiagnosticsExplain.active_route name B
//	fds_intact      no file the "app" opened before the switch, or between
//	                the TUN rotate and the switch, was closed underneath
//	                it (sentinel fds: fstat identity, write, read back)
//
// and after the disconnect that ends the session the same store and fd
// checks again (clear_route + clear_tun_fd was the same double close),
// active_route == "", and the direct-path control.
//
// `switch` (quick) does that for one TCP family and one QUIC family in
// both orders, then the two switches that must NOT take:
//
//	unreachable  B's endpoint is dropped at the censor. The engine tries
//	             B and gives it up; what it leaves running is recorded as
//	             it is (FINDINGS SW-1), and going back to A must work
//	refused      B is now cooling down: the switch is refused before
//	             anything is touched, A is still connected and still
//	             carries verified bytes on its own endpoint, and the
//	             diagnostics say why
//
// `switch-all` (full) walks every ORDERED pair of families in one
// rotate session, and the ring of them in one keep session.
func opSwitch(rc *RunCtx) {
	const phase = "op:switch"
	tcp, udp, ok := rc.switchPair()
	if !ok {
		rc.R.Add("", phase, "pair", Skipped, Skipped, "needs one TCP family and one QUIC/UDP family that this scenario does not block", nil, time.Now())
		return
	}
	if s := rc.startSwitchSession(phase, "rotate", tcp, []Family{tcp, udp}); s != nil {
		s.to("rotate", udp)
		s.to("rotate", tcp)
		s.disconnect()
	}
	if s := rc.startSwitchSession(phase, "keep", tcp, []Family{tcp, udp}); s != nil {
		if s.to("keep", udp) {
			s.to("keep", tcp)
		}
		s.disconnect()
	}
	if s := rc.startSwitchSession(phase, "check-rotate", tcp, []Family{tcp, udp}); s != nil {
		s.unreachableThenRefused(udp)
		s.disconnect()
	}
}

func opSwitchAll(rc *RunCtx) {
	const phase = "op:switch-all"
	var fams []Family
	for _, f := range rc.activeFamilies() {
		if e, _ := rc.Scn.ExpectFor(f.Name); e == Pass {
			fams = append(fams, f)
		}
	}
	if len(fams) < 2 {
		rc.R.Add("", phase, "pairs", Skipped, Skipped, "needs two families this scenario does not block", nil, time.Now())
		return
	}
	// Every ordered pair once: an Eulerian circuit of the complete
	// directed graph on the families (it has one: every vertex has as
	// many edges in as out).
	walk := eulerCircuit(len(fams))
	if s := rc.startSwitchSession(phase, "rotate", fams[walk[0]], fams); s != nil {
		for _, i := range walk[1:] {
			if !s.to("rotate", fams[i]) {
				break
			}
		}
		s.disconnect()
	}
	if s := rc.startSwitchSession(phase, "keep", fams[0], fams); s != nil {
		for i := 1; i <= len(fams); i++ {
			if !s.to("keep", fams[i%len(fams)]) {
				break
			}
		}
		s.disconnect()
	}
}

// eulerCircuit returns a closed walk over vertices 0..n-1 that uses every
// ordered pair (i, j), i != j, exactly once (Hierholzer).
func eulerCircuit(n int) []int {
	next := make([][]int, n)
	for i := range next {
		for j := 0; j < n; j++ {
			if j != i {
				next[i] = append(next[i], j)
			}
		}
	}
	var walk, stack []int
	stack = append(stack, 0)
	for len(stack) > 0 {
		v := stack[len(stack)-1]
		if len(next[v]) > 0 {
			stack = append(stack, next[v][0])
			next[v] = next[v][1:]
		} else {
			walk = append(walk, v)
			stack = stack[:len(stack)-1]
		}
	}
	for i, j := 0, len(walk)-1; i < j; i, j = i+1, j-1 {
		walk[i], walk[j] = walk[j], walk[i]
	}
	return walk
}

// switchPair picks the TCP family and the QUIC family the quick op
// switches between: vless-reality and hysteria2 where they are under
// test (the pair every censor world of the quick matrix runs), else the
// first of each kind.
func (rc *RunCtx) switchPair() (tcp, udp Family, ok bool) {
	pick := func(proto, prefer string) (Family, bool) {
		var first *Family
		for _, f := range rc.activeFamilies() {
			if e, _ := rc.Scn.ExpectFor(f.Name); e != Pass || f.Endpoint.Proto != proto {
				continue
			}
			if f.Name == prefer {
				return f, true
			}
			if first == nil {
				g := f
				first = &g
			}
		}
		if first == nil {
			return Family{}, false
		}
		return *first, true
	}
	tcp, okT := pick("tcp", "vless-reality")
	udp, okU := pick("udp", "hysteria2")
	return tcp, udp, okT && okU
}

// SwitchRoundTrips is how many further connections each `tunnel` check of
// a switch session opens after its fetch (see carries).
const SwitchRoundTrips = 20

// switchSession is one phone that stays up across several switches.
type switchSession struct {
	rc    *RunCtx
	phase string
	label string // rotate | keep | check-rotate: the order this session's switches use
	c     *Client
	cur   Family
	// armed: in at least one rotate switch a sentinel landed on the old
	// TUN's fd number — the trap for the double close was really set.
	armed, rotated bool
	dead           bool
	// tunsHeld: TUN interfaces a switch replaced that were still there
	// half a second after the engine closed the instance that read them.
	tunsHeld []string
}

// add records one check of this session: ids are "<label>.<step>.<id>".
func (s *switchSession) add(step string, f Family, id, expect, gotV, detail string, ev map[string]any, t0 time.Time) bool {
	saved := s.rc.R.prefix
	s.rc.R.prefix = saved + s.label + "." + step + "."
	defer func() { s.rc.R.prefix = saved }()
	return s.rc.R.Add(f.Name, s.phase, id, expect, gotV, detail, ev, t0)
}

// carries: verified bytes go out through the tunnel right now, and at
// the censor they are on f's endpoint and nowhere else on the relay.
func (s *switchSession) carries(step string, f Family, t0 time.Time) bool {
	rc := s.rc
	_, _ = WireReset(rc.Ctx) // what the engine's own connection check sent is not this fetch
	pr := ProbeApp(rc.Ctx, rc.P, false, false, 0, 10*time.Second)
	wire, werr := WireReset(rc.Ctx)
	outcome, detail := got(pr.OK, Pass, Blocked), pr.Error
	if pr.OK && pr.Remote != Relay1EgressIP {
		outcome, detail = Fail, "fetch succeeded but the target saw "+pr.Remote+", not the relay ("+Relay1EgressIP+"): this is not the tunnel"
	}
	// One fetch that gets through says the tunnel CAN carry. A person
	// opens connection after connection, so the same question is asked
	// SwitchRoundTrips more times, each a new connection, and every one
	// must come back: a tunnel that resets some of them (two readers on
	// one TUN after a switch — FINDINGS SW-2) passes a single fetch as
	// often as not.
	lost, firstLost := 0, ""
	for i := 0; i < SwitchRoundTrips && rc.Ctx.Err() == nil; i++ {
		q := ProbeWhoami(rc.Ctx, rc.P, 5*time.Second)
		if !q.NonceOK || q.Remote != Relay1EgressIP {
			lost++
			if firstLost == "" {
				firstLost = q.Error
			}
		}
	}
	if outcome == Pass && lost > 0 {
		outcome, detail = Blocked, fmt.Sprintf("the fetch got through, but %d of the %d connections opened right after it did not, first: %s", lost, SwitchRoundTrips, firstLost)
	} else if lost > 0 {
		detail += fmt.Sprintf(" — and %d of %d further connections failed too", lost, SwitchRoundTrips)
	}
	ok := s.add(step, f, "tunnel", Pass, outcome, detail, map[string]any{"target_saw": pr.Remote, "nonce_ok": pr.NonceOK,
		"blob_bytes": pr.BlobBytes, "blob_sha256_ok": pr.BlobOK, "upload_sha256_ok": pr.UploadOK, "fetch_ms": pr.Ms,
		"round_trips": SwitchRoundTrips, "round_trips_lost": lost}, t0)
	if pr.OK {
		// Where the fetch travelled. (A fetch that did not arrive has
		// already been said; the tap has nothing to add to it.)
		saved := rc.R.prefix
		rc.R.prefix = saved + s.label + "." + step + "."
		rc.wireCheck(f, s.phase, Pass, wire, werr, int64(pr.BlobBytes), true, t0)
		rc.R.prefix = saved
	}
	return ok
}

// startSwitchSession brings a fresh phone up on `first`.
func (rc *RunCtx) startSwitchSession(phase, label string, first Family, all []Family) *switchSession {
	s := &switchSession{rc: rc, phase: phase, label: label, cur: first}
	t0 := time.Now()
	pre := Probe(rc.Ctx, rc.P, false, 2*time.Second)
	s.add("connect", first, "control.before", Blocked, got(pre.OK, Pass, Blocked), pre.Error, nil, t0)
	experimental := false
	for _, f := range all {
		experimental = experimental || f.Experimental
	}
	t0 = time.Now()
	c, err := StartClient(rc.P, "switch-"+label, ClientOpts{Pack: rc.Pack, Family: first.Name, Experimental: experimental})
	if err != nil {
		s.add("connect", first, "connected", Pass, Fail, err.Error(), nil, t0)
		return nil
	}
	s.c = c
	ev, err := c.Wait(rc.Ctx, EngineConnectWait, "connected")
	if err != nil {
		detail := "engine did not connect: " + err.Error()
		if c.Died() {
			detail = "the engine process died: " + c.CrashSignature()
			ReapDeadVPN(rc.Ctx)
		}
		c.Stop()
		s.add("connect", first, "connected", Pass, Fail, detail, map[string]any{"client_dir": c.Dir}, t0)
		return nil
	}
	s.add("connect", first, "connected", Pass, Pass, "", map[string]any{"route_id": ev["route_id"], "client_dir": c.Dir}, t0)
	s.carries("connect", first, t0)
	return s
}

// ask sends one switch command and returns the client's account of it.
func (s *switchSession) ask(step, mode string, to Family, t0 time.Time) map[string]any {
	rc := s.rc
	if err := s.c.Send("switch " + mode + " " + to.Name); err != nil {
		s.add(step, to, "accepted", Pass, Fail, "could not tell the client to switch: "+err.Error(), nil, t0)
		s.dead = true
		return nil
	}
	ev, err := s.c.Wait(rc.Ctx, EngineConnectWait+10*time.Second, "switched")
	if err != nil {
		detail := "no answer to the switch: " + err.Error()
		if s.c.Died() {
			detail = "the engine process died during the switch: " + s.c.CrashSignature()
			ReapDeadVPN(rc.Ctx)
		}
		s.add(step, to, "engine.survived", Pass, Fail, detail, map[string]any{"client_dir": s.c.Dir}, t0)
		s.dead = true
		return nil
	}
	if a, _ := ev["fd_trap_armed"].(bool); a {
		s.armed = true
	}
	return ev
}

// storeAndFDs records the two checks every step shares: the store still
// answers, and nobody closed a file that was not theirs.
func (s *switchSession) storeAndFDs(step string, f Family, ev map[string]any, t0 time.Time) {
	store, _ := ev["store"].(map[string]any)
	failed := anyStrings(store["failed"])
	var problems []string
	for _, call := range failed {
		problems = append(problems, fmt.Sprintf("%s: %v", call, store[call]))
	}
	listed, _ := store["routes_listed"].(float64)
	if len(failed) == 0 && listed == 0 {
		problems = append(problems, "the engine lists no routes: the pack it imported is gone")
	}
	poll, _ := ev["poll"].(map[string]any)
	pollErrs, _ := poll["errors"].(float64)
	if pollErrs > 0 {
		problems = append(problems, fmt.Sprintf("%v of %v calls polled during the switch failed, first: %v", poll["errors"], poll["calls"], poll["first_error"]))
	}
	s.add(step, f, "store_survives", Pass, got(len(problems) == 0, Pass, Fail), strings.Join(problems, "; "),
		map[string]any{"failed_calls": failed, "routes_listed": listed, "polled_during_switch": poll}, t0)
	bad := anyStrings(ev["sentinels_bad"])
	if bad == nil {
		bad = anyStrings(store["sentinels_bad"])
	}
	s.add(step, f, "fds_intact", Pass, got(len(bad) == 0, Pass, Fail), strings.Join(bad, "; "),
		map[string]any{"old_tun_fd": ev["old_tun_fd"], "new_tun_fd": ev["new_tun_fd"], "a_sentinel_took_the_old_tun_number": ev["fd_trap_armed"]}, t0)
	if gone, replaced := ev["old_tun_gone"].(bool); replaced && !gone {
		s.tunsHeld = append(s.tunsHeld, fmt.Sprint(ev["old_tun"]))
	}
}

func diagOf(ev map[string]any) map[string]any {
	store, _ := ev["store"].(map[string]any)
	d, _ := store["diag"].(map[string]any)
	return d
}

func explainOf(ev map[string]any) map[string]any {
	store, _ := ev["store"].(map[string]any)
	d, _ := store["explain"].(map[string]any)
	return d
}

func anyStrings(v any) []string {
	xs, _ := v.([]any)
	var out []string
	for _, x := range xs {
		out = append(out, fmt.Sprint(x))
	}
	return out
}

// to switches to route `to` and expects it to take.
func (s *switchSession) to(mode string, to Family) bool {
	if s.dead {
		return false
	}
	step := s.cur.Name + ">" + to.Name
	return s.toAs(step, mode, to)
}

func (s *switchSession) toAs(step, mode string, to Family) bool {
	t0 := time.Now()
	ev := s.ask(step, mode, to, t0)
	if ev == nil {
		return false
	}
	if mode != "keep" {
		s.rotated = true
	}
	errText, _ := ev["error"].(string)
	refused, _ := ev["refused"].(string)
	outcome, detail := Pass, ""
	switch {
	case refused != "":
		outcome, detail = Refused, "the engine refused the route before starting it: "+refused
	case errText != "":
		outcome, detail = got(ev["stage"] == StageProof, Blocked, Fail), fmt.Sprintf("%v: %s", ev["stage"], errText)
	}
	ok := s.add(step, to, "accepted", Pass, outcome, detail, map[string]any{"mode": mode, "from": ev["from"], "to": ev["to"],
		"set_route_ms": ev["set_route_ms"], "precheck": ev["precheck"], "client_dir": s.c.Dir}, t0)
	s.storeAndFDs(step, to, ev, t0)
	if !ok {
		// Whatever is running now is not what this walk assumes: stop it
		// here, one red step instead of a column of misattributed ones.
		s.dead = true
		return false
	}
	s.cur = to
	diag, explain := diagOf(ev), explainOf(ev)
	want, _ := ev["to"].(string)
	var wrong []string
	if diag["active_route"] != want {
		wrong = append(wrong, fmt.Sprintf("ExportDiagnostics.active_route=%q", diag["active_route"]))
	}
	if diag["active_route_family"] != to.Name {
		wrong = append(wrong, fmt.Sprintf("ExportDiagnostics.active_route_family=%q", diag["active_route_family"]))
	}
	if explain["active_route"] != want {
		wrong = append(wrong, fmt.Sprintf("DiagnosticsExplain.active_route=%q", explain["active_route"]))
	}
	s.add(step, to, "active_route", Pass, got(len(wrong) == 0, Pass, Fail),
		got(len(wrong) == 0, "", "the engine carries "+want+" ("+to.Name+") but says: "+strings.Join(wrong, ", ")),
		map[string]any{"want": want, "active_route": diag["active_route"], "active_route_family": diag["active_route_family"],
			"explain_active_route": explain["active_route"], "route_check": diag["route_check"]}, t0)
	return s.carries(step, to, t0)
}

// unreachableThenRefused: the two switches that must not take, A → B
// with B first unreachable and then cooling down. The session is on A
// (s.cur). It runs in the check-rotate order, so that what it says about
// A afterwards is about the engine's handling of the switch and not
// about two instances sharing a TUN (FINDINGS SW-2).
func (s *switchSession) unreachableThenRefused(b Family) {
	if s.dead {
		return
	}
	rc, a := s.rc, s.cur
	// --- B's endpoint is dropped on the path.
	t0 := time.Now()
	if err := blockEndpoint(rc.Ctx, b); err != nil {
		s.add("unreachable", b, "censor.block", Pass, Fail, err.Error(), nil, t0)
		return
	}
	defer unblockEndpoint(rc.Ctx)
	step := "unreachable." + a.Name + ">" + b.Name
	ev := s.ask(step, s.label, b, t0)
	if ev == nil {
		return
	}
	s.rotated = s.rotated || s.label != "keep"
	errText, _ := ev["error"].(string)
	outcome := Pass
	switch {
	case ev["refused"] != nil:
		outcome = Refused
	case ev["stage"] == StageProof:
		outcome = Blocked
	case errText != "":
		outcome = Fail
	}
	s.add(step, b, "dead_route_not_connected", Blocked, outcome, errText, map[string]any{"stage": ev["stage"], "set_route_ms": ev["set_route_ms"]}, t0)
	s.storeAndFDs(step, b, ev, t0)
	diag := diagOf(ev)
	aID, _ := ev["from"].(string)
	// What is left running after the engine gave B up. The person was
	// connected on A and asked for something that turned out not to
	// work: A should still be carrying them. Today the engine has
	// already stopped A to try B (FINDINGS SW-1); the host goes back.
	left := Pass
	if diag["active_route"] != aID || diag["route_running"] != true {
		left = "disconnected"
	}
	s.add(step, a, "old_route_still_connected", Pass, left,
		got(left == Pass, "", "the engine stopped the connected route to try the new one and, when that carried nothing, left nothing running"),
		map[string]any{"active_route": diag["active_route"], "route_running": diag["route_running"], "route_check": diag["route_check"],
			"route_check_category": diag["route_check_category"], "was_on": aID}, t0)
	if outcome != Blocked {
		s.dead = true
		return
	}
	if left != Pass {
		// What the Android service does next (SwitchPolicy "Restore"):
		// set the old route again. B is still unreachable.
		if !s.toAs("restore."+a.Name, s.label, a) {
			return
		}
	} else {
		s.carries(step, a, t0)
	}
	unblockEndpoint(rc.Ctx)

	// --- B is reachable again, and cooling down after that failure.
	t0 = time.Now()
	step = "refused." + a.Name + ">" + b.Name
	ev = s.ask(step, s.label, b, t0)
	if ev == nil {
		return
	}
	code, _ := ev["refused"].(string)
	outcome = Refused
	if code == "" {
		outcome = got(ev["error"] == nil, Pass, Fail)
		s.dead = true // B was attempted: A is not what is running any more
	}
	s.add(step, b, "refused", Refused, outcome, got(code == "", fmt.Sprintf("the engine attempted a route that failed seconds ago: %v", ev["error"]), ""),
		map[string]any{"code": code, "attempted": ev["attempted"], "precheck": ev["precheck"]}, t0)
	s.storeAndFDs(step, b, ev, t0)
	if code == "" {
		return
	}
	diag = diagOf(ev)
	bID, _ := ev["to"].(string)
	said := diag["connect_refused"] == code && diag["connect_refused_route"] == bID
	s.add(step, b, "refusal_recorded", Pass, got(said, Pass, Fail),
		got(said, "", "the diagnostics do not say why the switch did not happen"),
		map[string]any{"connect_refused": diag["connect_refused"], "connect_refused_route": diag["connect_refused_route"], "want_code": code}, t0)
	still := diag["active_route"] == aID && diag["route_running"] == true
	s.add(step, a, "old_route_still_connected", Pass, got(still, Pass, "disconnected"),
		got(still, "", "a REFUSED switch took the connected route down"),
		map[string]any{"active_route": diag["active_route"], "route_running": diag["route_running"], "route_check": diag["route_check"], "was_on": aID}, t0)
	s.carries(step, a, t0)
}

// disconnect ends the session the way the service does and checks what
// the switch checks, once more: clear_route + clear_tun_fd was the same
// pair of closes.
func (s *switchSession) disconnect() {
	rc, f := s.rc, s.cur
	t0 := time.Now()
	if s.c.Died() {
		ReapDeadVPN(rc.Ctx)
		return // already recorded as engine.survived
	}
	bye := s.c.Stop()
	if bye == nil {
		s.add("disconnect", f, "clean", Pass, Fail, "the client did not report a disconnect: "+s.c.StderrTail(), map[string]any{"client_dir": s.c.Dir}, t0)
		ReapDeadVPN(rc.Ctx)
		return
	}
	errText, _ := bye["error"].(string)
	s.add("disconnect", f, "clean", Pass, got(errText == "", Pass, Fail), errText, nil, t0)
	after, _ := bye["after"].(map[string]any)
	ev := map[string]any{"store": after, "sentinels_bad": after["sentinels_bad"]}
	s.storeAndFDs("disconnect", f, ev, t0)
	diag := diagOf(ev)
	cleared := diag["active_route"] == "" && diag["active_route_family"] == ""
	s.add("disconnect", f, "active_route_cleared", Pass, got(cleared, Pass, Fail),
		got(cleared, "", fmt.Sprintf("nothing is running but the engine names %q", diag["active_route"])),
		map[string]any{"active_route": diag["active_route"], "route_running": diag["route_running"]}, t0)
	post := Probe(rc.Ctx, rc.P, false, 2*time.Second)
	s.add("disconnect", f, "control.after", Blocked, got(post.OK, Pass, Blocked), post.Error, nil, t0)
	if s.rotated {
		// A rotate session whose trap never closed proves less than it
		// looks like: say so instead of showing a column of green.
		s.add("session", Family{}, "fd_trap_armed", Pass, got(s.armed, Pass, Fail),
			got(s.armed, "", "in no switch of this session did a sentinel file get the old TUN's fd number: the double-close trap was never set"), nil, t0)
		// Every switch of this session built a new TUN. The one it
		// replaced exists for as long as anything in the engine holds it
		// open — and nothing should: the instance that read it has been
		// closed. One that is still there has a reader the engine never
		// stopped (FINDINGS SW-2); on a TUN that is KEPT across a switch
		// that same reader takes the new instance's packets.
		held := len(s.tunsHeld)
		s.add("session", Family{}, "old_tuns_released", Pass, got(held == 0, Pass, "held"),
			got(held == 0, "", fmt.Sprintf("%d replaced TUN interface(s) were still there after the engine instance that read them was closed (%s): the engine is still holding them", held, oneLine(strings.Join(s.tunsHeld, " "), 80))),
			map[string]any{"held": held}, t0)
	}
}

// ---- the censor, for one endpoint, for a moment --------------------------

const switchTable = "wb_switch"

// blockEndpoint drops everything the client sends to one family's
// endpoint on the relay: the route is unreachable, the relay and every
// other family are untouched.
func blockEndpoint(ctx context.Context, f Family) error {
	rules := fmt.Sprintf("add table inet %[1]s\ndelete table inet %[1]s\ntable inet %[1]s {\n  chain forward { type filter hook forward priority -10; policy accept;\n"+
		"    ip saddr %s ip daddr %s %s dport %d drop\n  }\n}\n", switchTable, ClientIP, RelayPublicAddrSet(), f.Endpoint.Proto, f.Endpoint.Port)
	cmd := exec.CommandContext(ctx, "ip", "netns", "exec", NSCensor, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("block %s: nft: %v: %s", f.Name, err, out)
	}
	return nil
}

func unblockEndpoint(ctx context.Context) {
	cmd := exec.CommandContext(ctx, "ip", "netns", "exec", NSCensor, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(fmt.Sprintf("add table inet %[1]s\ndelete table inet %[1]s\n", switchTable))
	_ = cmd.Run()
}
