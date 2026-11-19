package abi

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"daal/core/diagnostics"
	"daal/core/engine"
	"daal/core/netmem"
	"daal/core/pathmanager"
	"daal/core/routestore"
)

// The automatic connect (connect_auto.go). Every test drives the Stub
// driver; what each route's connection check finds is scripted per
// route id, read from the engine's own record of which route is up.

type autoRig struct {
	t    *testing.T
	c    *Core
	stub *engine.Stub

	mu     sync.Mutex
	script map[string]func(ctx context.Context) engine.ProofResult
	proved []string
	cfgs   []engine.ProofConfig
}

// The four routes of the phone pass: one file, one server, four
// families. r4 is the UDP one.
var autoFourRoutes = [][3]string{
	{"r1", "vless-reality", `{"type":"vless","server":"relay-a.example","server_port":443,"tls":{"enabled":true,"server_name":"cover.example"}}`},
	{"r2", "websocket-tls", `{"type":"vless","server":"relay-a.example","server_port":8443,"tls":{"enabled":true,"server_name":"own.example"}}`},
	{"r3", "naive", `{"type":"naive","server":"relay-a.example","server_port":9443}`},
	{"r4", "hysteria2", `{"type":"hysteria2","server":"relay-a.example","server_port":443,"tls":{"enabled":true,"server_name":"own.example"}}`},
}

func seedAutoRoute(t *testing.T, c *Core, id, family, profile string) {
	t.Helper()
	if err := c.store.UpsertPublisher(routestore.PublisherRow{
		PublisherID: "pub-auto", DisplayName: "Auto", TrustLevel: "tofu",
		FirstSeen: "2026-05-29T00:00:00Z", LastSeenBundle: "2026-05-29T00:00:00Z", KeyStatus: "active",
	}); err != nil {
		t.Fatal(err)
	}
	if err := c.store.UpsertRoute(routestore.RouteRow{
		RouteID: id, TransportFamily: family, Engine: "sing-box", SourceType: "imported",
		PublisherID: "pub-auto", TrustState: "trusted", ScarcityClass: "normal",
		ModesAllowed: []string{"lifeline", "normal"},
		ExpiresAt:    "2027-01-01T00:00:00Z", ImportedAt: "2026-05-29T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	if err := c.store.PutSecret("route:"+id, []byte(profile)); err != nil {
		t.Fatal(err)
	}
}

func newAutoRigIn(t *testing.T, dir string, routes [][3]string) *autoRig {
	t.Helper()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Shutdown() })
	c := mustCore()
	stub, ok := c.driver.(*engine.Stub)
	if !ok {
		t.Skipf("driver is %T, not the stub", c.driver)
	}
	for _, r := range routes {
		seedAutoRoute(t, c, r[0], r[1], r[2])
	}
	rig := &autoRig{t: t, c: c, stub: stub, script: map[string]func(context.Context) engine.ProofResult{}}
	stub.SetProofHook(func(ctx context.Context, cfg engine.ProofConfig) engine.ProofResult {
		id, _ := c.activeRouteFromMemory()
		rig.mu.Lock()
		rig.proved = append(rig.proved, id)
		rig.cfgs = append(rig.cfgs, cfg)
		f := rig.script[id]
		rig.mu.Unlock()
		if f == nil {
			return engine.ProofResult{OK: true, Attempts: 1}
		}
		return f(ctx)
	})
	return rig
}

func newAutoRig(t *testing.T, routes [][3]string) *autoRig {
	return newAutoRigIn(t, t.TempDir(), routes)
}

func (r *autoRig) set(id string, f func(ctx context.Context) engine.ProofResult) {
	r.mu.Lock()
	r.script[id] = f
	r.mu.Unlock()
}

func (r *autoRig) fail(id string, res engine.ProofResult) {
	r.set(id, func(context.Context) engine.ProofResult { return res })
}

func (r *autoRig) carry(id string) { r.set(id, nil) }

func (r *autoRig) provedRoutes() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.proved...)
}

func (r *autoRig) connectAuto() AutoResult {
	r.t.Helper()
	body, err := ConnectAuto()
	if err != nil {
		r.t.Fatal(err)
	}
	var res AutoResult
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		r.t.Fatalf("%v: %s", err, body)
	}
	return res
}

func autoBlock(t *testing.T) map[string]any {
	t.Helper()
	b, ok := diagBlob(t)["auto"].(map[string]any)
	if !ok {
		t.Fatal("diagnostics blob has no `auto` object")
	}
	return b
}

func triedIDs(tried []AutoTried, result string) []string {
	out := []string{}
	for _, tr := range tried {
		if result == "" || tr.Result == result {
			out = append(out, tr.RouteID)
		}
	}
	return out
}

func eq(a, b []string) bool { return strings.Join(a, ",") == strings.Join(b, ",") }

var (
	deadSYN   = func() engine.ProofResult { return failedProof(errSYNTimeout, diagnostics.PhaseReach, false, true) }
	silentUDP = func() engine.ProofResult {
		return failedProof(context.DeadlineExceeded, diagnostics.PhaseReach, true, true)
	}
	resetHello = func() engine.ProofResult {
		return failedProof(errors.New("read: connection reset by peer"), diagnostics.PhaseHandshake, false, true)
	}
	carryTimeout = func() engine.ProofResult {
		return failedProof(context.DeadlineExceeded, diagnostics.PhaseCarry, false, true)
	}
)

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

// The whole point: one call, no route id, and the person is connected
// on the first route that carries — the ones before it tried, recorded
// and said.
func TestConnectAuto_MovesOnToTheFirstRouteThatCarries(t *testing.T) {
	rig := newAutoRig(t, autoFourRoutes)
	lc := captureLog(t)
	rig.fail("r1", deadSYN())
	res := rig.connectAuto()
	if !res.Connected || res.RouteID != "r2" || res.Family != "websocket-tls" || res.Verdict != AutoVerdictMovedOn || res.Candidates != 4 {
		t.Fatalf("got %+v", res)
	}
	if len(res.Tried) != 2 || res.Tried[0].RouteID != "r1" || res.Tried[0].Result != AutoResultNotCarrying ||
		res.Tried[0].Category != "tcp_connect_timeout" || res.Tried[1].Result != AutoResultCarried {
		t.Fatalf("tried = %+v", res.Tried)
	}
	if got := rig.provedRoutes(); !eq(got, []string{"r1", "r2"}) {
		t.Fatalf("checked %v; r3 and r4 must not be started once r2 carries", got)
	}
	blob := diagBlob(t)
	if blob["active_route"] != "r2" || blob["route_check"] != RouteCheckOK || blob["route_running"] != true {
		t.Fatalf("engine state: active=%v check=%v running=%v", blob["active_route"], blob["route_check"], blob["route_running"])
	}
	a := autoBlock(t)
	if a["state"] != AutoStateConnected || a["mode"] != true || a["route_id"] != "r2" || a["verdict"] != AutoVerdictMovedOn || a["trying"] != "" {
		t.Fatalf("auto block: %v", a)
	}
	for _, want := range []string{
		"auto start candidates=4",
		"auto try route=r1 family=vless-reality index=1 total=4",
		"auto result route=r1 result=not_carrying category=tcp_connect_timeout",
		"auto try route=r2 family=websocket-tls index=2 total=4",
		"auto result route=r2 result=carried category=",
		"auto done connected=true route=r2 verdict=moved_on",
	} {
		if !lc.has(want) {
			t.Errorf("log has no line %q in:\n%s", want, strings.Join(lc.all(), "\n"))
		}
	}
	for _, l := range lc.all() {
		if strings.Contains(l, "relay-a") || strings.Contains(l, "cover.example") || strings.Contains(l, "own.example") {
			t.Errorf("log line carries something from a profile: %q", l)
		}
	}
	// The failed route is recorded exactly as a failed manual connect is.
	if ok, _ := rig.c.pm.CanAttempt("r1", "vless-reality"); ok {
		t.Fatal("r1 failed its check and is not cooling down")
	}
	// First try on a clean network: no verdict at all.
	if err := ClearRoute(); err != nil {
		t.Fatal(err)
	}
	res = rig.connectAuto()
	if !res.Connected || res.RouteID != "r2" || res.Verdict != AutoVerdictNone || res.Tried[0].Why != AutoWhyCarriedHere {
		t.Fatalf("second connect: %+v", res)
	}
}

// The order: what carried on THIS network first, the ranking next,
// what failed here recently last, what cannot be tried not at all —
// and each place explained.
func TestConnectAuto_OrderIsMemoryThenRankingThenRecentFailures(t *testing.T) {
	rig := newAutoRig(t, autoFourRoutes)
	for _, r := range autoFourRoutes {
		rig.fail(r[0], carryTimeout()) // "unknown": no cooldown-by-family side effects between cases
	}
	if _, err := NetworkChanged("wifi", "", "home"); err != nil {
		t.Fatal(err)
	}
	home := activeNetworkID()
	st := netmemStore()
	now := nowUTC()

	// Nothing remembered: the ranking (equal budgets → route id).
	res := rig.connectAuto()
	if got := triedIDs(res.Tried, AutoResultNotCarrying); !eq(got, []string{"r1", "r2", "r3", "r4"}) {
		t.Fatalf("with no memory the order is %v", got)
	}
	for _, tr := range res.Tried {
		if tr.Why != AutoWhyRanked {
			t.Fatalf("%s: why=%q, want ranked", tr.RouteID, tr.Why)
		}
	}
	if res.Connected || res.Verdict != AutoVerdictAllFailed {
		t.Fatalf("got %+v", res)
	}
	// That pass recorded four failures here. Now: r3 carried here after
	// its failure, r4 carried here after that (most recent first); r1's
	// failure stands; r2's failure is two days old.
	clearCooldowns(rig.c)
	if err := st.RecordRouteCarried(home, "r3", now); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordRouteCarried(home, "r4", now); err != nil {
		t.Fatal(err)
	}
	snap, _ := st.Get(home)
	m := snap.RouteMemory["r2"]
	m.FailedHour = now.Add(-48 * time.Hour).Truncate(time.Hour).Unix()
	snap.RouteMemory["r2"] = m
	if err := st.Put(home, snap, now); err != nil {
		t.Fatal(err)
	}
	res = rig.connectAuto()
	if got := triedIDs(res.Tried, AutoResultNotCarrying); !eq(got, []string{"r4", "r3", "r2", "r1"}) {
		t.Fatalf("order with memory = %v, want r4 r3 (carried here, latest first), r2 (old failure: ranked), r1 (failed here)", got)
	}
	why := map[string]string{}
	for _, tr := range res.Tried {
		why[tr.RouteID] = tr.Why
	}
	if why["r4"] != AutoWhyCarriedHere || why["r3"] != AutoWhyCarriedHere || why["r2"] != AutoWhyRanked || why["r1"] != AutoWhyFailedHere {
		t.Fatalf("why = %v", why)
	}

	// Another network knows none of this.
	clearCooldowns(rig.c)
	if _, err := NetworkChanged("cell", "carrier", ""); err != nil {
		t.Fatal(err)
	}
	res = rig.connectAuto()
	if got := triedIDs(res.Tried, AutoResultNotCarrying); !eq(got, []string{"r1", "r2", "r3", "r4"}) {
		t.Fatalf("on another network the order is %v", got)
	}

	// Back home, with r4 cooling down and r3 revoked: neither is
	// started, both are listed with the reason, and nothing is put in
	// connect_refused (nobody picked them).
	clearCooldowns(rig.c)
	if _, err := NetworkChanged("wifi", "", "home"); err != nil {
		t.Fatal(err)
	}
	rig.c.mu.Lock()
	rig.c.pm.Failed("r4", "hysteria2", diagnostics.UDPNoReply)
	rig.c.mu.Unlock()
	row, _ := rig.c.store.GetRoute("r3")
	row.TrustState = "revoked"
	if err := rig.c.store.UpsertRoute(row); err != nil {
		t.Fatal(err)
	}
	before := len(rig.provedRoutes())
	res = rig.connectAuto()
	if got := rig.provedRoutes()[before:]; !eq(got, []string{"r1", "r2"}) && !eq(got, []string{"r2", "r1"}) {
		t.Fatalf("started %v; r3 (revoked) and r4 (cooling) must not be started", got)
	}
	refused := map[string]string{}
	for _, tr := range res.Tried {
		if tr.Result == AutoResultRefused {
			refused[tr.RouteID] = tr.Refused
		}
	}
	if refused["r3"] != ConnectRefusedRevoked || refused["r4"] != ConnectRefusedCooldown || res.Candidates != 2 {
		t.Fatalf("refused = %v candidates = %d", refused, res.Candidates)
	}
	if got := diagField(t, "connect_refused"); got != "" {
		t.Fatalf("connect_refused = %v after an automatic pass", got)
	}
}

// clearCooldowns forgets every cooldown, so a test can run pass after
// pass over the same routes.
func clearCooldowns(c *Core) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pm = pathmanager.New()
	c.pm.SetNow(nowUTC)
	c.pm.SetActiveNetwork(activeNetworkID())
}

// A disconnect during a connection check ends the pass at once: the
// call returns "cancelled", the next candidate is never started, and
// nothing is recorded about the route whose check was abandoned.
func TestConnectAuto_ClearRouteCancelsDuringACheck(t *testing.T) {
	rig := newAutoRig(t, autoFourRoutes)
	inCheck := make(chan struct{})
	rig.set("r1", func(ctx context.Context) engine.ProofResult {
		close(inCheck)
		<-ctx.Done()
		return engine.ProofResult{Cancelled: true, Err: engine.ErrProofCancelled}
	})
	done := make(chan AutoResult, 1)
	go func() { done <- rig.connectAuto() }()
	<-inCheck
	if a := autoBlock(t); a["state"] != AutoStateTrying || a["trying"] != "r1" || a["index"] != float64(1) || a["total"] != float64(4) || a["mode"] != true {
		t.Fatalf("auto block during the first check: %v", a)
	}
	start := time.Now()
	if err := ClearRoute(); err != nil {
		t.Fatal(err)
	}
	var res AutoResult
	select {
	case res = <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("ConnectAuto did not return after ClearRoute")
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("cancel took %s", d)
	}
	if res.Connected || res.Verdict != AutoVerdictCancelled || len(res.Tried) != 1 || res.Tried[0].Result != AutoResultCancelled {
		t.Fatalf("got %+v", res)
	}
	if got := rig.provedRoutes(); !eq(got, []string{"r1"}) {
		t.Fatalf("checked %v after the cancel", got)
	}
	blob := diagBlob(t)
	a := blob["auto"].(map[string]any)
	if a["state"] != AutoStateIdle || a["mode"] != false || blob["active_route"] != "" || blob["route_check"] != RouteCheckNone {
		t.Fatalf("after the cancel: auto=%v active=%v check=%v", a, blob["active_route"], blob["route_check"])
	}
	if ok, _ := rig.c.pm.CanAttempt("r1", "vless-reality"); !ok {
		t.Fatal("an abandoned check was recorded as a failure of the route")
	}
	if mem := rig.c.routeMemory(); len(mem) != 0 {
		t.Fatalf("an abandoned check was remembered: %v", mem)
	}
}

// A route picked by hand during a pass takes over: the pass is
// cancelled, the picked route is what is connected, and the engine is
// no longer the one choosing.
func TestConnectAuto_ManualSetRouteTakesOver(t *testing.T) {
	rig := newAutoRig(t, autoFourRoutes)
	inCheck := make(chan struct{})
	rig.set("r1", func(ctx context.Context) engine.ProofResult {
		close(inCheck)
		<-ctx.Done()
		return engine.ProofResult{Cancelled: true, Err: engine.ErrProofCancelled}
	})
	done := make(chan AutoResult, 1)
	go func() { done <- rig.connectAuto() }()
	<-inCheck
	if err := SetRoute("r3"); err != nil {
		t.Fatal(err)
	}
	res := <-done
	if res.Verdict != AutoVerdictCancelled {
		t.Fatalf("got %+v", res)
	}
	blob := diagBlob(t)
	a := blob["auto"].(map[string]any)
	if blob["active_route"] != "r3" || blob["route_check"] != RouteCheckOK || a["mode"] != false || a["state"] != AutoStateIdle {
		t.Fatalf("active=%v check=%v auto=%v", blob["active_route"], blob["route_check"], a)
	}
	if got := rig.provedRoutes(); !eq(got, []string{"r1", "r3"}) {
		t.Fatalf("checked %v", got)
	}
}

// A newer automatic connect abandons the older one.
func TestConnectAuto_NewerPassAbandonsTheOlder(t *testing.T) {
	rig := newAutoRig(t, autoFourRoutes)
	inCheck := make(chan struct{})
	var once sync.Once
	rig.set("r1", func(ctx context.Context) engine.ProofResult {
		first := false
		once.Do(func() { first = true; close(inCheck) })
		if !first {
			return engine.ProofResult{OK: true, Attempts: 1}
		}
		<-ctx.Done()
		return engine.ProofResult{Cancelled: true, Err: engine.ErrProofCancelled}
	})
	done := make(chan AutoResult, 1)
	go func() { done <- rig.connectAuto() }()
	<-inCheck
	second := rig.connectAuto()
	first := <-done
	if first.Verdict != AutoVerdictCancelled || !second.Connected || second.RouteID != "r1" {
		t.Fatalf("first=%+v second=%+v", first, second)
	}
	if a := autoBlock(t); a["state"] != AutoStateConnected || a["mode"] != true || a["route_id"] != "r1" {
		t.Fatalf("auto block: %v", a)
	}
}

// Already connected: nothing is started, the running route is named —
// and the engine is in charge of it from this call on (see
// TestConnectAuto_TakesChargeOfARoutePickedByHand).
func TestConnectAuto_AlreadyConnectedIsANoOp(t *testing.T) {
	rig := newAutoRig(t, autoFourRoutes)
	if err := SetRoute("r3"); err != nil {
		t.Fatal(err)
	}
	n := rig.stub.ProofCount()
	res := rig.connectAuto()
	if !res.Connected || res.RouteID != "r3" || res.Family != "naive" || !res.AlreadyConnected || res.Verdict != "" || len(res.Tried) != 0 {
		t.Fatalf("got %+v", res)
	}
	if rig.stub.ProofCount() != n {
		t.Fatal("a connected engine was checked or restarted")
	}
	if a := autoBlock(t); a["mode"] != true || a["state"] != AutoStateConnected || a["route_id"] != "r3" {
		t.Fatalf("auto block: %v", a)
	}
	// And after an automatic connect, a second call changes nothing.
	_ = ClearRoute()
	first := rig.connectAuto()
	n = rig.stub.ProofCount()
	again := rig.connectAuto()
	if !again.AlreadyConnected || again.RouteID != first.RouteID || rig.stub.ProofCount() != n {
		t.Fatalf("first=%+v again=%+v", first, again)
	}
	if a := autoBlock(t); a["mode"] != true || a["state"] != AutoStateConnected {
		t.Fatalf("auto block: %v", a)
	}
}

// The budget: a candidate of an automatic pass is not asked twice at an
// address that never answered; a route the person picked keeps every
// attempt.
func TestConnectAuto_UsesTheShorterCheckBudget(t *testing.T) {
	rig := newAutoRig(t, autoFourRoutes)
	rig.connectAuto()
	_ = ClearRoute()
	if err := SetRoute("r1"); err != nil {
		t.Fatal(err)
	}
	rig.mu.Lock()
	defer rig.mu.Unlock()
	if len(rig.cfgs) != 2 || !rig.cfgs[0].StopAtUnreachedRelay || rig.cfgs[1].StopAtUnreachedRelay {
		t.Fatalf("StopAtUnreachedRelay: auto=%v manual=%v", rig.cfgs[0].StopAtUnreachedRelay, rig.cfgs[len(rig.cfgs)-1].StopAtUnreachedRelay)
	}
}

// ---- what a pass can say ----------------------------------------------

func obsOf(res engine.ProofResult, udp bool, host string, port int, name string) autoObs {
	if res.OK {
		return autoObs{result: AutoResultCarried, udp: udp, host: host, port: port, name: name}
	}
	return autoObs{result: AutoResultNotCarrying, category: res.Category(), obs: res.Observation, udp: udp, host: host, port: port, name: name}
}

// One row per verdict a pass that tried something can reach, and the
// refinement each route gets. Every row names its two observations.
func TestDeriveAuto_VerdictTable(t *testing.T) {
	ok := engine.ProofResult{OK: true}
	offline := failedProof(errors.New("dial tcp: connect: network is unreachable"), diagnostics.PhaseReach, false, true)
	swallowed := failedProof(context.DeadlineExceeded, diagnostics.PhaseHandshake, false, true)
	for _, tc := range []struct {
		name    string
		tried   []autoObs
		verdict string
		refined []string
	}{
		{"first route carries", []autoObs{obsOf(ok, false, "a", 443, "n1")}, AutoVerdictNone, []string{""}},
		{"second route carries", []autoObs{obsOf(deadSYN(), false, "a", 443, "n1"), obsOf(ok, false, "b", 443, "n2")}, AutoVerdictMovedOn, []string{"", ""}},
		{"silent UDP, then TCP to the same address carries: UDP is blocked here, not a dead address",
			[]autoObs{obsOf(silentUDP(), true, "a", 443, "n"), obsOf(ok, false, "a", 8443, "n")}, AutoVerdictMovedOn, []string{AutoRefinedUDPBlockedHere, ""}},
		{"silent UDP, then TCP to ANOTHER address carries: one observation, nothing added",
			[]autoObs{obsOf(silentUDP(), true, "a", 443, "n"), obsOf(ok, false, "b", 443, "n")}, AutoVerdictMovedOn, []string{"", ""}},
		{"the device says there is no network", []autoObs{obsOf(offline, false, "a", 443, "n"), obsOf(offline, true, "a", 443, "n")}, AutoVerdictNetworkDown, []string{"", ""}},
		{"every SYN to the address unanswered, its UDP route silent: the address",
			[]autoObs{obsOf(deadSYN(), false, "a", 443, "n1"), obsOf(deadSYN(), false, "a", 8443, "n2"), obsOf(silentUDP(), true, "a", 443, "n2")},
			AutoVerdictRelayUnreachable, []string{"", "", AutoRefinedRelayUnreachable}},
		{"a silent UDP route alone proves nothing about the address", []autoObs{obsOf(silentUDP(), true, "a", 443, "n")}, AutoVerdictAllFailed, []string{""}},
		{"UDP silent while TCP to the same address was answered (and then failed)",
			[]autoObs{obsOf(carryTimeout(), false, "a", 443, "n1"), obsOf(silentUDP(), true, "a", 443, "n2")}, AutoVerdictUDPBlockedHere, []string{"", AutoRefinedUDPBlockedHere}},
		{"one name reset where another name to the same address and port got through",
			[]autoObs{obsOf(resetHello(), false, "a", 443, "n1"), obsOf(carryTimeout(), false, "a", 443, "n2")}, AutoVerdictNameBlocked, []string{AutoRefinedNameBlocked, ""}},
		{"a different PORT got through: that does not prove the name",
			[]autoObs{obsOf(resetHello(), false, "a", 443, "n1"), obsOf(carryTimeout(), false, "a", 8443, "n2")}, AutoVerdictAllFailed, []string{"", ""}},
		{"two names stopped at the same point on the same address and port",
			[]autoObs{obsOf(resetHello(), false, "a", 443, "n1"), obsOf(swallowed, false, "a", 443, "n2")}, AutoVerdictAddressBlocked, []string{AutoRefinedAddressBlocked, AutoRefinedAddressBlocked}},
		{"the same name twice proves nothing",
			[]autoObs{obsOf(resetHello(), false, "a", 443, "n1"), obsOf(resetHello(), false, "a", 443, "n1")}, AutoVerdictAllFailed, []string{"", ""}},
		{"failures with nothing in common", []autoObs{obsOf(resetHello(), false, "a", 443, "n1"), obsOf(deadSYN(), false, "b", 443, "n2")}, AutoVerdictAllFailed, []string{"", ""}},
		{"a route whose address is not known is never a second observation",
			[]autoObs{obsOf(silentUDP(), true, "", 0, ""), obsOf(carryTimeout(), false, "", 0, "")}, AutoVerdictAllFailed, []string{"", ""}},
	} {
		verdict, refined := deriveAuto(tc.tried)
		if verdict != tc.verdict || !eq(refined, tc.refined) {
			t.Errorf("%s:\n  got  verdict=%q refined=%q\n  want verdict=%q refined=%q", tc.name, verdict, refined, tc.verdict, tc.refined)
		}
	}
}

// The verdicts of a pass that had nothing to try.
func TestVerdictWithoutCandidates_Table(t *testing.T) {
	r := func(codes ...string) []AutoTried {
		out := []AutoTried{}
		for _, c := range codes {
			out = append(out, AutoTried{Result: AutoResultRefused, Refused: c})
		}
		return out
	}
	for _, tc := range []struct {
		name   string
		routes int
		left   []AutoTried
		want   string
	}{
		{"nothing imported", 0, nil, AutoVerdictNoRoutes},
		{"every route from an old file", 2, r(ConnectRefusedNeedsNewFile, ConnectRefusedNeedsNewFile), AutoVerdictAllNeedNewFile},
		{"every route expired or revoked", 2, r(ConnectRefusedExpired, ConnectRefusedRevoked), AutoVerdictAllExpiredOrRevoked},
		{"old file beside expired: a new file is the remedy for all", 2, r(ConnectRefusedNeedsNewFile, ConnectRefusedExpired), AutoVerdictAllNeedNewFile},
		{"every route cooling down", 2, r(ConnectRefusedCooldown, ConnectRefusedCooldown), AutoVerdictAllCoolingDown},
		{"one cooling down beside dead ones: waiting helps", 2, r(ConnectRefusedCooldown, ConnectRefusedRevoked), AutoVerdictAllCoolingDown},
		{"only an experimental route, and those are off", 1, r(AutoRefusedExperimentalOff), AutoVerdictNoneUsable},
	} {
		if got := verdictWithoutCandidates(tc.routes, tc.left); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

// The verdicts through the real call, for the ones that depend on how
// the pass is wired rather than on the table.
func TestConnectAuto_VerdictsEndToEnd(t *testing.T) {
	t.Run("no_routes", func(t *testing.T) {
		rig := newAutoRig(t, nil)
		res := rig.connectAuto()
		if res.Connected || res.Verdict != AutoVerdictNoRoutes || res.Candidates != 0 {
			t.Fatalf("got %+v", res)
		}
		if a := autoBlock(t); a["state"] != AutoStateFailed || a["mode"] != false || a["verdict"] != AutoVerdictNoRoutes {
			t.Fatalf("auto block: %v", a)
		}
	})
	t.Run("all_cooling_down", func(t *testing.T) {
		rig := newAutoRig(t, autoFourRoutes[:2])
		rig.c.mu.Lock()
		rig.c.pm.Failed("r1", "vless-reality", diagnostics.TCPConnectTimeout)
		rig.c.pm.Failed("r2", "websocket-tls", diagnostics.TCPConnectTimeout)
		rig.c.mu.Unlock()
		res := rig.connectAuto()
		if res.Connected || res.Verdict != AutoVerdictAllCoolingDown || len(rig.provedRoutes()) != 0 {
			t.Fatalf("got %+v", res)
		}
	})
	t.Run("all_expired_or_revoked", func(t *testing.T) {
		rig := newAutoRig(t, autoFourRoutes[:2])
		for i, state := range []string{"revoked", "expired"} {
			row, _ := rig.c.store.GetRoute(autoFourRoutes[i][0])
			row.TrustState = state
			if err := rig.c.store.UpsertRoute(row); err != nil {
				t.Fatal(err)
			}
		}
		if res := rig.connectAuto(); res.Verdict != AutoVerdictAllExpiredOrRevoked {
			t.Fatalf("got %+v", res)
		}
	})
	t.Run("all_need_new_file", func(t *testing.T) {
		rig := newAutoRig(t, autoFourRoutes[:1])
		// A RelayPack route with no signed endpoint: the old-file case.
		row, _ := rig.c.store.GetRoute("r1")
		row.RelayPackID = "pack-1"
		if err := rig.c.store.UpsertRoute(row); err != nil {
			t.Fatal(err)
		}
		res := rig.connectAuto()
		if res.Verdict != AutoVerdictAllNeedNewFile || res.Tried[0].Refused != ConnectRefusedNeedsNewFile {
			t.Fatalf("got %+v", res)
		}
	})
	t.Run("experimental routes are left out while the gate is off", func(t *testing.T) {
		rig := newAutoRig(t, autoFourRoutes[:1])
		seedAutoRoute(t, rig.c, "r-exp", "tuic", `{"type":"tuic","server":"relay-a.example","server_port":443}`)
		rig.fail("r1", deadSYN())
		res := rig.connectAuto()
		if got := rig.provedRoutes(); !eq(got, []string{"r1"}) {
			t.Fatalf("started %v; the experimental route must not be started", got)
		}
		if res.Candidates != 1 || res.Tried[1].RouteID != "r-exp" || res.Tried[1].Refused != AutoRefusedExperimentalOff {
			t.Fatalf("got %+v", res)
		}
		if got := diagField(t, "experimental_routes_skipped"); got != float64(1) {
			t.Fatalf("experimental_routes_skipped = %v", got)
		}
		// Turned on, it is a candidate like any other.
		clearCooldowns(rig.c)
		rig.c.mu.Lock()
		rig.c.experimentalFamiliesEnabled = true
		rig.c.mu.Unlock()
		res = rig.connectAuto()
		if !res.Connected || res.RouteID != "r-exp" {
			t.Fatalf("with the gate open: %+v", res)
		}
	})
	t.Run("relay_unreachable, and the UDP route is refined", func(t *testing.T) {
		rig := newAutoRig(t, autoFourRoutes)
		rig.fail("r1", deadSYN())
		rig.fail("r2", deadSYN())
		rig.fail("r3", deadSYN())
		rig.fail("r4", silentUDP())
		res := rig.connectAuto()
		if res.Connected || res.Verdict != AutoVerdictRelayUnreachable {
			t.Fatalf("got %+v", res)
		}
		last := res.Tried[3]
		if last.RouteID != "r4" || last.Category != "udp_no_reply" || last.Refined != AutoRefinedRelayUnreachable || last.Relay != 1 {
			t.Fatalf("r4 = %+v; its own category must stay udp_no_reply and the refinement must say the address", last)
		}
		blob := diagBlob(t)
		a := blob["auto"].(map[string]any)
		if a["state"] != AutoStateFailed || a["verdict"] != AutoVerdictRelayUnreachable || blob["route_running"] != false || blob["active_route"] != "" {
			t.Fatalf("auto=%v running=%v active=%v", a, blob["route_running"], blob["active_route"])
		}
		// A host that tears down after a connect that did not come up
		// calls ClearRoute; the verdict must still be there to read.
		_ = ClearRoute()
		if a := autoBlock(t); a["state"] != AutoStateFailed || a["verdict"] != AutoVerdictRelayUnreachable || a["mode"] != false {
			t.Fatalf("after ClearRoute: %v", a)
		}
	})
	t.Run("udp blocked here: connected over TCP, the UDP route says why it was passed", func(t *testing.T) {
		rig := newAutoRig(t, autoFourRoutes)
		// Make the UDP route the first candidate on this network.
		_ = netmemStore().RecordRouteCarried(activeNetworkID(), "r4", nowUTC())
		rig.fail("r4", silentUDP())
		res := rig.connectAuto()
		if !res.Connected || res.RouteID != "r1" || res.Verdict != AutoVerdictMovedOn {
			t.Fatalf("got %+v", res)
		}
		if res.Tried[0].RouteID != "r4" || res.Tried[0].Category != "udp_no_reply" || res.Tried[0].Refined != AutoRefinedUDPBlockedHere {
			t.Fatalf("r4 = %+v", res.Tried[0])
		}
	})
}

// ---- staying connected -------------------------------------------------

func fastRecheck(c *Core) {
	c.mu.Lock()
	c.proofCfg.LivenessInterval = time.Hour
	c.proofCfg.RecheckInterval = 20 * time.Millisecond
	c.mu.Unlock()
}

// The connected route stops carrying and the engine moves to the next
// one by itself — no call from the host.
func TestAutoMode_FallsOverWhenTheRouteStopsCarrying(t *testing.T) {
	rig := newAutoRig(t, autoFourRoutes)
	fastRecheck(rig.c)
	if res := rig.connectAuto(); !res.Connected || res.RouteID != "r1" {
		t.Fatalf("got %+v", res)
	}
	rig.fail("r1", deadSYN())
	rig.fail("r2", deadSYN())
	rig.c.kickLiveness()
	waitFor(t, "the engine to be connected on r3", func() bool {
		r, _ := rig.c.activeRouteFromMemory()
		st, _ := rig.c.check.get()
		as, _ := rig.c.auto.snapshot()
		return r == "r3" && st == RouteCheckOK && as == AutoStateConnected
	})
	a := autoBlock(t)
	if a["state"] != AutoStateConnected || a["route_id"] != "r3" || a["mode"] != true || a["verdict"] != AutoVerdictMovedOn {
		t.Fatalf("auto block: %v", a)
	}
	tried := a["tried"].([]any)
	first := tried[0].(map[string]any)
	if first["route_id"] != "r1" || first["why"] != AutoWhyWasConnected || first["result"] != AutoResultNotCarrying {
		t.Fatalf("tried = %v", tried)
	}
	// The new route is watched in its turn.
	rig.fail("r3", deadSYN())
	rig.c.kickLiveness()
	waitFor(t, "the engine to be connected on r4", func() bool {
		r, _ := rig.c.activeRouteFromMemory()
		st, _ := rig.c.check.get()
		as, _ := rig.c.auto.snapshot()
		return r == "r4" && st == RouteCheckOK && as == AutoStateConnected
	})
}

// The same outage with a route the person picked by hand: the engine
// does not choose for them.
func TestManualMode_DoesNotFallOver(t *testing.T) {
	rig := newAutoRig(t, autoFourRoutes)
	fastRecheck(rig.c)
	if err := SetRoute("r1"); err != nil {
		t.Fatal(err)
	}
	rig.fail("r1", deadSYN())
	rig.c.kickLiveness()
	waitFor(t, "r1 to be failed", func() bool { st, _ := rig.c.check.get(); return st == RouteCheckFailed })
	time.Sleep(100 * time.Millisecond) // several rechecks
	blob := diagBlob(t)
	if blob["active_route"] != "r1" || blob["route_running"] != true {
		t.Fatalf("active=%v running=%v", blob["active_route"], blob["route_running"])
	}
	for _, id := range rig.provedRoutes() {
		if id != "r1" {
			t.Fatalf("route %s was started without anyone asking", id)
		}
	}
}

// Nothing else carries either: the instance of the route that was
// connected is put back and re-checked, so the tunnel heals by itself
// when the path returns — and says "connected" again when it does.
func TestAutoMode_NothingElseCarriesThenTheRouteComesBack(t *testing.T) {
	rig := newAutoRig(t, autoFourRoutes)
	fastRecheck(rig.c)
	if res := rig.connectAuto(); res.RouteID != "r1" {
		t.Fatalf("got %+v", res)
	}
	for _, id := range []string{"r1", "r3"} {
		rig.fail(id, deadSYN())
	}
	// A failure that does NOT cool the route down: the rechecks below
	// must still leave it alone.
	refusedCred := failedProof(errors.New("authentication failed"), diagnostics.PhaseCarry, false, true)
	if refusedCred.Category() != diagnostics.AuthFailed {
		t.Fatalf("premise: category = %s", refusedCred.Category())
	}
	rig.fail("r2", refusedCred)
	rig.fail("r4", silentUDP())
	rig.c.kickLiveness()
	waitFor(t, "the pass to fail and r1 to be running again", func() bool {
		r, _ := rig.c.activeRouteFromMemory()
		st, _, running := rig.c.check.snapshot()
		as, _ := rig.c.auto.snapshot()
		return as == AutoStateFailed && r == "r1" && st == RouteCheckFailed && running
	})
	a := autoBlock(t)
	if a["mode"] != true || a["verdict"] != AutoVerdictAllFailed {
		t.Fatalf("auto block: %v", a)
	}
	// Everything else is cooling down now; the rechecks of r1 must not
	// start anything.
	n := len(rig.provedRoutes())
	time.Sleep(100 * time.Millisecond)
	for _, id := range rig.provedRoutes()[n:] {
		if id != "r1" {
			t.Fatalf("a recheck started %s", id)
		}
	}
	if ok, _ := rig.c.pm.CanAttempt("r2", "websocket-tls"); !ok {
		t.Fatal("premise: r2 is not cooling down")
	}
	// The person asking is not held to that wait — and a pass with the
	// connected route down keeps that route when nothing else carries.
	res := rig.connectAuto()
	if res.Connected || res.Verdict == "" || !contains(strings.Join(rig.provedRoutes()[n:], ","), "r2") {
		t.Fatalf("explicit pass: %+v proved %v", res, rig.provedRoutes()[n:])
	}
	waitFor(t, "r1 to be running again after the explicit pass", func() bool {
		r, _ := rig.c.activeRouteFromMemory()
		st, _, running := rig.c.check.snapshot()
		return r == "r1" && st == RouteCheckFailed && running
	})
	rig.carry("r1")
	waitFor(t, "r1 to carry again", func() bool {
		st, _ := rig.c.check.get()
		as, _ := rig.c.auto.snapshot()
		return st == RouteCheckOK && as == AutoStateConnected
	})
	if a := autoBlock(t); a["route_id"] != "r1" || a["verdict"] != "" {
		t.Fatalf("auto block after recovery: %v", a)
	}
}

// ---- this network's memory ---------------------------------------------

// What carried on a network is remembered across a restart, is what the
// next connect tries first, is hashed-network-keyed, and is gone after
// a panic wipe.
func TestAutoMemory_PersistsAndIsWiped(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "daal-state")
	rig := newAutoRigIn(t, dir, autoFourRoutes)
	if _, err := NetworkChanged("wifi", "", "HomeNetworkName"); err != nil {
		t.Fatal(err)
	}
	rig.fail("r1", deadSYN())
	rig.fail("r2", deadSYN())
	if res := rig.connectAuto(); res.RouteID != "r3" {
		t.Fatalf("got %+v", res)
	}
	if err := Shutdown(); err != nil {
		t.Fatal(err)
	}

	rig = newAutoRigIn(t, dir, nil)
	if _, err := NetworkChanged("wifi", "", "HomeNetworkName"); err != nil {
		t.Fatal(err)
	}
	mem := rig.c.routeMemory()
	if !mem["r3"].CarriedLast() || mem["r1"].FailedCategory != "tcp_connect_timeout" || mem["r1"].CarriedLast() {
		t.Fatalf("memory after a restart: %+v", mem)
	}
	res := rig.connectAuto()
	if !res.Connected || res.RouteID != "r3" || res.Verdict != AutoVerdictNone || res.Tried[0].Why != AutoWhyCarriedHere {
		t.Fatalf("after a restart the route that carried here must be first: %+v", res)
	}
	if got := rig.provedRoutes(); !eq(got, []string{"r3"}) {
		t.Fatalf("checked %v", got)
	}
	// A network change rewrites the snapshot of the network left; the
	// memory must survive that.
	if _, err := NetworkChanged("cell", "carrier", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := NetworkChanged("wifi", "", "HomeNetworkName"); err != nil {
		t.Fatal(err)
	}
	if mem := rig.c.routeMemory(); !mem["r3"].CarriedLast() {
		t.Fatalf("a network change dropped the memory: %+v", mem)
	}
	// Nothing in the store names the network in clear.
	keys, _ := rig.c.store.ListSecretKeys("netmem:")
	for _, k := range keys {
		raw, _ := rig.c.store.GetSecret(k)
		if strings.Contains(k, "HomeNetworkName") || strings.Contains(string(raw), "HomeNetworkName") {
			t.Fatalf("the network's name is stored in clear under %s", k)
		}
	}
	// Deleting a route forgets it.
	_ = ClearRoute()
	if err := RouteDelete("r1"); err != nil {
		t.Fatal(err)
	}
	if _, ok := rig.c.routeMemory()["r1"]; ok {
		t.Fatal("a deleted route is still remembered")
	}

	if err := PanicWipe(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("state dir after a panic wipe: %v", err)
	}
	rig = newAutoRigIn(t, dir, nil)
	if _, err := NetworkChanged("wifi", "", "HomeNetworkName"); err != nil {
		t.Fatal(err)
	}
	if mem := rig.c.routeMemory(); len(mem) != 0 {
		t.Fatalf("memory survived a panic wipe: %+v", mem)
	}
}

// Reading never writes: the polled calls leave the stored memory
// byte-identical, and so does a liveness check that finds the route
// still carrying.
func TestAutoMemory_NoWriteOnPolledPaths(t *testing.T) {
	rig := newAutoRig(t, autoFourRoutes)
	rig.fail("r1", deadSYN())
	if res := rig.connectAuto(); res.RouteID != "r2" {
		t.Fatalf("got %+v", res)
	}
	key := "netmem:" + activeNetworkID()
	before, err := rig.c.store.GetSecret(key)
	if err != nil || !strings.Contains(string(before), `"route_memory"`) {
		t.Fatalf("premise: the connect wrote the memory: %q %v", before, err)
	}
	for i := 0; i < 3; i++ {
		if _, err := ExportDiagnostics(); err != nil {
			t.Fatal(err)
		}
		if _, err := DiagnosticsExplain(); err != nil {
			t.Fatal(err)
		}
		if _, err := RouteConnectPrecheck("r3"); err != nil {
			t.Fatal(err)
		}
		if _, err := CheckActiveRoute(); err != nil {
			t.Fatal(err)
		}
		if res := rig.connectAuto(); !res.AlreadyConnected {
			t.Fatalf("got %+v", res)
		}
	}
	after, _ := rig.c.store.GetSecret(key)
	if string(after) != string(before) {
		t.Fatalf("a read path rewrote the memory:\n before %s\n after  %s", before, after)
	}
}

// A store that stops answering in the middle of a pass does not fail
// the connect: the route that carries is connected, and the engine says
// so from memory.
func TestConnectAuto_AFailingStoreDoesNotFailTheConnect(t *testing.T) {
	rig := newAutoRig(t, autoFourRoutes[:1])
	seedStableRoute(t, rig.c, "r-st") // breakStore's premise reads it
	rig.fail("r-st", deadSYN())
	rig.set("r1", func(context.Context) engine.ProofResult {
		breakStore(t, rig.c)
		return engine.ProofResult{OK: true, Attempts: 1}
	})
	res := rig.connectAuto()
	if !res.Connected || res.RouteID != "r1" {
		t.Fatalf("got %+v", res)
	}
	if blob := diagBlob(t); blob["active_route"] != "r1" || blob["route_check"] != RouteCheckOK {
		t.Fatalf("active=%v check=%v", blob["active_route"], blob["route_check"])
	}
}

// ---- SW-1 ---------------------------------------------------------------

// A switch to a route that carries nothing: the switch fails and says
// so, and the route that was carrying is connected again instead of
// nothing being connected.
func TestSetRoute_FailedSwitchGoesBackToTheRouteThatWasCarrying(t *testing.T) {
	rig := newAutoRig(t, autoFourRoutes)
	lc := captureLog(t)
	if err := SetRoute("r1"); err != nil {
		t.Fatal(err)
	}
	rig.fail("r2", deadSYN())
	err := SetRoute("r2")
	if !errors.Is(err, ErrRouteNotCarrying) {
		t.Fatalf("SetRoute(r2) = %v; the switch failed and must say so", err)
	}
	blob := diagBlob(t)
	if blob["active_route"] != "r1" || blob["route_check"] != RouteCheckOK || blob["route_running"] != true {
		t.Fatalf("after a failed switch: active=%v check=%v running=%v; want r1 connected", blob["active_route"], blob["route_check"], blob["route_running"])
	}
	sb := blob["switch_back"].(map[string]any)
	if sb["failed_route"] != "r2" || sb["failed_family"] != "websocket-tls" || sb["category"] != "tcp_connect_timeout" || sb["restored_route"] != "r1" || sb["restored"] != true {
		t.Fatalf("switch_back = %v", sb)
	}
	if !lc.has("route switch_back failed=r2 category=tcp_connect_timeout back_to=r1 restored=true") {
		t.Fatalf("no switch_back log line in:\n%s", strings.Join(lc.all(), "\n"))
	}
	if got := rig.provedRoutes(); !eq(got, []string{"r1", "r2", "r1"}) {
		t.Fatalf("checked %v; the way back must be checked, not assumed", got)
	}
	if ok, _ := rig.c.pm.CanAttempt("r2", "websocket-tls"); ok {
		t.Fatal("the route that failed is not cooling down")
	}
	// r1 is watched again.
	rig.fail("r1", deadSYN())
	rig.c.kickLiveness()
	waitFor(t, "the restored route to be re-checked", func() bool { st, _ := rig.c.check.get(); return st == RouteCheckFailed })

	// The next connect that gets past its refusals clears the record.
	_ = ClearRoute()
	if sb := diagBlob(t)["switch_back"].(map[string]any); sb["failed_route"] != "" {
		t.Fatalf("switch_back after a disconnect: %v", sb)
	}
}

// The way back fails too: nothing is connected, and the failure shown
// is the switch's.
func TestSetRoute_FailedSwitchAndFailedWayBack(t *testing.T) {
	rig := newAutoRig(t, autoFourRoutes)
	if err := SetRoute("r1"); err != nil {
		t.Fatal(err)
	}
	rig.fail("r2", resetHello())
	rig.fail("r1", deadSYN())
	if err := SetRoute("r2"); !errors.Is(err, ErrRouteNotCarrying) {
		t.Fatalf("SetRoute(r2) = %v", err)
	}
	blob := diagBlob(t)
	if blob["active_route"] != "" || blob["route_check"] != RouteCheckFailed || blob["route_running"] != false ||
		blob["route_check_category"] != "tls_sni_or_cert_block_suspected" {
		t.Fatalf("active=%v check=%v/%v running=%v", blob["active_route"], blob["route_check"], blob["route_check_category"], blob["route_running"])
	}
	sb := blob["switch_back"].(map[string]any)
	if sb["failed_route"] != "r2" || sb["restored_route"] != "r1" || sb["restored"] != false {
		t.Fatalf("switch_back = %v", sb)
	}
}

// A first connect that fails (nothing was carrying before) is what it
// always was: no way back to take, nothing reported.
func TestSetRoute_FailedFirstConnectHasNoWayBack(t *testing.T) {
	rig := newAutoRig(t, autoFourRoutes)
	rig.fail("r2", deadSYN())
	if err := SetRoute("r2"); err == nil {
		t.Fatal("SetRoute succeeded")
	}
	blob := diagBlob(t)
	if sb := blob["switch_back"].(map[string]any); sb["failed_route"] != "" || blob["active_route"] != "" {
		t.Fatalf("switch_back=%v active=%v", sb, blob["active_route"])
	}
	if got := rig.provedRoutes(); !eq(got, []string{"r2"}) {
		t.Fatalf("checked %v", got)
	}
}

func TestConnectAuto_NotInitialised(t *testing.T) {
	_ = Shutdown()
	if _, err := ConnectAuto(); err == nil {
		t.Fatal("ConnectAuto without Init returned no error")
	}
}

var _ = netmem.SentinelUnset
