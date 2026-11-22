package abi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"daal/core/engine"
	"daal/core/netmem"
)

// The survey (survey.go): the other routes of the file, checked beside
// the tunnel. raceRoutes: r1 vless-reality, r2 websocket-tls, r3 naive
// (never raced, but surveyed: engine.SurveyProbeable), r4 / r5
// hysteria2. withWireGuard adds r6, which nothing may side-probe.

// surveyRig: the waits shortened (the background survey's to `gap`),
// connected automatically on r1, side limits cleared.
func surveyRig(t *testing.T, gap time.Duration) *raceRig {
	t.Helper()
	setClock(t, time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC))
	shortSurveyWaits(t, gap)
	rig := newRaceRig(t, raceRoutes)
	fastRecheck(rig.c)
	return rig
}

// withWireGuard adds r6 (wireguard: an endpoint, never side-probed) and
// opens the experimental gate so the automatic connect would try it.
func withWireGuard(t *testing.T, rig *raceRig) {
	t.Helper()
	seedAutoRoute(t, rig.c, "r6", "wireguard",
		`{"type":"wireguard","address":["10.0.0.2/32"],"private_key":"a","peers":[{"address":"vpn.example","port":51820,"public_key":"b","allowed_ips":["0.0.0.0/0"]}]}`)
	rig.c.mu.Lock()
	rig.c.experimentalFamiliesEnabled = true
	rig.c.mu.Unlock()
}

func shortSurveyWaits(t *testing.T, gap time.Duration) {
	t.Helper()
	orig := surveyWaits.Load()
	surveyWaits.Store(&surveyWaitSet{
		first: func() time.Duration { return gap },
		gap:   func() time.Duration { return gap },
		user:  func() time.Duration { return 5 * time.Millisecond },
	})
	t.Cleanup(func() { surveyWaits.Store(orig) })
}

// connectOnR1: an automatic connect that carries on r1 at once (inside
// the pair's delay, so its partner is never sent), side limits cleared
// so the survey starts with the whole allowance.
func connectOnR1(t *testing.T, rig *raceRig) {
	t.Helper()
	orig := raceDelay
	raceDelay = func() time.Duration { return 200 * time.Millisecond }
	res := rig.connectAuto()
	raceDelay = orig
	if !res.Connected || res.RouteID != "r1" {
		t.Fatalf("premise: got %+v", res)
	}
	rig.c.mu.Lock()
	rig.c.side = sideLimits{}
	rig.c.mu.Unlock()
}

func surveyBlock(t *testing.T) map[string]any {
	t.Helper()
	body, err := SurveyRoutes(false)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func surveyOver(t *testing.T) map[string]any {
	t.Helper()
	var b map[string]any
	waitFor(t, "the survey to be over", func() bool {
		b = surveyBlock(t)
		return b["state"] == SurveyDone || b["state"] == SurveyStopped
	})
	return b
}

func surveyResults(b map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, x := range b["results"].([]any) {
		m := x.(map[string]any)
		out[m["route_id"].(string)] = m
	}
	return out
}

// startBackgroundSurvey starts a background survey as a connect does.
func startBackgroundSurvey(rig *raceRig) {
	rig.c.mu.Lock()
	rig.c.side = sideLimits{}
	rig.c.startSurveyLocked(context.Background(), false)
	rig.c.mu.Unlock()
}

func routeRow(t *testing.T, id string) map[string]any {
	t.Helper()
	body, err := AvailableRoutes()
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Routes []map[string]any `json:"routes"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	for _, r := range out.Routes {
		if r["route_id"] == id {
			return r
		}
	}
	t.Fatalf("%s not in the route list", id)
	return nil
}

// After a connect, every other route that can be side-probed is checked
// — ONE at a time, each a gap after the last — and the tunnel is never
// touched: no instance started, no route switched, even when another
// route proves much faster than the one connected.
func TestSurvey_ChecksTheOthersOneAtATimeAndNeverSwitches(t *testing.T) {
	const gap = 60 * time.Millisecond
	rig := surveyRig(t, gap)
	withWireGuard(t, rig)
	lc := captureLog(t)
	rig.sideIn("r2", 300*time.Millisecond)
	rig.sideIn("r4", 100*time.Millisecond) // far faster than r1
	rig.sideIn("r5", 900*time.Millisecond)
	connectOnR1(t, rig)
	before := len(rig.sideProbed())
	rig.peak.Store(0)
	starts := rig.starts.Load()

	b := surveyOver(t)
	if b["state"] != SurveyDone || b["trigger"] != "auto" {
		t.Fatalf("survey block: %v", b)
	}
	probed := rig.sideProbed()[before:]
	if !sameSet(probed, "r2", "r3", "r4", "r5") {
		t.Fatalf("surveyed %v; want r2..r5 (not r1: in use; not r6: wireguard)", probed)
	}
	if p := rig.peak.Load(); p != 1 {
		t.Fatalf("%d side probes in flight at once; the background survey checks one at a time", p)
	}
	rig.smu.Lock()
	ev := append([]sideEvent(nil), rig.events[before:]...)
	rig.smu.Unlock()
	for i := 1; i < len(ev); i++ {
		if d := ev[i].start.Sub(ev[i-1].start); d < gap-5*time.Millisecond {
			t.Fatalf("%s started %s after %s; the gap is %s", ev[i].route, d, ev[i-1].route, gap)
		}
	}
	if r, _ := rig.c.activeRouteFromMemory(); r != "r1" {
		t.Fatalf("the survey moved the tunnel to %s", r)
	}
	if got := rig.starts.Load(); got != starts {
		t.Fatalf("the tunnel's instance was started %d more time(s) by the survey", got-starts)
	}
	if st, _ := rig.c.check.get(); st != RouteCheckOK {
		t.Fatalf("the running route's check is %q", st)
	}
	res := surveyResults(b)
	if res["r6"]["result"] != SurveyResultWhenUsed || res["r3"]["result"] != SurveyResultCarried || res["r2"]["result"] != SurveyResultCarried || res["r2"]["setup_ms"] != float64(300) {
		t.Fatalf("results: %v", res)
	}
	if _, ok := res["r1"]; ok {
		t.Fatalf("the route in use was surveyed: %v", res["r1"])
	}
	for _, want := range []string{"survey start trigger=auto", "survey try route=r2 family=websocket-tls index=1 total=4",
		"survey result route=r2 result=carried", "survey try route=r3 family=naive", "survey done trigger=auto checked=4"} {
		if !lc.has(want) {
			t.Fatalf("no %q in the log: %v", want, lc.all())
		}
	}
	for _, l := range lc.all() {
		if strings.Contains(l, "survey") && strings.Contains(l, "relay-a.example") {
			t.Fatalf("an address in a survey line: %s", l)
		}
	}
}

// A route with a fresh result on this network is not checked again by
// the background survey; one with only an old result is.
func TestSurvey_SkipsRoutesWithAFreshResult(t *testing.T) {
	rig := surveyRig(t, 5*time.Millisecond)
	connectOnR1(t, rig)
	surveyOver(t)
	before := len(rig.sideProbed())

	// Thirty minutes on: everything is fresh.
	clockOverride.Store(nowUTC().Add(30 * time.Minute).Unix())
	startBackgroundSurvey(rig)
	b := surveyOver(t)
	if got := rig.sideProbed()[before:]; len(got) != 0 {
		t.Fatalf("fresh routes checked again: %v", got)
	}
	if r := surveyResults(b)["r2"]; r["result"] != SurveyResultSkipped || r["reason"] != SurveySkipFresh {
		t.Fatalf("r2: %v", r)
	}
	// Three hours on: nothing is.
	clockOverride.Store(nowUTC().Add(3 * time.Hour).Unix())
	startBackgroundSurvey(rig)
	surveyOver(t)
	if got := rig.sideProbed()[before:]; !sameSet(got, "r2", "r3", "r4", "r5") {
		t.Fatalf("after three hours surveyed %v", got)
	}
}

// The hourly allowance: a background survey leaves surveyReserve of it
// to the passes, and what does not fit is skipped, not queued for later
// in a burst.
func TestSurvey_StaysInsideTheHourlyAllowance(t *testing.T) {
	rig := surveyRig(t, 5*time.Millisecond)
	shortSurveyWaits(t, time.Hour) // hold the first check until the limits are set
	connectOnR1(t, rig)
	shortSurveyWaits(t, 5*time.Millisecond)
	rig.c.mu.Lock()
	// Room for exactly one survey probe above the reserve.
	used := sideProbesPerHour - surveyReserve - 1
	for i := 0; i < used; i++ {
		rig.c.sideNoteLocked("x")
	}
	rig.c.startSurveyLocked(context.Background(), false)
	rig.c.mu.Unlock()
	before := sideTotal(rig)

	b := surveyOver(t)
	if n := sideTotal(rig) - before; n != 1 {
		t.Fatalf("%d survey probe(s) with room for one", n)
	}
	budget := 0
	for _, r := range surveyResults(b) {
		if r["reason"] == SurveySkipBudget {
			budget++
		}
	}
	if budget != 3 {
		t.Fatalf("%d route(s) skipped for the allowance, want 3: %v", budget, b["results"])
	}
	rig.c.mu.Lock()
	left := sideProbesPerHour - len(rig.c.side.perNet[activeNetworkID()])
	rig.c.mu.Unlock()
	if left != surveyReserve {
		t.Fatalf("the survey left %d of the allowance, want the reserve (%d)", left, surveyReserve)
	}
	// The pacing (survey.go WHY THESE WAITS): never a burst, and the
	// other three routes of a default relay known within two minutes.
	if surveyReserve < raceMaxInFlight || surveyFirstMin < 10*time.Second || surveyGapMin < 10*time.Second ||
		surveyFirstMax+3*surveyGapMax > 2*time.Minute {
		t.Fatalf("constants: reserve %d, first %s, gap %s..%s", surveyReserve, surveyFirstMin, surveyGapMin, surveyGapMax)
	}
}

// Metered: the background survey checks each route ONCE per network per
// 24 h there — and on an unmetered network, again whenever its result
// is no longer fresh.
func TestSurvey_MeteredOncePerRoutePerDay(t *testing.T) {
	rig := surveyRig(t, 5*time.Millisecond)
	facts(t, NetKindCellular, "operator-1", 1, 1)
	connectOnR1(t, rig)
	b := surveyOver(t)
	first := rig.sideProbed()
	if r := surveyResults(b)["r2"]; r["result"] != SurveyResultCarried {
		t.Fatalf("a metered network got no survey at all: %v", b["results"])
	}
	n := len(first)

	// Two hours on: not fresh, but checked by the survey today.
	clockOverride.Store(nowUTC().Add(2 * time.Hour).Unix())
	startBackgroundSurvey(rig)
	b = surveyOver(t)
	if got := rig.sideProbed()[n:]; len(got) != 0 {
		t.Fatalf("checked again on a metered network the same day: %v", got)
	}
	if r := surveyResults(b)["r4"]; r["reason"] != SurveySkipMetered {
		t.Fatalf("r4: %v", r)
	}
	// After a restart the in-memory note is gone; this network's memory
	// still holds today's result, and that is enough.
	rig.c.survey.mu.Lock()
	rig.c.survey.metered = nil
	rig.c.survey.mu.Unlock()
	startBackgroundSurvey(rig)
	surveyOver(t)
	if got := rig.sideProbed()[n:]; len(got) != 0 {
		t.Fatalf("checked again after the note was forgotten: %v", got)
	}

	// The same network, unmetered: checked.
	facts(t, NetKindCellular, "operator-1", 1, 0)
	startBackgroundSurvey(rig)
	surveyOver(t)
	if got := rig.sideProbed()[n:]; !sameSet(got, "r2", "r3", "r4", "r5") {
		t.Fatalf("unmetered, two hours on: surveyed %v", got)
	}
	n = len(rig.sideProbed())

	// Metered again, a day later: once more.
	facts(t, NetKindCellular, "operator-1", 1, 1)
	clockOverride.Store(nowUTC().Add(25 * time.Hour).Unix())
	startBackgroundSurvey(rig)
	surveyOver(t)
	if got := rig.sideProbed()[n:]; !sameSet(got, "r2", "r3", "r4", "r5") {
		t.Fatalf("metered, a day later: surveyed %v", got)
	}
}

// The survey ends with the tunnel: a disconnect stops the probe in
// flight at once and nothing more is sent or recorded. A network change
// ends it too.
func TestSurvey_StopsWithTheTunnelAndOnANetworkChange(t *testing.T) {
	t.Run("disconnect", func(t *testing.T) {
		rig := surveyRig(t, 5*time.Millisecond)
		rig.sideHang("r2")
		connectOnR1(t, rig)
		waitFor(t, "the survey to be checking r2", func() bool { return rig.stub.SideProbesInFlight() == 1 })
		before := len(rig.sideProbed())
		if err := ClearRoute(); err != nil {
			t.Fatal(err)
		}
		waitFor(t, "the probe in flight to be stopped", func() bool { return rig.stub.SideProbesInFlight() == 0 })
		b := surveyOver(t)
		if b["state"] != SurveyStopped || b["stop_reason"] != "tunnel" {
			t.Fatalf("survey block: %v", b)
		}
		time.Sleep(60 * time.Millisecond)
		if got := rig.sideProbed()[before:]; len(got) != 0 {
			t.Fatalf("probed after the disconnect: %v", got)
		}
		if _, ok := rig.c.routeMemory()["r2"]; ok {
			t.Fatal("the stopped probe was remembered")
		}
		if r := surveyResults(b)["r2"]; r["result"] != SurveyResultCancelled {
			t.Fatalf("r2: %v", r)
		}
	})
	t.Run("network change", func(t *testing.T) {
		rig := surveyRig(t, 5*time.Millisecond)
		rig.sideHang("r2")
		connectOnR1(t, rig)
		waitFor(t, "the survey to be checking r2", func() bool { return rig.stub.SideProbesInFlight() == 1 })
		facts(t, NetKindWiFi, "home", 1, 0)
		b := surveyOver(t)
		if b["state"] != SurveyStopped || b["stop_reason"] != "network" {
			t.Fatalf("survey block: %v", b)
		}
		waitFor(t, "the probe in flight to be stopped", func() bool { return rig.stub.SideProbesInFlight() == 0 })
		if r, _ := rig.c.activeRouteFromMemory(); r != "r1" {
			t.Fatalf("the network change through the survey moved the tunnel to %q", r)
		}
	})
	t.Run("shutdown", func(t *testing.T) {
		rig := surveyRig(t, 5*time.Millisecond)
		rig.sideHang("r2")
		connectOnR1(t, rig)
		waitFor(t, "the survey to be checking r2", func() bool { return rig.stub.SideProbesInFlight() == 1 })
		c := rig.c
		if err := Shutdown(); err != nil {
			t.Fatal(err)
		}
		if n := rig.stub.SideProbesInFlight(); n != 0 {
			t.Fatalf("%d side probes in flight after Shutdown", n)
		}
		if b := c.survey.block(); b["state"] != SurveyStopped {
			// finishSurvey may not have run yet; it must, promptly.
			waitFor(t, "the survey to have stopped", func() bool { return c.survey.block()["state"] == SurveyStopped })
		}
	})
}

// What a survey finds is what the route list shows: a success fills the
// score (health_pct, proven) and this network's grade exactly as a
// connect would; a failure that answered shows as failing here; a route
// that cannot be side-probed says it is checked when used.
func TestSurvey_ResultsReachTheRouteList(t *testing.T) {
	rig := surveyRig(t, 5*time.Millisecond)
	withWireGuard(t, rig)
	rig.sideIn("r2", 400*time.Millisecond)
	rig.sideFail("r4", answeredReset())
	connectOnR1(t, rig)
	if r := routeRow(t, "r2"); r["health_pct"] != nil || r["proven"] != false {
		t.Fatalf("premise: r2 has a score before the survey: %v", r)
	}
	seq := surveyBlock(t)["seq"].(float64)
	surveyOver(t)

	r2 := routeRow(t, "r2")
	m := r2["measured"].(map[string]any)
	if r2["health_pct"] != float64(100) || r2["proven"] != true || m["grade"] != netmem.GradeGood || m["setup_ms"] != float64(400) || m["carried"] != float64(1) {
		t.Fatalf("r2 after a survey success: %v", r2)
	}
	r4 := routeRow(t, "r4")
	if r4["measured"].(map[string]any)["grade"] != netmem.GradeFailing || r4["health_pct"] != nil {
		t.Fatalf("r4 after an answered survey failure: %v", r4)
	}
	if r6 := routeRow(t, "r6"); r6["checked_when_used"] != true || r6["health_pct"] != nil {
		t.Fatalf("r6 (wireguard): %v", r6)
	}
	if r3 := routeRow(t, "r3"); r3["health_pct"] != float64(100) {
		t.Fatalf("r3 (naive, surveyed): %v", r3)
	}
	for _, id := range []string{"r1", "r2", "r3", "r4", "r5"} {
		if routeRow(t, id)["checked_when_used"] != false {
			t.Fatalf("%s is side-probeable, yet listed as checked when used", id)
		}
	}
	if got := surveyBlock(t)["seq"].(float64); got < seq+4 {
		t.Fatalf("seq moved %v → %v for four results; a page re-reads the list on it", seq, got)
	}
	// The same as a connect would have written for r2.
	row, _ := rig.c.store.GetRoute("r2")
	if row.LastSuccessBucket == "" || row.ConsecutiveFailures != 0 {
		t.Fatalf("r2's route store row: %+v", row)
	}
}

// A failed survey is not a failed connect: nothing cools down, nothing
// is charged to the family, no durable failure row — an answered failure
// is remembered for this network, a silent one is not.
func TestSurvey_FailuresDoNotCoolDown(t *testing.T) {
	rig := surveyRig(t, 5*time.Millisecond)
	rig.sideFail("r2", answeredReset())
	rig.sideFail("r4", deadSYN())
	rig.sideSet("r5", func(context.Context) (engine.ProofResult, error) {
		return engine.ProofResult{}, errFakeStart
	})
	connectOnR1(t, rig)
	b := surveyOver(t)
	res := surveyResults(b)
	if res["r2"]["result"] != SurveyResultNotCarrying || res["r4"]["result"] != SurveyResultNotCarrying || res["r5"]["result"] != SurveyResultStartFailed {
		t.Fatalf("results: %v", res)
	}
	for _, x := range [][2]string{{"r2", "websocket-tls"}, {"r4", "hysteria2"}, {"r5", "hysteria2"}} {
		if ok, why := rig.c.pm.CanAttempt(x[0], x[1]); !ok {
			t.Fatalf("%s is cooling down after a survey failure: %s", x[0], why)
		}
		row, _ := rig.c.store.GetRoute(x[0])
		if row.LastFailureBucket != "" || row.ConsecutiveFailures != 0 || row.CooldownUntil != "" {
			t.Fatalf("%s got a durable failure row: %+v", x[0], row)
		}
	}
	for _, h := range rig.c.pm.RouteHealth() {
		if h.RouteID != "r1" {
			t.Fatalf("the path manager learned of %s from the survey: %+v", h.RouteID, h)
		}
	}
	mem := rig.c.routeMemory()
	if m, ok := mem["r2"]; !ok || m.FailedCategory == "" {
		t.Fatalf("an answered failure is remembered for this network: %+v", m)
	}
	for _, id := range []string{"r4", "r5"} {
		if m, ok := mem[id]; ok {
			t.Fatalf("%s (silent / no instance) was remembered: %+v", id, m)
		}
	}
	// The automatic connect still has every route to try.
	rig.c.mu.Lock()
	cands, _, _, _ := rig.c.autoCandidatesLocked("")
	rig.c.mu.Unlock()
	if len(cands) != 5 {
		t.Fatalf("%d candidates after the survey, want all 5", len(cands))
	}
}

// The person's button: the same survey now, two at a time (never the
// same address and port), metered allowed, with nothing connected too —
// and it starts nothing of the tunnel's.
func TestSurvey_TheButtonChecksAllInPairs(t *testing.T) {
	rig := surveyRig(t, time.Hour) // no background survey in the way
	facts(t, NetKindCellular, "operator-1", 1, 1)
	release := make(chan struct{})
	for _, id := range []string{"r1", "r2", "r3", "r4", "r5"} {
		rig.sideSet(id, func(ctx context.Context) (engine.ProofResult, error) {
			select {
			case <-release:
			case <-ctx.Done():
			}
			return engine.ProofResult{OK: true, Attempts: 1, Elapsed: 200 * time.Millisecond}, nil
		})
	}
	body, err := SurveyRoutes(true)
	if err != nil {
		t.Fatal(err)
	}
	var first map[string]any
	_ = json.Unmarshal([]byte(body), &first)
	if first["started"] != true || first["refused"] != "" || first["trigger"] != "user" {
		t.Fatalf("start: %v", first)
	}
	waitFor(t, "a pair in flight", func() bool { return rig.stub.SideProbesInFlight() == 2 })
	b := surveyBlock(t)
	if b["state"] != SurveyChecking || len(b["checking"].([]any)) != 2 || b["total"] != float64(5) {
		t.Fatalf("while checking: %v", b)
	}
	again, _ := SurveyRoutes(true)
	if !strings.Contains(again, `"refused":"running"`) || !strings.Contains(again, `"started":false`) {
		t.Fatalf("a second press: %s", again)
	}
	close(release)
	b = surveyOver(t)
	if b["state"] != SurveyDone {
		t.Fatalf("survey block: %v", b)
	}
	if p := rig.peak.Load(); p != 2 {
		t.Fatalf("peak %d in flight; the button checks two at a time", p)
	}
	probed := rig.sideProbed()
	if !sameSet(probed, "r1", "r2", "r3", "r4", "r5") {
		t.Fatalf("checked %v", probed)
	}
	// r1 / r2 share relay-a; never as a pair with the same port (they
	// differ: 443 / 8443), and the pair is of two transport kinds.
	if !eq(probed[:2], []string{"r1", "r4"}) {
		t.Fatalf("first pair %v; r1 goes with the other kind on another port (r4)", probed[:2])
	}
	if rig.starts.Load() != 0 {
		t.Fatalf("the tunnel's instance was started %d time(s) by the button", rig.starts.Load())
	}
	if r, _ := rig.c.activeRouteFromMemory(); r != "" {
		t.Fatalf("the button connected %s", r)
	}
	res := surveyResults(b)
	for _, id := range []string{"r1", "r2", "r3", "r4", "r5"} {
		if res[id]["result"] != SurveyResultCarried {
			t.Fatalf("%s: %v", id, res[id])
		}
	}
	// The per-route gap still applies to a press right after.
	SurveyRoutes(true)
	b = surveyOver(t)
	if got := rig.sideProbed(); len(got) != 5 {
		t.Fatalf("a press inside the per-route gap probed %v", got[5:])
	}
	if r := surveyResults(b)["r2"]; r["reason"] != SurveySkipRecent {
		t.Fatalf("r2 on a second press: %v", r)
	}
}

// A connect while the button's survey runs takes the engine: the survey
// ends at once.
func TestSurvey_TheButtonEndsWhenAConnectTakesTheEngine(t *testing.T) {
	rig := surveyRig(t, time.Hour)
	rig.sideHang("r1")
	rig.sideHang("r4")
	SurveyRoutes(true)
	rig.c.survey.mu.Lock()
	run := rig.c.survey.last
	rig.c.survey.mu.Unlock()
	waitFor(t, "a pair in flight", func() bool { return rig.stub.SideProbesInFlight() == 2 })
	if err := SetRoute("r2"); err != nil {
		t.Fatal(err)
	}
	// (The connect starts a background survey of its own; the button's
	// is the one asked about.)
	waitFor(t, "the button's survey to have stopped", func() bool {
		rig.c.survey.mu.Lock()
		defer rig.c.survey.mu.Unlock()
		return run.state == SurveyStopped
	})
	waitFor(t, "the pair to be stopped", func() bool { return rig.stub.SideProbesInFlight() == 0 })
	if r, _ := rig.c.activeRouteFromMemory(); r != "r2" {
		t.Fatalf("connected on %q", r)
	}
}

// sameSet: got holds exactly the routes want, once each, in any order
// (a later survey goes in the order of this network's memory).
func sameSet(got []string, want ...string) bool {
	if len(got) != len(want) {
		return false
	}
	seen := map[string]int{}
	for _, g := range got {
		seen[g]++
	}
	for _, w := range want {
		if seen[w] != 1 {
			return false
		}
	}
	return true
}

var errFakeStart = errFake("engine: side instance: start outbound: boom")

type errFake string

func (e errFake) Error() string { return string(e) }
