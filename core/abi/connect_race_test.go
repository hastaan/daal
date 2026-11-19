package abi

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"daal/core/diagnostics"
	"daal/core/engine"
	"daal/core/netmem"
)

// Racing (connect_race.go). The Stub answers side probes from a script
// keyed by route, exactly as autoRig scripts the tunnel instance's own
// checks; a route's SIDE result and its MAIN result are scripted apart,
// because the hand-over proves the winner a second time.

// Five routes, two servers. r3 (naive) can never be side-probed.
var raceRoutes = [][3]string{
	{"r1", "vless-reality", `{"type":"vless","server":"relay-a.example","server_port":443,"tls":{"enabled":true,"server_name":"cover.example"}}`},
	{"r2", "websocket-tls", `{"type":"vless","server":"relay-a.example","server_port":8443,"tls":{"enabled":true,"server_name":"own.example"}}`},
	{"r3", "naive", `{"type":"naive","server":"relay-a.example","server_port":9443}`},
	{"r4", "hysteria2", `{"type":"hysteria2","server":"relay-a.example","server_port":8444,"tls":{"enabled":true,"server_name":"own.example"}}`},
	{"r5", "hysteria2", `{"type":"hysteria2","server":"relay-b.example","server_port":443,"tls":{"enabled":true,"server_name":"own.example"}}`},
}

type sideEvent struct {
	route string
	start time.Time
}

type raceRig struct {
	*autoRig
	byEndpoint map[string]string

	smu      sync.Mutex
	side     map[string]func(ctx context.Context) (engine.ProofResult, error)
	events   []sideEvent
	inFlight atomic.Int32
	peak     atomic.Int32
	starts   atomic.Int32 // Starts of the TUNNEL's instance
}

func endpointKey(typ, server string, port any) string {
	return fmt.Sprintf("%s:%s:%v", typ, server, port)
}

func newRaceRigIn(t *testing.T, dir string, routes [][3]string) *raceRig {
	t.Helper()
	orig := raceDelay
	raceDelay = func() time.Duration { return 2 * time.Millisecond }
	t.Cleanup(func() { raceDelay = orig })
	r := &raceRig{autoRig: newAutoRigIn(t, dir, routes), byEndpoint: map[string]string{},
		side: map[string]func(context.Context) (engine.ProofResult, error){}}
	for _, rt := range routes {
		var p struct {
			Type   string `json:"type"`
			Server string `json:"server"`
			Port   int    `json:"server_port"`
		}
		_ = json.Unmarshal([]byte(rt[2]), &p)
		r.byEndpoint[endpointKey(p.Type, p.Server, p.Port)] = rt[0]
	}
	r.stub.SetStartHook(func() { r.starts.Add(1) })
	r.stub.SetSideProbeHook(func(ctx context.Context, cfg []byte, _ engine.ProofConfig) (engine.ProofResult, error) {
		id := r.routeOf(cfg)
		n := r.inFlight.Add(1)
		for {
			p := r.peak.Load()
			if n <= p || r.peak.CompareAndSwap(p, n) {
				break
			}
		}
		defer r.inFlight.Add(-1)
		r.smu.Lock()
		r.events = append(r.events, sideEvent{id, time.Now()})
		f := r.side[id]
		r.smu.Unlock()
		if f == nil {
			return engine.ProofResult{OK: true, Attempts: 1}, nil
		}
		return f(ctx)
	})
	return r
}

func newRaceRig(t *testing.T, routes [][3]string) *raceRig {
	return newRaceRigIn(t, t.TempDir(), routes)
}

func (r *raceRig) routeOf(cfg []byte) string {
	var raw struct {
		Outbounds []map[string]any `json:"outbounds"`
		Inbounds  []any            `json:"inbounds"`
	}
	_ = json.Unmarshal(cfg, &raw)
	for _, ob := range raw.Outbounds {
		if ob["tag"] == "active" {
			return r.byEndpoint[endpointKey(ob["type"].(string), ob["server"].(string), ob["server_port"])]
		}
	}
	return ""
}

func (r *raceRig) sideSet(id string, f func(ctx context.Context) (engine.ProofResult, error)) {
	r.smu.Lock()
	r.side[id] = f
	r.smu.Unlock()
}

func (r *raceRig) sideFail(id string, res engine.ProofResult) {
	r.sideSet(id, func(context.Context) (engine.ProofResult, error) { return res, nil })
}

// sideHang: the probe gets no answer until it is stopped.
func (r *raceRig) sideHang(id string) {
	r.sideSet(id, func(ctx context.Context) (engine.ProofResult, error) {
		<-ctx.Done()
		return engine.ProofResult{}, nil
	})
}

func (r *raceRig) sideIn(id string, d time.Duration) {
	r.sideSet(id, func(context.Context) (engine.ProofResult, error) {
		return engine.ProofResult{OK: true, Attempts: 1, Elapsed: d}, nil
	})
}

func (r *raceRig) sideProbed() []string {
	r.smu.Lock()
	defer r.smu.Unlock()
	out := []string{}
	for _, e := range r.events {
		out = append(out, e.route)
	}
	return out
}

func triedOf(tried []AutoTried, id string) []AutoTried {
	var out []AutoTried
	for _, tr := range tried {
		if tr.RouteID == id {
			out = append(out, tr)
		}
	}
	return out
}

// The order the pass tries a fresh network in (the ranking's), so the
// tests below do not have to guess it.
func (r *raceRig) order() []string {
	r.c.mu.Lock()
	defer r.c.mu.Unlock()
	cands, _, _, err := r.c.autoCandidatesLocked("")
	if err != nil {
		r.t.Fatal(err)
	}
	out := []string{}
	for _, cd := range cands {
		out = append(out, cd.routeID)
	}
	return out
}

// THE point of the wave: two candidates are checked beside each other,
// the one that proves first becomes the tunnel's route, and the other
// is stopped — having cost the person nothing and recorded nothing.
func TestRace_TheFirstOfTwoToProveWinsAndTheOtherIsStopped(t *testing.T) {
	rig := newRaceRig(t, raceRoutes)
	if got := rig.order(); !eq(got[:2], []string{"r1", "r2"}) {
		t.Fatalf("premise: the pass starts with %v", got)
	}
	// r1 is dead in the slow way; its partner answers.
	rig.sideHang("r1")
	lc := captureLog(t)
	t0 := time.Now()
	res := rig.connectAuto()
	if !res.Connected || res.Candidates != 5 {
		t.Fatalf("got %+v", res)
	}
	partner := res.RouteID
	if partner != "r4" {
		t.Fatalf("connected on %s; r1 is raced with r4 (the other kind, another port)", partner)
	}
	if d := time.Since(t0); d > 2*time.Second {
		t.Fatalf("the pass took %s: it waited for the dead route", d)
	}
	if got := rig.provedRoutes(); !eq(got, []string{partner}) {
		t.Fatalf("the tunnel's instance was started for %v; only the winner may be", got)
	}
	if got := rig.sideProbed(); len(got) != 2 || got[0] != "r1" || got[1] != partner {
		t.Fatalf("side-probed %v", got)
	}
	win := triedOf(res.Tried, partner)
	if len(win) != 1 || win[0].Result != AutoResultCarried || win[0].RacedWith != "r1" {
		t.Fatalf("the winner's entry: %+v", win)
	}
	lost := triedOf(res.Tried, "r1")
	if len(lost) != 1 || lost[0].Result != AutoResultStopped || lost[0].RacedWith != partner || lost[0].Category != "" {
		t.Fatalf("the stopped route's entry: %+v", lost)
	}
	if res.Verdict != AutoVerdictNone {
		t.Fatalf("verdict %q: a probe that was stopped is not a route that did not carry", res.Verdict)
	}
	// Nothing was learned about r1: not cooled, not remembered.
	if ok, why := rig.c.pm.CanAttempt("r1", "vless-reality"); !ok {
		t.Fatalf("the stopped route is cooling down: %s", why)
	}
	if m, ok := rig.c.routeMemory()["r1"]; ok {
		t.Fatalf("the stopped route was remembered: %+v", m)
	}
	if n := rig.stub.SideProbesInFlight(); n != 0 {
		t.Fatalf("%d side probes still in flight after the pass", n)
	}
	a := autoBlock(t)
	if a["state"] != AutoStateConnected || a["route_id"] != partner || len(a["racing"].([]any)) != 0 || a["trying"] != "" {
		t.Fatalf("auto block: %v", a)
	}
	if !lc.has("auto race first=r1 second="+partner) || !lc.has("auto race winner="+partner) {
		t.Fatalf("log: %v", lc.all())
	}
}

// While two are in flight the `auto` block says so, and `trying` stays
// the first of the pair for a page that knows nothing of racing.
func TestRace_TheBlockNamesBothWhileTheyAreInFlight(t *testing.T) {
	rig := newRaceRig(t, raceRoutes)
	release := make(chan struct{})
	for _, id := range []string{"r1", "r2", "r4", "r5"} {
		rig.sideSet(id, func(ctx context.Context) (engine.ProofResult, error) {
			select {
			case <-release:
			case <-ctx.Done():
			}
			return engine.ProofResult{OK: true, Attempts: 1}, nil
		})
	}
	done := make(chan AutoResult, 1)
	go func() { done <- rig.connectAuto() }()
	waitFor(t, "two probes in flight", func() bool { return rig.stub.SideProbesInFlight() == 2 })
	a := autoBlock(t)
	racing := a["racing"].([]any)
	if a["state"] != AutoStateTrying || len(racing) != 2 || racing[0] != "r1" || a["trying"] != "r1" || a["index"] != float64(1) || a["total"] != float64(5) {
		t.Fatalf("auto block during a race: %v", a)
	}
	close(release)
	res := <-done
	if !res.Connected {
		t.Fatalf("got %+v", res)
	}
}

// Never more than two in flight — counted by the test's own hook and by
// the driver — however many candidates there are; and every route is
// tried exactly once.
func TestRace_NeverMoreThanTwoInFlight(t *testing.T) {
	rig := newRaceRig(t, raceRoutes)
	for _, id := range []string{"r1", "r2", "r4", "r5"} {
		rig.sideSet(id, func(context.Context) (engine.ProofResult, error) {
			time.Sleep(30 * time.Millisecond)
			return answeredReset(), nil
		})
	}
	rig.fail("r3", answeredReset())
	res := rig.connectAuto()
	if res.Connected || res.Verdict == AutoVerdictCancelled {
		t.Fatalf("got %+v", res)
	}
	if p := rig.peak.Load(); p != 2 {
		t.Fatalf("peak side probes in flight = %d, want exactly 2", p)
	}
	if _, peak := rig.stub.SideProbeStats(); peak > raceMaxInFlight {
		t.Fatalf("the driver saw %d in flight", peak)
	}
	seen := map[string]int{}
	for _, tr := range res.Tried {
		seen[tr.RouteID]++
	}
	for _, rt := range raceRoutes {
		if seen[rt[0]] != 1 {
			t.Fatalf("route %s appears %d times in tried: %+v", rt[0], seen[rt[0]], res.Tried)
		}
	}
	if got := rig.provedRoutes(); !eq(got, []string{"r3"}) {
		t.Fatalf("the tunnel's instance was started for %v; only naive is tried that way", got)
	}
	if got := rig.sideProbed(); len(got) != 4 {
		t.Fatalf("side-probed %v", got)
	}
}

// Racing must not double-count: a route that failed in a side probe is
// cooled down like any failed candidate, charged once, and never starts
// its family's ladder.
func TestRace_AFailedProbeIsChargedOnceAndNeverStartsTheFamilyLadder(t *testing.T) {
	rig := newRaceRig(t, raceRoutes)
	for _, id := range []string{"r1", "r2", "r4", "r5"} {
		rig.sideFail(id, answeredReset())
	}
	rig.fail("r3", answeredReset())
	for pass := 0; pass < 3; pass++ {
		res := rig.connectAuto()
		if res.Connected {
			t.Fatalf("pass %d: %+v", pass, res)
		}
		clearCooldowns(rig.c)
		rig.c.mu.Lock()
		rig.c.side = sideLimits{}
		rig.c.mu.Unlock()
	}
	if sk := rig.c.pm.SkippedFamilies(); len(sk) != 0 {
		t.Fatalf("three failed passes rested whole families: %+v", sk)
	}
	row, err := rig.c.store.GetRoute("r1")
	if err != nil {
		t.Fatal(err)
	}
	if row.ConsecutiveFailures != 3 {
		t.Fatalf("r1 was charged %d failures for 3 passes", row.ConsecutiveFailures)
	}
	if m := rig.c.routeMemory()["r1"]; m.Failed != 3 {
		t.Fatalf("this network's memory counts %d failures of r1 for 3 passes", m.Failed)
	}
	// And one pass cools the route down, as a failed candidate always was.
	res := rig.connectAuto()
	if ok, _ := rig.c.pm.CanAttempt("r1", "vless-reality"); ok || res.Connected {
		t.Fatal("a route that answered and failed in a side probe is not cooling down")
	}
}

// The first slice's honesty rule holds for races: a pass in which
// nothing at all answered cools nothing down and writes nothing.
func TestRace_APassWhereNothingAnsweredCoolsNothingDown(t *testing.T) {
	rig := newRaceRig(t, raceRoutes)
	for _, id := range []string{"r1", "r2"} {
		rig.sideFail(id, deadSYN())
	}
	for _, id := range []string{"r4", "r5"} {
		rig.sideFail(id, silentUDP())
	}
	rig.fail("r3", deadSYN())
	res := rig.connectAuto()
	if res.Connected || len(triedIDs(res.Tried, AutoResultNotCarrying)) != 5 {
		t.Fatalf("got %+v", res)
	}
	for _, rt := range raceRoutes {
		if ok, why := rig.c.pm.CanAttempt(rt[0], rt[1]); !ok {
			t.Fatalf("%s is cooling down after a pass in which nothing answered: %s", rt[0], why)
		}
	}
	if mem := rig.c.routeMemory(); len(mem) != 0 {
		t.Fatalf("a silent pass was remembered: %+v", mem)
	}
	blob := diagBlob(t)
	if blob["route_check"] != RouteCheckFailed || blob["route_running"] != false {
		t.Fatalf("after a pass that only side-probed and failed the engine must still say the connect failed: check=%v running=%v",
			blob["route_check"], blob["route_running"])
	}
}

// The route that carried here last is tried ALONE: one connection, no
// burst. Only when it fails does the pass race the others.
func TestRace_TheRememberedRouteIsTriedAloneFirst(t *testing.T) {
	rig := newRaceRig(t, raceRoutes)
	rig.sideHang("r1")
	first := rig.connectAuto()
	if !first.Connected {
		t.Fatalf("got %+v", first)
	}
	home := first.RouteID
	if err := ClearRoute(); err != nil {
		t.Fatal(err)
	}
	sideBefore, _ := rig.stub.SideProbeStats()
	rig.mu.Lock()
	rig.proved = nil
	rig.mu.Unlock()

	res := rig.connectAuto()
	if !res.Connected || res.RouteID != home || res.Tried[0].Why != AutoWhyCarriedHere || res.Tried[0].RacedWith != "" {
		t.Fatalf("got %+v", res)
	}
	if n, _ := rig.stub.SideProbeStats(); n != sideBefore {
		t.Fatalf("%d side probes were made although the remembered route carried", n-sideBefore)
	}
	if got := rig.provedRoutes(); !eq(got, []string{home}) {
		t.Fatalf("checked %v", got)
	}

	// It has stopped working here: now the others are raced.
	if err := ClearRoute(); err != nil {
		t.Fatal(err)
	}
	rig.c.mu.Lock()
	rig.c.side = sideLimits{}
	rig.c.mu.Unlock()
	rig.fail(home, answeredReset())
	rig.sideSet("r1", nil)
	res = rig.connectAuto()
	if !res.Connected || res.RouteID == home {
		t.Fatalf("got %+v", res)
	}
	if res.Tried[0].RouteID != home || res.Tried[0].Result != AutoResultNotCarrying || res.Tried[0].RacedWith != "" {
		t.Fatalf("the remembered route must be tried first and alone: %+v", res.Tried)
	}
	if n, _ := rig.stub.SideProbeStats(); n == sideBefore {
		t.Fatal("after the remembered route failed nothing was raced")
	}
	if w := triedOf(res.Tried, res.RouteID); len(w) != 1 || w[0].RacedWith == "" {
		t.Fatalf("the winner was not raced: %+v", res.Tried)
	}
}

func cand(id string, udp bool, host string, port int, why string, side bool) autoCandidate {
	return autoCandidate{routeID: id, udp: udp, relayHost: host, relayPort: port, why: why, side: side}
}

// Which route is checked beside the first.
func TestPickRacePartner_Table(t *testing.T) {
	never := func(string) bool { return false }
	a := cand("a", false, "h1", 443, AutoWhyRanked, true)
	cases := []struct {
		name   string
		rest   []autoCandidate
		recent func(string) bool
		want   string
	}{
		{"same address and port is never raced, whatever its kind",
			[]autoCandidate{cand("b", true, "h1", 443, AutoWhyRanked, true)}, never, ""},
		{"the other kind on another port beats the same kind on another port",
			[]autoCandidate{cand("b", false, "h1", 8443, AutoWhyRanked, true), cand("c", true, "h1", 8444, AutoWhyRanked, true)}, never, "c"},
		{"the other kind on the same port number of another server beats the same kind on another port",
			[]autoCandidate{cand("b", false, "h1", 8443, AutoWhyRanked, true), cand("c", true, "h2", 443, AutoWhyRanked, true)}, never, "c"},
		{"equal scores: the earlier in the order",
			[]autoCandidate{cand("b", false, "h1", 8443, AutoWhyRanked, true), cand("c", false, "h1", 9443, AutoWhyRanked, true)}, never, "b"},
		{"a route that cannot be side-probed is skipped",
			[]autoCandidate{cand("b", true, "h1", 8444, AutoWhyRanked, false), cand("c", false, "h1", 8443, AutoWhyRanked, true)}, never, "c"},
		{"a route probed a moment ago is skipped",
			[]autoCandidate{cand("b", true, "h1", 8444, AutoWhyRanked, true), cand("c", false, "h1", 8443, AutoWhyRanked, true)},
			func(id string) bool { return id == "b" }, "c"},
		{"a route whose server is not known is skipped",
			[]autoCandidate{cand("b", true, "", 8444, AutoWhyRanked, true)}, never, ""},
		{"a route that failed here recently is not pulled ahead of one that did not",
			[]autoCandidate{cand("b", false, "h1", 8443, AutoWhyRanked, true), cand("c", true, "h1", 8444, AutoWhyFailedHere, true)}, never, "b"},
		{"…but it is raced when nothing else is left",
			[]autoCandidate{cand("c", true, "h1", 8444, AutoWhyFailedHere, true)}, never, "c"},
		{"nothing to race with", nil, never, ""},
	}
	for _, c := range cases {
		queue := append([]autoCandidate{a}, c.rest...)
		got := ""
		if j := pickRacePartner(queue, c.recent); j >= 0 {
			got = queue[j].routeID
		}
		if got != c.want {
			t.Errorf("%s: partner %q, want %q", c.name, got, c.want)
		}
	}
}

// End to end: of the routes left, the pass races a pair that looks
// different — r1 (a stream to :443) with a datagram route on another
// port — and never the naive route.
func TestRace_PairsDifferInKindAndPort(t *testing.T) {
	rig := newRaceRig(t, raceRoutes)
	for _, id := range []string{"r1", "r2", "r4", "r5"} {
		rig.sideFail(id, answeredReset())
	}
	rig.fail("r3", answeredReset())
	res := rig.connectAuto()
	pairs := map[string]string{}
	for _, tr := range res.Tried {
		pairs[tr.RouteID] = tr.RacedWith
	}
	if pairs["r1"] != "r4" || pairs["r4"] != "r1" {
		t.Fatalf("r1 (stream, :443) must be raced with r4 (datagram, :8444): %v", pairs)
	}
	if pairs["r2"] != "r5" || pairs["r5"] != "r2" {
		t.Fatalf("then r2 with r5: %v", pairs)
	}
	if pairs["r3"] != "" {
		t.Fatalf("naive was raced with %s", pairs["r3"])
	}
}

// The second probe of a pair starts after the delay, and the delay is
// drawn from the stated range.
func TestRace_TheSecondProbeStartsAfterARandomDelay(t *testing.T) {
	seen := map[time.Duration]bool{}
	orig := raceDelay
	for i := 0; i < 2000; i++ {
		d := orig()
		if d < raceDelayMin || d >= raceDelayMax {
			t.Fatalf("delay %s outside [%s, %s)", d, raceDelayMin, raceDelayMax)
		}
		seen[d/(10*time.Millisecond)] = true
	}
	if len(seen) < 10 {
		t.Fatalf("the delay takes only %d different values in 2000 draws", len(seen))
	}
	if raceDelayMin < 100*time.Millisecond || raceDelayMax > time.Second {
		t.Fatalf("range [%s, %s): a few hundred ms was agreed", raceDelayMin, raceDelayMax)
	}

	rig := newRaceRig(t, raceRoutes)
	raceDelay = func() time.Duration { return 120 * time.Millisecond }
	for _, id := range []string{"r1", "r4"} {
		rig.sideSet(id, func(context.Context) (engine.ProofResult, error) {
			time.Sleep(200 * time.Millisecond)
			return engine.ProofResult{OK: true, Attempts: 1}, nil
		})
	}
	if res := rig.connectAuto(); !res.Connected {
		t.Fatalf("got %+v", res)
	}
	rig.smu.Lock()
	ev := append([]sideEvent(nil), rig.events...)
	rig.smu.Unlock()
	if len(ev) != 2 {
		t.Fatalf("events: %+v", ev)
	}
	if gap := ev[1].start.Sub(ev[0].start); gap < 110*time.Millisecond {
		t.Fatalf("the second probe started %s after the first; the delay was 120 ms", gap)
	}
}

// A first probe that proves inside the delay means the second is never
// sent at all.
func TestRace_AWinnerInsideTheDelayMeansOneProbeOnly(t *testing.T) {
	rig := newRaceRig(t, raceRoutes)
	raceDelay = func() time.Duration { return 300 * time.Millisecond }
	res := rig.connectAuto()
	if !res.Connected || res.RouteID != "r1" {
		t.Fatalf("got %+v", res)
	}
	if got := rig.sideProbed(); !eq(got, []string{"r1"}) {
		t.Fatalf("side-probed %v; the partner must never have been sent", got)
	}
	if st := triedOf(res.Tried, "r4"); len(st) != 1 || st[0].Result != AutoResultStopped {
		t.Fatalf("the partner's entry: %+v", res.Tried)
	}
}

// Both prove: the first one wins, and the other's measurement is kept
// although it is not the route the tunnel runs on.
func TestRace_ALoserThatAlsoProvedIsMeasuredAndStopped(t *testing.T) {
	rig := newRaceRig(t, raceRoutes)
	r4done := make(chan struct{})
	rig.sideSet("r1", func(context.Context) (engine.ProofResult, error) {
		<-r4done
		time.Sleep(10 * time.Millisecond)
		return engine.ProofResult{OK: true, Attempts: 1, Elapsed: 900 * time.Millisecond}, nil
	})
	rig.sideSet("r4", func(context.Context) (engine.ProofResult, error) {
		defer close(r4done)
		return engine.ProofResult{OK: true, Attempts: 1, Elapsed: 300 * time.Millisecond}, nil
	})
	res := rig.connectAuto()
	if !res.Connected || res.RouteID != "r4" {
		t.Fatalf("got %+v", res)
	}
	l := triedOf(res.Tried, "r1")
	if len(l) != 1 || l[0].Result != AutoResultCarried || l[0].SetupMs != 900 || l[0].RacedWith != "r4" {
		t.Fatalf("the loser that proved: %+v", l)
	}
	if w := triedOf(res.Tried, "r4"); len(w) != 1 || w[0].SetupMs != 300 {
		t.Fatalf("the winner: %+v", w)
	}
	mem := rig.c.routeMemory()
	if m := mem["r1"].Measured(); m.Samples != 1 || m.SetupMs != 900 || m.Carried != 1 {
		t.Fatalf("the loser's measurement: %+v", m)
	}
	if m := mem["r4"].Measured(); m.Samples != 1 || m.SetupMs != 300 || m.Carried != 1 || m.Grade != netmem.GradeGood {
		t.Fatalf("the winner's measurement (one sample, not two — the hand-over is not a second one): %+v", m)
	}
	if got := rig.provedRoutes(); !eq(got, []string{"r4"}) {
		t.Fatalf("the tunnel's instance was started for %v", got)
	}
	if n := rig.stub.SideProbesInFlight(); n != 0 {
		t.Fatalf("%d still in flight", n)
	}
}

// The winner proved beside the tunnel and then not through it: it is
// charged once, with that failure; the probe that was stopped for its
// sake was never finished and is tried now — alone, it was just probed.
func TestRace_AWinnerWhoseHandOverFailsIsChargedOnce(t *testing.T) {
	rig := newRaceRig(t, raceRoutes)
	rig.sideHang("r4")
	rig.sideSet("r1", func(context.Context) (engine.ProofResult, error) {
		time.Sleep(40 * time.Millisecond) // r4's probe is in flight by now
		return engine.ProofResult{OK: true, Attempts: 1}, nil
	})
	rig.fail("r1", answeredReset())
	res := rig.connectAuto()
	if !res.Connected || res.RouteID != "r4" || res.Verdict != AutoVerdictMovedOn {
		t.Fatalf("got %+v", res)
	}
	w := triedOf(res.Tried, "r1")
	if len(w) != 1 || w[0].Result != AutoResultNotCarrying || w[0].RacedWith != "r4" {
		t.Fatalf("r1: %+v", w)
	}
	l := triedOf(res.Tried, "r4")
	if len(l) != 1 || l[0].Result != AutoResultCarried || l[0].RacedWith != "" {
		t.Fatalf("r4 must appear once, as the route that was then tried alone: %+v", res.Tried)
	}
	if got := rig.sideProbed(); !eq(got, []string{"r1", "r4"}) {
		t.Fatalf("side-probed %v: a route probed a moment ago must not be probed again", got)
	}
	if m := rig.c.routeMemory()["r1"]; m.Failed != 1 || m.Carried != 1 {
		t.Fatalf("r1's memory: %+v", m)
	}
}

// The hourly allowance and the per-route gap: when either is spent the
// pass goes on one route at a time — it is never refused.
func TestRace_LimitsFallBackToOneAtATime(t *testing.T) {
	if sideProbesPerHour < 4 || sideProbesPerHour > 30 || sideProbeRouteGap < time.Minute || sideProbeRouteGap > 10*time.Minute {
		t.Fatalf("limits: %d per hour, %s per route", sideProbesPerHour, sideProbeRouteGap)
	}
	at := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
	setClock(t, at)
	rig := newRaceRig(t, raceRoutes)
	rig.fail("r1", answeredReset())
	rig.fail("r4", answeredReset())

	// The allowance is all but spent: one probe left, a race needs two.
	rig.c.mu.Lock()
	rig.c.sideNoteLocked(make([]string, sideProbesPerHour-1)...)
	rig.c.mu.Unlock()
	res := rig.connectAuto()
	if !res.Connected || res.RouteID != "r2" {
		t.Fatalf("got %+v", res)
	}
	if n, _ := rig.stub.SideProbeStats(); n != 0 {
		t.Fatalf("%d side probes on a network whose allowance is spent", n)
	}
	if got := rig.provedRoutes(); !eq(got, []string{"r1", "r2"}) {
		t.Fatalf("checked %v; without racing the pass is the sequential one", got)
	}
	_ = ClearRoute()
	clearCooldowns(rig.c)

	// An hour later the allowance is back.
	clockOverride.Store(at.Add(61 * time.Minute).Unix())
	rig.fail("r2", answeredReset())
	rig.fail("r3", answeredReset())
	rig.carry("r1")
	rig.carry("r4")
	rig.sideHang("r1")
	res = rig.connectAuto()
	if n, _ := rig.stub.SideProbeStats(); n == 0 || !res.Connected {
		t.Fatalf("an hour later nothing was raced: %+v", res)
	}
	sideAfter, _ := rig.stub.SideProbeStats()
	raced := rig.sideProbed()
	_ = ClearRoute()
	clearCooldowns(rig.c)

	// Two minutes later: the routes just probed are not probed again.
	clockOverride.Store(at.Add(63 * time.Minute).Unix())
	rig.fail(res.RouteID, answeredReset())
	res = rig.connectAuto()
	for _, id := range rig.sideProbed()[sideAfter:] {
		for _, old := range raced {
			if id == old {
				t.Fatalf("%s was side-probed twice within %s", id, sideProbeRouteGap)
			}
		}
	}
	_ = res
}

// Cancel during a race: both probes are stopped, the call is back at
// once, and nothing is recorded about either route.
func TestRace_ClearRouteStopsBothProbes(t *testing.T) {
	rig := newRaceRig(t, raceRoutes)
	for _, id := range []string{"r1", "r2", "r4", "r5"} {
		rig.sideHang(id)
	}
	done := make(chan AutoResult, 1)
	go func() { done <- rig.connectAuto() }()
	waitFor(t, "two probes in flight", func() bool { return rig.stub.SideProbesInFlight() == 2 })
	t0 := time.Now()
	if err := ClearRoute(); err != nil {
		t.Fatal(err)
	}
	var res AutoResult
	select {
	case res = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the pass did not come back after a disconnect")
	}
	if d := time.Since(t0); d > time.Second {
		t.Fatalf("cancelling a race took %s", d)
	}
	if res.Connected || res.Verdict != AutoVerdictCancelled {
		t.Fatalf("got %+v", res)
	}
	if n := rig.stub.SideProbesInFlight(); n != 0 {
		t.Fatalf("%d side probes survived the disconnect", n)
	}
	if got := rig.sideProbed(); len(got) != 2 {
		t.Fatalf("after the cancel the pass went on to probe %v", got)
	}
	if mem := rig.c.routeMemory(); len(mem) != 0 {
		t.Fatalf("a cancelled race was remembered: %+v", mem)
	}
	for _, rt := range raceRoutes {
		if ok, _ := rig.c.pm.CanAttempt(rt[0], rt[1]); !ok {
			t.Fatalf("%s cools down after a cancelled race", rt[0])
		}
	}
	a := autoBlock(t)
	if a["state"] != AutoStateIdle || len(a["racing"].([]any)) != 0 {
		t.Fatalf("auto block after the cancel: %v", a)
	}
	if len(rig.provedRoutes()) != 0 || rig.starts.Load() != 0 {
		t.Fatal("the tunnel's instance was started by a race that was cancelled")
	}
}

// A route picked by hand, and a shutdown, stop a race the same way.
func TestRace_ManualSetRouteAndShutdownStopARace(t *testing.T) {
	rig := newRaceRig(t, raceRoutes)
	for _, id := range []string{"r1", "r2", "r4", "r5"} {
		rig.sideHang(id)
	}
	done := make(chan AutoResult, 1)
	go func() { done <- rig.connectAuto() }()
	waitFor(t, "two probes in flight", func() bool { return rig.stub.SideProbesInFlight() == 2 })
	if err := SetRoute("r3"); err != nil {
		t.Fatal(err)
	}
	if res := <-done; res.Verdict != AutoVerdictCancelled {
		t.Fatalf("got %+v", res)
	}
	if r, _ := rig.c.activeRouteFromMemory(); r != "r3" || rig.stub.SideProbesInFlight() != 0 {
		t.Fatalf("active=%s in flight=%d", r, rig.stub.SideProbesInFlight())
	}
	_ = ClearRoute()
	rig.c.mu.Lock()
	rig.c.side = sideLimits{}
	rig.c.mu.Unlock()
	// r3 carried here a moment ago and would be tried alone, and win.
	rig.fail("r3", answeredReset())

	go func() { done <- rig.connectAuto() }()
	waitFor(t, "two probes in flight again", func() bool { return rig.stub.SideProbesInFlight() == 2 })
	t0 := time.Now()
	if err := Shutdown(); err != nil {
		t.Fatal(err)
	}
	if n := rig.stub.SideProbesInFlight(); n != 0 {
		t.Fatalf("Shutdown returned with %d side probes in flight", n)
	}
	if d := time.Since(t0); d > time.Second {
		t.Fatalf("Shutdown took %s", d)
	}
	select {
	case res := <-done:
		if res.Connected {
			t.Fatalf("got %+v", res)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the pass did not come back after Shutdown")
	}
	if rig.starts.Load() != 2 {
		t.Fatalf("the tunnel's instance was started %d times; twice, both for r3 (by hand, then alone as the remembered route)", rig.starts.Load())
	}
}

// A fall-over pass that side-probes leaves the instance of the route it
// is moving away from EXACTLY as it is — no restart, the same check —
// and replaces it only when something else has proved.
func TestRace_AFallOverPassLeavesTheLostInstanceRunningUntilSomethingProves(t *testing.T) {
	rig := newRaceRig(t, raceRoutes)
	fastRecheck(rig.c)
	rig.sideHang("r1")
	if res := rig.connectAuto(); !res.Connected || res.RouteID != "r4" {
		t.Fatalf("got %+v", res)
	}
	rig.c.mu.Lock()
	rig.c.side = sideLimits{}
	rig.c.mu.Unlock()
	startsBefore := rig.starts.Load()

	// r4 stops carrying, and so does everything that can be raced; the
	// naive route is left out of this world.
	rig.fail("r4", answeredReset())
	rig.fail("r3", answeredReset())
	for _, id := range []string{"r1", "r2", "r5"} {
		rig.sideFail(id, answeredReset())
	}
	// r3 (naive) and the last candidate of a pass are tried through the
	// tunnel's instance, so r2 and r3 are resting: this test is about a
	// pass made of side probes only — r1 beside r5.
	rig.c.pm.FailedCandidate("r3", "naive", diagnostics.TCPConnectTimeout)
	rig.c.pm.FailedCandidate("r2", "websocket-tls", diagnostics.TCPConnectTimeout)
	rig.c.pm.Resume("r4", "hysteria2")
	sideBefore, _ := rig.stub.SideProbeStats()
	rig.c.kickLiveness()
	waitFor(t, "the fall-over pass to have failed", func() bool {
		as, _ := rig.c.auto.snapshot()
		return as == AutoStateFailed
	})
	if n := rig.starts.Load(); n != startsBefore {
		t.Fatalf("the tunnel's instance was restarted %d time(s) by a pass in which nothing proved", n-startsBefore)
	}
	blob := diagBlob(t)
	if blob["active_route"] != "r4" || blob["route_running"] != true || blob["route_check"] != RouteCheckFailed {
		t.Fatalf("the lost route must still be the tunnel's instance: active=%v running=%v check=%v",
			blob["active_route"], blob["route_running"], blob["route_check"])
	}
	if n, _ := rig.stub.SideProbeStats(); n != sideBefore+2 {
		t.Fatalf("%d side probes in the fall-over pass, want 2 (r1 beside r5)", n-sideBefore)
	}
	a := autoBlock(t)
	tried := a["tried"].([]any)
	if first := tried[0].(map[string]any); first["route_id"] != "r4" || first["why"] != AutoWhyWasConnected {
		t.Fatalf("tried = %v", tried)
	}
	// It is still watched, and comes back by itself.
	rig.carry("r4")
	waitFor(t, "r4 to carry again", func() bool {
		st, _ := rig.c.check.get()
		as, _ := rig.c.auto.snapshot()
		return st == RouteCheckOK && as == AutoStateConnected
	})
	if n := rig.starts.Load(); n != startsBefore {
		t.Fatalf("the instance was restarted %d time(s)", n-startsBefore)
	}
}

// …and when one of them proves, the tunnel moves to it.
func TestRace_AFallOverPassMovesToTheWinner(t *testing.T) {
	rig := newRaceRig(t, raceRoutes)
	fastRecheck(rig.c)
	rig.sideHang("r1")
	if res := rig.connectAuto(); res.RouteID != "r4" {
		t.Fatalf("got %+v", res)
	}
	rig.c.mu.Lock()
	rig.c.side = sideLimits{}
	rig.c.mu.Unlock()
	rig.fail("r4", answeredReset())
	rig.sideSet("r1", nil)
	rig.c.kickLiveness()
	waitFor(t, "the engine to have moved", func() bool {
		r, _ := rig.c.activeRouteFromMemory()
		st, _ := rig.c.check.get()
		as, _ := rig.c.auto.snapshot()
		return r != "r4" && st == RouteCheckOK && as == AutoStateConnected
	})
	a := autoBlock(t)
	if a["verdict"] != AutoVerdictMovedOn {
		t.Fatalf("auto block: %v", a)
	}
	if n := rig.stub.SideProbesInFlight(); n != 0 {
		t.Fatalf("%d in flight", n)
	}
}

// A driver that cannot side-probe (every test before this wave, and a
// build with no data plane) keeps the sequential pass.
func TestRace_WithoutASideProberThePassIsSequential(t *testing.T) {
	rig := newRaceRig(t, raceRoutes)
	rig.stub.SetSideProbeHook(nil)
	rig.fail("r1", deadSYN())
	res := rig.connectAuto()
	if !res.Connected || res.RouteID != "r2" {
		t.Fatalf("got %+v", res)
	}
	if got := rig.provedRoutes(); !eq(got, []string{"r1", "r2"}) {
		t.Fatalf("checked %v", got)
	}
	for _, tr := range res.Tried {
		if tr.RacedWith != "" {
			t.Fatalf("raced without a side prober: %+v", tr)
		}
	}
}

// Metered: a pass the person asked for may race; one the ENGINE starts
// by itself (the fall-over) goes one route at a time.
func TestRace_OnAMeteredNetworkTheEngineStartsNoSideProbeByItself(t *testing.T) {
	rig := newRaceRig(t, raceRoutes)
	fastRecheck(rig.c)
	facts(t, NetKindCellular, "operator-1", 1, 1)
	rig.sideHang("r1")
	if res := rig.connectAuto(); !res.Connected || res.RouteID != "r4" {
		t.Fatalf("got %+v", res)
	}
	asked, _ := rig.stub.SideProbeStats()
	if asked != 2 {
		t.Fatalf("a pass the person asked for made %d side probes on a metered network, want 2", asked)
	}
	rig.c.mu.Lock()
	rig.c.side = sideLimits{}
	rig.c.mu.Unlock()
	rig.mu.Lock()
	rig.proved = nil
	rig.mu.Unlock()

	rig.fail("r4", answeredReset())
	rig.fail("r1", answeredReset())
	rig.c.kickLiveness()
	waitFor(t, "the engine to have moved", func() bool {
		r, _ := rig.c.activeRouteFromMemory()
		st, _ := rig.c.check.get()
		return r == "r2" && st == RouteCheckOK
	})
	if n, _ := rig.stub.SideProbeStats(); n != asked {
		t.Fatalf("the engine started %d side probe(s) by itself on a metered network", n-asked)
	}
	got := rig.provedRoutes()
	if !eq(got[len(got)-2:], []string{"r1", "r2"}) {
		t.Fatalf("the fall-over pass checked %v; it must be the sequential one", got)
	}
}

// A pass the person asked for, racing beside a route that has stopped
// carrying and is still running: that route's own liveness loop goes on
// (the pass left it alone on purpose), fails its next check — and must
// NOT start a pass of its own, which cancelled the one in flight and
// sent the caller home with "cancelled" while the engine was still
// looking.
func TestRace_TheLivenessLoopOfTheLostRouteDoesNotCancelAPassInFlight(t *testing.T) {
	rig := newRaceRig(t, raceRoutes)
	rig.sideHang("r1")
	if res := rig.connectAuto(); !res.Connected || res.RouteID != "r4" {
		t.Fatalf("got %+v", res)
	}
	rig.c.mu.Lock()
	rig.c.side = sideLimits{}
	rig.c.proofCfg.LivenessInterval = time.Hour
	// Long enough for the explicit call to arrive between the first and
	// the second failed check, short enough to see several of them.
	rig.c.proofCfg.RecheckInterval = 150 * time.Millisecond
	rig.c.proofCfg.LivenessJitter = 0
	rig.c.mu.Unlock()
	// The loop reads its intervals when it starts: start it again.
	rig.c.mu.Lock()
	rig.c.startLivenessLocked()
	rig.c.mu.Unlock()

	// r4 stops carrying. r2 and r3 rest, so the pass is r1 beside r5 —
	// and neither gets an answer until the test lets r1 through.
	rig.fail("r4", answeredReset())
	rig.c.pm.FailedCandidate("r3", "naive", diagnostics.TCPConnectTimeout)
	rig.c.pm.FailedCandidate("r2", "websocket-tls", diagnostics.TCPConnectTimeout)
	release := make(chan struct{})
	rig.sideSet("r1", func(ctx context.Context) (engine.ProofResult, error) {
		select {
		case <-ctx.Done():
			return engine.ProofResult{Cancelled: true, Err: engine.ErrProofCancelled}, nil
		case <-release:
			return engine.ProofResult{OK: true, Attempts: 1}, nil
		}
	})
	rig.sideHang("r5")
	rig.c.kickLiveness()
	waitFor(t, "r4 to have failed ONE check", func() bool {
		st, _, running := rig.c.check.snapshot()
		return st == RouteCheckFailed && running
	})

	done := make(chan AutoResult, 1)
	go func() { done <- rig.connectAuto() }()
	waitFor(t, "the pair to be in flight", func() bool { return rig.stub.SideProbesInFlight() == 2 })
	checks := len(rig.provedRoutes())
	// Several more failed checks of r4 by its own loop, each of which
	// used to end in autoFallOver starting a pass.
	waitFor(t, "r4's loop to have checked it twice more", func() bool { return len(rig.provedRoutes()) >= checks+2 })
	select {
	case res := <-done:
		t.Fatalf("the pass the person asked for came back by itself while both probes were waiting: %+v", res)
	case <-time.After(100 * time.Millisecond):
	}
	if n := rig.stub.SideProbesInFlight(); n != 2 {
		t.Fatalf("%d probes in flight; the pair was stopped", n)
	}
	if a := autoBlock(t); a["state"] != AutoStateTrying {
		t.Fatalf("auto block while the pass is in flight: %v", a)
	}

	rig.carry("r1")
	close(release)
	select {
	case res := <-done:
		if !res.Connected || res.RouteID != "r1" || res.Verdict == AutoVerdictCancelled {
			t.Fatalf("got %+v", res)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the pass did not finish once a probe proved")
	}
}

// Both prove, and the winner's hand-over then fails through the tunnel:
// the other one — the one route of the pass KNOWN to answer from here —
// is tried next, through the tunnel, and is what the person ends up on.
// It appears once, is measured once, and is not side-probed again.
func TestRace_BothProveAndTheHandOverFailsThenTheOtherIsTried(t *testing.T) {
	both := func(rig *raceRig) {
		r4done := make(chan struct{})
		rig.sideSet("r1", func(context.Context) (engine.ProofResult, error) {
			<-r4done
			time.Sleep(10 * time.Millisecond)
			return engine.ProofResult{OK: true, Attempts: 1, Elapsed: 900 * time.Millisecond}, nil
		})
		rig.sideSet("r4", func(context.Context) (engine.ProofResult, error) {
			defer close(r4done)
			return engine.ProofResult{OK: true, Attempts: 1, Elapsed: 300 * time.Millisecond}, nil
		})
		rig.fail("r4", answeredReset()) // the winner, through the tunnel
		for _, id := range []string{"r2", "r3", "r5"} {
			rig.fail(id, answeredReset())
			rig.sideFail(id, answeredReset())
		}
	}

	rig := newRaceRig(t, raceRoutes)
	both(rig)
	res := rig.connectAuto()
	if !res.Connected || res.RouteID != "r1" || res.Verdict != AutoVerdictMovedOn {
		t.Fatalf("the route that had just answered was not what the pass connected on: %+v", res)
	}
	l := triedOf(res.Tried, "r1")
	if len(l) != 1 || l[0].Result != AutoResultCarried || l[0].RacedWith != "" {
		t.Fatalf("r1 must appear once, as the route then tried alone: %+v", res.Tried)
	}
	if w := triedOf(res.Tried, "r4"); len(w) != 1 || w[0].Result != AutoResultNotCarrying || w[0].RacedWith != "r1" {
		t.Fatalf("r4: %+v", w)
	}
	if got := rig.provedRoutes(); !eq(got, []string{"r4", "r1"}) {
		t.Fatalf("through the tunnel: %v, want r4 then r1 and nothing else", got)
	}
	if got := rig.sideProbed(); len(got) != 2 {
		t.Fatalf("side-probed %v", got)
	}
	if m := rig.c.routeMemory()["r1"].Measured(); m.Samples != 1 || m.SetupMs != 900 || m.Carried != 1 {
		t.Fatalf("r1 measured twice for one pass: %+v", m)
	}
	_ = Shutdown()

	// …and when that one does not carry through the tunnel either, the
	// pass that connected nothing does not read as one that connected.
	rig = newRaceRig(t, raceRoutes)
	both(rig)
	rig.fail("r1", answeredReset())
	res = rig.connectAuto()
	if res.Connected || res.Verdict == AutoVerdictNone || res.Verdict == AutoVerdictMovedOn {
		t.Fatalf("a pass that connected nothing: %+v", res)
	}
	for _, tr := range res.Tried {
		if tr.Result == AutoResultCarried {
			t.Fatalf("%s is reported as carried by a pass that connected nothing: %+v", tr.RouteID, res.Tried)
		}
	}
	if a := autoBlock(t); a["state"] != AutoStateFailed || a["verdict"] != res.Verdict {
		t.Fatalf("auto block: %v", a)
	}
}

// The pass's next route proves at its first attempt; the partner picked
// to be checked beside it fails first. Nothing was moved on from.
func TestRace_AFailedPartnerOfTheRouteThatConnectedIsNotMovedOn(t *testing.T) {
	rig := newRaceRig(t, raceRoutes)
	rig.sideFail("r4", answeredReset())
	rig.sideSet("r1", func(context.Context) (engine.ProofResult, error) {
		time.Sleep(40 * time.Millisecond)
		return engine.ProofResult{OK: true, Attempts: 1}, nil
	})
	res := rig.connectAuto()
	if !res.Connected || res.RouteID != "r1" {
		t.Fatalf("got %+v", res)
	}
	if l := triedOf(res.Tried, "r4"); len(l) != 1 || l[0].Result != AutoResultNotCarrying || l[0].RacedWith != "r1" {
		t.Fatalf("premise: r4 failed beside r1: %+v", res.Tried)
	}
	if res.Verdict != AutoVerdictNone || autoBlock(t)["verdict"] != AutoVerdictNone {
		t.Fatalf("verdict %q: the first route worked at its first attempt", res.Verdict)
	}
	_ = Shutdown()

	// The other way round — the pass's next route failed and its partner
	// is what connected — IS moving on.
	rig = newRaceRig(t, raceRoutes)
	rig.sideFail("r1", answeredReset())
	rig.sideSet("r4", func(context.Context) (engine.ProofResult, error) {
		time.Sleep(40 * time.Millisecond)
		return engine.ProofResult{OK: true, Attempts: 1}, nil
	})
	res = rig.connectAuto()
	if !res.Connected || res.RouteID != "r4" || res.Verdict != AutoVerdictMovedOn {
		t.Fatalf("got %+v", res)
	}
}

func TestDeriveAuto_SideOnlyCarriedAndRacePartners(t *testing.T) {
	fail := autoObs{result: AutoResultNotCarrying, category: diagnostics.TCPReset}
	with := func(o autoObs, id, raced string, second bool) autoObs {
		o.id, o.racedWith, o.second = id, raced, second
		return o
	}
	carried := autoObs{result: AutoResultCarried}
	side := autoObs{result: AutoResultCarried, sideOnly: true}
	cases := []struct {
		name string
		obs  []autoObs
		want string
	}{
		{"partner failed beside the route that connected", []autoObs{with(fail, "r4", "r1", true), with(carried, "r1", "r4", false)}, AutoVerdictNone},
		{"the first of the pair failed, its partner connected", []autoObs{with(fail, "r1", "r4", false), with(carried, "r4", "r1", false)}, AutoVerdictMovedOn},
		{"an earlier route failed alone", []autoObs{with(fail, "r0", "", false), with(fail, "r4", "r1", true), with(carried, "r1", "r4", false)}, AutoVerdictMovedOn},
		{"proved beside only, nothing connected", []autoObs{with(fail, "r4", "r1", false), with(side, "r1", "r4", false)}, AutoVerdictAllFailed},
		{"proved beside, and the winner connected", []autoObs{with(carried, "r4", "r1", false), with(side, "r1", "r4", false)}, AutoVerdictNone},
	}
	for _, c := range cases {
		if got, _ := deriveAuto(c.obs); got != c.want {
			t.Errorf("%s: verdict %q, want %q", c.name, got, c.want)
		}
	}
}
