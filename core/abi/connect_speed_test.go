package abi

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"daal/core/engine"
	"daal/core/netmem"
)

// Moving for speed (connect_speed.go).

func slowCheck(d time.Duration) func(context.Context) engine.ProofResult {
	return func(context.Context) engine.ProofResult {
		return engine.ProofResult{OK: true, Attempts: 1, Elapsed: d, Slow: true}
	}
}

// speedRig: connected automatically on r1, liveness driven by kicks.
func speedRig(t *testing.T) *raceRig {
	t.Helper()
	setClock(t, time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC))
	rig := newRaceRig(t, raceRoutes)
	fastRecheck(rig.c)
	// r1 answers at once, inside the pair's delay: its partner is never
	// sent, and r1 is the route that carried here.
	raceDelay = func() time.Duration { return 200 * time.Millisecond }
	if res := rig.connectAuto(); !res.Connected || res.RouteID != "r1" {
		t.Fatalf("got %+v", res)
	}
	rig.c.mu.Lock()
	rig.c.side = sideLimits{}
	rig.c.mu.Unlock()
	return rig
}

// kickAndWait asks for one liveness check and waits until it is filed.
func kickAndWait(t *testing.T, rig *raceRig) {
	t.Helper()
	n := len(rig.provedRoutes())
	rig.c.kickLiveness()
	waitFor(t, "one more liveness check", func() bool { return len(rig.provedRoutes()) > n })
	// …and for whatever the loop does with the result.
	time.Sleep(40 * time.Millisecond)
}

func sideTotal(rig *raceRig) int { n, _ := rig.stub.SideProbeStats(); return n }

// The move: slow twice in a row, another route proves clearly faster in
// a side instance, and the tunnel moves to it — said as moved_faster.
// Then the hold: no further move for speed, however slow things get.
func TestSpeed_MovesAfterTwoSlowChecksToAClearlyFasterRoute(t *testing.T) {
	rig := speedRig(t)
	lc := captureLog(t)
	before := sideTotal(rig)
	rig.set("r1", slowCheck(3*time.Second))
	rig.sideIn("r2", 900*time.Millisecond)

	kickAndWait(t, rig)
	if st, _ := rig.c.check.get(); st != RouteCheckDegraded {
		t.Fatalf("premise: r1 is %q", st)
	}
	if got := sideTotal(rig); got != before {
		t.Fatalf("ONE slow check started %d side probe(s)", got-before)
	}
	if r, _ := rig.c.activeRouteFromMemory(); r != "r1" {
		t.Fatalf("moved after one slow check, to %s", r)
	}

	rig.c.kickLiveness()
	waitFor(t, "the engine to have moved for speed", func() bool {
		r, _ := rig.c.activeRouteFromMemory()
		st, _ := rig.c.check.get()
		return r != "r1" && st == RouteCheckOK
	})
	to, _ := rig.c.activeRouteFromMemory()
	if to != "r2" {
		t.Fatalf("moved to %s; r2 is the next in the pass's order", to)
	}
	if got := sideTotal(rig); got != before+1 {
		t.Fatalf("%d side probes for one speed check, want exactly 1", got-before)
	}
	a := autoBlock(t)
	if a["state"] != AutoStateConnected || a["mode"] != true || a["route_id"] != "r2" || a["verdict"] != AutoVerdictMovedFaster {
		t.Fatalf("auto block: %v", a)
	}
	tried := a["tried"].([]any)
	last := tried[len(tried)-1].(map[string]any)
	if last["route_id"] != "r2" || last["result"] != AutoResultCarried || last["setup_ms"] != float64(900) {
		t.Fatalf("tried: %v", tried)
	}
	if !lc.has("auto moved_faster from=r1 to=r2") {
		t.Fatalf("log: %v", lc.all())
	}
	if m := rig.c.routeMemory()["r2"].Measured(); m.Samples != 1 || m.SetupMs != 900 {
		t.Fatalf("the candidate's measurement: %+v", m)
	}

	// The hold. r2 is slow now too, and the others would be much faster.
	rig.c.mu.Lock()
	rig.c.side = sideLimits{}
	rig.c.speed.nextProbeAt = time.Time{} // the hold alone must stop it
	rig.c.mu.Unlock()
	afterMove := sideTotal(rig)
	rig.set("r2", slowCheck(3*time.Second))
	rig.set("r1", nil)
	for i := 0; i < 4; i++ {
		kickAndWait(t, rig)
	}
	if got := sideTotal(rig); got != afterMove {
		t.Fatalf("%d side probe(s) inside the hold after a move for speed", got-afterMove)
	}
	if r, _ := rig.c.activeRouteFromMemory(); r != "r2" {
		t.Fatalf("flapped to %s inside the hold", r)
	}
	// After the hold it may look again.
	clockOverride.Store(nowUTC().Add(speedMoveHold + time.Minute).Unix())
	rig.c.mu.Lock()
	rig.c.side = sideLimits{}
	rig.c.mu.Unlock()
	kickAndWait(t, rig)
	waitFor(t, "a speed probe after the hold", func() bool { return sideTotal(rig) > afterMove })
}

// Not clearly better: the engine stays, and does not ask again for the
// back-off.
func TestSpeed_StaysWhenTheOtherIsNotClearlyFasterAndBacksOff(t *testing.T) {
	rig := speedRig(t)
	before := sideTotal(rig)
	rig.set("r1", slowCheck(3*time.Second))
	// 1.6 s against a 3 s check: faster, not clearly (more than half).
	rig.sideIn("r2", 1600*time.Millisecond)
	rig.sideIn("r4", 100*time.Millisecond)
	rig.sideIn("r5", 100*time.Millisecond)
	kickAndWait(t, rig)
	kickAndWait(t, rig)
	waitFor(t, "the speed probe", func() bool { return sideTotal(rig) == before+1 })
	time.Sleep(50 * time.Millisecond)
	if r, _ := rig.c.activeRouteFromMemory(); r != "r1" {
		t.Fatalf("moved to %s for a route that was not clearly faster", r)
	}
	if a := autoBlock(t); a["verdict"] == AutoVerdictMovedFaster || a["route_id"] != "r1" {
		t.Fatalf("auto block: %v", a)
	}
	if rig.starts.Load() != 1 {
		t.Fatalf("the tunnel's instance was started %d times; staying restarts nothing", rig.starts.Load())
	}
	// The candidate's measurement is kept all the same.
	if m := rig.c.routeMemory()["r2"].Measured(); m.SetupMs != 1600 || m.Grade != netmem.GradeOK {
		t.Fatalf("r2: %+v", m)
	}
	// Still slow, check after check: no further probe inside the
	// back-off, although r4 and r5 would win at once.
	for i := 0; i < 4; i++ {
		kickAndWait(t, rig)
	}
	if got := sideTotal(rig); got != before+1 {
		t.Fatalf("%d more side probe(s) inside the back-off", got-before-1)
	}
	clockOverride.Store(nowUTC().Add(speedProbeBackoff + time.Minute).Unix())
	kickAndWait(t, rig)
	waitFor(t, "the engine to have moved after the back-off", func() bool {
		r, _ := rig.c.activeRouteFromMemory()
		return r != "r1"
	})

	if speedMoveFactorPct > 60 || speedMoveHold < 2*speedProbeBackoff || speedProbeBackoff < 5*time.Minute || speedSlowChecks < 2 {
		t.Fatalf("constants: factor %d%%, hold %s, back-off %s, checks %d", speedMoveFactorPct, speedMoveHold, speedProbeBackoff, speedSlowChecks)
	}
}

// The candidate's own proof was slow, or it failed: stay. A failure
// that answered is remembered; nothing is cooled down.
func TestSpeed_StaysWhenTheCandidateIsSlowOrFails(t *testing.T) {
	rig := speedRig(t)
	rig.set("r1", slowCheck(10*time.Second))
	rig.sideSet("r2", func(context.Context) (engine.ProofResult, error) {
		return engine.ProofResult{OK: true, Attempts: 2, Elapsed: 2500 * time.Millisecond, Slow: true}, nil
	})
	before := sideTotal(rig)
	kickAndWait(t, rig)
	kickAndWait(t, rig)
	waitFor(t, "the speed probe", func() bool { return sideTotal(rig) == before+1 })
	time.Sleep(50 * time.Millisecond)
	if r, _ := rig.c.activeRouteFromMemory(); r != "r1" {
		t.Fatalf("moved to %s, whose own proof was slow", r)
	}

	clockOverride.Store(nowUTC().Add(speedProbeBackoff + time.Minute).Unix())
	rig.sideFail("r2", answeredReset())
	rig.sideFail("r4", answeredReset())
	rig.sideFail("r5", answeredReset())
	kickAndWait(t, rig)
	waitFor(t, "the second speed probe", func() bool { return sideTotal(rig) == before+2 })
	time.Sleep(50 * time.Millisecond)
	if r, _ := rig.c.activeRouteFromMemory(); r != "r1" {
		t.Fatalf("moved to %s after its probe failed", r)
	}
	probed := rig.sideProbed()
	failed := probed[len(probed)-1]
	if m := rig.c.routeMemory()[failed]; m.Failed != 1 {
		t.Fatalf("%s failed its speed probe and nothing is remembered: %+v", failed, m)
	}
	row, _ := rig.c.store.GetRoute(failed)
	if ok, why := rig.c.pm.CanAttempt(failed, row.TransportFamily); !ok {
		t.Fatalf("a speed probe cooled %s down: %s", failed, why)
	}
	if st, _ := rig.c.check.get(); st != RouteCheckDegraded {
		t.Fatalf("the running route's state was touched by a failed speed probe: %q", st)
	}
}

// Never by hand, never on a metered network, never to a route that
// cannot be side-probed or is graded no better.
func TestSpeed_DoesNotProbeWhenItMustNot(t *testing.T) {
	t.Run("a route picked by hand is never left", func(t *testing.T) {
		rig := newRaceRig(t, raceRoutes)
		fastRecheck(rig.c)
		if err := SetRoute("r1"); err != nil {
			t.Fatal(err)
		}
		rig.set("r1", slowCheck(5*time.Second))
		for i := 0; i < 4; i++ {
			kickAndWait(t, rig)
		}
		if n := sideTotal(rig); n != 0 {
			t.Fatalf("%d side probes in manual mode", n)
		}
	})
	t.Run("metered: the engine starts no side probe by itself", func(t *testing.T) {
		rig := speedRig(t)
		facts(t, NetKindCellular, "operator-1", 1, 1)
		time.Sleep(50 * time.Millisecond) // the kick of the network change
		before := sideTotal(rig)
		rig.set("r1", slowCheck(5*time.Second))
		for i := 0; i < 4; i++ {
			kickAndWait(t, rig)
		}
		if n := sideTotal(rig); n != before {
			t.Fatalf("%d side probes on a metered network", n-before)
		}
		// The same network, not metered: it looks.
		facts(t, NetKindCellular, "operator-1", 1, 0)
		kickAndWait(t, rig)
		kickAndWait(t, rig)
		waitFor(t, "a speed probe once the network is not metered", func() bool { return sideTotal(rig) > before })
	})
	t.Run("only a route graded better here, or never tried here", func(t *testing.T) {
		rig := speedRig(t)
		// r4 and r5 are slow here, r2 is failing here: nothing to move to.
		now := nowUTC()
		st := netmemStore()
		for i := 0; i < 2; i++ {
			_ = st.RecordRouteOutcome(activeNetworkID(), "r4", netmem.RouteOutcome{Carried: true, HasSetup: true, SetupMs: 7000}, now)
			_ = st.RecordRouteOutcome(activeNetworkID(), "r5", netmem.RouteOutcome{Carried: true, HasSetup: true, SetupMs: 7000}, now)
			_ = st.RecordRouteOutcome(activeNetworkID(), "r2", netmem.RouteOutcome{Category: "tcp_reset"}, now)
		}
		// …and r1 itself, so it stays the remembered route.
		_ = st.RecordRouteOutcome(activeNetworkID(), "r1", netmem.RouteOutcome{Carried: true}, now)
		before := sideTotal(rig)
		rig.set("r1", slowCheck(5*time.Second))
		for i := 0; i < 3; i++ {
			kickAndWait(t, rig)
		}
		if n := sideTotal(rig); n != before {
			t.Fatalf("%d side probes with no better-graded route (probed %v)", n-before, rig.sideProbed())
		}
		if r, _ := rig.c.activeRouteFromMemory(); r != "r1" {
			t.Fatalf("moved to %s", r)
		}
	})
	t.Run("a family that cannot be side-probed is never moved to", func(t *testing.T) {
		setClock(t, time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC))
		rig := newRaceRig(t, [][3]string{raceRoutes[0], raceRoutes[2]}) // r1 and the naive route
		fastRecheck(rig.c)
		if res := rig.connectAuto(); res.RouteID != "r1" {
			t.Fatalf("got %+v", res)
		}
		rig.set("r1", slowCheck(5*time.Second))
		for i := 0; i < 3; i++ {
			kickAndWait(t, rig)
		}
		if got := rig.provedRoutes(); got[len(got)-1] != "r1" || sideTotal(rig) != 0 {
			t.Fatalf("checked %v, %d side probes", got, sideTotal(rig))
		}
		if r, _ := rig.c.activeRouteFromMemory(); r != "r1" {
			t.Fatalf("moved to %s", r)
		}
	})
}

// A move whose hand-over fails: the candidate proved beside the tunnel
// and not through it. The route the person was on is put back WITHOUT a
// pass/fail check — here a fresh check of it would fail — is not charged
// for the engine's own detour, and the tunnel has an instance behind it
// when the call is over.
func TestSpeed_AFailedMoveGoesBackWithoutACheckAndChargesNothingToTheOldRoute(t *testing.T) {
	rig := speedRig(t)
	lc := captureLog(t)
	// r1: slow twice (the two checks that start the speed probe), then
	// ONE answered failure — the check a fresh start of it would have
	// been judged by — then slow again.
	var n atomic.Int32
	rig.set("r1", func(context.Context) engine.ProofResult {
		if n.Add(1) == 3 {
			return answeredReset()
		}
		return engine.ProofResult{OK: true, Attempts: 1, Elapsed: 3 * time.Second, Slow: true}
	})
	rig.sideIn("r2", 300*time.Millisecond) // proves beside the tunnel…
	rig.fail("r2", answeredReset())        // …and not through it
	for _, id := range []string{"r3", "r4", "r5"} {
		rig.fail(id, answeredReset())
		rig.sideFail(id, answeredReset())
	}

	kickAndWait(t, rig)
	rig.c.kickLiveness()
	waitFor(t, "the move to have been tried and undone", func() bool { return lc.has("auto speed back route=r1") })
	waitFor(t, "r1 to be the tunnel's instance again, carrying", func() bool {
		r, _ := rig.c.activeRouteFromMemory()
		st, _, running := rig.c.check.snapshot()
		return r == "r1" && running && st == RouteCheckDegraded && n.Load() >= 4
	})
	time.Sleep(60 * time.Millisecond)
	blob := diagBlob(t)
	if blob["active_route"] != "r1" || blob["route_running"] != true {
		t.Fatalf("after a failed move: active=%v running=%v check=%v", blob["active_route"], blob["route_running"], blob["route_check"])
	}
	a := autoBlock(t)
	if a["state"] != AutoStateConnected || a["mode"] != true || a["route_id"] != "r1" || a["verdict"] == AutoVerdictMovedFaster {
		t.Fatalf("auto block: %v", a)
	}
	rig.c.mu.Lock()
	_, _, err1 := rig.c.prepareRouteOpts("r1", false, false)
	_, _, err2 := rig.c.prepareRouteOpts("r2", false, false)
	rig.c.mu.Unlock()
	if err1 != nil {
		t.Fatalf("the route the person was on is refused after the engine's own detour: %v", err1)
	}
	if err2 == nil {
		t.Fatal("the candidate that did not carry through the tunnel is not resting")
	}
	// Nothing else was torn through on the way: the others were never
	// started.
	for _, id := range rig.provedRoutes() {
		if id != "r1" && id != "r2" {
			t.Fatalf("route %s was tried through the tunnel after a failed move: %v", id, rig.provedRoutes())
		}
	}
	if !lc.has("auto resume route=r1") {
		t.Fatalf("log: %v", lc.all())
	}
}
