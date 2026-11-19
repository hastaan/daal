package abi

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"daal/core/diagnostics"
	"daal/core/engine"
)

// Tests for the review of the automatic connect (2026-11-19): what a
// failed pass is charged with, when the engine moves by itself, who
// re-points tunnelled refresh, and the races around a pass in flight.

func setClock(t *testing.T, at time.Time) {
	t.Helper()
	clockOverride.Store(at.Unix())
	t.Cleanup(func() { clockOverride.Store(0) })
}

var answeredReset = func() engine.ProofResult {
	return failedProof(errors.New("read: connection reset by peer"), diagnostics.PhaseCarry, false, false)
}

// The uplink was out for a moment: every route was silent. Nothing is
// learned about any route, so nothing cools down — the next press tries
// all four again, and a pick by hand is not refused.
func TestConnectAuto_APassWhereNothingAnsweredCoolsNothingDown(t *testing.T) {
	rig := newAutoRig(t, autoFourRoutes)
	for _, id := range []string{"r1", "r2", "r3"} {
		rig.fail(id, deadSYN())
	}
	rig.fail("r4", silentUDP())
	res := rig.connectAuto()
	if res.Connected || res.Candidates != 4 || res.Verdict != AutoVerdictRelayUnreachable {
		t.Fatalf("premise: got %+v", res)
	}
	for _, r := range autoFourRoutes {
		if ok, why := rig.c.pm.CanAttempt(r[0], r[1]); !ok {
			t.Fatalf("%s is cooling down after a pass in which nothing answered: %s", r[0], why)
		}
		row, err := rig.c.store.GetRoute(r[0])
		if err != nil {
			t.Fatal(err)
		}
		if row.ConsecutiveFailures != 0 || row.CooldownUntil != "" {
			t.Fatalf("%s has a durable failure row: failures=%d cooldown=%q", r[0], row.ConsecutiveFailures, row.CooldownUntil)
		}
	}
	if mem := rig.c.routeMemory(); len(mem) != 0 {
		t.Fatalf("routes are remembered as failing on this network: %+v", mem)
	}
	// The verdict has no cooldown to wait out: a poll does not drop it.
	if a := autoBlock(t); a["state"] != AutoStateFailed || a["verdict"] != AutoVerdictRelayUnreachable {
		t.Fatalf("auto block: %v", a)
	}
	// The network is back ten seconds later.
	for _, r := range autoFourRoutes {
		rig.carry(r[0])
	}
	again := rig.connectAuto()
	if !again.Connected || again.Candidates != 4 || again.Verdict != "" {
		t.Fatalf("second press: %+v", again)
	}
	// And a pick by hand right after such a pass is not refused.
	_ = ClearRoute()
	rig.fail("r1", deadSYN())
	rig.fail("r2", deadSYN())
	rig.fail("r3", deadSYN())
	rig.fail("r4", silentUDP())
	_ = rig.connectAuto()
	rig.carry("r2")
	if err := SetRoute("r2"); err != nil {
		t.Fatalf("manual pick after an all-silent pass: %v", err)
	}
}

// A pass in which something DID answer charges what it always did: the
// route cools down, the failure is durable and remembered here.
func TestConnectAuto_AnAnsweredFailureStillCoolsItsRouteDown(t *testing.T) {
	rig := newAutoRig(t, autoFourRoutes[:2])
	rig.fail("r1", deadSYN())
	rig.fail("r2", answeredReset())
	res := rig.connectAuto()
	if res.Connected || res.Verdict != AutoVerdictAllFailed {
		t.Fatalf("premise: got %+v", res)
	}
	for _, r := range autoFourRoutes[:2] {
		if ok, _ := rig.c.pm.CanAttempt(r[0], r[1]); ok {
			t.Fatalf("%s is not cooling down", r[0])
		}
		row, _ := rig.c.store.GetRoute(r[0])
		if row.ConsecutiveFailures != 1 || row.CooldownUntil == "" {
			t.Fatalf("%s: durable row failures=%d cooldown=%q", r[0], row.ConsecutiveFailures, row.CooldownUntil)
		}
	}
	if mem := rig.c.routeMemory(); len(mem) != 2 {
		t.Fatalf("this network's memory: %+v", mem)
	}
	if again := rig.connectAuto(); again.Verdict != AutoVerdictAllCoolingDown {
		t.Fatalf("second press: %+v", again)
	}
}

// Hours of failed passes — a person's "Try again", a host's retry loop —
// never cool a whole family down. Before: three failures of a family in
// an hour started the 5 min … 24 h ladder, one step per further pass.
func TestConnectAuto_RepeatedFailedPassesNeverStartTheFamilyLadder(t *testing.T) {
	rig := newAutoRig(t, autoFourRoutes[:3])
	at := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
	setClock(t, at)
	for _, id := range []string{"r1", "r2", "r3"} {
		rig.fail(id, answeredReset())
	}
	for pass := 0; pass < 8; pass++ {
		res := rig.connectAuto()
		if res.Candidates != 3 {
			t.Fatalf("pass %d at +%s had %d candidates (tried %+v)", pass, nowUTC().Sub(at), res.Candidates, res.Tried)
		}
		if sk := rig.c.pm.SkippedFamilies(); len(sk) != 0 {
			t.Fatalf("pass %d: families cooling down: %+v", pass, sk)
		}
		// tcp_reset rests a route for 30 minutes.
		clockOverride.Store(nowUTC().Add(31 * time.Minute).Unix())
	}
}

// One failed check is not an outage: the engine checks again before it
// replaces the instance under every open connection.
func TestAutoMode_OneFailedCheckDoesNotMoveOn(t *testing.T) {
	rig := newAutoRig(t, autoFourRoutes)
	fastRecheck(rig.c)
	if res := rig.connectAuto(); res.RouteID != "r1" {
		t.Fatalf("got %+v", res)
	}
	var calls atomic.Int32
	rig.set("r1", func(context.Context) engine.ProofResult {
		if calls.Add(1) == 1 {
			return deadSYN()
		}
		return engine.ProofResult{OK: true, Attempts: 1}
	})
	rig.c.kickLiveness()
	waitFor(t, "r1 to fail once and carry again", func() bool {
		st, _ := rig.c.check.get()
		return calls.Load() >= 2 && st == RouteCheckOK
	})
	time.Sleep(60 * time.Millisecond)
	for _, id := range rig.provedRoutes() {
		if id != "r1" {
			t.Fatalf("one failed check started %s", id)
		}
	}
	if a := autoBlock(t); a["state"] != AutoStateConnected || a["route_id"] != "r1" {
		t.Fatalf("auto block: %v", a)
	}
}

// A route that is only slow (or whose relay cannot reach the check's
// targets, or whose device has no network) may still be carrying: the
// engine does not bounce it. When it then goes silent, it does move.
func TestAutoMode_DoesNotMoveOffARouteThatMayStillCarry(t *testing.T) {
	slow := failedProof(context.DeadlineExceeded, diagnostics.PhaseCarry, false, true)
	slow.Observation.Progress = true
	slow.Failed[0].Progress = true
	offline := failedProof(errors.New("connect: network is unreachable"), diagnostics.PhaseReach, false, true)
	noEgress := failedProof(context.DeadlineExceeded, diagnostics.PhaseCarry, false, true)
	noEgress.Observation.RelayNoEgress = true
	noEgress.Failed[0].RelayNoEgress = true
	for name, tc := range map[string]struct {
		res engine.ProofResult
		cat diagnostics.Category
	}{
		"path_too_slow":   {slow, diagnostics.PathTooSlow},
		"relay_no_egress": {noEgress, diagnostics.RelayNoEgress},
		"network_offline": {offline, diagnostics.NetworkOffline},
	} {
		t.Run(name, func(t *testing.T) {
			if tc.res.Category() != tc.cat {
				t.Fatalf("premise: category = %s", tc.res.Category())
			}
			rig := newAutoRig(t, autoFourRoutes)
			fastRecheck(rig.c)
			if res := rig.connectAuto(); res.RouteID != "r1" {
				t.Fatalf("got %+v", res)
			}
			rig.fail("r1", tc.res)
			rig.c.kickLiveness()
			waitFor(t, "r1 to be failed", func() bool { st, _ := rig.c.check.get(); return st == RouteCheckFailed })
			time.Sleep(150 * time.Millisecond) // several rechecks
			for _, id := range rig.provedRoutes() {
				if id != "r1" {
					t.Fatalf("%s: the engine started %s", name, id)
				}
			}
			if r, _ := rig.c.activeRouteFromMemory(); r != "r1" {
				t.Fatalf("active route = %q", r)
			}
			// The same route now gets no answer at all: a different
			// outage, and one to move away from.
			rig.fail("r1", deadSYN())
			waitFor(t, "the engine to move to r2", func() bool {
				r, _ := rig.c.activeRouteFromMemory()
				st, _ := rig.c.check.get()
				return r == "r2" && st == RouteCheckOK
			})
		})
	}
}

// The passes the engine starts by itself during one outage back off:
// 5, 10, 20, 40, 60, 60 minutes.
func TestAutoMode_EnginePassesBackOff(t *testing.T) {
	want := []time.Duration{5, 10, 20, 40, 60, 60, 60}
	for i, w := range want {
		if got := autoFallBackoff(i + 1); got != w*time.Minute {
			t.Fatalf("autoFallBackoff(%d) = %s, want %s", i+1, got, w*time.Minute)
		}
	}
	rig := newAutoRig(t, autoFourRoutes[:2])
	at := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
	setClock(t, at)
	fastRecheck(rig.c)
	if res := rig.connectAuto(); res.RouteID != "r1" {
		t.Fatalf("got %+v", res)
	}
	rig.fail("r1", deadSYN())
	rig.fail("r2", deadSYN())
	passes := func() int {
		n := 0
		for _, id := range rig.provedRoutes() {
			if id == "r2" {
				n++
			}
		}
		return n
	}
	rig.c.kickLiveness()
	waitFor(t, "the first pass", func() bool {
		as, _ := rig.c.auto.snapshot()
		_, _, running := rig.c.check.snapshot()
		return passes() == 1 && as == AutoStateFailed && running
	})
	// Nothing is cooling down (the pass was all silence), and still the
	// rechecks of r1 do not start r2 again.
	if ok, _ := rig.c.pm.CanAttempt("r2", "websocket-tls"); !ok {
		t.Fatal("premise: r2 is cooling down")
	}
	time.Sleep(150 * time.Millisecond)
	if passes() != 1 {
		t.Fatalf("r2 was started %d times within the back-off", passes())
	}
	clockOverride.Store(at.Add(5*time.Minute + time.Second).Unix())
	waitFor(t, "the second pass", func() bool { return passes() == 2 })
	time.Sleep(100 * time.Millisecond)
	// Six minutes after the second pass: inside its ten.
	clockOverride.Store(at.Add(11 * time.Minute).Unix())
	time.Sleep(150 * time.Millisecond)
	if passes() != 2 {
		t.Fatalf("the third pass came after 6 minutes (%d passes)", passes())
	}
	clockOverride.Store(at.Add(16 * time.Minute).Unix())
	waitFor(t, "the third pass", func() bool { return passes() == 3 })
}

// newInletPerStart makes the stub do what the real driver does: every
// instance gets an inlet of its own. It returns the port of the inlet
// of the instance started last.
func newInletPerStart(t *testing.T, rig *autoRig) func() int {
	t.Helper()
	var port atomic.Int32
	port.Store(41000)
	rig.stub.SetStartHook(func() {
		p := int(port.Add(1))
		engine.PublishRefreshInletForTest(&engine.RefreshInlet{Host: "127.0.0.1", Port: p, Username: "u", Password: "p"})
	})
	t.Cleanup(func() {
		rig.stub.SetStartHook(nil)
		engine.PublishRefreshInletForTest(nil)
	})
	return func() int { return int(port.Load()) }
}

func tunnelPort() int {
	if ep := currentTunnel(); ep != nil {
		return ep.port
	}
	return 0
}

// Every instance the engine starts by itself has a new inlet. A host
// that turned tunnelled refresh on is re-pointed by the engine: after a
// fall-over, after the instance of the same route is put back, and
// after the way back from a switch that failed.
func TestTunnelRefresh_FollowsTheInstancesTheEngineStartsItself(t *testing.T) {
	t.Run("fall-over to another route", func(t *testing.T) {
		rig := newAutoRig(t, autoFourRoutes)
		last := newInletPerStart(t, rig)
		fastRecheck(rig.c)
		if res := rig.connectAuto(); res.RouteID != "r1" {
			t.Fatalf("got %+v", res)
		}
		if _, err := SetTunnelRefresh(true); err != nil {
			t.Fatal(err)
		}
		armed := tunnelPort()
		rig.fail("r1", deadSYN())
		rig.c.kickLiveness()
		waitFor(t, "the engine to move to r2", func() bool {
			r, _ := rig.c.activeRouteFromMemory()
			st, _ := rig.c.check.get()
			return r == "r2" && st == RouteCheckOK
		})
		rig.c.mu.Lock() // the connect that proved r2 has returned
		rig.c.mu.Unlock()
		if got := tunnelPort(); got != last() || got == armed {
			t.Fatalf("refresh dials port %d (armed on %d); the running instance listens on %d", got, armed, last())
		}
	})
	t.Run("the same route put back", func(t *testing.T) {
		rig := newAutoRig(t, autoFourRoutes[:2])
		last := newInletPerStart(t, rig)
		fastRecheck(rig.c)
		if res := rig.connectAuto(); res.RouteID != "r1" {
			t.Fatalf("got %+v", res)
		}
		if _, err := SetTunnelRefresh(true); err != nil {
			t.Fatal(err)
		}
		armed := tunnelPort()
		rig.fail("r1", deadSYN())
		rig.fail("r2", deadSYN())
		rig.c.kickLiveness()
		waitFor(t, "r1 to be put back", func() bool {
			r, _ := rig.c.activeRouteFromMemory()
			as, _ := rig.c.auto.snapshot()
			_, _, running := rig.c.check.snapshot()
			return r == "r1" && as == AutoStateFailed && running
		})
		rig.c.mu.Lock()
		rig.c.mu.Unlock()
		if got := tunnelPort(); got != last() || got == armed {
			t.Fatalf("refresh dials port %d (armed on %d); the instance put back listens on %d", got, armed, last())
		}
	})
	t.Run("the way back from a failed switch", func(t *testing.T) {
		rig := newAutoRig(t, autoFourRoutes)
		last := newInletPerStart(t, rig)
		if err := SetRoute("r1"); err != nil {
			t.Fatal(err)
		}
		if _, err := SetTunnelRefresh(true); err != nil {
			t.Fatal(err)
		}
		armed := tunnelPort()
		rig.fail("r4", silentUDP())
		if err := SetRoute("r4"); err == nil {
			t.Fatal("premise: the switch did not fail")
		}
		if r, _ := rig.c.activeRouteFromMemory(); r != "r1" {
			t.Fatalf("premise: active route = %q", r)
		}
		if got := tunnelPort(); got != last() || got == armed {
			t.Fatalf("refresh dials port %d (armed on %d); the restored instance listens on %d", got, armed, last())
		}
	})
	t.Run("not when the host never asked", func(t *testing.T) {
		rig := newAutoRig(t, autoFourRoutes[:1])
		newInletPerStart(t, rig)
		if res := rig.connectAuto(); !res.Connected {
			t.Fatalf("got %+v", res)
		}
		if ep := currentTunnel(); ep != nil {
			t.Fatal("the engine turned tunnelled refresh on by itself")
		}
	})
}

// engine_connect_auto on an engine that is connected on a route picked
// by hand: nothing is started, and the engine is in charge from then on
// — it moves when that route stops carrying.
func TestConnectAuto_TakesChargeOfARoutePickedByHand(t *testing.T) {
	rig := newAutoRig(t, autoFourRoutes)
	fastRecheck(rig.c)
	if err := SetRoute("r3"); err != nil {
		t.Fatal(err)
	}
	if a := autoBlock(t); a["mode"] != false {
		t.Fatalf("premise: auto block %v", a)
	}
	n := rig.stub.ProofCount()
	res := rig.connectAuto()
	if !res.Connected || res.RouteID != "r3" || !res.AlreadyConnected || rig.stub.ProofCount() != n {
		t.Fatalf("got %+v", res)
	}
	if a := autoBlock(t); a["mode"] != true || a["state"] != AutoStateConnected || a["route_id"] != "r3" || a["family"] != "naive" {
		t.Fatalf("auto block: %v", a)
	}
	rig.fail("r3", deadSYN())
	rig.c.kickLiveness()
	waitFor(t, "the engine to move off r3", func() bool {
		r, _ := rig.c.activeRouteFromMemory()
		st, _ := rig.c.check.get()
		return r == "r1" && st == RouteCheckOK
	})
}

// A store that cannot be listed is not "nothing imported".
func TestConnectAuto_AnUnreadableStoreIsNotNoRoutes(t *testing.T) {
	rig := newAutoRig(t, autoFourRoutes)
	seedStableRoute(t, rig.c, "r-st")
	breakStore(t, rig.c)
	if _, err := rig.c.store.ListRoutes(); err == nil {
		t.Skip("premise: the store still lists routes")
	}
	res := rig.connectAuto()
	if res.Connected || res.Verdict != AutoVerdictStoreUnreadable {
		t.Fatalf("got %+v", res)
	}
	if len(rig.provedRoutes()) != 0 {
		t.Fatalf("something was started: %v", rig.provedRoutes())
	}
}

// A second engine_connect_auto while the engine is in the middle of
// moving away from a route: if nothing carries, the route it was moving
// away from is still put back.
func TestConnectAuto_DuringAFallOverPassStillPutsTheRouteBack(t *testing.T) {
	rig := newAutoRig(t, autoFourRoutes)
	fastRecheck(rig.c)
	if res := rig.connectAuto(); res.RouteID != "r1" {
		t.Fatalf("got %+v", res)
	}
	rig.fail("r1", deadSYN())
	rig.fail("r3", answeredReset())
	rig.fail("r4", silentUDP())
	var r2calls atomic.Int32
	rig.set("r2", func(ctx context.Context) engine.ProofResult {
		if r2calls.Add(1) == 1 {
			<-ctx.Done() // the fall-over pass, held in its check
			return engine.ProofResult{Cancelled: true}
		}
		return answeredReset()
	})
	rig.c.kickLiveness()
	waitFor(t, "the fall-over pass to be checking r2", func() bool {
		return r2calls.Load() == 1 && autoBlock(t)["trying"] == "r2"
	})
	res := rig.connectAuto()
	if res.Connected {
		t.Fatalf("got %+v", res)
	}
	if got := triedIDs(res.Tried, ""); len(got) == 0 || got[0] != "r1" || res.Tried[0].Why != AutoWhyWasConnected {
		t.Fatalf("the pass did not inherit the lost route: %+v", res.Tried)
	}
	waitFor(t, "r1's instance to be running again", func() bool {
		r, _ := rig.c.activeRouteFromMemory()
		st, _, running := rig.c.check.snapshot()
		return r == "r1" && st == RouteCheckFailed && running && rig.stub.Connected()
	})
}

// engine_shutdown in the middle of a pass: the pass stops there. It
// does not go on to start the next candidate on a core that is gone.
func TestShutdown_DuringAPassStartsNothingMore(t *testing.T) {
	rig := newAutoRig(t, autoFourRoutes)
	rig.set("r1", func(context.Context) engine.ProofResult {
		if err := Shutdown(); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
		// A check that did not notice it was abandoned.
		return deadSYN()
	})
	body, err := ConnectAuto()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, `"verdict":"cancelled"`) {
		t.Fatalf("got %s", body)
	}
	if got := rig.provedRoutes(); !eq(got, []string{"r1"}) {
		t.Fatalf("routes started: %v", got)
	}
	if rig.stub.Connected() {
		t.Fatal("an engine instance is running after engine_shutdown")
	}
}
