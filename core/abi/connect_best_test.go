package abi

import (
	"context"
	"testing"
	"time"

	"daal/core/engine"
	"daal/core/netmem"
)

// Moving to the best route once the survey ends (connect_best.go).

// provesIn: the route's connection check through the tunnel's instance
// takes d (its connect's setup time, and every liveness check's).
func provesIn(d time.Duration) func(context.Context) engine.ProofResult {
	return func(context.Context) engine.ProofResult {
		return engine.ProofResult{OK: true, Attempts: 1, Elapsed: d}
	}
}

// bestRig: the survey's waits shortened, every other route's side probe
// timed, and an automatic connect on r1 whose own proof took r1Proof.
func bestRig(t *testing.T, r1Proof time.Duration, side map[string]time.Duration) *raceRig {
	t.Helper()
	rig := surveyRig(t, 5*time.Millisecond)
	rig.sideIn("r1", r1Proof) // the race's probe, which wins the connect
	rig.set("r1", provesIn(r1Proof))
	for id, d := range side {
		rig.sideIn(id, d)
	}
	return rig
}

func waitActive(t *testing.T, rig *raceRig, want string) {
	t.Helper()
	waitFor(t, "the tunnel on "+want, func() bool {
		r, _ := rig.c.activeRouteFromMemory()
		st, _ := rig.c.check.get()
		return r == want && st == RouteCheckOK
	})
}

// The survey finds a route that sets up in a fraction of the running
// route's time: the engine moves to it ONCE, without probing it again,
// says moved_faster, and holds.
func TestBest_MovesOnceToAClearlyFasterRouteWhenTheSurveyEnds(t *testing.T) {
	rig := bestRig(t, time.Second, map[string]time.Duration{
		"r2": 700 * time.Millisecond, "r3": 650 * time.Millisecond,
		"r4": 100 * time.Millisecond, "r5": 300 * time.Millisecond,
	})
	lc := captureLog(t)
	connectOnR1(t, rig)
	waitActive(t, rig, "r4")
	if !lc.has("survey done trigger=auto checked=4") {
		t.Fatalf("moved before the survey was over: %v", lc.all())
	}
	a := autoBlock(t)
	if a["state"] != AutoStateConnected || a["mode"] != true || a["route_id"] != "r4" || a["verdict"] != AutoVerdictMovedFaster {
		t.Fatalf("auto block: %v", a)
	}
	tried := a["tried"].([]any)
	left, to := tried[0].(map[string]any), tried[len(tried)-1].(map[string]any)
	if left["route_id"] != "r1" || left["why"] != AutoWhyWasConnected || left["category"] != "" ||
		to["route_id"] != "r4" || to["setup_ms"] != float64(100) {
		t.Fatalf("tried: %v", tried)
	}
	if !lc.has("auto best move from=r1 to=r4") || !lc.has("auto moved_faster from=r1 to=r4") {
		t.Fatalf("log: %v", lc.all())
	}
	// The survey's check was the proof: r4 was side-probed once (by the
	// survey), not again for the move.
	n := 0
	for _, id := range rig.sideProbed() {
		if id == "r4" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("r4 side-probed %d times; the survey's check is the proof", n)
	}

	// Once per connect: the connect's next survey (and the person's
	// button) finding something even better does not move it again.
	rig.sideIn("r5", 10*time.Millisecond)
	rig.c.mu.Lock()
	rig.c.side = sideLimits{}
	rig.c.speed.holdUntil = time.Time{} // the once-per-connect rule alone
	rig.c.mu.Unlock()
	if _, err := SurveyRoutes(true); err != nil {
		t.Fatal(err)
	}
	b := surveyOver(t)
	if b["trigger"] != "user" || b["state"] != SurveyDone {
		t.Fatalf("premise: %v", b)
	}
	time.Sleep(50 * time.Millisecond)
	if r, _ := rig.c.activeRouteFromMemory(); r != "r4" {
		t.Fatalf("moved a second time in one connect, to %s", r)
	}
}

// A route a little faster is not clearly better: the engine stays, and
// sends nothing more.
func TestBest_StaysWhenNothingIsClearlyBetter(t *testing.T) {
	rig := bestRig(t, time.Second, map[string]time.Duration{
		"r2": 700 * time.Millisecond, "r3": 650 * time.Millisecond,
		"r4": 610 * time.Millisecond, "r5": 900 * time.Millisecond,
	})
	lc := captureLog(t)
	connectOnR1(t, rig)
	surveyOver(t)
	waitFor(t, "the comparison", func() bool { return lc.has("auto best stay route=r1 reason=none_clearly_better") })
	probes := len(rig.sideProbed())
	time.Sleep(50 * time.Millisecond)
	if r, _ := rig.c.activeRouteFromMemory(); r != "r1" {
		t.Fatalf("moved to %s; 610 ms is not at most %d%% of 1000 ms", r, bestMoveFactorPct)
	}
	if got := len(rig.sideProbed()); got != probes {
		t.Fatalf("%d side probe(s) after the comparison", got-probes)
	}
	if a := autoBlock(t); a["verdict"] == AutoVerdictMovedFaster {
		t.Fatalf("auto block: %v", a)
	}
}

// The running route is graded worse here than another that proved now:
// that is clearly better too, even short of the time factor.
func TestBest_MovesWhenTheRunningRouteIsGradedWorse(t *testing.T) {
	rig := bestRig(t, 2000*time.Millisecond, map[string]time.Duration{
		"r2": 1400 * time.Millisecond, "r3": 4500 * time.Millisecond,
		"r4": 4500 * time.Millisecond, "r5": 4500 * time.Millisecond,
	})
	// The survey waits for its first check until r1's grade is set.
	shortSurveyWaits(t, 300*time.Millisecond)
	connectOnR1(t, rig)
	// r1 has set up in 2.5 s here, again and again: "ok", not "good".
	for i := 0; i < 6; i++ {
		rig.c.rememberOutcome("r1", netmem.RouteOutcome{Carried: true, HasSetup: true, SetupMs: 2500})
	}
	if g := rig.c.routeMemory()["r1"].Grade(); g != netmem.GradeOK {
		t.Fatalf("premise: r1 is %q here", g)
	}
	waitActive(t, rig, "r2")
	if a := autoBlock(t); a["verdict"] != AutoVerdictMovedFaster || a["route_id"] != "r2" {
		t.Fatalf("auto block: %v", a)
	}
}

// A route picked by hand is never left, however much better another is.
func TestBest_NeverLeavesARoutePickedByHand(t *testing.T) {
	rig := bestRig(t, time.Second, map[string]time.Duration{
		"r2": 50 * time.Millisecond, "r3": 50 * time.Millisecond,
		"r4": 50 * time.Millisecond, "r5": 50 * time.Millisecond,
	})
	lc := captureLog(t)
	if err := SetRoute("r1"); err != nil {
		t.Fatal(err)
	}
	b := surveyOver(t)
	if b["state"] != SurveyDone {
		t.Fatalf("premise: %v", b)
	}
	time.Sleep(50 * time.Millisecond)
	if r, _ := rig.c.activeRouteFromMemory(); r != "r1" {
		t.Fatalf("left the route picked by hand for %s", r)
	}
	if lc.has("auto best move") || lc.has("auto moved_faster") {
		t.Fatalf("log: %v", lc.all())
	}
}

// The hand-over fails: the route is charged, and the one the person was
// on is put back as it was (ok, not degraded), never charged.
func TestBest_AFailedHandOverPutsTheRouteBack(t *testing.T) {
	rig := bestRig(t, time.Second, map[string]time.Duration{
		"r2": 700 * time.Millisecond, "r3": 700 * time.Millisecond,
		"r4": 100 * time.Millisecond, "r5": 700 * time.Millisecond,
	})
	lc := captureLog(t)
	rig.fail("r4", deadSYN())
	connectOnR1(t, rig)
	waitFor(t, "the move to have been tried and undone", func() bool { return lc.has("auto best back route=r1") })
	waitActive(t, rig, "r1")
	row, err := rig.c.store.GetRoute("r1")
	if err != nil {
		t.Fatal(err)
	}
	if row.ConsecutiveFailures != 0 || row.LastDegradedCategory != "" {
		t.Fatalf("r1 was charged for the detour: %+v", row)
	}
	if !lc.has("auto resume route=r1 family=vless-reality result=running state=ok") {
		t.Fatalf("log: %v", lc.all())
	}
}

// The next connect on the same network starts with the route this
// network's memory grades best — not with whichever was checked last.
func TestBest_TheNextConnectStartsWithTheBest(t *testing.T) {
	rig := bestRig(t, time.Second, map[string]time.Duration{
		"r2": 700 * time.Millisecond, "r3": 650 * time.Millisecond,
		"r4": 610 * time.Millisecond, "r5": 900 * time.Millisecond,
	})
	connectOnR1(t, rig)
	surveyOver(t)
	if err := ClearRoute(); err != nil {
		t.Fatal(err)
	}
	// r5 was checked last (the survey goes in the pass's order) and r1
	// carried most recently (the connect); r4 set up fastest here, r1
	// slowest.
	rig.c.mu.Lock()
	cands, _, _, err := rig.c.autoCandidatesLocked("")
	rig.c.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, cd := range cands {
		order = append(order, cd.routeID)
	}
	want := []string{"r4", "r3", "r2", "r5", "r1"}
	if len(order) != len(want) {
		t.Fatalf("order %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("order %v, want %v", order, want)
		}
	}
	for _, cd := range cands {
		if cd.why != AutoWhyCarriedHere {
			t.Fatalf("%s: why %q", cd.routeID, cd.why)
		}
	}
}

// Best first, by the memory alone: a route graded good comes before one
// that carried more recently but is graded ok; between two good routes
// the faster setup goes first.
func TestBest_RememberedRoutesAreOrderedBestFirst(t *testing.T) {
	setClock(t, time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC))
	rig := newRaceRig(t, raceRoutes)
	rem := func(id string, ms int) {
		rig.c.rememberOutcome(id, netmem.RouteOutcome{Carried: true, HasSetup: true, SetupMs: ms})
	}
	rem("r4", 900)
	rem("r2", 400)
	rem("r5", 3000) // ok
	rem("r1", 1200)
	rem("r5", 3000) // the most recent, and ok
	rig.c.mu.Lock()
	cands, _, _, err := rig.c.autoCandidatesLocked("")
	rig.c.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, cd := range cands {
		order = append(order, cd.routeID)
	}
	want := []string{"r2", "r4", "r1", "r5", "r3"}
	for i := range want {
		if i >= len(order) || order[i] != want[i] {
			t.Fatalf("order %v, want %v (r3: never tried here)", order, want)
		}
	}
}
