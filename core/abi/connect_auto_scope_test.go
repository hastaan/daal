package abi

import (
	"context"
	"testing"
	"time"

	"daal/core/engine"
)

// "Connect with this file" (connect_auto_scope.go): the automatic
// connect over one file's routes, no manual pin, the scope's life.

func inSet(id string, set ...string) bool {
	for _, s := range set {
		if s == id {
			return true
		}
	}
	return false
}

func armScope(t *testing.T, json string) int {
	t.Helper()
	n, err := SetAutoScope(json)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// The pass chooses among the file's routes only, the engine is in
// automatic mode (no pin), and a fall-over stays inside the file.
func TestAutoScope_ChoosesWithinTheFile(t *testing.T) {
	rig := newAutoRig(t, autoFourRoutes)
	fastRecheck(rig.c)
	if n := armScope(t, `["r3","r4","gone"]`); n != 2 {
		t.Fatalf("known %d", n)
	}
	res := rig.connectAuto()
	if !res.Connected || !inSet(res.RouteID, "r3", "r4") || res.Candidates != 2 {
		t.Fatalf("got %+v", res)
	}
	for _, tr := range res.Tried {
		if !inSet(tr.RouteID, "r3", "r4") {
			t.Fatalf("a route of another file was listed: %+v", res.Tried)
		}
	}
	a := autoBlock(t)
	if a["mode"] != true || a["scoped"] != true || a["state"] != AutoStateConnected {
		t.Fatalf("auto block: %v", a)
	}
	// The connected route stops carrying: the other route of the file,
	// never r1 or r2.
	first := res.RouteID
	other := "r4"
	if first == "r4" {
		other = "r3"
	}
	rig.fail(first, deadSYN())
	rig.c.kickLiveness()
	waitFor(t, "the engine to move to the file's other route", func() bool {
		r, _ := rig.c.activeRouteFromMemory()
		st, _ := rig.c.check.get()
		as, _ := rig.c.auto.snapshot()
		return r == other && st == RouteCheckOK && as == AutoStateConnected
	})
	for _, id := range rig.provedRoutes() {
		if !inSet(id, "r3", "r4") {
			t.Fatalf("route %s of another file was started", id)
		}
	}
}

// The scope is for the next connect only: a disconnect ends it, and
// the main button's connect after it chooses among every route.
func TestAutoScope_EndsWithTheConnect(t *testing.T) {
	rig := newAutoRig(t, autoFourRoutes)
	armScope(t, `["r4"]`)
	if res := rig.connectAuto(); !res.Connected || res.RouteID != "r4" {
		t.Fatalf("got %+v", res)
	}
	if err := ClearRoute(); err != nil {
		t.Fatal(err)
	}
	if a := autoBlock(t); a["scoped"] != false {
		t.Fatalf("a disconnect kept the scope: %v", a)
	}
	res := rig.connectAuto()
	if !res.Connected || res.Candidates != 4 {
		t.Fatalf("unscoped connect after the scope: %+v", res)
	}

	// A route picked by hand ends it too.
	_ = ClearRoute()
	armScope(t, `["r3"]`)
	rig.connectAuto()
	if err := SetRoute("r1"); err != nil {
		t.Fatal(err)
	}
	if a := autoBlock(t); a["scoped"] != false || a["mode"] != false {
		t.Fatalf("a manual pick kept the scope: %v", a)
	}

	// "[]" disarms; an arm older than the TTL is not used.
	_ = ClearRoute()
	armScope(t, `["r3"]`)
	armScope(t, `[]`)
	if res := rig.connectAuto(); res.Candidates != 4 {
		t.Fatalf("a disarmed scope was used: %+v", res)
	}
	_ = ClearRoute()
	armScope(t, `["r3"]`)
	rig.c.mu.Lock()
	rig.c.auto.pendingAt = nowUTC().Add(-autoScopeArmTTL - time.Second)
	rig.c.mu.Unlock()
	if res := rig.connectAuto(); res.Candidates != 4 {
		t.Fatalf("a stale arm was used: %+v", res)
	}
}

// Connected and carrying on a route of ANOTHER file: the call runs a
// pass over this file; on a route of this file it takes charge.
func TestAutoScope_ConnectedElsewhere(t *testing.T) {
	rig := newAutoRig(t, autoFourRoutes)
	if err := SetRoute("r1"); err != nil {
		t.Fatal(err)
	}
	armScope(t, `["r2"]`)
	res := rig.connectAuto()
	if !res.Connected || res.RouteID != "r2" || res.AlreadyConnected {
		t.Fatalf("got %+v", res)
	}
	n := rig.stub.ProofCount()
	armScope(t, `["r2","r3"]`)
	again := rig.connectAuto()
	if !again.AlreadyConnected || again.RouteID != "r2" || rig.stub.ProofCount() != n {
		t.Fatalf("again %+v", again)
	}
	if a := autoBlock(t); a["mode"] != true || a["scoped"] != true {
		t.Fatalf("auto block: %v", a)
	}
}

// Input checks.
func TestAutoScope_Input(t *testing.T) {
	newAutoRig(t, autoFourRoutes)
	if _, err := SetAutoScope(`{"r1":true}`); err == nil {
		t.Fatal("an object was taken")
	}
	if n, err := SetAutoScope(""); err != nil || n != 0 {
		t.Fatalf("empty: %d %v", n, err)
	}
	if n := armScope(t, `["nope"]`); n != 0 {
		t.Fatalf("unknown ids counted: %d", n)
	}
}

// Carrying on a route of ANOTHER file, and no route of this file
// carries: the candidate was tried through the tunnel's own instance,
// which stopped the route the person had. That route is put back and
// the automatic connect takes charge of it; the scope ends. The answer
// is the pass's (Connected false, its verdict).
func TestAutoScope_ConnectedElsewhereNothingCarriesPutsTheRouteBack(t *testing.T) {
	rig := newAutoRig(t, autoFourRoutes)
	if err := SetRoute("r1"); err != nil {
		t.Fatal(err)
	}
	rig.fail("r2", resetHello())
	armScope(t, `["r2"]`)
	res := rig.connectAuto()
	if res.Connected || res.Verdict == "" || res.Verdict == AutoVerdictCancelled {
		t.Fatalf("got %+v", res)
	}
	if got := rig.provedRoutes(); !inSet("r2", got...) {
		t.Fatalf("premise: r2 was not tried through the instance: %v", got)
	}
	if r, _ := rig.c.activeRouteFromMemory(); r != "r1" {
		t.Fatalf("active %q, want r1 put back", r)
	}
	rig.c.mu.Lock()
	running := rig.c.routeRunningLocked("r1")
	rig.c.mu.Unlock()
	if !running {
		t.Fatal("r1 is not running")
	}
	a := autoBlock(t)
	if a["mode"] != true || a["scoped"] != false || a["state"] != AutoStateConnected || a["route_id"] != "r1" || a["verdict"] != res.Verdict {
		t.Fatalf("auto block: %v", a)
	}
}

// The scope's life: a scoped pass that finds nothing in the file ends
// the scope, and the next connect with nothing armed lists every route.
func TestAutoScope_EndsWhenTheFileHasNothing(t *testing.T) {
	rig := newAutoRig(t, autoFourRoutes)
	rig.fail("r3", resetHello())
	armScope(t, `["r3"]`)
	if res := rig.connectAuto(); res.Connected {
		t.Fatalf("got %+v", res)
	}
	if a := autoBlock(t); a["scoped"] != false {
		t.Fatalf("a failed scoped pass kept the scope: %v", a)
	}
	rig.c.mu.Lock()
	kept := rig.c.auto.scope != nil
	rig.c.mu.Unlock()
	if kept {
		t.Fatal("scope kept")
	}
	res := rig.connectAuto()
	if !res.Connected || res.RouteID == "r3" || (res.Candidates != 4 && res.Candidates != 3) {
		t.Fatalf("unscoped connect after the scope: %+v", res)
	}

	// A scope with no candidates at all ends too.
	_ = ClearRoute()
	armScope(t, `["gone"]`)
	if res := rig.connectAuto(); res.Connected || res.Candidates != 0 {
		t.Fatalf("got %+v", res)
	}
	rig.c.mu.Lock()
	kept = rig.c.auto.scope != nil
	rig.c.mu.Unlock()
	if kept {
		t.Fatal("a pass with no candidates kept the scope")
	}
}

// The person's own "check all routes" checks every route, also while a
// scope limits the automatic connect.
func TestAutoScope_UserSurveyListsEveryRoute(t *testing.T) {
	rig := surveyRig(t, time.Hour)
	for _, id := range []string{"r1", "r2", "r3", "r4", "r5"} {
		rig.sideSet(id, func(ctx context.Context) (engine.ProofResult, error) {
			return engine.ProofResult{OK: true, Attempts: 1, Elapsed: 100 * time.Millisecond}, nil
		})
	}
	rig.c.mu.Lock()
	rig.c.setAutoScopeLocked(map[string]bool{"r1": true})
	rig.c.mu.Unlock()
	if _, err := SurveyRoutes(true); err != nil {
		t.Fatal(err)
	}
	b := surveyOver(t)
	res := surveyResults(b)
	for _, id := range []string{"r1", "r2", "r3", "r4", "r5"} {
		if res[id] == nil {
			t.Fatalf("%s missing from the person's survey: %v", id, b)
		}
	}
	rig.c.mu.Lock()
	kept := rig.c.auto.scope["r1"] && len(rig.c.auto.scope) == 1
	rig.c.mu.Unlock()
	if !kept {
		t.Fatal("the survey changed the scope")
	}
}
