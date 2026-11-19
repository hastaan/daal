package abi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"daal/core/engine"
	"daal/core/netmem"
)

// Measurement: what the engine remembers about how each route does on
// this network (core/netmem/measure.go), who feeds it, and where it is
// read.

func took(d time.Duration) func(context.Context) engine.ProofResult {
	return func(context.Context) engine.ProofResult {
		return engine.ProofResult{OK: true, Attempts: 1, Elapsed: d}
	}
}

func measuredOf(t *testing.T, routeID string) netmem.Measured {
	t.Helper()
	body, err := RouteSummary(routeID)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Measured *netmem.Measured `json:"measured"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil || out.Measured == nil {
		t.Fatalf("route_summary has no `measured` object: %s (%v)", body, err)
	}
	return *out.Measured
}

// An automatic connect, a connect by hand and the liveness check all
// write the same record; the route listing and the pass's own answer
// read it.
func TestMeasure_AutoManualAndLivenessFeedTheSameMemory(t *testing.T) {
	at := time.Date(2026, 11, 19, 14, 37, 12, 0, time.UTC)
	setClock(t, at)
	rig := newAutoRig(t, autoFourRoutes)
	fastRecheck(rig.c)

	// Nothing yet: every row is "unknown", and says so as an object.
	if m := measuredOf(t, "r1"); m != (netmem.Measured{Grade: netmem.GradeUnknown}) {
		t.Fatalf("before anything was tried: %+v", m)
	}

	// Automatic: r1 fails (answered), r2 carries in 640 ms.
	rig.fail("r1", answeredReset())
	rig.set("r2", took(640*time.Millisecond))
	res := rig.connectAuto()
	if !res.Connected || res.RouteID != "r2" {
		t.Fatalf("got %+v", res)
	}
	if w := res.Tried[1]; w.RouteID != "r2" || w.SetupMs != 640 {
		t.Fatalf("the answer's tried[] must carry this attempt's setup_ms: %+v", res.Tried)
	}
	if f := res.Tried[0]; f.SetupMs != 0 {
		t.Fatalf("a route that did not carry has no setup time: %+v", f)
	}
	tried := autoBlock(t)["tried"].([]any)
	if e := tried[1].(map[string]any); e["setup_ms"] != float64(640) || e["raced_with"] != "" {
		t.Fatalf("the auto block's tried[]: %v", tried)
	}
	m2 := measuredOf(t, "r2")
	if m2.Grade != netmem.GradeGood || m2.SetupMs != 640 || m2.Samples != 1 || m2.Carried != 1 || m2.Failed != 0 {
		t.Fatalf("r2 after an automatic connect: %+v", m2)
	}
	if m2.Last != at.Truncate(time.Hour).Unix() {
		t.Fatalf("last = %d: must be the hour bucket %d, never the minute", m2.Last, at.Truncate(time.Hour).Unix())
	}
	if m1 := measuredOf(t, "r1"); m1.Grade != netmem.GradeFailing || m1.Failed != 1 || m1.Carried != 0 || m1.Samples != 0 {
		t.Fatalf("r1 after failing: %+v", m1)
	}

	// The liveness check: slow twice in a row is "slow"; a check that
	// finds the route simply still fine writes nothing.
	rig.set("r2", func(context.Context) engine.ProofResult {
		return engine.ProofResult{OK: true, Attempts: 1, Elapsed: 3 * time.Second, Slow: true}
	})
	if _, err := CheckActiveRoute(); err != nil {
		t.Fatal(err)
	}
	if m := measuredOf(t, "r2"); m.Grade != netmem.GradeGood || m.Carried != 2 || m.Samples != 1 {
		t.Fatalf("after one slow check (not a setup sample, and one check flips nothing): %+v", m)
	}
	if _, err := CheckActiveRoute(); err != nil {
		t.Fatal(err)
	}
	if m := measuredOf(t, "r2"); m.Grade != netmem.GradeSlow || m.Carried != 3 || m.SetupMs != 640 {
		t.Fatalf("after two slow checks: %+v", m)
	}
	// It stops carrying: the liveness failure is a failure here.
	rig.fail("r2", answeredReset())
	rig.fail("r3", answeredReset())
	rig.fail("r4", answeredReset())
	if _, err := CheckActiveRoute(); err != nil {
		t.Fatal(err)
	}
	if m := measuredOf(t, "r2"); m.Failed != 1 {
		t.Fatalf("after a failed liveness check: %+v", m)
	}
	_ = ClearRoute()
	clearCooldowns(rig.c)

	// By hand: the same record, a second sample.
	rig.set("r2", took(1040*time.Millisecond))
	if err := SetRoute("r2"); err != nil {
		t.Fatal(err)
	}
	m2 = measuredOf(t, "r2")
	if m2.Samples != 2 || m2.SetupMs != 760 || m2.Carried != 4 || m2.Grade != netmem.GradeGood {
		t.Fatalf("r2 after a connect by hand (640 then 1040 → 760 smoothed): %+v", m2)
	}
	// The whole listing carries it too.
	body, err := AvailableRoutes()
	if err != nil {
		t.Fatal(err)
	}
	var list struct {
		Routes []struct {
			RouteID  string           `json:"route_id"`
			Measured *netmem.Measured `json:"measured"`
		} `json:"routes"`
	}
	if err := json.Unmarshal([]byte(body), &list); err != nil {
		t.Fatal(err)
	}
	for _, r := range list.Routes {
		if r.Measured == nil {
			t.Fatalf("route %s has no `measured` in the listing: %s", r.RouteID, body)
		}
		if r.RouteID == "r2" && *r.Measured != m2 {
			t.Fatalf("the listing says %+v, the summary %+v", *r.Measured, m2)
		}
		if r.RouteID == "r3" && r.Measured.Grade != netmem.GradeUnknown && r.Measured.Carried != 0 {
			t.Fatalf("r3: %+v", *r.Measured)
		}
	}
	if len(list.Routes) != 4 {
		t.Fatalf("listing: %s", body)
	}
}

// The measurement is per network, survives a restart, is forgotten with
// the route and removed by the panic wipe — and reading it writes
// nothing.
func TestMeasure_PerNetworkPersistedWipedAndNeverWrittenByAPoll(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "daal-state")
	rig := newAutoRigIn(t, dir, autoFourRoutes)
	facts(t, NetKindWiFi, "home", 1, 0)
	rig.set("r1", took(2300*time.Millisecond))
	if res := rig.connectAuto(); res.RouteID != "r1" {
		t.Fatalf("got %+v", res)
	}
	home := measuredOf(t, "r1")
	if home.Grade != netmem.GradeOK || home.SetupMs != 2300 {
		t.Fatalf("r1 at home: %+v", home)
	}

	// Polled reads leave the stored record byte-identical.
	key := "netmem:" + activeNetworkID()
	before, err := rig.c.store.GetSecret(key)
	if err != nil || !strings.Contains(string(before), `"setup_ms"`) {
		t.Fatalf("premise: the measurement is stored: %q %v", before, err)
	}
	for i := 0; i < 3; i++ {
		_, _ = RouteSummary("r1")
		_, _ = AvailableRoutes()
		_, _ = ExportDiagnostics()
		_, _ = DiagnosticsExplain()
		rig.set("r1", nil)
		_, _ = CheckActiveRoute()
		facts(t, NetKindWiFi, "home", 1, 0)
	}
	after, _ := rig.c.store.GetSecret(key)
	if string(after) != string(before) {
		t.Fatalf("a read path rewrote the measurement:\n before %s\n after  %s", before, after)
	}

	// Another network knows nothing of it; back home it is there.
	facts(t, NetKindCellular, "operator-1", 1, 1)
	if m := measuredOf(t, "r1"); m.Grade != netmem.GradeUnknown || m.Samples != 0 {
		t.Fatalf("r1 on another network: %+v", m)
	}
	facts(t, NetKindWiFi, "home", 1, 0)
	if m := measuredOf(t, "r1"); m != home {
		t.Fatalf("r1 back home: %+v, was %+v", m, home)
	}

	// A restart.
	if err := Shutdown(); err != nil {
		t.Fatal(err)
	}
	rig = newAutoRigIn(t, dir, nil)
	facts(t, NetKindWiFi, "home", 1, 0)
	if m := measuredOf(t, "r1"); m != home {
		t.Fatalf("r1 after a restart: %+v, was %+v", m, home)
	}

	// Deleting the route forgets its measurement.
	if err := RouteDelete("r1"); err != nil {
		t.Fatal(err)
	}
	if _, ok := rig.c.routeMemory()["r1"]; ok {
		t.Fatal("a deleted route is still measured")
	}

	// The panic wipe removes all of it.
	rig.set("r2", took(500*time.Millisecond))
	if res := rig.connectAuto(); res.RouteID != "r2" {
		t.Fatalf("got %+v", res)
	}
	if err := PanicWipe(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("state dir after a panic wipe: %v", err)
	}
	rig = newAutoRigIn(t, dir, autoFourRoutes)
	facts(t, NetKindWiFi, "home", 1, 0)
	if m := measuredOf(t, "r2"); m != (netmem.Measured{Grade: netmem.GradeUnknown}) {
		t.Fatalf("a measurement survived the panic wipe: %+v", m)
	}
}

// The grade shown does not flip on one sample, end to end: three good
// connects, one terrible one, and the row still says good.
func TestMeasure_OneBadConnectDoesNotFlipTheGrade(t *testing.T) {
	rig := newAutoRig(t, autoFourRoutes)
	connect := func(d time.Duration) {
		t.Helper()
		rig.set("r1", took(d))
		if err := SetRoute("r1"); err != nil {
			t.Fatal(err)
		}
		_ = ClearRoute()
	}
	connect(300 * time.Millisecond)
	connect(350 * time.Millisecond)
	connect(280 * time.Millisecond)
	connect(9 * time.Second)
	if m := measuredOf(t, "r1"); m.Grade != netmem.GradeGood || m.Samples != 4 {
		t.Fatalf("after one 9 s connect: %+v", m)
	}
	connect(8 * time.Second)
	if m := measuredOf(t, "r1"); m.Grade != netmem.GradeSlow {
		t.Fatalf("after two slow connects in a row: %+v", m)
	}
}
