package abi

import (
	"testing"

	"daal/core/engine"
	"daal/core/pathmanager"
	"daal/core/routestore"
)

// TestRowToDisplay_Proven asserts the Proven flag mirrors whether the
// route has ever recorded a success. This is what lets the UI show
// "not tested yet" instead of presenting the placeholder 50% health of
// an unproven route as a measured score.
func TestRowToDisplay_Proven(t *testing.T) {
	cases := []struct {
		name        string
		lastSuccess string
		wantProven  bool
	}{
		{"never succeeded", "", false},
		{"blank/whitespace only", "   ", false},
		{"has a success bucket", "2026-08-15T11:00:00Z", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			row := routestore.RouteRow{
				RouteID:           "pub/r1",
				LastSuccessBucket: tc.lastSuccess,
			}
			got := rowToDisplay(row, observeRoute(row, nil))
			if got.Proven != tc.wantProven {
				t.Fatalf("Proven=%v, want %v (LastSuccessBucket=%q)",
					got.Proven, tc.wantProven, tc.lastSuccess)
			}
			// healthPct present ⇔ proven. An unproven route has no
			// success to compute a rate from; the old code answered
			// with a hard-coded 50 (a cap, not a measurement) and two
			// UI surfaces then disagreed about whether to show it.
			if !got.Proven && got.HealthPct != nil {
				t.Fatalf("unproven route has HealthPct=%v; want nil", *got.HealthPct)
			}
		})
	}
}

// TestObserveRoute_NothingMeasuredIsNull is the regression for the
// Wave-1 honesty pass: a route nobody has observed must report null
// for every measured field, NOT a zero/false that renders as a
// confident "0% healthy, not cooled, budget fine".
func TestObserveRoute_NothingMeasuredIsNull(t *testing.T) {
	// Exactly what routestore.PutRoute writes: NULLs and zeroes.
	row := routestore.RouteRow{RouteID: "pub/r1", TransportFamily: "vless-reality"}
	got := rowToDisplay(row, observeRoute(row, nil))
	if got.HealthPct != nil {
		t.Errorf("HealthPct = %v, want nil (no writer has ever set the columns)", *got.HealthPct)
	}
	if got.InCooldown != nil {
		t.Errorf("InCooldown = %v, want nil (never attempted this session)", *got.InCooldown)
	}
	if got.BudgetExhausted != nil {
		t.Errorf("BudgetExhausted = %v, want nil (no budget accounting exists)", *got.BudgetExhausted)
	}
	if got.CooldownUntilUnixMs != 0 {
		t.Errorf("CooldownUntilUnixMs = %d, want 0", got.CooldownUntilUnixMs)
	}
}

// TestObserveRoute_LiveFSMIsAuthoritative: once the pathmanager has
// seen the route, in_cooldown / budget_exhausted stop being null and
// carry the FSM's real answer — including a real `false`.
func TestObserveRoute_LiveFSMIsAuthoritative(t *testing.T) {
	row := routestore.RouteRow{RouteID: "pub/r1"}
	live := map[string]pathmanager.RouteHealth{
		"pub/r1": {RouteID: "pub/r1", InCooldown: false, BudgetExhausted: true},
	}
	got := rowToDisplay(row, observeRoute(row, live))
	if got.InCooldown == nil || *got.InCooldown {
		t.Errorf("InCooldown = %v, want a non-nil false", got.InCooldown)
	}
	if got.BudgetExhausted == nil || !*got.BudgetExhausted {
		t.Errorf("BudgetExhausted = %v, want a non-nil true", got.BudgetExhausted)
	}
	// Health is a DIFFERENT question and still unmeasured.
	if got.HealthPct != nil {
		t.Errorf("HealthPct = %v, want nil — an attempt is not a health score", *got.HealthPct)
	}
}

// TestObserveRoute_DurableHistoryLightsUpHealth: the moment anything
// writes the outcome columns, health becomes a real number without
// any further change to this layer.
func TestObserveRoute_DurableHistoryLightsUpHealth(t *testing.T) {
	row := routestore.RouteRow{
		RouteID:             "pub/r1",
		LastSuccessBucket:   "2026-08-15T11:00:00Z",
		ConsecutiveFailures: 1,
	}
	got := rowToDisplay(row, observeRoute(row, nil))
	if got.HealthPct == nil {
		t.Fatal("HealthPct = nil, want a measured value once history exists")
	}
	if *got.HealthPct != 80 {
		t.Errorf("HealthPct = %v, want 80 (100 - 1×20)", *got.HealthPct)
	}
}

// TestDisplayMaturity_NaiveTracksTheShippedArtifact: `naive` is graded
// Stable by the family table because the transport is field-proven —
// but a given BUILD can only dial it if libcronet.so shipped beside
// the engine, which tools/build-engine-android.sh warns about and
// continues without. The badge must describe the artifact in the
// user's hand, not the family in principle.
//
// This unit build has no naive outbound compiled in at all, so
// loadCronet() records (attempted, !ok) the moment a driver starts —
// but the driver does not start in this test, so the honest answer
// here is "not looked yet" and the table value stands. Both halves
// matter: reporting `unsupported` before we have looked would be the
// same class of fabrication in the other direction.
func TestDisplayMaturity_NaiveTracksTheShippedArtifact(t *testing.T) {
	attempted, ok := engine.CronetStatus()
	got := displayMaturity("naive")
	switch {
	case attempted && !ok:
		if got != routestore.MaturityUnsupported.String() {
			t.Errorf("cronet load failed but naive renders %q", got)
		}
	default:
		if got != routestore.FamilyMaturity("naive").String() {
			t.Errorf("naive renders %q, want the table value %q",
				got, routestore.FamilyMaturity("naive").String())
		}
	}
	// Never widens: a family the table calls unsupported stays so.
	// The exemplar is `amneziawg` — it was `wireguard` until the Wave-5
	// wireguard lane gave SingBoxConfig an `endpoints[]` slot and moved
	// that family to Experimental. amneziawg stays Unsupported for a
	// reason no build flag can change: sing-box 1.13.12 contains no
	// AmneziaWG code at all, so there is nowhere to put the obfuscation
	// parameters that ARE the family.
	if displayMaturity("amneziawg") != routestore.MaturityUnsupported.String() {
		t.Errorf("amneziawg renders %q, want unsupported", displayMaturity("amneziawg"))
	}
	// And no other family consults the cronet state.
	if displayMaturity("vless-reality") != routestore.MaturityStable.String() {
		t.Errorf("vless-reality renders %q, want stable", displayMaturity("vless-reality"))
	}
}

// TestObserveRoute_FailuresAloneDoNotManufactureAScore: the failure
// columns are durable evidence, but they are evidence of failure — a
// success RATE cannot be computed from them. The old code capped such
// a route at a hard-coded 50 and returned it as a measurement, which
// would have rendered "· 50%" on the Routes screen next to
// RouteHealthBars' "not tested yet" for the same route. Nothing writes
// these columns yet (Wave-3), which is exactly why the guard must be
// here before the writer lands.
func TestObserveRoute_FailuresAloneDoNotManufactureAScore(t *testing.T) {
	for _, row := range []routestore.RouteRow{
		{RouteID: "pub/r1", LastFailureBucket: "2026-08-15T11:00:00Z"},
		{RouteID: "pub/r1", ConsecutiveFailures: 3},
		{RouteID: "pub/r1", CooldownUntil: "2099-01-01T00:00:00Z"},
	} {
		got := rowToDisplay(row, observeRoute(row, nil))
		if got.Proven {
			t.Fatalf("row %+v reported Proven", row)
		}
		if got.HealthPct != nil {
			t.Errorf("row %+v: HealthPct = %v, want nil", row, *got.HealthPct)
		}
	}
}

// TestSortByHealthDesc_UnmeasuredSortsLast — unmeasured routes must
// not be ordered as if they scored 0.
func TestSortByHealthDesc_UnmeasuredSortsLast(t *testing.T) {
	low, high := 10.0, 90.0
	rs := []RouteSummaryDisplay{
		{PublisherName: "b", HealthPct: nil},
		{PublisherName: "a", HealthPct: &low},
		{PublisherName: "c", HealthPct: &high},
		{PublisherName: "a", HealthPct: nil},
	}
	sortByHealthDesc(rs)
	want := []string{"c", "a", "a", "b"}
	for i, w := range want {
		if rs[i].PublisherName != w {
			t.Fatalf("order[%d] = %q, want %q (full: %+v)", i, rs[i].PublisherName, w, rs)
		}
	}
	if rs[2].HealthPct != nil || rs[3].HealthPct != nil {
		t.Fatal("the two unmeasured rows must occupy the last two slots")
	}
}
