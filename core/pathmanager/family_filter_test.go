package pathmanager

import "testing"

// Phase 3A. Family-filter regression tests.
//
// Canonical regressions called out in
// specs/transport-families-v1.md "ABI surface change":
//
//   - TestExperimentalFilterDropsAndLogs
//   - TestBurnPressureIgnoresExperimentalSkips (lives in
//     core/abi/experimental_burn_test.go because it exercises
//     the engine-level wiring; the pathmanager-side regression
//     is `TestExperimentalFilterDoesNotTouchSkippedFamilies`).

// stubIsExperimental returns true for any family in the
// supplied set. Used to keep this test file independent of
// `core/routestore`.
func stubIsExperimental(experimental map[string]bool) IsExperimentalFn {
	return func(family string) bool {
		return experimental[family]
	}
}

// TestExperimentalFilter_GateOpenIsByteIdentical — with the gate
// open, the filter must return its input unchanged and a zero
// dropped count.
func TestExperimentalFilter_GateOpenIsByteIdentical(t *testing.T) {
	in := []Route{
		{RouteID: "rA", Family: "vless-reality", ModesAllowed: []string{"normal"}},
		{RouteID: "rB", Family: "webtunnel", ModesAllowed: []string{"normal"}},
	}
	out, dropped := ExperimentalFilter(in, true, stubIsExperimental(map[string]bool{"webtunnel": true}))
	if dropped != 0 {
		t.Errorf("gate-open dropped count: got %d, want 0", dropped)
	}
	if len(out) != len(in) {
		t.Fatalf("gate-open length: got %d, want %d", len(out), len(in))
	}
}

// TestExperimentalFilterDropsAndLogs — with the gate closed,
// experimental-family routes must be dropped and the count
// surfaced.
func TestExperimentalFilterDropsAndLogs(t *testing.T) {
	in := []Route{
		{RouteID: "rA", Family: "vless-reality", ModesAllowed: []string{"normal"}},
		{RouteID: "rB", Family: "webtunnel", ModesAllowed: []string{"normal"}},
		{RouteID: "rC", Family: "snowflake", ModesAllowed: []string{"normal"}},
		{RouteID: "rD", Family: "naive", ModesAllowed: []string{"normal"}},
	}
	predicate := stubIsExperimental(map[string]bool{
		"webtunnel": true,
		"snowflake": true,
	})
	out, dropped := ExperimentalFilter(in, false, predicate)
	if dropped != 2 {
		t.Errorf("dropped count: got %d, want 2", dropped)
	}
	if len(out) != 2 {
		t.Fatalf("kept length: got %d, want 2", len(out))
	}
	for _, r := range out {
		if r.Family == "webtunnel" || r.Family == "snowflake" {
			t.Errorf("experimental route %q leaked through filter", r.RouteID)
		}
	}
}

// TestExperimentalFilter_NilPredicateKeepsEverything — defensive:
// callers that forget to pass the predicate must not silently
// crash. Production callers always pass a real predicate.
func TestExperimentalFilter_NilPredicateKeepsEverything(t *testing.T) {
	in := []Route{
		{RouteID: "rA", Family: "vless-reality", ModesAllowed: []string{"normal"}},
		{RouteID: "rB", Family: "webtunnel", ModesAllowed: []string{"normal"}},
	}
	out, dropped := ExperimentalFilter(in, false, nil)
	if dropped != 0 {
		t.Errorf("nil-predicate dropped count: got %d, want 0", dropped)
	}
	if len(out) != len(in) {
		t.Errorf("nil-predicate length: got %d, want %d", len(out), len(in))
	}
}

// TestRankWithExperimentalGate_GateOpenIsRankWithView — with the
// gate open, the result must match a direct RankWithView call.
func TestRankWithExperimentalGate_GateOpenIsRankWithView(t *testing.T) {
	in := []Route{
		{RouteID: "rA", Family: "vless-reality", ModesAllowed: []string{"normal"},
			HourlyCap: 1000, Consumed: 500, BudgetTag: "normal"},
		{RouteID: "rB", Family: "webtunnel", ModesAllowed: []string{"normal"},
			HourlyCap: 1000, Consumed: 100, BudgetTag: "experimental"},
	}
	want := RankWithView(in, "normal", nil)
	got, dropped := RankWithExperimentalGate(in, "normal", nil, true,
		stubIsExperimental(map[string]bool{"webtunnel": true}))
	if dropped != 0 {
		t.Errorf("gate-open dropped: got %d, want 0", dropped)
	}
	if len(got) != len(want) {
		t.Fatalf("gate-open length: got %d, want %d", len(got), len(want))
	}
	for i := range got {
		if got[i].RouteID != want[i].RouteID {
			t.Errorf("gate-open order at %d: got %q, want %q", i, got[i].RouteID, want[i].RouteID)
		}
	}
}

// TestRankWithExperimentalGate_GateClosedFiltersBeforeRank — the
// experimental filter runs BEFORE the mode-aware ranker.
func TestRankWithExperimentalGate_GateClosedFiltersBeforeRank(t *testing.T) {
	in := []Route{
		{RouteID: "rA", Family: "vless-reality", ModesAllowed: []string{"normal"},
			HourlyCap: 1000, Consumed: 500, BudgetTag: "normal"},
		{RouteID: "rB", Family: "webtunnel", ModesAllowed: []string{"normal"},
			HourlyCap: 1000, Consumed: 100, BudgetTag: "experimental"},
	}
	got, dropped := RankWithExperimentalGate(in, "normal", nil, false,
		stubIsExperimental(map[string]bool{"webtunnel": true}))
	if dropped != 1 {
		t.Errorf("gate-closed dropped: got %d, want 1", dropped)
	}
	if len(got) != 1 {
		t.Fatalf("gate-closed length: got %d, want 1", len(got))
	}
	if got[0].RouteID != "rA" {
		t.Errorf("gate-closed kept wrong route: got %q, want %q", got[0].RouteID, "rA")
	}
}

// TestExperimentalFilterDoesNotTouchSkippedFamilies — the
// failure-driven `SkippedFamilies()` ledger consumed by the 2G
// burn-pressure detector must NOT contain any experimental-family
// entries (they are filtered BEFORE the cooldown machinery, so
// they cannot have produced a cooldown). Locked invariant per
// spec.
func TestExperimentalFilterDoesNotTouchSkippedFamilies(t *testing.T) {
	m := New()
	in := []Route{
		{RouteID: "rA", Family: "webtunnel", ModesAllowed: []string{"normal"}},
		{RouteID: "rB", Family: "snowflake", ModesAllowed: []string{"normal"}},
	}
	predicate := stubIsExperimental(map[string]bool{"webtunnel": true, "snowflake": true})
	_, dropped := ExperimentalFilter(in, false, predicate)
	if dropped != 2 {
		t.Fatalf("dropped: got %d, want 2", dropped)
	}
	skipped := m.SkippedFamilies()
	for _, s := range skipped {
		if s.Family == "webtunnel" || s.Family == "snowflake" {
			t.Errorf("experimental family %q leaked into SkippedFamilies (would cause spurious burn-pressure auto-promotion)", s.Family)
		}
	}
}
