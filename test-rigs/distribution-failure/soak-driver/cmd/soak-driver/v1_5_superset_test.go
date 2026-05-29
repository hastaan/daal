package main

import (
	"path/filepath"
	"sort"
	"testing"
)

// TestV1_5SupersetCount locks the FRP-7 v1-5-superset whitelist
// size at **6** scenarios. Any change to this count requires a
// roadmap amendment (specs/v1-5-closure-v1.md and
// specs/blackout-soak-rig-v1.md).
func TestV1_5SupersetCount(t *testing.T) {
	scenarioDir := filepath.Join("..", "..", "..", "scenarios")
	got, err := loadScenarios(scenarioDir, "v1-5-superset")
	if err != nil {
		t.Fatalf("loadScenarios v1-5-superset: %v", err)
	}
	if len(got) != 6 {
		t.Errorf("v1-5-superset size = %d, want 6", len(got))
		for _, s := range got {
			t.Logf("  selected: %s", s.ID)
		}
	}
}

// TestV1_5SupersetExactIDs asserts the v1-5-superset selector
// returns exactly the 6 named scenarios (and nothing else). This
// guards against accidental scenario-id renames and against
// silent membership drift.
func TestV1_5SupersetExactIDs(t *testing.T) {
	scenarioDir := filepath.Join("..", "..", "..", "scenarios")
	got, err := loadScenarios(scenarioDir, "v1-5-superset")
	if err != nil {
		t.Fatalf("loadScenarios v1-5-superset: %v", err)
	}
	want := []string{
		"v1-5-1-rotation-under-60s",
		"v1-5-7-day-stay-online",
		"v1-5-family-online-under-60s",
		"v1-5-l3-fast-path",
		"v1-5-mode-aware-schema-end-to-end",
		"v1-5-provisioning-under-10min",
	}
	gotIDs := make([]string, 0, len(got))
	for _, s := range got {
		gotIDs = append(gotIDs, s.ID)
	}
	sort.Strings(gotIDs)
	for i, w := range want {
		if i >= len(gotIDs) {
			t.Errorf("missing scenario at index %d: want %s", i, w)
			continue
		}
		if gotIDs[i] != w {
			t.Errorf("scenario[%d] = %q, want %q", i, gotIDs[i], w)
		}
	}
}

// TestV1_5SupersetIsAdditive asserts that adding the v1-5-superset
// did not change the size of the v2-superset (26) or v3-superset
// (31). Both selectors stay LOCKED. Listed redundantly with
// v3_superset_test.go to fail loudly if either drifts.
func TestV1_5SupersetIsAdditive(t *testing.T) {
	scenarioDir := filepath.Join("..", "..", "..", "scenarios")
	v2, err := loadScenarios(scenarioDir, "v2-superset")
	if err != nil {
		t.Fatalf("v2-superset: %v", err)
	}
	if len(v2) != 26 {
		t.Errorf("v2-superset size = %d, want 26 (FRP-7 must be additive)", len(v2))
	}
	v3, err := loadScenarios(scenarioDir, "v3-superset")
	if err != nil {
		t.Fatalf("v3-superset: %v", err)
	}
	if len(v3) != 31 {
		t.Errorf("v3-superset size = %d, want 31 (FRP-7 must be additive)", len(v3))
	}
}
