package main

import (
	"path/filepath"
	"testing"
)

// TestV3SupersetCount locks the 3-Soak v3-superset whitelist size at
// **31** scenarios (the 26-scenario v2-superset + 5 new V3 scenarios).
// Any change to this count requires a roadmap amendment.
func TestV3SupersetCount(t *testing.T) {
	scenarioDir := filepath.Join("..", "..", "..", "scenarios")
	got, err := loadScenarios(scenarioDir, "v3-superset")
	if err != nil {
		t.Fatalf("loadScenarios v3-superset: %v", err)
	}
	if len(got) != 31 {
		t.Errorf("v3-superset size = %d, want 31", len(got))
		for _, s := range got {
			t.Logf("  selected: %s", s.ID)
		}
	}
}

// TestV2SupersetUnchanged guards against accidentally widening the
// 2G locked v2-superset (which is also a 3F-locked surface). The
// v3-superset is additive; v2-superset stays at 26.
func TestV2SupersetUnchanged(t *testing.T) {
	scenarioDir := filepath.Join("..", "..", "..", "scenarios")
	got, err := loadScenarios(scenarioDir, "v2-superset")
	if err != nil {
		t.Fatalf("loadScenarios v2-superset: %v", err)
	}
	if len(got) != 26 {
		t.Errorf("v2-superset size = %d, want 26 (locked at 3F)", len(got))
	}
}

// TestLegacyUnchanged guards the 1.5C-locked legacy parity selector.
func TestLegacyUnchanged(t *testing.T) {
	scenarioDir := filepath.Join("..", "..", "..", "scenarios")
	got, err := loadScenarios(scenarioDir, "legacy")
	if err != nil {
		t.Fatalf("loadScenarios legacy: %v", err)
	}
	if len(got) != 5 {
		t.Errorf("legacy size = %d, want 5 (locked at 1.5C)", len(got))
	}
}
