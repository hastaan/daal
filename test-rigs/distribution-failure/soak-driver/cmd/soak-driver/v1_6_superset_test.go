package main

import (
	"path/filepath"
	"sort"
	"testing"
)

// TestV1_6SupersetCount locks the FRP-9 V1.6 selector at seven
// scenarios. This is the engineering-controlled synthetic gate in
// specs/v1-6-closure-v1.md; the live two-FRP pilot is separate.
func TestV1_6SupersetCount(t *testing.T) {
	scenarioDir := filepath.Join("..", "..", "..", "scenarios")
	got, err := loadScenarios(scenarioDir, "v1-6-superset")
	if err != nil {
		t.Fatalf("loadScenarios v1-6-superset: %v", err)
	}
	if len(got) != 7 {
		t.Errorf("v1-6-superset size = %d, want 7", len(got))
		for _, s := range got {
			t.Logf("  selected: %s", s.ID)
		}
	}
}

// TestV1_6SupersetExactIDs guards against silent scenario drift. The
// scenario list mirrors supplement §22.2 and the V1.6 closure record.
func TestV1_6SupersetExactIDs(t *testing.T) {
	scenarioDir := filepath.Join("..", "..", "..", "scenarios")
	got, err := loadScenarios(scenarioDir, "v1-6-superset")
	if err != nil {
		t.Fatalf("loadScenarios v1-6-superset: %v", err)
	}
	want := []string{
		"v1-6-cdn-dominant-route",
		"v1-6-cf-hostname-blocked-fallback",
		"v1-6-dns-only-a-leak-detected",
		"v1-6-freshness-atomic-swap",
		"v1-6-origin-ip-scan-rejected",
		"v1-6-origin-only-rotation",
		"v1-6-public-surface-rotation",
	}
	gotIDs := make([]string, 0, len(got))
	for _, s := range got {
		gotIDs = append(gotIDs, s.ID)
	}
	sort.Strings(gotIDs)
	if len(gotIDs) != len(want) {
		t.Fatalf("v1-6-superset IDs = %v, want %v", gotIDs, want)
	}
	for i, w := range want {
		if gotIDs[i] != w {
			t.Errorf("scenario[%d] = %q, want %q", i, gotIDs[i], w)
		}
	}
}

// TestV1_6SupersetIsAdditive asserts FRP-9 does not move the
// locked legacy/V2/V3 selectors.
func TestV1_6SupersetIsAdditive(t *testing.T) {
	scenarioDir := filepath.Join("..", "..", "..", "scenarios")
	checks := map[string]int{
		"v1-5-superset": 6,
		"v2-superset":   26,
		"v3-superset":   31,
	}
	for selector, want := range checks {
		got, err := loadScenarios(scenarioDir, selector)
		if err != nil {
			t.Fatalf("%s: %v", selector, err)
		}
		if len(got) != want {
			t.Errorf("%s size = %d, want %d", selector, len(got), want)
		}
	}
}

// TestV1_6ScenariosUseKnownActions ensures the final FRP-9 synthetic
// gate cannot ship with forward-declared/unknown actions.
func TestV1_6ScenariosUseKnownActions(t *testing.T) {
	scenarioDir := filepath.Join("..", "..", "..", "scenarios")
	got, err := loadScenarios(scenarioDir, "v1-6-superset")
	if err != nil {
		t.Fatalf("loadScenarios v1-6-superset: %v", err)
	}
	known := map[string]bool{
		"soak_cdn_provision_attestation":  true,
		"soak_simulate_dns_only_leak":     true,
		"soak_simulate_origin_ip_scan":    true,
		"soak_simulate_cf_hostname_block": true,
		"soak_rotate_public_surface":      true,
		"soak_rotate_origin_only":         true,
		"soak_freshness_atomic_swap":      true,
	}
	for _, sc := range got {
		if len(sc.EngineActions) == 0 {
			t.Errorf("%s has no engine_actions", sc.ID)
		}
		for _, act := range sc.EngineActions {
			if !known[act.Name] {
				t.Errorf("%s has unknown V1.6 action %q", sc.ID, act.Name)
			}
		}
	}
}
