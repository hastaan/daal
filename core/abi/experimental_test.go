package abi

import (
	"strings"
	"testing"
)

// Phase 3A. Experimental-families gate ABI tests.
//
// Canonical regressions called out in
// specs/transport-families-v1.md "ABI surface change":
//
//   - TestExperimentalGateDefaultsOff
//   - TestExperimentalGateSurvivesSessionEpoch
//   - TestExperimentalGatePersistsAcrossModeChange

// TestExperimentalGateDefaultsOff — engine_init must start with
// the gate disabled per spec (V0 conservative default).
func TestExperimentalGateDefaultsOff(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	if ExperimentalFamiliesEnabled() {
		t.Error("experimental-families gate should default to OFF")
	}
	body, err := ExportDiagnostics()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, `"experimental_families_enabled": false`) {
		t.Errorf("diagnostics missing/wrong experimental_families_enabled:\n%s", body)
	}
	if !strings.Contains(body, `"experimental_routes_skipped": 0`) {
		t.Errorf("diagnostics missing/wrong experimental_routes_skipped:\n%s", body)
	}
}

// TestSetExperimentalFamiliesEnabled_RoundTrip — flipping the
// flag round-trips through diagnostics.
func TestSetExperimentalFamiliesEnabled_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	SetExperimentalFamiliesEnabled(true)
	if !ExperimentalFamiliesEnabled() {
		t.Error("flag did not flip to true")
	}
	body, _ := ExportDiagnostics()
	if !strings.Contains(body, `"experimental_families_enabled": true`) {
		t.Errorf("diagnostics did not reflect true:\n%s", body)
	}
	SetExperimentalFamiliesEnabled(false)
	if ExperimentalFamiliesEnabled() {
		t.Error("flag did not flip back to false")
	}
}

// TestExperimentalGateSurvivesSessionEpoch — a Shutdown + Init
// preserves the flag value (the flag is a user preference, not
// session state). Locked in spec.
func TestExperimentalGateSurvivesSessionEpoch(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	SetExperimentalFamiliesEnabled(true)
	if err := Shutdown(); err != nil {
		t.Fatal(err)
	}
	// Re-init the same state directory — this is the canonical
	// session epoch boundary per 2A-Polish.
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	if !ExperimentalFamiliesEnabled() {
		t.Error("experimental gate must survive session epoch (Shutdown + Init)")
	}
}

// TestExperimentalGatePersistsAcrossModeChange — mode change is
// not a clearing event for the gate. Locked in spec.
func TestExperimentalGatePersistsAcrossModeChange(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	SetExperimentalFamiliesEnabled(true)
	for _, mode := range []string{"lifeline", "lifeline-strict", "normal", "bulk"} {
		if err := SetMode(mode); err != nil {
			t.Fatalf("SetMode(%q): %v", mode, err)
		}
		if !ExperimentalFamiliesEnabled() {
			t.Fatalf("gate cleared by SetMode(%q)", mode)
		}
	}
}

// TestExperimentalGate_OffByDefaultAcrossInits — a fresh state
// directory must not silently carry the gate ON (the persisted
// default is "absent" → false).
func TestExperimentalGate_OffByDefaultAcrossInits(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	if err := Shutdown(); err != nil {
		t.Fatal(err)
	}
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })
	if ExperimentalFamiliesEnabled() {
		t.Error("a fresh state directory must default to gate OFF")
	}
}

// TestSetExperimentalRoutesSkipped — the pathmanager-side hook
// that surfaces the per-rank-pass tally rounds-trips into
// diagnostics.
func TestSetExperimentalRoutesSkipped(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	SetExperimentalRoutesSkipped(7)
	body, _ := ExportDiagnostics()
	if !strings.Contains(body, `"experimental_routes_skipped": 7`) {
		t.Errorf("diagnostics did not reflect skip count:\n%s", body)
	}
	// Snapshot semantics: a fresh write replaces, does not accumulate.
	SetExperimentalRoutesSkipped(2)
	body, _ = ExportDiagnostics()
	if !strings.Contains(body, `"experimental_routes_skipped": 2`) {
		t.Errorf("snapshot did not replace:\n%s", body)
	}
}
