package abi

import (
	"os"
	"strings"
	"testing"
)

// Phase 3C MASQUE ABI tests. Canonical regressions called out
// in specs/engine-abi-v1.md "Phase 3C" and
// specs/masque-ladder-v1.md.
//
//   - TestMasqueSubmodeOverride_DefaultsEmpty
//   - TestSetMasqueSubmodeOverride_AcceptsKnownSubmode
//   - TestSetMasqueSubmodeOverride_RejectsUnknownSubmode
//   - TestSetMasqueSubmodeOverride_EmptyClears
//   - TestMasqueOverrideSurvivesSessionEpoch
//   - TestMasqueOverride_AcceptedInVaultProfile
//   - TestRecordChosenMasqueSubmode_PersistsThroughLayers
//   - TestRecordChosenMasqueSubmode_RejectsUnknownSubmode
//   - TestDiagnostics_AlwaysCarryMasqueFields

func TestMasqueSubmodeOverride_DefaultsEmpty(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	if got := MasqueSubmodeOverride(); got != "" {
		t.Errorf("default override: got %q want empty", got)
	}
	body, _ := ExportDiagnostics()
	if !strings.Contains(body, `"masque_submode_override": ""`) {
		t.Errorf("diagnostics did not show empty override:\n%s", body)
	}
	if !strings.Contains(body, `"masque_submode": ""`) {
		t.Errorf("diagnostics did not show empty masque_submode:\n%s", body)
	}
}

func TestSetMasqueSubmodeOverride_AcceptsKnownSubmode(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	for _, sm := range []string{"masque_h3_quic", "masque_h2_connect", "masque_lifeline"} {
		if rc := SetMasqueSubmodeOverride(sm); rc != 0 {
			t.Errorf("SetMasqueSubmodeOverride(%q): rc=%d", sm, rc)
		}
		if got := MasqueSubmodeOverride(); got != sm {
			t.Errorf("round-trip %q: got %q", sm, got)
		}
	}
}

func TestSetMasqueSubmodeOverride_RejectsUnknownSubmode(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	if rc := SetMasqueSubmodeOverride("masque_h3_avian"); rc != -3 {
		t.Errorf("unknown sub-mode: got %d want -3", rc)
	}
	// Override unchanged.
	if got := MasqueSubmodeOverride(); got != "" {
		t.Errorf("override after rejected set: got %q want empty", got)
	}
}

func TestSetMasqueSubmodeOverride_EmptyClears(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	if rc := SetMasqueSubmodeOverride("masque_h3_quic"); rc != 0 {
		t.Fatal(rc)
	}
	if rc := SetMasqueSubmodeOverride(""); rc != 0 {
		t.Errorf("clear: got rc=%d want 0", rc)
	}
	if got := MasqueSubmodeOverride(); got != "" {
		t.Errorf("after clear: got %q", got)
	}
}

// TestMasqueOverrideSurvivesSessionEpoch — the override is
// persisted in secrets KV and redaalted on Init. A subsequent
// Init in the same state-dir must see the previously-set
// override.
func TestMasqueOverrideSurvivesSessionEpoch(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	if rc := SetMasqueSubmodeOverride("masque_h2_connect"); rc != 0 {
		t.Fatal(rc)
	}
	if err := Shutdown(); err != nil {
		t.Fatal(err)
	}

	// Re-init.
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	if got := MasqueSubmodeOverride(); got != "masque_h2_connect" {
		t.Errorf("override after re-init: got %q want masque_h2_connect", got)
	}
}

// TestMasqueOverride_AcceptedInVaultProfile — unlike 3B's push
// opt-in, the MASQUE override has no FCM/APNS surface and so
// is accepted in BOTH the keystore and vault storage profiles.
func TestMasqueOverride_AcceptedInVaultProfile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/.use_vault", []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	if rc := SetMasqueSubmodeOverride("masque_lifeline"); rc != 0 {
		t.Errorf("vault profile must accept masque override; got %d", rc)
	}
}

// TestRecordChosenMasqueSubmode_PersistsThroughLayers — the
// engine-side hook from the masque handler updates (a) the
// in-memory diagnostics field, (b) the routestore (per-route
// secrets-KV record), and (c) the netmem store (per-network
// LastUsedMasqueSubmode).
func TestRecordChosenMasqueSubmode_PersistsThroughLayers(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	if err := RecordChosenMasqueSubmode("r-mq-1", "masque_h3_quic", "net-99"); err != nil {
		t.Fatalf("RecordChosenMasqueSubmode: %v", err)
	}

	// (a) in-memory.
	if got := LastChosenMasqueSubmode(); got != "masque_h3_quic" {
		t.Errorf("LastChosenMasqueSubmode: got %q", got)
	}
	// (b) routestore (per-route).
	body, err := globalCore.store.GetSecret("masque_submode:r-mq-1")
	if err != nil {
		t.Fatalf("routestore lookup: %v", err)
	}
	if string(body) != "masque_h3_quic" {
		t.Errorf("routestore value: got %q", string(body))
	}
	// (c) netmem (per-network).
	if ns := netmemStore(); ns != nil {
		if got := ns.LookupLastUsedMasqueSubmode("net-99"); got != "masque_h3_quic" {
			t.Errorf("netmem hint: got %q", got)
		}
	}
}

func TestRecordChosenMasqueSubmode_RejectsUnknownSubmode(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	if err := RecordChosenMasqueSubmode("r-mq-1", "masque_quantum", "net-99"); err == nil {
		t.Error("unknown sub-mode must be rejected")
	}
}

// TestDiagnostics_AlwaysCarryMasqueFields — the two 3C
// diagnostic fields must be present regardless of whether any
// MASQUE route has been activated this session. JSON shape
// stability is the contract.
func TestDiagnostics_AlwaysCarryMasqueFields(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	body, err := ExportDiagnostics()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, `"masque_submode"`) {
		t.Errorf("masque_submode missing from diagnostics:\n%s", body)
	}
	if !strings.Contains(body, `"masque_submode_override"`) {
		t.Errorf("masque_submode_override missing from diagnostics:\n%s", body)
	}
}
