//go:build no_psiphon

// Phase 3D refraction-family ABI tests for the GPLv3-isolation
// build (`-tags no_psiphon`). The vendor tree is excluded; the
// compile-in flag flips to false; the engine refuses to record
// a psiphon active route. Conjure is unaffected (Apache-2.0
// vendor tree ships unconditionally).

package abi

import (
	"strings"
	"testing"
)

// TestPsiphonCompiledIn_FalseUnderIsolationTag — `-tags
// no_psiphon` flips the diagnostic flag to false.
func TestPsiphonCompiledIn_FalseUnderIsolationTag(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	body, _ := ExportDiagnostics()
	if !strings.Contains(body, `"psiphon_compiled_in": false`) {
		t.Errorf("psiphon_compiled_in not false under no_psiphon:\n%s", body)
	}
	if !strings.Contains(body, `"conjure_compiled_in": true`) {
		t.Errorf("conjure_compiled_in must remain true:\n%s", body)
	}
}

// TestRecordPsiphonActiveRoute_RejectedUnderIsolationTag — the
// engine MUST refuse to advertise an active psiphon route when
// the vendor tree is excluded. Pass-through with empty routeID
// is still allowed (clearing).
func TestRecordPsiphonActiveRoute_RejectedUnderIsolationTag(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	if err := RecordPsiphonActiveRoute("ps-test"); err == nil {
		t.Error("RecordPsiphonActiveRoute MUST refuse non-empty routeID under no_psiphon")
	}
	// Empty routeID (the clear case) is still allowed.
	if err := RecordPsiphonActiveRoute(""); err != nil {
		t.Errorf("clearing should still succeed: %v", err)
	}
}

// TestRecordConjureActivation_StillWorksUnderIsolationTag —
// conjure is unaffected by the isolation tag.
func TestRecordConjureActivation_StillWorksUnderIsolationTag(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	if err := RecordConjureActivation("cj-test", "192.122.190.42"); err != nil {
		t.Errorf("conjure activation rejected under no_psiphon: %v", err)
	}
	if got := ConjureActiveRoute(); got != "cj-test" {
		t.Errorf("conjure route round-trip: got %q", got)
	}
}
