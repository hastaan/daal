//go:build !no_psiphon

// Phase 3D refraction-family ABI tests. These tests assume the
// default (un-isolated) build where the psiphon vendor tree is
// compiled in. The `-tags no_psiphon` build excludes both the
// vendor tree and these tests; the compiled-in-flag-OFF
// behaviour is covered by `refraction_excluded_test.go`.

package abi

import (
	"strings"
	"testing"
)

// Phase 3D refraction-family ABI tests. Canonical regressions
// called out in specs/engine-abi-v1.md "Phase 3D",
// specs/psiphon-route-v1.md, and specs/conjure-route-v1.md.

// TestDiagnostics_AlwaysCarryRefractionFields — the five 3D
// diagnostic fields are ALWAYS present in the rendered JSON,
// even before any refraction route activates. Snapshot, not
// cumulative.
func TestDiagnostics_AlwaysCarryRefractionFields(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	body, err := ExportDiagnostics()
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		`"psiphon_compiled_in"`,
		`"conjure_compiled_in"`,
		`"psiphon_active_route"`,
		`"conjure_active_route"`,
		`"conjure_phantom_in_use"`,
	} {
		if !strings.Contains(body, field) {
			t.Errorf("diagnostics missing %s:\n%s", field, body)
		}
	}
	// Default values: empty strings for the route IDs and the
	// phantom hash; compile-in flags reflect the build tags.
	if !strings.Contains(body, `"psiphon_active_route": ""`) {
		t.Errorf("psiphon_active_route not empty by default:\n%s", body)
	}
	if !strings.Contains(body, `"conjure_active_route": ""`) {
		t.Errorf("conjure_active_route not empty by default:\n%s", body)
	}
	if !strings.Contains(body, `"conjure_phantom_in_use": ""`) {
		t.Errorf("conjure_phantom_in_use not empty by default:\n%s", body)
	}
}

// TestRecordPsiphonActiveRoute_RoundTrips — the psiphon
// handler's recording hook surfaces in diagnostics.
func TestRecordPsiphonActiveRoute_RoundTrips(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	if err := RecordPsiphonActiveRoute("ps-test-route"); err != nil {
		t.Fatal(err)
	}
	if got := PsiphonActiveRoute(); got != "ps-test-route" {
		t.Errorf("read-back: got %q", got)
	}
	body, _ := ExportDiagnostics()
	if !strings.Contains(body, `"psiphon_active_route": "ps-test-route"`) {
		t.Errorf("diagnostics did not surface psiphon route:\n%s", body)
	}
	// Empty string clears.
	_ = RecordPsiphonActiveRoute("")
	body, _ = ExportDiagnostics()
	if !strings.Contains(body, `"psiphon_active_route": ""`) {
		t.Errorf("diagnostics not cleared:\n%s", body)
	}
}

// TestRecordConjureActivation_HashesPhantomIP — the recording
// hook stores ONLY the 16-hex-char hash; the raw IP MUST NOT
// appear in diagnostics. This is the canonical
// no-IP-leak regression for 3D.
func TestRecordConjureActivation_HashesPhantomIP(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	rawIP := "192.122.190.42"
	if err := RecordConjureActivation("cj-test-route", rawIP); err != nil {
		t.Fatal(err)
	}
	body, _ := ExportDiagnostics()
	if strings.Contains(body, rawIP) {
		t.Errorf("RAW phantom IP leaked into diagnostics:\n%s", body)
	}
	hash := ConjurePhantomInUseHash()
	if len(hash) != 16 {
		t.Errorf("hash length: got %d want 16 (8 bytes hex)", len(hash))
	}
	if !strings.Contains(body, `"conjure_phantom_in_use": "`+hash+`"`) {
		t.Errorf("hash not surfaced in diagnostics:\n%s", body)
	}
	if !strings.Contains(body, `"conjure_active_route": "cj-test-route"`) {
		t.Errorf("conjure route not surfaced:\n%s", body)
	}
	// Empty raw IP clears the hash; route ID can still be set.
	_ = RecordConjureActivation("cj-test-route", "")
	if got := ConjurePhantomInUseHash(); got != "" {
		t.Errorf("hash not cleared: got %q", got)
	}
}

// TestRecordConjureActivation_DifferentIPsHashDifferently —
// sanity-check the hash is non-trivial.
func TestRecordConjureActivation_DifferentIPsHashDifferently(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	_ = RecordConjureActivation("r", "192.122.190.1")
	h1 := ConjurePhantomInUseHash()
	_ = RecordConjureActivation("r", "192.122.190.2")
	h2 := ConjurePhantomInUseHash()
	if h1 == h2 {
		t.Errorf("two IPs produced identical hashes: %q", h1)
	}
}

// TestPsiphonCompiledInFlag_TruePerDefault — release builds
// (no `-tags no_psiphon`) report `psiphon_compiled_in: true`.
func TestPsiphonCompiledInFlag_TruePerDefault(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	body, _ := ExportDiagnostics()
	if !strings.Contains(body, `"psiphon_compiled_in": true`) {
		t.Errorf("psiphon_compiled_in not true by default:\n%s", body)
	}
	if !strings.Contains(body, `"conjure_compiled_in": true`) {
		t.Errorf("conjure_compiled_in not true by default:\n%s", body)
	}
}

// TestVersionStringIs090 — explicit guard that the engine
// version is at the current Phase 3F target.
func TestVersionStringIs090(t *testing.T) {
	if VersionString() != "daal-core 0.9.0+v3-share" {
		t.Fatalf("version: %s", VersionString())
	}
}
