// Wave 5. Refraction-family ABI tests, rewritten from the Phase
// 3D originals.
//
// The 3D versions asserted `psiphon_compiled_in: true` and
// `conjure_compiled_in: true` and round-tripped an "active
// route" through both recorders. Every one of those assertions
// was green and none of them was true: neither
// psiphon-tunnel-core nor gotapdance is in `core/go.mod`, so the
// binary under test linked neither tree. The build-tag pair that
// nominally flipped the psiphon flag was never passed by any
// build script, and its companion file
// (`refraction_excluded_test.go`) is gone with it.
//
// What is asserted now is the opposite and is checkable: both
// flags are false in every build, both recorders refuse to name
// an active route, and the three route fields stay empty. See
// `refraction_compiled.go` for why this is permanent rather than
// a backlog item.

package abi

import (
	"strings"
	"testing"

	"daal/core/transports/conjure"
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

// TestRecordPsiphonActiveRoute_RefusesActivation — psiphon has
// no implementation in this build and cannot acquire one (it is
// somebody else's network), so naming an active psiphon route in
// diagnostics is refused. Clearing still succeeds.
func TestRecordPsiphonActiveRoute_RefusesActivation(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	if err := RecordPsiphonActiveRoute("ps-test-route"); err == nil {
		t.Fatal("RecordPsiphonActiveRoute must refuse a non-empty route ID")
	}
	if got := PsiphonActiveRoute(); got != "" {
		t.Errorf("refused activation still stored a route: %q", got)
	}
	// Clearing is always allowed so callers need no special case.
	if err := RecordPsiphonActiveRoute(""); err != nil {
		t.Errorf("clearing should succeed: %v", err)
	}
	body, _ := ExportDiagnostics()
	if !strings.Contains(body, `"psiphon_active_route": ""`) {
		t.Errorf("psiphon_active_route not empty:\n%s", body)
	}
}

// TestRecordConjureActivation_RefusesActivation — conjure needs
// a cooperating ISP running a refraction station, which no
// self-hosted publisher has, so the engine refuses to report an
// active conjure route or a phantom hash. The raw IP must not
// reach diagnostics by any path, refused or not.
func TestRecordConjureActivation_RefusesActivation(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	const rawIP = "192.122.190.42"
	if err := RecordConjureActivation("cj-test", rawIP); err == nil {
		t.Fatal("RecordConjureActivation must refuse a non-empty route ID")
	}
	if got := ConjureActiveRoute(); got != "" {
		t.Errorf("refused activation still stored a route: %q", got)
	}
	if got := ConjurePhantomInUseHash(); got != "" {
		t.Errorf("refused activation still stored a phantom hash: %q", got)
	}
	if err := RecordConjureActivation("", ""); err != nil {
		t.Errorf("clearing should succeed: %v", err)
	}
	body, _ := ExportDiagnostics()
	if strings.Contains(body, rawIP) {
		t.Fatalf("raw phantom IP leaked into diagnostics:\n%s", body)
	}
	if !strings.Contains(body, `"conjure_phantom_in_use": ""`) {
		t.Errorf("conjure_phantom_in_use not empty:\n%s", body)
	}
}

// TestHashPhantom_StillRedacts — HashPhantom is the only
// implementation of the no-raw-IP redaction contract that the
// soak rig's `ruleNoRawPhantomIPLeakInDiagnostics` asserts
// against, so it keeps its own regression even though nothing
// calls it on a live path any more: distinct IPs hash distinctly
// and the output is not the input.
func TestHashPhantom_StillRedacts(t *testing.T) {
	h1 := conjure.HashPhantom("192.122.190.1")
	h2 := conjure.HashPhantom("192.122.190.2")
	if h1 == h2 {
		t.Errorf("two IPs produced identical hashes: %q", h1)
	}
	if strings.Contains(h1, "192.122.190.1") {
		t.Errorf("hash contains the raw IP: %q", h1)
	}
	if len(h1) != 16 {
		t.Errorf("hash is not the locked 8-byte-hex shape: %q", h1)
	}
}

// TestRefractionCompiledInFlags_FalseInEveryBuild — the
// headline correction. `psiphon_compiled_in` and
// `conjure_compiled_in` claim a vendored tree is linked into the
// running binary; `core/go.mod` requires neither
// psiphon-tunnel-core nor gotapdance, so both claims were false
// in every build the project has ever shipped. There is no build
// tag left that can flip either one.
func TestRefractionCompiledInFlags_FalseInEveryBuild(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	body, _ := ExportDiagnostics()
	if !strings.Contains(body, `"psiphon_compiled_in": false`) {
		t.Errorf("psiphon_compiled_in must be false:\n%s", body)
	}
	if !strings.Contains(body, `"conjure_compiled_in": false`) {
		t.Errorf("conjure_compiled_in must be false:\n%s", body)
	}
}

// TestVersionStringIs090 — explicit guard that the engine
// version is at the current Phase 3F target.
func TestVersionStringIs090(t *testing.T) {
	if VersionString() != "daal-core 0.9.0+v3-share" {
		t.Fatalf("version: %s", VersionString())
	}
}
