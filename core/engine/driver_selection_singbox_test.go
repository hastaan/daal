//go:build singbox

package engine

import "testing"

// TestDriverSelectionByBuildTag (singbox twin) — when the build tag
// `singbox` is set (release Android / iOS artefact, eventually
// desktop), the engine must link the singBox driver. See the !singbox
// twin in driver_selection_stub_test.go for the symmetric guard.
func TestDriverSelectionByBuildTag(t *testing.T) {
	d := NewDefaultDriver()
	if d == nil {
		t.Fatal("NewDefaultDriver returned nil")
	}
	if _, ok := d.(*singBox); !ok {
		t.Fatalf("expected *singBox from singbox build, got %T", d)
	}
}

// HasRealDataPlane must track the driver the tag actually selected —
// see the !singbox twin for why this matters.
func TestHasRealDataPlaneMatchesDriver(t *testing.T) {
	if !HasRealDataPlane {
		t.Fatal("HasRealDataPlane is false on a singbox build, which links the real driver")
	}
}
