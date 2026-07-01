//go:build !singbox

package engine

import "testing"

// TestDriverSelectionByBuildTag (stub twin) — when the build tag
// `singbox` is absent (unit tests + ABI-stability soak), the engine
// must link the deterministic Stub driver. The singbox twin file in
// driver_selection_singbox_test.go asserts the inverse. Together they
// pin Phase 45 invariant 1: NewDefaultDriver is the only constructor
// the ABI calls, and which driver it returns is controlled entirely by
// build tags.
func TestDriverSelectionByBuildTag(t *testing.T) {
	d := NewDefaultDriver()
	if d == nil {
		t.Fatal("NewDefaultDriver returned nil")
	}
	if _, ok := d.(*Stub); !ok {
		t.Fatalf("expected *Stub from !singbox build, got %T", d)
	}
}
