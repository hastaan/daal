package relaypack

import (
	"testing"

	"daal/bundle-go/relaypackvalidate"
)

// TestAllowedModifierKindsForPhase_FRP12ShipIsEmpty asserts the
// FRP-12 wiring contract: at every validator phase the
// allowedModifierKindsForPhase helper returns an empty map because
// the modifier registry has zero PASS records at FRP-12 ship
// (locked invariant 37).
//
// If a future post-track phase adds a PASS record AND its min_phase
// is <= the requested validator phase, this test will fail by
// design — the post-track phase MUST update or replace this test
// with the appropriate non-empty assertion.
func TestAllowedModifierKindsForPhase_FRP12ShipIsEmpty(t *testing.T) {
	for _, p := range []relaypackvalidate.Phase{
		relaypackvalidate.PhaseV15,
		relaypackvalidate.PhaseV16,
		relaypackvalidate.PhasePostV2,
	} {
		got := allowedModifierKindsForPhase(p)
		if len(got) != 0 {
			t.Errorf("allowedModifierKindsForPhase(%s) = %v; want empty (locked invariant 37)", p, got)
		}
	}
}

// TestAllowedModifierKindsForPhase_UnknownPhaseEmpty checks the
// helper returns an empty map for unrecognised validator phases
// (defensive default — never propagate an unknown phase as an
// implicit allow).
func TestAllowedModifierKindsForPhase_UnknownPhaseEmpty(t *testing.T) {
	got := allowedModifierKindsForPhase(relaypackvalidate.Phase("V99"))
	if len(got) != 0 {
		t.Errorf("allowedModifierKindsForPhase(V99) = %v; want empty", got)
	}
}
