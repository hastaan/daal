//go:build cshared

package abi

import "C"

// engine_set_experimental_families_enabled is the Phase 3A
// release ABI symbol (release surface 41 → 42). Sets the
// engine's experimental-families gate.
//
// Pass 1 to enable, 0 to disable. Default OFF at engine_init.
// The flag survives session epochs (it is a user preference).
// Returns 0 on success, -1 if the engine is not initialised.
//
// See specs/transport-families-v1.md "Experimental gate".

//export engine_set_experimental_families_enabled
func engine_set_experimental_families_enabled(enabled C.int) C.int {
	if globalCore == nil {
		return -1
	}
	SetExperimentalFamiliesEnabled(enabled != 0)
	return 0
}
