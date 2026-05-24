//go:build cshared

package abi

import "C"

// engine_set_masque_submode_override is the Phase 3C release
// ABI symbol (release surface 44 → 45). Sets the per-engine
// MASQUE sub-mode override.
//
// `submode` is a UTF-8 NUL-terminated string. NULL is treated
// as empty (clears the override). The empty string clears the
// override and returns the engine to the auto cascade. Valid
// non-empty values are: "masque_h3_quic", "masque_h2_connect",
// "masque_lifeline".
//
// Returns:
//
//	 0 success
//	-1 engine not initialised
//	-3 sub-mode is not in the v1 closed list
//
// See specs/engine-abi-v1.md "Phase 3C" and
// specs/masque-ladder-v1.md.

//export engine_set_masque_submode_override
func engine_set_masque_submode_override(submode *C.char) C.int {
	if globalCore == nil {
		return -1
	}
	val := ""
	if submode != nil {
		val = C.GoString(submode)
	}
	return C.int(SetMasqueSubmodeOverride(val))
}
