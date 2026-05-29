//go:build cshared

package abi

import "C"

import "errors"

// engine_unlock_secrets is one of two Phase 2D release ABI symbols.
// For the "vault" storage profile, derives an AES key over the PIN
// via Argon2id and unseals the on-disk age identity. For the
// "keystore" storage profile returns -2 (vault profile not enabled).
//
// Returns:
//
//	0  — unlocked
//	-1 — wrong PIN, empty PIN, or other unlock failure
//	-2 — engine is not running under the vault storage profile

//export engine_unlock_secrets
func engine_unlock_secrets(pin *C.char) C.int {
	err := UnlockSecrets(C.GoString(pin))
	if err == nil {
		return 0
	}
	if errors.Is(err, ErrVaultProfileNotEnabled) {
		return -2
	}
	return -1
}

// engine_set_allow_bulk_capable is the second Phase 2D release ABI
// symbol. Sets the budget engine's per-session bulk-capable
// opt-in flag, which the ranker honours when filtering routes in
// lifeline-strict. The flag is cleared by every NewSession (engine
// init or session-epoch bump) and survives SetMode and
// network_changed.
//
// Pass `1` to allow, `0` to disallow. Always returns 0; if the
// budget engine has not been instantiated (no SetRouteBudget call
// yet) the call is a no-op.

//export engine_set_allow_bulk_capable
func engine_set_allow_bulk_capable(allow C.int) C.int {
	SetAllowBulkCapable(allow != 0)
	return 0
}
