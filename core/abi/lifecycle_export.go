//go:build cshared

package abi

import "C"

// engine_lifecycle_event is the Phase 2E release ABI symbol
// (release surface 40 → 41). The iOS Swift bridge calls this once
// per Network-Extension state transition.
//
// Accepted token values (v1 set, locked at 2E):
//
//   - "will_sleep"
//   - "did_wake"
//   - "memory_pressure_warning"
//
// Returns 0 on success, -1 if the token is outside the locked v1
// set (the engine refuses to silently accept tokens introduced by
// a future Swift version without an ABI spec amendment).
//
// The function is side-effect-light by design: the engine records
// the event for diagnostics. Real reactions (cooldown adjustment,
// refresh deferral) happen elsewhere when those code paths consult
// diagnostics state. This keeps the bridge / engine boundary
// clean and means non-iOS platforms (Linux / Android / desktop)
// pay zero runtime cost — no caller invokes this symbol on those
// platforms, and the diagnostics fields simply stay absent.

//export engine_lifecycle_event
func engine_lifecycle_event(token *C.char) C.int {
	if token == nil {
		return -1
	}
	t := C.GoString(token)
	if err := LifecycleEvent(t); err != nil {
		return -1
	}
	return 0
}
