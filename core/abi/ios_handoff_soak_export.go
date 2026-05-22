//go:build cshared && soak

package abi

import "C"

// engine_soak_set_wg_memory_kib drives the simulated WG sub-engine
// RSS gauge the `ios-wireguard-handoff` scenario uses. Soak-only;
// not part of the release ABI surface.

//export engine_soak_set_wg_memory_kib
func engine_soak_set_wg_memory_kib(kib C.longlong) {
	SetWGMemoryKiB(int64(kib))
}

// engine_soak_force_wg_handoff stamps a forced-handoff timestamp.
// The diagnostics field `wg_subengine_handoff_at` becomes
// non-empty after this call and remains so until shutdown.

//export engine_soak_force_wg_handoff
func engine_soak_force_wg_handoff() {
	ForceWGHandoff()
}
