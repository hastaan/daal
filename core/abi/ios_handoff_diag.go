//go:build soak

package abi

// On soak builds, register the WG-subengine diagnostics renderer.
// Release builds never compile this file, so the diagnostics shape
// off-soak is unaffected.
func init() {
	soakDiagHook = func(out map[string]any) {
		kib, at := readWGHandoffSoak()
		if kib > 0 {
			out["wg_subengine_memory_kib"] = kib
		}
		if !at.IsZero() {
			out["wg_subengine_handoff_at"] = at.Format("2006-01-02T15:04:05Z07:00")
		}
	}
}
