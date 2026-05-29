//go:build !cshared

package abi

// EngineSetMasqueSubmodeOverride is the gomobile facade for
// Phase 3C's MASQUE sub-mode override. Pass an empty string to
// clear (engine returns to the auto cascade). Mirrors the
// cshared symbol with a Go-typed int return so the iOS /
// Android bridges can call it through the standard gomobile
// binding surface.
//
// Returns:
//
//	 0 success
//	-1 engine not initialised
//	-3 sub-mode is not in the v1 closed list
func EngineSetMasqueSubmodeOverride(submode string) int {
	return SetMasqueSubmodeOverride(submode)
}
