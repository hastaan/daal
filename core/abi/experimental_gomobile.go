//go:build !cshared

package abi

// EngineSetExperimentalFamiliesEnabled is the gomobile facade.
// Phase 3A. Mirrors the cshared symbol with a Go-typed int return
// so the iOS / Android bridges can call it through the standard
// gomobile binding surface.
func EngineSetExperimentalFamiliesEnabled(enabled int) int {
	if globalCore == nil {
		return -1
	}
	SetExperimentalFamiliesEnabled(enabled != 0)
	return 0
}
