//go:build gomobile

package abi

// Phase 2E gomobile facade for engine_lifecycle_event.
//
// gomobile cannot return Go-typed errors across the language
// boundary, so the facade returns 0 / -1 to mirror the cshared ABI.
// The Swift bridge gets identical semantics on both build modes.

func (h *DaalCore) LifecycleEvent(token string) int {
	if err := LifecycleEvent(token); err != nil {
		return -1
	}
	return 0
}
