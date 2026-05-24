//go:build gomobile && soak

package abi

// gomobile facades for the iOS WG-handoff soak knobs.

func (h *DaalCore) SoakSetWGMemoryKiB(kib int64) {
	SetWGMemoryKiB(kib)
}

func (h *DaalCore) SoakForceWGHandoff() {
	ForceWGHandoff()
}
