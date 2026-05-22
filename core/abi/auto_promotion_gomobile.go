//go:build gomobile

package abi

// Phase 2G gomobile facade for engine_set_auto_promotion.

func (h *DaalCore) SetAutoPromotion(enabled bool) {
	SetAutoPromotion(enabled)
}
