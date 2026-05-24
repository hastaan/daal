//go:build gomobile

package abi

// Phase 2D gomobile facades.

func (h *DaalCore) UnlockSecrets(pin string) error {
	return UnlockSecrets(pin)
}

func (h *DaalCore) SetAllowBulkCapable(allow bool) {
	SetAllowBulkCapable(allow)
}
