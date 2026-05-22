//go:build gomobile

package abi

// Phase 2A gomobile facade.

func (h *DaalCore) SetRouteBudget(routeID, tag string) (string, error) {
	return SetRouteBudget(routeID, tag)
}
