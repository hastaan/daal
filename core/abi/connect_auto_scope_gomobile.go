//go:build gomobile

package abi

// SetAutoScope is the gomobile twin of engine_set_auto_scope.
func (h *DaalCore) SetAutoScope(routeIDsJSON string) (int, error) {
	return SetAutoScope(routeIDsJSON)
}
