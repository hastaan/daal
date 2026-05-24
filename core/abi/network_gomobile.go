//go:build gomobile

package abi

// Phase 2C gomobile facade for engine_network_changed.

func (h *DaalCore) NetworkChanged(kind, carrier, ssid string) (string, error) {
	return NetworkChanged(kind, carrier, ssid)
}
