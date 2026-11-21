//go:build gomobile

package abi

// RelayPackRefresh is the gomobile twin of engine_relaypack_refresh.
func (h *DaalCore) RelayPackRefresh(relayPackID string) (string, error) {
	return RelayPackRefresh(relayPackID)
}
