//go:build gomobile

package abi

// Optional add-ons S7: the standby key on the gomobile facade.

func (h *DaalCore) StandbyKey(relayPackID, key string) (string, error) {
	return StandbyKey(relayPackID, key)
}
