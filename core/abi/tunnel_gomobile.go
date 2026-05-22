//go:build gomobile

package abi

// SetTunnelSocks is exposed via gomobile for parity with the cshared
// surface, even though Phase 1.5B ships TunnelDialer wiring on desktop
// only — Android adopts it in Phase 1.5C.
func (h *DaalCore) SetTunnelSocks(host string, port int, username, password string) (string, error) {
	return SetTunnelSocks(host, port, username, password)
}
