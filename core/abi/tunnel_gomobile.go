//go:build gomobile

package abi

// SetTunnelSocks is exposed via gomobile for parity with the cshared
// surface. It is the DESKTOP shape — the host owns a sidecar and knows
// the endpoint. A gomobile host that runs sing-box in-process should
// call SetTunnelRefresh instead.
func (h *DaalCore) SetTunnelSocks(host string, port int, username, password string) (string, error) {
	return SetTunnelSocks(host, port, username, password)
}

// SetTunnelRefresh points scheduled refresh at the engine's own
// in-process loopback SOCKS inlet (enabled=true), or clears it
// (enabled=false). Must be called AFTER SetRoute succeeds; see
// core/abi/tunnel_refresh.go for the ordering contract and for why no
// endpoint or credential crosses this boundary.
func (h *DaalCore) SetTunnelRefresh(enabled bool) (string, error) {
	return SetTunnelRefresh(enabled)
}
