//go:build gomobile

package abi

// ConnectAuto is the gomobile twin of engine_connect_auto.
func (h *DaalCore) ConnectAuto() (string, error) {
	return ConnectAuto()
}
