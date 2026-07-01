//go:build gomobile

package abi

// SetTunFD is exposed via gomobile so a non-Tauri Android host (or
// future AAR consumer) can hand the VpnService fd to the in-process
// driver with the same semantics as engine_set_tun_fd. The fd
// ownership contract is identical: after a successful return the
// caller MUST NOT close it.
func (h *DaalCore) SetTunFD(fd int) (string, error) {
	return SetTunFD(fd)
}

// ClearTunFD mirrors engine_clear_tun_fd.
func (h *DaalCore) ClearTunFD() (string, error) {
	return ClearTunFD()
}

// RegisterProtectCallback mirrors engine_register_protect_callback.
// gomobile callers pass the C function pointer as a uintptr (the only
// type gomobile bind exposes for arbitrary pointers); the engine
// stores it atomically and the driver dereferences it via cgo at
// upstream-dial time.
func (h *DaalCore) RegisterProtectCallback(ptr int64) (string, error) {
	return RegisterProtectCallback(uintptr(ptr))
}
