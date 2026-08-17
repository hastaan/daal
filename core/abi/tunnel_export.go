//go:build cshared

package abi

import "C"

import "unsafe"

//export engine_set_tunnel_socks
func engine_set_tunnel_socks(host *C.char, port C.int,
	username, password *C.char,
	out unsafe.Pointer, outLen C.int) C.int {
	body, err := SetTunnelSocks(C.GoString(host), int(port),
		C.GoString(username), C.GoString(password))
	if err != nil && body == "" {
		return -1
	}
	return copyOut(body, out, outLen)
}

// engine_set_tunnel_refresh(enabled) — turn scheduled refresh onto the
// engine's own in-process loopback SOCKS inlet, or off again. Takes no
// endpoint and no credential: both are engine-side state (see
// core/abi/tunnel_refresh.go for why the host is not given them).
//
// Returns -1 when there is no live inlet, which is what a host gets for
// calling before engine_set_route has succeeded. That is a safe failure:
// refresh then stays fail-closed rather than dialling direct.
//
//export engine_set_tunnel_refresh
func engine_set_tunnel_refresh(enabled C.int, out unsafe.Pointer, outLen C.int) C.int {
	body, err := SetTunnelRefresh(enabled != 0)
	if err != nil && body == "" {
		return -1
	}
	return copyOut(body, out, outLen)
}
