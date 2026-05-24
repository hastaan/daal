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
