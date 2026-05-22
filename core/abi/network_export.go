//go:build cshared

package abi

import "C"

import "unsafe"

// engine_network_changed is the Phase 2C release ABI symbol — the
// 37th. Hashes the (kind, carrier, ssid) tuple and swaps the
// engine's active per-network state. Returns the JSON status blob.

//export engine_network_changed
func engine_network_changed(kind, carrier, ssid *C.char,
	out unsafe.Pointer, outLen C.int) C.int {
	body, err := NetworkChanged(C.GoString(kind), C.GoString(carrier), C.GoString(ssid))
	if err != nil && body == "" {
		return -1
	}
	if err != nil {
		_ = copyOut(body, out, outLen)
		return -1
	}
	return copyOut(body, out, outLen)
}
