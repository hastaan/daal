//go:build cshared

package abi

import "C"

import "unsafe"

// engine_network_facts tells the engine what the HOST knows about the
// network the device is on. See NetworkFacts (network_facts.go).
//
//	int engine_network_facts(const char* kind, const char* id,
//	                         int validated, int metered,
//	                         void* out, int out_len);
//
//	kind       "wifi" | "cellular" | "ethernet" | "vpn" | "other" | "none"
//	id         opaque per-network string; hashed on entry, never stored
//	           or logged in clear. May be "".
//	validated  1 | 0 | -1 (unknown)
//	metered    1 | 0 | -1 (unknown)
//
// Writes to `out` (caller-owned buffer, same convention as
// engine_network_changed):
//
//	{"network_id":"<hashed>","kind":"wifi","validated":1,"metered":0,
//	 "changed":true,"fresh":false}
//
// Returns the number of bytes written, or a negative value for an
// unknown kind or an engine that is not initialised. It never blocks on
// a connection check. engine_network_changed keeps working for a host
// that has no such callback; once this has been called, that call is
// answered and changes nothing.
//
//export engine_network_facts
func engine_network_facts(kind, id *C.char, validated, metered C.int,
	out unsafe.Pointer, outLen C.int) C.int {
	body, err := NetworkFacts(C.GoString(kind), C.GoString(id), int(validated), int(metered))
	if err != nil {
		return exportFail("engine_network_facts", err)
	}
	return copyOut(body, out, outLen)
}
