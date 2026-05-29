//go:build cshared

package abi

import "C"

import "unsafe"

// engine_redistribute_route is the Phase 3F release ABI symbol
// 48 (release surface 47 → 48). Builds a `.sbp.share` envelope
// for the given route, signed by the device's 1C share
// identity, addressed to the recipient's delegate fingerprint.
//
// Returns serialized bundle bytes (a JSON envelope; see
// specs/delegate-keys-v1.md "Wire format") on success, or a
// JSON error envelope on failure:
//
//	{"error":"policy_refuses"|"cap_exhausted"|
//	         "chain_depth_exceeded"|"route_unknown"|
//	         "identity_unavailable", "detail":"..."}
//
// Empty / `identity_unavailable` envelope under
// `-tags no_delegate_share`. Always succeeds in the sense of
// not panicking.
//
// Caller-owned buffer (same convention as
// engine_export_diagnostics).

//export engine_redistribute_route
func engine_redistribute_route(routeIDC, recipientFPC *C.char, out unsafe.Pointer, outLen C.int) C.int {
	routeID := C.GoString(routeIDC)
	recipient := C.GoString(recipientFPC)
	body := RedistributeRoute(routeID, recipient)
	return copyOut(body, out, outLen)
}
