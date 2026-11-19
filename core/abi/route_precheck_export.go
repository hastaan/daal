//go:build cshared

package abi

import "C"

import "unsafe"

// engine_route_precheck asks whether engine_set_route(route_id) would
// be refused right now, without starting or stopping anything. See
// RouteConnectPrecheck (route_check.go) for the contract.
//
// Writes {"route_id":"…","refused":"<code>","active_route":"…"} to
// `out` (caller-owned buffer, same convention as
// engine_export_diagnostics). `refused` is "" when the route would be
// attempted, else one of "needs_new_file", "cooldown", "revoked",
// "expired", "other", "no_data_plane". A refusal is also recorded in
// the diagnostics blob (connect_refused / connect_refused_route)
// exactly as a refused engine_set_route records it.
//
// Returns the number of bytes written, or -1 if the engine is not
// initialised. A refusal is NOT an error: the answer is in the JSON.
//
//export engine_route_precheck
func engine_route_precheck(routeID *C.char, out unsafe.Pointer, outLen C.int) C.int {
	body, err := RouteConnectPrecheck(C.GoString(routeID))
	if err != nil {
		return exportFail("engine_route_precheck", err)
	}
	return copyOut(body, out, outLen)
}
