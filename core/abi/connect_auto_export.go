//go:build cshared

package abi

import "C"

import "unsafe"

// engine_connect_auto connects on the first route that carries, the
// engine choosing: no route id. See ConnectAuto (connect_auto.go).
//
// Blocking, like engine_set_route, and it uses the TUN fd already set
// exactly as engine_set_route does. engine_clear_route, a newer
// engine_set_route or a newer engine_connect_auto abandons it promptly,
// a connection check in flight included.
//
// Writes to `out` (caller-owned buffer, same convention as
// engine_export_diagnostics):
//
//	{"connected":true|false,"route_id":"r2","family":"websocket-tls",
//	 "tried":[{"route_id":"r1","family":"vless-reality",
//	           "result":"carried|not_carrying|start_failed|refused|cancelled",
//	           "category":"<failure category or empty>",
//	           "refined":"", "refused":"", "why":"ranked", "relay":1}],
//	 "verdict":"<closed code>","candidates":4,"already_connected":false}
//
// Returns the number of bytes written, or -1 if the engine is not
// initialised. A pass in which nothing carried is NOT an error: the
// answer is in the JSON.
//
//export engine_connect_auto
func engine_connect_auto(out unsafe.Pointer, outLen C.int) C.int {
	body, err := ConnectAuto()
	if err != nil {
		return exportFail("engine_connect_auto", err)
	}
	return copyOut(body, out, outLen)
}
