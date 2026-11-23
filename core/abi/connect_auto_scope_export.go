//go:build cshared

package abi

import "C"

// engine_set_auto_scope arms "Connect with this file": the NEXT
// engine_connect_auto (on Android: the VPN service's automatic connect,
// vpn_start with no route id) chooses only among these routes, and the
// automatic connect stays limited to them while it is in charge. The
// argument is a JSON list of route ids; "[]" disarms. The arm lapses
// after two minutes; a route picked by hand, a disconnect or the next
// engine_connect_auto ends the scope. See SetAutoScope
// (connect_auto_scope.go).
//
// Returns how many of the ids the store holds (>= 0), or -1 when the
// engine is not initialised or the input is not a JSON list of strings.
// Optional for the hosts (added 2026-11-23).
//
//	int engine_set_auto_scope(const char* route_ids_json);
//
//export engine_set_auto_scope
func engine_set_auto_scope(routeIDsJSON *C.char) C.int {
	n, err := SetAutoScope(C.GoString(routeIDsJSON))
	if err != nil {
		return exportFailCode("engine_set_auto_scope", -1, "not initialised, or not a JSON list of route ids")
	}
	return C.int(n)
}
