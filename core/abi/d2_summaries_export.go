//go:build cshared

package abi

import "C"

import "unsafe"

//export engine_route_summary
func engine_route_summary(routeID *C.char, out unsafe.Pointer, outLen C.int) C.int {
	body, err := RouteSummary(C.GoString(routeID))
	if err != nil && body == "" {
		return -1
	}
	return copyOut(body, out, outLen)
}

//export engine_available_routes
func engine_available_routes(out unsafe.Pointer, outLen C.int) C.int {
	body, err := AvailableRoutes()
	if err != nil && body == "" {
		return -1
	}
	return copyOut(body, out, outLen)
}

//export engine_throughput_snapshot
func engine_throughput_snapshot(out unsafe.Pointer, outLen C.int) C.int {
	body, err := ThroughputSnapshot()
	if err != nil && body == "" {
		return -1
	}
	return copyOut(body, out, outLen)
}

//export engine_panic_wipe
func engine_panic_wipe() C.int {
	if err := PanicWipe(); err != nil {
		return -1
	}
	return 0
}
