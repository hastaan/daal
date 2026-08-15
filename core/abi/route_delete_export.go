//go:build cshared

package abi

import "C"

// engine_route_delete hard-removes one imported route. Returns 0 on
// success, -1 on error (including "not initialized").
//
//export engine_route_delete
func engine_route_delete(routeID *C.char) C.int {
	if err := RouteDelete(C.GoString(routeID)); err != nil {
		return -1
	}
	return 0
}

// engine_publisher_delete hard-removes a publisher and all of its routes.
// Returns the number of routes removed (>= 0) on success, or -1 on error.
//
//export engine_publisher_delete
func engine_publisher_delete(publisherID *C.char) C.int {
	n, err := PublisherDelete(C.GoString(publisherID))
	if err != nil {
		return -1
	}
	return C.int(n)
}
