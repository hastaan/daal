//go:build gomobile

package abi

// Hard-delete facade for the gomobile (iOS) build, mirroring the cshared
// engine_route_delete / engine_publisher_delete exports.

func (h *DaalCore) RouteDelete(routeID string) error {
	return RouteDelete(routeID)
}

// PublisherDelete returns the number of routes removed.
func (h *DaalCore) PublisherDelete(publisherID string) (int, error) {
	return PublisherDelete(publisherID)
}
