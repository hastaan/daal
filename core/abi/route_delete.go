package abi

import "errors"

// RouteDelete is engine_route_delete: hard-remove a single imported route
// (and its per-route secrets) from the device store. Distinct from a
// revoke — the route vanishes entirely. Callers should disconnect first if
// the route is active; deleting a stored route does not tear down a live
// tunnel by itself.
func RouteDelete(routeID string) error {
	if loadedCore() == nil {
		return errors.New("abi: not initialized")
	}
	return loadedCore().store.DeleteRoute(routeID)
}

// PublisherDelete is engine_publisher_delete: hard-remove a publisher and
// ALL of its imported routes. Returns the number of routes removed.
func PublisherDelete(publisherID string) (int, error) {
	if loadedCore() == nil {
		return 0, errors.New("abi: not initialized")
	}
	return loadedCore().store.DeletePublisher(publisherID)
}
