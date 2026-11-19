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
	if err := loadedCore().store.DeleteRoute(routeID); err != nil {
		return err
	}
	// The per-network memory of the route goes with it (best effort).
	if st := netmemStore(); st != nil {
		_ = st.ForgetRoute(routeID)
	}
	return nil
}

// PublisherDelete is engine_publisher_delete: hard-remove a publisher and
// ALL of its imported routes. Returns the number of routes removed.
func PublisherDelete(publisherID string) (int, error) {
	if loadedCore() == nil {
		return 0, errors.New("abi: not initialized")
	}
	c := loadedCore()
	var ids []string
	if rows, err := c.store.ListRoutes(); err == nil {
		for _, r := range rows {
			if r.PublisherID == publisherID {
				ids = append(ids, r.RouteID)
			}
		}
	}
	n, err := c.store.DeletePublisher(publisherID)
	if err == nil {
		if st := netmemStore(); st != nil {
			for _, id := range ids {
				_ = st.ForgetRoute(id)
			}
		}
	}
	return n, err
}
