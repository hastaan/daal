package abi

import (
	"errors"
	"fmt"

	"daal/core/engine"
)

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

// routeRebound is core/trust StoreAdapter.OnRouteRebound: an import has
// saved a route whose id now names another server (a new relay under a
// reused id, a new address, a new relay key — core/trust
// route_identity.go) and has reset the route row's history. What the
// engine keeps beside the row goes too: every network's memory of the
// route and its variants (the grade, the setup time, the order of the
// next connect), and the path manager's cooldown. Takes no Core lock —
// an import may run under it.
func (c *Core) routeRebound(routeID string) {
	if st := netmemStore(); st != nil {
		_ = st.ForgetRoute(routeID)
	}
	c.pm.Forgive(routeID)
	engine.LogInfo(fmt.Sprintf("route history reset route=%s reason=another_server", engine.LogID(routeID)))
}
