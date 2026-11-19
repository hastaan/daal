//go:build gomobile

package abi

// RouteConnectPrecheck is the gomobile twin of engine_route_precheck.
func (h *DaalCore) RouteConnectPrecheck(routeID string) (string, error) {
	return RouteConnectPrecheck(routeID)
}
