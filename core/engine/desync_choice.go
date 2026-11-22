package engine

import "daal/core/desync"

// RouteDesyncChoice returns the run-time desync choice SetRouteDesync
// made for the route, if any — so a caller that sets one for a while
// (the network test forces the split off, then on) can put back exactly
// what was there. ok=false: no run-time choice; ClearRouteDesync is the
// way back.
func RouteDesyncChoice(routeID string) (desync.Strategy, bool) { return routeDesyncChoice(routeID) }
