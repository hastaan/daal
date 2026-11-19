package abi

// endpoint_guard.go — the set-route half of the signed endpoint
// commitment (bundle/go/bundle/endpoint.go; specs/relaypack-v1.md
// "Endpoint commitment").
//
// The importer already refuses a pack whose outbounds disagree with
// what the publisher signed. This is the same check made once more, at
// the last moment before the engine dials, against the commitment the
// import stored. It exists because the profile in the store is just
// bytes: any path that ever writes "route:<id>" without coming through
// the importer's plan — a future import path, a migration, a bug —
// would otherwise be a way to make the engine dial an address nobody
// signed. One small function, called from SetRoute and nowhere else.

import (
	"encoding/json"
	"errors"
	"fmt"

	"daal/bundle-go/bundle"
	"daal/core/routestore"
	"daal/core/trust"
)

// ErrRouteEndpoint is returned by SetRoute when the stored outbound of
// a route does not match the endpoint its publisher signed, or when a
// RelayPack route has no signed endpoint at all. It is not a network
// failure and is never recorded as one.
var ErrRouteEndpoint = errors.New("abi: route does not match the endpoint its publisher signed")

// ErrRouteNeedsNewFile is wrapped (beside ErrRouteEndpoint) by the one
// refusal a person can do something about: the route came from a pack
// made before packs carried signed endpoints, so the file itself has to
// be replaced. The diagnostics blob reports it as
// connect_refused = "needs_new_file".
var ErrRouteNeedsNewFile = errors.New("abi: this route was imported from a file made by an older version; a new file is needed")

// endpointSecrets is the slice of the store the guard reads.
type endpointSecrets interface {
	GetSecret(key string) ([]byte, error)
}

// routeEndpointGuard returns nil when the route may be dialled.
//
//   - A stored commitment always binds: the outbound must match it.
//   - A RelayPack route (row.RelayPackID set) with NO stored commitment
//     is refused. Such a row can only come from a pack that predates
//     commitments, and "we cannot tell where this points" is not a
//     state to connect from.
//   - Any other route (pasted URI, subscription, directory) has no
//     commitment and is not this function's business.
func routeEndpointGuard(st endpointSecrets, row routestore.RouteRow, profile []byte) error {
	raw, err := st.GetSecret(trust.RouteEndpointKey(row.RouteID))
	if err != nil || len(raw) == 0 {
		if row.RelayPackID != "" {
			return fmt.Errorf("%w: route %s has no signed endpoint: %w", ErrRouteEndpoint, row.RouteID, ErrRouteNeedsNewFile)
		}
		return nil
	}
	var ep bundle.Endpoint
	if err := json.Unmarshal(raw, &ep); err != nil {
		return fmt.Errorf("%w: route %s: stored endpoint is unreadable", ErrRouteEndpoint, row.RouteID)
	}
	if err := bundle.CheckOutbound(row.TransportFamily, &ep, profile); err != nil {
		return fmt.Errorf("%w: route %s: %v", ErrRouteEndpoint, row.RouteID, err)
	}
	return nil
}
