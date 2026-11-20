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
//
// Two commitment shapes are stored under the same key, told apart by
// bundle.IsCDNCommitment:
//
//   - a direct endpoint (bundle.Endpoint). The outbound's server may be
//     the committed one, or — the standby add-on — the route's open
//     standby, or the address inside a held standby key that matches
//     the sealed commitment (bundle.CheckOutboundStandby). Nothing else
//     is relaxed, and never for shadowsocks;
//   - a CDN-fronted endpoint (bundle.CDNEndpoint), checked by
//     bundle.CheckCDNOutbound.
func routeEndpointGuard(st endpointSecrets, row routestore.RouteRow, profile []byte) error {
	raw, err := st.GetSecret(trust.RouteEndpointKey(row.RouteID))
	if err != nil || len(raw) == 0 {
		if row.RelayPackID != "" {
			return fmt.Errorf("%w: route %s has no signed endpoint: %w", ErrRouteEndpoint, row.RouteID, ErrRouteNeedsNewFile)
		}
		return nil
	}
	if bundle.IsCDNCommitment(raw) {
		cep, err := bundle.ParseCDNEndpointJSON(row.TransportFamily, raw)
		if err != nil {
			return fmt.Errorf("%w: route %s: stored CDN endpoint is unusable", ErrRouteEndpoint, row.RouteID)
		}
		if err := bundle.CheckCDNOutbound(cep, profile); err != nil {
			return fmt.Errorf("%w: route %s: %v", ErrRouteEndpoint, row.RouteID, err)
		}
		return nil
	}
	var ep bundle.Endpoint
	if err := json.Unmarshal(raw, &ep); err != nil {
		return fmt.Errorf("%w: route %s: stored endpoint is unreadable", ErrRouteEndpoint, row.RouteID)
	}
	sb, key := routeStandby(st, row, &ep)
	if err := bundle.CheckOutboundStandby(row.TransportFamily, &ep, sb, key, profile); err != nil {
		return fmt.Errorf("%w: route %s: %v", ErrRouteEndpoint, row.RouteID, err)
	}
	return nil
}

// routeStandby reads the standby a route may be dialled at: its signed
// `_standby` (bundle.StandbyStoreKey) and any accepted key
// (bundle.StandbyKeyStoreKey, the 16 raw bytes). nil when there is
// none, when either is unreadable, or for shadowsocks — every failure
// is "no standby", which only narrows what may be dialled.
func routeStandby(st endpointSecrets, row routestore.RouteRow, ep *bundle.Endpoint) (*bundle.Standby, *bundle.StandbyKeyBytes) {
	if row.TransportFamily == string(bundle.TransportShadowsocks) {
		return nil, nil
	}
	raw, err := st.GetSecret(bundle.StandbyStoreKey(row.RouteID))
	if err != nil || len(raw) == 0 {
		return nil, nil
	}
	sb, err := bundle.ParseStandbyJSON(raw)
	if err != nil {
		return nil, nil
	}
	if sb.Mode == bundle.StandbyModeOpen && sb.Server == ep.Server {
		return nil, nil
	}
	if kb, err := st.GetSecret(bundle.StandbyKeyStoreKey(row.RouteID)); err == nil && len(kb) > 0 {
		if k, err := bundle.StandbyKeyFromBytes(kb); err == nil && sb.Matches(k) {
			return sb, &k
		}
	}
	return sb, nil
}

// routeStandbyAddress is the address a route may be dialled at instead
// of its committed server, for the ladder's address variant (S7): the
// open standby, or the address of a held key that matches the sealed
// commitment. false when the route has none (or is shadowsocks, or has
// no direct commitment). A variant built from it still goes through
// routeEndpointGuard.
func routeStandbyAddress(st endpointSecrets, row routestore.RouteRow) (string, bool) {
	raw, err := st.GetSecret(trust.RouteEndpointKey(row.RouteID))
	if err != nil || len(raw) == 0 || bundle.IsCDNCommitment(raw) {
		return "", false
	}
	var ep bundle.Endpoint
	if json.Unmarshal(raw, &ep) != nil {
		return "", false
	}
	sb, key := routeStandby(st, row, &ep)
	return sb.DialAddress(key)
}
