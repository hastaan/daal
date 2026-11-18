package importer

// endpoint_plan.go — what an import DOES with each route of a RelayPack,
// decided before anything is shown to the user or written to the store.
//
// Three rules, and every import path (file, QR, trust prompt, freshness)
// goes through the same function so they cannot drift apart:
//
//  1. AUTHENTICATED ENDPOINT. A route whose profile carries an outbound
//     must match the endpoint its publisher signed for it
//     (bundle.CheckOutbound). One route that does not match refuses the
//     WHOLE pack with a reason of its own — it is evidence the file was
//     altered after signing, and that is not a question to put to the
//     user as a trust prompt. A RelayPack route that carries an outbound
//     and no commitment at all is refused the same way: it is a format
//     that cannot say where it points.
//
//  2. NOTHING UNCONNECTABLE IS STORED. A route whose profile holds no
//     outbound — the signed skeleton's metadata-only profile, or a route
//     the minter marked `_daal_unavailable` — is never written as a
//     route. It is reported in Verdict.Unavailable so the UI can say
//     what is missing; it cannot be listed, selected or activated,
//     because it does not exist on the device.
//
//  3. A SIGNED ENDPOINT IS MERGED INTO CREDENTIALS THE DEVICE HOLDS. If
//     the device already has a working profile for that route, from the
//     same publisher, the new signed endpoint is applied to it and the
//     credentials are kept (bundle.MergeEndpoint). This is what lets the
//     publisher put the credential-less signed pack on the freshness
//     mirrors: after an address move or a cover-host change the phone
//     repairs itself and nobody is handed a file. A route that cannot be
//     merged is LEFT EXACTLY AS IT WAS. A profile that yields no
//     outbound never replaces one that does.
//
//  4. A FILE ONLY MOVES A ROUTE FORWARD. The credential-less signed
//     pack is public by design — it is what the freshness mirrors
//     serve — so anybody can keep an old one, and an in-place rotation
//     (port, cover host, REALITY key, TLS key) does not change the pack
//     id. Without a publisher-signed statement of succession (the
//     freshness document, which has its own sequence high-water mark),
//     a merge therefore also requires the incoming manifest to have
//     been signed LATER than the manifest the route's endpoint came
//     from (bundle.created_at, kept by the store beside the
//     commitment). An older one is reported and the route is left
//     exactly as it was: otherwise whoever holds a burned relay key
//     could hand a recipient the old public file and put the phone
//     back on that key. The very manifest the route is already on is a
//     no-op and is allowed.
//
//  5. A COMMITMENT IS STICKY. Once a route on the device is held to a
//     signed endpoint (or belongs to a RelayPack), nothing that carries
//     NO commitment for that route id may replace it. A bundle with no
//     relay_pack slot has profiles that no signature covers, so one
//     genuine bundle of that kind — same publisher, same route ids,
//     profiles rewritten by anyone, no key needed — would otherwise
//     turn authenticated routes into unauthenticated ones pointing
//     wherever the rewriter chose, with no prompt. The whole import is
//     refused (ReasonEndpointDowngrade) and the routes are left as
//     they were. The store enforces the same rule on its own
//     (core/trust SaveImport), for any State and any caller.

import (
	"bytes"
	"encoding/json"
	"errors"
	"time"

	"daal/bundle-go/bundle"
)

// Reasons an import is refused by this file. They are part of the ABI:
// the UI maps each to plain-language copy.
const (
	// ReasonEndpointMismatch: an outbound disagrees with its route's
	// signed endpoint. The file was altered, or it was minted for a
	// relay that has since moved and was never re-signed.
	ReasonEndpointMismatch = "endpoint_mismatch"
	// ReasonEndpointUnauthenticated: an outbound with no signed
	// endpoint (a pack from before endpoint commitments, or one whose
	// commitment was never issued).
	ReasonEndpointUnauthenticated = "endpoint_unauthenticated"
	// ReasonEndpointMalformed: the signed commitment itself is unusable.
	ReasonEndpointMalformed = "endpoint_malformed"
	// ReasonNoCredentials: the file verifies and contains no personal
	// access for this device — it is the publisher's signed skeleton,
	// and this device holds nothing to merge it into.
	ReasonNoCredentials = "pack_has_no_credentials"
	// ReasonEndpointDowngrade: the file carries no signed endpoint for a
	// route this device already holds WITH one. Taking it would replace
	// a route that is checked against its publisher's signature by one
	// that is not (rule 5). Nothing was changed.
	ReasonEndpointDowngrade = "endpoint_downgrade"
	// ReasonPackIsOlder: the file verifies, carries no personal access,
	// and was signed before what this device already holds for the same
	// routes. Nothing was changed (rule 4).
	ReasonPackIsOlder = "pack_is_older"
)

// ErrEndpointDowngrade is the error behind ReasonEndpointDowngrade.
var ErrEndpointDowngrade = errors.New("importer: a route held to a signed endpoint cannot be replaced by one with no signed endpoint")

// Why a route in the pack did not become a route on the device.
const (
	// UnavailableNotOffered: the publisher's tool marked the route as
	// one this relay could not serve for this recipient.
	UnavailableNotOffered = "not_offered"
	// UnavailableNoCredentials: the file carries no credentials for the
	// route and the device holds none.
	UnavailableNoCredentials = "no_credentials"
	// UnavailableNeedsNewFile: the device holds credentials for the
	// route, but they cannot belong to the relay the publisher now
	// signs for (its key changed). The existing route is untouched.
	UnavailableNeedsNewFile = "needs_new_file"
	// UnavailableOlderThanDevice: the file carries no credentials for
	// the route, and what it signs for the route is older than what the
	// device already holds. The existing route is untouched (rule 4).
	UnavailableOlderThanDevice = "older_than_device"
)

// UnavailableRoute is one manifest route that was not stored, and why.
type UnavailableRoute struct {
	RouteID string
	Family  string
	Reason  string
}

// DeviceRoute is what the device already holds for one route id.
type DeviceRoute struct {
	PublisherFingerprint string
	RelayPackID          string
	TransportFamily      string
	Profile              []byte
	// Endpoint is the signed commitment the route is held to, and
	// SignedAt the bundle.created_at of the manifest it came from
	// (RouteInput.Endpoint / RouteInput.SignedAt, as stored). A State
	// that cannot supply SignedAt gets no file-path merges (rule 4).
	Endpoint []byte
	SignedAt string
}

// DeviceRoutes is implemented by a State that can show the importer the
// route a device already holds. It is optional: a State without it
// simply never merges (every credential-less route is unavailable).
type DeviceRoutes interface {
	DeviceRoute(routeID string) (DeviceRoute, bool, error)
}

// CommittedRoutes is implemented by a State that can say whether the
// device already holds a route, under that id, that is bound to a
// signed endpoint commitment or belongs to a RelayPack — in ANY trust
// state: an expired or revoked committed route is still not something
// an unauthenticated one may take the place of. An error fails the
// import (the question could not be answered; fail closed).
type CommittedRoutes interface {
	RouteCommitted(routeID string) (bool, error)
}

// plannedRoute is one route the import will store.
type plannedRoute struct {
	route    bundle.RouteManifestEntry
	profile  []byte
	endpoint []byte // the signed commitment, as JSON; nil for a non-RelayPack route
	merged   bool
}

type routePlan struct {
	routes      []plannedRoute
	unavailable []UnavailableRoute
	merged      int
}

// planRoutes applies the rules above. continuity says the caller
// has a publisher-signed statement that this pack REPLACES the one the
// device holds (the freshness document, which names the packs it
// supersedes); without it a merge additionally requires the pack ids to
// be equal, so a skeleton for one relay can never rewrite routes that
// belong to another relay of the same publisher.
func planRoutes(parsed *bundle.Bundle, st State, fingerprintHex string, continuity bool) (routePlan, string, error) {
	var plan routePlan
	usable := bundle.UsableRoutes(parsed)
	if parsed.Manifest.RelayPack == nil {
		// Not a RelayPack: no route carries a commitment, and the
		// profile bytes are covered by NO signature (sbp-v1 signs the
		// manifest, not the profiles), so whoever handles the file can
		// rewrite them. Such a route may be added; it may not REPLACE
		// one that is held to a signed endpoint (rule 5).
		committed, _ := st.(CommittedRoutes)
		for _, r := range usable {
			if committed != nil {
				held, err := committed.RouteCommitted(r.ID)
				if err != nil {
					return plan, "lookup_failed", err
				}
				if held {
					return plan, ReasonEndpointDowngrade, errRoute(r.ID, ErrEndpointDowngrade)
				}
			}
			plan.routes = append(plan.routes, plannedRoute{route: r, profile: parsed.Profiles[r.ConfigPath]})
		}
		return plan, "", nil
	}
	packID := parsed.Manifest.RelayPack.RelayPackID
	device, _ := st.(DeviceRoutes)

	for _, r := range usable {
		profile := parsed.Profiles[r.ConfigPath]
		ep, epErr := bundle.ParseEndpoint(r.FamilySpecificConfig)
		if epErr != nil && !errors.Is(epErr, bundle.ErrNoEndpoint) {
			return plan, ReasonEndpointMalformed, epErr
		}
		var epJSON []byte
		if ep != nil {
			if err := ep.Validate(r.TransportFamily); err != nil {
				return plan, ReasonEndpointMalformed, err
			}
			epJSON = endpointJSON(r)
		}

		if bundle.ProfileOutboundType(profile) != "" {
			if ep == nil {
				return plan, ReasonEndpointUnauthenticated,
					errRoute(r.ID, bundle.ErrEndpointUnauthenticated)
			}
			if err := bundle.CheckOutbound(r.TransportFamily, ep, profile); err != nil {
				return plan, ReasonEndpointMismatch, errRoute(r.ID, err)
			}
			plan.routes = append(plan.routes, plannedRoute{route: r, profile: profile, endpoint: epJSON})
			continue
		}

		// No outbound in this file for this route.
		reason := UnavailableNoCredentials
		if bundle.ProfileUnavailable(profile) {
			reason = UnavailableNotOffered
		}
		if ep != nil && device != nil {
			cur, ok, err := device.DeviceRoute(r.ID)
			if err != nil {
				return plan, "lookup_failed", err
			}
			if ok && sameFingerprint(cur.PublisherFingerprint, fingerprintHex) &&
				cur.TransportFamily == r.TransportFamily &&
				(continuity || (packID != "" && cur.RelayPackID == packID)) &&
				bundle.ProfileOutboundType(cur.Profile) != "" {
				forward := succession(continuity, parsed.Manifest.Bundle.CreatedAt, epJSON, cur)
				var merged []byte
				mErr := errors.New("importer: not a later signing than the route holds")
				if forward == successionOK {
					merged, mErr = bundle.MergeEndpoint(r.TransportFamily, ep, cur.Profile)
				}
				if mErr == nil {
					plan.routes = append(plan.routes, plannedRoute{route: r, profile: merged, endpoint: epJSON, merged: true})
					plan.merged++
					continue
				}
				reason = UnavailableNeedsNewFile
				if forward == successionOlder {
					reason = UnavailableOlderThanDevice
				}
			}
		}
		plan.unavailable = append(plan.unavailable, UnavailableRoute{
			RouteID: r.ID, Family: r.TransportFamily, Reason: reason,
		})
	}
	if len(plan.routes) == 0 {
		for _, u := range plan.unavailable {
			if u.Reason == UnavailableOlderThanDevice {
				return plan, ReasonPackIsOlder, errors.New("importer: this pack is older than what this device already holds")
			}
		}
		return plan, ReasonNoCredentials, errors.New("importer: this pack holds no route this device can connect with")
	}
	return plan, "", nil
}

const (
	successionOK      = iota // the merge may go ahead
	successionOlder          // the incoming manifest is not later than the route's
	successionUnknown        // it cannot be shown either way
)

// succession is rule 4: may a credential-less route signed at
// incomingSignedAt, committing to incomingEndpoint, be merged into cur?
//
// continuity (the freshness path) is the publisher's own signed
// statement that this pack replaces the device's, ordered by the
// freshness sequence; it needs nothing from here. Otherwise the
// incoming manifest must be strictly later than the one cur's endpoint
// came from — or be that very manifest, which changes nothing. Anything
// that cannot be established fails closed: the route is left alone.
func succession(continuity bool, incomingSignedAt string, incomingEndpoint []byte, cur DeviceRoute) int {
	if continuity {
		return successionOK
	}
	incoming, err := time.Parse(time.RFC3339, incomingSignedAt)
	if err != nil {
		return successionUnknown
	}
	held, err := time.Parse(time.RFC3339, cur.SignedAt)
	if err != nil {
		return successionUnknown
	}
	switch {
	case incoming.After(held):
		return successionOK
	case incoming.Equal(held) && sameJSON(incomingEndpoint, cur.Endpoint):
		return successionOK
	default:
		return successionOlder
	}
}

// sameJSON reports whether two JSON values are the same value,
// whatever their whitespace.
func sameJSON(a, b []byte) bool {
	var ca, cb bytes.Buffer
	if json.Compact(&ca, a) != nil || json.Compact(&cb, b) != nil {
		return false
	}
	return ca.Len() > 0 && bytes.Equal(ca.Bytes(), cb.Bytes())
}

// endpointJSON returns the signed commitment as the JSON the publisher
// wrote, for the store to keep beside the route.
func endpointJSON(r bundle.RouteManifestEntry) []byte {
	raw, ok := rawMember(r.FamilySpecificConfig, bundle.EndpointKey)
	if !ok {
		return nil
	}
	return raw
}

type routeErr struct {
	id  string
	err error
}

func (e routeErr) Error() string { return "route " + e.id + ": " + e.err.Error() }
func (e routeErr) Unwrap() error { return e.err }

func errRoute(id string, err error) error { return routeErr{id: id, err: err} }

func sameFingerprint(a, b string) bool { return a != "" && equalHex(a, b) }
