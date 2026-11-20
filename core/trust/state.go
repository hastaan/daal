package trust

import (
	"database/sql"
	"errors"
	"fmt"
	"runtime"
	"time"

	"daal/bundle-go/bundle"
	"daal/bundle-go/importer"
	"daal/core/internal/selection"
	"daal/core/routestore"
)

// StoreAdapter wires a routestore.Store to the importer.State interface.
type StoreAdapter struct {
	S *routestore.Store

	// ModifierPlatformPolicy is the FRP-12 importer-side platform
	// gate. Nil is intentionally fail-closed for modifier-bearing
	// routes: at FRP-12 ship every modifier spec is PENDING, so no
	// modifier kind is importable until a later censor-lab PASS phase
	// wires a concrete policy.
	ModifierPlatformPolicy ModifierPlatformPolicy

	// ModifierRuntimeGOOS and ModifierDesktopHint are test/embedding
	// overrides for the modifier platform gate. Empty RuntimeGOOS uses
	// runtime.GOOS. DesktopHint defaults true for desktop GOOS values
	// (linux/darwin/windows), false for android/ios.
	ModifierRuntimeGOOS string
	ModifierDesktopHint bool
}

// ModifierPlatformPolicy is the trust-package view of the FRP-12
// modifier allow-list. It deliberately avoids exporting
// core/internal/selection types through StoreAdapter's public shape.
type ModifierPlatformPolicy func(kind string) ModifierPlatformAllow

// ModifierPlatformAllow is one modifier kind's import-time platform
// policy. Pass=false rejects the kind regardless of platform.
type ModifierPlatformAllow struct {
	Pass      bool
	Platforms []string
}

// FreshnessMirrorsKey is the secrets_kv key holding one pack's raw,
// unverified `trust/freshness-mirrors.json` as it arrived in the .sbp.
//
// It lives in this package rather than in core/refresh (which reads it)
// because core/refresh already depends on core/trust and the reverse
// edge would be a cycle. The writer therefore owns the name, and the
// reader aliases it — one spelling, checked by the compiler, which is
// the whole reason this value goes missing when it goes missing.
func FreshnessMirrorsKey(relayPackID string) string {
	return "freshness-mirrors:" + relayPackID
}

// RouteEndpointKey is the secrets_kv key holding one route's SIGNED
// endpoint commitment (bundle.Endpoint JSON), written by SaveImport
// from a manifest whose signature the importer has just verified.
//
// The profile beside it ("route:<id>") is the outbound the engine
// dials, and nothing signs those bytes. The commitment is what the
// outbound is held to: at import (bundle/go/importer planRoutes) and
// again at set-route (core/abi), so no path that writes a profile can
// make the engine dial somewhere the publisher did not sign.
func RouteEndpointKey(routeID string) string { return "endpoint:" + routeID }

// RouteEndpointSignedAtKey is the secrets_kv key holding the signed
// manifest's bundle.created_at for the manifest that route's endpoint
// commitment came from. It is written and deleted together with
// RouteEndpointKey, and read back by DeviceRoute so the importer can
// refuse to merge a signed skeleton that is OLDER than what the route
// holds (bundle/go/importer planRoutes, rule 4): the skeleton is public
// and an in-place key rotation keeps the pack id, so without this an
// old file would silently return a phone to a burned relay key.
func RouteEndpointSignedAtKey(routeID string) string { return "endpoint-signed-at:" + routeID }

// DeviceRoute implements importer.DeviceRoutes: what this device
// already holds for a route id, so the importer can apply a NEW signed
// endpoint to credentials that are already here instead of replacing a
// working profile with a credential-less one.
func (a *StoreAdapter) DeviceRoute(routeID string) (importer.DeviceRoute, bool, error) {
	row, err := a.S.GetRoute(routeID)
	if errors.Is(err, sql.ErrNoRows) {
		return importer.DeviceRoute{}, false, nil
	}
	if err != nil {
		return importer.DeviceRoute{}, false, err
	}
	// A revoked or expired route is not something to carry forward.
	if row.TrustState == "revoked" || row.TrustState == "expired" {
		return importer.DeviceRoute{}, false, nil
	}
	profile, err := a.S.GetSecret("route:" + routeID)
	if err != nil {
		// No readable profile is "nothing to merge", not a failed import.
		return importer.DeviceRoute{}, false, nil
	}
	// Absent (a route stored before these were kept) is not an error:
	// the importer then declines file-path merges into this route.
	endpoint, _ := a.S.GetSecret(RouteEndpointKey(routeID))
	signedAt, _ := a.S.GetSecret(RouteEndpointSignedAtKey(routeID))
	return importer.DeviceRoute{
		PublisherFingerprint: row.PublisherID,
		RelayPackID:          row.RelayPackID,
		TransportFamily:      row.TransportFamily,
		Profile:              profile,
		Endpoint:             endpoint,
		SignedAt:             string(signedAt),
	}, true, nil
}

// RouteCommitted implements importer.CommittedRoutes: does this device
// hold a route under that id that is bound to a signed endpoint, or
// that belongs to a RelayPack? Asked of the row in ANY trust state — an
// expired or revoked committed route is still not one an
// unauthenticated route may take the place of. A commitment that is
// present but unreadable counts as present (fail closed). A commitment
// left behind by a route the user has since removed does not: there is
// no route for it to protect.
func (a *StoreAdapter) RouteCommitted(routeID string) (bool, error) {
	row, err := a.S.GetRoute(routeID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if row.RelayPackID != "" {
		return true, nil
	}
	raw, err := a.S.GetSecret(RouteEndpointKey(routeID))
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return true, nil
	}
	return len(raw) > 0, nil
}

// LookupPublisher implements importer.State.
func (a *StoreAdapter) LookupPublisher(fingerprint string) (importer.Pin, bool, error) {
	row, err := a.S.GetPublisher(fingerprint)
	if errors.Is(err, sql.ErrNoRows) {
		return importer.Pin{}, false, nil
	}
	if err != nil {
		return importer.Pin{}, false, err
	}
	return importer.Pin{
		TrustLevel:    row.TrustLevel,
		KeyStatus:     row.KeyStatus,
		DisplayName:   row.DisplayName,
		RotationChain: row.RotationChain,
	}, true, nil
}

// SaveImport implements importer.State. The publisher row is upserted, then
// each route row is inserted, then each route's profile bytes are
// age-encrypted into secrets_kv keyed by `route:<route_id>`.
func (a *StoreAdapter) SaveImport(p importer.PublisherInput, routes []importer.RouteInput) error {
	for _, r := range routes {
		if r.RelayPack == nil {
			continue
		}
		if err := a.rejectDisallowedModifiers(r.RelayPack.ModifiersJSON); err != nil {
			return fmt.Errorf("modifier platform gate route %s: %w", r.RouteID, err)
		}
	}
	// A commitment is sticky (bundle/go/importer endpoint_plan.go,
	// rule 5). The importer refuses this before it gets here; the store
	// holds the line itself, BEFORE writing anything, so that no other
	// caller and no State wrapper can overwrite a route that is checked
	// against its publisher's signature with one that is not — which
	// would also blank relay_pack_id and drop the stored commitment,
	// the two things core/abi routeEndpointGuard keys on.
	for _, r := range routes {
		if len(r.Endpoint) > 0 {
			continue
		}
		held, err := a.RouteCommitted(r.RouteID)
		if err != nil {
			return fmt.Errorf("save route %s: %w", r.RouteID, err)
		}
		if held {
			return fmt.Errorf("save route %s: %w", r.RouteID, importer.ErrEndpointDowngrade)
		}
	}

	pubRow := routestore.PublisherRow{
		PublisherID:       p.Fingerprint,
		DisplayName:       p.DisplayName,
		TrustLevel:        p.TrustLevel,
		FirstSeen:         p.FirstSeen,
		LastSeenBundle:    p.LastSeenBundle,
		KeyStatus:         p.KeyStatus,
		RotationChain:     p.RotationChain,
		RevocationSources: []string{},
	}
	// First-seen path keeps any existing FirstSeen; LookupPublisher would
	// have caught a pinned row earlier. We always overwrite LastSeenBundle.
	if existing, err := a.S.GetPublisher(p.Fingerprint); err == nil {
		pubRow.FirstSeen = existing.FirstSeen
		pubRow.RevocationSources = existing.RevocationSources
		if pubRow.TrustLevel == "" {
			pubRow.TrustLevel = existing.TrustLevel
		}
	}
	if err := a.S.UpsertPublisher(pubRow); err != nil {
		return err
	}
	if err := a.S.AppendTrustAudit(p.Fingerprint, "*", p.TrustLevel,
		"import via Phase 1B importer", time.Now().UTC()); err != nil {
		return err
	}
	// One pack's mirror set is denormalised onto every one of its
	// candidates; write it once.
	mirrorsSaved := map[string]bool{}
	for _, r := range routes {
		row := routestore.RouteRow{
			RouteID:         r.RouteID,
			TransportFamily: r.TransportFamily,
			Engine:          r.Engine,
			SourceType:      r.SourceType,
			PublisherID:     p.Fingerprint,
			PublisherLabel:  p.DisplayName,
			TrustState:      r.TrustState,
			ScarcityClass:   r.ScarcityClass,
			ModesAllowed:    r.ModesAllowed,
			ExpiresAt:       r.ExpiresAt,
			ImportedAt:      r.ImportedAt,
			// The engine's part of the signed family_specific_config
			// (importer RouteInput.EngineConfig; "" stores "{}"). Written
			// on every save, so a refreshed pack that drops its cover
			// names or its desync offer drops them here too.
			FamilySpecificConfigJSON: r.EngineConfig,
		}
		// FRP-2: copy parsed-and-validated RelayPack metadata onto
		// the routestore row when present. nil RelayPack leaves all
		// 9 RouteRow fields zero-valued (sentinel-empty per
		// schema defaults; legacy-route path).
		if r.RelayPack != nil {
			row.ExposureMode = r.RelayPack.ExposureMode
			row.FamilyClass = r.RelayPack.FamilyClass
			row.ProbingRiskClass = r.RelayPack.ProbingRiskClass
			row.PublicRiskTags = append([]string(nil), r.RelayPack.PublicRiskTags...)
			row.OriginRiskTags = append([]string(nil), r.RelayPack.OriginRiskTags...)
			row.ModifiersJSON = r.RelayPack.ModifiersJSON
			row.RelayPackID = r.RelayPack.RelayPackID
			row.FreshnessURL = r.RelayPack.FreshnessURL
			row.SharedRiskGraphJSON = r.RelayPack.SharedRiskGraphJSON
		}
		if err := a.S.UpsertRoute(row); err != nil {
			return fmt.Errorf("save route %s: %w", r.RouteID, err)
		}
		// FRP-8: park the pack's signed freshness mirror set where the
		// refresher can find it.
		//
		// This is the ONE seam every import path shares — .sbp file,
		// QR/URI paste, subscription refresh, bootstrap directory and
		// the freshness path itself all end at SaveImport — which is
		// why it is here and not sprinkled over the seven callers of
		// importer.ImportBytes. The row's FreshnessURL is a SINGLE url
		// (the manifest's legacy scalar); without this, a recipient
		// holding a 3-mirror pack polls one host until a refresh
		// succeeds, and the recipient who needs the other two is by
		// definition the one whose refreshes are failing.
		//
		// Stored raw and UNVERIFIED, deliberately: this entry is not
		// covered by manifest.sig, so it is attacker-writable in
		// transit. core/refresh verifies its publisher signature
		// against the pinned key on every read, before any URL in it
		// is dialled. Nothing here may treat it as trusted, and a
		// failure to store it must not fail the import — the pack and
		// its routes are the thing the user asked for; losing the
		// spare endpoints degrades recovery, refusing the import
		// destroys the route.
		if r.RelayPack != nil && r.RelayPack.RelayPackID != "" &&
			r.RelayPack.FreshnessMirrorsJSON != "" && !mirrorsSaved[r.RelayPack.RelayPackID] {
			mirrorsSaved[r.RelayPack.RelayPackID] = true
			_ = a.S.PutSecret(FreshnessMirrorsKey(r.RelayPack.RelayPackID),
				[]byte(r.RelayPack.FreshnessMirrorsJSON))
		}
		if len(r.Profile) > 0 {
			if err := a.S.PutSecret("route:"+r.RouteID, r.Profile); err != nil {
				return fmt.Errorf("save profile %s: %w", r.RouteID, err)
			}
		}
		// The signed endpoint travels with the profile it bounds. A
		// failure to store it FAILS the import: a RelayPack route with
		// no stored commitment is one the engine refuses to dial
		// (core/abi routeEndpointGuard), so carrying on would list a
		// route that cannot be activated. A route that is not part of
		// a RelayPack has none; the only commitment that can still be
		// under its id here is one left behind by a route the user has
		// since removed (a route that still exists and is committed
		// was refused at the top of this function), and that one must
		// not stay behind to veto the new route.
		if len(r.Endpoint) > 0 {
			// The standby travels with the commitment it stands beside
			// (saveStandby): what this device held there is removed
			// FIRST, so every state a failure can leave behind is
			// narrower than either the old or the new one.
			if err := a.forgetStandby(r.RouteID, len(r.Standby) == 0); err != nil {
				return fmt.Errorf("save standby %s: %w", r.RouteID, err)
			}
			if err := a.S.PutSecret(RouteEndpointKey(r.RouteID), r.Endpoint); err != nil {
				return fmt.Errorf("save endpoint %s: %w", r.RouteID, err)
			}
			// When that endpoint was signed. Written on every save so
			// it always describes the commitment beside it; a failure
			// fails the import for the same reason as above, and
			// because a commitment with a stale date would let an older
			// signed skeleton be merged over it.
			if r.SignedAt == "" {
				_ = a.S.DeleteSecret(RouteEndpointSignedAtKey(r.RouteID))
			} else if err := a.S.PutSecret(RouteEndpointSignedAtKey(r.RouteID), []byte(r.SignedAt)); err != nil {
				return fmt.Errorf("save endpoint date %s: %w", r.RouteID, err)
			}
			if len(r.Standby) > 0 {
				if err := a.S.PutSecret(bundle.StandbyStoreKey(r.RouteID), append([]byte(nil), r.Standby...)); err != nil {
					return fmt.Errorf("save standby %s: %w", r.RouteID, err)
				}
			}
		} else {
			// No commitment: no standby either. Removed before the
			// commitment, for the same reason as above.
			if err := a.forgetStandby(r.RouteID, true); err != nil {
				return fmt.Errorf("save standby %s: %w", r.RouteID, err)
			}
			_ = a.S.DeleteSecret(RouteEndpointKey(r.RouteID))
			_ = a.S.DeleteSecret(RouteEndpointSignedAtKey(r.RouteID))
		}
	}
	return nil
}

// forgetStandby removes the route's stored `_standby`
// (bundle.StandbyStoreKey) and, when withKey, any standby key accepted
// for it (bundle.StandbyKeyStoreKey: 16 raw bytes).
//
// THE STANDBY AND ITS COMMITMENT (specs/relaypack-v1.md "`_standby`
// key", "On the device"). `_standby` names a second address of the
// relay; the set-route guard (core/abi routeEndpointGuard) lets an
// outbound sit there only while it is stored. The store has no
// transaction across secrets, so SaveImport orders the writes instead:
// the old standby goes first, then the commitment is written, then the
// new standby. A failure at any step leaves the route with NO standby
// beside whichever commitment it holds — never an old address beside a
// new commitment (a publisher may have released that address), and
// never a new one beside an old commitment. Every step that fails
// fails the import, as a commitment that cannot be stored does.
//
// The key is kept when the new pack still carries a `_standby`: a key
// only ever opens the commitment it hashes to (bundle Standby.Matches,
// checked at every connect), so one that does not match the new
// commitment is inert, and one that does was accepted for exactly this
// address. A pack WITHOUT `_standby` removes it: the publisher has
// withdrawn the standby, and the address inside the key may already be
// someone else's.
func (a *StoreAdapter) forgetStandby(routeID string, withKey bool) error {
	if err := a.S.DeleteSecret(bundle.StandbyStoreKey(routeID)); err != nil {
		return err
	}
	if withKey {
		return a.S.DeleteSecret(bundle.StandbyKeyStoreKey(routeID))
	}
	return nil
}

func (a *StoreAdapter) rejectDisallowedModifiers(modifiersJSON string) error {
	if modifiersJSON == "" || modifiersJSON == "null" || modifiersJSON == "[]" {
		return nil
	}
	goos := a.ModifierRuntimeGOOS
	if goos == "" {
		goos = runtime.GOOS
	}
	policy := selection.PolicyFn(func(kind string) selection.AllowOf {
		if a.ModifierPlatformPolicy == nil {
			return selection.MakeAllow(false)
		}
		allow := a.ModifierPlatformPolicy(kind)
		return selection.MakeAllow(allow.Pass, allow.Platforms...)
	})
	return selection.RejectByPlatform(modifiersJSON, goos, a.modifierDesktopHint(goos), policy)
}

func (a *StoreAdapter) modifierDesktopHint(goos string) bool {
	if a.ModifierDesktopHint {
		return true
	}
	switch goos {
	case "linux", "darwin", "windows":
		return true
	default:
		return false
	}
}

// MarkPublisherRevoked implements importer.State.
func (a *StoreAdapter) MarkPublisherRevoked(fingerprint, source, reason string, now time.Time) error {
	return MarkRevoked(a.S, fingerprint, reason, source, now)
}

// MarkRouteRevoked implements importer.State.
func (a *StoreAdapter) MarkRouteRevoked(routeID string) error {
	return a.S.MarkRouteRevoked(routeID)
}
