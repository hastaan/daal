package trust

import (
	"database/sql"
	"errors"
	"fmt"
	"runtime"
	"time"

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
