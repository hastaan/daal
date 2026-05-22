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
