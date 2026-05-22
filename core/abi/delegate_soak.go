// Phase 3F. Helpers the soak engine binary uses to seed
// delegate-share routes without a full bundle import. Linked
// into release builds too — the function does only what the
// release-surface route-import path would do, so no
// soak-specific code paths sneak into production.

package abi

import (
	"errors"
	"time"

	"daal/core/routestore"
)

// SoakSeedDelegateRoute creates (or upserts) a publisher +
// route with the supplied (policy, cap). The route uses
// transport_family = vless-reality + scarcity_class = normal
// for shape parity with the rest of the soak rig. Used only
// by the soak engine binary; not part of the release ABI.
func SoakSeedDelegateRoute(routeID, policy string, cap uint8) error {
	c := tryGetCore()
	if c == nil || c.store == nil {
		return errors.New("soak: engine not initialised")
	}
	const pubID = "soak-3f-publisher"
	if err := c.store.UpsertPublisher(routestore.PublisherRow{
		PublisherID: pubID, DisplayName: "Soak Publisher",
		TrustLevel:     "trusted_provider",
		FirstSeen:      time.Now().UTC().Format(time.RFC3339),
		LastSeenBundle: time.Now().UTC().Format(time.RFC3339),
		KeyStatus:      "active",
		RotationChain:  []string{}, RevocationSources: []string{},
	}); err != nil {
		return err
	}
	now := time.Now().UTC()
	return c.store.UpsertRoute(routestore.RouteRow{
		RouteID:              routeID,
		TransportFamily:      "vless-reality",
		Engine:               "sing-box",
		SourceType:           "trusted_provider",
		PublisherID:          pubID,
		PublisherLabel:       "Soak Publisher",
		TrustState:           "tofu",
		ScarcityClass:        "normal",
		ModesAllowed:         []string{"normal"},
		ExpiresAt:            now.Add(7 * 24 * time.Hour).Format(time.RFC3339),
		ImportedAt:           routestore.HourBucket(now),
		RedistributionPolicy: policy,
		RedistributionCap:    cap,
	})
}
