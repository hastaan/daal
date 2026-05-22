package refresh

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"

	"daal/bundle-go/bundle"
	bundleshare "daal/bundle-go/share"
)

// BuildSyntheticSubscriptionBundle wraps the parsed routes into a
// transient signed .sbp produced under the device-local delegate key
// (the same identity Phase 1C uses for friend-shares). The resulting
// archive walks the existing importer, so trust prompts, age-encrypted
// caching, and rotation chains all work without a new code path.
//
// The synthetic publisher fingerprint matches the user's own device key.
// Display name is the subscription's profile_title (or the explicit
// displayName fallback).
func BuildSyntheticSubscriptionBundle(parsed ParsedSubscription, ident bundleshare.PublisherIdentity,
	displayName string, subscriptionID string, now time.Time) ([]byte, error) {

	if len(parsed.Routes) == 0 {
		return nil, errors.New("synthetic: no routes parsed")
	}
	if len(ident.PrivateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("synthetic: bad device key")
	}

	profiles := map[string][]byte{}
	manifestRoutes := make([]bundle.RouteManifestEntry, 0, len(parsed.Routes))
	for _, r := range parsed.Routes {
		path := "profiles/" + sanitizeID(r.RouteID) + ".json"
		profiles[path] = append([]byte(nil), r.OutboundJSON...)
		manifestRoutes = append(manifestRoutes, bundle.RouteManifestEntry{
			ID:              r.RouteID,
			ScarcityClass:   "normal",
			TransportFamily: r.TransportFamily,
			ConfigPath:      path,
			ValidFrom:       now.UTC().Format(time.RFC3339),
			ValidUntil:      now.UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
		})
	}

	pubName := displayName
	if pubName == "" {
		pubName = parsed.ProfileTitle
	}
	if pubName == "" {
		pubName = "Subscription"
	}

	fp := bundle.PublisherFingerprint(ident.PublicKey)
	manifest := bundle.Manifest{
		SpecVersion: 2, // synthetic bundles are produced by Phase 1.5A clients
		Publisher: bundle.PublisherInfo{
			Name:              pubName,
			KeyFingerprintHex: fp.Hex,
			KeyCreatedAt:      ident.KeyCreatedAt.UTC().Format(time.RFC3339),
			TrustClass:        "tofu_friend", // matches the per-device share identity
		},
		Bundle: bundle.BundleInfo{
			ID: "subscription-" + subscriptionID + "-" + now.UTC().Format("20060102T150405Z"),
			// The bundle TYPE remains "friend_share" so the existing
			// importer + cache code accepts it; the source_type column
			// at routestore-write time records "subscription".
			Type:      "friend_share",
			CreatedAt: now.UTC().Format(time.RFC3339),
			ExpiresAt: now.UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
		},
		Routes: manifestRoutes,
	}

	body, err := bundle.BuildSignedBundle(manifest, profiles, ident.PublicKey, ident.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("synthetic: build: %w", err)
	}
	return body, nil
}

func sanitizeID(s string) string {
	out := strings.Builder{}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			out.WriteRune(r)
		default:
			out.WriteByte('_')
		}
	}
	return out.String()
}

// Identity is a thin local alias so callers don't need to import
// daal/bundle-go/share by name; refresh.Identity is the shape the ABI
// layer threads through.
type Identity = bundleshare.PublisherIdentity
