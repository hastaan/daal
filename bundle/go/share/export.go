// Package share builds export artifacts on top of bundle-go: signed
// share-bundle .sbp archives, static QR codes, and the manifest extension
// fields that the importer uses to recognize a friend-share.
package share

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"

	"daal/bundle-go/bundle"
)

// ExportInput is one route the user wants to share. Content here mirrors
// what the routestore holds, but expressed in plain-data terms so the
// share package never touches the routestore directly.
type ExportInput struct {
	RouteID           string
	TransportFamily   string
	ScarcityClass     string
	ProfileBytes      []byte // sing-box outbound JSON
	ValidFrom         time.Time
	ValidUntil        time.Time
	UDPGated          bool
	AllowRedistribute bool // legacy 1C gate; superseded at 3F by RedistributionPolicy

	// Phase 3F. Per-route redistribution policy and cap, carried
	// verbatim onto the manifest entry. Empty policy is silently
	// promoted to "none" downstream by the receiver. See
	// specs/delegate-keys-v1.md and specs/share-bundle-v1.md
	// "Phase 3F".
	RedistributionPolicy string
	RedistributionCap    uint8
}

// PublisherIdentity is the on-device share identity. Friend shares use a
// per-device ed25519 keypair so the recipient can pin "shared by Alice's
// phone" and reject if the same display name later signs with a different
// key.
type PublisherIdentity struct {
	DisplayName  string
	PublicKey    ed25519.PublicKey
	PrivateKey   ed25519.PrivateKey
	TrustClass   string // "tofu_friend"
	KeyCreatedAt time.Time
}

// BuildShareBundle constructs a signed friend-share .sbp containing the
// supplied routes. Every input route MUST set AllowRedistribute=true; the
// function returns an error if any route refuses redistribution.
func BuildShareBundle(routes []ExportInput, ident PublisherIdentity, now time.Time) ([]byte, error) {
	if len(routes) == 0 {
		return nil, errors.New("share: no routes to export")
	}
	for _, r := range routes {
		if !r.AllowRedistribute {
			return nil, fmt.Errorf("share: route %s is non-redistributable", r.RouteID)
		}
		if len(r.ProfileBytes) == 0 {
			return nil, fmt.Errorf("share: route %s has empty profile", r.RouteID)
		}
	}
	if len(ident.PrivateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("share: bad publisher private key")
	}

	// Profiles directory.
	profiles := map[string][]byte{}
	manifestRoutes := make([]bundle.RouteManifestEntry, 0, len(routes))
	for _, r := range routes {
		path := "profiles/" + sanitizeID(r.RouteID) + ".json"
		profiles[path] = append([]byte(nil), r.ProfileBytes...)
		manifestRoutes = append(manifestRoutes, bundle.RouteManifestEntry{
			ID:                   r.RouteID,
			ScarcityClass:        r.ScarcityClass,
			TransportFamily:      r.TransportFamily,
			ConfigPath:           path,
			ValidFrom:            r.ValidFrom.UTC().Format(time.RFC3339),
			ValidUntil:           r.ValidUntil.UTC().Format(time.RFC3339),
			UDPGated:             r.UDPGated,
			RedistributionPolicy: r.RedistributionPolicy,
			RedistributionCap:    r.RedistributionCap,
		})
	}

	fp := bundle.PublisherFingerprint(ident.PublicKey)
	manifest := bundle.Manifest{
		SpecVersion: 1,
		Publisher: bundle.PublisherInfo{
			Name:              ident.DisplayName,
			KeyFingerprintHex: fp.Hex,
			KeyCreatedAt:      ident.KeyCreatedAt.UTC().Format(time.RFC3339),
			TrustClass:        ident.TrustClass,
		},
		Bundle: bundle.BundleInfo{
			ID:        "share-" + ident.DisplayName + "-" + now.UTC().Format("20060102T150405Z"),
			Type:      "friend_share",
			CreatedAt: now.UTC().Format(time.RFC3339),
			ExpiresAt: now.UTC().Add(30 * 24 * time.Hour).Format(time.RFC3339),
		},
		Routes: manifestRoutes,
	}

	body, err := bundle.BuildSignedBundle(manifest, profiles, ident.PublicKey, ident.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("share: build signed bundle: %w", err)
	}
	return body, nil
}

// ShareChainHop is the wire shape of one hop in a `.sbp.share`
// redistribution_chain, mirrored from `core/delegate.ChainHop`
// + `bundle.RedistributionChainHop`. The share package owns the
// shape only insofar as it embeds it into the manifest; the
// canonical source of truth is `core/delegate`.
type ShareChainHop struct {
	DelegateFPHex  string
	DelegatePub    string
	SignedAt       string
	RecipientFPHex string
	SignatureB64   string
}

// ShareCapEntry is the wire shape of one delegate_caps[] entry,
// mirrored from `core/delegate.CapEntry`.
type ShareCapEntry struct {
	RouteID                   string
	SharedWithCountAtSignTime uint8
	CapAtSignTime             uint8
}

// BuildShareBundleDelegated constructs a `.sbp.share` (a `.sbp`
// variant whose `bundle.type == "delegated_share"`). The caller
// supplies the redistribution chain + caps already produced by
// the engine's `core/delegate` package; this function splices
// them onto the manifest, then signs+emits.
//
// The original publisher signature on the routes is preserved
// at the manifest's `manifest.sig` layer (the same Ed25519
// signing path used by `BuildShareBundle`); the chain is the
// delegate's *additional* signature trail. See
// specs/delegate-keys-v1.md "Wire format".
func BuildShareBundleDelegated(
	routes []ExportInput,
	chain []ShareChainHop,
	caps []ShareCapEntry,
	ident PublisherIdentity,
	now time.Time,
) ([]byte, error) {
	if len(routes) == 0 {
		return nil, errors.New("share: no routes to export")
	}
	if len(chain) == 0 || len(caps) == 0 {
		return nil, errors.New("share: delegated_share requires non-empty chain + caps")
	}
	if len(ident.PrivateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("share: bad publisher private key")
	}

	profiles := map[string][]byte{}
	manifestRoutes := make([]bundle.RouteManifestEntry, 0, len(routes))
	for _, r := range routes {
		if len(r.ProfileBytes) == 0 {
			return nil, fmt.Errorf("share: route %s has empty profile", r.RouteID)
		}
		path := "profiles/" + sanitizeID(r.RouteID) + ".json"
		profiles[path] = append([]byte(nil), r.ProfileBytes...)
		manifestRoutes = append(manifestRoutes, bundle.RouteManifestEntry{
			ID:                   r.RouteID,
			ScarcityClass:        r.ScarcityClass,
			TransportFamily:      r.TransportFamily,
			ConfigPath:           path,
			ValidFrom:            r.ValidFrom.UTC().Format(time.RFC3339),
			ValidUntil:           r.ValidUntil.UTC().Format(time.RFC3339),
			UDPGated:             r.UDPGated,
			RedistributionPolicy: r.RedistributionPolicy,
			RedistributionCap:    r.RedistributionCap,
		})
	}

	// Lift the share-package shapes onto the bundle-package
	// shapes. The bundle module is a separate go.mod, so we
	// pass through a small marshal layer; the wire bytes are
	// identical (locked by `bundle/go/bundle/v3f_test.go`).
	chainOut := make([]bundle.RedistributionChainHop, len(chain))
	for i, h := range chain {
		chainOut[i] = bundle.RedistributionChainHop{
			DelegateFPHex:  h.DelegateFPHex,
			DelegatePub:    h.DelegatePub,
			SignedAt:       h.SignedAt,
			RecipientFPHex: h.RecipientFPHex,
			SignatureB64:   h.SignatureB64,
		}
	}
	capsOut := make([]bundle.DelegateCapEntry, len(caps))
	for i, c := range caps {
		capsOut[i] = bundle.DelegateCapEntry{
			RouteID:                   c.RouteID,
			SharedWithCountAtSignTime: c.SharedWithCountAtSignTime,
			CapAtSignTime:             c.CapAtSignTime,
		}
	}

	fp := bundle.PublisherFingerprint(ident.PublicKey)
	manifest := bundle.Manifest{
		SpecVersion: 1,
		Publisher: bundle.PublisherInfo{
			Name:              ident.DisplayName,
			KeyFingerprintHex: fp.Hex,
			KeyCreatedAt:      ident.KeyCreatedAt.UTC().Format(time.RFC3339),
			TrustClass:        ident.TrustClass,
		},
		Bundle: bundle.BundleInfo{
			ID:        "share-" + ident.DisplayName + "-" + now.UTC().Format("20060102T150405Z"),
			Type:      "delegated_share",
			CreatedAt: now.UTC().Format(time.RFC3339),
			ExpiresAt: now.UTC().Add(30 * 24 * time.Hour).Format(time.RFC3339),
		},
		Routes:              manifestRoutes,
		RedistributionChain: chainOut,
		DelegateCaps:        capsOut,
	}

	body, err := bundle.BuildSignedBundle(manifest, profiles, ident.PublicKey, ident.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("share: build signed delegated bundle: %w", err)
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
