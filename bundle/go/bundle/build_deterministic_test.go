package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestDeterministicBuildIsByteIdentical(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// VerifyBundle checks expiry against the wall clock, so the
	// window is derived from now — hardcoded dates turn this test
	// into a time bomb (it went red 2026-05-25). Determinism is
	// asserted by building twice from the SAME manifest, so dynamic
	// timestamps cost nothing.
	created := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	expires := time.Now().UTC().Add(30 * 24 * time.Hour).Format(time.RFC3339)
	manifest := Manifest{
		SpecVersion: 1,
		Publisher: PublisherInfo{
			Name:              "Det Publisher",
			KeyFingerprintHex: PublisherFingerprint(pub).Hex,
			KeyCreatedAt:      created,
			TrustClass:        "community",
		},
		Bundle: BundleInfo{
			ID:             "bundle-det",
			Type:           "provider",
			CreatedAt:      created,
			ExpiresAt:      expires,
			SupersedesKeys: []string{},
		},
		Routes: []RouteManifestEntry{{
			ID:              "route-det",
			ScarcityClass:   "normal",
			TransportFamily: "vless-reality",
			ConfigPath:      "profiles/route-det.json",
			ValidFrom:       created,
			ValidUntil:      expires,
		}},
	}
	profiles := map[string][]byte{"profiles/route-det.json": []byte(`{"type":"direct"}`)}

	a, err := BuildSignedBundleDeterministic(manifest, profiles, nil, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuildSignedBundleDeterministic(manifest, profiles, nil, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("deterministic build returned different bytes: %d vs %d", len(a), len(b))
	}

	// Round-trip parse + verify on the deterministic bytes.
	parsed, err := ParseSBP(bytes.NewReader(a), int64(len(a)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := VerifyBundle(parsed); err != nil {
		t.Fatalf("verify: %v", err)
	}
	_ = time.Now
}
