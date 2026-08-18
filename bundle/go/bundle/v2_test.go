package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSpecV2BundleVerifies(t *testing.T) {
	manifest := baseManifest(t, "normal", "vless-reality", time.Now().Add(24*time.Hour))
	manifest.SpecVersion = 2
	manifest.Publisher.RevocationURL = "https://example.invalid/revocation.json"
	manifest.Publisher.RevocationFingerprintHex = "00000000000000000000000000000000000000000000000000000000000000ff"

	data := mustSignedBundle(t, manifest, nil)
	b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("parse v2: %v", err)
	}
	if b.Manifest.SpecVersion != 2 {
		t.Fatalf("expected spec_version 2, got %d", b.Manifest.SpecVersion)
	}
	if b.Manifest.Publisher.RevocationURL == "" {
		t.Fatal("expected RevocationURL to round-trip")
	}
	if err := VerifyBundle(b); err != nil {
		t.Fatalf("verify v2: %v", err)
	}
}

func TestSpecV1AndV2BothAccepted(t *testing.T) {
	for _, sv := range []int{1, 2} {
		m := baseManifest(t, "normal", "vless-reality", time.Now().Add(24*time.Hour))
		m.SpecVersion = sv
		data := mustSignedBundle(t, m, nil)
		b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			t.Fatalf("parse spec_version=%d: %v", sv, err)
		}
		if err := VerifyBundle(b); err != nil {
			t.Fatalf("verify spec_version=%d: %v", sv, err)
		}
	}
}

// FRP-1: spec_version=3 is the RelayPack profile and is accepted.
func TestSpecV3Accepted(t *testing.T) {
	m := baseManifest(t, "normal", "vless-reality", time.Now().Add(24*time.Hour))
	m.SpecVersion = 3
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m.Publisher.KeyFingerprintHex = PublisherFingerprint(pub).Hex
	data, err := BuildSignedBundle(m,
		map[string][]byte{"profiles/route.json": []byte(`{"type":"direct"}`)}, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(b); err != nil {
		t.Fatalf("expected spec_version=3 to verify cleanly, got %v", err)
	}
}

// FRP-7.5: spec_version=4 is now accepted (sub-key cert chain
// landed). spec_version=5 is the next reserved-future and
// remains rejected.
func TestSpecV4Accepted(t *testing.T) {
	m := baseManifest(t, "normal", "vless-reality", time.Now().Add(24*time.Hour))
	m.SpecVersion = 4
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m.Publisher.KeyFingerprintHex = PublisherFingerprint(pub).Hex
	data, err := BuildSignedBundle(m,
		map[string][]byte{"profiles/route.json": []byte(`{"type":"direct"}`)}, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(b); err != nil {
		t.Fatalf("expected spec_version=4 to verify cleanly post-FRP-7.5, got %v", err)
	}
}

// TestSpecV6Rejected pins the "one past the top" boundary.
//
// It used to be TestSpecV5Rejected. Wave 5 spent spec_version 5 on
// anytls (see SpecVersionAnyTLS), so the rejected value moves up by
// one — and that move IS the cost of the bump, recorded here rather
// than quietly deleted. Every verifier built before Wave 5 still
// rejects 5, which is the property the anytls gate relies on.
func TestSpecV6Rejected(t *testing.T) {
	m := baseManifest(t, "normal", "vless-reality", time.Now().Add(24*time.Hour))
	m.SpecVersion = 6
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m.Publisher.KeyFingerprintHex = PublisherFingerprint(pub).Hex
	data, err := BuildSignedBundle(m,
		map[string][]byte{"profiles/route.json": []byte(`{"type":"direct"}`)}, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(b); !errors.Is(err, ErrUnsupportedSpec) {
		t.Fatalf("expected ErrUnsupportedSpec for spec_version=6, got %v", err)
	}
}

func TestSpecV2PointerRotationRefRoundTrips(t *testing.T) {
	m := baseManifest(t, "normal", "vless-reality", time.Now().Add(24*time.Hour))
	m.SpecVersion = 2
	m.Bundle.Type = "directory"
	m.Bundle.PointerRotation = &PointerRotationRef{Path: "trust/pointer-rotation.json"}
	data := mustSignedBundle(t, m, nil)
	b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if b.Manifest.Bundle.PointerRotation == nil ||
		b.Manifest.Bundle.PointerRotation.Path != "trust/pointer-rotation.json" {
		t.Fatalf("pointer rotation ref did not round-trip: %+v", b.Manifest.Bundle.PointerRotation)
	}
	if err := VerifyBundle(b); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestSpecV2CanonicalManifestSorted(t *testing.T) {
	m := baseManifest(t, "normal", "vless-reality", time.Now().Add(24*time.Hour))
	m.SpecVersion = 2
	m.Publisher.RevocationURL = "https://example.invalid/revocation.json"
	body, err := CanonicalManifestJSON(m)
	if err != nil {
		t.Fatal(err)
	}
	// canonical JSON: keys MUST be sorted; revocation_url comes after
	// name in alpha order; the bundle ID appears before publisher.
	if !strings.Contains(string(body), `"revocation_url":"https://example.invalid/revocation.json"`) {
		t.Fatalf("revocation_url missing from canonical JSON: %s", body)
	}
}
