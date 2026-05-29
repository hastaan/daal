package bundle

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func TestValidBundleVerifies(t *testing.T) {
	data := mustSignedBundle(t, baseManifest(t, "normal", "vless-reality", time.Now().Add(24*time.Hour)), nil)
	b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := VerifyBundle(b); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestInvalidSignatureRejected(t *testing.T) {
	data := mustSignedBundle(t, baseManifest(t, "normal", "vless-reality", time.Now().Add(24*time.Hour)), nil)
	b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	b.Signature[0] ^= 0xff
	if err := VerifyBundle(b); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected invalid signature, got %v", err)
	}
}

func TestMissingManifestRejected(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	if err := writeZipFile(zw, "publisher.pub", make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if err := writeZipFile(zw, "manifest.sig", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseSBP(bytes.NewReader(buf.Bytes()), int64(buf.Len())); !errors.Is(err, ErrMissingManifest) {
		t.Fatalf("expected missing manifest, got %v", err)
	}
}

func TestExpiredRouteRejected(t *testing.T) {
	data := mustSignedBundle(t, baseManifest(t, "normal", "vless-reality", time.Now().Add(-time.Hour)), nil)
	b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := VerifyBundle(b); !errors.Is(err, ErrExpiredRoute) {
		t.Fatalf("expected expired route, got %v", err)
	}
}

func TestUnknownTransportRejected(t *testing.T) {
	data := mustSignedBundle(t, baseManifest(t, "normal", "unknown-family", time.Now().Add(24*time.Hour)), nil)
	b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := VerifyBundle(b); !errors.Is(err, ErrInvalidEnum) {
		t.Fatalf("expected invalid enum, got %v", err)
	}
}

func TestRevokedPublisherRejected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := baseManifestWithKey(t, pub, "normal", "vless-reality", time.Now().Add(24*time.Hour))
	sig, err := SignManifest(manifest, priv)
	if err != nil {
		t.Fatal(err)
	}
	b := &Bundle{
		Manifest:     manifest,
		Signature:    sig,
		PublisherPub: pub,
		Profiles:     map[string][]byte{"profiles/route.json": []byte(`{"type":"direct"}`)},
		Revocation:   &RevocationList{RevokedPublishers: []string{PublisherFingerprint(pub).Hex}},
	}
	if err := VerifyBundle(b); !errors.Is(err, ErrRevokedPublisher) {
		t.Fatalf("expected revoked publisher, got %v", err)
	}
}

func TestChangedPublisherKeyFingerprintRejected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := baseManifestWithKey(t, pub, "normal", "vless-reality", time.Now().Add(24*time.Hour))
	manifest.Publisher.KeyFingerprintHex = "changed"
	data, err := BuildSignedBundle(manifest, map[string][]byte{"profiles/route.json": []byte(`{"type":"direct"}`)}, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := VerifyBundle(b); !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatalf("expected fingerprint mismatch, got %v", err)
	}
}

func TestMissingProfileRejected(t *testing.T) {
	data := mustSignedBundle(t, baseManifest(t, "normal", "vless-reality", time.Now().Add(24*time.Hour)), map[string][]byte{})
	b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := VerifyBundle(b); !errors.Is(err, ErrMissingProfile) {
		t.Fatalf("expected missing profile, got %v", err)
	}
}

func TestFingerprintRenderingDeterministic(t *testing.T) {
	pub := bytes.Repeat([]byte{7}, ed25519.PublicKeySize)
	fp := PublisherFingerprint(pub)
	words := Wordlists{
		English: []string{"alpha", "bravo", "charlie", "delta"},
		Persian: []string{"یک", "دو", "سه", "چهار"},
	}
	a, err := RenderFingerprint(fp, words)
	if err != nil {
		t.Fatal(err)
	}
	b, err := RenderFingerprint(fp, words)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("fingerprint rendering is not deterministic")
	}
	if a.EN == "" || a.FA == "" || a.Visual == "" || a.Hex == "" {
		t.Fatalf("missing rendered fields: %+v", a)
	}
}

func mustSignedBundle(t *testing.T, manifest Manifest, profiles map[string][]byte) []byte {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Publisher.KeyFingerprintHex = PublisherFingerprint(pub).Hex
	if profiles == nil {
		profiles = map[string][]byte{"profiles/route.json": []byte(`{"type":"direct"}`)}
	}
	data, err := BuildSignedBundle(manifest, profiles, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func baseManifest(t *testing.T, scarcity, transport string, validUntil time.Time) Manifest {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return baseManifestWithKey(t, pub, scarcity, transport, validUntil)
}

func baseManifestWithKey(t *testing.T, pub ed25519.PublicKey, scarcity, transport string, validUntil time.Time) Manifest {
	t.Helper()
	fingerprint := PublisherFingerprint(pub).Hex
	return Manifest{
		SpecVersion: 1,
		Publisher: PublisherInfo{
			Name:              "Test Publisher",
			KeyFingerprintHex: fingerprint,
			KeyCreatedAt:      time.Now().UTC().Format(time.RFC3339),
			TrustClass:        "unknown",
		},
		Bundle: BundleInfo{
			ID:             "bundle-test",
			Type:           "provider",
			CreatedAt:      time.Now().UTC().Format(time.RFC3339),
			ExpiresAt:      time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
			SupersedesKeys: []string{},
		},
		Routes: []RouteManifestEntry{{
			ID:              "route-test",
			ScarcityClass:   scarcity,
			TransportFamily: transport,
			ConfigPath:      "profiles/route.json",
			ValidFrom:       time.Now().UTC().Format(time.RFC3339),
			ValidUntil:      validUntil.UTC().Format(time.RFC3339),
		}},
	}
}
