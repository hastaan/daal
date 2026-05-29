package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

// TestVerifyBundleFor_NoBinding pins back-compat: a manifest with
// empty bundle.recipient_fp_hex (a legacy V1.5 pack) verifies even
// when a recipient identity is supplied.
func TestVerifyBundleFor_NoBinding(t *testing.T) {
	data := mustSignedBundle(t, baseManifest(t, "normal", "vless-reality", time.Now().Add(24*time.Hour)), nil)
	b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundleFor(b, make([]byte, 32)); err != nil {
		t.Fatalf("VerifyBundleFor unexpectedly failed: %v", err)
	}
}

// TestVerifyBundleFor_Match — a pack with a non-empty binding
// verifies when the supplied identity matches.
func TestVerifyBundleFor_Match(t *testing.T) {
	var pub [32]byte
	if _, err := rand.Read(pub[:]); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(pub[:])
	fp := hex.EncodeToString(sum[:])

	m := baseManifest(t, "normal", "vless-reality", time.Now().Add(24*time.Hour))
	m.Bundle.RecipientFPHex = fp
	data := mustSignedBundle(t, m, nil)

	b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundleFor(b, pub[:]); err != nil {
		t.Fatalf("matching identity rejected: %v", err)
	}
}

// TestVerifyBundleFor_Mismatch — wrong identity returns
// ErrRecipientMismatch.
func TestVerifyBundleFor_Mismatch(t *testing.T) {
	var pubA, pubB [32]byte
	if _, err := rand.Read(pubA[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(pubB[:]); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(pubA[:])
	fp := hex.EncodeToString(sum[:])

	m := baseManifest(t, "normal", "vless-reality", time.Now().Add(24*time.Hour))
	m.Bundle.RecipientFPHex = fp
	data := mustSignedBundle(t, m, nil)

	b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundleFor(b, pubB[:]); !errors.Is(err, ErrRecipientMismatch) {
		t.Fatalf("got %v, want ErrRecipientMismatch", err)
	}
}

// TestVerifyBundleFor_MalformedIdentity — non-32-byte local
// identity returns ErrRecipientIdentityMalformed.
func TestVerifyBundleFor_MalformedIdentity(t *testing.T) {
	m := baseManifest(t, "normal", "vless-reality", time.Now().Add(24*time.Hour))
	m.Bundle.RecipientFPHex = "00" // any non-empty value
	data := mustSignedBundle(t, m, nil)

	b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundleFor(b, []byte{1, 2, 3}); !errors.Is(err, ErrRecipientIdentityMalformed) {
		t.Fatalf("got %v, want ErrRecipientIdentityMalformed", err)
	}
}

// TestVerifyBundle_IgnoresBindingWhenNoIdentity — base
// VerifyBundle (no recipient identity) skips the binding check
// even when the field is present, because the field is part of
// the signed payload and tampering would fail VerifyManifest.
func TestVerifyBundle_IgnoresBindingWhenNoIdentity(t *testing.T) {
	m := baseManifest(t, "normal", "vless-reality", time.Now().Add(24*time.Hour))
	m.Bundle.RecipientFPHex = "deadbeef"
	data := mustSignedBundle(t, m, nil)

	b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(b); err != nil {
		t.Fatalf("VerifyBundle without identity rejected: %v", err)
	}
}

// TestRecipientFPHex_IsPartOfSignedPayload — flipping a bit of the
// binding field after signing fails the signature check, proving
// the field is part of the canonical signed manifest.
func TestRecipientFPHex_IsPartOfSignedPayload(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := baseManifestWithKey(t, pub, "normal", "vless-reality", time.Now().Add(24*time.Hour))
	m.Bundle.RecipientFPHex = "aa" + hex.EncodeToString(make([]byte, 31))
	sig, err := SignManifest(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	// Now tamper.
	m.Bundle.RecipientFPHex = "bb" + hex.EncodeToString(make([]byte, 31))
	if err := VerifyManifest(m, sig, pub); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tampering with recipient_fp_hex was not detected: %v", err)
	}
}
