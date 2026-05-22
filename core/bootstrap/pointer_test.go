package bootstrap

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestPointerSetSignAndVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	set := PointerSet{
		Set:        "primary",
		IssuedAt:   now.Format(time.RFC3339),
		ValidUntil: now.Add(365 * 24 * time.Hour).Format(time.RFC3339),
		Pointers: []Pointer{
			{URL: "https://b.example/dir.sbp", ExpectedPublisherFingerprintHex: hexN(64, 'a')},
			{URL: "https://a.example/dir.sbp", ExpectedPublisherFingerprintHex: hexN(64, 'b')},
		},
	}
	signed, err := SignPointerSet(set, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPointerSet(signed, pub, now); err != nil {
		t.Fatalf("expected valid set: %v", err)
	}

	// Tamper a URL → signature must fail.
	tampered := signed
	tampered.Pointers = append([]Pointer{}, signed.Pointers...)
	tampered.Pointers[0].URL = "https://evil.example/dir.sbp"
	if err := VerifyPointerSet(tampered, pub, now); err == nil {
		t.Fatal("expected tampered set to fail signature verification")
	}

	// Tamper a fingerprint pin → signature must fail.
	tampered2 := signed
	tampered2.Pointers = append([]Pointer{}, signed.Pointers...)
	tampered2.Pointers[1].ExpectedPublisherFingerprintHex = hexN(64, 'c')
	if err := VerifyPointerSet(tampered2, pub, now); err == nil {
		t.Fatal("expected fingerprint tamper to fail")
	}

	// Expired set is rejected.
	expired := signed
	expired.ValidUntil = now.Add(-1 * time.Hour).Format(time.RFC3339)
	// Re-sign so signature matches the new ValidUntil.
	expiredSigned, err := SignPointerSet(expired, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPointerSet(expiredSigned, pub, now); err == nil {
		t.Fatal("expected expired set to be rejected")
	}

	// Wrong root pubkey → reject.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := VerifyPointerSet(signed, otherPub, now); err == nil {
		t.Fatal("expected wrong-root verify to fail")
	}
}

func TestPointerSetCanonicalOrderingIsStable(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	a := PointerSet{
		Set:        "primary",
		IssuedAt:   now.Format(time.RFC3339),
		ValidUntil: now.Add(time.Hour).Format(time.RFC3339),
		Pointers: []Pointer{
			{URL: "https://a.example/x", ExpectedPublisherFingerprintHex: hexN(64, '1')},
			{URL: "https://b.example/x", ExpectedPublisherFingerprintHex: hexN(64, '2')},
		},
	}
	b := a
	b.Pointers = []Pointer{a.Pointers[1], a.Pointers[0]}
	sa, _ := SignPointerSet(a, priv)
	sb, _ := SignPointerSet(b, priv)
	if sa.SignatureHex != sb.SignatureHex {
		t.Fatalf("expected canonical signature to be input-order independent\n a=%s\n b=%s",
			sa.SignatureHex, sb.SignatureHex)
	}
}

func hexN(n int, c byte) string {
	s := make([]byte, n)
	for i := range s {
		s[i] = c
	}
	return string(s)
}
