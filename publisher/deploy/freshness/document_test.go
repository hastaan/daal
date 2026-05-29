package freshness

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestBuild_Defaults(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	body := []byte("signed sbp bytes")
	doc, err := Build(BuildOpts{
		RelayPackID:      "rp-aaaa",
		BundleBytes:      body,
		CurrentSignedURL: "https://frp.example.com/current.sbp",
		PublisherPubHex:  hex.EncodeToString(pub),
	})
	if err != nil {
		t.Fatal(err)
	}
	if doc.Kind != "daal/freshness-v1" {
		t.Errorf("kind = %q", doc.Kind)
	}
	if doc.RelayPackID != "rp-aaaa" {
		t.Errorf("relay_pack_id = %q", doc.RelayPackID)
	}
	want := sha256.Sum256(body)
	if doc.CurrentBundleSHA256 != hex.EncodeToString(want[:]) {
		t.Errorf("bundle sha = %q, want %x", doc.CurrentBundleSHA256, want)
	}
	if _, err := time.Parse(time.RFC3339, doc.LastModified); err != nil {
		t.Fatalf("last_modified parse: %v", err)
	}
}

func TestBuild_RequiresFields(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	pubHex := hex.EncodeToString(pub)
	if _, err := Build(BuildOpts{BundleBytes: []byte("x"), CurrentSignedURL: "https://x/sbp", PublisherPubHex: pubHex}); err == nil {
		t.Error("want error on empty RelayPackID")
	}
	if _, err := Build(BuildOpts{RelayPackID: "x", CurrentSignedURL: "https://x/sbp", PublisherPubHex: pubHex}); err == nil {
		t.Error("want error on empty bundle sha")
	}
	if _, err := Build(BuildOpts{RelayPackID: "x", BundleBytes: []byte("x"), PublisherPubHex: pubHex}); err == nil {
		t.Error("want error on missing signed URL")
	}
	if _, err := Build(BuildOpts{RelayPackID: "x", BundleBytes: []byte("x"), CurrentSignedURL: "http://x/sbp", PublisherPubHex: pubHex}); err == nil {
		t.Error("want error on non-https signed URL")
	}
}

func TestSign_RootRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := Build(BuildOpts{
		RelayPackID:      "rp-1",
		BundleBytes:      []byte("bundle"),
		CurrentSignedURL: "https://frp.example.com/rp-1.sbp",
		PublisherPubHex:  hex.EncodeToString(pub),
	})
	bytes_, err := Sign(doc, priv)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify(bytes_, VerifyOpts{PublisherRootPub: pub})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.RelayPackID != "rp-1" {
		t.Errorf("rp = %q", got.RelayPackID)
	}
	if len(got.SubkeyCert) != 0 {
		t.Errorf("subkey_cert should be empty for root sign, got %s", got.SubkeyCert)
	}
}

func TestSign_Tampered(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	doc, _ := Build(BuildOpts{
		RelayPackID:      "rp-1",
		BundleBytes:      []byte("x"),
		CurrentSignedURL: "https://frp.example.com/rp.sbp",
		PublisherPubHex:  hex.EncodeToString(pub),
	})
	b, _ := Sign(doc, priv)
	idx := strings.Index(string(b), "rp-1")
	if idx < 0 {
		t.Fatal("test setup")
	}
	b[idx] = 'X'
	if _, err := Verify(b, VerifyOpts{PublisherRootPub: pub}); err == nil {
		t.Fatal("want signature failure on tampered body")
	}
}

func TestSign_MissingFieldsRejected(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	bad := `{"kind":"daal/freshness-v1","relay_pack_id":"","current_bundle_sha256":"","current_signed_url":"","last_modified":"","publisher_pub_hex":"","signature_hex":""}`
	if _, err := Verify([]byte(bad), VerifyOpts{PublisherRootPub: pub}); err == nil {
		t.Fatal("want error on missing fields")
	}
}

func TestSign_WrongVersion(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	bad := `{"kind":"relaypack_freshness","relay_pack_id":"rp","current_bundle_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","current_signed_url":"https://x/sbp","last_modified":"2099-01-01T00:00:00Z","publisher_pub_hex":"aa","signature_hex":""}`
	if _, err := Verify([]byte(bad), VerifyOpts{PublisherRootPub: pub}); err == nil {
		t.Fatal("want error on unsupported kind")
	}
}

func TestSignWithSubkey_RoundTrip(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	subPub, subPriv, _ := ed25519.GenerateKey(rand.Reader)

	from := time.Now().UTC().Add(-time.Hour)
	until := time.Now().UTC().Add(48 * time.Hour)
	cert := subkeyCertWire{
		V:                  1,
		Kind:               "subkey_cert",
		RootFingerprintHex: publisherFingerprintHex(rootPub),
		SubkeyPubHex:       hex.EncodeToString(subPub),
		ValidFrom:          from.Format(time.RFC3339),
		ValidUntil:         until.Format(time.RFC3339),
		Label:              "test",
	}
	body, err := canonicalCertBytesExcludingSignature(cert)
	if err != nil {
		t.Fatal(err)
	}
	cert.SignatureHex = hex.EncodeToString(ed25519.Sign(rootPriv, body))
	certJSON, _ := json.Marshal(cert)

	doc, _ := Build(BuildOpts{
		RelayPackID:      "rp-2",
		BundleBytes:      []byte("bundle"),
		CurrentSignedURL: "https://frp.example.com/rp-2.sbp",
		PublisherPubHex:  hex.EncodeToString(rootPub),
	})
	signed, err := SignWithSubkey(doc, subPriv, certJSON)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	got, err := Verify(signed, VerifyOpts{PublisherRootPub: rootPub})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(got.SubkeyCert) == 0 {
		t.Error("subkey_cert should be populated")
	}
}

func TestSignWithSubkey_RequiresCert(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	doc, _ := Build(BuildOpts{
		RelayPackID:      "rp",
		BundleBytes:      []byte("x"),
		CurrentSignedURL: "https://frp.example.com/rp.sbp",
		PublisherPubHex:  hex.EncodeToString(pub),
	})
	if _, err := SignWithSubkey(doc, priv, nil); err == nil {
		t.Fatal("want error on missing cert")
	}
}

func TestSignWithSubkey_RootMismatchRejected(t *testing.T) {
	rootPub, _, _ := ed25519.GenerateKey(rand.Reader)
	otherRootPub, otherRootPriv, _ := ed25519.GenerateKey(rand.Reader)
	subPub, subPriv, _ := ed25519.GenerateKey(rand.Reader)

	cert := subkeyCertWire{
		V:                  1,
		Kind:               "subkey_cert",
		RootFingerprintHex: publisherFingerprintHex(otherRootPub),
		SubkeyPubHex:       hex.EncodeToString(subPub),
		ValidFrom:          time.Now().UTC().Format(time.RFC3339),
		ValidUntil:         time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
	}
	body, _ := canonicalCertBytesExcludingSignature(cert)
	cert.SignatureHex = hex.EncodeToString(ed25519.Sign(otherRootPriv, body))
	certJSON, _ := json.Marshal(cert)

	doc, _ := Build(BuildOpts{
		RelayPackID:      "rp",
		BundleBytes:      []byte("x"),
		CurrentSignedURL: "https://frp.example.com/rp.sbp",
		PublisherPubHex:  hex.EncodeToString(rootPub),
	})
	signed, _ := SignWithSubkey(doc, subPriv, certJSON)
	if _, err := Verify(signed, VerifyOpts{PublisherRootPub: rootPub}); err == nil {
		t.Fatal("want error on root mismatch")
	}
}

func TestSignWithSubkey_OutOfWindowRejected(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	subPub, subPriv, _ := ed25519.GenerateKey(rand.Reader)

	cert := subkeyCertWire{
		V:                  1,
		Kind:               "subkey_cert",
		RootFingerprintHex: publisherFingerprintHex(rootPub),
		SubkeyPubHex:       hex.EncodeToString(subPub),
		ValidFrom:          time.Now().UTC().Add(-48 * time.Hour).Format(time.RFC3339),
		ValidUntil:         time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
	}
	body, _ := canonicalCertBytesExcludingSignature(cert)
	cert.SignatureHex = hex.EncodeToString(ed25519.Sign(rootPriv, body))
	certJSON, _ := json.Marshal(cert)

	doc, _ := Build(BuildOpts{
		RelayPackID:      "rp",
		BundleBytes:      []byte("x"),
		CurrentSignedURL: "https://frp.example.com/rp.sbp",
		PublisherPubHex:  hex.EncodeToString(rootPub),
	})
	signed, _ := SignWithSubkey(doc, subPriv, certJSON)
	if _, err := Verify(signed, VerifyOpts{PublisherRootPub: rootPub}); err == nil {
		t.Fatal("want error on cert out-of-window")
	}
}
