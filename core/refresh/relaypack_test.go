package refresh

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

func TestVerifyFreshnessDoc_RootSigned(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	doc := FreshnessDocument{
		Kind:                "daal/freshness-v1",
		RelayPackID:         "rp-1",
		CurrentBundleSHA256: stringsRepeatHex("de"),
		CurrentSignedURL:    "https://frp.example.com/current.sbp",
		LastModified:        now.Format(time.RFC3339),
		PublisherPubHex:     hex.EncodeToString(pub),
	}
	body, _ := canonicalDocBytesExcludingSignature(&doc)
	doc.SignatureHex = hex.EncodeToString(ed25519.Sign(priv, body))
	signed, _ := json.Marshal(doc)
	got, err := verifyFreshnessDoc(signed, pub, now)
	if err != nil {
		t.Fatal(err)
	}
	if got.RelayPackID != "rp-1" || got.CurrentBundleSHA256 != doc.CurrentBundleSHA256 {
		t.Errorf("round-trip lost data: %+v", got)
	}
}

func TestVerifyFreshnessDoc_UnsupportedVersion(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	bad := []byte(`{"kind":"relaypack_freshness","relay_pack_id":"rp","current_bundle_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","current_signed_url":"https://x/sbp","last_modified":"2099-01-01T00:00:00Z","publisher_pub_hex":"aa","signature_hex":""}`)
	if _, err := verifyFreshnessDoc(bad, pub, now); err != ErrFreshnessVersion {
		t.Errorf("want ErrFreshnessVersion, got %v", err)
	}
}

func TestVerifyFreshnessDoc_BadSignature(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	doc := FreshnessDocument{
		Kind:                "daal/freshness-v1",
		RelayPackID:         "rp",
		CurrentBundleSHA256: stringsRepeatHex("ab"),
		CurrentSignedURL:    "https://frp.example.com/rp.sbp",
		LastModified:        now.Format(time.RFC3339),
		PublisherPubHex:     hex.EncodeToString(pub),
		SignatureHex:        hex.EncodeToString(make([]byte, ed25519.SignatureSize)),
	}
	signed, _ := json.Marshal(doc)
	if _, err := verifyFreshnessDoc(signed, pub, now); err == nil {
		t.Fatal("want signature error")
	}
}

func TestVerifyFreshnessDoc_SubkeySigned(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	subPub, subPriv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)

	cert := struct {
		V                  int    `json:"v"`
		Kind               string `json:"kind"`
		RootFingerprintHex string `json:"root_fingerprint_hex"`
		SubkeyPubHex       string `json:"subkey_pub_hex"`
		ValidFrom          string `json:"valid_from"`
		ValidUntil         string `json:"valid_until"`
		Label              string `json:"label"`
		SignatureHex       string `json:"signature_hex"`
	}{
		V: 1, Kind: "subkey_cert",
		SubkeyPubHex: hex.EncodeToString(subPub),
		ValidFrom:    now.Add(-time.Hour).Format(time.RFC3339),
		ValidUntil:   now.Add(48 * time.Hour).Format(time.RFC3339),
	}
	sum := sha256.Sum256(rootPub)
	cert.RootFingerprintHex = hex.EncodeToString(sum[:])
	body, _ := canonicalCertBytesExcludingSignature(cert)
	cert.SignatureHex = hex.EncodeToString(ed25519.Sign(rootPriv, body))
	certJSON, _ := json.Marshal(cert)

	doc := FreshnessDocument{
		Kind:                "daal/freshness-v1",
		RelayPackID:         "rp-1",
		CurrentBundleSHA256: stringsRepeatHex("de"),
		CurrentSignedURL:    "https://frp.example.com/current.sbp",
		LastModified:        now.Format(time.RFC3339),
		PublisherPubHex:     hex.EncodeToString(rootPub),
		SubkeyCert:          certJSON,
	}
	docBody, _ := canonicalDocBytesExcludingSignature(&doc)
	doc.SignatureHex = hex.EncodeToString(ed25519.Sign(subPriv, docBody))
	signed, _ := json.Marshal(doc)

	got, err := verifyFreshnessDoc(signed, rootPub, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.SubkeyCert) == 0 {
		t.Error("subkey cert not preserved")
	}
}

func TestVerifyFreshnessDoc_SubkeyCertOutOfWindowRejected(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	subPub, subPriv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)

	cert := struct {
		V                  int    `json:"v"`
		Kind               string `json:"kind"`
		RootFingerprintHex string `json:"root_fingerprint_hex"`
		SubkeyPubHex       string `json:"subkey_pub_hex"`
		ValidFrom          string `json:"valid_from"`
		ValidUntil         string `json:"valid_until"`
		Label              string `json:"label"`
		SignatureHex       string `json:"signature_hex"`
	}{
		V: 1, Kind: "subkey_cert",
		SubkeyPubHex: hex.EncodeToString(subPub),
		ValidFrom:    now.Add(-48 * time.Hour).Format(time.RFC3339),
		ValidUntil:   now.Add(-time.Hour).Format(time.RFC3339),
	}
	sum := sha256.Sum256(rootPub)
	cert.RootFingerprintHex = hex.EncodeToString(sum[:])
	body, _ := canonicalCertBytesExcludingSignature(cert)
	cert.SignatureHex = hex.EncodeToString(ed25519.Sign(rootPriv, body))
	certJSON, _ := json.Marshal(cert)

	doc := FreshnessDocument{
		Kind:                "daal/freshness-v1",
		RelayPackID:         "rp-1",
		CurrentBundleSHA256: stringsRepeatHex("ab"),
		CurrentSignedURL:    "https://frp.example.com/current.sbp",
		LastModified:        now.Format(time.RFC3339),
		PublisherPubHex:     hex.EncodeToString(rootPub),
		SubkeyCert:          certJSON,
	}
	docBody, _ := canonicalDocBytesExcludingSignature(&doc)
	doc.SignatureHex = hex.EncodeToString(ed25519.Sign(subPriv, docBody))
	signed, _ := json.Marshal(doc)

	if _, err := verifyFreshnessDoc(signed, rootPub, now); err == nil {
		t.Fatal("want error on out-of-window cert")
	}
}

func TestEqualHex_CaseInsensitive(t *testing.T) {
	if !equalHex("ABcd", "abCD") {
		t.Error("equalHex should be case-insensitive")
	}
	if equalHex("ab", "abc") {
		t.Error("len mismatch should fail")
	}
}

func stringsRepeatHex(pair string) string {
	out := ""
	for len(out) < 64 {
		out += pair
	}
	return out[:64]
}
