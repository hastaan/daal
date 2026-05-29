package freshness

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// subkeyCertWire is the on-disk shape of an FRP-7.5 SubkeyCert.
// Mirrors `publisher.SubkeyCert` and `bundle.subkeyCertWire` exactly
// — the freshness verifier walks the same chain the SBP verifier
// walks, so the cert shape is locked across all three modules.
type subkeyCertWire struct {
	V                  int    `json:"v"`
	Kind               string `json:"kind"`
	RootFingerprintHex string `json:"root_fingerprint_hex"`
	SubkeyPubHex       string `json:"subkey_pub_hex"`
	ValidFrom          string `json:"valid_from"`
	ValidUntil         string `json:"valid_until"`
	Label              string `json:"label"`
	SignatureHex       string `json:"signature_hex"`
}

var (
	errSubkeyCertMalformed    = errors.New("subkey cert malformed")
	errSubkeyCertRootMismatch = errors.New("subkey cert root fingerprint mismatch")
	errSubkeyCertOutOfWindow  = errors.New("subkey cert outside validity window")
	errSubkeyCertBadSig       = errors.New("subkey cert signature invalid")
)

// walkSubkeyCert parses + verifies the cert against rootPub,
// enforces its validity window with `now`, and returns the
// cert's subject sub-key on success. Mirrors the bundle's
// resolveManifestSigningKey logic exactly.
func walkSubkeyCert(certJSON []byte, rootPub ed25519.PublicKey, now time.Time) (ed25519.PublicKey, error) {
	var cert subkeyCertWire
	if err := json.Unmarshal(certJSON, &cert); err != nil {
		return nil, errSubkeyCertMalformed
	}
	if cert.V != 1 || cert.Kind != "subkey_cert" {
		return nil, errSubkeyCertMalformed
	}
	subPub, err := hex.DecodeString(cert.SubkeyPubHex)
	if err != nil || len(subPub) != ed25519.PublicKeySize {
		return nil, errSubkeyCertMalformed
	}
	rootFP := publisherFingerprintHex(rootPub)
	if cert.RootFingerprintHex != rootFP {
		return nil, errSubkeyCertRootMismatch
	}
	from, err1 := time.Parse(time.RFC3339, cert.ValidFrom)
	until, err2 := time.Parse(time.RFC3339, cert.ValidUntil)
	if err1 != nil || err2 != nil {
		return nil, errSubkeyCertMalformed
	}
	if now.Before(from) || !now.Before(until) {
		return nil, errSubkeyCertOutOfWindow
	}
	body, err := canonicalCertBytesExcludingSignature(cert)
	if err != nil {
		return nil, errSubkeyCertMalformed
	}
	sig, err := hex.DecodeString(cert.SignatureHex)
	if err != nil {
		return nil, errSubkeyCertBadSig
	}
	if !ed25519.Verify(rootPub, body, sig) {
		return nil, errSubkeyCertBadSig
	}
	return ed25519.PublicKey(subPub), nil
}

func canonicalCertBytesExcludingSignature(cert subkeyCertWire) ([]byte, error) {
	raw, err := json.Marshal(cert)
	if err != nil {
		return nil, err
	}
	var any any
	if err := json.Unmarshal(raw, &any); err != nil {
		return nil, err
	}
	if obj, ok := any.(map[string]interface{}); ok {
		delete(obj, "signature_hex")
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, any); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// publisherFingerprintHex returns the SHA-256 hex of pub. Mirrors
// publisher.PublisherFingerprint(...).Hex.
func publisherFingerprintHex(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}
