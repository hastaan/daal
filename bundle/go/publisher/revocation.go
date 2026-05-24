package publisher

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
)

// VerifySignedRevocationBytes parses and verifies a SignedRevocation
// payload that was fetched from the network (or read from disk) against a
// pinned ed25519 public key.
//
// Phase 1.5A's per-publisher refresh path uses this to confirm the
// payload was signed by the expected revocation key (the publisher's
// root, or a dedicated revocation sub-key whose fingerprint is pinned in
// the manifest under PublisherInfo.RevocationFingerprintHex).
func VerifySignedRevocationBytes(body []byte, signingPub ed25519.PublicKey) (*SignedRevocation, error) {
	if len(body) == 0 {
		return nil, fmt.Errorf("revocation body is empty")
	}
	var rev SignedRevocation
	if err := json.Unmarshal(body, &rev); err != nil {
		return nil, fmt.Errorf("revocation parse: %w", err)
	}
	if rev.V != 1 {
		return nil, fmt.Errorf("revocation version unsupported")
	}
	if rev.IssuedAt == "" || rev.Reason == "" {
		return nil, fmt.Errorf("revocation missing required fields")
	}
	if err := verifyCanonical(rev, "signature_hex", rev.SignatureHex, signingPub); err != nil {
		return nil, fmt.Errorf("revocation signature: %w", err)
	}
	return &rev, nil
}

// BuildSignedRevocationList is a small convenience used by tests and the
// directory builder; it has the same shape as Revoke() but operates
// in-memory (no file I/O).
func BuildSignedRevocationList(priv ed25519.PrivateKey, issuedAt string,
	revokedPublishers, revokedRoutes []string, reason string) (*SignedRevocation, []byte, error) {

	rev := SignedRevocation{
		V:                 1,
		IssuedAt:          issuedAt,
		RevokedPublishers: append([]string(nil), revokedPublishers...),
		RevokedRoutes:     append([]string(nil), revokedRoutes...),
		Reason:            reason,
	}
	sig, err := signCanonical(rev, "signature_hex", priv)
	if err != nil {
		return nil, nil, err
	}
	rev.SignatureHex = sig
	body, err := json.Marshal(rev)
	if err != nil {
		return nil, nil, err
	}
	return &rev, body, nil
}
