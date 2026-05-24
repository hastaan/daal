package publisher

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// SignedRevocation is the operator-side wire format. Phase 0B's
// bundle.RevocationList stays as the in-archive shape; this struct adds an
// Ed25519 signature plus audit fields.
type SignedRevocation struct {
	V                 int      `json:"v"`
	IssuedAt          string   `json:"issued_at"`
	RevokedPublishers []string `json:"revoked_publishers,omitempty"`
	RevokedRoutes     []string `json:"revoked_routes,omitempty"`
	Reason            string   `json:"reason"`
	SignatureHex      string   `json:"signature_hex,omitempty"`
}

// RevokeOptions configures revoke.
type RevokeOptions struct {
	RootPrivPath          string
	BundleIDs             []string
	RouteIDs              []string
	PublisherFingerprints []string
	Reason                string
	Out                   string
}

// Revoke produces a signed revocation file.
func Revoke(opts RevokeOptions) (*SignedRevocation, error) {
	if opts.RootPrivPath == "" || opts.Reason == "" || opts.Out == "" {
		return nil, fmt.Errorf("--root-priv, --reason, and --out are required")
	}
	if len(opts.BundleIDs)+len(opts.RouteIDs)+len(opts.PublisherFingerprints) == 0 {
		return nil, fmt.Errorf("revoke requires at least one --bundle-id, --route-id, or --publisher-fingerprint")
	}
	priv, err := LoadPriv(opts.RootPrivPath)
	if err != nil {
		return nil, err
	}
	rev := SignedRevocation{
		V:                 1,
		IssuedAt:          time.Now().UTC().Format(time.RFC3339),
		RevokedPublishers: opts.PublisherFingerprints,
		RevokedRoutes:     opts.RouteIDs,
		Reason:            opts.Reason,
	}
	sig, err := signCanonical(rev, "signature_hex", priv)
	if err != nil {
		return nil, err
	}
	rev.SignatureHex = sig
	body, err := json.MarshalIndent(rev, "", "  ")
	if err != nil {
		return nil, err
	}
	body = append(body, '\n')
	if err := writeFileAtomic(opts.Out, body, 0o644); err != nil {
		return nil, err
	}
	_ = opts.BundleIDs // tracked for audit; consumed by V1.5 directory tooling.
	return &rev, nil
}

// VerifyRevocation returns nil if the file at path is signed by rootPub.
func VerifyRevocation(path string, rootPub ed25519.PublicKey) error {
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var rev SignedRevocation
	if err := json.Unmarshal(body, &rev); err != nil {
		return err
	}
	if rev.V != 1 {
		return fmt.Errorf("revocation version unsupported")
	}
	return verifyCanonical(rev, "signature_hex", rev.SignatureHex, rootPub)
}
