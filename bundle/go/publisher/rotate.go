package publisher

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"daal/bundle-go/bundle"
)

// RotationChain is the canonical-JSON document signed by the OLD root.
type RotationChain struct {
	V                     int    `json:"v"`
	Kind                  string `json:"kind"`
	OldRootFingerprintHex string `json:"old_root_fingerprint_hex"`
	NewRootPubHex         string `json:"new_root_pub_hex"`
	TransitionStartsAt    string `json:"transition_starts_at"`
	TransitionEndsAt      string `json:"transition_ends_at"`
	SignatureHex          string `json:"signature_hex,omitempty"`
}

// RotateOptions configures rotate-key.
type RotateOptions struct {
	OldRootPrivPath  string
	NewRootPubPath   string
	TransitionWindow time.Duration
	Out              string
}

// Rotate produces a rotation chain signed by the old root.
func Rotate(opts RotateOptions) (*RotationChain, error) {
	if opts.OldRootPrivPath == "" || opts.NewRootPubPath == "" || opts.TransitionWindow <= 0 || opts.Out == "" {
		return nil, fmt.Errorf("--old-root-priv, --new-root-pub, --transition-window, --out are required")
	}
	oldPriv, err := LoadPriv(opts.OldRootPrivPath)
	if err != nil {
		return nil, err
	}
	newPub, err := LoadPub(opts.NewRootPubPath)
	if err != nil {
		return nil, err
	}
	oldPub := ed25519.PublicKey(oldPriv.Public().(ed25519.PublicKey))
	now := time.Now().UTC()
	chain := RotationChain{
		V:                     1,
		Kind:                  "root_rotation",
		OldRootFingerprintHex: bundle.PublisherFingerprint(oldPub).Hex,
		NewRootPubHex:         hex.EncodeToString(newPub),
		TransitionStartsAt:    now.Format(time.RFC3339),
		TransitionEndsAt:      now.Add(opts.TransitionWindow).Format(time.RFC3339),
	}
	sig, err := signCanonical(chain, "signature_hex", oldPriv)
	if err != nil {
		return nil, err
	}
	chain.SignatureHex = sig
	body, err := json.MarshalIndent(chain, "", "  ")
	if err != nil {
		return nil, err
	}
	body = append(body, '\n')
	if err := writeFileAtomic(opts.Out, body, 0o644); err != nil {
		return nil, err
	}
	return &chain, nil
}

// VerifyRotationChain returns nil if chain is well-formed, signed by oldPub,
// references the expected newPub, and is currently inside its window.
func VerifyRotationChain(chain RotationChain, oldPub, newPub ed25519.PublicKey, now time.Time) error {
	if chain.V != 1 || chain.Kind != "root_rotation" {
		return fmt.Errorf("rotation chain: unsupported version or kind")
	}
	if bundle.PublisherFingerprint(oldPub).Hex != chain.OldRootFingerprintHex {
		return fmt.Errorf("rotation chain: old root fingerprint mismatch")
	}
	declared, err := hex.DecodeString(chain.NewRootPubHex)
	if err != nil || len(declared) != ed25519.PublicKeySize {
		return fmt.Errorf("rotation chain: invalid new_root_pub_hex")
	}
	if !equalBytes(declared, newPub) {
		return fmt.Errorf("rotation chain: new root pub mismatch")
	}
	from, err1 := time.Parse(time.RFC3339, chain.TransitionStartsAt)
	until, err2 := time.Parse(time.RFC3339, chain.TransitionEndsAt)
	if err1 != nil || err2 != nil {
		return fmt.Errorf("rotation chain: invalid transition timestamps")
	}
	if now.Before(from) || !now.Before(until) {
		return fmt.Errorf("rotation chain: outside transition window")
	}
	return verifyCanonical(chain, "signature_hex", chain.SignatureHex, oldPub)
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
