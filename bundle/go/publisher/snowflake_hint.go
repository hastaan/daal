package publisher

// Phase 3B. Helpers for the `daal-publish snowflake-rendezvous-hint`
// subcommand. The CLI surface is documented in
// specs/publisher-cli-v1.md and specs/snowflake-route-v1.md.
//
// daal-publish never opens a network socket. The
// snowflake-rendezvous-hint subcommand takes a Snowflake bridge
// fingerprint + endpoint description, stamps it with a NotAfter
// expiry, signs the canonical-JSON payload under the publisher's
// signing key, and emits a single object suitable for the
// top-level `manifest.rendezvous_hints[]` slot.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"daal/bundle-go/bundle"
)

// SnowflakeHintOptions are the inputs to the
// snowflake-rendezvous-hint subcommand. Bridge + Fingerprint are
// mandatory; everything else has a documented default.
type SnowflakeHintOptions struct {
	Bridge         string        // host:port of the Snowflake bridge endpoint
	FingerprintHex string        // SHA-1 or SHA-256 hex fingerprint of the bridge cert
	Validity       time.Duration // default 30d
	OutPath        string        // path to write the signed-hint JSON
	PrivKeyPath    string        // publisher.priv path (PEM-encoded)
	PubKeyPath     string        // publisher.pub path (raw 32-byte)
}

// SnowflakeHintPayload is the canonical-JSON structure that gets
// signed. The on-disk representation in the bundle wraps this in a
// `bundle.RendezvousHint{ Payload, Signature }`. The struct shape
// is locked at 3B.
type SnowflakeHintPayload struct {
	Bridge         string `json:"bridge"`
	FingerprintHex string `json:"fp"`
	NotAfter       string `json:"not_after"`    // RFC3339Z
	HintVersion    int    `json:"hint_version"` // 1
}

// SnowflakeRendezvousHint produces a signed offline-hint envelope
// ready to be spliced into manifest.rendezvous_hints[]. The
// returned bytes are the canonical-JSON encoding of the
// `bundle.RendezvousHint` envelope; the caller is expected to
// embed those bytes in the manifest before running
// `daal-publish bundle`.
func SnowflakeRendezvousHint(opts SnowflakeHintOptions) (*bundle.RendezvousHint, error) {
	if strings.TrimSpace(opts.Bridge) == "" {
		return nil, errors.New("snowflake-rendezvous-hint: --bridge is required")
	}
	if strings.TrimSpace(opts.FingerprintHex) == "" {
		return nil, errors.New("snowflake-rendezvous-hint: --fingerprint is required")
	}
	if opts.PrivKeyPath == "" {
		return nil, errors.New("snowflake-rendezvous-hint: --key is required")
	}
	if opts.OutPath == "" {
		return nil, errors.New("snowflake-rendezvous-hint: --out is required")
	}
	priv, err := loadPrivKey(opts.PrivKeyPath)
	if err != nil {
		return nil, err
	}

	validity := opts.Validity
	if validity == 0 {
		validity = 30 * 24 * time.Hour
	}

	payload := SnowflakeHintPayload{
		Bridge:         opts.Bridge,
		FingerprintHex: opts.FingerprintHex,
		NotAfter:       time.Now().UTC().Add(validity).Format(time.RFC3339),
		HintVersion:    1,
	}
	body, err := json.Marshal(&payload)
	if err != nil {
		return nil, fmt.Errorf("snowflake-rendezvous-hint: marshal: %w", err)
	}
	sig := ed25519.Sign(priv, body)

	envelope := &bundle.RendezvousHint{
		Payload:   body,
		Signature: base64.RawURLEncoding.EncodeToString(sig),
	}
	out, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(opts.OutPath, append(out, '\n'), 0o600); err != nil {
		return nil, fmt.Errorf("snowflake-rendezvous-hint: write %s: %w", opts.OutPath, err)
	}
	return envelope, nil
}

// loadPrivKey loads a publisher's signing key from
// `publisher.priv`. The keystore writes raw 64-byte ed25519
// private keys (32-byte seed || 32-byte public). We accept that
// raw shape; PEM-wrapping is reserved for HSM-backed keys.
func loadPrivKey(path string) (ed25519.PrivateKey, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("snowflake-rendezvous-hint: read key: %w", err)
	}
	if len(body) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("snowflake-rendezvous-hint: --key must be %d-byte raw ed25519, got %d",
			ed25519.PrivateKeySize, len(body))
	}
	return ed25519.PrivateKey(append([]byte(nil), body...)), nil
}
