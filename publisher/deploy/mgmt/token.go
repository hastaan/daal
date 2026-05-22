// Package mgmt is the Helper-side client for the V2 in-box
// daal-relay-mgmt service. It owns:
//
//   - Authorization: Daal-Mgmt-Token <nonce:ts:op:sig> minting
//     (token.go).
//   - TLS-pinned HTTPS calls to the box's mgmt port
//     (client.go).
//   - The fast-path orchestration that opens an ephemeral
//     cloud-firewall rule via Provider.SetEphemeralFirewallRule,
//     drives the mgmt call, then explicitly removes the rule
//     even on error (flow.go).
//
// Position B preserved: this package never reaches any URL except
// the box's MgmtPort, validated against the pinned cert
// fingerprint. No telemetry surface.
package mgmt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// MintToken returns the body of the Authorization: Daal-Mgmt-Token
// header for the given op + Helper-side timestamp. The token shape
// is "<nonce>:<ts>:<op>:<base64-sig>" where the signature covers
// "<nonce>:<ts>:<op>".
//
// privKey must be the Ed25519 private key whose public half is
// embedded in the box's /etc/daal/mgmt/pubkey by cloud-init.
func MintToken(privKey ed25519.PrivateKey, op string, ts time.Time) (string, error) {
	if len(privKey) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("mgmt: privKey wrong size %d (want %d)", len(privKey), ed25519.PrivateKeySize)
	}
	if op != "rotate-credentials" && op != "rotate-tls" {
		return "", fmt.Errorf("mgmt: unknown op %q (must be rotate-credentials or rotate-tls)", op)
	}
	var nonceB [16]byte
	if _, err := rand.Read(nonceB[:]); err != nil {
		return "", fmt.Errorf("mgmt: nonce: %w", err)
	}
	nonce := hex.EncodeToString(nonceB[:])
	tsStr := strconv.FormatInt(ts.UTC().Unix(), 10)
	msg := []byte(nonce + ":" + tsStr + ":" + op)
	sig := ed25519.Sign(privKey, msg)
	return nonce + ":" + tsStr + ":" + op + ":" + base64.StdEncoding.EncodeToString(sig), nil
}

// ParseToken is the inverse of MintToken; used only by tests and
// the on-box service. Returns the four token components.
func ParseToken(token string) (nonce, tsStr, op string, sig []byte, err error) {
	const sep = ":"
	parts := splitN(token, sep, 4)
	if len(parts) != 4 {
		err = errors.New("mgmt: malformed token (need 4 colon-separated parts)")
		return
	}
	nonce, tsStr, op = parts[0], parts[1], parts[2]
	sig, err = base64.StdEncoding.DecodeString(parts[3])
	return
}

// splitN is a stdlib-free strings.SplitN equivalent (avoids
// importing strings just for one call).
func splitN(s, sep string, n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n-1; i++ {
		idx := indexOf(s, sep)
		if idx < 0 {
			break
		}
		out = append(out, s[:idx])
		s = s[idx+len(sep):]
	}
	out = append(out, s)
	return out
}

func indexOf(s, sep string) int {
	for i := 0; i+len(sep) <= len(s); i++ {
		if s[i:i+len(sep)] == sep {
			return i
		}
	}
	return -1
}
