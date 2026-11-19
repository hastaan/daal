// Package mgmt is the Helper-side client for the V2 in-box
// daal-relay-mgmt service. It owns:
//
//   - Authorization: Daal-Mgmt-Token <v2:nonce:ts:op:sig> minting
//     — the signature covers the method, path and body digest
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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// TokenVersion is the first field of every token. The box refuses
// anything else, including the unversioned v1 shape
// ("<nonce>:<ts>:<op>:<sig>", signature over "nonce:ts:op"), which did
// not sign the request. Mirrors tokenVersion in cmd/daal-relay-mgmt.
const TokenVersion = "v2"

// TokenContext is the first line of what a token signs: it separates
// this signature from every other document the publisher key signs.
// Mirrors tokenContext in cmd/daal-relay-mgmt.
const TokenContext = "daal-mgmt-token-v2"

// opRoute is the ONE request each op may be signed for. The box derives
// the expected op from the path (opFromPath) and verifies the method and
// path under the signature, so these are a wire contract with
// cmd/daal-relay-mgmt, not local naming — and keeping them in one table
// is what stops a caller signing one route and sending another.
type opRoute struct{ Method, Path string }

var opRoutes = map[string]opRoute{
	"rotate-credentials": {"POST", "/rotate-credentials"},
	"rotate-tls":         {"POST", "/rotate-tls"},
	"users-provision":    {"POST", "/users/provision"},
	"users-revoke":       {"POST", "/users/revoke"},
	"users-list":         {"GET", "/users/list"},
	"whoami":             {"GET", "/whoami"},
	"identity":           {"GET", "/identity"},
	"bind-address":       {"POST", "/bind-address"},
	"unbind-address":     {"POST", "/unbind-address"},
}

// RouteForOp returns the method and path an op is sent on.
func RouteForOp(op string) (method, path string, ok bool) {
	r, ok := opRoutes[op]
	return r.Method, r.Path, ok
}

// signingInput is the exact byte string a token signs:
//
//	daal-mgmt-token-v2 \n <relay> \n <nonce> \n <ts> \n <op> \n <METHOD> \n <path> \n <hex sha256(body)>
//
// Eight lines joined by one "\n", no trailing newline. An absent body
// and an empty one are the same thing (the digest of zero bytes).
//
// <relay> names the ONE relay the token is for: the lower-case hex
// SHA-256 of its management TLS certificate, i.e. the value the session
// is pinned on (OperatorRecord.MgmtTLSFingerprint), as tokenAudience
// returns it. A publisher key can be trusted by more than one relay (an
// imported key; the old and the new box around a rebuild), and without
// this line a relay that received a request could present the identical
// request to another of them inside the accept window.
//
// Mirrors tokenSigningInput in cmd/daal-relay-mgmt; the fixture
// testdata/token_v2_vector.json pins both ends to the same bytes.
func signingInput(audience, nonce, ts, op, method, path string, body []byte) []byte {
	sum := sha256.Sum256(body)
	return []byte(strings.Join([]string{
		TokenContext, audience, nonce, ts, op, method, path, hex.EncodeToString(sum[:]),
	}, "\n"))
}

// tokenAudience turns a recorded management TLS fingerprint into the
// name a token carries for that relay: trimmed, lower case, and exactly
// 32 bytes of hex — the spelling the box computes for itself. Anything
// else is refused rather than signed: a token that names no relay, or
// names one in a spelling no relay answers to, is not worth minting.
func tokenAudience(mgmtTLSFingerprint string) (string, error) {
	fp := strings.ToLower(strings.TrimSpace(mgmtTLSFingerprint))
	if raw, err := hex.DecodeString(fp); err != nil || len(raw) != sha256.Size {
		return "", fmt.Errorf("mgmt: a token must name the relay it is for by its management TLS fingerprint (32-byte hex); got %q", mgmtTLSFingerprint)
	}
	return fp, nil
}

// MintToken returns the value of the Authorization: Daal-Mgmt-Token
// header for ONE request to ONE relay: the relay whose management TLS
// fingerprint is given (OperatorRecord.MgmtTLSFingerprint), op (which
// fixes the method and path) and the exact body bytes that will be
// sent. The token shape is "v2:<nonce>:<ts>:<op>:<base64-sig>"; the
// signature covers signingInput — the relay, the op, the method, the
// path and the SHA-256 of the body — so that relay will honour it for
// that request and no other, and no other relay will honour it at all.
// A token minted for one body and sent with another is refused (401).
//
// body is nil for the GETs.
//
// privKey must be the Ed25519 private key whose public half is
// embedded in the box's /etc/daal/mgmt/pubkey by cloud-init.
func MintToken(privKey ed25519.PrivateKey, mgmtTLSFingerprint, op string, body []byte, ts time.Time) (string, error) {
	if len(privKey) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("mgmt: privKey wrong size %d (want %d)", len(privKey), ed25519.PrivateKeySize)
	}
	audience, err := tokenAudience(mgmtTLSFingerprint)
	if err != nil {
		return "", err
	}
	route, ok := opRoutes[op]
	if !ok {
		return "", fmt.Errorf("mgmt: unknown op %q", op)
	}
	var nonceB [16]byte
	if _, err := rand.Read(nonceB[:]); err != nil {
		return "", fmt.Errorf("mgmt: nonce: %w", err)
	}
	return mintTokenWithNonce(privKey, audience, hex.EncodeToString(nonceB[:]), op, route, body, ts), nil
}

func mintTokenWithNonce(privKey ed25519.PrivateKey, audience, nonce, op string, route opRoute, body []byte, ts time.Time) string {
	tsStr := strconv.FormatInt(ts.UTC().Unix(), 10)
	sig := ed25519.Sign(privKey, signingInput(audience, nonce, tsStr, op, route.Method, route.Path, body))
	return TokenVersion + ":" + nonce + ":" + tsStr + ":" + op + ":" + base64.StdEncoding.EncodeToString(sig)
}

// VerifyToken checks a token against the request it claims to
// authorise and the relay it is presented to (named by its management
// TLS fingerprint), exactly as the box does minus the clock and the
// nonce set.
// It exists for the fake boxes in tests (this package's and its
// callers'), so that a client which signs one body and sends another
// fails there as it would on a relay.
func VerifyToken(pub ed25519.PublicKey, mgmtTLSFingerprint, token, method, path string, body []byte) (op string, err error) {
	audience, err := tokenAudience(mgmtTLSFingerprint)
	if err != nil {
		return "", err
	}
	nonce, tsStr, op, sig, err := ParseToken(token)
	if err != nil {
		return "", err
	}
	if !ed25519.Verify(pub, signingInput(audience, nonce, tsStr, op, method, path, body), sig) {
		return op, errors.New("mgmt: token does not sign this relay, method, path and body")
	}
	return op, nil
}

// ParseToken splits a token into its components (the version field is
// checked, not returned). Used only by tests.
func ParseToken(token string) (nonce, tsStr, op string, sig []byte, err error) {
	parts := strings.Split(token, ":")
	if len(parts) != 5 || parts[0] != TokenVersion {
		err = errors.New("mgmt: malformed token (need v2:nonce:ts:op:sig)")
		return
	}
	nonce, tsStr, op = parts[1], parts[2], parts[3]
	sig, err = base64.StdEncoding.DecodeString(parts[4])
	return
}
