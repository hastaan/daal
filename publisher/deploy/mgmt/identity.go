package mgmt

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"daal/publisher/deploy/provider"
)

// OpIdentity is the token op for GET /identity. Mirrors identityOp in
// cmd/daal-relay-mgmt.
const OpIdentity = "identity"

// IdentityVersion is the /identity reply shape this client understands.
// Mirrors identityVersion in cmd/daal-relay-mgmt.
const IdentityVersion = 1

// ErrIdentityUnsupported means the relay's management service predates
// GET /identity (it answered 404 or 405). It is an ANSWER, not a
// failure: the caller falls back to the older sources of the same
// material (the OperatorRecord, a users-provision reply). A relay that
// refuses the token, or a network error, is never this.
var ErrIdentityUnsupported = errors.New("mgmt: relay predates GET /identity")

// RelayIdentityFamily is one transport family the relay serves.
type RelayIdentityFamily struct {
	Family    string `json:"family"`
	Port      int    `json:"port"`
	Listening bool   `json:"listening"`
}

// RelayIdentity is the relay's own statement of its public connection
// identity — what a signed endpoint commits a route to
// (specs/daal-relay-mgmt-v1.md §4.9, specs/relaypack-v1.md "Endpoint
// commitment"). None of it is a secret and none of it names a
// recipient.
//
// Every field the box sends and a signer reads MUST be declared here:
// encoding/json drops unknown keys silently, and a value lost in this
// struct is a route signed without an endpoint.
type RelayIdentity struct {
	IdentityVersion int `json:"identity_version"`
	// RealityPublicKey is the REALITY x25519 public key (base64).
	RealityPublicKey string `json:"reality_public_key,omitempty"`
	// TLSCertSHA256 is the base64 SHA-256 of the data-plane
	// certificate's SubjectPublicKeyInfo — the pin.
	TLSCertSHA256 string `json:"tls_cert_sha256,omitempty"`
	// CoverSNI is the REALITY cover host the relay serves right now.
	CoverSNI string `json:"cover_sni,omitempty"`
	// SSMethod / SSServerKeySHA256: the shadowsocks method and
	// bundle.SSServerKeyDigest of the box-wide key. The key itself is
	// not sent.
	SSMethod          string `json:"ss_method,omitempty"`
	SSServerKeySHA256 string `json:"ss_server_key_sha256,omitempty"`
	// Families is every family the relay serves, with its port.
	Families []RelayIdentityFamily `json:"families"`
	// PendingFamilies names served families whose identity material
	// does not exist yet (shadowsocks before the first recipient). A
	// pack signed now cannot commit those routes; sign again when the
	// list is empty.
	PendingFamilies []string `json:"pending_families"`
	GeneratedAtUnix int64    `json:"generated_at_unix"`
}

// Identity calls GET /identity.
//
// The reply is trusted for the same reason every other reply from the
// box is: it arrives on a TLS session pinned to the certificate
// fingerprint recorded when the relay was built (NewClient). That
// matters more here than anywhere else — what comes back is what the
// publisher signs.
func (c *Client) Identity(ctx context.Context, rec *provider.OperatorRecord, privKey ed25519.PrivateKey) (*RelayIdentity, error) {
	req, err := c.signedRequest(ctx, rec, privKey, OpIdentity, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mgmt: identity: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound, http.StatusMethodNotAllowed:
		return nil, fmt.Errorf("%w (status %d)", ErrIdentityUnsupported, resp.StatusCode)
	default:
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("mgmt: identity %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("mgmt: identity read: %w", err)
	}
	return ParseRelayIdentity(raw)
}

// ParseRelayIdentity decodes and checks an /identity reply — from the
// wire, or from the file a caller saved one to. A document this client
// cannot read exactly is refused: guessing at it would put the guess
// under a signature.
func ParseRelayIdentity(raw []byte) (*RelayIdentity, error) {
	var out RelayIdentity
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("mgmt: identity: not JSON: %w", err)
	}
	if out.IdentityVersion != IdentityVersion {
		return nil, fmt.Errorf("mgmt: identity: version %d is not one this publisher understands (want %d)",
			out.IdentityVersion, IdentityVersion)
	}
	if (out.SSMethod == "") != (out.SSServerKeySHA256 == "") {
		return nil, errors.New("mgmt: identity: shadowsocks method and server-key digest must come together")
	}
	return &out, nil
}

// Pending reports whether the relay named family as served-but-not-yet-
// identifiable.
func (id *RelayIdentity) Pending(family string) bool {
	if id == nil {
		return false
	}
	for _, f := range id.PendingFamilies {
		if f == family {
			return true
		}
	}
	return false
}

// PortFor returns the port the relay says it serves family on, or 0
// when it does not list the family.
func (id *RelayIdentity) PortFor(family string) int {
	if id == nil {
		return 0
	}
	for _, f := range id.Families {
		if f.Family == family {
			return f.Port
		}
	}
	return 0
}

// IdentityWithFW fetches the relay's identity inside an ephemeral
// firewall window. Read-only on the box.
func IdentityWithFW(ctx context.Context, prov provider.Provider, rec *provider.OperatorRecord, privKey ed25519.PrivateKey, callerIP string) (*RelayIdentity, error) {
	return withFirewallWindow(ctx, prov, rec, callerIP, func(cli *Client) (*RelayIdentity, error) {
		return cli.Identity(ctx, rec, privKey)
	})
}
