// FRP-14: client-side wrappers for the three per-recipient routes
// on the V2 mgmt plane. Shape mirrors cmd/daal-relay-mgmt/users.go
// (the on-box service).
package mgmt

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"daal/publisher/deploy/provider"
)

// UserCreds matches the JSON returned by /users/provision.
type UserCreds struct {
	Name              string `json:"name"`
	VLESSUUID         string `json:"vless_uuid"`
	RealityShortID    string `json:"reality_short_id"`
	Hy2Password       string `json:"hy2_password"`
	NaivePassword     string `json:"naive_password"`
	WSPath            string `json:"ws_path"`
	ProvisionedAtUnix int64  `json:"provisioned_at_unix"`

	// FRP-14 Tier-2 box-wide connection material (see the mgmt
	// server's userCreds). RealityPublicKey is the base64 x25519
	// pubkey for the vless-reality client outbound; TLSCertSHA256 is
	// the hex pin for the ws/hy2/naive self-signed TLS. Both empty
	// on a pre-Tier-2 box.
	RealityPublicKey string `json:"reality_public_key,omitempty"`
	TLSCertSHA256    string `json:"tls_cert_sha256,omitempty"`
	// TLSCertPEM is the box's data-plane leaf cert (PEM), the naive
	// client's trusted root (Cronet verifies against a root set, not an
	// SPKI pin). Empty when the data-plane cert is absent.
	TLSCertPEM string `json:"tls_cert_pem,omitempty"`

	// Wave 2. This struct is the TRANSPORT between the box and the pack
	// minter, and a field missing here is silently dropped: encoding/json
	// discards unknown keys on decode, so the box can send a value, this
	// struct can omit it, and the re-encoded creds file loses it with no
	// error anywhere. That is exactly what happened on the first real
	// provision after Wave 2 — the box echoed both fields below and the
	// publisher swallowed them. Anything the box learns and the minter
	// needs MUST appear here.
	//
	// CoverSNI is the REALITY cover host this box actually serves, read
	// from its live sing-box config. It is the authoritative value: the
	// publisher's OperatorRecord is only a record of what was requested,
	// while this is what is really on the wire. Empty on a pre-Wave-2 box,
	// where the record fallback takes over.
	CoverSNI string `json:"cover_sni,omitempty"`
	// MuxInbound reports whether every vless-family inbound carries an
	// enabled multiplex block. The pack must emit a mux outbound ONLY when
	// this is true: a mux client against a mux-less inbound fails hard
	// (measured: curl rc=56), while a mux inbound serves a non-mux client
	// fine. Absent (false) on a pre-Wave-2 box, which is the safe default.
	MuxInbound bool `json:"mux_inbound"`
}

// UserMeta is the lightweight per-user descriptor returned by
// /users/list (no secrets).
type UserMeta struct {
	Name              string `json:"name"`
	ProvisionedAtUnix int64  `json:"provisioned_at_unix"`
}

// ProvisionUser calls POST /users/provision. `name` must match
// `r[0-9]{1,12}` (validated on box). The returned UserCreds is the
// only time the secrets ever leave the box — the publisher app
// MUST persist them immediately (operator_recipients row).
func (c *Client) ProvisionUser(ctx context.Context, rec *provider.OperatorRecord, priv ed25519.PrivateKey, name string) (*UserCreds, error) {
	tok, err := MintToken(priv, "users-provision", c.now())
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(map[string]string{"name": name})
	req, err := http.NewRequestWithContext(ctx, "POST", c.boxURL(rec, "/users/provision"), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Daal-Mgmt-Token "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mgmt: users/provision: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("mgmt: users/provision %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out UserCreds
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RevokeUser calls POST /users/revoke. Returns the box-side
// timestamp at which the revoke (and the kick wrapper) ran.
type RevokeResp struct {
	RevokedAtUnix int64 `json:"revoked_at_unix"`
}

func (c *Client) RevokeUser(ctx context.Context, rec *provider.OperatorRecord, priv ed25519.PrivateKey, name string) (*RevokeResp, error) {
	tok, err := MintToken(priv, "users-revoke", c.now())
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(map[string]string{"name": name})
	req, err := http.NewRequestWithContext(ctx, "POST", c.boxURL(rec, "/users/revoke"), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Daal-Mgmt-Token "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mgmt: users/revoke: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("mgmt: users/revoke %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out RevokeResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListUsers calls GET /users/list. Returns the recipient roster
// the box currently honors (canonical source: the VLESS inbound's
// users[] table).
func (c *Client) ListUsers(ctx context.Context, rec *provider.OperatorRecord, priv ed25519.PrivateKey) ([]UserMeta, error) {
	tok, err := MintToken(priv, "users-list", c.now())
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "GET", c.boxURL(rec, "/users/list"), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Daal-Mgmt-Token "+tok)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mgmt: users/list: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("mgmt: users/list %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out struct {
		Users []UserMeta `json:"users"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Users, nil
}
