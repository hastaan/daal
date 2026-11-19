package mgmt

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"

	"daal/publisher/deploy/provider"
)

// ErrWhoAmIUnsupported means the box did not give a usable /whoami
// answer: it predates the route (404/405), or what it sent back is not
// an address. Per specs/daal-relay-mgmt-v1.md §4.7 this must never
// fail, block or degrade a publisher action — the caller keeps the
// helper address it already had.
var ErrWhoAmIUnsupported = errors.New("mgmt: relay gave no usable /whoami answer")

// WhoAmIResp is the box's account of the connection it is answering.
type WhoAmIResp struct {
	// SourceIP is the peer address of the TCP connection as the box saw
	// it — the one value a cloud-firewall allowlist entry for this
	// publisher has to carry. Parsed and re-rendered here, so a caller
	// never handles a string the box chose.
	SourceIP       net.IP `json:"-"`
	ServerTimeUnix int64  `json:"server_time_unix"`
	APIVersion     int    `json:"api_version"`
}

// WhoAmI calls GET /whoami: "which address do you see me coming from?".
//
// It existed on the box since the publisher redesign with no caller that
// could authenticate to it — MintToken refused the op (the end-to-end
// rig's finding LC-O2). It is op-bound and request-bound like every
// other authenticated call.
//
// It cannot bootstrap an allowlist: the route sits behind the firewall
// it would verify, so an answer only ever confirms an address that
// already works.
func (c *Client) WhoAmI(ctx context.Context, rec *provider.OperatorRecord, privKey ed25519.PrivateKey) (*WhoAmIResp, error) {
	req, err := c.signedRequest(ctx, rec, privKey, "whoami", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mgmt: whoami: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound, http.StatusMethodNotAllowed:
		return nil, fmt.Errorf("%w (status %d)", ErrWhoAmIUnsupported, resp.StatusCode)
	default:
		// 401 and friends are NOT "older box": a relay that refuses the
		// publisher's token is a fact the caller has to see.
		return nil, fmt.Errorf("mgmt: whoami %d", resp.StatusCode)
	}
	var raw struct {
		WhoAmIResp
		SourceIP string `json:"source_ip"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWhoAmIUnsupported, err)
	}
	ip := net.ParseIP(raw.SourceIP)
	if ip == nil {
		return nil, fmt.Errorf("%w: source_ip is not an address", ErrWhoAmIUnsupported)
	}
	out := raw.WhoAmIResp
	out.SourceIP = ip
	return &out, nil
}
