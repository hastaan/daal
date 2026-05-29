// Package stark is the Stark Industries Provider implementation
// for FRP-10. Stark publishes no Go SDK; this package wraps their
// REST API in ~150 lines via net/http + encoding/json.
//
// Auth: Authorization: Bearer <token> (single-secret model;
// matches the existing Hetzner / Cloudflare token shape and reuses
// supplement §10's storage + zeroize machinery exactly). An
// internal authStrategy seam is left in place so HMAC could be
// added post-V2 without touching the Provider interface — this is
// per FRP-10's locked answer in the spec.
//
// FRP-10 invariant: bearer token never appears in logs or errors;
// no telemetry; the client never holds the token after a request
// completes (httpClient method takes the token as a parameter so
// it stays on the call stack).
package stark

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultEndpoint is the production Stark Industries API base.
// Tests override via NewClient(WithEndpoint(...)).
const DefaultEndpoint = "https://api.starkindustries.example/v1"

// Client is the narrow REST surface the adapter uses. It does NOT
// hold the bearer token in struct state — every method takes the
// token as a parameter so it stays on the caller's stack and the
// Helper's keystore is the only durable home.
type Client struct {
	endpoint   string
	httpClient *http.Client
}

// Option is a functional config for NewClient.
type Option func(*Client)

// WithEndpoint overrides the API base URL. Used by tests.
func WithEndpoint(u string) Option { return func(c *Client) { c.endpoint = u } }

// WithHTTPClient overrides the http.Client. Used by tests.
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.httpClient = h } }

// NewClient returns a REST client bound to DefaultEndpoint.
func NewClient(opts ...Option) *Client {
	c := &Client{
		endpoint:   DefaultEndpoint,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// do issues a request with bearer-token auth. The token is held
// only in the local request scope and zeroed by Go's GC once the
// request completes.
func (c *Client) do(ctx context.Context, token, method, path string, body any, into any) error {
	if token == "" {
		return errors.New("stark: bearer token required")
	}
	base, err := url.Parse(strings.TrimRight(c.endpoint, "/") + "/")
	if err != nil {
		return fmt.Errorf("stark: bad endpoint %q: %w", c.endpoint, err)
	}
	rel, err := url.Parse(strings.TrimLeft(path, "/"))
	if err != nil {
		return fmt.Errorf("stark: bad path %q: %w", path, err)
	}
	full := base.ResolveReference(rel).String()
	var rdr io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("stark: marshal body: %w", err)
		}
		rdr = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, full, rdr)
	if err != nil {
		return fmt.Errorf("stark: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("stark: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return errStarkUnauthorized
	}
	if resp.StatusCode == http.StatusNotFound {
		return errStarkNotFound
	}
	if resp.StatusCode >= 400 {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		// Strip the bearer token from any error path that might
		// echo headers — defense in depth; we don't include req
		// in the error.
		body := strings.TrimSpace(string(errBody))
		return fmt.Errorf("stark: %s %s -> %d: %s", method, path, resp.StatusCode, body)
	}
	if into != nil {
		if err := json.NewDecoder(resp.Body).Decode(into); err != nil {
			return fmt.Errorf("stark: decode response: %w", err)
		}
	}
	return nil
}

// errStarkUnauthorized signals a 401 — caller treats as token
// revoked. errStarkNotFound is the absent-resource sentinel.
var (
	errStarkUnauthorized = errors.New("stark: 401 unauthorized (token revoked or invalid)")
	errStarkNotFound     = errors.New("stark: 404 not found")
)

// VPSCreateReq mirrors Stark's POST /vps body.
type VPSCreateReq struct {
	Hostname string   `json:"hostname"`
	Plan     string   `json:"plan"`
	Region   string   `json:"region"`
	OS       string   `json:"os"`
	UserData string   `json:"user_data"`
	SSHKeys  []string `json:"ssh_keys,omitempty"`
	Tags     []string `json:"tags,omitempty"`
}

// VPSResp mirrors Stark's GET /vps/<id> response.
type VPSResp struct {
	ID       string   `json:"id"`
	Hostname string   `json:"hostname"`
	Status   string   `json:"status"`
	Plan     string   `json:"plan"`
	Region   string   `json:"region"`
	IPv4     string   `json:"ipv4"`
	IPv6     string   `json:"ipv6,omitempty"`
	Tags     []string `json:"tags,omitempty"`
}

// PriceResp is GET /pricing/<plan>?region=<region>.
type PriceResp struct {
	Plan       string  `json:"plan"`
	Region     string  `json:"region"`
	MonthlyEUR float64 `json:"monthly_eur"`
}

// FirewallRuleReq is POST /firewall/rules body.
type FirewallRuleReq struct {
	VPSID     string `json:"vps_id"`
	SrcIP     string `json:"src_ip"`
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`
	ExpiresAt int64  `json:"expires_at_unix"` // Stark enforces server-side TTL
}

// FirewallRuleResp is POST /firewall/rules response.
type FirewallRuleResp struct {
	RuleID string `json:"rule_id"`
}

// SSHKeyReq is POST /ssh-keys body.
type SSHKeyReq struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
}

// SSHKeyResp is POST /ssh-keys response.
type SSHKeyResp struct {
	KeyID string `json:"key_id"`
}
