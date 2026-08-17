package mgmt

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"daal/publisher/deploy/provider"
)

// Client is the Helper-side mgmt-plane HTTPS client. It pins the
// box's TLS leaf cert against the SHA-256 fingerprint persisted in
// OperatorRecord.MgmtTLSFingerprint (FRP-10 invariant 26). Wrong
// fingerprint = ErrFingerprintMismatch (no fallback to system
// trust store; no InsecureSkipVerify).
type Client struct {
	httpClient *http.Client
	now        func() time.Time
}

// NewClient returns a Client bound to the supplied OperatorRecord.
// The TLS dialer pins against rec.MgmtTLSFingerprint; an empty
// fingerprint fails closed.
func NewClient(rec *provider.OperatorRecord) (*Client, error) {
	if rec == nil {
		return nil, errors.New("mgmt: nil OperatorRecord")
	}
	if rec.MgmtTLSFingerprint == "" {
		return nil, errors.New("mgmt: OperatorRecord.MgmtTLSFingerprint empty (FRP-10 invariant 26: pin required)")
	}
	if err := provider.ValidateMgmtPort(rec.MgmtPort); err != nil {
		return nil, fmt.Errorf("mgmt: OperatorRecord.MgmtPort invalid (FRP-10 invariant 27): %w", err)
	}
	wantFP := strings.ToLower(strings.TrimSpace(rec.MgmtTLSFingerprint))
	rawFP, err := hex.DecodeString(wantFP)
	if err != nil || len(rawFP) != sha256.Size {
		return nil, fmt.Errorf("mgmt: OperatorRecord.MgmtTLSFingerprint invalid (want 32-byte hex): %q", wantFP)
	}
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // we do our own pinning below
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("mgmt: no peer cert presented")
			}
			sum := sha256.Sum256(rawCerts[0])
			got := hex.EncodeToString(sum[:])
			if got != wantFP {
				return fmt.Errorf("%w: got %s want %s", ErrFingerprintMismatch, got, wantFP)
			}
			return nil
		},
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	return &Client{
		httpClient: &http.Client{Timeout: 30 * time.Second, Transport: transport},
		now:        time.Now,
	}, nil
}

// ErrFingerprintMismatch is returned by Client when the box
// presents a TLS cert whose SHA-256 doesn't match the pinned
// MgmtTLSFingerprint. Callers should treat this as a hard fail
// and surface it to the operator (potential MITM / box swap).
var ErrFingerprintMismatch = errors.New("mgmt: TLS fingerprint mismatch")

// SetClock injects a deterministic clock for tests.
func (c *Client) SetClock(now func() time.Time) { c.now = now }

// SetTransport overrides the HTTP transport (test injection).
func (c *Client) SetTransport(t http.RoundTripper) {
	c.httpClient.Transport = t
}

// boxURL builds https://<host>:<port><path> from rec.PublicIP +
// rec.MgmtPort.
func (c *Client) boxURL(rec *provider.OperatorRecord, path string) string {
	host := rec.PublicIP.String()
	if rec.PublicIP == nil {
		host = "127.0.0.1"
	}
	return fmt.Sprintf("https://%s:%d%s", host, rec.MgmtPort, path)
}

// RotateCredentials calls POST /rotate-credentials. Returns the
// new credentials JSON the box generated, plus any TLS-pin error.
//
// WIRE-FORMAT NOTE — RealityPrivKey encoding changed, and the two ends
// version-skew independently.
//
// Pre-Wave-2 boxes return 64 lowercase hex characters. That was a
// box-bricking bug rather than a style choice: sing-box decodes
// reality.private_key with base64.RawURLEncoding, so a hex string
// decodes to 48 bytes and the inbound FATALs on the restart the handler
// performs. Wave 2's handler emits 43 base64url characters, which is
// what `sing-box generate reality-keypair` produces and what cloud-init
// injects.
//
// This field is decoded as an untyped string, so neither end notices
// the mismatch. Nothing depends on it today — RotateCredentials has no
// production caller, the rotation ladder is a later wave — but the
// first caller must not inherit a silent skew, so:
//
//   - RealityPubKey is new and is ONLY present on a Wave-2 box. Its
//     absence is the reliable "this box is old" signal, better than
//     guessing from the private key's length.
//   - Users is the per-recipient map; a pre-Wave-2 box rotated only
//     inbounds[0].users[0], so a bare UUID from such a box means "one
//     recipient was rotated and the rest still have live credentials",
//     not "rotation complete".
//   - The handler regenerates the BOX keypair on every call, which
//     invalidates the pinned public key in every already-distributed
//     pack. It is therefore only usable together with a redistribution
//     path.
//
// mgmt_encoding_test.go pins the encoding so the skew is caught by a
// test rather than by a dead relay.
type Credentials struct {
	UUID            string            `json:"uuid"`
	Users           map[string]string `json:"users,omitempty"`
	RealityPrivKey  string            `json:"reality_private_key"`
	RealityPubKey   string            `json:"reality_public_key,omitempty"`
	GeneratedAtUnix int64             `json:"generated_at_unix"`
}

func (c *Client) RotateCredentials(ctx context.Context, rec *provider.OperatorRecord, privKey ed25519.PrivateKey) (*Credentials, error) {
	tok, err := MintToken(privKey, "rotate-credentials", c.now())
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.boxURL(rec, "/rotate-credentials"), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Daal-Mgmt-Token "+tok)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mgmt: rotate-credentials: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("mgmt: rotate-credentials %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var got Credentials
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		return nil, err
	}
	return &got, nil
}

// RotateTLS calls POST /rotate-tls.
type TLSProfile struct {
	NewSNI    string   `json:"new_sni"`
	NewDests  []string `json:"new_dests"`
	NewWSPath string   `json:"new_ws_path,omitempty"`
}

type RotateTLSResp struct {
	AppliedAtUnix int64 `json:"applied_at_unix"`
}

func (c *Client) RotateTLS(ctx context.Context, rec *provider.OperatorRecord, privKey ed25519.PrivateKey, profile TLSProfile) (*RotateTLSResp, error) {
	tok, err := MintToken(privKey, "rotate-tls", c.now())
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(profile)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.boxURL(rec, "/rotate-tls"), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Daal-Mgmt-Token "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mgmt: rotate-tls: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("mgmt: rotate-tls %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	var got RotateTLSResp
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		return nil, err
	}
	return &got, nil
}

// Health calls GET /health (no auth required).
func (c *Client) Health(ctx context.Context, rec *provider.OperatorRecord) error {
	req, err := http.NewRequestWithContext(ctx, "GET", c.boxURL(rec, "/health"), nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("mgmt: health: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("mgmt: health %d", resp.StatusCode)
	}
	return nil
}
