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

// Credentials is the LEGACY (pre-Step-7) /rotate-credentials response:
// one conflated action that rotated per-recipient credentials AND the
// box-wide REALITY keypair. No current call site decodes it — the
// capability interlock in capability.go refuses to talk to a box that
// speaks this shape — but it stays here, with its encoding test, as the
// written record of what an un-updated relay answers and why we must
// never send it a rotation.
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

// ErrRecipientNameRequired guards the single most destructive mistake
// available on this surface.
//
// The Step-7 contract says an omitted "name" is an ERROR, never "rotate
// all". That is not tidiness: the pre-Step-7 box on the other end of a
// version skew ignores the body and rotates the box-wide REALITY
// keypair, invalidating the pinned public key in every pack ever
// distributed. A request with an empty name is therefore refused before
// it is built, before any firewall window opens, and regardless of what
// the box would have done with it.
var ErrRecipientNameRequired = errors.New("mgmt: rotate-credentials requires a recipient name (an omitted name is an error, never 'rotate all')")

// RotatedCreds is the Step-7 /rotate-credentials response: the named
// recipient's freshly minted per-user credentials.
//
// It embeds UserCreds rather than redeclaring the fields, so the wire
// keys are byte-identical to /users/provision's. That is deliberate and
// load-bearing twice over:
//
//   - the pack minter (users-pack-sbp) consumes provision output, so a
//     rotation feeds the existing mint path with no translation layer;
//   - encoding/json drops unknown keys silently, and this project has
//     already shipped one inert feature that way (cover_sni and
//     mux_inbound were echoed by the box and swallowed here). Sharing
//     ONE struct means a field added for provision is automatically
//     carried through rotation instead of having to be remembered
//     twice.
//
// Anything the box learns and the minter needs belongs in UserCreds,
// never in a rotation-only struct.
type RotatedCreds struct {
	UserCreds
	// RotatedAtUnix is the box's own clock at the moment the rewritten
	// config went live. The publisher records it so "when did this
	// recipient's old UUID stop working?" has an answer.
	RotatedAtUnix int64 `json:"rotated_at_unix"`

	// UpdatedInbounds names every inbound whose user table the box
	// actually rewrote. It is the honesty field, and it is the whole
	// reason BUG-6 was a bug rather than a typo: a revocation that
	// reached three of four inbounds leaves the leaked credential live
	// on the fourth, and the caller cannot tell from a 200. Empty from
	// a box that does not report it — which is itself worth saying,
	// because then nothing verified that the revocation was complete.
	UpdatedInbounds []string `json:"updated_inbounds,omitempty"`

	// BoxKeysRotated must be false. It exists so "the box keypair was
	// not touched" is an assertion the publisher can check rather than
	// an assumption it inherits — a true here means every distributed
	// pack just died and the operator has to be told immediately.
	BoxKeysRotated bool `json:"box_keys_rotated"`

	// Warnings is whatever the box wants said out loud. Rendered
	// verbatim, never summarised.
	Warnings []string `json:"warnings,omitempty"`

	// GeneratedAtUnix is the legacy spelling of RotatedAtUnix, kept
	// because the box still emits both.
	GeneratedAtUnix int64 `json:"generated_at_unix,omitempty"`
}

// RotateCredentials calls POST /rotate-credentials {"name":"<name>"}:
// a TARGETED REVOCATION of one recipient, across every inbound,
// touching no REALITY key material and no other recipient.
//
// Callers should reach this through RotateCredentialsWithFW, which
// opens the firewall window and runs the capability interlock. Driving
// the client directly against a box of unknown vintage is the unsafe
// path — see capability.go.
func (c *Client) RotateCredentials(ctx context.Context, rec *provider.OperatorRecord, privKey ed25519.PrivateKey, name string) (*RotatedCreds, error) {
	if strings.TrimSpace(name) == "" {
		return nil, ErrRecipientNameRequired
	}
	tok, err := MintToken(privKey, "rotate-credentials", c.now())
	if err != nil {
		return nil, err
	}
	reqBody, err := json.Marshal(map[string]string{"name": name})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.boxURL(rec, "/rotate-credentials"), bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Daal-Mgmt-Token "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mgmt: rotate-credentials: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("mgmt: rotate-credentials %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var got RotatedCreds
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		return nil, err
	}
	// A box that answers 200 for somebody else is not a box that did
	// what was asked, and the caller is about to mint a pack from this.
	// Catch it here rather than in the field.
	if got.Name != "" && got.Name != name {
		return nil, fmt.Errorf("mgmt: rotate-credentials asked for %q but the box answered for %q", name, got.Name)
	}
	got.Name = name
	// A rotation that moved the box keypair is not this operation: it
	// invalidates every pinned public key in the field. But it is NOT
	// returned as an error, and the distinction matters more than it
	// looks. The box has already moved — the recipient's row now carries
	// a new UUID whatever we do here — so an error would exit the CLI
	// before the credentials were printed, leave the publisher's roster
	// holding credentials the relay no longer accepts, and hand the
	// operator a raw Go sentence in place of the escalation copy the
	// wizard already has for exactly this case. Instead the response is
	// returned as the success it factually is, with the escalation
	// carried in the two channels the whole chain reads: the
	// BoxKeysRotated flag (which the wizard turns into the "EVERY file
	// has stopped working" banner) and a warning at the head of the
	// list, ahead of the box's own.
	if got.BoxKeysRotated {
		got.Warnings = append([]string{
			fmt.Sprintf("relay reported box_keys_rotated=true while rotating %q: it replaced box-wide REALITY key material as well, so EVERY distributed pack is now dead, not just this recipient's — treat this as a fleet event and re-deliver to everyone", name),
		}, got.Warnings...)
	}
	if got.RotatedAtUnix == 0 {
		got.RotatedAtUnix = got.GeneratedAtUnix
	}
	return &got, nil
}

// TLSProfile is the POST /rotate-tls body. An entirely zero profile is
// the contract's `{}` — "box, pick your own cover". The publisher
// normally fills NewSNI/NewDests itself (see RotateTLSWithFW) because
// it owns the SNI pool and its admissibility rule, and because it has
// to record the result in the OperatorRecord either way.
type TLSProfile struct {
	NewSNI    string   `json:"new_sni,omitempty"`
	NewDests  []string `json:"new_dests,omitempty"`
	NewWSPath string   `json:"new_ws_path,omitempty"`
}

// RotateTLSResp is what the box echoes back.
//
// AppliedSNI / AppliedHandshake are NOT decoration. The box has emitted
// them since Wave 2 and this struct dropped them on the floor —
// encoding/json discards unknown keys — the identical failure that made
// cover_sni inert on the provision path. They are the only
// authoritative answer to "what is this relay advertising now", the
// publisher's record has to follow them, and their agreement is the
// Wave-2 invariant (reality.handshake.server == tls.server_name) that a
// rotation must not regress.
type RotateTLSResp struct {
	AppliedAtUnix int64 `json:"applied_at_unix"`
	// AppliedSNI is the cover host now in the box's live config.
	AppliedSNI string `json:"applied_sni,omitempty"`
	// AppliedHandshake is "<host>:<port>" of reality.handshake.server.
	AppliedHandshake string `json:"applied_handshake,omitempty"`
	// AppliedWSPath is the shared ws path after the rewrite, present
	// only when the request moved it.
	AppliedWSPath string `json:"applied_ws_path,omitempty"`
	// Changed names the parameters that actually moved. It is what
	// keeps an empty-bodied `{}` call honest: a 200 alone cannot
	// distinguish "rotated" from "decided nothing needed rotating", and
	// telling an operator their cover host moved when it did not is how
	// a relay stays burned after a rotation everyone believes happened.
	Changed []string `json:"changed,omitempty"`
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
