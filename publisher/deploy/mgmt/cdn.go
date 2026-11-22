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

	"daal/publisher/deploy/cloudflare"
	"daal/publisher/deploy/provider"
)

// CapCDNDoor is the /health token of a box whose daal-relay-mgmt serves
// POST /cdn (add-on 2, the way in through Cloudflare) and keeps the
// door's users in step with every provision and revoke.
//
// It names the BINARY: such a box also opens the door's port at its own
// firewall (ufw) to the Cloudflare ranges the enable request carries,
// and closes those rules on disable, so a relay needs no Cloudflare
// ranges at provision time. The end-to-end test through the front
// (cdn-test) is what proves the whole path.
//
// WIRE CONTRACT with cmd/daal-relay-mgmt (capCDNDoor). No version
// fallback in Has(): the verb rides the pinned artifact.
const CapCDNDoor = "cdn"

// ErrCDNDoorUnsupported means the relay's daal-relay-mgmt has no /cdn
// route or does not advertise it: the pinned relay binary predates the
// add-on. The fix is a relay built with a newer pin, not a retry.
var ErrCDNDoorUnsupported = errors.New("mgmt: this relay's management service has no Cloudflare door (built before the add-on; rebuild the relay)")

// ErrCDNDoorNoRecipient means the relay refused to open the door
// because nobody is on it yet (409: sing-box refuses an inbound with no
// users). Nothing was changed on the relay. The app keeps the way in
// waiting and opens the door once the first person is added.
var ErrCDNDoorNoRecipient = errors.New("mgmt: the relay has nobody on it yet, so the Cloudflare door cannot open")

// CDNDoorResp is the box's answer to POST /cdn. It never carries key
// material. Mirrors cdnResp in cmd/daal-relay-mgmt/singbox_cdn.go.
type CDNDoorResp struct {
	Action                 string `json:"action"`
	Enabled                bool   `json:"enabled"`
	Changed                bool   `json:"changed"`
	Port                   int    `json:"port,omitempty"`
	WSPath                 string `json:"ws_path,omitempty"`
	Users                  int    `json:"users"`
	OriginCertSHA256       string `json:"origin_cert_sha256,omitempty"`
	OriginCertNotAfterUnix int64  `json:"origin_cert_not_after_unix,omitempty"`
	// BoxFirewallRules is how many Cloudflare ranges the relay's box
	// firewall opens the door's port to (rules the door wrote).
	BoxFirewallRules int `json:"box_firewall_rules"`
}

// CDNDoorEnable opens ws-cdn-in on the relay with the Origin CA
// certificate, its key and the origin-pull CA that ProvisionFront wrote
// for front (cloudflare.BuildDoorEnable checks them first).
//
// The request carries a private key, so it is sent only to a box that
// says it serves the door: the capability is read first and a box that
// does not advertise it gets nothing. The request body is dropped after
// sending; nothing here writes it anywhere.
//
// The answer must describe the door that was asked for — enabled, on
// the same port and WebSocket path — or the call fails: the caller is
// about to sign a pack naming that path.
func (c *Client) CDNDoorEnable(ctx context.Context, rec *provider.OperatorRecord, privKey ed25519.PrivateKey, front *cloudflare.FrontRecord) (*CDNDoorResp, error) {
	req, err := cloudflare.BuildDoorEnable(front)
	if err != nil {
		return nil, err
	}
	defer func() { req.OriginKeyPEM = "" }()
	caps, err := c.Capabilities(ctx, rec)
	if err != nil {
		return nil, fmt.Errorf("mgmt: cdn: capability probe failed (refusing to send door material to a box whose software we cannot identify): %w", err)
	}
	if !caps.Has(CapCDNDoor) {
		return nil, ErrCDNDoorUnsupported
	}
	got, err := c.cdnDoor(ctx, rec, privKey, req)
	if err != nil {
		return nil, err
	}
	if !got.Enabled || got.Port != req.Port || got.WSPath != req.WSPath {
		return got, fmt.Errorf("mgmt: cdn enable: relay answered enabled=%v port=%d path=%q, asked port=%d path=%q",
			got.Enabled, got.Port, got.WSPath, req.Port, req.WSPath)
	}
	if len(req.EdgeRanges) > 0 && got.BoxFirewallRules == 0 {
		return got, errors.New("mgmt: cdn enable: the relay opened its door behind no box-firewall rule for Cloudflare's ranges")
	}
	return got, nil
}

// CDNDoorEnableWithFW is CDNDoorEnable inside an ephemeral provider
// firewall window for callerIP, like every other management call.
func CDNDoorEnableWithFW(ctx context.Context, prov provider.Provider, rec *provider.OperatorRecord, privKey ed25519.PrivateKey, callerIP string, front *cloudflare.FrontRecord) (*CDNDoorResp, error) {
	return withFirewallWindow(ctx, prov, rec, callerIP, func(cli *Client) (*CDNDoorResp, error) {
		return cli.CDNDoorEnable(ctx, rec, privKey, front)
	})
}

// CDNDoorDisableWithFW is CDNDoorDisable inside an ephemeral provider
// firewall window for callerIP.
func CDNDoorDisableWithFW(ctx context.Context, prov provider.Provider, rec *provider.OperatorRecord, privKey ed25519.PrivateKey, callerIP string) (*CDNDoorResp, error) {
	return withFirewallWindow(ctx, prov, rec, callerIP, func(cli *Client) (*CDNDoorResp, error) {
		return cli.CDNDoorDisable(ctx, rec, privKey)
	})
}

// CDNDoorDisable closes ws-cdn-in and removes the door's files on the
// relay. Idempotent on the box. A box without the route answers
// ErrCDNDoorUnsupported, which for removal means there is no door to
// close; the caller decides how to report it.
func (c *Client) CDNDoorDisable(ctx context.Context, rec *provider.OperatorRecord, privKey ed25519.PrivateKey) (*CDNDoorResp, error) {
	got, err := c.cdnDoor(ctx, rec, privKey, cloudflare.DoorDisable())
	if err != nil {
		return nil, err
	}
	if got.Enabled {
		return got, errors.New("mgmt: cdn disable: relay reports the door still open")
	}
	return got, nil
}

// CDNDoorStatus reads the door's state. POST like the other two actions
// (the route has one method), and so single-use on the box like every
// POST.
func (c *Client) CDNDoorStatus(ctx context.Context, rec *provider.OperatorRecord, privKey ed25519.PrivateKey) (*CDNDoorResp, error) {
	return c.cdnDoor(ctx, rec, privKey, cloudflare.DoorRequest{Action: "status"})
}

func (c *Client) cdnDoor(ctx context.Context, rec *provider.OperatorRecord, privKey ed25519.PrivateKey, door cloudflare.DoorRequest) (*CDNDoorResp, error) {
	body, err := json.Marshal(door)
	if err != nil {
		return nil, err
	}
	defer zero(body)
	req, err := c.signedRequest(ctx, rec, privKey, "cdn", body)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mgmt: cdn %s: %w", door.Action, err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, ErrCDNDoorUnsupported
	default:
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if resp.StatusCode == http.StatusConflict && door.Action == "enable" {
			return nil, fmt.Errorf("%w (relay: %s)", ErrCDNDoorNoRecipient, strings.TrimSpace(string(raw)))
		}
		return nil, fmt.Errorf("mgmt: cdn %s %d: %s", door.Action, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var got CDNDoorResp
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&got); err != nil {
		return nil, fmt.Errorf("mgmt: cdn %s: decode: %w", door.Action, err)
	}
	if got.Action != "" && got.Action != door.Action {
		return nil, fmt.Errorf("mgmt: cdn: asked %q, relay answered for %q", door.Action, got.Action)
	}
	return &got, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
