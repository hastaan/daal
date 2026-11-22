// firewall_cf.go is the Hetzner side of the CDN way in (add-on 2, item
// B-2): it satisfies cloudflare.FirewallApplier by putting ONE rule on
// the relay's own firewall that opens the CDN door's port
// (relayports.CDNOrigin, ws-cdn-in) to Cloudflare's published ranges and
// to nothing else.
//
// What changed from FRP-8, and why (blackout plan, Group B, defect 3):
//   - the port is a parameter, and defaults to the CDN door, not 443
//     (443/tcp is REALITY's and already world-open, so a rule for it
//     narrowed nothing);
//   - the rule goes on the relay's firewall (daal-relay-<server id>);
//     an empty firewall id is refused instead of creating a firewall
//     attached to nothing;
//   - a port the firewall already opens to everyone is refused.
//
// Runs on the publisher's device, never on the relay: the relay holds
// no Hetzner token.

package hetzner

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"daal/publisher/deploy/cloudflare"
	"daal/publisher/deploy/relayports"
)

// errEmptyRanges is returned when the applier is invoked with no
// ranges. A failed range fetch must never become an empty rule.
var errEmptyRanges = errors.New("hetzner: edge ranges required")

// cloudflarePortRuler is the port-aware half of the live client. It is
// an optional interface rather than an hcloudClient method so the
// shared client interface (client.go) and its fakes need no change; the
// live client implements it.
type cloudflarePortRuler interface {
	FirewallApplyCloudflareRuleOnPort(ctx context.Context, firewallID string, port int, ipv4Ranges, ipv6Ranges []string) (string, error)
	FirewallRemoveCloudflareRule(ctx context.Context, firewallID string) error
	FirewallCloudflareRule(ctx context.Context, firewallID string) (CloudflareRuleState, error)
}

// CloudflareFirewallApplier adapts an hcloudClient into the
// cloudflare.FirewallApplier interface.
type CloudflareFirewallApplier struct {
	c hcloudClient
	// Port is the relay port the rule opens. Zero means the CDN door
	// (relayports.CDNOrigin).
	Port int
}

// NewCloudflareFirewallApplier wraps the supplied hcloudClient; the
// rule opens the CDN door's port.
func NewCloudflareFirewallApplier(c hcloudClient) *CloudflareFirewallApplier {
	return &CloudflareFirewallApplier{c: c}
}

func (a *CloudflareFirewallApplier) port() int {
	if a.Port == 0 {
		return relayports.CDNOrigin.Port
	}
	return a.Port
}

// resolve turns a relay firewall's name into its id. The wizard knows a
// relay by its server id, and so its firewall by the name provisioning
// gave it (firewallNameForServer: daal-relay-<server id>); the record
// does not carry the firewall's id. Anything else is taken as an id.
func (a *CloudflareFirewallApplier) resolve(ctx context.Context, idOrName string) (string, error) {
	idOrName = strings.TrimSpace(idOrName)
	if idOrName == "" {
		return "", errNoRelayFirewall
	}
	if !strings.HasPrefix(idOrName, firewallNameForServer("")) {
		return idOrName, nil
	}
	fws, err := a.c.FirewallList(ctx)
	if err != nil {
		return "", fmt.Errorf("hetzner: find firewall %q: %w", idOrName, err)
	}
	for _, f := range fws {
		if f.Name == idOrName {
			return f.ID, nil
		}
	}
	return "", fmt.Errorf("hetzner: no firewall named %q on this account", idOrName)
}

// ApplyCloudflareRule satisfies cloudflare.FirewallApplier. firewallID
// must be the relay's own firewall, by id or by name. Returns its id.
func (a *CloudflareFirewallApplier) ApplyCloudflareRule(ctx context.Context, firewallID string, ranges *cloudflare.EdgeRanges) (string, error) {
	if ranges == nil {
		return "", errEmptyRanges
	}
	firewallID, err := a.resolve(ctx, firewallID)
	if err != nil {
		return "", err
	}
	if pr, ok := a.c.(cloudflarePortRuler); ok {
		return pr.FirewallApplyCloudflareRuleOnPort(ctx, firewallID, a.port(), ranges.V4, ranges.V6)
	}
	// A client without the port-aware call (test fakes, the dry-run
	// client) can only open the default port.
	if a.port() != relayports.CDNOrigin.Port {
		return "", fmt.Errorf("hetzner: this client cannot open port %d", a.port())
	}
	return a.c.FirewallApplyCloudflareRule(ctx, firewallID, ranges.V4, ranges.V6)
}

// RemoveCloudflareRule takes the rule off the relay firewall (cdn-remove).
func (a *CloudflareFirewallApplier) RemoveCloudflareRule(ctx context.Context, firewallID string) error {
	pr, ok := a.c.(cloudflarePortRuler)
	if !ok {
		return errors.New("hetzner: this client cannot remove the Cloudflare rule")
	}
	firewallID, err := a.resolve(ctx, firewallID)
	if err != nil {
		return err
	}
	return pr.FirewallRemoveCloudflareRule(ctx, firewallID)
}

// CloudflareRule reads the rule back (cdn-posture). Present with the
// door's port and at least one source is what "only Cloudflare can
// reach the door" needs from Hetzner.
func (a *CloudflareFirewallApplier) CloudflareRule(ctx context.Context, firewallID string) (CloudflareRuleState, error) {
	pr, ok := a.c.(cloudflarePortRuler)
	if !ok {
		return CloudflareRuleState{}, errors.New("hetzner: this client cannot read the Cloudflare rule")
	}
	firewallID, err := a.resolve(ctx, firewallID)
	if err != nil {
		return CloudflareRuleState{}, err
	}
	return pr.FirewallCloudflareRule(ctx, firewallID)
}

// DoorPortOpenToCloudflareOnly reports whether st is the rule this
// applier would have written.
func (a *CloudflareFirewallApplier) DoorPortOpenToCloudflareOnly(st CloudflareRuleState) bool {
	return st.Present && st.Sources > 0 && st.Port == fmt.Sprint(a.port())
}
