// firewall_cf.go is the FRP-8 Hetzner-side adapter that satisfies
// the cloudflare.FirewallApplier interface. It binds the supplied
// EdgeRanges to a Hetzner Cloud Firewall rule allowing inbound
// 443/tcp ONLY from Cloudflare-published edge IP ranges.
//
// Per supplement §11.7 + phase doc §13 rule 5: this code runs on
// the FRP Helper machine (the wizard process), NEVER on the
// origin box. The origin box holds no Hetzner API token.

package hetzner

import (
	"context"
	"errors"

	"daal/publisher/deploy/cloudflare"
)

// errEmptyRanges is returned when the FirewallApplier is invoked
// with a nil EdgeRanges pointer. The caller (wizard) treats this
// as a programming error and surfaces it to the FRP unchanged.
var errEmptyRanges = errors.New("hetzner: edge ranges required")

// CloudflareFirewallApplier adapts an hcloudClient into the
// cloudflare.FirewallApplier interface. Constructed by the
// wizard's Tauri shim alongside the existing Hetzner Provider.
type CloudflareFirewallApplier struct {
	c hcloudClient
}

// NewCloudflareFirewallApplier wraps the supplied hcloudClient.
// The same client object the existing Hetzner Provider uses can
// be reused; the firewall API is independent of the server API.
func NewCloudflareFirewallApplier(c hcloudClient) *CloudflareFirewallApplier {
	return &CloudflareFirewallApplier{c: c}
}

// ApplyCloudflareRule satisfies cloudflare.FirewallApplier.
// firewallID == "" creates a fresh rule; non-empty updates the
// existing rule in place. Returns the rule's Hetzner-side ID.
func (a *CloudflareFirewallApplier) ApplyCloudflareRule(ctx context.Context, firewallID string, ranges *cloudflare.EdgeRanges) (string, error) {
	if ranges == nil {
		return "", errEmptyRanges
	}
	return a.c.FirewallApplyCloudflareRule(ctx, firewallID, ranges.V4, ranges.V6)
}
