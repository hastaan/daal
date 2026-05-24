// Package hetzner is the Hetzner Cloud Provider implementation for FRP-4a.
//
// The package wraps the hetznercloud/hcloud-go/v2 SDK behind a narrow
// hcloudClient interface (defined in this file) so tests can run
// against an in-memory fake. The real adapter at adapter.go binds
// the interface to the live SDK.
package hetzner

import (
	"context"
	"net"
	"time"
)

// hcloudClient is the narrow surface the adapter uses against the
// Hetzner Cloud SDK. We define it locally so tests can implement a
// fake without pulling hcloud-go into the test binary.
type hcloudClient interface {
	ServerCreate(ctx context.Context, opts ServerCreateOpts) (*ServerInfo, error)
	ServerRebuild(ctx context.Context, id string, image string, userData string) (*ServerInfo, error)
	ServerByID(ctx context.Context, id string) (*ServerInfo, error)
	ServerByName(ctx context.Context, name string) (*ServerInfo, error)
	ServerList(ctx context.Context) ([]*ServerInfo, error)
	ServerDelete(ctx context.Context, id string) error
	ServerTypePrice(ctx context.Context, region, serverType string) (hourlyEUR, monthlyEUR float64, err error)

	SSHKeyCreate(ctx context.Context, name string, publicKey []byte) (id string, err error)
	SSHKeyDelete(ctx context.Context, id string) error

	FloatingIPAssign(ctx context.Context, fipID, serverID string) error
	FloatingIPUnassign(ctx context.Context, fipID string) error

	// FirewallApplyCloudflareRule creates or updates a firewall
	// rule allowing inbound 443/tcp ONLY from the supplied edge
	// ranges. firewallID is "" on first call (creates a new
	// rule + returns its ID); subsequent calls update the same
	// rule in place.
	//
	// FRP-8: this binds the §11.7 origin firewall to the
	// freshly-fetched Cloudflare edge ranges. Called from the
	// Helper, never from the origin box.
	FirewallApplyCloudflareRule(ctx context.Context, firewallID string, ipv4Ranges, ipv6Ranges []string) (newID string, err error)

	// FirewallAddEphemeralRule appends a single time-bounded
	// inbound rule allowing (callerIP/32, port, tcp) to the
	// server's firewall. Returns a stable rule identifier the
	// caller persists in EphemeralFirewallRule.ID. Hetzner's
	// Cloud Firewalls API does not enforce server-side TTL, so
	// the adapter spawns a defensive expiry sweep; the Helper
	// is still expected to call FirewallRemoveEphemeralRule on
	// completion. FRP-10 §9.5.2.
	FirewallAddEphemeralRule(ctx context.Context, serverID, callerIP string, port int, expiresAt time.Time) (ruleID string, err error)

	// FirewallRemoveEphemeralRule removes the rule identified by
	// ruleID. Idempotent: removing an absent rule returns nil.
	FirewallRemoveEphemeralRule(ctx context.Context, ruleID string) error

	// FirewallEnsureForServer creates (idempotently) a per-server
	// Hetzner Cloud Firewall with a baseline ruleset that locks
	// the box down so the V2 mgmt-plane port (random, 10000–65535)
	// is reachable only through the wizard's ephemeral allowances
	// added by FirewallAddEphemeralRule.
	//
	// The baseline ruleset opens 443/tcp + 443/udp + 80/tcp from
	// anywhere (so sing-box on the relay can serve recipients) and
	// nothing else. Hetzner's "any inbound rule present → drop
	// everything else by default" semantics make the random mgmt
	// port unreachable until an ephemeral allow rule is added.
	//
	// The firewall is named "daal-relay-<serverID>" so cleanup on
	// teardown is straightforward. Returns the firewall ID; safe
	// to call multiple times for the same server (returns the
	// existing firewall ID without re-attaching).
	FirewallEnsureForServer(ctx context.Context, serverID string) (firewallID string, err error)

	// FirewallDeleteForServer detaches and deletes the per-server
	// firewall created by FirewallEnsureForServer. Idempotent:
	// missing firewall is treated as success.
	FirewallDeleteForServer(ctx context.Context, serverID string) error
}

// ServerCreateOpts is the cloud-provider-agnostic input to
// hcloudClient.ServerCreate. Mirrors the relevant subset of
// hcloud.ServerCreateOpts.
type ServerCreateOpts struct {
	Name       string
	ServerType string
	Region     string
	Image      string
	UserData   string // rendered cloud-init YAML
	SSHKeyIDs  []string
	Labels     map[string]string
}

// ServerInfo is what an hcloudClient returns for a server (created
// or queried). Fields are the subset the adapter needs.
type ServerInfo struct {
	ID         string
	Name       string
	Status     string // "initializing" | "running" | ...
	ServerType string
	Region     string
	PublicIP   net.IP
	PublicIPv6 net.IP
	Labels     map[string]string
	// RootPassword is only populated by rebuild responses. It is
	// kept in-memory for diagnostics during provisioning and must
	// never be serialized into OperatorRecord.
	RootPassword string
}
