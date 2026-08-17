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

	// SSHKeyCreate uploads the public half of the one-shot
	// provisioning keypair. labels are the ownership stamp
	// (managed-by=daal-deploy plus daal-relay=<derived server
	// name>) teardown matches on; see ownsEphemeralKey.
	SSHKeyCreate(ctx context.Context, name string, publicKey []byte, labels map[string]string) (id string, err error)
	SSHKeyDelete(ctx context.Context, id string) error

	// SSHKeyList returns every SSH key on the account with the
	// name + labels teardown needs to prove ownership. Hetzner has
	// no "get by label" for SSH keys, and neither the key id nor
	// its name is persisted on OperatorRecord, so the sweep is
	// list-then-match-by-derived-name.
	SSHKeyList(ctx context.Context) ([]SSHKeyInfo, error)

	// FloatingIPCreate reserves a new floating IP on the account.
	//
	// Until Step 9 no floating-IP CREATION existed anywhere in this
	// repository, which meant the whole L3 rung — the cheapest and
	// fastest answer to the one failure that actually kills a relay,
	// a blocked address — was reachable only by an operator who had
	// reserved an IP by hand in the provider console and knew its
	// numeric id. There was no field to type it into either. A rung
	// nobody can climb is not a rung.
	//
	// opts.HomeLocation is load-bearing, not cosmetic: a floating IP
	// is announced from its home location, and that location is what
	// decides whether the relay's cover SNI is still plausible for
	// the address (see assignFloatingIP's zone check).
	FloatingIPCreate(ctx context.Context, opts FloatingIPCreateOpts) (*FloatingIPInfo, error)

	// FloatingIPDelete releases a floating IP back to the provider.
	// Idempotent: deleting an absent id returns nil.
	//
	// This is the only call in the adapter that STOPS billing for an
	// address, and it is also the only one that can destroy something
	// the operator created themselves. Callers must delete only ids
	// they created (see Provider.ReleaseFloatingIP), because a
	// floating IP the operator reserved by hand is not ours to bin.
	FloatingIPDelete(ctx context.Context, fipID string) error

	// FloatingIPByID reads a floating IP back: its address, its home
	// location, and which server (if any) it is currently attached to.
	//
	// AssignFloatingIP cannot do its job without this. The whole point
	// of an L3 swap is to change the address recipients dial, and the
	// caller supplies an opaque numeric id — so something has to turn
	// that id into an address before the record and the candidate
	// tags can name it. Before Step 9 nothing did, which is exactly
	// why the swap moved nothing.
	FloatingIPByID(ctx context.Context, fipID string) (*FloatingIPInfo, error)

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
	// a missing firewall is success (Found=false, Deleted=false).
	//
	// Safety: the firewall is deleted ONLY when nothing but
	// serverID is still attached to it. If the operator (or a
	// second relay) applied it elsewhere, it is left completely
	// alone and the other server ids come back in SharedWith so
	// the caller can tell the user why it survived. Tearing down
	// one relay must never strip another relay's firewall.
	FirewallDeleteForServer(ctx context.Context, serverID string) (FirewallTeardownResult, error)
}

// FloatingIPCreateOpts is the input to hcloudClient.FloatingIPCreate.
type FloatingIPCreateOpts struct {
	// Name is the provider-side object name. Derived from the relay
	// so an operator reading their Hetzner console can tell which
	// address belongs to which relay.
	Name string
	// HomeLocation is the Hetzner location code the address is
	// announced from ("fsn1", "hel1", …). Required: an address with
	// no home location cannot be checked against the relay's cover
	// SNI, and Hetzner will not create one without it.
	HomeLocation string
	// Description is free text shown in the console.
	Description string
	// Labels are the ownership stamp (managed-by=daal-deploy plus
	// daal-relay=<derived server name>). They are what makes it safe
	// to delete an address later: without them, teardown cannot tell
	// an address daal-deploy reserved from one the operator did.
	Labels map[string]string
}

// FloatingIPInfo is what an hcloudClient returns for a floating IP.
type FloatingIPInfo struct {
	ID string
	// IP is the actual address. This is the field the whole L3 rung
	// turns on — it becomes OperatorRecord.PublicIP and every
	// candidate's public_ip:* tag.
	IP net.IP
	// HomeLocation is where the address is announced from. May differ
	// from the attached server's region: Hetzner allows the
	// cross-location attachment and routes via the home location.
	HomeLocation string
	// ServerID is the server the address is currently attached to,
	// or "" when unattached. Read back after an assign so the adapter
	// proves the routing change landed instead of assuming it.
	ServerID string
	Name     string
	Labels   map[string]string
}

// SSHKeyInfo is the subset of a Hetzner SSH key teardown needs to
// decide whether the key belongs to a given relay.
type SSHKeyInfo struct {
	ID     string
	Name   string
	Labels map[string]string
}

// FirewallTeardownResult is what FirewallDeleteForServer did.
//
//	Found   — a firewall named daal-relay-<serverID> exists.
//	Deleted — it is gone now.
//	SharedWith — other server ids still attached; non-empty means
//	             the firewall was deliberately preserved.
type FirewallTeardownResult struct {
	FirewallID string
	Found      bool
	Deleted    bool
	SharedWith []string
}

// Ownership labels stamped on every cloud resource daal-deploy
// creates. labelRelay carries the derived server name
// ("daal-<region>-<hex8 of publisher pubkey>"), which is what makes
// a teardown match proof of ownership rather than a prefix guess.
const (
	labelManagedBy      = "managed-by"
	labelManagedByValue = "daal-deploy"
	labelRelay          = "daal-relay"
)

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
