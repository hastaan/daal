// Package vultr is the Vultr Provider implementation for FRP-10.
//
// Mirrors the publisher/deploy/providers/hetzner adapter shape:
// the Provider type binds to a narrow vultrClient interface so unit
// tests can swap in an in-memory fake without pulling govultr/v3
// into the test binary. Live SDK wiring (govultr/v3) is a
// documented FRP-10 carry-over — the live path returns
// ErrLiveNotImplemented until wired, the same way FRP-8's
// cf_client_live shipped.
package vultr

import (
	"context"
	"errors"
	"net"
	"time"
)

// ErrLiveNotImplemented is returned by NewLiveClient until the
// govultr/v3 SDK wiring lands as a follow-up patch. Mocks +
// dry-run cover the unit-test surface today.
var ErrLiveNotImplemented = errors.New("vultr: live govultr/v3 client not yet wired")

// vultrClient is the narrow surface the adapter uses against the
// Vultr API. Defined locally so tests can implement a fake without
// pulling govultr/v3 into the test binary.
type vultrClient interface {
	InstanceCreate(ctx context.Context, opts InstanceCreateOpts) (*InstanceInfo, error)
	InstanceByID(ctx context.Context, id string) (*InstanceInfo, error)
	InstanceByLabel(ctx context.Context, label string) (*InstanceInfo, error)
	InstanceDelete(ctx context.Context, id string) error
	PlanPrice(ctx context.Context, region, plan string) (hourlyEUR, monthlyEUR float64, err error)

	SSHKeyCreate(ctx context.Context, name string, publicKey []byte) (id string, err error)
	SSHKeyDelete(ctx context.Context, id string) error

	ReservedIPAttach(ctx context.Context, ipID, instanceID string) error
	ReservedIPDetach(ctx context.Context, ipID string) error

	// FirewallAddEphemeralRule appends a single inbound
	// (callerIP/32, port, tcp) rule to the instance's firewall
	// group. Vultr's API does not enforce server-side TTL, so
	// the adapter spawns a defensive expiry sweep; the Helper
	// is still expected to call FirewallRemoveEphemeralRule on
	// completion. The rule is description-tagged with a stable
	// id derived from (instanceID, callerIP, port, expiresAt).
	FirewallAddEphemeralRule(ctx context.Context, instanceID, callerIP string, port int, expiresAt time.Time) (ruleID string, err error)

	// FirewallRemoveEphemeralRule strips the rule. Idempotent.
	FirewallRemoveEphemeralRule(ctx context.Context, ruleID string) error
}

// InstanceCreateOpts mirrors govultr.InstanceCreateReq subset.
type InstanceCreateOpts struct {
	Label    string
	Plan     string
	Region   string
	OS       string
	UserData string // base64-encoded cloud-init YAML
	SSHKeys  []string
	Tags     []string
}

// InstanceInfo is what a vultrClient returns for an instance.
type InstanceInfo struct {
	ID     string
	Label  string
	Status string
	Plan   string
	Region string
	MainIP net.IP
	V6Main net.IP
	Tags   []string
}

// errInstanceNotFound is the sentinel for an absent instance.
var errInstanceNotFound = errors.New("vultr: instance not found")
