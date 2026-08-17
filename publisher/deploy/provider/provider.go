package provider

import (
	"context"
	"time"
)

// Provider is the FRP-4a deploy contract. The Hetzner adapter at
// providers/hetzner/ was the first implementation; Vultr and Stark
// land at FRP-10 alongside it under publisher/deploy/providers/.
// The wizard's deploy step is provider-agnostic and binds to this
// interface only.
//
// Provision returns an OperatorRecord on success. The caller (FRP-5
// wizard via FRP-4b binder) signs the RelayPack from the record's
// CandidateMeta slice. The publisher private key is supplied by the
// caller; this interface never holds it.
//
// Idempotence:
//   - Provision twice with the same ProvisionOpts on the same
//     account observes the existing server and returns the same
//     OperatorRecord (no duplicate VPS created).
//   - Reprovision is idempotent: re-running on the same record
//     converges the box to the requested ReprovisionOpts.
//   - Decommission on an absent server returns an all-true report
//     and nil (success).
//   - AssignFloatingIP with an already-attached fipID is a no-op.
//   - UnassignFloatingIP with no attached floating IP is a no-op.
type Provider interface {
	Provision(ctx context.Context, opts ProvisionOpts) (*OperatorRecord, error)
	Reprovision(ctx context.Context, rec *OperatorRecord, opts ReprovisionOpts) error
	// Decommission destroys every cloud resource the adapter
	// created for this record — the VPS itself plus whatever
	// provisioning created alongside it (per-server firewall,
	// one-shot SSH key). Implementations MUST NOT stop at the
	// server: an orphaned SSH key permanently blocks the next
	// provision, and an orphaned firewall lingers on the account.
	//
	// The returned report is always non-nil, including on error, so
	// the caller can render exactly how far teardown got. A
	// non-fatal per-resource failure is recorded in the report
	// (boolean false + a Warning) and does not abort the remaining
	// resources. A non-nil error is reserved for the fatal case —
	// the billing server itself could not be deleted — and the
	// caller must then NOT discard the local record, because that
	// record is the only way back to the surviving server.
	Decommission(ctx context.Context, rec *OperatorRecord) (*DecommissionReport, error)
	AssignFloatingIP(ctx context.Context, rec *OperatorRecord, fipID string) error
	UnassignFloatingIP(ctx context.Context, rec *OperatorRecord) error
	Pricing(ctx context.Context, rec *OperatorRecord) (Pricing, error)

	// SetEphemeralFirewallRule opens a time-bounded inbound
	// allowlist on the cloud-provider firewall for the supplied
	// (callerIP, port) tuple. Used by the V2 mgmt-plane fast path
	// (supplement §9.5.2): the Helper calls this to allowlist its
	// own outbound IP for ~5 minutes before driving an L1/L2
	// rotation through the in-box daal-relay-mgmt service, then
	// calls RemoveEphemeralFirewallRule on completion.
	//
	// Implementations enforce auto-expiry (server-side where the
	// API supports it; via a defensive goroutine where it does
	// not). The returned EphemeralFirewallRule is opaque to the
	// caller except for ID (used for explicit removal) and
	// ExpiresAt (used for diagnostic display).
	//
	// FRP-10 invariant 28: the (port, IP) tuple is the rule's
	// full key — never just (IP). Implementations MUST refuse to
	// open a rule with port == 0 or durationSec <= 0.
	SetEphemeralFirewallRule(ctx context.Context, serverID, callerIP string, port int, durationSec int) (*EphemeralFirewallRule, error)

	// RemoveEphemeralFirewallRule closes the rule returned by
	// SetEphemeralFirewallRule. Idempotent: removing an
	// already-expired or already-deleted rule returns nil.
	RemoveEphemeralFirewallRule(ctx context.Context, rule *EphemeralFirewallRule) error
}

// EphemeralFirewallRule is the opaque handle returned by
// Provider.SetEphemeralFirewallRule. The caller persists nothing
// about this struct beyond the call duration; OperatorRecord holds
// MgmtPort + MgmtTLSFingerprint, not ephemeral firewall state.
//
// Wire shape: canonical-JSON serialisable (mgmt-plane diagnostic
// payloads echo it back to the wizard for display).
type EphemeralFirewallRule struct {
	ID        string    `json:"id"`
	ServerID  string    `json:"server_id"`
	CallerIP  string    `json:"caller_ip"`
	Port      int       `json:"port"`
	ExpiresAt time.Time `json:"expires_at"`
}
