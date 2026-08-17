// Package provider holds the FRP-4a Provider interface and the
// types that flow across it.
//
// Wire shape: every type in this file is canonical-JSON serialisable.
// FRP-5's wizard persists OperatorRecord to SQLite; FRP-4b's
// BindAndSign reads OperatorRecord and signs the RelayPack. The JSON
// must round-trip byte-identical across the FRP-4a → FRP-5 → FRP-4b
// boundary.
package provider

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"time"
)

const (
	// MinMgmtPort and MaxMgmtPort bound the FRP-10
	// daal-relay-mgmt random per-deploy port. Ports below 10000
	// are deliberately excluded; 65000 is the inclusive upper bound
	// used by the phase/spec lock.
	MinMgmtPort = 10000
	MaxMgmtPort = 65000
)

// OperatorRecord is the durable state for one provisioned VPS. The
// wizard (FRP-5) persists this to SQLite; the binder (FRP-4b) signs
// the resulting RelayPack against this record's CandidateMeta slice.
//
// At V1.5 ExposureMode is always "direct_vps" on every CandidateMeta.
// V1.6 (FRP-8) adds cdn_fronted candidates; the schema does not
// change here.
type OperatorRecord struct {
	Provider            string          `json:"provider"`
	ServerID            string          `json:"server_id"`
	ServerType          string          `json:"server_type"`
	Region              string          `json:"region"`
	PublicIP            net.IP          `json:"public_ip"`
	PublicIPv6          net.IP          `json:"public_ipv6,omitempty"`
	FloatingIPID        string          `json:"floating_ip_id,omitempty"`
	ToolboxProfile      string          `json:"toolbox_profile"`
	PublisherPubKey     []byte          `json:"publisher_pub_key"`
	Candidates          []CandidateMeta `json:"candidates"`
	ProvisionedAt       time.Time       `json:"provisioned_at"`
	LastReprovisionedAt *time.Time      `json:"last_reprovisioned_at,omitempty"`

	// MgmtPort is the V2 daal-relay-mgmt listening port chosen
	// at provision time in [10000, 65000]. Zero on V1.5 records
	// (no V2 mgmt-plane). FRP-10 invariant 27: every Helper-side
	// L1/L2 fast-path call reads this from the record — never
	// from a constant.
	MgmtPort int `json:"mgmt_port,omitempty"`

	// MgmtTLSFingerprint is the hex-lowercase SHA-256 of the
	// mgmt-plane TLS leaf certificate's DER bytes. Captured at
	// provision time via the bootstrap fingerprint relay; pinned
	// for every subsequent L1/L2 mgmt call (FRP-10 invariant 26).
	// Empty on V1.5 records.
	MgmtTLSFingerprint string `json:"mgmt_tls_fingerprint,omitempty"`

	// FRP-14 Tier-2 client-connection material, read off the box over
	// SSH at provision time (the box writes reality.pub at cloud-init,
	// independent of the released daal-relay-mgmt binary). The
	// publisher uses these to assemble a working client outbound.
	//   RealityPublicKey — base64 x25519 pubkey of vless-in's REALITY
	//     keypair (/etc/daal/reality.pub).
	//   TLSCertSHA256 — base64 SHA-256 of the self-signed leaf SPKI for
	//     the ws/hy2/naive inbounds (/etc/daal/tls-cert.pem); empty
	//     until the box ships those TLS inbounds.
	RealityPublicKey string `json:"reality_public_key,omitempty"`
	TLSCertSHA256    string `json:"tls_cert_sha256,omitempty"`
}

// CandidateMeta is one candidate entry on an OperatorRecord. It is
// the unsigned shape FRP-4b will fold into the per-route
// `_relaypack` sub-object. Field names match the on-disk relaypack-v1
// vocabulary so the binder can copy fields without mapping.
type CandidateMeta struct {
	Family           string          `json:"family"`
	ExposureMode     string          `json:"exposure_mode"`
	FamilyClass      string          `json:"family_class"`
	ProbingRiskClass string          `json:"probing_risk_class"`
	Port             int             `json:"port"`
	Params           json.RawMessage `json:"params,omitempty"`
	PublicRiskTags   []string        `json:"public_risk_tags"`
	OriginRiskTags   []string        `json:"origin_risk_tags"`

	// FRP-8: per-candidate §11.7 hardening attestation. Non-nil
	// only for ExposureMode=cdn_fronted candidates; the binder
	// emits this verbatim into the per-route FamilySpecificConfig
	// blob under the reserved key `_cdn_attestation`. Public-CDN-
	// metadata-only (matches bundle.CDNAttestation byte-for-byte).
	CDNAttestation *CDNAttestation `json:"cdn_attestation,omitempty"`
}

// CDNAttestation is the publisher-side mirror of bundle.CDNAttestation.
// Locked across modules: a regression test (validator_frp8_test.go +
// FRP-4b CLI integration) round-trips this shape.
type CDNAttestation struct {
	OriginCAFingerprint string `json:"origin_ca_fingerprint"`
	AOPEnabled          bool   `json:"aop_enabled"`
	FirewallID          string `json:"firewall_id"`
	DNSOnlyPresent      bool   `json:"dns_only_present"`
}

// ProvisionOpts is the input to Provider.Provision.
//
// PublisherPubKey: the wizard's Ed25519 public key, supplied so the
// box can embed it in the artefact manifest at provision time. The
// private half stays on the Helper machine; FRP-4a never sees it.
//
// EphemeralSSHKey: a one-shot Ed25519 keypair. Public half goes into
// cloud-init `ssh_authorized_keys`; private half lives in memory on
// the Helper for the 60-second provisioning window only. Supplement
// §9.5.1.
type ProvisionOpts struct {
	PublisherPubKey []byte   `json:"publisher_pub_key"`
	Region          string   `json:"region"`
	ServerType      string   `json:"server_type"`
	ToolboxProfile  string   `json:"toolbox_profile"`
	EnabledFamilies []string `json:"enabled_families,omitempty"`
	HelperIP        net.IP   `json:"helper_ip"`
	// MgmtPort is optional input. Zero means "generate a random
	// per-deploy V2 mgmt-plane port"; non-zero values must be in
	// [MinMgmtPort, MaxMgmtPort]. Providers persist the resolved
	// port into OperatorRecord.MgmtPort and stamp it into the V2
	// cloud-init template.
	MgmtPort int `json:"mgmt_port,omitempty"`
	// WaitForHealth asks a provider's live Provision path to poll
	// the bootstrap health endpoint and capture
	// MgmtTLSFingerprint before returning. Tests and dry-runs leave
	// this false.
	WaitForHealth   bool               `json:"wait_for_health,omitempty"`
	EphemeralSSHKey ed25519.PrivateKey `json:"-"` // never serialised
	DryRun          bool               `json:"dry_run,omitempty"`
	// ExistingServerID, when non-empty, tells the provider to
	// rebuild this server instead of creating a new one. The
	// server is re-imaged with the same cloud-init as a fresh
	// provision; its IP and billing stay unchanged.
	ExistingServerID string `json:"existing_server_id,omitempty"`
	// RollbackOnFailure asks the provider to destroy the cloud
	// resources it created when provisioning fails *after* the
	// server exists (cloud-init never went healthy, the temporary
	// firewall window could not be opened, …).
	//
	// Default false, deliberately: by then the box is a real,
	// billing resource that the idempotent retry path will reuse,
	// and a slow boot is not the same thing as a dead box. With
	// rollback off the provider does the next-best thing and names
	// the survivors out loud — a "provision_orphan" progress event
	// plus the server id / IP inside the returned error — so the
	// caller can offer the user a one-click teardown instead of
	// silently leaving a server on the meter. Set true for
	// unattended runs that must never leak a billing resource.
	RollbackOnFailure bool `json:"rollback_on_failure,omitempty"`
	// OnProgress is called at key provisioning milestones. May be
	// nil (no-op). The step string is machine-readable; message is
	// human-readable.
	OnProgress func(step, message string) `json:"-"`
}

// ResolveMgmtPort returns the caller-supplied mgmt port after
// range validation, or generates a fresh random per-deploy port
// when requested == 0.
func ResolveMgmtPort(requested int) (int, error) {
	if requested != 0 {
		if requested < MinMgmtPort || requested > MaxMgmtPort {
			return 0, fmt.Errorf("mgmt port %d outside [%d, %d]", requested, MinMgmtPort, MaxMgmtPort)
		}
		return requested, nil
	}
	span := big.NewInt(int64(MaxMgmtPort - MinMgmtPort + 1))
	n, err := rand.Int(rand.Reader, span)
	if err != nil {
		return 0, fmt.Errorf("generate mgmt port: %w", err)
	}
	return MinMgmtPort + int(n.Int64()), nil
}

// ValidateMgmtPort returns nil only when port is in the FRP-10
// production mgmt-plane range.
func ValidateMgmtPort(port int) error {
	if port < MinMgmtPort || port > MaxMgmtPort {
		return fmt.Errorf("mgmt port %d outside [%d, %d]", port, MinMgmtPort, MaxMgmtPort)
	}
	return nil
}

// DecommissionReport is the per-resource outcome of a teardown. It
// is the wire contract between `daal-deploy decommission` (which
// prints it as JSON on stdout) and the wizard's DestroyReport — the
// three booleans map 1:1 onto the shim's server_deleted /
// ssh_key_deleted / firewall_deleted fields.
//
// Boolean semantics, and they matter: a field is true when **nothing
// of that kind from this deploy is left behind in the cloud
// account** — which includes "there was never one to begin with".
// It does NOT mean "this run issued a delete call". False always
// means something survived, and Warnings then says what and why in
// operator-readable prose. The UI can render a true field as a
// green check without lying to anyone.
//
// Wire shape: canonical-JSON serialisable; Warnings is never null so
// the Rust side can deserialise it straight into a Vec<String>.
type DecommissionReport struct {
	Provider        string `json:"provider"`
	ServerID        string `json:"server_id,omitempty"`
	ServerDeleted   bool   `json:"server_deleted"`
	SSHKeyDeleted   bool   `json:"ssh_key_deleted"`
	FirewallDeleted bool   `json:"firewall_deleted"`

	// DeletedSSHKeyIDs / FirewallID are diagnostics: exactly which
	// cloud objects went away, so an operator cross-checking the
	// provider console can match them up.
	DeletedSSHKeyIDs []string `json:"deleted_ssh_key_ids,omitempty"`
	FirewallID       string   `json:"firewall_id,omitempty"`

	// Preserved names every resource teardown deliberately did not
	// delete, as "<kind>:<id-or-name>". A shared firewall, a
	// floating IP the operator owns, a key whose server is still
	// alive. The user is told, never surprised.
	Preserved []string `json:"preserved,omitempty"`

	// Warnings are non-fatal cloud errors and preservation reasons,
	// rendered verbatim by the caller. Never null.
	Warnings []string `json:"warnings"`
}

// NewDecommissionReport returns a report with every boolean false
// (nothing proven gone yet) and a non-nil Warnings slice.
func NewDecommissionReport(providerName, serverID string) *DecommissionReport {
	return &DecommissionReport{
		Provider: providerName,
		ServerID: serverID,
		Warnings: []string{},
	}
}

// Warnf appends one operator-readable warning. Teardown is
// best-effort by design: every non-fatal failure lands here instead
// of aborting the remaining resources.
func (r *DecommissionReport) Warnf(format string, args ...any) {
	r.Warnings = append(r.Warnings, fmt.Sprintf(format, args...))
}

// Preserve records a resource teardown left in place, as
// "<kind>:<id-or-name>" (e.g. "firewall:daal-relay-42").
func (r *DecommissionReport) Preserve(resource string) {
	r.Preserved = append(r.Preserved, resource)
}

// Clean reports whether the teardown left nothing behind.
func (r *DecommissionReport) Clean() bool {
	return r.ServerDeleted && r.SSHKeyDeleted && r.FirewallDeleted && len(r.Preserved) == 0
}

// ReprovisionOpts is the input to Provider.Reprovision. Implements
// supplement §9.5.1's L1/L2/L4/L5/L6 rotation paths via redeploy.
type ReprovisionOpts struct {
	NewToolboxProfile string `json:"new_toolbox_profile,omitempty"`
	NewSNI            string `json:"new_sni,omitempty"`
	NewWSPath         string `json:"new_ws_path,omitempty"`
	RegenCredentials  bool   `json:"regen_credentials,omitempty"`
}

// Pricing is the live per-hour cost for a server type, surfaced by
// the wizard's cost-disclosure screen.
type Pricing struct {
	Provider     string  `json:"provider"`
	Region       string  `json:"region"`
	ServerType   string  `json:"server_type"`
	HourlyEUR    float64 `json:"hourly_eur"`
	MonthlyEUR   float64 `json:"monthly_eur"`
	IncludedTBM  float64 `json:"included_traffic_tb_per_month,omitempty"`
	OverageEURGB float64 `json:"overage_eur_per_gb,omitempty"`
}
