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
