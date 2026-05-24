package cloudflare

import (
	"errors"
	"time"
)

// FrontRecord is the durable state for one Cloudflare-fronted
// candidate. It is what the wizard persists to the V005 SQLite
// table and what the binder consumes when emitting the
// `_cdn_attestation` blob inside the bundle's `_relaypack`
// per-candidate sub-object.
//
// Rule 5 of phase doc §13: this struct holds **public CDN
// metadata only**. Cloudflare API tokens live in the OS
// keystore; Origin CA private bytes live on disk under
// staging_dir/cdn/{operator_id}/ at mode 0600 and are
// referenced by path in the V005 row, never embedded inline.
type FrontRecord struct {
	// Hostname is the public domain the recipient connects to,
	// e.g. "momsroute.example.com". MUST be proxied through
	// Cloudflare (orange cloud); the validator and the deploy
	// path both refuse DNS-only records.
	Hostname string `json:"hostname"`

	// ZoneID is Cloudflare's zone identifier (32-hex). Used
	// for every zone-scoped API call; surfaced to the wizard
	// so subsequent rotations can target the same zone
	// without re-resolving.
	ZoneID string `json:"zone_id"`

	// PublicPath is the visible random path the family's
	// client targets, e.g. "/r/8c1f4a23". A Worker on the
	// FRP's zone rewrites it to OriginPath before forwarding
	// to the origin. Rotating PublicPath is a
	// Cloudflare-API-only operation (no box redeploy).
	PublicPath string `json:"public_path"`

	// OriginPath is the stable path the sing-box config on
	// the origin expects, e.g. "/ws". Never visible to the
	// censor. Set once at provision time; rotated only on
	// box redeploy (rare).
	OriginPath string `json:"origin_path"`

	// WorkerRouteID is the Cloudflare route binding that
	// targets the rewrite Worker. Surfaced so RotatePath can
	// update the binding in place rather than recreating it.
	WorkerRouteID string `json:"worker_route_id"`

	// FirewallID is the cloud-provider firewall rule (e.g.
	// Hetzner Cloud Firewall ID) that locks origin 443/tcp
	// to Cloudflare edge ranges. Refreshed by the Helper at
	// every deploy + rotate + explicit "verify posture" + the
	// optional OS scheduled task.
	FirewallID string `json:"firewall_id"`

	// OriginCAFingerprint is the SHA-256 fingerprint of the
	// Cloudflare-issued Origin CA cert deployed on the
	// origin. PUBLIC fingerprint, hex-encoded; the actual
	// private key + cert PEM live on disk at OriginCAPrivPath
	// + OriginCACertPath, never inline here.
	OriginCAFingerprint string `json:"origin_ca_fingerprint"`

	// OriginCACertPath is the on-disk path to the Origin CA
	// certificate (PEM). The cloud-init template reads this
	// at provision time. Mode 0600.
	OriginCACertPath string `json:"origin_ca_cert_path"`

	// OriginCAPrivPath is the on-disk path to the Origin CA
	// private key (PEM). Mode 0600. NEVER stored in the
	// OperatorRecord JSON blob; only the path is durable.
	OriginCAPrivPath string `json:"origin_ca_priv_path"`

	// AOPClientCertPath is the on-disk path to the
	// Cloudflare-signed Authenticated Origin Pulls client
	// cert (PEM). Deployed to the origin via cloud-init.
	AOPClientCertPath string `json:"aop_client_cert_path"`

	// AOPEnabled is the toggle the wizard sets on the zone.
	// Always true under §11.7. The validator checks this
	// flag inside the signed attestation (RP022).
	AOPEnabled bool `json:"aop_enabled"`

	// FreshnessURL is the FRP-controlled static-host URL the
	// wizard uploads the freshness JSON document to. Empty
	// if the FRP skipped the freshness mechanism.
	// Mirrors Manifest.RelayPack.FreshnessURL one-to-one.
	FreshnessURL string `json:"freshness_url,omitempty"`

	// FreshnessHost is which static-host backend the wizard
	// uses: "r2" | "github_pages" | "ipfs" (ipfs reserved /
	// disabled at FRP-8). Drives which credential set the
	// wizard reads from the keystore at upload time.
	FreshnessHost string `json:"freshness_host,omitempty"`

	// LastEdgeRefreshUnix is the wall-clock at which the
	// Helper last fetched the Cloudflare edge IP ranges and
	// applied them to the firewall. Surfaced in the wizard
	// "Verify CDN posture" panel.
	LastEdgeRefreshUnix int64 `json:"last_edge_refresh_unix,omitempty"`
}

// CDNAttestation is the additive sub-object that lands inside
// the per-candidate `_relaypack` opaque blob (FRP-1's
// json.RawMessage slot). At V1.6 every cdn_fronted candidate's
// `_relaypack._cdn_attestation` MUST carry these four fields;
// the validator (RP022) rejects malformed or missing
// attestations, and (RP023) rejects attestations that report
// `dns_only_present: true`.
//
// The struct is canonicalisable in the same json.Marshal-key-
// sort sense as the rest of the relaypack profile.
type CDNAttestation struct {
	OriginCAFingerprint string `json:"origin_ca_fingerprint"`
	AOPEnabled          bool   `json:"aop_enabled"`
	FirewallID          string `json:"firewall_id"`
	DNSOnlyPresent      bool   `json:"dns_only_present"`
}

// CloudflareOpts is the input to ProvisionFront. The Cloudflare
// API token is supplied via the secret-bytes channel; ProvisionFront
// never logs it.
type CloudflareOpts struct {
	// Hostname is the public domain to provision.
	Hostname string

	// OriginIP is the public IP the proxied A record points at.
	OriginIP string

	// OriginIPv6 is the public IPv6 the proxied AAAA record
	// points at. Empty skips AAAA.
	OriginIPv6 string

	// PublicPath is the visible random path. If empty,
	// ProvisionFront generates a 16-hex-char random path.
	PublicPath string

	// OriginPath is the stable origin path the sing-box
	// expects. Required.
	OriginPath string

	// CFTokenSecret is the Cloudflare API token bytes.
	// Zeroized after the Provision call returns.
	CFTokenSecret []byte

	// OutDir is the directory the live impl writes
	// origin_ca.pem, origin_ca.key, aop_client.pem to.
	// Mode 0700 expected.
	OutDir string

	// Now is the wall-clock; tests inject a fixed time.
	Now func() time.Time
}

// PostureReport is the result of a "Verify CDN posture" check
// (the wizard's settings button per §11.7). The wizard surfaces
// any non-PASS field to the operator.
type PostureReport struct {
	OriginCAFingerprintMatch bool   `json:"origin_ca_fingerprint_match"`
	AOPEnabled               bool   `json:"aop_enabled"`
	FirewallEdgeRangesFresh  bool   `json:"firewall_edge_ranges_fresh"`
	DNSProxiedOnly           bool   `json:"dns_proxied_only"`
	Notes                    string `json:"notes,omitempty"`
}

// Errors used across the package.
var (
	// ErrCFNotImplemented remains reserved for optional providers
	// that deliberately do not implement a Cloudflare API method.
	// NewLiveCFClient no longer returns it for the FRP-8 critical
	// path.
	ErrCFNotImplemented = errors.New("cloudflare: API method not implemented")

	// ErrDNSOnlyRecordPresent is returned by EnsureProxiedRecords
	// when the chosen subdomain has any non-proxied A or AAAA
	// record. The wizard refuses to proceed; this maps to RP023.
	ErrDNSOnlyRecordPresent = errors.New("cloudflare: existing DNS-only A/AAAA record on subdomain (refusing per §11.7)")

	// ErrOriginCAIssueFailed is returned by IssueOriginCert.
	ErrOriginCAIssueFailed = errors.New("cloudflare: origin CA cert issuance failed")

	// ErrAOPEnableFailed is returned by EnableAOP.
	ErrAOPEnableFailed = errors.New("cloudflare: enable Authenticated Origin Pulls failed")
)
