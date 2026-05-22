package bundle

import (
	"encoding/json"
	"errors"
)

// RelayPack is the bundle-level RelayPack metadata landed at FRP-1.
//
// Mirrors the additive Manifest-slot pattern used by 3A KillSwitches,
// 3B RendezvousHints, 3E TransportModules, 3F RedistributionChain /
// DelegateCaps. Nil for non-RelayPack bundles; non-nil iff the bundle
// was sealed by an FRP at V1.5+.
//
// Schema lifted verbatim from supplement v2.3.7 §12.2 + §12.2.5.
//
// Old clients (spec_version < 3): the parser rejects bundles carrying
// this slot at signature verification time because the new field is
// part of the canonical signed payload. Update-required, same contract
// as 3A/3B/3E/3F.
type RelayPack struct {
	// RelayPackID is one per FRP-provisioned VPS (or per
	// FRP-managed cluster). Stable across rotations of any
	// single candidate inside the bundle. Used by recipients
	// to recognise "the same FRP's pack" after rotation.
	RelayPackID string `json:"relay_pack_id"`

	// SharedRiskGraph is the bundle-wide shared-risk annotation
	// computed by the Helper at sign time. Each edge names a
	// risk tag (e.g. "public_ip:5.75.x.x") and the candidate
	// IDs sharing it. The selector consumes this for cooldown
	// propagation per supplement §13.4.
	SharedRiskGraph []SharedRiskEdge `json:"shared_risk_graph"`

	// CellScopeDefault is the V2 cell-scope default applied to
	// every candidate that does not specify its own cell_scope.
	// Nil at V1.5; FRP-11 widens to allow non-nil values.
	CellScopeDefault *CellScope `json:"cell_scope_default,omitempty"`

	// FreshnessURL is the V1.6 signed-JSON freshness endpoint
	// (supplement §11.7). Empty at V1.5; FRP-8 lifts the
	// validator to accept non-empty values.
	FreshnessURL string `json:"freshness_url,omitempty"`
}

// SharedRiskEdge names one tag and the candidate IDs sharing it.
// See supplement §12.3 ("shared-risk-graph annotation").
type SharedRiskEdge struct {
	Tag     string   `json:"tag"`
	Members []string `json:"members"`
}

// RelayPackEntry is the per-candidate _relaypack sub-object carried
// inside RouteManifestEntry.FamilySpecificConfig (an opaque
// json.RawMessage). The bundle parser does NOT know about this
// shape; the shared validator at bundle/go/relaypackvalidate
// parses it out at import time. The `_relaypack` key is reserved
// inside the family-specific blob.
//
// Schema lifted verbatim from supplement v2.3.7 §12.2.2 + §12.2.2.bis.
type RelayPackEntry struct {
	// ExposureMode := direct_vps | cdn_fronted | serverless_external.
	// V1.5 accepts only direct_vps; V1.6 lifts to also accept
	// cdn_fronted; serverless_external is reserved post-V2.
	ExposureMode string `json:"exposure_mode"`

	// FamilyClass := vps-native | vps-possible | external-ecosystem.
	// Drives UI explanation and rotation-ladder pivots (§14).
	FamilyClass string `json:"family_class"`

	// ProbingRiskClass := low | moderate | high.
	// Drives anti-burn race policy (§15).
	ProbingRiskClass string `json:"probing_risk_class"`

	// Modifiers are client-side packet-mutation modifiers
	// (§12.2.2.bis). Empty at V1.5 / V1.6; reserved post-V2.
	// FRP-12 introduces the per-modifier framework.
	Modifiers []Modifier `json:"modifiers,omitempty"`

	// PublicRiskTags are the surfaces the censor (TIC) can
	// directly observe and blocklist. Cooldown propagation
	// across candidates sharing a public_risk_tag is mandatory
	// (§13.4).
	PublicRiskTags []string `json:"public_risk_tags"`

	// OriginRiskTags are surfaces visible only in the operator's
	// deployment topology — never exposed to TIC under a
	// correctly hardened cdn_fronted deployment (§11.7).
	// Empty for direct_vps candidates (in direct mode the
	// origin IS the public surface).
	OriginRiskTags []string `json:"origin_risk_tags"`

	// CellScope is per-candidate V2 cell metadata. Nil at V1.5;
	// nullable at V2 for plain family-only RelayPacks.
	CellScope *CellScope `json:"cell_scope,omitempty"`

	// InnerProvenance is present only on cell-aggregated bundles.
	// It links the aggregate candidate back to the original cell
	// member that contributed it. The recipient-side cell chain
	// verifier requires PublisherFPHex/SubkeyFPHex to match a
	// member in trust/cell-membership.json before accepting the
	// aggregate. ProofB64 is reserved for a future per-candidate
	// signed envelope; FRP-11 treats it as opaque metadata.
	InnerProvenance *CellInnerProvenance `json:"_inner_provenance,omitempty"`
}

// CellInnerProvenance is the per-candidate provenance marker
// injected by publisher/cell when a member RelayPack route is
// merged into a cell aggregate. It is deliberately inside the
// signed route manifest entry, not in an unsigned sidecar.
type CellInnerProvenance struct {
	PublisherFPHex string `json:"publisher_fp_hex"`
	SubkeyFPHex    string `json:"subkey_fp_hex,omitempty"`
	ProofB64       string `json:"proof_b64,omitempty"`
}

// Modifier is one client-side packet-mutation modifier per
// §12.2.2.bis. Reserved schema slot at V1.5 / V1.6; the validator
// rejects any non-empty modifiers[] array. FRP-12 lifts per-kind
// after censor-lab PASS records exist.
type Modifier struct {
	Kind             string `json:"kind"`                         // client_desync | tls_fragment (post-V2)
	Platform         string `json:"platform,omitempty"`           // e.g. linux_desktop_only
	ProbingRiskClass string `json:"probing_risk_class,omitempty"` // overrides candidate's class
}

// CellScope is V2 redistribution metadata extending 3F's
// redistribution_policy + redistribution_cap. The 3F fields stay
// where they are at the route level; cell_scope adds new
// V2-cell-only metadata alongside them. See supplement §12.2.5.
//
// Nil at V1.5; FRP-11 lifts the validator. The cell_scope.policy
// transitive value is rejected at V1.5 (RP016).
type CellScope struct {
	CellID       string `json:"cell_id,omitempty"`
	CellJoinFP   string `json:"cell_join_fp,omitempty"`
	CellMaxDepth int    `json:"cell_max_depth,omitempty"`
}

// CDNAttestation is the FRP-8 §11.7 hardening attestation. It is
// produced by the wizard / publisher/deploy/cloudflare provider
// at deploy/rotate time and embedded in the per-candidate
// FamilySpecificConfig blob under the reserved key
// `_cdn_attestation`. The validator (relaypackvalidate package)
// reads it via ParseCDNAttestation and rejects bundles whose
// attestation fails the §11.7 mandatory assertions.
//
// Public-CDN-metadata-only: this struct carries fingerprints +
// IDs + booleans. Tokens, private keys, and AOP client cert
// bytes never appear here; they live on disk at mode 0600 (Origin
// CA priv + AOP client cert priv) and in the OS keystore (CF
// API token).
type CDNAttestation struct {
	// OriginCAFingerprint is the SHA-256 hex of the Cloudflare
	// Origin CA cert binding the origin to a Cloudflare-only
	// trust chain. Required (non-empty hex) at V16+.
	OriginCAFingerprint string `json:"origin_ca_fingerprint"`

	// AOPEnabled is true iff Authenticated Origin Pulls is on
	// for the zone fronting this candidate. Required true at V16+.
	AOPEnabled bool `json:"aop_enabled"`

	// FirewallID is the cloud-provider firewall rule ID
	// locking the origin's 443/tcp ingress to Cloudflare edge
	// IPs. Required (non-empty) at V16+.
	FirewallID string `json:"firewall_id"`

	// DNSOnlyPresent records whether any non-proxied A or AAAA
	// record exists on the chosen subdomain. Required false at
	// V16+ (RP023). The wizard refuses to deploy when this is
	// true; the validator independently rejects the bundle.
	DNSOnlyPresent bool `json:"dns_only_present"`
}

// ErrNoCDNAttestation is the sentinel returned by
// ParseCDNAttestation when no _cdn_attestation key is present.
var ErrNoCDNAttestation = errors.New("no _cdn_attestation sub-object in family_specific_config")

// ParseCDNAttestation extracts the _cdn_attestation sub-object
// from a RouteManifestEntry.FamilySpecificConfig blob. Returns
// ErrNoCDNAttestation (sentinel) if absent; a typed error if
// present but malformed.
func ParseCDNAttestation(familySpecificConfig json.RawMessage) (*CDNAttestation, error) {
	if len(familySpecificConfig) == 0 {
		return nil, ErrNoCDNAttestation
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(familySpecificConfig, &probe); err != nil {
		return nil, err
	}
	raw, ok := probe["_cdn_attestation"]
	if !ok {
		return nil, ErrNoCDNAttestation
	}
	var att CDNAttestation
	if err := json.Unmarshal(raw, &att); err != nil {
		return nil, err
	}
	return &att, nil
}

// ErrNoRelayPack is returned by ParseRelayPackEntry when the
// FamilySpecificConfig blob contains no _relaypack key. It is
// not a parse error; the caller treats this as "non-RelayPack
// candidate" and skips RelayPack validation for the candidate.
var ErrNoRelayPack = errors.New("no _relaypack sub-object in family_specific_config")

// ParseRelayPackEntry extracts the _relaypack sub-object out of a
// RouteManifestEntry.FamilySpecificConfig blob. Returns
// ErrNoRelayPack (sentinel) if the blob is absent, empty, or
// carries no _relaypack key. Returns a typed error if _relaypack
// is present but malformed.
//
// The bundle parser does not call this — it lives here so the
// publisher-side validator and downstream FRP-2 importer share
// one parser. Round-trip guarantee: the returned struct
// re-marshals to bytes that compare equal under
// CanonicalManifestJSON regardless of which Go map order is
// chosen at marshal time, because canonical.go re-parses through
// `any` and sorts object keys.
func ParseRelayPackEntry(familySpecificConfig json.RawMessage) (*RelayPackEntry, error) {
	if len(familySpecificConfig) == 0 {
		return nil, ErrNoRelayPack
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(familySpecificConfig, &probe); err != nil {
		return nil, err
	}
	raw, ok := probe["_relaypack"]
	if !ok {
		return nil, ErrNoRelayPack
	}
	var entry RelayPackEntry
	if err := json.Unmarshal(raw, &entry); err != nil {
		return nil, err
	}
	return &entry, nil
}
