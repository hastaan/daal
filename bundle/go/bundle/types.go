package bundle

import (
	"encoding/json"
	"time"
)

type TrustState string
type ScarcityClass string
type TransportFamily string
type FailureCategory string

const (
	TrustTrusted    TrustState = "trusted"
	TrustTOFU       TrustState = "tofu"
	TrustUnknown    TrustState = "unknown"
	TrustExpired    TrustState = "expired"
	TrustRevoked    TrustState = "revoked"
	TrustChangedKey TrustState = "changed_key"

	ScarcityEmergency    ScarcityClass = "emergency"
	ScarcityLow          ScarcityClass = "low"
	ScarcityNormal       ScarcityClass = "normal"
	ScarcityBulkCapable  ScarcityClass = "bulk-capable"
	ScarcityExperimental ScarcityClass = "experimental"
	ScarcityLifelineOnly ScarcityClass = "lifeline-only"

	TransportVLESSReality TransportFamily = "vless-reality"
	TransportNaive        TransportFamily = "naive"
	TransportWebSocketTLS TransportFamily = "websocket-tls"
	TransportHysteria2    TransportFamily = "hysteria2"
	TransportTUIC         TransportFamily = "tuic"
	TransportSnowflake    TransportFamily = "snowflake"
	TransportWebTunnel    TransportFamily = "webtunnel"
	TransportMASQUE       TransportFamily = "masque"
	TransportShadowsocks  TransportFamily = "shadowsocks"
	TransportTorBridge    TransportFamily = "tor-bridge"
	TransportWireGuard    TransportFamily = "wireguard"
	TransportAmneziaWG    TransportFamily = "amneziawg"
	// Phase 3A widens the parser-accepted family enum with the
	// V3 reserved values per specs/transport-families-v1.md.
	// Only `webtunnel` ships an engine handler at 3A; the rest
	// are reserved here so the parser accepts forward-compatible
	// bundles without bumping the spec version.
	TransportPsiphon         TransportFamily = "psiphon"
	TransportConjure         TransportFamily = "conjure"
	TransportTransportModule TransportFamily = "transport_module"
	TransportLifelineRelay   TransportFamily = "lifeline_relay"
	TransportOther           TransportFamily = "other"
)

type Manifest struct {
	SpecVersion int                  `json:"spec_version"`
	Publisher   PublisherInfo        `json:"publisher"`
	Bundle      BundleInfo           `json:"bundle"`
	Routes      []RouteManifestEntry `json:"routes"`

	// Phase 3A: reserved top-level slot for the family-level
	// kill-switch deltas. The 3A parser accepts the field (must
	// be a JSON array if present) but the engine ignores its
	// contents until 3E (`specs/wasm-kill-switch-v1.md`).
	// Reserving the slot now avoids a spec_version bump at 3E.
	KillSwitches []KillSwitchEntry `json:"kill_switches,omitempty"`

	// Phase 3B: top-level offline rendezvous hints. Each entry
	// is a publisher-signed Snowflake bridge hint suitable for
	// the `offline_hint` rendezvous channel. The parser
	// validates each entry's inner signature (covers
	// canonical(hint payload) under the publisher's signing
	// key) before admission; entries with a bad signature are
	// rejected and the bundle import fails. See
	// specs/snowflake-route-v1.md "Offline hints".
	RendezvousHints []RendezvousHint `json:"rendezvous_hints,omitempty"`

	// Phase 3E: top-level WASM transport modules. Each entry is
	// a self-describing (slug, sha256, raw bytes) tuple. The
	// parser enforces the per-module 4 MiB cap, the per-bundle
	// 16 MiB total cap, the slug regex, and that the sha256
	// matches the decoded blob. The engine activates a module
	// only when a route's `transport_module_slug` references
	// the entry. See specs/wasm-transport-v1.md.
	TransportModules []TransportModuleEntry `json:"transport_modules,omitempty"`

	// Phase 3F: the `.sbp.share` re-share variant. Present iff
	// Bundle.Type == "delegated_share". Both fields are required
	// when the type is delegated_share; the parser rejects
	// either one alone. See specs/delegate-keys-v1.md.
	RedistributionChain []RedistributionChainHop `json:"redistribution_chain,omitempty"`
	DelegateCaps        []DelegateCapEntry       `json:"delegate_caps,omitempty"`

	// FRP-1: bundle-level RelayPack metadata. Nil for non-RelayPack
	// bundles. Non-nil iff the bundle was sealed by an FRP at V1.5+
	// per supplement v2.3.7 §12.2 + §21.1. Setting this slot
	// requires spec_version >= 3 (enforced by VerifyBundle); old
	// clients (spec_version 1 or 2) reject RelayPack-bearing bundles
	// at signature verification time because the new field is part
	// of the canonical signed payload. Same update-required contract
	// as 3A KillSwitches / 3B RendezvousHints / 3E TransportModules /
	// 3F RedistributionChain. See specs/relaypack-v1.md.
	RelayPack *RelayPack `json:"relay_pack,omitempty"`
}

// RedistributionChainHop is the locked-at-3F wire shape of one
// hop in a `.sbp.share` redistribution chain. Mirrors
// `core/delegate.ChainHop`; the duplication is unavoidable
// because the bundle module is its own go.mod. A regression
// in `bundle/go/bundle/v3f_test.go` and a regression in
// `core/delegate/delegate_test.go` together lock the wire
// shape on both sides.
type RedistributionChainHop struct {
	DelegateFPHex  string `json:"delegate_fp_hex"`
	DelegatePub    string `json:"delegate_pub"`
	SignedAt       string `json:"signed_at"`
	RecipientFPHex string `json:"recipient_fp_hex"`
	SignatureB64   string `json:"signature"`
}

// DelegateCapEntry is the locked-at-3F wire shape of the
// per-route advisory cap pinned at sign time. The receiver
// uses these values to enforce caps at import time; see
// `core/delegate.EnforceCap`.
type DelegateCapEntry struct {
	RouteID                   string `json:"route_id"`
	SharedWithCountAtSignTime uint8  `json:"shared_with_count_at_sign_time"`
	CapAtSignTime             uint8  `json:"cap_at_sign_time"`
}

// RendezvousHint is the Phase 3B offline-hint envelope. The hint
// payload (Bridge / Fingerprint / NotAfter / etc.) is JSON-encoded
// inside `Payload` and signed by the publisher; carrying it as
// `RawMessage` keeps the canonicalisation stable.
type RendezvousHint struct {
	Payload   json.RawMessage `json:"payload"`
	Signature string          `json:"signature"` // base64-RFC4648-no-padding of Ed25519(canonical(payload))
}

// KillSwitchEntry is the locked-at-3E wire shape of a single
// signed kill-switch tuple. The bundle-side struct mirrors the
// engine-side one in `core/wasm.KillSwitchEntry`; the duplication
// is unavoidable because the bundle module is its own go.mod.
// A regression in `bundle/go/bundle/v3e_test.go` round-trips the
// JSON shape and a regression in `core/wasm/killswitch_test.go`
// exercises the verifier.
//
// The signature covers the canonical payload
// `{"slug":"…","sha256":"…","generation":N}` (no whitespace,
// keys in literal order); see `core/wasm/killswitch.go::canonicalEntryBytes`.
type KillSwitchEntry struct {
	Slug         string `json:"slug"`
	SHA256Hex    string `json:"sha256"`
	Generation   uint64 `json:"generation"`
	SignatureB64 string `json:"signature"`
}

// TransportModuleEntry is the locked-at-3E wire shape of a
// signed WASM transport module bundled into the .sbp. The
// `wasm_blob_b64` field carries the raw module bytes
// base64-encoded; the parser enforces the per-module 4 MiB cap
// and the per-bundle 16 MiB total cap. The `min_engine_version`
// is checked against the running engine version at activation
// time (NOT at parse time — so an older bundle can carry a
// module that requires a newer engine without bouncing the
// import). Slug regex `[a-z0-9_-]{3,32}` is enforced at parse
// time. See specs/wasm-transport-v1.md.
type TransportModuleEntry struct {
	Slug                 string   `json:"slug"`
	SHA256Hex            string   `json:"sha256"`
	WASMBlobB64          string   `json:"wasm_blob_b64"`
	MinEngineVersion     string   `json:"min_engine_version,omitempty"`
	OptionalCapabilities []string `json:"optional_capabilities,omitempty"`
}

type PublisherInfo struct {
	Name                 string `json:"name"`
	KeyFingerprintHex    string `json:"key_fingerprint_hex"`
	KeyFingerprintEN     string `json:"key_fingerprint_en,omitempty"`
	KeyFingerprintFA     string `json:"key_fingerprint_fa,omitempty"`
	KeyFingerprintVisual string `json:"key_fingerprint_visual,omitempty"`
	KeyCreatedAt         string `json:"key_created_at"`
	TrustClass           string `json:"trust_class"`

	// v2 (Phase 1.5A) — JSON-additive within v2; absent in v1.
	RevocationURL            string `json:"revocation_url,omitempty"`
	RevocationFingerprintHex string `json:"revocation_fingerprint_hex,omitempty"`
}

type BundleInfo struct {
	ID               string   `json:"id"`
	Type             string   `json:"type"`
	CreatedAt        string   `json:"created_at"`
	ExpiresAt        string   `json:"expires_at"`
	PreviousBundleID *string  `json:"previous_bundle_id"`
	SupersedesKeys   []string `json:"supersedes_keys"`

	// v2 (Phase 1.5A) — only populated on directory bundles.
	PointerRotation *PointerRotationRef `json:"pointer_rotation_ref,omitempty"`
}

// PointerRotationRef points to a project-root-signed pointer rotation
// envelope embedded in the same .sbp under the named archive entry.
type PointerRotationRef struct {
	Path string `json:"path"` // e.g., "trust/pointer-rotation.json"
}

type RouteManifestEntry struct {
	ID              string `json:"id"`
	ScarcityClass   string `json:"scarcity_class"`
	TransportFamily string `json:"transport_family"`
	ConfigPath      string `json:"config_path"`
	ValidFrom       string `json:"valid_from"`
	ValidUntil      string `json:"valid_until"`
	UDPGated        bool   `json:"udp_gated,omitempty"`

	// Phase 3A. See specs/transport-families-v1.md and
	// specs/sbp-v1.md.
	//
	// FamilySpecificConfig is opaque-to-bundle: the parser
	// validates only that it is a JSON object (or absent). Each
	// transport family's spec defines the keys (e.g.
	// webtunnel_secret_path / webtunnel_sni / webtunnel_alpn for
	// the WebTunnel family per specs/webtunnel-route-v1.md).
	FamilySpecificConfig json.RawMessage `json:"family_specific_config,omitempty"`

	// CaveatFAIR overrides the family-default Iranian region
	// caveat for this route. Optional. Default empty (the
	// family's default caveat applies, if any).
	CaveatFAIR string `json:"caveat_fa_ir,omitempty"`

	// ExperimentalMinEngineVersion is a semver pin. If the
	// engine is older, the route is filtered as if the
	// experimental gate were OFF, regardless of the user's
	// toggle. Optional. Default empty (no minimum).
	ExperimentalMinEngineVersion string `json:"experimental_min_engine_version,omitempty"`

	// RendezvousPriority is the bundle-supplied per-route
	// priority list of rendezvous channels for the Phase 3B
	// rendezvous Selector. Each entry MUST be in the v1 closed
	// list (domain_fronted_broker / sqs / amp_cache / push /
	// offline_hint). Empty / absent means "use the engine
	// default order"; an unknown entry rejects the bundle.
	// See specs/rendezvous-channels-v1.md.
	RendezvousPriority []string `json:"rendezvous_priority,omitempty"`

	// MasqueEndpoint is the Phase 3C MASQUE upstream URL the
	// publisher operates. ONLY meaningful for routes whose
	// `transport_family = "masque"`; the parser rejects the
	// field on non-MASQUE routes (defence-in-depth — keeps
	// the `routes[]` shape unambiguous).
	//
	// MUST be a parseable `https://host[:port]/path` URL with
	// non-empty path. The `https` scheme is mandatory; `http`
	// is rejected. The path holds the upstream's MASQUE
	// resource (per RFC 9298 / RFC 9484). Empty / absent on a
	// MASQUE route means the route has no usable endpoint and
	// is filtered as broken at import time.
	//
	// See specs/masque-ladder-v1.md.
	MasqueEndpoint string `json:"masque_endpoint,omitempty"`

	// PsiphonBundleBlobB64 is the Phase 3D base64-encoded
	// upstream-Psiphon publisher bundle bytes. ONLY meaningful
	// for routes whose `transport_family = "psiphon"`; the
	// parser rejects the field on non-psiphon routes.
	//
	// The decoded bytes MUST be in [256, 65536]. Daal does NOT
	// parse the contents — semantic validation (signature /
	// expiry / protocol-class selection) is the upstream
	// psiphon-tunnel-core library's responsibility. See
	// specs/psiphon-route-v1.md.
	PsiphonBundleBlobB64 string `json:"psiphon_bundle_blob_b64,omitempty"`

	// ConjurePhantomSubnets is the Phase 3D non-empty list of
	// CIDRs forming the phantom-pool for a Conjure route. ONLY
	// meaningful for routes whose `transport_family =
	// "conjure"`; the parser rejects the field on non-conjure
	// routes.
	//
	// Each CIDR MUST parse and MUST satisfy the locked-at-3D
	// prefix-length floors (/24 IPv4, /32 IPv6) — refusing
	// implausibly broad pools is defence-in-depth. See
	// specs/conjure-route-v1.md.
	ConjurePhantomSubnets []string `json:"conjure_phantom_subnets,omitempty"`

	// ConjureStationPubkey is the Phase 3D Conjure Tap-Dance
	// station's curve25519 public key, hex-encoded (64 hex
	// chars). ONLY meaningful for `transport_family =
	// "conjure"` routes.
	ConjureStationPubkey string `json:"conjure_station_pubkey,omitempty"`

	// ConjureDecoyPool is the Phase 3D list of decoy hostnames
	// (RFC 1123) the upstream library MAY use for registration
	// cover. Empty list ⇒ upstream picks defaults. ONLY
	// meaningful for `transport_family = "conjure"` routes.
	ConjureDecoyPool []string `json:"conjure_decoy_pool,omitempty"`

	// TransportModuleSlug is the Phase 3E reference into the
	// bundle's `transport_modules[]` table. ONLY meaningful for
	// routes whose `transport_family = "transport_module"`; the
	// parser rejects the field on non-module routes (defence-
	// in-depth). Empty / absent on a transport_module route is
	// NOT a parse-time rejection — the engine treats it as "no
	// usable module" and filters at activation time, matching
	// the 3C / 3D soft-validation discipline. See
	// specs/wasm-transport-v1.md.
	TransportModuleSlug string `json:"transport_module_slug,omitempty"`

	// RedistributionPolicy is the Phase 3F closed enum the
	// publisher attaches per route. One of {none, delegated_n,
	// transitive}. Absent/empty defaults to "none" (fail-closed)
	// at the receiver side. ONLY the publisher sets this field;
	// the engine NEVER amends it. See specs/delegate-keys-v1.md.
	RedistributionPolicy string `json:"redistribution_policy,omitempty"`

	// RedistributionCap is the Phase 3F per-route cap the
	// publisher attaches when RedistributionPolicy = "delegated_n".
	// MUST be in [1, 255] when policy is delegated_n; MUST be
	// absent (0) for other policies. The parser rejects mismatches.
	RedistributionCap uint8 `json:"redistribution_cap,omitempty"`
}

type Bundle struct {
	Manifest     Manifest
	Signature    []byte
	PublisherPub []byte
	Profiles     map[string][]byte
	Revocation   *RevocationList

	// FRP-7.5: when present, the archive carried
	// `trust/subkey-cert.json` and the manifest signature was
	// produced by the sub-key (cert subject), not by
	// PublisherPub directly. The verifier walks pub→cert→sub
	// before checking the manifest signature. Nil for legacy
	// 1A bundles. Requires Manifest.SpecVersion >= 4.
	// See specs/sbp-v1.md "Sub-key cert chain".
	SubkeyCertJSON []byte

	// FRP-11: when present, the archive carried
	// `trust/cell-membership.json` (admin-quorum-signed M-of-N
	// canonical membership document) and `trust/cell-delegation.json`
	// (admin-quorum-signed delegation grant of bundle-signer
	// authority). Both are NEW bundle files; manifest schema is
	// UNCHANGED at SpecVersion 4. VerifyBundle does NOT parse
	// these — the recipient-side chain walk lives at
	// `core/trust/cell_verify.go` and calls into
	// `bundle.ParseCellDocs`. Bundle-local canonicalisation +
	// admin-quorum signature verification live in
	// `bundle/go/bundle/cellcanon.go`. Module-boundary invariant
	// (FRP-track v1 §61): bundle/go/bundle/ MUST NOT import
	// daal/core. Both fields nil for non-cell bundles. See
	// specs/cell-v1.md.
	CellMembershipJSON []byte
	CellDelegationJSON []byte
}

// CellMembershipDoc is the locked-at-FRP-11 wire shape of
// `trust/cell-membership.json`. Carries the cell ID, the
// admin pubkey set, the quorum threshold M, the member list,
// the rule set, and the M-of-N independent Ed25519 admin
// signatures over the canonical document body (the document
// with the `admin_signatures` field stripped). N ∈ [1, 25];
// M ≤ N; default M = ⌈(N+1)/2⌉.
//
// Locked invariant (FRP-track v1 §31): cell admin scheme is
// M-of-N independent Ed25519. NO threshold cryptosystem.
type CellMembershipDoc struct {
	CellID          string               `json:"cell_id"`
	AdminPubkeys    []string             `json:"admin_pubkeys"`
	QuorumM         int                  `json:"quorum_m"`
	Members         []CellMember         `json:"members"`
	RuleSet         CellRuleSet          `json:"rule_set"`
	AdminSignatures []CellAdminSignature `json:"admin_signatures"`
}

// CellMember names a publisher participating in the cell. The
// fingerprints reference the FRP-7.5 sub-key cert chain so the
// inner-publisher provenance walk has somewhere to land.
type CellMember struct {
	PublisherFPHex string `json:"publisher_fp_hex"`
	SubkeyFPHex    string `json:"subkey_fp_hex"`
	JoinedAtUnix   int64  `json:"joined_at_unix"`
}

// CellRuleSet carries the cell-scope governance fields. The
// `cell_max_depth` field is bounded by the route-level FRP-3F
// `redistribution_cap`; the validator caller (recipient) is
// responsible for taking the min when projecting policy.
type CellRuleSet struct {
	CellMaxDepth   uint8  `json:"cell_max_depth"`
	AbuseRoute     string `json:"abuse_route"`
	ValidUntilUnix int64  `json:"valid_until_unix"`
}

// CellAdminSignature is one signature in the M-of-N quorum.
// AdminPubkeyIdx indexes into CellMembershipDoc.AdminPubkeys.
// The signature covers `canonical(membership doc with the
// admin_signatures field stripped)`; see cellcanon.go.
type CellAdminSignature struct {
	AdminPubkeyIdx int    `json:"admin_pubkey_idx"`
	SignatureB64   string `json:"signature_b64"`
}

// CellDelegationDoc is the locked-at-FRP-11 wire shape of
// `trust/cell-delegation.json`. The cell admins (M-of-N
// quorum) sign this grant authorising a per-cell Ed25519
// bundle-signer key. The aggregated RelayPack's manifest
// signature is produced by that bundle-signer key, NOT by
// the admin keys directly. This lets the bundle-signer be
// rotated without re-signing every aggregate.
type CellDelegationDoc struct {
	CellID             string               `json:"cell_id"`
	BundleSignerPubkey string               `json:"bundle_signer_pubkey"`
	ValidFromUnix      int64                `json:"valid_from_unix"`
	ValidUntilUnix     int64                `json:"valid_until_unix"`
	AdminSignatures    []CellAdminSignature `json:"admin_signatures"`
}

type RevocationList struct {
	RevokedPublishers []string `json:"revoked_publishers,omitempty"`
	RevokedRoutes     []string `json:"revoked_routes,omitempty"`
}

type Route struct {
	RouteID              string   `json:"route_id"`
	TransportFamily      string   `json:"transport_family"`
	Engine               string   `json:"engine"`
	SourceType           string   `json:"source_type"`
	PublisherID          string   `json:"publisher_id"`
	PublisherLabel       string   `json:"publisher_label"`
	TrustState           string   `json:"trust_state"`
	ScarcityClass        string   `json:"scarcity_class"`
	ModesAllowed         []string `json:"modes_allowed"`
	ExpiresAt            string   `json:"expires_at"`
	ImportedAt           string   `json:"imported_at"`
	LastSuccessBucket    string   `json:"last_success_bucket,omitempty"`
	LastFailureBucket    string   `json:"last_failure_bucket,omitempty"`
	LastFailureCategory  string   `json:"last_failure_category,omitempty"`
	ConsecutiveFailures  int      `json:"consecutive_failures"`
	CooldownUntil        *string  `json:"cooldown_until"`
	BytesUsedThisHour    int64    `json:"bytes_used_this_hour"`
	BytesUsedThisSession int64    `json:"bytes_used_this_session"`
	UserNote             string   `json:"user_note,omitempty"`
}

type Publisher struct {
	PublisherID       string   `json:"publisher_id"`
	DisplayName       string   `json:"display_name"`
	TrustLevel        string   `json:"trust_level"`
	FirstSeen         string   `json:"first_seen"`
	LastSeenBundle    string   `json:"last_seen_bundle"`
	KeyStatus         string   `json:"key_status"`
	RotationChain     []string `json:"rotation_chain"`
	RevocationSources []string `json:"revocation_sources"`
	UserAssignedLabel string   `json:"user_assigned_label,omitempty"`
}

func ParseTime(value string) (time.Time, error) {
	return time.Parse(time.RFC3339, value)
}
