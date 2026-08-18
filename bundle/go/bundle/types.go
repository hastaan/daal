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

	// TransportFamily is the RECIPIENT-SIDE VOCABULARY: the set of
	// values a pack is allowed to DECLARE. It is not a list of what
	// Daal can serve, and it is not a list of what Daal can dial.
	// Those three sets are different and the canonical
	// family-by-family reconciliation of them is
	// `docs/transport-family-inventory.md`; the machine-readable
	// answer to "can this build dial it" is
	// `core/routestore/family.go`'s maturity table.
	//
	// Every value below is permanent. Removing one is a wire break
	// for older clients (the parser rejects unknown values with
	// `bundle_corrupted`) and buys nothing, so the values marked
	// STRUCTURALLY UNAVAILABLE below stay reserved forever.

	TransportVLESSReality TransportFamily = "vless-reality"
	TransportNaive        TransportFamily = "naive"
	TransportWebSocketTLS TransportFamily = "websocket-tls"
	TransportHysteria2    TransportFamily = "hysteria2"
	TransportTUIC         TransportFamily = "tuic"

	// TransportSnowflake — RE-SCOPED, not impossible.
	// Snowflake is reachable, but ONLY as a Tor pluggable
	// transport driven by the `tor` outbound (sing-box 1.13.12
	// registers `tor`; it does not register `snowflake`). It is
	// NOT reachable by vendoring `pion/webrtc` into core/go.mod.
	// Phase 3B wrote a Handler + WebRTCDialer state machine for
	// that path; Wave 5 deleted it (`core/transports/snowflake`,
	// zero references outside its own tests) because the path is
	// not being taken: it drags a WebRTC/DTLS/SCTP stack and a
	// broker rendezvous into the engine for a transport the `tor`
	// outbound can already carry through torrc. The rendezvous
	// machinery it used (`core/rendezvous`) stays — that is used
	// by the ABI.
	TransportSnowflake TransportFamily = "snowflake"

	// TransportWebTunnel — RE-SCOPED, and re-scoped downward.
	// WebTunnel is a Tor pluggable transport; like snowflake it
	// arrives free through the `tor` outbound and has no outbound
	// of its own in sing-box 1.13.12. Two facts about it are
	// routinely stated the wrong way round in this repo's older
	// prose: it is field-effective in CHINA and it FAILS in IRAN,
	// which is our stated primary target. Do not present it to an
	// Iranian user as a recommended family.
	TransportWebTunnel TransportFamily = "webtunnel"

	// TransportMASQUE — STRUCTURALLY UNAVAILABLE at this
	// engine version, and dormant rather than deleted.
	// sing-box 1.13.12 registers NO masque outbound (see
	// `include/registry.go`: direct, block, selector, urltest,
	// socks, http, shadowsocks, vmess, trojan, naive, tor, ssh,
	// shadowtls, vless, anytls, + the with_quic set). There is
	// therefore nothing to dial with, and separately nothing to
	// serve with: MASQUE's value is riding a large provider's
	// existing CONNECT-UDP infrastructure, which a self-hosted
	// publisher does not have — a self-hosted MASQUE proxy is a
	// single-tenant QUIC endpoint with none of the anonymity-set
	// benefit that motivates RFC 9298 in the first place.
	// What would have to become true: an upstream sing-box
	// release registering a masque outbound, or a provider
	// relationship. Neither is a code change here.
	TransportMASQUE TransportFamily = "masque"

	// TransportShadowsocks means SHADOWSOCKS-2022 and nothing else.
	// Daal's publisher mints exactly one method under this name,
	// 2022-blake3-aes-128-gcm; it never serves a legacy AEAD cipher
	// (no replay protection, defeated by active probing) or a stream
	// cipher. The family string stays "shadowsocks" deliberately: it
	// is already in every shipped client's accepted enum, and a new
	// "shadowsocks-2022" value would be wire-breaking for packs that
	// older builds must keep importing.
	//
	// It is the only family Daal serves with NO TLS handshake in it,
	// which is its entire reason for existing — the Xue et al. (USENIX
	// Security 2024) nested-TLS classifier threatens vless-reality,
	// websocket-tls and naive simultaneously, and cannot see this one.
	// It is correlation-breaking diversity and NOT a stronger tier:
	// shadowsocks is the best-studied target of entropy and
	// packet-length classifiers, so it is weak on its own.
	TransportShadowsocks TransportFamily = "shadowsocks"
	TransportTorBridge   TransportFamily = "tor-bridge"

	// TransportWireGuard — DIALABLE SINCE WAVE 5, and this comment
	// carried the pre-Wave-5 reason for a wave after the reason stopped
	// being true. Corrected in the repair pass, because this file is
	// the one the next engineer opens.
	//
	// What is now true: sing-box models WireGuard as an `endpoints[]`
	// adapter, not an outbound, and `core/engine/config.go` grew the
	// `Endpoints []map[string]any` slot for it; `bundle/go/uri/
	// wireguard.go` emits a real WireGuardEndpointOptions object with
	// `"type":"wireguard"` (it emitted `"amnezia-wg"` before, which is
	// registered nowhere); and the Android engine is built with
	// `with_wireguard`, so the endpoint is registered rather than
	// stubbed. It is MaturityExperimental in
	// `core/routestore/family.go`.
	//
	// WHAT THE LABEL MUST NOT BORROW. AmneziaWG — WireGuard plus
	// obfuscation — is the most resilient transport measured in Iran.
	// PLAIN WireGuard, which is all this build can dial, is a named
	// immediate-block target there and is UDP, which the adversary
	// document states the intent to block completely and permanently.
	// A WireGuard route is worth having where WireGuard is allowed and
	// is among the first things to die where it is not. No copy may
	// borrow AmneziaWG's track record for it.
	//
	// Daal does not SERVE this family: no relay inbound, no
	// per-recipient credential, no firewall rule. Paste/import only.
	TransportWireGuard TransportFamily = "wireguard"

	// TransportAmneziaWG — STILL cannot be EXPRESSED, and the reason is
	// the protocol rather than the plumbing. sing-box 1.13.12 contains
	// no AmneziaWG code whatsoever (`grep -ri amnezia` over the module
	// returns nothing), so there is nowhere to put the Jc/Jmin/Jmax/
	// S1/S2/H1..H4 parameters that ARE the family. An AmneziaWG conf
	// imports as a DOWNGRADED plain-wireguard route, labelled
	// `wireguard`, because WireGuard is what goes on the wire.
	// MaturityUnsupported in `core/routestore/family.go` — NOT
	// "experimental", because experimental invites the user to flip the
	// experimental gate and watch every route fail identically.
	// Promoting it requires an engine that implements AmneziaWG, not a
	// relabelling.
	TransportAmneziaWG TransportFamily = "amneziawg"

	// Phase 3A widened the parser-accepted family enum with the
	// V3 reserved values per specs/transport-families-v1.md, on
	// the assumption that each would later grow a handler. Two of
	// them cannot, for reasons that are properties of the
	// protocols and not of this codebase. They are recorded here
	// so the question is not re-opened every six months.

	// TransportPsiphon — STRUCTURALLY UNAVAILABLE to a
	// self-hosted publisher. Psiphon is a third party's
	// proprietary network operated by Psiphon Inc.; you can hand
	// a client OFF to it, you cannot HOST it. There is no server
	// side for a Daal publisher to run, so a "psiphon route" can
	// never be something this project mints — at most it is a
	// pointer to somebody else's infrastructure, carried under
	// their terms and their GPLv3 client. `core/go.mod` does not
	// require psiphon-tunnel-core and never has; the
	// `psiphon_compiled_in` diagnostic said `true` for that
	// non-existent tree until Wave 5 corrected it, and Wave 5
	// deleted the zero-reference `core/transports/psiphon`
	// skeleton that documented how the absent tree would be
	// wired.
	// What would have to become true: a vendored GPLv3 client
	// tree AND an accepted relationship with Psiphon Inc. Neither
	// is a transport-family decision.
	TransportPsiphon TransportFamily = "psiphon"

	// TransportConjure — STRUCTURALLY UNAVAILABLE to anyone
	// self-hosting, by design of the technique. Conjure is
	// refraction networking: it works because a COOPERATING ISP
	// runs a refraction station in the middle of the network,
	// tapping a transit link and answering for unused ("phantom")
	// addresses inside that ISP's own space. The station is the
	// product; the client half is worthless without it. A Daal
	// publisher renting a VPS has no transit link to tap and no
	// address space to phantom into, so there is nothing to
	// deploy. `core/go.mod` does not require gotapdance and never
	// has; `conjure_compiled_in` claimed an "Apache-2.0 vendored
	// tree ships unconditionally" that is not in the module graph.
	// What would have to become true: a partnership with a
	// network operator running a station. Not a code change.
	TransportConjure TransportFamily = "conjure"

	TransportTransportModule TransportFamily = "transport_module"
	TransportLifelineRelay   TransportFamily = "lifeline_relay"
	TransportOther           TransportFamily = "other"

	// Wave 5. anytls — the one family whose padding and native
	// session reuse are IN the protocol rather than bolted on
	// (option/anytls.go: PaddingScheme on the inbound;
	// MinIdleSession / IdleSessionTimeout on the outbound). The
	// shipped engine already registers the outbound
	// (include/registry.go:92), so the client half costs no new
	// dependency.
	//
	// THIS VALUE IS WIRE-BREAKING AND THE BREAK IS AT PACK
	// GRANULARITY, NOT ROUTE GRANULARITY. Every client shipped
	// before Wave 5 — Go and Rust alike — rejects the ENTIRE
	// bundle when any single route names a family it does not
	// know:
	//
	//	sbp.go      for _, route := range b.Manifest.Routes {
	//	                if err := validateRoute(...); err != nil { return err }
	//	            }
	//	sbp.go      validateRoute -> !validTransport(...) -> ErrInvalidEnum
	//	sbp.rs:180  !TRANSPORT_FAMILIES.contains(...) -> Error::InvalidEnum
	//	importer    classifyVerifyError(ErrInvalidEnum) -> "bundle_corrupted"
	//
	// So an old recipient handed a pack containing ONE anytls
	// route loses the other three working routes too, and is told
	// the pack is corrupt — a diagnosis that sends them looking
	// for a transfer error that did not happen.
	//
	// That is why anytls is gated on SpecVersionAnyTLS. A pack
	// carrying an anytls route MUST declare spec_version >= 5
	// (enforced in validateRoute); an old verifier then stops at
	// the spec gate, BEFORE the route loop, and says "unsupported
	// spec version" — which is true, actionable, and does not
	// accuse the sender of shipping a broken file. A pack with no
	// anytls route keeps its old spec_version and imports on old
	// clients completely unchanged.
	//
	// From spec_version 5 onward the blast radius is one route:
	// see the errUnknownFamily branch in verifyBundleCore. That
	// rule cannot be backported into binaries already in the
	// field, which is the whole cost of this value.
	TransportAnyTLS TransportFamily = "anytls"
)

// SpecVersionAnyTLS is the manifest spec_version at which two things
// become true at once, and they are deliberately coupled:
//
//  1. `anytls` is a legal transport_family.
//  2. An UNKNOWN transport_family stops being fatal to the pack. The
//     offending route is dropped from the usable set and every other
//     route imports normally (verifyBundleCore / UsableRoutes).
//
// Coupling them is the point. Rule 2 is what makes the NEXT family
// cheap; rule 1 is the family that had to pay full price to establish
// it. A spec_version-5 recipient can be handed a spec_version-6 pack
// naming families it has never heard of and will still come away with
// every route it does understand.
//
// Anything at or below spec_version 4 keeps the historical behaviour
// byte for byte — unknown family rejects the bundle with
// ErrInvalidEnum — so already-distributed packs and the cross-language
// fixture corpus are untouched.
const SpecVersionAnyTLS = 5

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

	// FRP-14: SHA-256 (hex, lowercase, 64 chars) of the
	// recipient's 32-byte X25519 public key. Binds the signed
	// pack to one recipient identity so a malicious publisher
	// cannot re-wrap recipient A's pack to recipient B. Empty /
	// omitted on V1.5 packs (no binding). When non-empty, the
	// recipient app's VerifyBundle cross-checks against the
	// local identity and rejects mismatches with
	// ErrRecipientMismatch. See specs/sbpx-envelope-v1.md §4
	// and specs/relaypack-v1.md (RP024).
	RecipientFPHex string `json:"recipient_fp_hex,omitempty"`
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

	// FRP-8: when present, the archive carried
	// `trust/freshness-mirrors.json` — the publisher-signed set of N
	// freshness endpoints across N DISTINCT providers. Raw bytes only:
	// this package neither parses nor verifies it, exactly as it
	// leaves the cell documents alone, because the one implementation
	// of that wire format lives on the recipient side
	// (core/refresh.VerifyMirrorDocument) and a second one here would
	// be a second thing to keep in step.
	//
	// It is a separate archive entry rather than a manifest field
	// because VerifyManifest canonicalises the PARSED struct: a
	// manifest field an already-distributed client does not know is
	// dropped before its canonicalisation, so its computed body
	// diverges and it rejects the ENTIRE pack. An unknown zip entry is
	// ignored. Nil for packs minted before FRP-8.
	FreshnessMirrorsJSON []byte
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
