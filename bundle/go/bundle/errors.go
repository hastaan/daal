package bundle

import "errors"

var (
	ErrMissingManifest     = errors.New("missing manifest.json")
	ErrMissingSignature    = errors.New("missing manifest.sig")
	ErrMissingPublisherKey = errors.New("missing publisher.pub")
	ErrInvalidSignature    = errors.New("invalid bundle signature")
	ErrInvalidPublisherKey = errors.New("invalid publisher public key")
	ErrUnsupportedSpec     = errors.New("unsupported spec version")
	ErrExpiredBundle       = errors.New("bundle expired")
	ErrExpiredRoute        = errors.New("route expired")
	ErrMissingProfile      = errors.New("missing route profile")
	ErrUnsafePath          = errors.New("unsafe archive path")
	ErrInvalidEnum         = errors.New("invalid enum value")
	ErrRevokedPublisher    = errors.New("publisher revoked")
	ErrRevokedRoute        = errors.New("route revoked")
	ErrFingerprintMismatch = errors.New("publisher fingerprint mismatch")

	// Phase 3A. See specs/sbp-v1.md "Validation Rules".
	ErrFamilySpecificConfigShape     = errors.New("family_specific_config must be a JSON object")
	ErrInvalidExperimentalMinVersion = errors.New("experimental_min_engine_version must be valid semver")
	ErrWebTunnelBulkCapable          = errors.New("webtunnel routes may not be scarcity_class bulk-capable")

	// Phase 3B. See specs/sbp-v1.md "Phase 3B widening" and
	// specs/rendezvous-channels-v1.md.
	ErrInvalidRendezvousChannel   = errors.New("rendezvous_priority entry not in v1 closed list")
	ErrRendezvousHintBadSignature = errors.New("rendezvous_hints entry signature verification failed")
	ErrRendezvousHintMalformed    = errors.New("rendezvous_hints entry malformed")

	// Phase 3C. See specs/sbp-v1.md "Phase 3C widening" and
	// specs/masque-ladder-v1.md.
	ErrMasqueEndpointOnNonMasqueRoute = errors.New("masque_endpoint may only appear on transport_family=masque routes")
	ErrMasqueEndpointMalformed        = errors.New("masque_endpoint must be a parseable https:// URL with non-empty path")

	// Phase 3D. See specs/sbp-v1.md "Phase 3D widening",
	// specs/psiphon-route-v1.md, and specs/conjure-route-v1.md.
	ErrPsiphonBlobOnNonPsiphonRoute   = errors.New("psiphon_bundle_blob_b64 may only appear on transport_family=psiphon routes")
	ErrPsiphonBlobMalformed           = errors.New("psiphon_bundle_blob_b64 must base64-decode to between 256 and 65536 bytes")
	ErrConjureFieldOnNonConjureRoute  = errors.New("conjure_* fields may only appear on transport_family=conjure routes")
	ErrConjurePhantomSubnetsMalformed = errors.New("conjure_phantom_subnets must be a non-empty list of CIDRs with prefix ≥ /24 (IPv4) / /32 (IPv6)")
	ErrConjureStationPubkeyMalformed  = errors.New("conjure_station_pubkey must be exactly 64 hex chars (32 bytes)")
	ErrConjureDecoyPoolMalformed      = errors.New("conjure_decoy_pool must contain RFC 1123 hostnames")

	// Phase 3E. See specs/sbp-v1.md "Phase 3E widening" and
	// specs/wasm-transport-v1.md. The 5 errors below are the
	// closed list; new failure modes require a roadmap-level
	// decision and a v3f errors.go widening.
	ErrTransportModuleSlugOnNonModuleRoute = errors.New("transport_module_slug may only appear on transport_family=transport_module routes")
	ErrTransportModuleSlugMalformed        = errors.New("transport_module_slug must match [a-z0-9_-]{3,32}")
	ErrTransportModulesEntryMalformed      = errors.New("transport_modules[] entry malformed: slug regex / sha256 hex / wasm_blob_b64 / size cap")
	ErrTransportModuleHashMismatch         = errors.New("transport_modules[] entry sha256 does not match decoded wasm_blob_b64")
	ErrTransportModuleOversize             = errors.New("transport_modules[] entry exceeds 4 MiB or bundle total exceeds 16 MiB")

	// Phase 3F. See specs/sbp-v1.md "Phase 3F widening" and
	// specs/delegate-keys-v1.md. The 6 errors below are the
	// locked-at-3F closed list. New failure modes require a
	// roadmap-level decision and a v3g errors.go widening.
	ErrRedistributionPolicyMalformed = errors.New("redistribution_policy must be one of {none, delegated_n, transitive}")
	ErrRedistributionCapMalformed    = errors.New("redistribution_cap must be a uint8 (0..255), present iff redistribution_policy=delegated_n")
	ErrRedistributionChainBroken     = errors.New("redistribution_chain[] signature walk failed")
	ErrRedistributionChainTooDeep    = errors.New("redistribution_chain[] depth > 5")
	ErrRedistributionCapExceeded     = errors.New("delegate_caps[] entry has shared_with_count_at_sign_time >= cap_at_sign_time")
	ErrRedistributionPolicyForbids   = errors.New("redistribution_policy refuses re-share for this route")

	// FRP-7.5. See specs/sbp-v1.md "Sub-key cert chain". The 5
	// errors below are the locked-at-7.5 closed list. New
	// failure modes require a roadmap-level decision.
	ErrSubkeyCertMalformed         = errors.New("trust/subkey-cert.json malformed (parse / kind / version / hex)")
	ErrSubkeyCertRootMismatch      = errors.New("trust/subkey-cert.json root_fingerprint_hex does not match publisher.pub")
	ErrSubkeyCertOutOfWindow       = errors.New("trust/subkey-cert.json outside its valid_from..valid_until window")
	ErrSubkeyCertBadSignature      = errors.New("trust/subkey-cert.json signature does not verify under publisher.pub")
	ErrSubkeyCertSpecVersionTooOld = errors.New("trust/subkey-cert.json requires spec_version >= 4")

	// FRP-11. See specs/cell-v1.md. The 9 errors below are the
	// locked-at-FRP-11 closed list for cell-doc parse +
	// canonicalisation + admin-quorum signature verification.
	// These are produced by `bundle.ParseCellDocs` and
	// `bundle.VerifyCellMembershipQuorum` /
	// `bundle.VerifyCellDelegationQuorum` only; the recipient-
	// side chain walk in `core/trust/cell_verify.go` produces
	// its own widening (chain-walk failure modes are core-side
	// because the bundle module deliberately cannot reach
	// publisher fingerprints — `core → bundle` invariant).
	ErrCellMembershipMalformed      = errors.New("trust/cell-membership.json malformed (parse / cell_id / quorum / hex)")
	ErrCellDelegationMalformed      = errors.New("trust/cell-delegation.json malformed (parse / cell_id / window)")
	ErrCellAdminPubkeyMalformed     = errors.New("admin_pubkeys[] entry must base64-rawstd-decode to 32 bytes")
	ErrCellQuorumOutOfRange         = errors.New("quorum_m must satisfy 1 <= M <= N <= 25")
	ErrCellAdminSignatureMalformed  = errors.New("admin_signatures[] entry malformed (idx range / base64)")
	ErrCellAdminQuorumNotMet        = errors.New("fewer than M valid admin signatures cover the canonical doc")
	ErrCellAdminQuorumDuplicateIdx  = errors.New("admin_signatures[] contains duplicate admin_pubkey_idx")
	ErrCellDelegationCellIDMismatch = errors.New("cell-delegation.json cell_id does not match cell-membership.json")
	ErrCellDelegationOutOfWindow    = errors.New("cell-delegation.json outside its valid_from..valid_until window")

	// FRP-14. See specs/sbpx-envelope-v1.md §4 and
	// specs/relaypack-v1.md RP024. Returned by VerifyBundleFor
	// when the manifest's bundle.recipient_fp_hex is non-empty
	// and does not match the local recipient identity supplied
	// to VerifyBundleFor. The base VerifyBundle skips this
	// check (no local identity available).
	ErrRecipientMismatch = errors.New("relay pack is bound to a different recipient identity")

	// FRP-14. Returned by VerifyBundleFor when the supplied
	// local identity is malformed (must be exactly 32 bytes).
	ErrRecipientIdentityMalformed = errors.New("local recipient identity must be 32 bytes")
)
