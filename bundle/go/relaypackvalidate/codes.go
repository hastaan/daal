// Package relaypackvalidate implements the FRP-1 RelayPack profile
// validator. Moved here at FRP-2 (rename from package relaypack) so the
// on-device importer (`bundle/go/importer`) can call it without
// violating the FRP-1 asymmetric-guard invariant: bundle/ and core/
// MUST NOT import the publisher module. Both publisher and importer
// call the same validator via this neutral bundle-side package.
//
// The validator parses the per-candidate _relaypack sub-object out of
// each route's FamilySpecificConfig blob and the bundle-level
// Manifest.RelayPack slot, then enforces the structural and policy
// rules locked at FRP-1 (RP001..RP018/RP021 errors + RP019/RP020 warnings)
// against a phase-aware ValidateOpts.Phase value.
//
// Phase enum: V15 (direct_vps only; V1.5 ship), V16 (lifts cdn_fronted;
// FRP-8 ship), PostV2 (lifts serverless_external + per-modifier framework;
// FRP-12 ship). The same validator binary is used across all three phases —
// phase progression flips constants, not validator code.
//
// See specs/relaypack-v1.md for the locked rule list and lint codebook.
// See phases of development/29-phase-frp-1-relaypack-schema.md §3 for
// the 27 invariants this package must preserve.
package relaypackvalidate

import "daal/bundle-go/phase"

// Code is a typed error / warning identifier from the locked
// FRP-1 codebook. Errors are prefixed RP001..RP018/RP021 and
// cause Validate to return a non-nil error; warnings RP019/RP020
// are surfaced in the LintReport and never block import.
type Code string

const (
	// Errors (Validate returns non-nil error).

	// CodeRP001: a candidate carries a _relaypack sub-object but
	// the bundle's Manifest.RelayPack slot is nil.
	CodeRP001 Code = "RP001"

	// CodeRP002: exposure_mode is not one of
	// direct_vps | cdn_fronted | serverless_external.
	CodeRP002 Code = "RP002"

	// CodeRP003: exposure_mode=serverless_external rejected at
	// V15 / V16 (reserved schema slot; supplement §11.6).
	CodeRP003 Code = "RP003"

	// CodeRP004: exposure_mode=cdn_fronted rejected at V15.
	// FRP-8 lifts at V16.
	CodeRP004 Code = "RP004"

	// CodeRP005: cdn_fronted candidate must carry >=1 cdn:* tag
	// in public_risk_tags.
	CodeRP005 Code = "RP005"

	// CodeRP006: cdn_fronted candidate must carry >=1 origin_*
	// tag in origin_risk_tags.
	CodeRP006 Code = "RP006"

	// CodeRP007: cdn_fronted family must appear `yes` or
	// `conditional` in supplement §11.1.1.
	CodeRP007 Code = "RP007"

	// CodeRP008: direct_vps candidate must carry >=1 public_ip:* tag.
	CodeRP008 Code = "RP008"

	// CodeRP009: direct_vps candidate must NOT carry any cdn:* tag
	// (CDN-mode-only).
	CodeRP009 Code = "RP009"

	// CodeRP010: direct_vps candidate must NOT carry any origin_*
	// tag (in direct mode the origin IS the public surface).
	CodeRP010 Code = "RP010"

	// CodeRP011: family_class must be one of
	// vps-native | vps-possible | external-ecosystem.
	CodeRP011 Code = "RP011"

	// CodeRP012: probing_risk_class must be one of
	// low | moderate | high.
	CodeRP012 Code = "RP012"

	// CodeRP013: non-empty modifiers[] rejected at V15 / V16.
	// FRP-12 lifts per-kind (post-V2).
	CodeRP013 Code = "RP013"

	// CodeRP014: bundle must contain >=2 vps-native candidates.
	// One-candidate RelayPacks defeat the purpose.
	CodeRP014 Code = "RP014"

	// CodeRP015: family_class=external-ecosystem rejected for
	// any FRP-self-hosted candidate (these must come from
	// partner-supplied bundles).
	CodeRP015 Code = "RP015"

	// CodeRP016: cell_scope.policy=transitive rejected at V15
	// (cells require V2 / FRP-11).
	CodeRP016 Code = "RP016"

	// CodeRP017: legacy flat shared_risk_tags array on
	// RouteManifestEntry rejected with explicit pointer to
	// v2.3.5 schema.
	CodeRP017 Code = "RP017"

	// CodeRP018: relay_pack.shared_risk_graph.members must
	// reference candidate IDs that exist in the bundle.
	CodeRP018 Code = "RP018"

	// CodeRP021: Manifest.relay_pack.freshness_url is populated
	// before V1.6 / FRP-8. The slot is reserved at FRP-1, but live
	// freshness endpoints are not accepted at V1.5.
	CodeRP021 Code = "RP021"

	// CodeRP022: cdn_fronted candidate's _cdn_attestation
	// sub-object is missing, malformed, or fails the §11.7
	// hardening assertions: origin_ca_fingerprint must be
	// non-empty hex, aop_enabled must be true, firewall_id
	// must be non-empty. The attestation is produced by the
	// wizard / publisher/deploy/cloudflare provider; the
	// validator never calls Cloudflare. RP022 fires at V16+.
	CodeRP022 Code = "RP022"

	// CodeRP023: cdn_fronted candidate's CDN attestation
	// reports dns_only_present=true (DNS-only A/AAAA record on
	// the chosen subdomain). §11.7 hard rule: refused at
	// deploy time AND at validator time (defence in depth).
	CodeRP023 Code = "RP023"

	// CodeRP024 (warning): a cdn_fronted candidate ships
	// without any direct_vps sibling in the bundle. Per phase
	// doc §13: cdn_fronted is the second leg of a defence
	// bundle, not a replacement for direct_vps. Surface as
	// a warning so the FRP gets a clear nudge but the bundle
	// is still importable.
	CodeRP024 Code = "RP024"

	// RP025 is RESERVED for the FRP-14 recipient-binding
	// mismatch (bundle.ErrRecipientMismatch, raised by
	// bundle-go's VerifyBundleFor, not by this validator).
	// specs/relaypack-v1.md briefly double-assigned RP024 to
	// that error; renumbered 2026-08-14. Do not reuse RP025.

	// Warnings (surfaced in LintReport; never block import).

	// CodeRP019: all candidates share every public_risk_tag
	// (no diversity at all). UI nudge: add CDN, second VPS, or
	// different provider.
	CodeRP019 Code = "RP019"

	// CodeRP020: bundle has no udp_gated:true candidates AND no
	// UDP-shaped candidates of any kind. Recipient on a UDP-only
	// network will have no path.
	CodeRP020 Code = "RP020"
)

// Phase is the validator phase enum. The same validator binary is
// used across V1.5 / V1.6 / PostV2; phase progression flips
// constants, not validator code.
//
// This is an ALIAS, not a definition. The enum itself lives in
// daal/bundle-go/phase, which is also aliased by
// core/internal/selection and publisher/deploy/modifiers — so all
// four packages are the same type and the compiler, not a string
// comparison, is what keeps them in agreement. See that package's
// doc comment for the history this prevents repeating.
type Phase = phase.Phase

const (
	// PhaseV15: direct_vps only. cdn_fronted and serverless_external
	// rejected. Non-empty modifiers[] rejected.
	PhaseV15 = phase.V15

	// PhaseV16: direct_vps + cdn_fronted. serverless_external
	// rejected. Non-empty modifiers[] rejected. FRP-8 lifts.
	PhaseV16 = phase.V16

	// PhasePostV2: direct_vps + cdn_fronted + serverless_external.
	// Non-empty modifiers[] allowed iff each kind appears in
	// ValidateOpts.AllowedModifierKinds. FRP-12 populates.
	PhasePostV2 = phase.PostV2

	// CurrentPhase is what this build ships. Every producer and every
	// consumer reads it; nothing else may write a phase literal.
	CurrentPhase = phase.Current
)
