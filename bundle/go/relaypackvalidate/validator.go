package relaypackvalidate

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"daal/bundle-go/bundle"
)

// ValidateOpts configures Validate. Phase is required; the other
// fields are optional and have safe zero-value defaults.
type ValidateOpts struct {
	// Phase selects which schema gates apply at this call.
	// V15: V1.5 ship; cdn_fronted and serverless_external rejected.
	// V16: V1.6 ship; cdn_fronted lifted (FRP-8). serverless_external rejected.
	// PostV2: serverless_external + non-empty modifiers[] allowed iff
	//          each modifier kind appears in AllowedModifierKinds.
	Phase Phase

	// AllowedModifierKinds is the per-kind allow-list populated at
	// FRP-12. Empty at V1.5 / V1.6. A non-empty modifiers[] array on
	// any candidate is rejected at V15 / V16 by RP013 regardless of
	// this field.
	AllowedModifierKinds map[string]bool

	// FamilyMatrix is the §11.1.1 cdn_fronted compatibility matrix.
	// Optional; if nil, RP007 falls back to the package-default
	// matrix in defaultFamilyMatrix(). Populated by FRP-8 to lock
	// the table at V1.6 ship.
	FamilyMatrix FamilyExposureMatrix

	// FRPSelfHosted is the set of candidate IDs the FRP is
	// self-hosting. RP015 rejects family_class=external-ecosystem
	// for any candidate in this set. Empty by default (no
	// self-hosting attribution; RP015 inert).
	FRPSelfHosted map[string]bool
}

// FamilyExposureMatrix encodes the §11.1.1 cdn_fronted column.
// `yes` and `conditional` rows allow cdn_fronted; `no` rejects.
type FamilyExposureMatrix map[string]ExposureSupport

// ExposureSupport is the per-family-per-mode support state.
type ExposureSupport string

const (
	ExposureYes         ExposureSupport = "yes"
	ExposureConditional ExposureSupport = "conditional"
	ExposureNo          ExposureSupport = "no"
)

// LintReport is the non-blocking warning surface. Warnings RP019 /
// RP020 surface here; errors RP001..RP018/RP021 return as the second
// Validate result.
type LintReport struct {
	Warnings []LintWarning
}

// LintWarning is one non-blocking finding.
type LintWarning struct {
	Code    Code
	Message string
	Pointer string // candidate ID or "manifest"
}

// ValidationError is the typed error returned by Validate. Errors
// can be unwrapped to inspect Code and Pointer.
type ValidationError struct {
	Code    Code
	Message string
	Pointer string
}

// Error implements error.
func (e *ValidationError) Error() string {
	if e.Pointer != "" {
		return fmt.Sprintf("relaypack %s at %s: %s", e.Code, e.Pointer, e.Message)
	}
	return fmt.Sprintf("relaypack %s: %s", e.Code, e.Message)
}

// Validate enforces the FRP-1 RelayPack schema rules against the
// supplied bundle. Returns a LintReport of warnings (always; may be
// empty) and an error iff any RP001..RP018/RP021 rule fires. Lint
// warnings never block import.
//
// The validator is import-time only — the selector at FRP-3 reads
// _relaypack at selection time without re-validating. The validator
// is also stateless: given the same (bundle, opts) it always returns
// the same (LintReport, error).
func Validate(b *bundle.Bundle, opts ValidateOpts) (LintReport, error) {
	if b == nil {
		return LintReport{}, &ValidationError{
			Code:    "RP000",
			Message: "nil bundle",
		}
	}
	if opts.Phase == "" {
		return LintReport{}, &ValidationError{
			Code:    "RP000",
			Message: "ValidateOpts.Phase is required",
		}
	}
	// Fail closed on any phase this validator has no rule-set for.
	//
	// Every phase gate below is written as "reject at V15 (and V16)",
	// so an unrecognised value — a typo, or the selector's reserved
	// `V2` — would match none of them and land on the MOST PERMISSIVE
	// branch: cdn_fronted, serverless_external, modifiers[] and
	// cell_scope would all sail through unchecked. That is precisely
	// backwards. Reject instead.
	switch opts.Phase {
	case PhaseV15, PhaseV16, PhasePostV2:
	default:
		return LintReport{}, &ValidationError{
			Code: "RP000",
			Message: fmt.Sprintf("unsupported ValidateOpts.Phase %q (want %s | %s | %s)",
				opts.Phase, PhaseV15, PhaseV16, PhasePostV2),
		}
	}
	matrix := opts.FamilyMatrix
	if matrix == nil {
		matrix = defaultFamilyMatrix()
	}

	// Per-candidate parse: build a parallel slice of *RelayPackEntry,
	// nil for non-RelayPack candidates. RP017 fires here too because
	// the legacy flat shared_risk_tags array (pre-v2.3.4) sits as a
	// peer key inside FamilySpecificConfig.
	entries := make([]*bundle.RelayPackEntry, len(b.Manifest.Routes))
	hasAnyRelayPack := false
	for i, r := range b.Manifest.Routes {
		// RP017: legacy flat shared_risk_tags -> hard reject.
		if hasLegacyFlatSharedRiskTags(r.FamilySpecificConfig) {
			return LintReport{}, &ValidationError{
				Code:    CodeRP017,
				Pointer: r.ID,
				Message: "legacy flat `shared_risk_tags` array on RouteManifestEntry rejected; migrate to v2.3.5 mode-aware schema (see specs/relaypack-v1.md)",
			}
		}
		entry, err := bundle.ParseRelayPackEntry(r.FamilySpecificConfig)
		if errors.Is(err, bundle.ErrNoRelayPack) {
			continue
		}
		if err != nil {
			return LintReport{}, &ValidationError{
				Code:    CodeRP002,
				Pointer: r.ID,
				Message: fmt.Sprintf("malformed _relaypack sub-object: %v", err),
			}
		}
		entries[i] = entry
		hasAnyRelayPack = true
	}

	// RP001: any candidate carrying _relaypack requires
	// Manifest.RelayPack to be non-nil.
	if hasAnyRelayPack && b.Manifest.RelayPack == nil {
		return LintReport{}, &ValidationError{
			Code:    CodeRP001,
			Pointer: "manifest",
			Message: "candidate carries _relaypack but Manifest.relay_pack is nil",
		}
	}

	// If no candidate carries _relaypack and there is no
	// Manifest.RelayPack, the bundle is non-RelayPack and the
	// validator has nothing to enforce.
	if !hasAnyRelayPack && b.Manifest.RelayPack == nil {
		return LintReport{}, nil
	}

	// RP021: freshness_url is a reserved FRP-1 / V1.5 schema slot.
	// FRP-8 lifts this at V1.6 when the signed freshness endpoint
	// and key-binding flow exist.
	//
	// "Lifts" is not "stops checking". The blanket V1.5 rejection was
	// the ONLY thing standing between an attacker-controlled bundle
	// and a string the importer denormalises onto every RouteInput
	// (importer.go) and the routestore writes to every route row —
	// a URL this device will later poll on a cadence. Moving the
	// phase to V1.6 without replacing the gate would accept
	// `http://beacon.example/?id=…` or `https://10.0.0.1/…` as
	// freely as the FRP-controlled endpoint the spec describes. So
	// at V1.6+ the blanket rejection becomes a SHAPE check, under
	// the same RP021 code so the importer's existing
	// `relaypack_RP021` reason plumbing still renders.
	if b.Manifest.RelayPack != nil && b.Manifest.RelayPack.FreshnessURL != "" {
		if opts.Phase == PhaseV15 {
			return LintReport{}, &ValidationError{
				Code:    CodeRP021,
				Pointer: "manifest.relay_pack.freshness_url",
				Message: "freshness_url is reserved at V1.5 and accepted only at V1.6 / FRP-8",
			}
		}
		if err := validateFreshnessURL(b.Manifest.RelayPack.FreshnessURL); err != nil {
			return LintReport{}, err
		}
	}

	// Per-candidate schema validation.
	vpsNativeCount := 0
	hasCDNFronted := false
	hasDirectVPS := false
	for i, r := range b.Manifest.Routes {
		entry := entries[i]
		if entry == nil {
			continue
		}
		if err := validateEntry(r.ID, entry, opts, matrix); err != nil {
			return LintReport{}, err
		}
		// RP007: cdn_fronted family must be `yes` or `conditional`
		// in §11.1.1's cdn_fronted column. The matrix is consulted
		// here because the family lives on RouteManifestEntry, not
		// inside the _relaypack sub-object.
		if entry.ExposureMode == "cdn_fronted" {
			hasCDNFronted = true
			support, known := matrix[r.TransportFamily]
			if !known || support == ExposureNo {
				return LintReport{}, &ValidationError{
					Code:    CodeRP007,
					Pointer: r.ID,
					Message: fmt.Sprintf("transport_family %q does not support exposure_mode=cdn_fronted (per supplement §11.1.1)", r.TransportFamily),
				}
			}
			// FRP-8 RP022 / RP023: enforce §11.7 hardening
			// attestation. The validator never calls
			// Cloudflare; it reads the signed attestation
			// produced by the wizard / publisher provider.
			// Only fires at V16+ (V15 rejects cdn_fronted via
			// RP004 and never reaches this block).
			if opts.Phase != PhaseV15 {
				if err := validateCDNAttestation(r.ID, r.FamilySpecificConfig); err != nil {
					return LintReport{}, err
				}
			}
		}
		if entry.ExposureMode == "direct_vps" {
			hasDirectVPS = true
		}
		if entry.FamilyClass == "vps-native" {
			vpsNativeCount++
		}
	}

	// RP014: bundle must contain >=2 vps-native candidates.
	if vpsNativeCount < 2 {
		return LintReport{}, &ValidationError{
			Code:    CodeRP014,
			Pointer: "manifest",
			Message: fmt.Sprintf("bundle must contain >=2 `vps-native` candidates; got %d", vpsNativeCount),
		}
	}

	// RP018: shared_risk_graph members must reference candidate IDs
	// that exist in the bundle.
	if b.Manifest.RelayPack != nil {
		ids := make(map[string]bool, len(b.Manifest.Routes))
		for _, r := range b.Manifest.Routes {
			ids[r.ID] = true
		}
		for _, edge := range b.Manifest.RelayPack.SharedRiskGraph {
			for _, m := range edge.Members {
				if !ids[m] {
					return LintReport{}, &ValidationError{
						Code:    CodeRP018,
						Pointer: edge.Tag,
						Message: fmt.Sprintf("shared_risk_graph references unknown candidate id %q", m),
					}
				}
			}
		}
	}

	// Lint warnings (RP019 / RP020 / RP024) are non-blocking.
	var report LintReport
	if rp019 := lintRP019(b, entries); rp019 != nil {
		report.Warnings = append(report.Warnings, *rp019)
	}
	if rp020 := lintRP020(b); rp020 != nil {
		report.Warnings = append(report.Warnings, *rp020)
	}
	if rp024 := lintRP024(hasCDNFronted, hasDirectVPS); rp024 != nil {
		report.Warnings = append(report.Warnings, *rp024)
	}
	return report, nil
}

// maxFreshnessURLLen bounds the freshness_url. The bundle is
// attacker-controlled bytes and this string is persisted onto every
// route row; 2048 is the conventional practical URL ceiling and is
// three orders of magnitude more than any real endpoint needs.
const maxFreshnessURLLen = 2048

// validateFreshnessURL is the V1.6+ half of RP021. specs/relaypack-v1.md
// §"Manifest.relay_pack.freshness_url" specifies "a non-empty
// FRP-controlled `https://` URL"; before this, nothing anywhere
// enforced the `https://` half — core/bootstrap/fetcher.go checks the
// scheme at FETCH time, which is far too late to keep the value out of
// the routestore and which turns a bad pack into a permanently broken
// refresh rather than a rejected import.
//
// The rules are deliberately syntactic. The validator cannot know
// which host an FRP controls, so it enforces only what is decidable
// from the string: a parseable absolute https URL, a real hostname,
// no embedded credentials, and not an address that points back at the
// recipient's own machine or LAN.
func validateFreshnessURL(raw string) error {
	fail := func(msg string) error {
		return &ValidationError{
			Code:    CodeRP021,
			Pointer: "manifest.relay_pack.freshness_url",
			Message: msg,
		}
	}
	if len(raw) > maxFreshnessURLLen {
		return fail(fmt.Sprintf("freshness_url exceeds %d bytes", maxFreshnessURLLen))
	}
	if strings.TrimSpace(raw) != raw {
		return fail("freshness_url must not carry leading/trailing whitespace")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fail("freshness_url is not a parseable URL")
	}
	if u.Scheme != "https" {
		return fail(fmt.Sprintf("freshness_url scheme must be https (got %q)", u.Scheme))
	}
	if u.User != nil {
		return fail("freshness_url must not carry embedded credentials")
	}
	host := u.Hostname()
	if host == "" {
		return fail("freshness_url must carry a host")
	}
	// A literal IP defeats the only authentication an https endpoint
	// has (the certificate's name), and the loopback / private /
	// link-local ranges make the recipient poll itself or its own LAN.
	if ip := net.ParseIP(host); ip != nil {
		return fail("freshness_url host must be a domain name, not an IP literal")
	}
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return fail("freshness_url host must not be loopback")
	}
	if !strings.Contains(host, ".") {
		return fail("freshness_url host must be a fully-qualified domain name")
	}
	return nil
}

// validateCDNAttestation enforces RP022 (presence + structural
// soundness of the §11.7 attestation) and RP023 (DNS-only-record
// posture failure). The validator NEVER calls Cloudflare; it
// reads the signed attestation produced by the wizard /
// publisher/deploy/cloudflare provider out of the candidate's
// FamilySpecificConfig blob under the reserved key
// _cdn_attestation.
func validateCDNAttestation(id string, fsc json.RawMessage) error {
	att, err := bundle.ParseCDNAttestation(fsc)
	if err != nil {
		return &ValidationError{
			Code:    CodeRP022,
			Pointer: id,
			Message: fmt.Sprintf("cdn_fronted candidate is missing or has malformed _cdn_attestation: %v", err),
		}
	}
	if att.OriginCAFingerprint == "" {
		return &ValidationError{
			Code:    CodeRP022,
			Pointer: id,
			Message: "cdn_fronted attestation: origin_ca_fingerprint must be non-empty hex (§11.7)",
		}
	}
	if !att.AOPEnabled {
		return &ValidationError{
			Code:    CodeRP022,
			Pointer: id,
			Message: "cdn_fronted attestation: aop_enabled must be true (§11.7)",
		}
	}
	if att.FirewallID == "" {
		return &ValidationError{
			Code:    CodeRP022,
			Pointer: id,
			Message: "cdn_fronted attestation: firewall_id must be non-empty (§11.7)",
		}
	}
	if att.DNSOnlyPresent {
		return &ValidationError{
			Code:    CodeRP023,
			Pointer: id,
			Message: "cdn_fronted attestation: dns_only_present=true — DNS-only A/AAAA record on the chosen subdomain (§11.7)",
		}
	}
	return nil
}

// lintRP024 surfaces a non-blocking warning when a bundle has
// at least one cdn_fronted candidate but no direct_vps sibling.
// Per phase doc §13: cdn_fronted is the second leg of a defence
// bundle, not a replacement for direct_vps.
func lintRP024(hasCDNFronted, hasDirectVPS bool) *LintWarning {
	if !hasCDNFronted || hasDirectVPS {
		return nil
	}
	return &LintWarning{
		Code:    CodeRP024,
		Pointer: "manifest",
		Message: "cdn_fronted candidate present but no direct_vps sibling; consider adding a direct_vps candidate so the recipient has a non-CDN fallback (per phase doc §13)",
	}
}

// validateEntry enforces the per-candidate rules RP002..RP013, RP015,
// RP016. Returns nil if the candidate passes.
func validateEntry(id string, e *bundle.RelayPackEntry, opts ValidateOpts, matrix FamilyExposureMatrix) error {
	// RP002: exposure_mode enum.
	switch e.ExposureMode {
	case "direct_vps", "cdn_fronted", "serverless_external":
	default:
		return &ValidationError{
			Code:    CodeRP002,
			Pointer: id,
			Message: fmt.Sprintf("unknown exposure_mode %q (allowed: direct_vps | cdn_fronted | serverless_external)", e.ExposureMode),
		}
	}

	// RP003: serverless_external rejected at V15 / V16.
	if e.ExposureMode == "serverless_external" && (opts.Phase == PhaseV15 || opts.Phase == PhaseV16) {
		return &ValidationError{
			Code:    CodeRP003,
			Pointer: id,
			Message: "exposure_mode=serverless_external is reserved (post-V2)",
		}
	}

	// RP004: cdn_fronted rejected at V15.
	if e.ExposureMode == "cdn_fronted" && opts.Phase == PhaseV15 {
		return &ValidationError{
			Code:    CodeRP004,
			Pointer: id,
			Message: "exposure_mode=cdn_fronted is reserved at V1.5 (lifts at V1.6 / FRP-8)",
		}
	}

	// RP011: family_class enum.
	switch e.FamilyClass {
	case "vps-native", "vps-possible", "external-ecosystem":
	default:
		return &ValidationError{
			Code:    CodeRP011,
			Pointer: id,
			Message: fmt.Sprintf("unknown family_class %q (allowed: vps-native | vps-possible | external-ecosystem)", e.FamilyClass),
		}
	}

	// RP015: family_class=external-ecosystem rejected for FRP-self-hosted.
	if e.FamilyClass == "external-ecosystem" && opts.FRPSelfHosted[id] {
		return &ValidationError{
			Code:    CodeRP015,
			Pointer: id,
			Message: "family_class=external-ecosystem rejected for FRP-self-hosted candidate",
		}
	}

	// RP012: probing_risk_class enum.
	switch e.ProbingRiskClass {
	case "low", "moderate", "high":
	default:
		return &ValidationError{
			Code:    CodeRP012,
			Pointer: id,
			Message: fmt.Sprintf("unknown probing_risk_class %q (allowed: low | moderate | high)", e.ProbingRiskClass),
		}
	}

	// RP013: non-empty modifiers[] rejected at V15 / V16.
	if len(e.Modifiers) > 0 && (opts.Phase == PhaseV15 || opts.Phase == PhaseV16) {
		return &ValidationError{
			Code:    CodeRP013,
			Pointer: id,
			Message: "non-empty modifiers[] reserved at V1.5 / V1.6 (FRP-12 lifts per-kind)",
		}
	}
	// At PostV2: per-kind allow-list.
	if len(e.Modifiers) > 0 && opts.Phase == PhasePostV2 {
		for _, m := range e.Modifiers {
			if !opts.AllowedModifierKinds[m.Kind] {
				return &ValidationError{
					Code:    CodeRP013,
					Pointer: id,
					Message: fmt.Sprintf("modifier kind %q not in AllowedModifierKinds at PostV2", m.Kind),
				}
			}
		}
	}

	// RP016: cell_scope rejected below V2.
	// CellScope is a struct, not a map; we check the nullable-ness
	// rule per supplement §12.2.5: cell_id and cell_join_fp are
	// nullable for plain family-only RelayPacks — but if a cell_scope
	// is present we reject any non-empty cell_id, because cells
	// require V2 / FRP-11. The "transitive" policy per phase-doc text
	// is not a separate field on CellScope yet; FRP-11 introduces the
	// policy field. Below V2 we hard-reject any non-zero CellScope to
	// be safe.
	//
	// THE PHASE LIST MATTERS. This used to read `== PhaseV15`, from
	// the era when V1.5 was the only phase the device validated at.
	// Moving the importer to V1.6 would then have switched the rule
	// off silently — and nothing would have replaced it: RP016 is the
	// only cell_scope check in the repo, and core/trust's
	// VerifyCellChain (the FRP-11 chain walker that would actually
	// validate a cell claim) has no production caller. The claim would
	// be neither rejected nor verified. Written as an explicit
	// pre-V2 list, exactly like RP003 and RP013 above.
	if (opts.Phase == PhaseV15 || opts.Phase == PhaseV16) && e.CellScope != nil {
		cs := *e.CellScope
		if cs.CellID != "" || cs.CellJoinFP != "" || cs.CellMaxDepth != 0 {
			return &ValidationError{
				Code:    CodeRP016,
				Pointer: id,
				Message: "non-empty cell_scope rejected at V1.5 / V1.6 (cells require V2 / FRP-11; cell_scope.policy=transitive is rejected here)",
			}
		}
	}

	// Mode-specific tag rules.
	switch e.ExposureMode {
	case "direct_vps":
		// RP008: must carry >=1 public_ip:* tag.
		if !hasTagPrefix(e.PublicRiskTags, "public_ip:") {
			return &ValidationError{
				Code:    CodeRP008,
				Pointer: id,
				Message: "direct_vps candidate must carry >=1 `public_ip:*` tag in public_risk_tags",
			}
		}
		// RP009: must NOT carry any cdn:* tag.
		if hasTagPrefix(e.PublicRiskTags, "cdn:") {
			return &ValidationError{
				Code:    CodeRP009,
				Pointer: id,
				Message: "direct_vps candidate must NOT carry `cdn:*` tags (CDN-mode-only)",
			}
		}
		// RP010: must NOT carry any origin_* tag (in either array).
		if hasTagPrefix(e.PublicRiskTags, "origin_") || hasTagPrefix(e.OriginRiskTags, "origin_") {
			return &ValidationError{
				Code:    CodeRP010,
				Pointer: id,
				Message: "direct_vps candidate must NOT carry `origin_*` tags (origin IS the public surface in direct mode)",
			}
		}

	case "cdn_fronted":
		// RP005: must carry >=1 cdn:* tag in public_risk_tags.
		if !hasTagPrefix(e.PublicRiskTags, "cdn:") {
			return &ValidationError{
				Code:    CodeRP005,
				Pointer: id,
				Message: "cdn_fronted candidate must carry >=1 `cdn:*` tag in public_risk_tags",
			}
		}
		// RP006: must carry >=1 origin_* tag in origin_risk_tags.
		if !hasTagPrefix(e.OriginRiskTags, "origin_") {
			return &ValidationError{
				Code:    CodeRP006,
				Pointer: id,
				Message: "cdn_fronted candidate must carry >=1 `origin_*` tag in origin_risk_tags",
			}
		}
	}

	// RP007: cdn_fronted family compatibility per §11.1.1.
	// Lookup uses RouteManifestEntry.TransportFamily so we re-resolve
	// it from the parent route. The validator has the route ID; it
	// would need the family. We pass a closure-friendly form via the
	// outer Validate call where the route is in scope.
	// (Implemented in the outer loop below by passing TransportFamily;
	// we add a separate check there.)

	return nil
}

// hasTagPrefix returns true iff any element of tags starts with the
// given prefix.
func hasTagPrefix(tags []string, prefix string) bool {
	for _, t := range tags {
		if strings.HasPrefix(t, prefix) {
			return true
		}
	}
	return false
}

// hasLegacyFlatSharedRiskTags inspects a FamilySpecificConfig blob
// for the pre-v2.3.4 flat `shared_risk_tags` array. Triggers RP017.
func hasLegacyFlatSharedRiskTags(blob json.RawMessage) bool {
	if len(blob) == 0 {
		return false
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(blob, &probe); err != nil {
		return false
	}
	_, ok := probe["shared_risk_tags"]
	return ok
}

// lintRP019: all candidates share every public_risk_tag.
func lintRP019(b *bundle.Bundle, entries []*bundle.RelayPackEntry) *LintWarning {
	first := -1
	for i, e := range entries {
		if e != nil {
			first = i
			break
		}
	}
	if first < 0 {
		return nil
	}
	firstSet := tagSet(entries[first].PublicRiskTags)
	if len(firstSet) == 0 {
		return nil
	}
	allSame := true
	count := 0
	for _, e := range entries {
		if e == nil {
			continue
		}
		count++
		if !setsEqual(firstSet, tagSet(e.PublicRiskTags)) {
			allSame = false
			break
		}
	}
	if !allSame || count < 2 {
		return nil
	}
	return &LintWarning{
		Code:    CodeRP019,
		Pointer: "manifest",
		Message: "all RelayPack candidates share every public_risk_tag (no diversity at all); consider adding a CDN front, a second VPS, or a different provider",
	}
}

// lintRP020: bundle has no UDP-shaped candidates and no udp_gated:true.
func lintRP020(b *bundle.Bundle) *LintWarning {
	hasUDPGated := false
	hasUDPFamily := false
	for _, r := range b.Manifest.Routes {
		if r.UDPGated {
			hasUDPGated = true
		}
		switch r.TransportFamily {
		case "hysteria2", "tuic", "wireguard", "amneziawg", "masque":
			hasUDPFamily = true
		}
	}
	if hasUDPGated || hasUDPFamily {
		return nil
	}
	return &LintWarning{
		Code:    CodeRP020,
		Pointer: "manifest",
		Message: "bundle has no UDP-shaped candidates and no `udp_gated:true` candidates; recipients on UDP-only paths will have no candidate",
	}
}

func tagSet(tags []string) map[string]bool {
	m := make(map[string]bool, len(tags))
	for _, t := range tags {
		m[t] = true
	}
	return m
}

func setsEqual(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// defaultFamilyMatrix returns the §11.1.1 cdn_fronted compatibility
// row used by RP007 when ValidateOpts.FamilyMatrix is nil. FRP-1
// seeds with the V1.5 / V1.6 row; FRP-8 may extend.
//
// Per supplement §11.1.1:
//   - vless-reality, naive, websocket-tls: yes (TCP-shaped, CDN-able)
//   - hysteria2, tuic: no (UDP-only; CDNs do not transparently proxy UDP)
//   - anytls: yes (TLS-over-TCP, same shape as the three above).
//     Added in the Wave-5 repair pass: without a row, RP007's
//     `support, known := matrix[...]` lookup fails the KNOWN check and
//     a cdn_fronted anytls candidate is refused as "does not support
//     exposure_mode=cdn_fronted" — the wrong reason for a missing row,
//     and a diagnosis the next wave would have had to work backwards
//     from. Inert at V1.5/V1.6, which are direct_vps only.
//   - snowflake, webtunnel, masque, shadowsocks, tor-bridge,
//     wireguard, amneziawg, psiphon, conjure, transport_module,
//     lifeline_relay, other: conditional (case-by-case)
func defaultFamilyMatrix() FamilyExposureMatrix {
	return FamilyExposureMatrix{
		"vless-reality":    ExposureYes,
		"naive":            ExposureYes,
		"websocket-tls":    ExposureYes,
		"anytls":           ExposureYes,
		"hysteria2":        ExposureNo,
		"tuic":             ExposureNo,
		"snowflake":        ExposureConditional,
		"webtunnel":        ExposureConditional,
		"masque":           ExposureConditional,
		"shadowsocks":      ExposureConditional,
		"tor-bridge":       ExposureConditional,
		"wireguard":        ExposureNo,
		"amneziawg":        ExposureNo,
		"psiphon":          ExposureConditional,
		"conjure":          ExposureConditional,
		"transport_module": ExposureConditional,
		"lifeline_relay":   ExposureConditional,
		"other":            ExposureConditional,
	}
}
