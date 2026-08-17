package rotation

import (
	"fmt"
	"sort"
	"strings"

	"daal/publisher/deploy/provider"
)

// Level is one rung of the supplement §14.1 direct-VPS rotation
// ladder. Closed enum; adding a level is a spec_version bump on the
// supplement.
type Level string

const (
	// L1: regenerate credentials (UUIDs, passwords, X25519 keys);
	// re-sign RelayPack with same publisher key.
	L1 Level = "L1"
	// L2: change TLS / route parameters (REALITY dest, WS path, SNI,
	// ports). Same IP family.
	L2 Level = "L2"
	// L3: floating-IP swap. Same server. ~10 s wall-clock at V1.5.
	L3 Level = "L3"
	// L4: move datacenter (redeploy on a fresh box, old one deleted).
	L4 Level = "L4"
	// L5: move provider (redeploy at a different cloud provider).
	L5 Level = "L5"
	// L6: change protocol mix (different toolbox profile;
	// e.g. tcp-only-vps-native).
	L6 Level = "L6"
)

// Confidence reports how certain the recommender is that the
// chosen level matches the actual failure. Bound by data source:
// Explanation can return high; context-only is capped at medium;
// sparse context (or empty Explanation) is low.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// estWallClockV15 is the supplement §14.1 V1.5 column. Surfaced to
// the wizard so the FRP knows what to expect before they tap.
var estWallClockV15 = map[Level]string{
	L1: "~90s",
	L2: "~90s",
	L3: "~10s",
	L4: "~3min",
	L5: "~2min",
	L6: "~3min",
}

// RotationRecommendation is the wizard-facing output. Override
// lists the legal alternative levels the operator may pick from
// the dropdown — when no override makes sense (e.g. L3 fast path
// with no signal of wider trouble) the slice is empty.
type RotationRecommendation struct {
	Level        Level      `json:"level"`
	Confidence   Confidence `json:"confidence"`
	Reason       string     `json:"reason"`
	EstWallClock string     `json:"est_wallclock"`
	Override     []Level    `json:"override"`

	// Action is the concrete operation that performs this rung on this
	// relay — which verb, what it touches, and whether the relay in
	// front of you can actually do it. Added at Step 7, when L1 and L2
	// stopped being advice and became executable. See action.go.
	Action Action `json:"action"`
}

// Explanation is the publisher-side mirror of
// core/internal/selection.Explanation. The publisher cannot import
// the internal selection package (Go internal-import rule), so we
// re-declare the wire shape here. Field names + JSON tags MUST stay
// byte-identical to the FRP-3 wire shape; explain_test.go in the
// recommender_test golden walker pins this.
//
// Only the fields the recommender actually reads are mirrored;
// adding a field is allowed (forward-compatible JSON unmarshal),
// removing one would be a wire break.
type Explanation struct {
	Pick            ExplPicked     `json:"pick"`
	Failures        []ExplFailure  `json:"failures"`
	ActiveCooldowns []ExplCooldown `json:"active_cooldowns"`
	NetworkSignals  []string       `json:"network_signals"`
	Phase           string         `json:"phase"`
}

// ExplPicked mirrors selection.PickedCandidate (subset).
type ExplPicked struct {
	RouteID      string `json:"route_id"`
	ExposureMode string `json:"exposure_mode"`
}

// ExplFailure mirrors selection.FailureRecord.
type ExplFailure struct {
	RouteID        string `json:"route_id"`
	Classification string `json:"classification"`
	Tag            string `json:"tag,omitempty"`
}

// ExplCooldown mirrors selection.CooldownEntry.
type ExplCooldown struct {
	Tag           string `json:"tag"`
	ExpiresAtUnix int64  `json:"expires_at_unix"`
	Reason        string `json:"reason"`
}

// RotationContext is the FromContext input. The FRP fills it in by
// hand or by checkbox in the wizard when they cannot get the
// recipient's Explanation JSON (the realistic outage case).
type RotationContext struct {
	// FailureClassifications is the closed set of strings the
	// FRP-3 classifier emits (see core/diagnostics/classify.go +
	// supplement §13.3): e.g. "tcp_reset", "sni_rst",
	// "udp_collapsed", "origin_unhealthy", "dns_bogon",
	// "credential_leak". Open-vocabulary on the publisher side
	// (we don't validate; the recommender just pattern-matches).
	FailureClassifications []string

	// NetworkSignals is the FRP-3 9-signal vocabulary (supplement
	// §13.3). Open-vocabulary here for forward-compat.
	NetworkSignals []string

	// ExposureMode is "direct_vps" at V1.5 (always). FRP-8 will
	// add "cdn_fronted" here.
	ExposureMode string

	// OperatorRecord is the FRP's provisioned VPS record. Used
	// for the L3 vs L4/L5 decision (does the box have a floating
	// IP attached?).
	OperatorRecord *provider.OperatorRecord

	// CredentialLeakSuspected is the FRP-side hygiene flag.
	// True ⇒ recommend L1 with operator-asserted confidence.
	CredentialLeakSuspected bool

	// RelayCapabilities is what the caller learned by probing this
	// relay's in-box mgmt binary (mgmt.CapabilitiesWithFW). The zero
	// value means "not probed", which yields an Action marked
	// AvailabilityUnknown rather than a confident one — the recommender
	// is offline and must never guess a relay's vintage.
	RelayCapabilities RelayCapabilities
}

// signalSet is the recommender's internal, normalised view of the
// inputs. Built by signalSetFromExplanation / signalSetFromContext.
type signalSet struct {
	classifications map[string]bool
	signals         map[string]bool
	cooldownTags    map[string]bool
	exposureMode    string
	hasFloatingIP   bool
	credLeakHinted  bool
	relayCaps       RelayCapabilities
	source          string // "explanation" or "context"
}

func newSignalSet(source string) *signalSet {
	return &signalSet{
		classifications: map[string]bool{},
		signals:         map[string]bool{},
		cooldownTags:    map[string]bool{},
		source:          source,
	}
}

func signalSetFromExplanation(e Explanation, rec *provider.OperatorRecord) *signalSet {
	s := newSignalSet("explanation")
	for _, f := range e.Failures {
		s.classifications[f.Classification] = true
		if f.Tag != "" {
			s.cooldownTags[f.Tag] = true
		}
	}
	for _, c := range e.ActiveCooldowns {
		s.cooldownTags[c.Tag] = true
	}
	for _, sig := range e.NetworkSignals {
		s.signals[sig] = true
	}
	s.exposureMode = e.Pick.ExposureMode
	if s.exposureMode == "" {
		s.exposureMode = "direct_vps"
	}
	if rec != nil {
		s.hasFloatingIP = rec.FloatingIPID != ""
	}
	return s
}

func signalSetFromContext(ctx RotationContext) *signalSet {
	s := newSignalSet("context")
	for _, f := range ctx.FailureClassifications {
		s.classifications[f] = true
	}
	for _, sig := range ctx.NetworkSignals {
		s.signals[sig] = true
	}
	s.exposureMode = ctx.ExposureMode
	if s.exposureMode == "" {
		s.exposureMode = "direct_vps"
	}
	if ctx.OperatorRecord != nil {
		s.hasFloatingIP = ctx.OperatorRecord.FloatingIPID != ""
	}
	s.credLeakHinted = ctx.CredentialLeakSuspected
	s.relayCaps = ctx.RelayCapabilities
	return s
}

// hasTagPrefix reports whether any active cooldown tag starts
// with the given prefix. Mirrors the supplement §13.4 tag
// vocabulary: public_ip:*, public_asn:*, public_provider:*,
// public_domain:*, host:*, sni:*, cdn:*, origin_*.
func (s *signalSet) hasTagPrefix(prefix string) bool {
	for tag := range s.cooldownTags {
		if strings.HasPrefix(tag, prefix) {
			return true
		}
	}
	return false
}

// FromExplanation runs the ladder mapping over the recipient's
// FRP-3 Explanation. Confidence is high when the Explanation
// carries any signal the recommender recognises; low when the
// Explanation is empty (no failures, no signals, no cooldowns).
func FromExplanation(e Explanation, rec *provider.OperatorRecord) RotationRecommendation {
	return FromExplanationWithCapabilities(e, rec, RelayCapabilities{})
}

// FromExplanationWithCapabilities is FromExplanation plus what the
// caller probed about the relay's in-box mgmt binary. The recommendation
// is identical; only [Action] differs, and only in whether it can claim
// the in-place verb is reachable. FromExplanation delegates here with an
// unprobed RelayCapabilities, so an un-updated caller gets
// AvailabilityUnknown — never a false "ready".
func FromExplanationWithCapabilities(e Explanation, rec *provider.OperatorRecord, caps RelayCapabilities) RotationRecommendation {
	s := signalSetFromExplanation(e, rec)
	s.relayCaps = caps
	return s.recommend()
}

// FromContext runs the ladder mapping over an FRP-supplied
// context. Confidence is capped at medium even with rich input —
// the recommender does not have the recipient's authoritative
// per-decision record.
func FromContext(ctx RotationContext) RotationRecommendation {
	s := signalSetFromContext(ctx)
	return s.recommend()
}

// recommend is the core mapping. Order matters: L1 credential
// hygiene wins over everything (it's the cheapest "always-safe"
// recommendation when the FRP suspects compromise); then signal-
// driven escalations from cheapest (L3) to most expensive (L6).
//
//nolint:gocyclo // ladder mapping is intrinsically a switch tree
func (s *signalSet) recommend() RotationRecommendation {
	// 1. Operator-asserted credential leak (context-only path).
	if s.credLeakHinted {
		return s.build(L1,
			"Operator flagged suspected credential leak; rotating credentials in place",
			[]Level{L2, L3})
	}

	// 2. cdn_fronted candidates do not exist at V1.5. If the
	// caller asked us to rotate one, surface a clear "no cdn
	// candidates available at V1.5" reason mapped to L3 (the
	// cheapest direct rotation that exists today).
	if s.exposureMode == "cdn_fronted" {
		return s.build(L3,
			"V1.5 has no cdn_fronted candidates; recommending L3 floating-IP swap on the underlying direct candidate",
			[]Level{L1, L2, L4})
	}

	// 3. Provider-account suspended / DC outage (medium-low
	// confidence even from Explanation; the selector cannot
	// observe a provider-side suspension directly — we infer it
	// from a public_provider:* cooldown plus an unhealthy origin
	// signal).
	if s.classifications["provider_suspended"] {
		return s.build(L5,
			"Cloud provider account suspended or unreachable; redeploying at a different provider",
			[]Level{L4, L6})
	}

	// 4. UDP collapsed signal: shift to TCP-only profile (L6).
	if s.signals["udp_collapsed"] {
		return s.build(L6,
			"UDP collapsed on the recipient's network; switching to a TCP-only protocol mix",
			[]Level{L4, L5})
	}

	// 5. Whole protocol family burned: ≥2 distinct family-class
	// failures observed. L6 (different toolbox profile).
	if s.protocolFamilyBurned() {
		return s.build(L6,
			"Multiple protocol families failing; provisioning a different toolbox profile",
			[]Level{L4, L5})
	}

	// 6. ASN- or provider-level burn ⇒ L4 (move datacenter).
	if s.hasTagPrefix("public_asn:") || s.hasTagPrefix("public_provider:") {
		return s.build(L4,
			"ASN- or provider-level cooldown active; redeploying in a different datacenter",
			[]Level{L5, L3})
	}

	// 7. tcp_reset failure with public_ip:* cooldown ⇒ L3 fast
	// path. The most common rotation, per supplement §14.1
	// "L3 ... most common rotation".
	if s.classifications["tcp_reset"] && s.hasTagPrefix("public_ip:") {
		if s.hasFloatingIP {
			return s.build(L3,
				"TCP reset on a single IP that's burned; floating-IP swap on the same server",
				[]Level{L4, L2})
		}
		// No floating IP attached: L3 unavailable; fall back to L4.
		return s.build(L4,
			"TCP reset on a single burned IP but the box has no floating IP; redeploy in a different DC",
			[]Level{L5, L2})
	}

	// 8. sni_rst on direct_vps ⇒ L2 (change TLS/route params).
	if s.classifications["sni_rst"] {
		return s.build(L2,
			"SNI-based TLS reset detected; rotating TLS/route parameters",
			[]Level{L3, L4})
	}

	// 9. Credential leak classification (from Explanation) ⇒ L1.
	if s.classifications["credential_leak"] {
		return s.build(L1,
			"Credential leak classification observed; regenerating credentials",
			[]Level{L2, L3})
	}

	// 10. Default fallback: empty Explanation / no recognised
	// signal. L1 (cheapest hygiene rotation), low confidence.
	return s.build(L1,
		"No specific failure signal observed; defaulting to credential hygiene rotation",
		[]Level{L2, L3, L4})
}

// protocolFamilyBurned reports whether the inputs suggest >=2
// distinct family-class failures. Crude heuristic: count the number
// of unique family-class hints in the failure tags
// (origin_family:*, host:*, family:*) plus explicit "protocol_*"
// classifications.
func (s *signalSet) protocolFamilyBurned() bool {
	families := map[string]bool{}
	for tag := range s.cooldownTags {
		if strings.HasPrefix(tag, "family:") {
			families[strings.TrimPrefix(tag, "family:")] = true
		}
		if strings.HasPrefix(tag, "origin_family:") {
			families[strings.TrimPrefix(tag, "origin_family:")] = true
		}
	}
	if s.signals["protocol_whitelist_mode"] {
		// Strong signal: the network only allows whitelisted
		// protocols; any non-whitelisted family will burn.
		return true
	}
	return len(families) >= 2
}

// build assembles the RotationRecommendation, applies the
// confidence cap, and looks up the V1.5 wall-clock estimate.
func (s *signalSet) build(level Level, reason string, override []Level) RotationRecommendation {
	wc, ok := estWallClockV15[level]
	if !ok {
		wc = "~unknown"
	}
	action := ActionFor(level, s.relayCaps)
	// The ~90s figures for L1/L2 are the IN-PLACE cost. On a relay too
	// old for the split endpoints the only route to the same outcome is
	// destroy-and-rebuild, and quoting 90 seconds for a 3-minute
	// reprovision is the kind of dial-that-lies this project spent a
	// step removing.
	if action.DestroysServer && (level == L1 || level == L2) {
		wc = estWallClockV15[L4] + " (reprovision fallback: this relay cannot rotate in place)"
	}
	return RotationRecommendation{
		Level:        level,
		Confidence:   s.confidenceFor(level),
		Reason:       reason,
		EstWallClock: wc,
		Override:     dedupeLevels(override),
		Action:       action,
	}
}

// confidenceFor implements the data-source confidence cap:
//
//	Explanation source + concrete signal           => high
//	Explanation source + empty/default fallback    => low
//	Context source + operator-asserted credential  => medium
//	Context source + concrete signal               => medium
//	Context source + empty/default fallback        => low
func (s *signalSet) confidenceFor(level Level) Confidence {
	hasAnySignal := len(s.classifications) > 0 ||
		len(s.signals) > 0 ||
		len(s.cooldownTags) > 0 ||
		s.credLeakHinted
	if !hasAnySignal {
		return ConfidenceLow
	}
	if s.source == "explanation" {
		// L1 by way of "credential_leak" classification is medium
		// — the selector classifies but it can't strictly prove a
		// leak vs. a hostile re-auth.
		if level == L1 && s.classifications["credential_leak"] {
			return ConfidenceMedium
		}
		return ConfidenceHigh
	}
	// Context source (incl. operator-asserted leak) caps at medium.
	return ConfidenceMedium
}

// dedupeLevels removes duplicates while preserving first-seen order.
// Keeps the override slice tidy when callers pass overlapping lists.
func dedupeLevels(in []Level) []Level {
	seen := map[Level]bool{}
	out := make([]Level, 0, len(in))
	for _, l := range in {
		if seen[l] {
			continue
		}
		seen[l] = true
		out = append(out, l)
	}
	return out
}

// AllLevels returns L1..L6 in canonical order. Used by the wizard
// override dropdown when the recommender returns Override = nil.
func AllLevels() []Level {
	return []Level{L1, L2, L3, L4, L5, L6}
}

// String renders a Level for log lines. The JSON tag is the wire
// shape; this is purely human-readable.
func (l Level) String() string {
	switch l {
	case L1:
		return "L1 regen credentials"
	case L2:
		return "L2 change TLS/route params"
	case L3:
		return "L3 floating-IP swap"
	case L4:
		return "L4 move datacenter"
	case L5:
		return "L5 move provider"
	case L6:
		return "L6 change protocol mix"
	default:
		return fmt.Sprintf("unknown(%s)", string(l))
	}
}

// SortedLevels is a deterministic sort over a Level slice. Used by
// goldens to keep override comparisons stable.
func SortedLevels(in []Level) []Level {
	out := append([]Level(nil), in...)
	sort.SliceStable(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
