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
//
// THESE ARE BOUNDS, NOT MEASUREMENTS. Nothing in this repository times
// a rotation against a live provider; W3-10 says the same about the L3
// budget. Where a figure is uncertain it must therefore be rounded UP,
// because the number is rendered verbatim to an operator deciding
// whether to accept an outage, and a rung that finishes early costs
// them nothing while one that overruns its quote is the dial-that-lies
// this file exists to refuse.
//
// L5 READ "~2min" UNTIL WAVE 6, faster than the L4 sitting directly
// above it. L5 does strictly more work than L4: both delete a server
// and build another, and L5 does it across two different clouds, with
// the create leg landing on a COLD account — no cached image, no
// existing SSH key, no firewall group, and a first-call latency Daal
// has never measured because until this wave there was no second live
// provider to measure against. A rung cannot be cheaper than the rung
// it strictly contains. It is quoted at L4's figure as a floor.
var estWallClockV15 = map[Level]string{
	L1: "~90s",
	L2: "~90s",
	L3: "~10s",
	L4: "~3min",
	L5: "~3min",
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

	// ReasonCode is Reason's machine-readable parallel: one stable code
	// naming the rule that fired, drawn from the closed vocabulary
	// below.
	//
	// WHY BOTH, same argument as Evidence.AbsentCodes. Reason is
	// English prose built here, and the panel that renders it
	// (client-ui RotationAdvice.tsx) ships in Farsi. Reason is the
	// single most decisive sentence on that screen — it is the whole
	// substance of the answer, and three of the six rungs it can point
	// at DESTROY the relay. An operator deciding whether to rebuild was
	// reading that sentence in a language they may not have.
	//
	// The prose stays as the fallback for a code a catalog does not
	// carry yet: a new rule must degrade to English, never to silence.
	ReasonCode string `json:"reason_code"`

	// ReasonDetail is the machine-specific fragment some reason codes
	// interpolate — the concrete blocker that made an in-place address
	// swap impossible, or the list of inputs that matched no rung. It
	// is deliberately NOT translated: it is provider notes and
	// closed-vocabulary identifiers, and a translated sentence with an
	// English parenthetical beats an entirely English one.
	//
	// Empty for every code that needs no detail. A catalog string
	// substitutes it for `{detail}`.
	ReasonDetail string `json:"reason_detail,omitempty"`

	// Action is the concrete operation that performs this rung on this
	// relay — which verb, what it touches, and whether the relay in
	// front of you can actually do it. Added at Step 7, when L1 and L2
	// stopped being advice and became executable. See action.go.
	Action Action `json:"action"`

	// Grounded reports whether Level was chosen FROM evidence.
	//
	// This is the field the whole Wave-6 pass exists for. Until it, the
	// recommender's last rule returned L1 with a sentence that read like
	// advice ("defaulting to credential hygiene rotation") and — on the
	// Explanation path — a HIGH confidence, because confidenceFor only
	// asked "was any input non-empty", never "did any input actually
	// decide this". A relay with nothing wrong and a relay with a
	// failure the ladder has no rung for produced the same confident
	// answer, and an operator who acts on it destroys a working relay.
	//
	// Grounded == false means: Level is the ladder's cheapest safe
	// default, Confidence is low, and Reason names what was missing. A
	// UI must render that as "Daal cannot tell you", never as a rung to
	// press.
	Grounded bool `json:"grounded"`

	// Evidence is what the recommender was actually given — and, just
	// as load-bearing, what it was not. See Evidence.
	Evidence Evidence `json:"evidence"`
}

// Evidence is the recommender's account of its own inputs.
//
// It exists because the failure mode of a recommender is not "wrong
// answer", it is "confident answer from nothing". Every rendered
// recommendation carries the inputs it saw so the operator can judge
// the advice instead of trusting it, and carries the named absences so
// "not measured" never reads as "measured negative".
type Evidence struct {
	// Source is "explanation" (the recipient's own selector record) or
	// "context" (what the operator typed or ticked). It is the ceiling
	// on confidence, not a detail.
	Source string `json:"source"`
	// Classifications / Signals / CooldownTags are the inputs that were
	// present, sorted for a stable render.
	Classifications []string `json:"classifications"`
	Signals         []string `json:"signals"`
	CooldownTags    []string `json:"cooldown_tags"`
	// Unrecognised lists inputs that WERE present and that no rule on
	// this ladder consumes. They are the difference between "nothing is
	// wrong" and "something is wrong that rotation does not fix", and
	// collapsing the two is how an operator rotates a relay whose
	// problem was an expired route or a revoked publisher.
	Unrecognised []string `json:"unrecognised"`
	// Absent names the inputs that are structurally unavailable, each
	// with the reason. Absence is a fact about Daal, not about the
	// relay, and it must survive to the screen: a rung that cannot fire
	// because nothing produces its evidence is not a rung the operator
	// has ruled out.
	Absent []string `json:"absent"`
	// AbsentCodes is Absent's machine-readable parallel: one stable
	// code per entry, same order, same length.
	//
	// WHY BOTH. `Absent` is English prose built here, and the panel
	// that renders it (client-ui RotationAdvice.tsx) is a D-2 surface
	// that ships in Farsi. Rendering the prose verbatim gave a Farsi
	// operator a translated frame around untranslated content — and the
	// absences are the half of that panel carrying the honesty, because
	// they are what distinguishes "measured and fine" from "never
	// measured at all". The half the operator could not read was the
	// half that matters.
	//
	// The codes are a CLOSED set (see the constants below), so the UI
	// can key them, and the prose stays as the fallback for a code a
	// catalog does not yet carry — a new absence must degrade to
	// English, never to silence.
	AbsentCodes []string `json:"absent_codes"`
}

// The closed vocabulary of AbsentCodes. Adding one here means adding a
// key on the UI side; until then the English prose is rendered, which
// is the intended degradation.
const (
	// No classified failure was recorded on this relay in the window.
	AbsentNoFailures = "no_failures"
	// Nothing in Daal attributes a cooldown to a shared risk tag.
	AbsentNoCooldownProducer = "no_cooldown_producer"
	// The probe-derived signals have no producer at all.
	AbsentNoProber = "no_prober"
	// The run used operator-supplied context, not the recipient's own
	// selector record.
	AbsentOperatorSupplied = "operator_supplied"
)

// The closed vocabulary of ReasonCode: one code per arm of recommend()
// (plus the two fallback silences, which are different facts and must
// not collapse into one sentence). Adding a rule here means adding a
// key on the UI side; until then the English prose is rendered, which
// is the intended degradation.
//
// The codes are named for WHAT WAS OBSERVED, not for the rung chosen,
// because the same rung is reached from different evidence and the
// operator is owed the evidence.
const (
	// Rule 1: the operator asserted a credential leak. Nothing measured
	// this — no classifier emits it — so the code says "suspected".
	ReasonCredentialLeakSuspected = "credential_leak_suspected"
	// Rule 2: cdn_fronted was asked for and V1.5 has no such candidate.
	ReasonNoCDNCandidates = "no_cdn_candidates"
	// Rule 3: the cloud account looks suspended or unreachable.
	ReasonProviderSuspended = "provider_suspended"
	// Rule 4: UDP collapsed on the recipient's network.
	ReasonUDPCollapsed = "udp_collapsed"
	// Rule 5: two or more protocol families failing at once.
	ReasonProtocolFamiliesBurned = "protocol_families_burned"
	// Rule 6: a cooldown attributes trouble to the whole ASN or
	// provider, not to this one address.
	ReasonSharedRiskCooldown = "shared_risk_cooldown"
	// Rule 7, four arms. The address is being blocked; which sentence
	// applies turns on how strong the evidence is (a reset is proof, a
	// connect timeout looks the same as a dead box) and on whether
	// anything attributed the block to this relay's address. Both axes
	// change what the operator should believe, so both are codes.
	ReasonAddressResetAttributed     = "address_reset_attributed"
	ReasonAddressResetUnattributed   = "address_reset_unattributed"
	ReasonAddressTimeoutAttributed   = "address_timeout_attributed"
	ReasonAddressTimeoutUnattributed = "address_timeout_unattributed"
	// Rule 7's rebuild arm: the address is blocked AND this relay
	// cannot swap it. ReasonDetail carries the blocker.
	ReasonAddressBlockNoSwap = "address_block_no_swap"
	// Rule 8: TLS is being blocked on the name, not the address.
	ReasonSNIBlock = "sni_block"
	// Rule 9: a credential-leak classification arrived as measurement.
	ReasonCredentialLeakObserved = "credential_leak_observed"
	// The fallback's two silences, which mean opposite things. Both are
	// refusals: Grounded is false and neither may render as advice.
	//
	// NoEvidenceAtAll: nothing reached the recommender.
	// NothingMatchedLadder: something did, and no rung addresses it —
	// rotating would change the relay without touching what was seen.
	// ReasonDetail carries what was recorded.
	ReasonNoEvidenceAtAll      = "no_evidence_at_all"
	ReasonNothingMatchedLadder = "nothing_matched_ladder"
)

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
	// providerName is the record's cloud adapter ("hetzner", "vultr",
	// "stark"). It decides L3's availability, because whether an
	// address swap actually moves the record's dialled address is a
	// property of the adapter, not of the remote box — see
	// ActionForProvider.
	providerName string
	source       string // "explanation" or "context"
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
		s.providerName = rec.Provider
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
		s.providerName = ctx.OperatorRecord.Provider
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
		return s.build(L1, ReasonCredentialLeakSuspected,
			"Operator flagged suspected credential leak; rotating credentials in place",
			[]Level{L2, L3})
	}

	// 2. cdn_fronted candidates do not exist at V1.5. If the
	// caller asked us to rotate one, surface a clear "no cdn
	// candidates available at V1.5" reason mapped to L3 (the
	// cheapest direct rotation that exists today).
	if s.exposureMode == "cdn_fronted" {
		return s.build(L3, ReasonNoCDNCandidates,
			"V1.5 has no cdn_fronted candidates; recommending L3 floating-IP swap on the underlying direct candidate",
			[]Level{L1, L2, L4})
	}

	// 3. Provider-account suspended / DC outage (medium-low
	// confidence even from Explanation; the selector cannot
	// observe a provider-side suspension directly — we infer it
	// from a public_provider:* cooldown plus an unhealthy origin
	// signal).
	if s.classifications["provider_suspended"] {
		return s.build(L5, ReasonProviderSuspended,
			"Cloud provider account suspended or unreachable; redeploying at a different provider",
			[]Level{L4, L6})
	}

	// 4. UDP collapsed signal: shift to TCP-only profile (L6).
	if s.signals["udp_collapsed"] {
		return s.build(L6, ReasonUDPCollapsed,
			"UDP collapsed on the recipient's network; switching to a TCP-only protocol mix",
			[]Level{L4, L5})
	}

	// 5. Whole protocol family burned: ≥2 distinct family-class
	// failures observed. L6 (different toolbox profile).
	if s.protocolFamilyBurned() {
		return s.build(L6, ReasonProtocolFamiliesBurned,
			"Multiple protocol families failing; provisioning a different toolbox profile",
			[]Level{L4, L5})
	}

	// 6. ASN- or provider-level burn ⇒ L4 (move datacenter).
	if s.hasTagPrefix("public_asn:") || s.hasTagPrefix("public_provider:") {
		return s.build(L4, ReasonSharedRiskCooldown,
			"ASN- or provider-level cooldown active; redeploying in a different datacenter",
			[]Level{L5, L3})
	}

	// 7. Address-level block ⇒ L3, the cheapest and least destructive
	// rung: the server, its keys and everyone's credentials survive and
	// only the address people dial moves.
	//
	// TWO CORRECTIONS LIVE HERE, both of which used to point the
	// operator at a rebuild they did not need.
	//
	// (a) The tag is no longer REQUIRED. This rule used to fire only on
	// `tcp_reset` AND a `public_ip:*` cooldown tag, and no code in this
	// repository produces a tag-level cooldown: selection.PropagateCooldown
	// has no production caller, so Explanation.ActiveCooldowns is empty
	// in every real blob. Requiring the tag therefore made the most
	// common rotation on the ladder unreachable from measured data,
	// while a rung that DESTROYS the server (rule 6) sat above it. A
	// reset is address-level evidence on its own; the tag is the
	// ATTRIBUTION, and the honest response to a missing attribution is a
	// lower confidence and a reason that says which half is missing —
	// not a bigger hammer.
	//
	// (b) The old "no floating IP ⇒ L4" branch is gone. It predates the
	// step that taught the Hetzner adapter to RESERVE an address, so
	// "the box has no floating IP" stopped meaning "L3 is impossible"
	// and started meaning "L3 will mint one" — which is the state of
	// every relay provisioned before that step, i.e. every relay in the
	// field. Whether L3 can run is now asked of the thing that knows:
	// ActionForProvider, which weighs the cloud adapter AND the relay's
	// mgmt vintage and has three answers, not two. Only a KNOWN-
	// unsupported L3 falls through to a rebuild; "not probed yet" keeps
	// the cheap rung and says it is unverified.
	if s.addressLevelBlock() {
		if s.canSwapAddress() {
			code, prose := s.addressReason()
			return s.build(L3, code, prose, []Level{L4, L2})
		}
		blocker := s.l3Blocker()
		rec := s.build(L4, ReasonAddressBlockNoSwap,
			"Address-level block, and this relay cannot swap its address ("+
				blocker+"); redeploying in a different datacenter gets a new address",
			[]Level{L5, L2})
		rec.ReasonDetail = blocker
		return rec
	}

	// 8. SNI-based TLS block ⇒ L2 (change TLS/route params).
	//
	// Both spellings are matched. `sni_rst` is the selector's signal
	// name; `tls_sni_or_cert_block_suspected` is what
	// core/diagnostics/classify.go actually stamps on a route row, and
	// it is therefore the one that arrives on the measured path. A rule
	// that only knew the first spelling could never fire on real data.
	if s.classifications["sni_rst"] ||
		s.classifications["tls_sni_or_cert_block_suspected"] ||
		s.signals["sni_rst"] {
		return s.build(L2, ReasonSNIBlock,
			"SNI-based TLS block detected; rotating TLS/route parameters",
			[]Level{L3, L4})
	}

	// 9. Credential leak classification (from Explanation) ⇒ L1.
	//
	// NOTE the vocabulary gap, deliberately not papered over:
	// "credential_leak" is not a diagnostics.Category and no classifier
	// emits it, so this rule is reachable only from an operator
	// assertion. `auth_failed` IS emitted and is NOT mapped here — on a
	// relay you own it almost always means a stale pack, and rotating
	// credentials in response would strand the recipient it was trying
	// to help.
	if s.classifications["credential_leak"] {
		return s.build(L1, ReasonCredentialLeakObserved,
			"Credential leak classification observed; regenerating credentials",
			[]Level{L2, L3})
	}

	// 10. NO RULE FIRED. This is not a recommendation and must not be
	// rendered as one — see RotationRecommendation.Grounded.
	return s.fallback()
}

// addressLevelBlock reports the classifications that mean "the address
// this relay answers on is being blocked", which is what L3 fixes.
//
// tcp_reset and tcp_connect_timeout are both diagnostics.Category
// values the classifier really emits. A connect timeout is weaker
// evidence than a reset (it is also what a dead box looks like), so it
// is recognised but noted in the reason rather than treated as proof.
func (s *signalSet) addressLevelBlock() bool {
	return s.classifications["tcp_reset"] || s.classifications["tcp_connect_timeout"]
}

// canSwapAddress asks action.go whether an L3 is possible on this
// relay. "Not probed" counts as possible-but-unverified: the rung is
// cheap and reversible, and downgrading an unknown to a rebuild is how
// a recommender destroys a working relay on missing information.
func (s *signalSet) canSwapAddress() bool {
	return ActionForProvider(L3, s.relayCaps, s.providerName).Availability != AvailabilityUnsupported
}

// l3Blocker renders why L3 was refused, in the operator's terms.
func (s *signalSet) l3Blocker() string {
	a := ActionForProvider(L3, s.relayCaps, s.providerName)
	if a.Note != "" {
		return a.Note
	}
	return "address swap unsupported on this relay"
}

// addressReason names how strong the evidence actually is, including
// the attribution that is missing on every measured run today.
//
// It returns the code alongside the prose because both axes it varies
// on — reset vs timeout, attributed vs not — change what the operator
// should believe, and a single code covering all four would hand a
// Farsi reader one sentence for four different situations.
func (s *signalSet) addressReason() (string, string) {
	reset := s.classifications["tcp_reset"]
	what := "TCP reset"
	if !reset {
		what = "TCP connect timeout (weaker evidence than a reset — an unreachable box looks the same)"
	}
	if s.hasTagPrefix("public_ip:") {
		code := ReasonAddressResetAttributed
		if !reset {
			code = ReasonAddressTimeoutAttributed
		}
		return code, what + " attributed to this relay's address; floating-IP swap on the same server"
	}
	code := ReasonAddressResetUnattributed
	if !reset {
		code = ReasonAddressTimeoutUnattributed
	}
	return code, what + " on this relay, with no address-level attribution recorded " +
		"(nothing in Daal produces one yet); a floating-IP swap is the cheapest thing that would fix it"
}

// fallback is the answer when no rule fired.
//
// It still names L1, because the wire shape requires a Level and L1 is
// the cheapest rung that cannot make anything worse — but Grounded is
// false, confidence is low, and the reason says which of the two very
// different silences this is.
func (s *signalSet) fallback() RotationRecommendation {
	var reason, code, detail string
	switch {
	case !s.hasAnyInput():
		code = ReasonNoEvidenceAtAll
		reason = "Nothing has been recorded about this relay yet — no failure, no cooldown and " +
			"no network signal reached the recommender — so there is no evidence for any rung. " +
			"This is not a recommendation to rotate."
	default:
		code = ReasonNothingMatchedLadder
		detail = strings.Join(s.recordedSummary(), ", ")
		reason = "What has been recorded (" + detail +
			") does not point at any rung of this ladder. Rotating would change the relay " +
			"without addressing what was actually observed. This is not a recommendation to rotate."
	}
	rec := s.build(L1, code, reason, []Level{L2, L3, L4})
	rec.ReasonDetail = detail
	rec.Grounded = false
	rec.Confidence = ConfidenceLow
	return rec
}

func (s *signalSet) hasAnyInput() bool {
	return len(s.classifications) > 0 || len(s.signals) > 0 ||
		len(s.cooldownTags) > 0 || s.credLeakHinted
}

// recordedSummary is the human-readable list of what WAS present when
// nothing matched. Sorted so the sentence is stable.
func (s *signalSet) recordedSummary() []string {
	out := append([]string{}, sortedKeys(s.classifications)...)
	out = append(out, sortedKeys(s.signals)...)
	out = append(out, sortedKeys(s.cooldownTags)...)
	if len(out) == 0 {
		out = append(out, "nothing")
	}
	return out
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
func (s *signalSet) build(level Level, code, reason string, override []Level) RotationRecommendation {
	return RotationRecommendation{
		Level:        level,
		Confidence:   s.confidenceFor(level),
		Reason:       reason,
		ReasonCode:   code,
		EstWallClock: WallClockFor(level, ActionForProvider(level, s.relayCaps, s.providerName)),
		Override:     dedupeLevels(override),
		Action:       ActionForProvider(level, s.relayCaps, s.providerName),
		Grounded:     true,
		Evidence:     s.evidence(),
	}
}

// alwaysDestroys is true for the rungs whose whole definition is a new
// server. Their estWallClockV15 figures are already the rebuild cost,
// so the fallback override below must not fire on them.
func alwaysDestroys(l Level) bool { return l == L4 || l == L5 || l == L6 }

// WallClockFor is the one place a rung's duration is decided, so every
// surface that shows one shows the same one.
//
// It is exported because the UI must render THIS string and never its
// own lookup table. The estWallClockV15 column is the IN-PLACE cost,
// and on a relay that can only reach the same outcome by
// destroy-and-rebuild, quoting 90 seconds for a 3-minute reprovision is
// the kind of dial-that-lies this project spent a step removing.
func WallClockFor(level Level, action Action) string {
	wc, ok := estWallClockV15[level]
	if !ok {
		wc = "~unknown"
	}
	switch {
	case action.DestroysServer && !alwaysDestroys(level):
		// The relay cannot do the in-place verb; the action returned is
		// the reprovision FALLBACK, and it costs what a reprovision
		// costs.
		return estWallClockV15[L4] + " (reprovision fallback: this relay cannot rotate in place)"
	case action.Availability == AvailabilityUnsupported:
		// Known-unsupported with no rebuild fallback attached — an L3
		// on an adapter that would leave every pack pointing at the
		// address being rotated away from. A duration here would be a
		// promise about something that is going to refuse.
		return "not available on this relay"
	}
	return wc
}

// probeDerivedSignals are the four members of the FRP-3 signal
// vocabulary that NOTHING in this repository produces.
//
// They are cross-candidate, cross-network probe aggregations
// (cdn_wide_failure is specified as "2+ candidates failed across 3+
// networks"); no single classified error implies any of them, and
// core/abi's producer refuses to synthesise them — a refusal pinned by
// its own tests. They are listed here so a recommendation can SAY they
// were unavailable, because a rung that never fires because its
// evidence has no producer is not a rung the operator has ruled out.
var probeDerivedSignals = []string{
	"cdn_hostname_blocked",
	"cdn_wide_failure",
	"protocol_whitelist_mode",
	"stateful_reassembly_present",
}

// recognisedClassifications / recognisedSignals are the inputs some
// rule above actually consumes. Anything present and not in here lands
// in Evidence.Unrecognised rather than being silently ignored.
var recognisedClassifications = map[string]bool{
	"provider_suspended":              true,
	"tcp_reset":                       true,
	"tcp_connect_timeout":             true,
	"sni_rst":                         true,
	"tls_sni_or_cert_block_suspected": true,
	"credential_leak":                 true,
}

var recognisedSignals = map[string]bool{
	"udp_collapsed":           true,
	"sni_rst":                 true,
	"protocol_whitelist_mode": true,
}

var recognisedTagPrefixes = []string{
	"public_ip:", "public_asn:", "public_provider:", "family:", "origin_family:",
}

// evidence reports what the recommender was given and what it was not.
func (s *signalSet) evidence() Evidence {
	e := Evidence{
		Source:          s.source,
		Classifications: sortedKeys(s.classifications),
		Signals:         sortedKeys(s.signals),
		CooldownTags:    sortedKeys(s.cooldownTags),
		Unrecognised:    []string{},
		Absent:          []string{},
		AbsentCodes:     []string{},
	}
	for _, c := range e.Classifications {
		if !recognisedClassifications[c] {
			e.Unrecognised = append(e.Unrecognised, "classification "+c)
		}
	}
	for _, sig := range e.Signals {
		if !recognisedSignals[sig] {
			e.Unrecognised = append(e.Unrecognised, "signal "+sig)
		}
	}
	for _, tag := range e.CooldownTags {
		known := false
		for _, p := range recognisedTagPrefixes {
			if strings.HasPrefix(tag, p) {
				known = true
				break
			}
		}
		if !known {
			e.Unrecognised = append(e.Unrecognised, "cooldown tag "+tag)
		}
	}

	if len(e.Classifications) == 0 {
		e.Absent = append(e.Absent,
			"failures: none recorded — nobody has hit a classified failure on this relay "+
				"inside the window, so there is no failure to rotate away from")
		e.AbsentCodes = append(e.AbsentCodes, AbsentNoFailures)
	}
	if len(e.CooldownTags) == 0 {
		e.Absent = append(e.Absent,
			"cooldown tags: no producer — nothing in Daal attributes a cooldown to a shared "+
				"risk tag (public_ip:*, public_asn:*, public_provider:*), so the rungs that need "+
				"that attribution cannot fire from measured data. Their absence is not evidence "+
				"that the ASN or the provider is fine")
		e.AbsentCodes = append(e.AbsentCodes, AbsentNoCooldownProducer)
	}
	var missingProbes []string
	for _, sig := range probeDerivedSignals {
		if !s.signals[sig] {
			missingProbes = append(missingProbes, sig)
		}
	}
	if len(missingProbes) > 0 {
		e.Absent = append(e.Absent,
			"network signals "+strings.Join(missingProbes, ", ")+
				": no prober exists, so these are never present. Absent here means UNMEASURED, "+
				"not measured-negative")
		e.AbsentCodes = append(e.AbsentCodes, AbsentNoProber)
	}
	if s.source == "context" {
		e.Absent = append(e.Absent,
			"the recipient's own selector record: this ran on what the operator supplied, "+
				"which is why confidence cannot exceed medium")
		e.AbsentCodes = append(e.AbsentCodes, AbsentOperatorSupplied)
	}
	return e
}

// sortedKeys renders a set as a stable, sorted slice. Non-nil even when
// empty so the JSON carries [] rather than null and a renderer never
// has to distinguish the two.
func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// confidenceFor implements the data-source confidence cap:
//
//	Explanation source + concrete signal           => high
//	Explanation source + empty/default fallback    => low
//	Context source + operator-asserted credential  => medium
//	Context source + concrete signal               => medium
//	Context source + empty/default fallback        => low
//
// TWO CAPS BELOW THAT, both added in Wave 6 and both about the same
// thing: the cost of being wrong is not symmetric across the ladder.
//
//  1. A rung that DESTROYS the server is capped at medium unless the
//     evidence carries a shared-risk attribution. Every measured input
//     today is one route's classification on one device; "this route
//     got reset" is real evidence, and "therefore rebuild the relay in
//     another datacenter" is an inference several steps past it. High
//     confidence on a destroy is the single most expensive thing this
//     file can say, and provisioning has no rollback: a failed rebuild
//     leaves a second billing server and an SSH key that blocks the
//     retry.
//  2. An L3 recommended without an address-level attribution is capped
//     at medium too. The rung is cheap and reversible, so it is still
//     recommended (see rule 7) — but the tag that would prove the
//     address is the burned thing has no producer, and pretending
//     otherwise is how "high confidence" stops meaning anything.
func (s *signalSet) confidenceFor(level Level) Confidence {
	if !s.hasAnyInput() {
		return ConfidenceLow
	}
	c := ConfidenceMedium
	if s.source == "explanation" {
		c = ConfidenceHigh
		// L1 by way of "credential_leak" classification is medium
		// — the selector classifies but it can't strictly prove a
		// leak vs. a hostile re-auth.
		if level == L1 && s.classifications["credential_leak"] {
			c = ConfidenceMedium
		}
	}
	if c == ConfidenceHigh && alwaysDestroys(level) && !s.hasRiskAttribution() {
		c = ConfidenceMedium
	}
	if c == ConfidenceHigh && level == L3 && !s.hasTagPrefix("public_ip:") {
		c = ConfidenceMedium
	}
	return c
}

// hasRiskAttribution reports whether anything in the inputs attributes
// a failure to something SHARED — an ASN, a provider, a protocol family
// — rather than to one route. It is the difference between "this route
// broke" and "the thing this relay sits on is burned", and only the
// second justifies a rebuild at high confidence.
func (s *signalSet) hasRiskAttribution() bool {
	return s.hasTagPrefix("public_asn:") ||
		s.hasTagPrefix("public_provider:") ||
		s.hasTagPrefix("family:") ||
		s.hasTagPrefix("origin_family:")
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
