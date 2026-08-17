package selection

import (
	"encoding/json"

	"daal/bundle-go/phase"
)

// Phase is the spec-version cohort the decision was made under. Locked
// at FRP-3. Used to gate cdn_fronted rules (no-op at V1.5; live at
// V1.6+).
//
// This is an ALIAS of daal/bundle-go/phase.Phase, not a second
// declaration. It used to be its own `type Phase string` whose PostV2
// constant was spelled "post-V2" while the validator's was spelled
// "PostV2" — two types compared as strings, so nothing caught it. One
// type, one spelling, and the compiler enforces both.
type Phase = phase.Phase

const (
	PhaseV15    = phase.V15
	PhaseV16    = phase.V16
	PhaseV2     = phase.V2
	PhasePostV2 = phase.PostV2

	// CurrentPhase is what this build ships — the same constant the
	// importer validates with, so a decision can never be explained
	// under a phase the routes were not admitted under.
	CurrentPhase = phase.Current
)

// Explanation is the UI-binding contract. FRP-6 (recipient UX)
// renders this struct verbatim in EN/FA. Field names and JSON tags
// are LOCKED at FRP-3 and must not change without a spec_version
// bump on selection-v1.
//
// FRP-3 locks this JSON wire shape but does not modify core/abi.
// FRP-4/FRP-6 route it through the existing diagnostics export path.
type Explanation struct {
	// Picked candidate (route_id) and the reason in one sentence.
	Pick PickedCandidate `json:"pick"`

	// Shortlist actually raced (in race order).
	Shortlist []ShortlistEntry `json:"shortlist"`

	// Failures classified during this decision.
	Failures []FailureRecord `json:"failures"`

	// Cooldowns currently active that influenced this decision.
	ActiveCooldowns []CooldownEntry `json:"active_cooldowns"`

	// Network signals observed during the probe (selector-owned
	// vocabulary; see signals.go). Sorted lexicographically for
	// deterministic JSON output.
	NetworkSignals []string `json:"network_signals"`

	// Network-memory hint that influenced shortlisting (if any).
	MemoryHint *MemoryHint `json:"memory_hint,omitempty"`

	// Plain-language reason. Single sentence. Localizable. No
	// identifiers. Example: "Used REALITY because UDP is blocked
	// on this network."
	Reason string `json:"reason"`

	// Decision identifier (deterministic; for log correlation).
	DecisionID string `json:"decision_id"`

	// Phase in which the decision was made.
	Phase string `json:"phase"`
}

// PickedCandidate is the chosen route projected for UI consumption.
// All fields are best-effort: when the selector has no choice (e.g.
// empty candidate set), the struct may be zero-valued and the
// Reason field on Explanation explains why.
type PickedCandidate struct {
	RouteID      string `json:"route_id"`
	Family       string `json:"family"`
	ExposureMode string `json:"exposure_mode"`
	FamilyClass  string `json:"family_class"`
	ProbingRisk  string `json:"probing_risk_class"`
}

// ShortlistEntry is one slot in the staggered race. Position is
// 0-indexed (0 = leader). StartedAtMs is milliseconds after pipeline
// start; pre-FRP-3 callers may set 0. Outcome is one of
// {"success", "failed", "not_started"}.
type ShortlistEntry struct {
	RouteID     string `json:"route_id"`
	Position    int    `json:"position"`
	StartedAtMs int    `json:"started_at_ms"`
	Outcome     string `json:"outcome"`
}

// FailureRecord attributes one failure to a route + classification +
// optional risk-tag. Tag is the public_risk_tag (or origin_*) that
// drove the cooldown propagation, if any.
type FailureRecord struct {
	RouteID        string `json:"route_id"`
	Classification string `json:"classification"`
	Tag            string `json:"tag,omitempty"`
}

// CooldownEntry is one currently-active cooldown surfaced to the
// UI. ExpiresAtUnix is seconds-since-epoch. Reason is the
// NetworkSignal string that started it.
type CooldownEntry struct {
	Tag           string `json:"tag"`
	ExpiresAtUnix int64  `json:"expires_at_unix"`
	Reason        string `json:"reason"`
}

// MemoryHint records what the per-network memory store contributed
// to this decision. Signature is the canonical-sorted-comma-joined
// public_risk_tags string. Nil on the Explanation struct means "no
// memory was consulted or no entry matched".
type MemoryHint struct {
	Signature    string `json:"signature"`
	LastOutcome  string `json:"last_outcome"`
	LastSeenUnix int64  `json:"last_seen_unix"`
}

// NewExplanation returns a zero-valued Explanation with the given
// decision identifier and phase. Slice fields are pre-allocated to
// non-nil empty slices so JSON output never includes "null".
func NewExplanation(decisionID string, p Phase) *Explanation {
	return &Explanation{
		Shortlist:       []ShortlistEntry{},
		Failures:        []FailureRecord{},
		ActiveCooldowns: []CooldownEntry{},
		NetworkSignals:  []string{},
		DecisionID:      decisionID,
		Phase:           string(p),
	}
}

// MarshalCanonical encodes the Explanation as canonical JSON (sorted
// keys at every level via encoding/json). Test goldens are byte-stable
// across regenerations.
func (e *Explanation) MarshalCanonical() ([]byte, error) {
	return json.MarshalIndent(e, "", "  ")
}
