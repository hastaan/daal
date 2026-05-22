// Package invariants asserts the rules in
// `phases of development/10-phase-1-5c-blackout-soak.md` per simulated
// day per client. Each rule returns an Outcome; the soak run fails iff
// any Outcome.Pass is false.
package invariants

import (
	"encoding/json"
	"strings"

	"daal/soak-driver/internal/censor"
)

// OutcomeRecord is one engine call recorded during a simulated day.
type OutcomeRecord struct {
	Kind  string          `json:"kind"`
	Body  json.RawMessage `json:"body,omitempty"`
	Error string          `json:"error,omitempty"`
}

// Outcome is one invariant assertion result.
type Outcome struct {
	Rule   string `json:"rule"`
	Pass   bool   `json:"pass"`
	Detail string `json:"detail,omitempty"`
}

// Input is the per-day per-client snapshot fed to Assess.
type Input struct {
	Day                   int
	Lifted                bool
	Scenario              string
	DiagExplainJSON       json.RawMessage
	BootstrapStatusJSON   json.RawMessage
	PointerStatusJSON     json.RawMessage
	SubscriptionListJSON  json.RawMessage
	ExportDiagnosticsJSON json.RawMessage // Phase 2C: engine_export_diagnostics body
	ScenarioRaw           censor.Scenario // Phase 2C: full scenario shape for engine_actions context
	Outcomes              []OutcomeRecord
}

// Assess runs every rule and returns the ledger.
func Assess(in Input) []Outcome {
	return []Outcome{
		ruleEngineOK(in),
		ruleNoAuthFailedFromBlackout(in),
		ruleRefreshOutcomeMapped(in),
		rulePointerStatusShape(in),
		ruleNoFalsePositiveRevoke(in),
		ruleDiagExplainNonEmpty(in),
		ruleNoSSIDLeakInDiagnostics(in),
		ruleNoPINLeakInDiagnostics(in),
		ruleNoRawPhantomIPLeakInDiagnostics(in),
	}
}

// 9 (Phase 3D): Conjure phantom-IP no-leak. If the scenario
// carries any `soak_record_conjure_activation` engine_actions,
// the raw_phantom_ip string supplied to those actions MUST NOT
// appear anywhere in engine_export_diagnostics. The engine
// HASHES the IP at the boundary (8-byte SHA-256 truncation,
// hex-encoded) and only the hash may surface in
// `conjure_phantom_in_use`. This is the V0.1 + CC.6 privacy
// regression for the conjure family — same shape as the SSID +
// PIN no-leak invariants. See specs/conjure-route-v1.md
// "Diagnostics".
func ruleNoRawPhantomIPLeakInDiagnostics(in Input) Outcome {
	if len(in.ExportDiagnosticsJSON) == 0 {
		return Outcome{Rule: "no_raw_phantom_ip_leak_in_diagnostics", Pass: true}
	}
	body := string(in.ExportDiagnosticsJSON)
	for _, act := range in.ScenarioRaw.EngineActions {
		if act.Name != "soak_record_conjure_activation" {
			continue
		}
		raw, _ := act.Args["raw_phantom_ip"].(string)
		if raw != "" && strings.Contains(body, raw) {
			return Outcome{
				Rule:   "no_raw_phantom_ip_leak_in_diagnostics",
				Pass:   false,
				Detail: "raw phantom IP leaked into export_diagnostics: " + raw,
			}
		}
	}
	return Outcome{Rule: "no_raw_phantom_ip_leak_in_diagnostics", Pass: true}
}

// 8 (Phase 2D): PIN no-leak. If the scenario carries any
// `unlock_secrets` engine_actions, the raw PIN string supplied to
// those actions MUST NOT appear anywhere in
// engine_export_diagnostics. Mirrors ruleNoSSIDLeakInDiagnostics.
func ruleNoPINLeakInDiagnostics(in Input) Outcome {
	if len(in.ExportDiagnosticsJSON) == 0 {
		return Outcome{Rule: "no_pin_leak_in_diagnostics", Pass: true}
	}
	body := string(in.ExportDiagnosticsJSON)
	for _, act := range in.ScenarioRaw.EngineActions {
		if act.Name != "unlock_secrets" {
			continue
		}
		pin, _ := act.Args["pin"].(string)
		if pin != "" && strings.Contains(body, pin) {
			return Outcome{
				Rule:   "no_pin_leak_in_diagnostics",
				Pass:   false,
				Detail: "raw PIN leaked into export_diagnostics: " + pin,
			}
		}
	}
	return Outcome{Rule: "no_pin_leak_in_diagnostics", Pass: true}
}

// 7 (Phase 2C): the canonical V0.1 + CC.6 privacy regression. If
// the scenario carries network_changed engine_actions, NEITHER the
// raw SSID NOR the raw carrier strings supplied to those actions
// may appear anywhere in engine_export_diagnostics.
//
// The hashed `current_network_id` field IS expected to appear and
// is excluded from this check.
func ruleNoSSIDLeakInDiagnostics(in Input) Outcome {
	if len(in.ExportDiagnosticsJSON) == 0 {
		// Pre-2C build or scenario didn't capture: skip cleanly.
		return Outcome{Rule: "no_ssid_leak_in_diagnostics", Pass: true}
	}
	body := string(in.ExportDiagnosticsJSON)
	for _, act := range in.ScenarioRaw.EngineActions {
		if act.Name != "network_changed" {
			continue
		}
		ssid, _ := act.Args["ssid"].(string)
		carrier, _ := act.Args["carrier"].(string)
		if ssid != "" && strings.Contains(body, ssid) {
			return Outcome{
				Rule:   "no_ssid_leak_in_diagnostics",
				Pass:   false,
				Detail: "raw SSID leaked into export_diagnostics: " + ssid,
			}
		}
		if carrier != "" && strings.Contains(body, carrier) {
			return Outcome{
				Rule:   "no_ssid_leak_in_diagnostics",
				Pass:   false,
				Detail: "raw carrier leaked into export_diagnostics: " + carrier,
			}
		}
	}
	return Outcome{Rule: "no_ssid_leak_in_diagnostics", Pass: true}
}

// 1: any engine call must have produced parseable JSON, no panics.
func ruleEngineOK(in Input) Outcome {
	if !json.Valid(in.DiagExplainJSON) || !json.Valid(in.BootstrapStatusJSON) {
		return Outcome{Rule: "engine_responsive", Pass: false, Detail: "non-JSON response from engine"}
	}
	return Outcome{Rule: "engine_responsive", Pass: true}
}

// 2: the soak must NEVER observe `auth_failed` during a blackout.
//
//	auth_failed is reserved for actual server-side credential rejection
//	and must not cascade from network blackouts (CC.4).
func ruleNoAuthFailedFromBlackout(in Input) Outcome {
	for _, o := range in.Outcomes {
		if strings.Contains(string(o.Body), `"auth_failed"`) {
			return Outcome{
				Rule:   "no_auth_failed_from_blackout",
				Pass:   false,
				Detail: "auth_failed observed in " + o.Kind,
			}
		}
	}
	return Outcome{Rule: "no_auth_failed_from_blackout", Pass: true}
}

// 3: every refresh outcome string must be in {ok, subscription_unreachable,
//
//	bundle_corrupted, bundle_signature_invalid, skipped_lifeline_strict}.
//
// Phase 2D adds `skipped_lifeline_strict` — NOT a failure, just a
// "did not attempt" status emitted by the gated scheduler-driven
// path. See specs/failure-taxonomy-v1.md.
func ruleRefreshOutcomeMapped(in Input) Outcome {
	allowed := map[string]bool{
		"ok":                       true,
		"subscription_unreachable": true,
		"bundle_corrupted":         true,
		"bundle_signature_invalid": true,
		"skipped_lifeline_strict":  true, // 2D
		"":                         true, // bootstrap-status / list returns no outcome string
	}
	for _, o := range in.Outcomes {
		if o.Kind != "subscription_refresh" {
			continue
		}
		var parsed struct {
			Outcome string `json:"outcome"`
		}
		_ = json.Unmarshal(o.Body, &parsed)
		if !allowed[parsed.Outcome] {
			return Outcome{
				Rule:   "refresh_outcome_mapped",
				Pass:   false,
				Detail: "unmapped subscription_refresh outcome: " + parsed.Outcome,
			}
		}
	}
	return Outcome{Rule: "refresh_outcome_mapped", Pass: true}
}

// 4: pointer-rotation-status must be a JSON object with the documented
//
//	fields (have_persisted, primary_source, fallback_source).
func rulePointerStatusShape(in Input) Outcome {
	var parsed map[string]any
	if err := json.Unmarshal(in.PointerStatusJSON, &parsed); err != nil {
		return Outcome{Rule: "pointer_status_shape", Pass: false, Detail: err.Error()}
	}
	for _, k := range []string{"have_persisted", "primary_source", "fallback_source"} {
		if _, ok := parsed[k]; !ok {
			return Outcome{
				Rule:   "pointer_status_shape",
				Pass:   false,
				Detail: "missing field: " + k,
			}
		}
	}
	return Outcome{Rule: "pointer_status_shape", Pass: true}
}

// 5: a missed revocation refresh must NEVER set trust_state=revoked
//
//	on existing routes. We assert this indirectly: under the
//	publisher-revocation-url-unreachable scenario, the outcome from
//	revocation_refresh_all must be "subscription_unreachable" (or its
//	moral equivalent: the per-publisher entry shows
//	"subscription_unreachable") but no subscription's outcome should
//	be "publisher_revoked" as a side-effect.
func ruleNoFalsePositiveRevoke(in Input) Outcome {
	if in.Scenario != "publisher-revocation-url-unreachable" {
		return Outcome{Rule: "no_false_positive_revocation", Pass: true}
	}
	for _, o := range in.Outcomes {
		if strings.Contains(string(o.Body), `"publisher_revoked"`) {
			return Outcome{
				Rule:   "no_false_positive_revocation",
				Pass:   false,
				Detail: "publisher_revoked seen during revocation blackout",
			}
		}
	}
	return Outcome{Rule: "no_false_positive_revocation", Pass: true}
}

// 6: diag-explain.why_chose_route must be non-empty after blackout
//
//	starts (the FSM should have *some* reason).
func ruleDiagExplainNonEmpty(in Input) Outcome {
	var parsed struct {
		WhyChoseRoute string `json:"why_chose_route"`
	}
	if err := json.Unmarshal(in.DiagExplainJSON, &parsed); err != nil {
		return Outcome{Rule: "diag_explain_non_empty", Pass: false, Detail: err.Error()}
	}
	if parsed.WhyChoseRoute == "" {
		return Outcome{Rule: "diag_explain_non_empty", Pass: false, Detail: "why_chose_route empty"}
	}
	return Outcome{Rule: "diag_explain_non_empty", Pass: true}
}
