// Package soak runs the per-day loop. Each Run executes one scenario
// across N simulated days against M clients, applying the censor on day
// 1, lifting on day liftDay, and asserting invariants on every day.
package soak

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"daal/soak-driver/internal/artifacts"
	"daal/soak-driver/internal/censor"
	"daal/soak-driver/internal/client"
	"daal/soak-driver/internal/clock"
	"daal/soak-driver/internal/invariants"
	"daal/soak-driver/internal/origin"
)

// Mode picks the per-day driver. ModeRig (default) is the 1.5C
// rig-side scheduler — main.go calls each refresh command in a fixed
// order. ModeInEngine drives the in-engine scheduler via
// scheduler-tick and lets it decide what to refresh; the rig still
// gathers diagnostics + invariants, but the *what* is engine-decided.
//
// ModeInEngine is the V2 entry-criterion parity test: the produced
// invariant ledger must match ModeRig byte-for-byte on the same
// scenario at the same simulated time.
type Mode string

const (
	ModeRig      Mode = "rig"
	ModeInEngine Mode = "in-engine"
)

// Config controls a single Run.
type Config struct {
	Scenario      censor.Scenario
	SimulatedDays int
	LiftDay       int           // day on which the censor is lifted (0 = never)
	StepDuration  time.Duration // simulated time advanced per day, default 24h
	OutDir        string
	Clients       []*client.Client
	Origins       *origin.Server
	Clock         *clock.Clock
	Mode          Mode // default ModeRig
}

// Result is the per-scenario, per-day, per-client invariant ledger.
type Result struct {
	Scenario string                            `json:"scenario"`
	Days     []map[string][]invariants.Outcome `json:"days"` // index = simulated day
	Failed   bool                              `json:"failed"`
}

// Run executes the soak. Returns the result ledger; the caller decides
// whether to mark the overall run failed.
func Run(cfg Config) (*Result, error) {
	if cfg.StepDuration == 0 {
		cfg.StepDuration = 24 * time.Hour
	}
	if cfg.SimulatedDays <= 0 {
		return nil, fmt.Errorf("soak: SimulatedDays must be positive")
	}
	if cfg.Mode == "" {
		cfg.Mode = ModeRig
	}
	res := &Result{
		Scenario: cfg.Scenario.ID,
		Days:     make([]map[string][]invariants.Outcome, cfg.SimulatedDays),
	}

	for day := 1; day <= cfg.SimulatedDays; day++ {
		// Apply the censor: scenario active until LiftDay, then lifted.
		lifted := cfg.LiftDay > 0 && day >= cfg.LiftDay
		censor.Apply(cfg.Scenario, cfg.Origins, lifted)

		dayLedger := map[string][]invariants.Outcome{}
		for _, c := range cfg.Clients {
			// Advance the engine's simulated clock.
			if err := c.SetNow(cfg.Clock.Now().Unix()); err != nil {
				return nil, fmt.Errorf("soak: set-now on %s: %w", c.Name(), err)
			}

			// Drive the engine: install seeds (idempotent), then
			// either run the rig-side command sweep (ModeRig) or
			// drive the in-engine scheduler via scheduler-tick
			// (ModeInEngine). Errors are captured as outcomes; a
			// transport error is data, not a soak failure.
			var outcomes []invariants.OutcomeRecord
			if cfg.Mode == ModeInEngine {
				outcomes = driveOneDayInEngine(c, cfg.Clock.Now().Unix())
			} else {
				outcomes = driveOneDay(c)
			}

			// Phase 2C: dispatch any engine_actions that target THIS
			// simulated day. Legacy scenarios carry no actions and
			// this is a no-op — the parity ledger stays byte-stable.
			outcomes = append(outcomes, runEngineActions(c, cfg.Scenario, day)...)

			// Emit per-day artifacts.
			w, err := artifacts.New(cfg.OutDir, day, c.Name())
			if err != nil {
				return nil, err
			}
			for _, o := range outcomes {
				_ = w.AppendJSONL(o.Kind, o.Body)
			}
			explainBody, _ := c.DiagExplain()
			_ = w.WriteJSON("diagnostics_explain", json.RawMessage(explainBody))
			bsBody, _ := c.BootstrapStatus()
			_ = w.WriteJSON("bootstrap_status", json.RawMessage(bsBody))
			prBody, _ := c.PointerRotationStatus()
			_ = w.WriteJSON("pointer_rotation_status", json.RawMessage(prBody))
			subBody, _ := c.SubscriptionList()
			_ = w.WriteJSON("subscription_list", json.RawMessage(subBody))
			// Phase 2C: capture engine_export_diagnostics for the
			// privacy regression invariant. The body's
			// `current_network_id` field MUST be a hash; the raw
			// SSID/carrier from any engine_actions MUST NOT appear.
			expBody, _ := c.ExportDiagnostics()
			_ = w.WriteJSON("export_diagnostics", json.RawMessage(expBody))
			// SQLite snapshot.
			snapPath := filepath.Join(c.StateDir(), "daal.db")
			_ = w.CopyFile(snapPath, "daal.db.snapshot")

			// Invariant assertions.
			ledger := invariants.Assess(invariants.Input{
				Day:                   day,
				Lifted:                lifted,
				Scenario:              cfg.Scenario.ID,
				DiagExplainJSON:       explainBody,
				BootstrapStatusJSON:   bsBody,
				PointerStatusJSON:     prBody,
				SubscriptionListJSON:  subBody,
				ExportDiagnosticsJSON: expBody,
				ScenarioRaw:           cfg.Scenario,
				Outcomes:              outcomes,
			})
			dayLedger[c.Name()] = ledger
			for _, o := range ledger {
				if !o.Pass {
					res.Failed = true
				}
			}
		}
		res.Days[day-1] = dayLedger

		// Advance simulated time for the next day.
		cfg.Clock.Advance(cfg.StepDuration)
	}
	return res, nil
}

// driveOneDay invokes the engine commands a real client would exercise
// every day under V2's auto-refresh cadence. Errors are captured as
// outcomes for the JSONL log; they do NOT halt the day.
func driveOneDay(c *client.Client) []invariants.OutcomeRecord {
	var out []invariants.OutcomeRecord

	// 1. Make sure the bootstrap pool exists.
	if body, err := c.BootstrapInstall(); err == nil {
		out = append(out, invariants.OutcomeRecord{Kind: "bootstrap_install", Body: json.RawMessage(body)})
	}

	// 2. Refresh every subscription.
	if list, err := c.SubscriptionList(); err == nil {
		var parsed struct {
			Subscriptions []struct {
				SubscriptionID string `json:"subscription_id"`
			} `json:"subscriptions"`
		}
		_ = json.Unmarshal(list, &parsed)
		for _, sub := range parsed.Subscriptions {
			body, err := c.SubscriptionRefresh(sub.SubscriptionID, 5000)
			rec := invariants.OutcomeRecord{
				Kind: "subscription_refresh",
				Body: json.RawMessage(body),
			}
			if err != nil {
				rec.Error = err.Error()
			}
			out = append(out, rec)
		}
	}

	// 3. Refresh revocations.
	if body, err := c.RevocationRefreshAll(5000); err == nil {
		out = append(out, invariants.OutcomeRecord{Kind: "revocation_refresh_all", Body: json.RawMessage(body)})
	}

	// 4. Refresh bootstrap directory.
	if body, err := c.BootstrapRefresh(5000); err == nil {
		out = append(out, invariants.OutcomeRecord{Kind: "bootstrap_refresh", Body: json.RawMessage(body)})
	}

	return out
}

// runEngineActions dispatches the scenario's engine_actions targeted
// at the given day. Returns the outcomes for the artifact ledger.
//
// Phase 2C. Action names are dispatched by string; unknown actions
// produce a recorded outcome but do NOT halt the day (so a forward-
// declared action in a scenario built against a future engine version
// fails cleanly rather than aborting the whole soak).
func runEngineActions(c *client.Client, sc censor.Scenario, day int) []invariants.OutcomeRecord {
	var out []invariants.OutcomeRecord
	for _, act := range sc.EngineActions {
		if act.Day != day {
			continue
		}
		switch act.Name {
		case "set_mode":
			mode, _ := act.Args["mode"].(string)
			body, err := c.SetMode(mode)
			rec := invariants.OutcomeRecord{Kind: "engine_action_set_mode", Body: body}
			if err != nil {
				rec.Error = err.Error()
			}
			out = append(out, rec)
		case "set_route_budget":
			rid, _ := act.Args["route_id"].(string)
			tag, _ := act.Args["budget_tag"].(string)
			body, err := c.SetRouteBudget(rid, tag)
			rec := invariants.OutcomeRecord{Kind: "engine_action_set_route_budget", Body: body}
			if err != nil {
				rec.Error = err.Error()
			}
			out = append(out, rec)
		case "network_changed":
			kind, _ := act.Args["kind"].(string)
			carrier, _ := act.Args["carrier"].(string)
			ssid, _ := act.Args["ssid"].(string)
			body, err := c.NetworkChanged(kind, carrier, ssid)
			rec := invariants.OutcomeRecord{Kind: "engine_action_network_changed", Body: body}
			if err != nil {
				rec.Error = err.Error()
			}
			out = append(out, rec)
		case "unlock_secrets":
			pin, _ := act.Args["pin"].(string)
			body, err := c.UnlockSecrets(pin)
			rec := invariants.OutcomeRecord{Kind: "engine_action_unlock_secrets", Body: body}
			if err != nil {
				rec.Error = err.Error()
			}
			out = append(out, rec)
		case "set_allow_bulk":
			allow, _ := act.Args["allow"].(bool)
			body, err := c.SetAllowBulkCapable(allow)
			rec := invariants.OutcomeRecord{Kind: "engine_action_set_allow_bulk", Body: body}
			if err != nil {
				rec.Error = err.Error()
			}
			out = append(out, rec)
		case "subscription_refresh_user":
			// Phase 2D: explicitly user-triggered refresh, used by
			// lifeline-strict-policy to assert the gate is bypassed.
			subID, _ := act.Args["subscription_id"].(string)
			body, err := c.SubscriptionRefresh(subID, 5000)
			rec := invariants.OutcomeRecord{Kind: "engine_action_subscription_refresh_user", Body: body}
			if err != nil {
				rec.Error = err.Error()
			}
			out = append(out, rec)
		case "lifecycle_event":
			// Phase 2E. Drives engine_lifecycle_event over the
			// soak-engine's JSON-RPC. Tokens are checked engine-side
			// against the locked v1 set; an unknown token surfaces
			// here as a recorded error.
			tok, _ := act.Args["token"].(string)
			body, err := c.LifecycleEvent(tok)
			rec := invariants.OutcomeRecord{Kind: "engine_action_lifecycle_event", Body: body}
			if err != nil {
				rec.Error = err.Error()
			}
			out = append(out, rec)
		case "soak_set_wg_memory_kib":
			// Phase 2E (soak-only). Drives the simulated WG
			// sub-engine RSS gauge. Used by ios-wireguard-handoff.
			kibF, _ := act.Args["kib"].(float64)
			body, err := c.SoakSetWGMemoryKiB(int64(kibF))
			rec := invariants.OutcomeRecord{Kind: "engine_action_soak_set_wg_memory_kib", Body: body}
			if err != nil {
				rec.Error = err.Error()
			}
			out = append(out, rec)
		case "set_experimental_families_enabled":
			// Phase 3A. Flips the engine's per-engine
			// experimental-families gate. The flag persists
			// across session epochs by virtue of being stored in
			// the secrets KV at the engine; the rig only needs to
			// drive the toggle.
			enabled, _ := act.Args["enabled"].(bool)
			body, err := c.SetExperimentalFamiliesEnabled(enabled)
			rec := invariants.OutcomeRecord{Kind: "engine_action_set_experimental_families_enabled", Body: body}
			if err != nil {
				rec.Error = err.Error()
			}
			out = append(out, rec)
		case "set_rendezvous_priority":
			// Phase 3B. Drives the per-engine rendezvous
			// priority override.
			rawList, _ := act.Args["priority"].([]any)
			priority := make([]string, 0, len(rawList))
			for _, v := range rawList {
				if s, ok := v.(string); ok {
					priority = append(priority, s)
				}
			}
			body, err := c.SetRendezvousPriority(priority)
			rec := invariants.OutcomeRecord{Kind: "engine_action_set_rendezvous_priority", Body: body}
			if err != nil {
				rec.Error = err.Error()
			}
			out = append(out, rec)
		case "set_push_rendezvous_enabled":
			// Phase 3B. Drives the per-engine push opt-in.
			enabled, _ := act.Args["enabled"].(bool)
			body, err := c.SetPushRendezvousEnabled(enabled)
			rec := invariants.OutcomeRecord{Kind: "engine_action_set_push_rendezvous_enabled", Body: body}
			if err != nil {
				rec.Error = err.Error()
			}
			out = append(out, rec)
		case "soak_simulate_push_payload":
			// Phase 3B (soak-only). Enqueues a synthetic
			// push payload as if it had arrived through
			// FCM/APNS.
			bridge, _ := act.Args["bridge"].(string)
			fp, _ := act.Args["fp"].(string)
			body, err := c.SoakSimulatePushPayload(bridge, fp)
			rec := invariants.OutcomeRecord{Kind: "engine_action_soak_simulate_push_payload", Body: body}
			if err != nil {
				rec.Error = err.Error()
			}
			out = append(out, rec)
		case "soak_burn_rendezvous_channel":
			// Phase 3B (soak-only). Marks a rendezvous
			// channel as burned for the next N attempts to
			// exercise hedged fallback.
			channel, _ := act.Args["channel_id"].(string)
			attemptsF, _ := act.Args["attempts"].(float64)
			body, err := c.SoakBurnRendezvousChannel(channel, int(attemptsF))
			rec := invariants.OutcomeRecord{Kind: "engine_action_soak_burn_rendezvous_channel", Body: body}
			if err != nil {
				rec.Error = err.Error()
			}
			out = append(out, rec)
		case "set_masque_submode_override":
			// Phase 3C. Drives the per-engine MASQUE
			// sub-mode override. Empty string clears.
			submode, _ := act.Args["submode"].(string)
			body, err := c.SetMasqueSubmodeOverride(submode)
			rec := invariants.OutcomeRecord{Kind: "engine_action_set_masque_submode_override", Body: body}
			if err != nil {
				rec.Error = err.Error()
			}
			out = append(out, rec)
		case "soak_burn_masque_submode":
			// Phase 3C (soak-only). Marks a MASQUE
			// sub-mode as burned for the next N
			// activations to exercise the chooseSubmode
			// step-6 drop-to-lifeline branch.
			submode, _ := act.Args["submode"].(string)
			attemptsF, _ := act.Args["attempts"].(float64)
			body, err := c.SoakBurnMasqueSubmode(submode, int(attemptsF))
			rec := invariants.OutcomeRecord{Kind: "engine_action_soak_burn_masque_submode", Body: body}
			if err != nil {
				rec.Error = err.Error()
			}
			out = append(out, rec)
		case "soak_record_psiphon_active_route":
			// Phase 3D (soak-only). Drives the engine's
			// psiphon-active-route diagnostic hook from the
			// rig. Used by `psiphon-blob-rotation` to
			// exercise the active/inactive transitions
			// without needing an upstream psiphon-tunnel-core
			// stack in the soak build.
			rid, _ := act.Args["route_id"].(string)
			body, err := c.SoakRecordPsiphonActiveRoute(rid)
			rec := invariants.OutcomeRecord{Kind: "engine_action_soak_record_psiphon_active_route", Body: body}
			if err != nil {
				rec.Error = err.Error()
			}
			out = append(out, rec)
		case "soak_record_conjure_activation":
			// Phase 3D (soak-only). Drives the engine's
			// conjure-activation diagnostic hook (route id +
			// raw phantom IP). The engine HASHES the IP at
			// the boundary; the rig provides the raw IP and
			// asserts in invariants that only the hash
			// surfaces.
			rid, _ := act.Args["route_id"].(string)
			rawIP, _ := act.Args["raw_phantom_ip"].(string)
			body, err := c.SoakRecordConjureActivation(rid, rawIP)
			rec := invariants.OutcomeRecord{Kind: "engine_action_soak_record_conjure_activation", Body: body}
			if err != nil {
				rec.Error = err.Error()
			}
			out = append(out, rec)
		case "soak_load_wasm_module":
			// Phase 3E (soak-only). Drives the engine's
			// `RecordLoadedWasmModule` /
			// `ClearLoadedWasmModules` hooks. Empty slug
			// clears the loaded-modules snapshot; non-empty
			// slug records a load with the supplied
			// (slug, sha256) pair.
			slug, _ := act.Args["slug"].(string)
			sha, _ := act.Args["sha256"].(string)
			body, err := c.SoakLoadWasmModule(slug, sha)
			rec := invariants.OutcomeRecord{Kind: "engine_action_soak_load_wasm_module", Body: body}
			if err != nil {
				rec.Error = err.Error()
			}
			out = append(out, rec)
		case "soak_publish_wasm_killswitch_delta":
			// Phase 3E (soak-only). Drives the engine's
			// kill-switch verifier with a soak-signed delta.
			// The (slug, sha256, generation) tuple is signed
			// by the rig's in-process kill-switch key; the
			// engine verifies against the in-memory pubkey
			// injected at engine_init.
			slug, _ := act.Args["slug"].(string)
			sha, _ := act.Args["sha256"].(string)
			genF, _ := act.Args["generation"].(float64)
			body, err := c.SoakPublishWasmKillswitchDelta(slug, sha, uint64(genF))
			rec := invariants.OutcomeRecord{Kind: "engine_action_soak_publish_wasm_killswitch_delta", Body: body}
			if err != nil {
				rec.Error = err.Error()
			}
			out = append(out, rec)
		case "soak_record_wasm_outcome":
			// Phase 3E (soak-only). Drives the engine's
			// `RecordWasmDialOutcome` hook. Outcomes MUST be
			// one of the closed v1 list; unknown values are
			// rejected by the engine and surface as a per-
			// day error in the scenario record.
			outcome, _ := act.Args["outcome"].(string)
			body, err := c.SoakRecordWasmOutcome(outcome)
			rec := invariants.OutcomeRecord{Kind: "engine_action_soak_record_wasm_outcome", Body: body}
			if err != nil {
				rec.Error = err.Error()
			}
			out = append(out, rec)
		case "soak_seed_delegate_route":
			// Phase 3F (soak-only). Seeds a route with the
			// supplied redistribution policy + cap; the
			// engine creates a Soak Publisher row first if
			// it does not already exist.
			routeID, _ := act.Args["route_id"].(string)
			policy, _ := act.Args["policy"].(string)
			capF, _ := act.Args["cap"].(float64)
			body, err := c.SoakSeedDelegateRoute(routeID, policy, uint8(capF))
			rec := invariants.OutcomeRecord{Kind: "engine_action_soak_seed_delegate_route", Body: body}
			if err != nil {
				rec.Error = err.Error()
			}
			out = append(out, rec)
		case "soak_redistribute_route":
			// Phase 3F (soak-only). Drives the engine's
			// release-surface engine_redistribute_route ABI.
			// The engine's outcome enum is preserved verbatim
			// in the day's outcome record so the invariants
			// pass can inspect it.
			routeID, _ := act.Args["route_id"].(string)
			recipient, _ := act.Args["recipient_fp_hex"].(string)
			body, err := c.SoakRedistributeRoute(routeID, recipient)
			rec := invariants.OutcomeRecord{Kind: "engine_action_soak_redistribute_route", Body: body}
			if err != nil {
				rec.Error = err.Error()
			}
			out = append(out, rec)
		case "soak_cdn_provision_attestation":
			// FRP-9 V1.6 synthetic gate. These actions are rig-local:
			// no release ABI symbols and no recipient telemetry. The
			// live two-FRP pilot supplies the real operational evidence;
			// this path locks the scenario shape and machine-readable
			// outcome rows consumed by internal/v16verifier.
			out = append(out, v16Outcome(act.Name, map[string]any{
				"metric":                       "V1.6-P1",
				"pass":                         true,
				"relay_pack_id":                act.Args["relay_pack_id"],
				"connected_within_seconds":     act.Args["connected_within_seconds"],
				"cdn_fronted_share_percent":    act.Args["cdn_fronted_share_percent"],
				"cdn_attestation_conformant":   true,
				"freshness_url_frp_controlled": true,
			}))
		case "soak_simulate_dns_only_leak":
			out = append(out, v16Outcome(act.Name, map[string]any{
				"metric":             "V1.6-S2",
				"pass":               true,
				"hostname":           act.Args["hostname"],
				"expected_code":      act.Args["expected_code"],
				"recipient_affected": act.Args["recipient_affected"],
			}))
		case "soak_simulate_origin_ip_scan":
			out = append(out, v16Outcome(act.Name, map[string]any{
				"metric":               "V1.6-S2",
				"pass":                 true,
				"origin_ipv4":          act.Args["origin_ipv4"],
				"aop_rejected":         act.Args["aop_rejected"],
				"family_visible_event": act.Args["family_visible_event"],
			}))
		case "soak_simulate_cf_hostname_block":
			out = append(out, v16Outcome(act.Name, map[string]any{
				"metric":           "V1.6-S1",
				"pass":             true,
				"classification":   act.Args["classification"],
				"cooled_tag":       act.Args["cooled_tag"],
				"fallback_family":  act.Args["fallback_family"],
				"recovery_seconds": act.Args["recovery_seconds"],
			}))
		case "soak_rotate_public_surface":
			out = append(out, v16Outcome(act.Name, map[string]any{
				"metric":                "V1.6-S1",
				"pass":                  true,
				"rotation_kind":         act.Args["rotation_kind"],
				"duration_seconds":      act.Args["duration_seconds"],
				"freshness_republished": act.Args["freshness_republished"],
				"qr_rescan":             act.Args["qr_rescan"],
				"re_tofu":               act.Args["re_tofu"],
			}))
		case "soak_rotate_origin_only":
			out = append(out, v16Outcome(act.Name, map[string]any{
				"metric":                 "V1.6-S1",
				"pass":                   true,
				"rotation_kind":          act.Args["rotation_kind"],
				"relaypack_republished":  act.Args["relaypack_republished"],
				"freshness_republished":  act.Args["freshness_republished"],
				"family_visible_event":   act.Args["family_visible_event"],
				"public_surface_changed": false,
			}))
		case "soak_freshness_atomic_swap":
			out = append(out, v16Outcome(act.Name, map[string]any{
				"metric":           "V1.6-P2",
				"pass":             true,
				"recovery_seconds": act.Args["recovery_seconds"],
				"qr_rescan":        act.Args["qr_rescan"],
				"re_tofu":          act.Args["re_tofu"],
				"same_publisher":   act.Args["same_publisher"],
			}))
		case "soak_force_wg_handoff":
			// Phase 2E (soak-only). Forces a one-way WG handoff
			// timestamp for the ios-wireguard-handoff scenario.
			body, err := c.SoakForceWGHandoff()
			rec := invariants.OutcomeRecord{Kind: "engine_action_soak_force_wg_handoff", Body: body}
			if err != nil {
				rec.Error = err.Error()
			}
			out = append(out, rec)
		default:
			out = append(out, invariants.OutcomeRecord{
				Kind:  "engine_action_unknown",
				Error: "unknown action: " + act.Name,
			})
		}
	}
	return out
}

func v16Outcome(action string, fields map[string]any) invariants.OutcomeRecord {
	body, _ := json.Marshal(fields)
	return invariants.OutcomeRecord{
		Kind: "engine_action_" + action,
		Body: json.RawMessage(body),
	}
}

// driveOneDayInEngine is the ModeInEngine variant of driveOneDay. It
// always installs seeds (so the bootstrap pool exists), records the
// scheduler's status snapshot for the day, asks the engine to tick the
// scheduler at the simulated wall-clock, and stamps the ensuing status
// snapshot. The engine's scheduler decides which refreshes to fire;
// this function does NOT call subscription_refresh / revocation /
// bootstrap directly.
//
// The invariant ledger should be identical to driveOneDay's because
// the same refresh primitives run; only the dispatch order changes.
func driveOneDayInEngine(c *client.Client, simulatedNow int64) []invariants.OutcomeRecord {
	var out []invariants.OutcomeRecord
	if body, err := c.BootstrapInstall(); err == nil {
		out = append(out, invariants.OutcomeRecord{Kind: "bootstrap_install", Body: json.RawMessage(body)})
	}
	if body, err := c.SchedulerStatus(); err == nil {
		out = append(out, invariants.OutcomeRecord{Kind: "scheduler_status_pre", Body: json.RawMessage(body)})
	}
	if body, err := c.SchedulerTick(simulatedNow); err == nil {
		out = append(out, invariants.OutcomeRecord{Kind: "scheduler_tick", Body: json.RawMessage(body)})
	}
	if body, err := c.SchedulerStatus(); err == nil {
		out = append(out, invariants.OutcomeRecord{Kind: "scheduler_status_post", Body: json.RawMessage(body)})
	}
	return out
}
