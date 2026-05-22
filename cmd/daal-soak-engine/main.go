// daal-soak-engine is a Phase 1.5C developer tool. It is a long-lived
// child process the soak driver spawns once per simulated client. The
// driver pipes line-delimited JSON commands on stdin and reads
// line-delimited JSON responses on stdout. The binary itself is
// stdlib-only and binds to the same `daal/core/abi` package the
// release CLI uses, so the engine state machine under test is byte-
// identical to release.
//
// Build with `-tags soak` to enable the `set-now` command, which
// overrides the engine's `time.Now()` for every subsequent ABI call.
// Without `-tags soak`, the binary refuses `set-now` with
// `{"error":"set-now requires -tags soak"}`.
//
// This binary is NEVER shipped to users.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"time"

	"daal/core/abi"
)

type request struct {
	ID  string          `json:"id"`
	Cmd string          `json:"cmd"`
	Arg json.RawMessage `json:"arg,omitempty"`
}

type response struct {
	ID    string          `json:"id"`
	OK    bool            `json:"ok"`
	Body  json.RawMessage `json:"body,omitempty"`
	Error string          `json:"error,omitempty"`
}

func main() {
	stateDir := os.Getenv("DAAL_SOAK_STATE_DIR")
	if stateDir == "" {
		fmt.Fprintln(os.Stderr, "soak-engine: DAAL_SOAK_STATE_DIR is required")
		os.Exit(2)
	}
	if err := abi.Init(stateDir, "warn"); err != nil {
		fmt.Fprintln(os.Stderr, "soak-engine: init:", err)
		os.Exit(1)
	}
	defer abi.Shutdown()

	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<16), 1<<22)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()

	for in.Scan() {
		line := in.Bytes()
		if len(line) == 0 {
			continue
		}
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			writeResp(out, response{Error: "bad request: " + err.Error()})
			continue
		}
		resp := dispatch(req)
		writeResp(out, resp)
	}
	if err := in.Err(); err != nil && err != io.EOF {
		fmt.Fprintln(os.Stderr, "soak-engine: stdin:", err)
		os.Exit(1)
	}
}

func writeResp(out *bufio.Writer, r response) {
	body, _ := json.Marshal(r)
	body = append(body, '\n')
	out.Write(body)
	out.Flush()
}

func dispatch(req request) response {
	switch req.Cmd {
	case "version":
		body, _ := json.Marshal(abi.VersionString())
		return response{ID: req.ID, OK: true, Body: body}
	case "set-now":
		return setNow(req)
	case "subscription-add":
		var a struct {
			PublisherFP string `json:"publisher_fp"`
			URL         string `json:"url"`
			DisplayName string `json:"display_name"`
		}
		if err := json.Unmarshal(req.Arg, &a); err != nil {
			return response{ID: req.ID, Error: err.Error()}
		}
		body, err := abi.SubscriptionAdd(a.PublisherFP, a.URL, a.DisplayName)
		return wrap(req.ID, body, err)
	case "subscription-refresh":
		var a struct {
			SubscriptionID string `json:"subscription_id"`
			TimeoutMs      int    `json:"timeout_ms"`
		}
		if err := json.Unmarshal(req.Arg, &a); err != nil {
			return response{ID: req.ID, Error: err.Error()}
		}
		body, err := abi.SubscriptionRefresh(a.SubscriptionID, a.TimeoutMs)
		return wrap(req.ID, body, err)
	case "subscription-list":
		body, err := abi.SubscriptionList()
		return wrap(req.ID, body, err)
	case "subscription-remove":
		var a struct {
			SubscriptionID string `json:"subscription_id"`
		}
		if err := json.Unmarshal(req.Arg, &a); err != nil {
			return response{ID: req.ID, Error: err.Error()}
		}
		err := abi.SubscriptionRemove(a.SubscriptionID)
		return wrap(req.ID, "", err)
	case "revocation-refresh-all":
		var a struct {
			TimeoutMs int `json:"timeout_ms"`
		}
		_ = json.Unmarshal(req.Arg, &a)
		body, err := abi.RevocationRefreshAll(a.TimeoutMs)
		return wrap(req.ID, body, err)
	case "bootstrap-install":
		body, err := abi.BootstrapInstallSeeds()
		return wrap(req.ID, body, err)
	case "bootstrap-refresh":
		var a struct {
			TimeoutMs int `json:"timeout_ms"`
		}
		_ = json.Unmarshal(req.Arg, &a)
		body, err := abi.BootstrapRefresh(a.TimeoutMs)
		return wrap(req.ID, body, err)
	case "bootstrap-status":
		body, err := abi.BootstrapStatus()
		return wrap(req.ID, body, err)
	case "pointer-rotation-status":
		body, err := abi.PointerRotationStatus()
		return wrap(req.ID, body, err)
	case "diag-explain":
		body, err := abi.DiagnosticsExplain()
		return wrap(req.ID, body, err)
	case "export-diagnostics":
		body, err := abi.ExportDiagnostics()
		return wrap(req.ID, body, err)
	case "set-route-budget":
		// Phase 2A. Validates against the closed cap map; rejection
		// returns a body with {"error":"unknown_budget_tag",...}.
		var a struct {
			RouteID   string `json:"route_id"`
			BudgetTag string `json:"budget_tag"`
		}
		if err := json.Unmarshal(req.Arg, &a); err != nil {
			return response{ID: req.ID, Error: err.Error()}
		}
		body, err := abi.SetRouteBudget(a.RouteID, a.BudgetTag)
		return wrap(req.ID, body, err)
	case "set-mode":
		// Phase 2B / 2C / 2D. Accepts
		// {lifeline, lifeline-strict, normal, bulk}.
		var a struct {
			Mode string `json:"mode"`
		}
		if err := json.Unmarshal(req.Arg, &a); err != nil {
			return response{ID: req.ID, Error: err.Error()}
		}
		err := abi.SetMode(a.Mode)
		return wrap(req.ID, "", err)
	case "unlock-secrets":
		// Phase 2D. Drives the Argon2id PIN-vault. Under the
		// keystore storage profile this returns an error wrapping
		// ErrVaultProfileNotEnabled; the soak rig uses that error
		// as a signal that the no-op path was hit (the driver
		// passes the error to the invariant ledger as data).
		var a struct {
			PIN string `json:"pin"`
		}
		if err := json.Unmarshal(req.Arg, &a); err != nil {
			return response{ID: req.ID, Error: err.Error()}
		}
		err := abi.UnlockSecrets(a.PIN)
		return wrap(req.ID, "", err)
	case "set-allow-bulk":
		// Phase 2D. Sets the engine's per-session bulk-capable
		// opt-in flag for lifeline-strict.
		var a struct {
			Allow bool `json:"allow"`
		}
		if err := json.Unmarshal(req.Arg, &a); err != nil {
			return response{ID: req.ID, Error: err.Error()}
		}
		// Reach the budget engine through the lazy ensureBudget
		// path: SetRouteBudget on a placeholder tags a route, but
		// here we just want to flip the flag. The simplest path is
		// to expose the setter via a thin abi function — we call
		// SetAllowBulkCapable below.
		abi.SetAllowBulkCapable(a.Allow)
		return wrap(req.ID, "", nil)
	case "network-changed":
		// Phase 2C. Hashes (kind, carrier, ssid) on entry and swaps
		// the engine's per-network state. Returns the JSON status
		// blob containing the hashed network ID.
		var a struct {
			Kind    string `json:"kind"`
			Carrier string `json:"carrier"`
			SSID    string `json:"ssid"`
		}
		if err := json.Unmarshal(req.Arg, &a); err != nil {
			return response{ID: req.ID, Error: err.Error()}
		}
		body, err := abi.NetworkChanged(a.Kind, a.Carrier, a.SSID)
		return wrap(req.ID, body, err)
	case "scheduler-status":
		body, err := abi.SchedulerStatus()
		return wrap(req.ID, body, err)
	case "lifecycle-event":
		// Phase 2E. The Swift bridge calls engine_lifecycle_event
		// once per NE state transition; the soak rig drives the
		// same Go function over JSON-RPC for the
		// `ios-extension-memory` and `ios-wireguard-handoff`
		// scenarios. Tokens are checked against the locked v1 set
		// (will_sleep / did_wake / memory_pressure_warning); an
		// unknown token is reported back to the rig as an error.
		var a struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(req.Arg, &a); err != nil {
			return response{ID: req.ID, Error: err.Error()}
		}
		if err := abi.LifecycleEvent(a.Token); err != nil {
			return wrap(req.ID, "", err)
		}
		return wrap(req.ID, "", nil)
	case "soak-set-wg-memory-kib":
		// Phase 2E soak knob; only meaningful under `-tags soak`.
		// On a release build, abi.SetWGMemoryKiB is not compiled
		// in and the call is a typed compile error. The soak
		// engine binary is always built with -tags soak so this
		// branch is always live here.
		var a struct {
			KiB int64 `json:"kib"`
		}
		if err := json.Unmarshal(req.Arg, &a); err != nil {
			return response{ID: req.ID, Error: err.Error()}
		}
		abi.SetWGMemoryKiB(a.KiB)
		return wrap(req.ID, "", nil)
	case "soak-force-wg-handoff":
		// Phase 2E soak knob; -tags soak only.
		abi.ForceWGHandoff()
		return wrap(req.ID, "", nil)
	case "set-experimental-families-enabled":
		// Phase 3A. The Swift / Kotlin bridge calls
		// engine_set_experimental_families_enabled to flip the
		// per-engine experimental-families gate; the soak rig
		// drives the same flag over JSON-RPC for the
		// `experimental-gate-respected` and `webtunnel-handshake`
		// scenarios. Persists across session epochs (the engine
		// re-reads the flag from secrets KV at Init).
		var a struct {
			Enabled bool `json:"enabled"`
		}
		if err := json.Unmarshal(req.Arg, &a); err != nil {
			return response{ID: req.ID, Error: err.Error()}
		}
		abi.SetExperimentalFamiliesEnabled(a.Enabled)
		return wrap(req.ID, "", nil)
	case "set-rendezvous-priority":
		// Phase 3B. Drives the per-engine rendezvous priority
		// override.
		var a struct {
			Priority []string `json:"priority"`
		}
		if err := json.Unmarshal(req.Arg, &a); err != nil {
			return response{ID: req.ID, Error: err.Error()}
		}
		if rc := abi.SetRendezvousPriority(a.Priority); rc != 0 {
			return response{ID: req.ID, Error: rcError(rc)}
		}
		return wrap(req.ID, "", nil)
	case "set-push-rendezvous-enabled":
		// Phase 3B. Drives the per-engine push opt-in.
		var a struct {
			Enabled bool `json:"enabled"`
		}
		if err := json.Unmarshal(req.Arg, &a); err != nil {
			return response{ID: req.ID, Error: err.Error()}
		}
		if rc := abi.SetPushRendezvousEnabled(a.Enabled); rc != 0 {
			return response{ID: req.ID, Error: rcError(rc)}
		}
		return wrap(req.ID, "", nil)
	case "soak-burn-rendezvous-channel":
		// Phase 3B (soak-only).
		var a struct {
			ChannelID string `json:"channel_id"`
			Attempts  int    `json:"attempts"`
		}
		if err := json.Unmarshal(req.Arg, &a); err != nil {
			return response{ID: req.ID, Error: err.Error()}
		}
		abi.MarkRendezvousChannelBurned(a.ChannelID, a.Attempts)
		return wrap(req.ID, "", nil)
	case "soak-simulate-push-payload":
		// Phase 3B (soak-only).
		var a struct {
			Bridge string `json:"bridge"`
			FP     string `json:"fp"`
		}
		if err := json.Unmarshal(req.Arg, &a); err != nil {
			return response{ID: req.ID, Error: err.Error()}
		}
		abi.SimulatePushPayload(a.Bridge, a.FP)
		return wrap(req.ID, "", nil)
	case "set-masque-submode-override":
		// Phase 3C. Drives the per-engine MASQUE sub-mode
		// override. Empty string clears (auto cascade).
		var a struct {
			Submode string `json:"submode"`
		}
		if err := json.Unmarshal(req.Arg, &a); err != nil {
			return response{ID: req.ID, Error: err.Error()}
		}
		if rc := abi.SetMasqueSubmodeOverride(a.Submode); rc != 0 {
			return response{ID: req.ID, Error: rcError(rc)}
		}
		return wrap(req.ID, "", nil)
	case "soak-burn-masque-submode":
		// Phase 3C (soak-only).
		var a struct {
			Submode  string `json:"submode"`
			Attempts int    `json:"attempts"`
		}
		if err := json.Unmarshal(req.Arg, &a); err != nil {
			return response{ID: req.ID, Error: err.Error()}
		}
		abi.MarkMasqueSubmodeBurned(a.Submode, a.Attempts)
		return wrap(req.ID, "", nil)
	case "soak-record-psiphon-active-route":
		// Phase 3D (soak-only). Drives the engine's
		// psiphon-active-route diagnostic-recording hook
		// without requiring an upstream psiphon-tunnel-core
		// stack in the soak build. The engine refuses the
		// recording when `-tags no_psiphon` is in effect; the
		// rig surfaces that as a per-day outcome rather than
		// halting the soak.
		var a struct {
			RouteID string `json:"route_id"`
		}
		if err := json.Unmarshal(req.Arg, &a); err != nil {
			return response{ID: req.ID, Error: err.Error()}
		}
		if err := abi.RecordPsiphonActiveRoute(a.RouteID); err != nil {
			return response{ID: req.ID, Error: err.Error()}
		}
		return wrap(req.ID, "", nil)
	case "soak-record-conjure-activation":
		// Phase 3D (soak-only). Drives the engine's
		// conjure-activation diagnostic-recording hook
		// (route id + RAW phantom IP). The engine HASHES the
		// IP at the boundary; the rig MUST be able to send
		// the raw IP because the no-IP-leak invariant is
		// asserted on the resulting diagnostics output, not
		// on this RPC.
		var a struct {
			RouteID      string `json:"route_id"`
			RawPhantomIP string `json:"raw_phantom_ip"`
		}
		if err := json.Unmarshal(req.Arg, &a); err != nil {
			return response{ID: req.ID, Error: err.Error()}
		}
		if err := abi.RecordConjureActivation(a.RouteID, a.RawPhantomIP); err != nil {
			return response{ID: req.ID, Error: err.Error()}
		}
		return wrap(req.ID, "", nil)
	case "soak-load-wasm-module":
		// Phase 3E (soak-only). Drives the engine's
		// `RecordLoadedWasmModule` / `ClearLoadedWasmModules`
		// hooks without instantiating the wazero runtime.
		// Empty slug clears the loaded-modules snapshot; non-
		// empty slug records a (slug, sha256) tuple.
		var a struct {
			Slug      string `json:"slug"`
			SHA256Hex string `json:"sha256"`
		}
		if err := json.Unmarshal(req.Arg, &a); err != nil {
			return response{ID: req.ID, Error: err.Error()}
		}
		if a.Slug == "" {
			abi.ClearLoadedWasmModules()
			return wrap(req.ID, "", nil)
		}
		if err := abi.RecordLoadedWasmModule(a.Slug, a.SHA256Hex,
			time.Now().UTC().Format(time.RFC3339)); err != nil {
			return response{ID: req.ID, Error: err.Error()}
		}
		return wrap(req.ID, "", nil)
	case "soak-publish-wasm-killswitch-delta":
		// Phase 3E (soak-only). The driver-side rig signs the
		// (slug, sha256, generation) tuple under the soak
		// kill-switch key (NOT the production CC.4 key); the
		// engine verifies against the in-memory pubkey
		// injected at engine_init by the soak harness.
		// Implementation note: the soak harness wires the
		// verifier on first use of this RPC if it has not
		// already been wired by the host caller.
		var a struct {
			Slug       string `json:"slug"`
			SHA256Hex  string `json:"sha256"`
			Generation uint64 `json:"generation"`
		}
		if err := json.Unmarshal(req.Arg, &a); err != nil {
			return response{ID: req.ID, Error: err.Error()}
		}
		if err := soakApplyWasmKillswitchDelta(a.Slug, a.SHA256Hex, a.Generation); err != nil {
			return response{ID: req.ID, Error: err.Error()}
		}
		return wrap(req.ID, "", nil)
	case "soak-record-wasm-outcome":
		// Phase 3E (soak-only). Drives the engine's
		// `RecordWasmDialOutcome` hook. Outcomes MUST be one
		// of the closed v1 list.
		var a struct {
			Outcome string `json:"outcome"`
		}
		if err := json.Unmarshal(req.Arg, &a); err != nil {
			return response{ID: req.ID, Error: err.Error()}
		}
		if err := abi.RecordWasmDialOutcome(a.Outcome); err != nil {
			return response{ID: req.ID, Error: err.Error()}
		}
		return wrap(req.ID, "", nil)
	case "soak-seed-delegate-route":
		// Phase 3F (soak-only). Creates a publisher + route in
		// the routestore with the supplied redistribution
		// policy + cap. The rig uses this to set up routes
		// for the delegate-share scenarios without going
		// through a full bundle import.
		var a struct {
			RouteID string `json:"route_id"`
			Policy  string `json:"policy"`
			Cap     uint8  `json:"cap"`
		}
		if err := json.Unmarshal(req.Arg, &a); err != nil {
			return response{ID: req.ID, Error: err.Error()}
		}
		if err := abi.SoakSeedDelegateRoute(a.RouteID, a.Policy, a.Cap); err != nil {
			return response{ID: req.ID, Error: err.Error()}
		}
		return wrap(req.ID, "", nil)
	case "soak-redistribute-route":
		// Phase 3F (soak-only). Calls the release-surface
		// engine_redistribute_route ABI. Returns the JSON
		// envelope verbatim (success body or error envelope).
		var a struct {
			RouteID        string `json:"route_id"`
			RecipientFPHex string `json:"recipient_fp_hex"`
		}
		if err := json.Unmarshal(req.Arg, &a); err != nil {
			return response{ID: req.ID, Error: err.Error()}
		}
		body := abi.RedistributeRoute(a.RouteID, a.RecipientFPHex)
		return wrap(req.ID, body, nil)
	case "scheduler-tick":
		// Soak-only convenience: drive one Tick at the engine's
		// current time. The driver uses this when running with
		// `--mode in-engine` so the scheduler decides what to do
		// instead of the rig hard-coding the per-day command sweep.
		var a struct {
			UnixSeconds int64 `json:"unix_seconds"`
		}
		_ = json.Unmarshal(req.Arg, &a)
		var now time.Time
		if a.UnixSeconds > 0 {
			now = time.Unix(a.UnixSeconds, 0).UTC()
		} else {
			now = time.Now().UTC()
		}
		if err := abi.SchedulerTick(now); err != nil {
			return wrap(req.ID, "", err)
		}
		body, err := abi.SchedulerStatus()
		return wrap(req.ID, body, err)
	}
	return response{ID: req.ID, Error: "unknown command: " + req.Cmd}
}

// rcError translates the cshared / gomobile int return codes
// into a soak-driver-readable error string. Used by the 3B / 3C
// command dispatchers; the legacy commands return Go errors
// instead.
func rcError(rc int) string {
	switch rc {
	case 0:
		return ""
	case -1:
		return "engine not initialised"
	case -2:
		return "rejected by storage profile (vault)"
	case -3:
		return "value not in v1 closed list"
	case -4:
		return "input malformed"
	default:
		return "rc=" + itoa(rc)
	}
}

func itoa(n int) string {
	// Avoid an strconv import for one call site; this is the
	// soak engine, so the compactness matters less than keeping
	// the imports minimal.
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func wrap(id, body string, err error) response {
	r := response{ID: id, OK: err == nil}
	if err != nil {
		r.Error = err.Error()
	}
	if body != "" {
		r.Body = json.RawMessage(body)
	}
	return r
}
