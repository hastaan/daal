// Package client is the rig-side wrapper around a soak-engine child
// process. It speaks the same line-delimited JSON protocol the
// daal-soak-engine binary expects.
package client

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
)

// Client is a single soak-engine subprocess. Each scenario per simulated
// client gets its own Client; the soak driver creates as many as it
// needs (typically: linux-cli, linux-desktop, android).
type Client struct {
	name     string
	stateDir string
	cmd      *exec.Cmd
	stdin    io.WriteCloser
	stdout   *bufio.Reader
	mu       sync.Mutex
	idCount  atomic.Int64
}

// Spawn starts a new soak-engine child. binary must be built with
// `-tags soak` for the SetNow plumbing to work; non-soak builds will
// reject `set-now` calls but still implement everything else.
func Spawn(name, binary, stateDir string) (*Client, error) {
	return SpawnWithEnv(name, binary, stateDir, nil)
}

// SpawnWithEnv is the Phase 2E variant. The `extraEnv` map is appended
// to the child process's environment. The `ios-extension-memory`
// scenario uses this to set `GOMEMLIMIT=50MiB` so the soak engine
// runs under the iOS NE memory ceiling.
func SpawnWithEnv(name, binary, stateDir string, extraEnv map[string]string) (*Client, error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	cmd := exec.Command(binary)
	env := append(os.Environ(), "DAAL_SOAK_STATE_DIR="+filepath.Clean(stateDir))
	for k, v := range extraEnv {
		env = append(env, k+"="+v)
	}
	cmd.Env = env
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("client: spawn %s: %w", binary, err)
	}
	return &Client{
		name:     name,
		stateDir: stateDir,
		cmd:      cmd,
		stdin:    stdin,
		stdout:   bufio.NewReaderSize(stdout, 1<<20),
	}, nil
}

// Name returns the human-readable client label (linux-cli / linux-desktop / android).
func (c *Client) Name() string { return c.name }

// StateDir returns the per-client state directory. Snapshot copies of
// daal.db are taken from here.
func (c *Client) StateDir() string { return c.stateDir }

// Pid returns the engine subprocess PID, or 0 if the child has not
// started yet. Used by the wall-clock smoke loop to read /proc/pid/fd.
func (c *Client) Pid() int {
	if c.cmd == nil || c.cmd.Process == nil {
		return 0
	}
	return c.cmd.Process.Pid
}

type response struct {
	ID    string          `json:"id"`
	OK    bool            `json:"ok"`
	Body  json.RawMessage `json:"body,omitempty"`
	Error string          `json:"error,omitempty"`
}

// Call sends a single command and returns the response Body.
func (c *Client) Call(cmd string, arg any) (json.RawMessage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	id := fmt.Sprintf("r%d", c.idCount.Add(1))
	var argRaw json.RawMessage
	if arg != nil {
		b, err := json.Marshal(arg)
		if err != nil {
			return nil, err
		}
		argRaw = b
	}
	req := struct {
		ID  string          `json:"id"`
		Cmd string          `json:"cmd"`
		Arg json.RawMessage `json:"arg,omitempty"`
	}{ID: id, Cmd: cmd, Arg: argRaw}
	body, _ := json.Marshal(req)
	body = append(body, '\n')
	if _, err := c.stdin.Write(body); err != nil {
		return nil, err
	}
	line, err := c.stdout.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	var resp response
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, fmt.Errorf("client: decode resp %q: %w", string(line), err)
	}
	if resp.ID != id {
		return nil, fmt.Errorf("client: id mismatch want %q got %q", id, resp.ID)
	}
	if !resp.OK {
		return resp.Body, errors.New(resp.Error)
	}
	return resp.Body, nil
}

// Version is engine_version.
func (c *Client) Version() (string, error) {
	body, err := c.Call("version", nil)
	if err != nil {
		return "", err
	}
	var s string
	if err := json.Unmarshal(body, &s); err != nil {
		return "", err
	}
	return s, nil
}

// SetNow overrides the engine's clock. Requires the soak-tagged binary.
func (c *Client) SetNow(unixSec int64) error {
	_, err := c.Call("set-now", map[string]any{"unix_seconds": unixSec})
	return err
}

// SubscriptionAdd wraps engine_subscription_add.
func (c *Client) SubscriptionAdd(publisherFP, url, displayName string) (json.RawMessage, error) {
	return c.Call("subscription-add", map[string]any{
		"publisher_fp": publisherFP,
		"url":          url,
		"display_name": displayName,
	})
}

// SubscriptionRefresh wraps engine_subscription_refresh.
func (c *Client) SubscriptionRefresh(subscriptionID string, timeoutMs int) (json.RawMessage, error) {
	return c.Call("subscription-refresh", map[string]any{
		"subscription_id": subscriptionID,
		"timeout_ms":      timeoutMs,
	})
}

// SubscriptionList wraps engine_subscription_list.
func (c *Client) SubscriptionList() (json.RawMessage, error) {
	return c.Call("subscription-list", nil)
}

// RevocationRefreshAll wraps engine_revocation_refresh_all.
func (c *Client) RevocationRefreshAll(timeoutMs int) (json.RawMessage, error) {
	return c.Call("revocation-refresh-all", map[string]any{"timeout_ms": timeoutMs})
}

// BootstrapInstall, BootstrapRefresh, BootstrapStatus, PointerRotationStatus, DiagExplain all map directly.
func (c *Client) BootstrapInstall() (json.RawMessage, error) {
	return c.Call("bootstrap-install", nil)
}
func (c *Client) BootstrapRefresh(timeoutMs int) (json.RawMessage, error) {
	return c.Call("bootstrap-refresh", map[string]any{"timeout_ms": timeoutMs})
}
func (c *Client) BootstrapStatus() (json.RawMessage, error) {
	return c.Call("bootstrap-status", nil)
}
func (c *Client) PointerRotationStatus() (json.RawMessage, error) {
	return c.Call("pointer-rotation-status", nil)
}
func (c *Client) DiagExplain() (json.RawMessage, error) {
	return c.Call("diag-explain", nil)
}

// SchedulerStatus wraps engine_scheduler_status (Phase 2F).
func (c *Client) SchedulerStatus() (json.RawMessage, error) {
	return c.Call("scheduler-status", nil)
}

// ExportDiagnostics wraps engine_export_diagnostics. Phase 2A widens
// the body with a `budgets` array; the soak driver records this for
// the per-day artifact ledger.
func (c *Client) ExportDiagnostics() (json.RawMessage, error) {
	return c.Call("export-diagnostics", nil)
}

// SetRouteBudget wraps engine_set_route_budget (Phase 2A).
func (c *Client) SetRouteBudget(routeID, budgetTag string) (json.RawMessage, error) {
	return c.Call("set-route-budget", map[string]any{
		"route_id":   routeID,
		"budget_tag": budgetTag,
	})
}

// SchedulerTick advances the in-engine scheduler at simulated time
// `unixSec`. Used by the soak driver's `--mode in-engine` flag.
func (c *Client) SchedulerTick(unixSec int64) (json.RawMessage, error) {
	return c.Call("scheduler-tick", map[string]any{"unix_seconds": unixSec})
}

// SetMode wraps engine_set_mode (Phase 2B). Used by per-day engine
// actions in scenarios such as `mode-bulk-unlock`.
func (c *Client) SetMode(mode string) (json.RawMessage, error) {
	return c.Call("set-mode", map[string]any{"mode": mode})
}

// NetworkChanged wraps engine_network_changed (Phase 2C). The
// kind/carrier/ssid arguments are hashed by the engine; nothing
// raw is persisted. Used by per-day engine actions in the
// `network-roam` scenario.
func (c *Client) NetworkChanged(kind, carrier, ssid string) (json.RawMessage, error) {
	return c.Call("network-changed", map[string]any{
		"kind":    kind,
		"carrier": carrier,
		"ssid":    ssid,
	})
}

// UnlockSecrets wraps engine_unlock_secrets (Phase 2D). For ordinary
// class returns an error wrapping ErrNoHighRiskProfile. The PIN
// string MUST never be persisted in scenarios that exercise this
// path; the soak rig's `no_pin_leak_in_diagnostics` invariant
// regresses against any leak.
func (c *Client) UnlockSecrets(pin string) (json.RawMessage, error) {
	return c.Call("unlock-secrets", map[string]any{"pin": pin})
}

// SetAllowBulkCapable wraps the soak-only set-allow-bulk command
// driving the budget engine's per-session bulk-capable opt-in flag
// (Phase 2D).
func (c *Client) SetAllowBulkCapable(allow bool) (json.RawMessage, error) {
	return c.Call("set-allow-bulk", map[string]any{"allow": allow})
}

// LifecycleEvent wraps the lifecycle-event command (Phase 2E). The
// engine accepts the locked v1 token set; an unknown token surfaces
// as an error from the soak engine.
func (c *Client) LifecycleEvent(token string) (json.RawMessage, error) {
	return c.Call("lifecycle-event", map[string]any{"token": token})
}

// SoakSetWGMemoryKiB drives the soak-only WG sub-engine memory gauge
// (Phase 2E). Used by the ios-wireguard-handoff scenario.
func (c *Client) SoakSetWGMemoryKiB(kib int64) (json.RawMessage, error) {
	return c.Call("soak-set-wg-memory-kib", map[string]any{"kib": kib})
}

// SoakForceWGHandoff stamps a forced WG handoff timestamp
// (Phase 2E soak knob).
func (c *Client) SoakForceWGHandoff() (json.RawMessage, error) {
	return c.Call("soak-force-wg-handoff", nil)
}

// SetExperimentalFamiliesEnabled wraps engine_set_experimental_families_enabled
// (Phase 3A). Drives the per-engine experimental-families gate
// from the soak driver.
func (c *Client) SetExperimentalFamiliesEnabled(enabled bool) (json.RawMessage, error) {
	return c.Call("set-experimental-families-enabled", map[string]any{"enabled": enabled})
}

// SetRendezvousPriority wraps engine_set_rendezvous_priority
// (Phase 3B). Drives the per-engine rendezvous priority
// override from the soak driver. `priority` is a list of
// channel IDs from the v1 closed taxonomy.
func (c *Client) SetRendezvousPriority(priority []string) (json.RawMessage, error) {
	return c.Call("set-rendezvous-priority", map[string]any{"priority": priority})
}

// SetPushRendezvousEnabled wraps engine_set_push_rendezvous_enabled
// (Phase 3B). Drives the per-engine push opt-in flag from the
// soak driver.
func (c *Client) SetPushRendezvousEnabled(enabled bool) (json.RawMessage, error) {
	return c.Call("set-push-rendezvous-enabled", map[string]any{"enabled": enabled})
}

// SoakSimulatePushPayload is the soak-build-only knob that
// enqueues a synthetic push payload as if it had arrived
// through the FCM/APNS data-message surface. Used by
// `push-rendezvous-opt-in` to assert the queue + verifier path.
func (c *Client) SoakSimulatePushPayload(bridge, fpHex string) (json.RawMessage, error) {
	return c.Call("soak-simulate-push-payload", map[string]any{
		"bridge": bridge,
		"fp":     fpHex,
	})
}

// SoakBurnRendezvousChannel is the soak-only knob that injects
// a "broker burned" signal for the named rendezvous channel
// for the next N rendezvous attempts. Used by
// `snowflake-broker-burn` to assert hedged fallback.
func (c *Client) SoakBurnRendezvousChannel(channelID string, attempts int) (json.RawMessage, error) {
	return c.Call("soak-burn-rendezvous-channel", map[string]any{
		"channel_id": channelID,
		"attempts":   attempts,
	})
}

// SetMasqueSubmodeOverride wraps
// engine_set_masque_submode_override (Phase 3C). Drives the
// per-engine MASQUE sub-mode override from the soak driver.
// Empty string clears the override (auto cascade resumes).
func (c *Client) SetMasqueSubmodeOverride(submode string) (json.RawMessage, error) {
	return c.Call("set-masque-submode-override", map[string]any{
		"submode": submode,
	})
}

// SoakBurnMasqueSubmode is the soak-only knob that injects a
// burn signal for the named MASQUE sub-mode for the next N
// activations on this engine. Used by `masque-lifeline-rung`
// to drive the chooseSubmode cascade's step-6 drop-to-lifeline
// branch.
func (c *Client) SoakBurnMasqueSubmode(submode string, attempts int) (json.RawMessage, error) {
	return c.Call("soak-burn-masque-submode", map[string]any{
		"submode":  submode,
		"attempts": attempts,
	})
}

// SoakRecordPsiphonActiveRoute is the Phase 3D soak-only knob
// that drives the psiphon transport's diagnostic-recording
// hook from the rig. The engine's
// `RecordPsiphonActiveRoute` is normally invoked by the
// in-process psiphon handler at activation time; in soak
// builds the rig drives it directly so the
// `psiphon-blob-rotation` scenario can assert the resulting
// diagnostics shape without instantiating the full upstream
// psiphon-tunnel-core stack.
func (c *Client) SoakRecordPsiphonActiveRoute(routeID string) (json.RawMessage, error) {
	return c.Call("soak-record-psiphon-active-route", map[string]any{
		"route_id": routeID,
	})
}

// SoakRecordConjureActivation is the Phase 3D soak-only knob
// that drives the conjure transport's diagnostic-recording
// hook from the rig. The engine's
// `RecordConjureActivation` is normally invoked by the
// in-process conjure handler at activation time; in soak
// builds the rig drives it directly so the
// `conjure-phantom-pool` scenario can assert the
// hash-only-no-raw-IP invariant without instantiating the
// full upstream gotapdance stack.
func (c *Client) SoakRecordConjureActivation(routeID, rawPhantomIP string) (json.RawMessage, error) {
	return c.Call("soak-record-conjure-activation", map[string]any{
		"route_id":       routeID,
		"raw_phantom_ip": rawPhantomIP,
	})
}

// SoakLoadWasmModule is the Phase 3E soak-only knob that
// drives the engine's `RecordLoadedWasmModule` /
// `ClearLoadedWasmModules` hooks from the rig without
// instantiating the wazero runtime. Empty slug clears the
// loaded-modules snapshot.
func (c *Client) SoakLoadWasmModule(slug, sha256Hex string) (json.RawMessage, error) {
	return c.Call("soak-load-wasm-module", map[string]any{
		"slug":   slug,
		"sha256": sha256Hex,
	})
}

// SoakPublishWasmKillswitchDelta is the Phase 3E soak-only
// knob that drives the engine's `KillSwitchVerifier.Apply`
// hook from the rig. The rig signs the (slug, sha256,
// generation) under the soak-only kill-switch private key
// (NOT the production CC.4 hardware-token key); the engine
// verifies against the in-memory pubkey injected at
// `engine_init` time.
func (c *Client) SoakPublishWasmKillswitchDelta(slug, sha256Hex string, generation uint64) (json.RawMessage, error) {
	return c.Call("soak-publish-wasm-killswitch-delta", map[string]any{
		"slug":       slug,
		"sha256":     sha256Hex,
		"generation": generation,
	})
}

// SoakRecordWasmOutcome is the Phase 3E soak-only knob that
// drives the engine's `RecordWasmDialOutcome` hook from the
// rig. The outcome MUST be one of the closed v1 list;
// unknown values are rejected by the engine and surface as a
// per-day error in the scenario record.
func (c *Client) SoakRecordWasmOutcome(outcome string) (json.RawMessage, error) {
	return c.Call("soak-record-wasm-outcome", map[string]any{
		"outcome": outcome,
	})
}

// SoakSeedDelegateRoute is the Phase 3F soak-only knob that
// creates / upserts a route in the routestore with the given
// redistribution policy + cap, so the rig can exercise the
// re-share surface without driving a full bundle import.
func (c *Client) SoakSeedDelegateRoute(routeID, policy string, capN uint8) (json.RawMessage, error) {
	return c.Call("soak-seed-delegate-route", map[string]any{
		"route_id": routeID,
		"policy":   policy,
		"cap":      capN,
	})
}

// SoakRedistributeRoute is the Phase 3F soak-only knob that
// invokes the release-surface engine_redistribute_route ABI
// from the rig. Returns the engine's verbatim JSON envelope
// (success body or closed-enum error envelope).
func (c *Client) SoakRedistributeRoute(routeID, recipientFPHex string) (json.RawMessage, error) {
	return c.Call("soak-redistribute-route", map[string]any{
		"route_id":         routeID,
		"recipient_fp_hex": recipientFPHex,
	})
}

// Close shuts down the child process.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = c.stdin.Close()
	if c.cmd.Process != nil {
		_ = c.cmd.Wait()
	}
	return nil
}
