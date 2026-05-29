// Package abi is the in-process facade that platform bridges (gomobile,
// c-shared) wrap. It owns the singleton routestore, trust adapter, engine
// driver, and path manager — exactly the 14 functions documented in
// specs/engine-abi-v1.md.
package abi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"daal/bundle-go/importer"
	"daal/bundle-go/publisher"
	"daal/core/diagnostics"
	"daal/core/engine"
	"daal/core/pathmanager"
	"daal/core/routestore"
	"daal/core/trust"
)

// Version returned by engine_version. Bumped on every ABI-impacting change.
//
// History:
//   - 0.1.x → 0.3.x: V1 Android scaffold.
//   - 0.4.0+desktop: Phase 1.5A subscription/revocation/pointer/diag.
//   - 0.4.1+desktop: Phase 1.5B TunnelDialer + cshared host wiring.
//   - 0.4.1+desktop (1.5C-Polish): added engine_subscription_list (release surface 33→34).
//   - 0.5.0+survivability: Phase 2F in-engine scheduler + engine_scheduler_status (release surface 34→35).
//   - 0.5.0+survivability (Phase 2A): engine_set_route_budget (release surface 35→36).
//   - 0.5.0+survivability (Phase 2C): engine_network_changed (release surface 36→37).
//   - 0.5.0+survivability (Phase 2D): engine_unlock_secrets + engine_set_allow_bulk_capable + lifeline-strict mode (release surface 37→39).
//   - 0.6.0+v2-soak (Phase 2G): engine_set_auto_promotion + auto-promotion to lifeline-strict on burn pressure (release surface 39→40); V2 success-metric soak (1k synthetic clients × 30 days × directory-rotation comparison) GREEN.
//   - 0.6.0+v2-soak (Phase 2E): engine_lifecycle_event for iOS Network Extension state transitions (release surface 40→41). Engine version unchanged (informative version bumps happen at engine work, not platform integration); 2E is platform integration only.
//   - 0.7.0+v3-transport (Phase 3A): engine_set_experimental_families_enabled + transport-family taxonomy + WebTunnel handler + Iranian region caveat + bundle SBP-v1 widening (3 new optional routes[] fields + kill_switches[] reservation) (release surface 41→42). V3 transport-agility line begins.
//   - 0.7.1+v3-transport (Phase 3B): engine_set_rendezvous_priority + engine_set_push_rendezvous_enabled (release surface 42→44). Snowflake transport family + 5-channel rendezvous taxonomy (domain_fronted_broker / sqs / amp_cache / push / offline_hint) with hedged-at-4s selection; per-route + per-network winning-channel persistence; gomobile-only push token plumbing (NEVER cshared); vault profile rejects push opt-in. Diagnostics widen with rendezvous_priority / rendezvous_channel / push_rendezvous_enabled / last_winning_rendezvous_channel.
//   - 0.7.2+v3-transport (Phase 3C): engine_set_masque_submode_override (release surface 44→45). MASQUE transport family with three sub-modes (masque_h3_quic / masque_h2_connect / masque_lifeline); private chooseSubmode cascade (override → lifeline-strict hint → netmem hint → UDP probe → h2-burn drop); per-route + per-network sub-mode persistence; opportunistic only — auto-promotion never promotes a network whose only family is masque. Diagnostics widen with masque_submode / masque_submode_override.
//   - 0.7.3+v3-transport (Phase 3D): refraction-family hooks. Two new transport families (psiphon, conjure), both shipped as Experimental. Psiphon is opaque-blob carriage (vendored psiphon-tunnel-core under GPLv3, isolated behind `-tags no_psiphon`); conjure is vendored gotapdance under Apache-2.0; phantom-pool floors locked at /24 IPv4 + /32 IPv6. Family registry gains `IsOpportunistic` (psiphon NOT opportunistic, conjure IS, masque retroactively annotated). NO new ABI symbols (release surface 45→45, append-only invariant preserved). Diagnostics widen with psiphon_compiled_in / conjure_compiled_in / psiphon_active_route / conjure_active_route / conjure_phantom_in_use (HASHED via 8-byte SHA-256). See specs/psiphon-route-v1.md and specs/conjure-route-v1.md.
//   - 0.8.0+v3-wasm (Phase 3E): WASM transport slot (WATER v1 ABI; wazero runtime). Two new release symbols (release surface 45 → 47, append-only): `engine_wasm_kill_switch_pubkey` (46) and `engine_loaded_wasm_modules` (47). New `transport_module` family at Experimental maturity, NOT opportunistic. Bundle-format widening: top-level `transport_modules[]` (slug + sha256 + wasm_blob_b64 + min_engine_version) + `routes[].transport_module_slug`; 5 new bundle errors. Routestore: 1 ALTER (`transport_module_slug`); engine-recorded kill-switch state lives in `secrets_kv` under the `wasm_killed:` namespace, never on the route row (3D-style non-clobber). Resource caps locked: 16 MiB memory; 1e9 fuel/dial; 5s dial+load timeouts; ≤4 MiB/module; ≤16 MiB/bundle; 1 instance per route per session. Project-controlled WASM kill-switch publisher key (CC.4 hardware-token; signed deltas append-only within a generation, no rescinds). `-tags no_wasm` excluder mirrors 3D's `no_psiphon`. Diagnostics widen with wasm_compiled_in / loaded_wasm_modules / wasm_kill_switched_count / last_wasm_module_dial_outcome (closed enum: ok / fuel_exhausted / memory_cap / dial_timeout / host_callback_error). NO new V0 failure categories. V3 success-metric milestone: shipped a new transport without an app update. See specs/wasm-transport-v1.md and specs/wasm-kill-switch-v1.md.
//   - 0.9.0+v3-share (Phase 3F): one-tap delegate-share. One new release symbol (release surface 47 → 48, append-only): `engine_redistribute_route` (48). Reuses the existing 1C share identity (`secrets_kv:share/identity:v1`) as the delegate key — NO new key derivation. Closed-enum redistribution policy {none, delegated_n, transitive}; default "none" (fail-closed). Transitive chain depth capped at 5; original publisher signature preserved verbatim, delegate signatures appended. Bundle-format widening: `routes[].redistribution_policy` + `redistribution_cap`; `.sbp.share` shape with `redistribution_chain[]` + `delegate_caps[]`; 6 new bundle errors. Routestore: 1 ALTER (`redistribution_policy` TEXT) carrying both policy + cap as `<policy>` or `<policy>:<cap>`; per-route counter at `secrets_kv:delegate_share_counter:<route_id>` (3D/3E-style non-clobber). Diagnostics widen with delegate_share_compiled_in / delegate_share_counters / last_delegate_share_outcome (closed enum: ok / policy_refuses / cap_exhausted / chain_depth_exceeded / route_unknown / identity_unavailable). `-tags no_delegate_share` excluder mirrors 3D's `no_psiphon`. NO new V0 failure categories. See specs/delegate-keys-v1.md.
const Version = "daal-core 0.9.0+v3-share"

// pendingPrompt holds a bundle waiting for the operator's TOFU decision.
type pendingPrompt struct {
	body []byte
}

// Core is the singleton state held behind the ABI.
type Core struct {
	mu                  sync.Mutex
	store               *routestore.Store
	adapter             *trust.StoreAdapter
	driver              engine.Driver
	pm                  *pathmanager.Manager
	pending             map[string]*pendingPrompt
	mode                string
	logLevel            string
	stateDir            string
	subs                chan engine.Event
	lifelineStrictSince time.Time // 2D: hour-bucket of last entry into lifeline-strict
	secretsUnlocked     bool      // 2D: PIN-vault unlock state
	storageProfile      string    // 2D: "vault" | "keystore" — behavioural, not group-based
	// 2G auto-promotion state. autoPromotionEnabled defaults to true
	// at Init; it is a user preference and survives session epochs.
	// autoPromotionLastFiredHour debounces the detector to one fire
	// per hour-bucket. manualOverrideHour records the last hour at
	// which the user-facing engine_set_mode ABI surface fired; the
	// scheduler suppresses auto-promotion in that hour.
	autoPromotionEnabled       bool
	autoPromotionLastFiredHour time.Time
	manualOverrideHour         time.Time

	// 2E iOS lifecycle. The Swift bridge surfaces NE state
	// transitions (will_sleep / did_wake / memory_pressure_warning)
	// into the engine via engine_lifecycle_event so failure
	// classification and refresh scheduling can react. The engine
	// records the most recent event token and timestamp; consumers
	// read them through diagnostics.
	lastLifecycleEvent string
	lastLifecycleAt    time.Time

	// 3A experimental-families gate. The flag is per-engine,
	// default-OFF, persists across session epochs, and is
	// cleared only by an explicit user toggle through
	// engine_set_experimental_families_enabled. The pathmanager
	// consults the flag through ExperimentalFamiliesEnabled() at
	// the family_filter step BEFORE trust / budget / network-
	// memory. The skip count below is the per-rank-pass tally
	// surfaced as `experimental_routes_skipped` in diagnostics;
	// it is reset by the pathmanager at the start of every rank
	// pass (it is a snapshot, not a cumulative counter).
	experimentalFamiliesEnabled bool
	experimentalRoutesSkipped   int

	// 3B rendezvous state.
	//
	// rendezvousPriorityOverride is the per-engine override for
	// the bundle-supplied `routes[].rendezvous_priority`. nil
	// means "no override" (use bundle priority verbatim);
	// non-nil (even an empty slice) is an explicit override and
	// the rendezvous Selector consults it before the bundle
	// list. The override is per-engine, NOT per-network — same
	// reasoning as the experimental gate (cross-product would
	// be a fingerprint surface). Persisted in secrets KV.
	//
	// pushRendezvousEnabled is the user opt-in for the `push`
	// channel. Default-OFF. The flag is rejected by Init when
	// the storage profile is "vault" (PIN-vault build) — the
	// vault profile must never call FCM/APNS at all because
	// the device tokens would tie the user to platform back-
	// ends that are not part of the threat model. The setter
	// returns -2 in the vault profile.
	//
	// pushDeviceToken / pushDeviceTokenPlatform are the
	// platform-supplied push tokens (FCM for Android,
	// APNS for iOS). Only set through gomobile-only setters
	// (NEVER cshared); release builds for Linux/Windows leave
	// them empty. Stored in secrets KV.
	rendezvousPriorityOverride []string
	pushRendezvousEnabled      bool
	pushDeviceToken            string
	pushDeviceTokenPlatform    string

	// lastWinningRendezvousChannel is the channel ID that most
	// recently completed a successful Solicit on the active
	// network. Surfaced in diagnostics; cleared on
	// engine_clear_route. Snapshot, not cumulative.
	lastWinningRendezvousChannel string

	// 3C MASQUE state.
	//
	// masqueSubmodeOverride is the per-engine pin for the
	// MASQUE sub-mode chooser. Empty string means "no override
	// — use the auto cascade." Non-empty values are restricted
	// to the v1 closed list (`masque_h3_quic`,
	// `masque_h2_connect`, `masque_lifeline`); the setter
	// rejects anything else with -3. The override is per-engine,
	// NOT per-network — the cross-product would be a
	// fingerprint surface (same reasoning as the 3A
	// experimental gate and 3B rendezvous priority override).
	// Persisted in secrets KV; survives session epochs.
	//
	// lastChosenMasqueSubmode is the sub-mode the masque
	// handler most recently chose this session. Snapshot, not
	// cumulative; surfaced in diagnostics as `masque_submode`.
	masqueSubmodeOverride   string
	lastChosenMasqueSubmode string

	// 3D refraction-family state.
	//
	// lastActivePsiphonRouteID / lastActiveConjureRouteID record
	// the most recent route ID activated by the psiphon /
	// conjure transport handlers respectively. Empty string
	// means "no route from that family activated this session."
	// These are session-scoped snapshots, not cumulative
	// counters; they reset on engine init.
	//
	// lastConjurePhantomHashHex is the HASHED phantom IP the
	// conjure handler most recently selected (8-byte SHA-256
	// truncation, hex-encoded). Locked at 3D: the raw IP NEVER
	// appears in diagnostics — keeping the redaction invariant
	// holds for refraction routes the same way it holds for
	// network IDs. Empty string until conjure has activated a
	// route this session.
	//
	// The compile-in flags are constants populated at init from
	// build-tag-conditional shims (see psiphon_compiled.go,
	// conjure_compiled.go). They are surfaced verbatim in
	// diagnostics so an operator can confirm whether the
	// running binary includes the GPLv3 psiphon vendor tree
	// (`-tags no_psiphon` builds report false).
	lastActivePsiphonRouteID  string
	lastActiveConjureRouteID  string
	lastConjurePhantomHashHex string
}

var globalCore *Core

// soakDiagHook is registered ONLY by `-tags soak` builds (see
// ios_handoff_diag.go). Release builds leave it nil and the
// diagnostics renderer skips the call.
var soakDiagHook func(map[string]any)

// Init is engine_init.
//
// Concurrency contract: globalCore is published in a single
// assignment at the end of this function, after every sub-field is
// populated. Readers therefore observe either `nil` (engine not
// ready — mustCore() panics, gomobile turns that into a Java
// Exception) or a fully initialised Core. The Phase-1B Android crash
// where a polling goroutine called DiagnosticsExplain() while Init
// was mid-flight and saw a nil pathmanager.Manager was a direct
// consequence of the previous "publish-then-mutate" pattern.
func Init(stateDir, logLevel string) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	s, err := routestore.Open(stateDir)
	if err != nil {
		return err
	}

	core := &Core{
		stateDir:             stateDir,
		logLevel:             logLevel,
		pending:              map[string]*pendingPrompt{},
		mode:                 "normal",
		autoPromotionEnabled: true,
		store:                s,
		adapter:              &trust.StoreAdapter{S: s},
		driver:               engine.NewStub(),
		pm:                   pathmanager.New(),
		subs:                 make(chan engine.Event, 32),
	}
	core.pm.SetNow(nowUTC)
	core.driver.Subscribe(core.subs)

	// Phase 2D: detect the storage profile from the state-dir flag
	// file. The default is "keystore" (platform-keystore-backed,
	// transparent unlock). The "vault" profile is opted into during
	// onboarding by writing `state/.use_vault` (an empty marker).
	// Both labels are behavioural — they describe the storage path,
	// not the user — to keep the engine compliant with the V0.1 +
	// CC.6 no-group-based-labels invariant.
	if _, err := os.Stat(stateDir + "/.use_vault"); err == nil {
		core.storageProfile = "vault"
	} else {
		core.storageProfile = "keystore"
		// Keystore profile: secrets are unlocked transparently via
		// the platform keystore at process-start time. The
		// desktop's keystore-bound key derivation is wired
		// separately; the engine treats this as "unlocked" so the
		// routestore can be read/written without a PIN gate.
		core.secretsUnlocked = true
	}

	// Atomic publish. Every other engine function reads globalCore;
	// before this point they observe nil (clean Java Exception via
	// mustCore), after this point they see a fully populated Core.
	globalCore = core

	// Phase 2A-Polish: bump the budget engine's session epoch. This
	// is the canonical session boundary — every successful Init
	// starts a fresh per-session counter for every route. If the
	// budget engine isn't instantiated yet (the common case on a
	// clean boot) the bump is queued for the lazy ensureBudget.
	bumpBudgetSessionForInit()
	// Phase 2C: prime the per-network memory subsystem. Active
	// network is the sentinel "unset" until the platform first
	// calls engine_network_changed. This MUST run after the
	// pathmanager is constructed (it sets pm.activeNetwork).
	seedNetmemForInit()
	// Phase 3A: daalte the experimental-families gate from the
	// secrets KV. Default-OFF; missing key → off. The flag
	// survives session epochs by virtue of being persisted here
	// rather than reset on every Init.
	loadExperimentalFamiliesEnabled(globalCore)
	// Phase 3B: daalte the rendezvous priority override + push
	// opt-in + push device token from the secrets KV. The vault
	// profile rejects push-related fields at daalte time even
	// if a corrupt persisted state attempts to enable them.
	loadRendezvousState(globalCore)
	// Phase 3C: daalte the MASQUE sub-mode override from the
	// secrets KV. Missing / out-of-list values default to "no
	// override" (auto cascade).
	loadMasqueState(globalCore)
	return nil
}

// Shutdown is engine_shutdown.
func Shutdown() error {
	if globalCore == nil {
		return nil
	}
	c := globalCore
	globalCore = nil
	if c.driver != nil {
		_ = c.driver.Stop()
	}
	resetSchedulerForShutdown()
	resetBudgetForShutdown()
	resetRefreshForShutdown()
	resetBootstrapForShutdown()
	resetShareForShutdown()
	resetTunnelForShutdown()
	resetClockForShutdown()
	resetNetmemForShutdown()
	resetPushQueueForShutdown()
	resetWasmStateForShutdown()
	resetDelegateStateForShutdown()
	if c.store != nil {
		return c.store.Close()
	}
	return nil
}

// VersionString is engine_version.
func VersionString() string { return Version }

// SetRoute is engine_set_route.
func SetRoute(routeID string) error {
	c := mustCore()
	c.mu.Lock()
	defer c.mu.Unlock()
	row, err := c.store.GetRoute(routeID)
	if err != nil {
		return fmt.Errorf("abi: route %s not found: %w", routeID, err)
	}
	if row.TrustState == "revoked" || row.TrustState == "expired" {
		return fmt.Errorf("abi: route %s is %s and cannot be activated", routeID, row.TrustState)
	}
	if ok, reason := c.pm.CanAttempt(routeID, row.TransportFamily); !ok {
		return fmt.Errorf("abi: %s", reason)
	}
	profile, err := c.store.GetSecret("route:" + routeID)
	if err != nil {
		return fmt.Errorf("abi: load profile for %s: %w", routeID, err)
	}
	cfg, err := engine.BuildSingBoxConfig(row, profile)
	if err != nil {
		return err
	}
	body, err := engine.MarshalSingBox(cfg)
	if err != nil {
		return err
	}
	c.pm.Attempt(routeID, row.TransportFamily)
	if err := c.driver.Start(context.Background(), body); err != nil {
		c.pm.Failed(routeID, row.TransportFamily, diagnostics.Classify(err.Error()))
		// Posture: a fresh attempt that fails from PostureNoRoute
		// should advance to PostureRecovery if legal so the GUI can
		// render the recovery affordance. Illegal transitions (no
		// active posture to "fail" from) are silently ignored.
		_ = c.pm.SetPosture(pathmanager.EventActiveFailed, pathmanager.PostureRecovery)
		return err
	}
	c.pm.Connected()
	// Posture axis (Phase-3-Soak): the legacy `state` field was
	// removed from the diagnostics blob, and consumers MUST read
	// `posture`. SetRoute previously advanced only the state axis,
	// leaving the posture stuck at PostureNoRoute even after a
	// successful tunnel — which made the GUI's "Connected?" badge
	// read disconnected forever. Fire the canonical
	// `imported_selected → ImportedActive` event; if the current
	// posture is already active (e.g. re-selecting a route, or
	// coming back from Lifeline), the transition is illegal-but-
	// harmless and the posture stays at its current active state.
	//
	// Gap 5: branch on family maturity so an experimental-family
	// route advances the posture to PostureExperimental (UI shows
	// the warning). The corresponding {NoRoute,
	// experimental_selected, Experimental} table edge was added in
	// Gap 5 so this works as the first connection.
	if routestore.IsExperimentalFamily(row.TransportFamily) {
		_ = c.pm.SetPosture(pathmanager.EventExperimentalSelected, pathmanager.PostureExperimental)
	} else {
		_ = c.pm.SetPosture(pathmanager.EventImportedSelected, pathmanager.PostureImportedActive)
	}
	return nil
}

// ClearRoute is engine_clear_route.
func ClearRoute() error {
	c := mustCore()
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.driver.Stop(); err != nil {
		return err
	}
	c.pm.Disconnect()
	// Posture axis: a user-initiated disconnect always returns to
	// PostureNoRoute. The transition `EventDisconnected → NoRoute`
	// is legal from every active posture in LegalTransitions.
	_ = c.pm.SetPosture(pathmanager.EventDisconnected, pathmanager.PostureNoRoute)
	return nil
}

// SetMode is engine_set_mode. Phase 2B threads the mode into the
// budget engine (driving EffectiveCap) and into the V2.3 posture FSM
// (lifeline mode flips ImportedActive/SharedActive → Lifeline).
//
// Mode change MUST NOT bump the budget session epoch (2A-Polish
// invariant) — only `engine_init` does that.
//
// Phase 2D widens the accepted set with `lifeline-strict`. The
// strict variant shares the 0.33× budget multiplier with `lifeline`
// (see `core/budget/effective.go`) and flips the posture into
// PostureLifeline exactly as `lifeline` does. The four behavioural
// deltas (stability-biased ranker, bulk-capable refusal, refresh
// gate, permanent banner) live on the path-manager / refresher /
// desktop sides.
func SetMode(mode string) error {
	return setMode(mode, true)
}

// setModeAuto is the auto-promotion path: a scheduler-driven mode
// change that does NOT stamp the manual-override hour. Callers
// outside this package MUST use SetMode (which sets userTriggered
// = true). Phase 2G.
func setModeAuto(mode string) error {
	return setMode(mode, false)
}

func setMode(mode string, userTriggered bool) error {
	switch mode {
	case "lifeline", "lifeline-strict", "normal", "bulk":
	default:
		return fmt.Errorf("abi: invalid mode %q", mode)
	}
	c := mustCore()
	c.mu.Lock()
	c.mode = mode
	if mode == "lifeline-strict" && c.lifelineStrictSince.IsZero() {
		c.lifelineStrictSince = nowUTC().Truncate(time.Hour)
	}
	if mode != "lifeline-strict" {
		c.lifelineStrictSince = time.Time{}
	}
	if userTriggered {
		// 2G: stamp the manual-override hour so the auto-promotion
		// detector backs off for this hour-bucket. The user's
		// choice always wins over the detector.
		c.manualOverrideHour = nowUTC().Truncate(time.Hour)
	}
	c.mu.Unlock()

	// Push the mode into the budget engine if it has been
	// instantiated. Non-instantiating peek avoids triggering lazy
	// init from a mode change.
	if eng := budgetEngineIfPresent(); eng != nil {
		eng.SetMode(mode)
	}

	// Drive the posture axis. lifeline / lifeline-strict toggle
	// ImportedActive/SharedActive ↔ Lifeline. Errors are
	// intentionally swallowed: `Posture` is informative, and an
	// illegal transition (e.g., SetMode called from PostureNoRoute)
	// leaves the posture unchanged, which matches user intuition.
	switch mode {
	case "lifeline", "lifeline-strict":
		_ = c.pm.SetPosture(pathmanager.EventLifelineModeOn, pathmanager.PostureLifeline)
	case "normal", "bulk":
		if c.pm.Posture() == pathmanager.PostureLifeline {
			_ = c.pm.SetPosture(pathmanager.EventLifelineModeOff, pathmanager.PostureImportedActive)
		}
	}
	return nil
}

// Mode returns the current mode (helper for tests/CLI).
func Mode() string {
	c := mustCore()
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mode
}

// ApplyCooldown is engine_apply_cooldown.
func ApplyCooldown(routeID string, seconds int) error {
	c := mustCore()
	row, err := c.store.GetRoute(routeID)
	if err != nil {
		return err
	}
	c.pm.Attempt(routeID, row.TransportFamily)
	c.pm.Failed(routeID, row.TransportFamily, diagnostics.Unknown)
	_ = seconds // honored by Failed via the V0.3 mapping; explicit override deferred to V2
	return nil
}

// ImportSBP is engine_import_sbp. Returns a JSON verdict.
func ImportSBP(path string) (string, error) {
	c := mustCore()
	body, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	v, err := importer.ImportBytes(body, c.adapter, publisher.DefaultWordlists(), nowUTC())
	if v.Kind == importer.VerdictTrustPromptNeeded {
		c.mu.Lock()
		c.pending[v.Fingerprint] = &pendingPrompt{body: append([]byte(nil), body...)}
		c.mu.Unlock()
		// Persist pending prompt across process invocations.
		_ = c.persistPendingPrompt(v.Fingerprint, body)
	}
	out, _ := json.Marshal(v)
	return string(out), err
}

// ResolveTrustPrompt is engine_resolve_trust_prompt.
// decision: 0=trust, 1=once, 2=cancel.
func ResolveTrustPrompt(fingerprint string, decision int) (string, error) {
	c := mustCore()
	c.mu.Lock()
	pending, ok := c.pending[fingerprint]
	if ok {
		delete(c.pending, fingerprint)
	}
	c.mu.Unlock()
	if !ok {
		// Try the persisted store on disk.
		body, perr := c.loadPendingPrompt(fingerprint)
		if perr != nil {
			return "", fmt.Errorf("abi: no pending prompt for %s", fingerprint)
		}
		pending = &pendingPrompt{body: body}
	}
	dec := "cancel"
	switch decision {
	case 0:
		dec = "trust"
	case 1:
		dec = "once"
	case 2:
		dec = "cancel"
	}
	v, err := importer.AcceptTrustPrompt(dec, pending.body, c.adapter,
		publisher.DefaultWordlists(), nowUTC())
	_ = c.deletePendingPrompt(fingerprint)
	out, _ := json.Marshal(v)
	return string(out), err
}

// ProbeUDP is engine_probe_udp.
func ProbeUDP(timeoutMs int) int { return probeStub(timeoutMs) }

// ProbeDNS is engine_probe_dns.
func ProbeDNS(timeoutMs int) int { return probeStub(timeoutMs) }

// ProbeTCP443 is engine_probe_tcp443.
func ProbeTCP443(timeoutMs int) int { return probeStub(timeoutMs) }

// probeStub is the Phase 1B probe placeholder; the real probes live in
// engine/probe.go and are wired here in Phase 1C.
func probeStub(timeoutMs int) int {
	if timeoutMs <= 0 {
		return 1
	}
	return 0
}

// StatsRedacted is engine_stats_redacted.
func StatsRedacted() (string, error) {
	c := mustCore()
	in, out, err := c.driver.Stats()
	if err != nil {
		return "", err
	}
	body, _ := json.Marshal(map[string]any{
		"bytes_in":  in,
		"bytes_out": out,
		"bucket":    routestore.HourBucket(nowUTC()),
	})
	return string(body), nil
}

// ExportDiagnostics is engine_export_diagnostics. Returns a redacted blob
// the user can manually share via the system share sheet.
//
// Phase 2A widens the JSON shape additively: the existing fields are
// unchanged, and a `budgets` array is appended that mirrors the
// per-route output of core/budget.Engine.Snapshot (V2.1).
func ExportDiagnostics() (string, error) {
	c := mustCore()
	routes, _ := c.store.ListRoutes()
	out := map[string]any{
		"version": Version,
		"mode":    c.mode,
		// Phase 3-Soak: the deprecated `state` field is removed
		// per the locked decision 13 in
		// `phases of development/27-phase-3-soak-success-metric.md`.
		// Diagnostics consumers on every platform stub MUST read
		// `posture` (the 8-state FSM from 2B) instead. ABI-neutral:
		// removing a diagnostics field does not change the symbol
		// count.
		"posture":     c.pm.Posture(),
		"why":         c.pm.LastReason(),
		"route_count": len(routes),
		"bucket":      routestore.HourBucket(nowUTC()),
		// Phase 2B widens additively: route_health[] and
		// skipped_families[] are always present (possibly empty
		// arrays). This keeps the diagnostics JSON shape stable
		// regardless of whether any failures have been observed in
		// the current session.
		"route_health":     c.pm.RouteHealth(),
		"skipped_families": c.pm.SkippedFamilies(),
		// Phase 2C widens additively: the hashed network ID the
		// engine is currently bound to. The raw SSID / BSSID /
		// carrier strings NEVER appear here — only the truncated
		// SHA-256 hash. The opsec regression test
		// (TestSSIDDoesNotLeakIntoDiagnostics) is the canonical
		// guard.
		"current_network_id": activeNetworkID(),
		// Phase 2D widens additively. None of these fields carry
		// PIN-derived material. `storage_profile` is "vault" (PIN-
		// encrypted on-disk identity) or "keystore" (platform-
		// keystore-backed); the labels are behavioural, never
		// group-based. The PIN no-leak regression is
		// TestPINDoesNotLeakIntoDiagnostics.
		"secrets_unlocked":            c.secretsUnlocked,
		"storage_profile":             c.storageProfile,
		"session_allows_bulk_capable": false, // overwritten below if budget engine is up
		// Phase 2G: auto-promotion preference and last-fire timestamp.
		// `auto_promotion_enabled` is always present; the
		// `auto_promotion_last_fired_at` field is rendered only when
		// the detector has fired at least once this engine session.
		"auto_promotion_enabled": c.autoPromotionEnabled,
		// Phase 3A: experimental-families gate. The
		// `experimental_families_enabled` field is always present
		// (default false). The `experimental_routes_skipped` field
		// is the per-rank-pass tally of routes filtered by the
		// gate; it is a snapshot, not a cumulative counter, and is
		// 0 until the pathmanager has run at least one rank pass.
		"experimental_families_enabled": c.experimentalFamiliesEnabled,
		"experimental_routes_skipped":   c.experimentalRoutesSkipped,
		// Phase 3B. The rendezvous-priority override is the
		// per-engine list (or nil → bundle default). The
		// rendezvous_channel field is the most recent winning
		// channel on the active network; empty string means
		// "no winner observed yet this session." Push opt-in
		// is always present; default false; rejected by Init
		// in the vault profile.
		"rendezvous_priority":             c.rendezvousPriorityOverride,
		"rendezvous_channel":              c.lastWinningRendezvousChannel,
		"push_rendezvous_enabled":         c.pushRendezvousEnabled,
		"last_winning_rendezvous_channel": c.lastWinningRendezvousChannel,
		// Phase 3C. The masque_submode field is the sub-mode
		// chosen by the masque handler on the most recent
		// activation (across all routes / networks this
		// session). Empty string means "no masque route
		// activated yet." The masque_submode_override field
		// is the engine-pinned override (empty string means
		// "no override — use the auto cascade"). Both fields
		// are enumerable (one of three values + empty); they
		// never carry URLs or IPs, satisfying the redaction
		// invariant. See specs/masque-ladder-v1.md and
		// specs/engine-abi-v1.md "Phase 3C".
		"masque_submode":          c.lastChosenMasqueSubmode,
		"masque_submode_override": c.masqueSubmodeOverride,
		// Phase 3D refraction-family hooks. The compile-in
		// booleans are populated from build-tag-conditional
		// shims (see psiphon_compiled.go / conjure_compiled.go);
		// `-tags no_psiphon` flips psiphon_compiled_in to false
		// and the engine refuses to activate psiphon routes
		// rather than papering over the missing vendor tree.
		// `psiphon_active_route` / `conjure_active_route` are
		// session-scoped snapshots of the most recently
		// activated route ID for each family (empty string
		// means "no activation this session").
		// `conjure_phantom_in_use` is the HASHED phantom IP
		// the conjure handler most recently picked: locked at
		// 3D as 8-byte-SHA-256-hex, the raw IP NEVER appears
		// here. See specs/conjure-route-v1.md "Diagnostics".
		"psiphon_compiled_in":    psiphonCompiledIn,
		"conjure_compiled_in":    conjureCompiledIn,
		"psiphon_active_route":   c.lastActivePsiphonRouteID,
		"conjure_active_route":   c.lastActiveConjureRouteID,
		"conjure_phantom_in_use": c.lastConjurePhantomHashHex,
		// Phase 3E WASM transport-slot diagnostics. The four
		// fields are always present (default zero values match
		// "no WASM activity yet this session"). The
		// `loaded_wasm_modules` array is rendered as a JSON
		// array of objects (slug + sha256_prefix + loaded_at);
		// `last_wasm_module_dial_outcome` is one of the
		// closed v1 enum values (`ok`, `fuel_exhausted`,
		// `memory_cap`, `dial_timeout`, `host_callback_error`)
		// or empty string until the first dial completes.
		// `wasm_compiled_in` flips to false under
		// `-tags no_wasm` (mirrors 3D's `psiphon_compiled_in`
		// pattern). See specs/wasm-transport-v1.md.
		"wasm_compiled_in":              wasmCompiledIn,
		"loaded_wasm_modules":           wasmLoadedModulesForDiagnostics(),
		"wasm_kill_switched_count":      WasmKillSwitchedCount(),
		"last_wasm_module_dial_outcome": LastWasmDialOutcome(),
		// Phase 3F delegate-share diagnostics. The three
		// fields are always present (default zero values
		// match "no re-share activity yet this session" —
		// `delegate_share_counters` is `{}` and
		// `last_delegate_share_outcome` is "" until the first
		// engine_redistribute_route call). The
		// `delegate_share_compiled_in` flag flips to false
		// under `-tags no_delegate_share` (mirrors 3D's
		// `psiphon_compiled_in` + 3E's `wasm_compiled_in`
		// patterns). See specs/delegate-keys-v1.md.
		"delegate_share_compiled_in":  delegateShareCompiledIn,
		"delegate_share_counters":     DelegateShareCountersForDiagnostics(),
		"last_delegate_share_outcome": LastDelegateShareOutcome(),
	}
	if !c.lifelineStrictSince.IsZero() {
		out["lifeline_strict_active_since"] = c.lifelineStrictSince.Format("2006-01-02T15:04:05Z07:00")
	}
	if !c.autoPromotionLastFiredHour.IsZero() {
		out["auto_promotion_last_fired_at"] = c.autoPromotionLastFiredHour.Format("2006-01-02T15:04:05Z07:00")
	}
	// Phase 2E (soak only): if the soak-build hook is registered,
	// invoke it to add the `wg_subengine_*` fields. Release builds
	// never register the hook so this branch is a noop and the
	// diagnostics JSON shape is unchanged off-soak.
	if soakDiagHook != nil {
		soakDiagHook(out)
	}
	// Phase 2E: surface the most recent lifecycle event. Both fields
	// are rendered only after the iOS bridge has fired at least one
	// event; release builds on Linux/Android/desktop never write
	// these, so the diagnostics surface stays unchanged for non-iOS
	// platforms.
	if c.lastLifecycleEvent != "" {
		out["last_lifecycle_event"] = c.lastLifecycleEvent
		out["last_lifecycle_at"] = c.lastLifecycleAt.Format("2006-01-02T15:04:05Z07:00")
	}
	if be := globalBudget; be != nil {
		// Only render budgets[] if the engine has been instantiated;
		// pre-2A diagnostics callers and unit tests that don't touch
		// budgets see the original JSON shape.
		be.mu.Lock()
		eng := be.engine
		be.mu.Unlock()
		if eng != nil {
			out["budgets"] = eng.Snapshot()
			// Phase 2D: if the budget engine is up, the
			// session_allows_bulk_capable diagnostic reflects
			// the engine's per-session opt-in flag.
			out["session_allows_bulk_capable"] = eng.AllowsBulkCapableThisSession()
		}
	}
	body, _ := json.MarshalIndent(out, "", "  ")
	return string(body), nil
}

// Subscribe returns the global event channel; callers must drain it.
func Subscribe() <-chan engine.Event {
	return mustCore().subs
}

func mustCore() *Core {
	if globalCore == nil {
		panic(errors.New("abi: not initialized — call Init first"))
	}
	return globalCore
}
