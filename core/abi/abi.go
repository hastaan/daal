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
	"sync/atomic"
	"time"

	"daal/bundle-go/importer"
	"daal/bundle-go/publisher"
	"daal/core/diagnostics"
	"daal/core/engine"
	"daal/core/netmem"
	"daal/core/pathmanager"
	"daal/core/refresh"
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
//   - 0.7.3+v3-transport (Phase 3D): refraction-family hooks. Two new transport families (psiphon, conjure), both shipped as Experimental. [CORRECTED IN WAVE 5 — this sentence was never true. Neither tree was ever vendored: core/go.mod has never required psiphon-tunnel-core or gotapdance, and no build script passes `-tags no_psiphon`. `psiphon_compiled_in` and `conjure_compiled_in` were hard-coded `true` for an absent dependency until Wave 5 set both to false and made the recorders refuse; see core/abi/refraction_compiled.go for the audit. NO GPLv3 CODE IS LINKED INTO ANY SHIPPED DAAL BINARY. The original claim: "Psiphon is opaque-blob carriage (vendored psiphon-tunnel-core under GPLv3, isolated behind `-tags no_psiphon`); conjure is vendored gotapdance under Apache-2.0".] Phantom-pool floors locked at /24 IPv4 + /32 IPv6. Family registry gains `IsOpportunistic` (psiphon NOT opportunistic, conjure IS, masque retroactively annotated). NO new ABI symbols (release surface 45→45, append-only invariant preserved). Diagnostics widen with psiphon_compiled_in / conjure_compiled_in / psiphon_active_route / conjure_active_route / conjure_phantom_in_use (HASHED via 8-byte SHA-256). See specs/psiphon-route-v1.md and specs/conjure-route-v1.md.
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
	// engine_set_experimental_families_enabled.
	//
	// ONE rank pass reads the flag: the automatic connect
	// (connect_auto.go, autoCandidatesLocked →
	// pathmanager.RankWithExperimentalGate), which leaves experimental
	// routes out of its candidates while the flag is off and writes the
	// number it left out to experimentalRoutesSkipped. A route the
	// person picks by hand (engine_set_route) is NOT gated, as before:
	// until the automatic connect existed nothing read the flag at all,
	// and this comment said so.
	//
	// The skip count is the tally of the LAST automatic pass, surfaced
	// as `experimental_routes_skipped` in diagnostics (a snapshot, not a
	// cumulative counter). 0 until a pass has run.
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

	// Connection check (route_check.go). proofCfg is read once at Init
	// from the optional engine-config.json. activeRoute/activeFamily
	// name the route whose engine instance is running (verifying or
	// connected); routeEpoch increments every time that changes hands
	// (SetRoute, ClearRoute), so a proof that returns after the route
	// it was proving has been replaced can tell and records nothing.
	// All four are guarded by mu; `check` has its own lock.
	proofCfg     engine.ProofConfig
	activeRoute  string
	activeFamily string
	routeEpoch   uint64
	check        routeCheck
	// auto: the automatic connect (connect_auto.go). Its own lock for
	// the readers; `gen` inside it is guarded by mu.
	auto autoState
	// recover: the direct walk for a new relay address when the
	// connected route has gone dead (relaypack_recover.go). Its control
	// fields are guarded by mu; its own lock for the readers.
	recover recoverState
	// shuttingDown: Shutdown has taken this core. Nothing starts an
	// engine instance after it is set. Guarded by mu.
	shuttingDown bool
	// side / race: the side-probe limits and the race in flight
	// (connect_race.go). speed: the move to a faster route
	// (connect_speed.go). All guarded by mu.
	side  sideLimits
	race  *raceHandle
	speed speedState
	// survey: checking the other routes beside the tunnel (survey.go).
	// Its own lock.
	survey surveyState

	// activeSnap mirrors activeRoute/activeFamily for readers that must
	// not wait for mu (SetRoute holds it across driver.Start): the
	// diagnostics blob serves `active_route` from here. Written only by
	// setActiveLocked. It is the engine's MEMORY of what is running and
	// never depends on the route store being readable.
	activeSnap atomic.Pointer[activeRouteSnap]

	// storeRecovered: the route store was found damaged and set aside
	// (routestore.OpenOrRecover) at this start or an earlier one, and
	// the person has not imported anything since. `store_recovered` in
	// the diagnostics blob.
	storeRecovered atomic.Bool

	// explainMu / explainWritten: the last "why this route?" record
	// DiagnosticsExplain persisted, so a poll that has nothing new to
	// say does not write to the store (refresh.go).
	explainMu      sync.Mutex
	explainWritten [3]string
	explainSaved   bool
}

// activeRouteSnap is one consistent (route, family) pair.
type activeRouteSnap struct{ route, family string }

// setActiveLocked records which route's engine instance is running
// ("" for none). Called with mu held; the only writer of activeRoute.
func (c *Core) setActiveLocked(routeID, family string) {
	c.activeRoute, c.activeFamily = routeID, family
	c.activeSnap.Store(&activeRouteSnap{route: routeID, family: family})
}

// activeRouteFromMemory returns the running route and its family
// without taking mu and without touching the store.
func (c *Core) activeRouteFromMemory() (routeID, family string) {
	if a := c.activeSnap.Load(); a != nil {
		return a.route, a.family
	}
	return "", ""
}

// globalCorePtr holds the process-wide Core. Init fully constructs the
// Core, then publishes it with one atomic store; readers go through
// loadedCore() and observe either nil (clean "not initialized" error)
// or a fully initialised Core — never a partially built one. A plain
// pointer variable here is a data race against the concurrent ABI
// pollers (TestInit_NoNilDerefFromConcurrentReaders).
var globalCorePtr atomic.Pointer[Core]

func loadedCore() *Core { return globalCorePtr.Load() }

// soakDiagHook is registered ONLY by `-tags soak` builds (see
// ios_handoff_diag.go). Release builds leave it nil and the
// diagnostics renderer skips the call.
var soakDiagHook func(map[string]any)

// Init is engine_init.
//
// Concurrency contract: the Core is published in a single atomic
// store at the end of this function, after every sub-field is
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
	// Before the store is opened: a configuration file that does not
	// parse must fail Init without leaving a database handle behind.
	proofCfg, err := loadProofConfig(stateDir)
	if err != nil {
		return err
	}
	// A route store that is not a usable database is set aside (never
	// deleted) and replaced by an empty one, instead of failing Init:
	// the shell treats a failed Init as fatal, so a damaged file would
	// otherwise crash the app on every launch, and the only way out a
	// person has — clearing the app's data — also destroys the
	// publisher's operator database. Anything that is not damage (a
	// permission error, a bad secrets key, a full disk) still fails
	// here. See routestore.OpenOrRecover for what counts.
	s, setAside, err := routestore.OpenOrRecover(stateDir, nowUTC())
	if err != nil {
		return err
	}
	if len(setAside) > 0 {
		engine.LogError(fmt.Sprintf("init: the route store was damaged; set aside %d file(s) and started empty", len(setAside)))
	}

	core := &Core{
		proofCfg:             proofCfg,
		stateDir:             stateDir,
		logLevel:             logLevel,
		pending:              map[string]*pendingPrompt{},
		mode:                 "normal",
		autoPromotionEnabled: true,
		store:                s,
		adapter:              &trust.StoreAdapter{S: s},
		driver:               newEngineDriver(),
		pm:                   pathmanager.New(),
		subs:                 make(chan engine.Event, 32),
	}
	core.pm.SetNow(nowUTC)
	core.adapter.OnRouteRebound = core.routeRebound
	core.driver.Subscribe(core.subs)
	// From what this Init just did, not only from the marker on disk:
	// the marker is written best-effort (a nearly full disk can take the
	// renames and refuse the new file), and a person whose routes were
	// just set aside must be told whether or not it was.
	core.storeRecovered.Store(len(setAside) > 0 || s.RecoveryPending())

	// Wave 5: tell the engine where tor may keep its data directory.
	// tor caches the directory consensus there; without it every route
	// switch pays a cold bootstrap (sing-box's own docs call
	// data_directory "Recommended" for this reason). The path must be
	// app-writable and sandboxed, which is exactly what stateDir is.
	engine.SetTorStateDir(stateDir)

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

	// Atomic publish. Every other engine function reads loadedCore();
	// before this point they observe nil (clean Java Exception via
	// mustCore), after this point they see a fully populated Core.
	globalCorePtr.Store(core)

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
	loadExperimentalFamiliesEnabled(loadedCore())
	// Phase 3B: daalte the rendezvous priority override + push
	// opt-in + push device token from the secrets KV. The vault
	// profile rejects push-related fields at daalte time even
	// if a corrupt persisted state attempts to enable them.
	loadRendezvousState(loadedCore())
	// Phase 3C: daalte the MASQUE sub-mode override from the
	// secrets KV. Missing / out-of-list values default to "no
	// override" (auto cascade).
	loadMasqueState(loadedCore())
	// Step 11: reap abandoned trust prompts. Every
	// VerdictTrustPromptNeeded writes the decoded bundle to
	// stateDir/pending/<fp>.sbp so the decision survives a restart, and
	// only ResolveTrustPrompt deletes it — so a prompt the user closes
	// without answering keeps plaintext route credentials on disk
	// indefinitely. Init is the safe moment: no prompt is mid-flight.
	core.sweepPendingPrompts(PendingPromptTTL, nowUTC())
	// Retention, enforced on the one event that happens regardless of
	// ticks and tunnels. The refresh_audit / diagnostics_explain prunes
	// otherwise run only on the write path, so a device that stopped
	// writing — disconnected, or seized — keeps its last 72 hours
	// forever. See routestore.PruneLocalHistory.
	_ = s.PruneLocalHistory(nowUTC())
	return nil
}

// Shutdown is engine_shutdown.
func Shutdown() error {
	// Swap so concurrent Shutdown calls cannot double-Stop the same
	// Core: exactly one caller wins the pointer.
	c := globalCorePtr.Swap(nil)
	if c == nil {
		return nil
	}
	// A proof in flight and the liveness loop both hold the driver;
	// let go of them before it is stopped.
	c.check.abandon()
	// Under the lock, so a connect that holds it between two candidates
	// of an automatic pass (or on its way back to a route) has either
	// not begun its next instance — and will not: shuttingDown — or has
	// registered the check that the second abandon cancels. Without
	// this a pass went on to start, prove and watch a route on a core
	// whose store this call is about to close (and whose state
	// directory PanicWipe is about to delete). The lock is never held
	// across a connection check, so this does not wait for one.
	c.mu.Lock()
	c.shuttingDown = true
	c.routeEpoch++
	c.auto.gen++
	c.cancelRaceLocked()
	c.survey.stop("shutdown")
	recoverDone := c.recover.done
	c.cancelRecoverLocked()
	c.check.abandon()
	if c.driver != nil {
		_ = c.driver.Stop()
	}
	c.mu.Unlock()
	// A walk for a new relay address that was just cut off writes its
	// stamps back on the way out; let it, briefly, before the store
	// closes. (Outside the lock: it takes the lock to finish.)
	if recoverDone != nil {
		select {
		case <-recoverDone:
		case <-time.After(recoverShutdownWait):
		}
	}
	// Side instances (a race, a speed check) are cancelled above or by
	// the liveness loop's context; this waits until each is closed, so
	// nothing of the engine is still dialling when the store goes away.
	// Outside the lock: a probe's caller takes it to file its result.
	if sp, ok := c.driver.(engine.SideProber); ok {
		sp.StopSideProbes()
	}
	resetSchedulerForShutdown()
	resetBudgetForShutdown()
	resetRefreshForShutdown()
	resetBootstrapForShutdown()
	resetShareForShutdown()
	resetTunnelForShutdown()
	resetTunFDForShutdown()
	resetClockForShutdown()
	resetNetmemForShutdown()
	resetPushQueueForShutdown()
	resetWasmStateForShutdown()
	resetDelegateStateForShutdown()
	resetFieldProbeForShutdown()
	if c.store != nil {
		return c.store.Close()
	}
	return nil
}

// VersionString is engine_version.
func VersionString() string { return Version }

// SetRoute is engine_set_route.
//
// It returns nil only when the route has CARRIED A ROUND TRIP. The
// engine instance starting is not that: sing-box dials the relay lazily,
// so a route to a blocked relay starts like any other. After Start the
// route is "verifying" (route_check in the diagnostics blob), the
// driver proves the data plane through the route's own outbound
// (core/engine/proof.go), and only then is the route Connected and a
// success recorded. A route that fails the proof is torn down,
// classified, cooled down and recorded exactly as a Start failure is,
// and the error is returned. See route_check.go.
//
// The proof takes up to the configured bound (8 s by default; a tor
// route is given longer). Core.mu is NOT held across it: the
// diagnostics pollers, SetMode and — above all — ClearRoute must not
// wait for a connection check, and a ClearRoute or a second SetRoute
// during it cancels it (ErrConnectCancelled).
//
// A call that is REFUSED — unknown route, revoked or expired, cooling
// down, endpoint guard, config build — changes nothing: the route that
// was connected stays connected and stays watched by its liveness loop,
// and a connection check in flight for another SetRoute goes on.
//
// A switch AWAY from a route that was carrying, to a route that then
// carries nothing, still returns the error — and the engine goes back
// to the route that was carrying (see `switch_back`, and the end-to-end
// rig's finding SW-1). A host must therefore read `active_route` /
// `route_running` after a failed SetRoute before it tears anything
// down.
//
// A SetRoute that gets past its refusals is the person choosing a route
// by hand: it ends the automatic connect (`auto.mode` false).
func SetRoute(routeID string) error {
	c := mustCore()
	// Fail closed before anything else. On a build with no data plane
	// linked the driver is engine.Stub, whose Start() returns nil
	// without opening a socket and whose Prove() has nothing to
	// disprove — so every line below would faithfully record a tunnel
	// that does not exist and the GUI would render it. Refusing here is
	// the only honest outcome; see core/abi/dataplane.go for the
	// artefact-by-artefact tag table.
	if !dataPlaneLinked {
		return ErrNoDataPlane
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// What was connected before this call, for the way back (below).
	prev := c.activeRoute
	st, _, running := c.check.snapshot()
	prevCarrying := prev != "" && prev != routeID && running && (st == RouteCheckOK || st == RouteCheckDegraded)

	out := c.connectRouteLocked(routeID, connectOpts{manual: true, record: true})
	if (out.result == AutoResultNotCarrying || out.result == AutoResultStartFailed) && prevCarrying {
		// The end-to-end rig's finding SW-1: the person was connected,
		// switched, and the new route carries nothing. The switch has
		// failed and is reported as that (the error below, the route's
		// failure row and cooldown) — and the route that was carrying a
		// moment ago is started and checked again rather than leaving
		// them with nothing. `switch_back` in the diagnostics says so.
		sb := SwitchBack{FailedRoute: routeID, FailedFamily: out.family, Category: string(out.category), RestoredRoute: prev}
		back := c.connectRouteLocked(prev, connectOpts{restore: true})
		switch back.result {
		case AutoResultCancelled:
			// Somebody else took the engine meanwhile; the state is
			// theirs.
			return out.err
		case AutoResultCarried:
			sb.Restored = true
		default:
			// The way back failed too. What the person asked for was
			// the switch, so the failure they are shown is the switch's.
			c.check.setFailed(out.category, false)
			c.check.mu.Lock()
			c.check.failedRoute, c.check.failedFamily = routeID, out.family
			c.check.failedCooled = !pmCooldownUntil(c, routeID).IsZero() && out.category != diagnostics.PathTooSlow
			c.check.mu.Unlock()
		}
		c.check.setSwitchBack(sb)
		engine.LogInfo(fmt.Sprintf("route switch_back failed=%s category=%s back_to=%s restored=%t",
			engine.LogID(routeID), engine.LogID(string(out.category)), engine.LogID(prev), sb.Restored))
	}
	return out.err
}

// connectOpts says on whose behalf connectRouteLocked runs.
type connectOpts struct {
	// manual: the person picked this route (engine_set_route). Getting
	// past the refusals ends the automatic connect: its pass in flight
	// is abandoned and `auto.mode` goes false.
	manual bool
	// record: a refusal is kept in connect_refused and logged.
	record bool
	// auto: a candidate of an automatic pass. The connection check is
	// given the shorter budget (ProofConfig.StopAtUnreachedRelay), and
	// a failure is charged as a candidate's (routeDownOptsLocked): the
	// pass settles the durable record once it knows what the whole set
	// of results says (autoSettleLocked).
	auto bool
	// restore: going back to the route that was connected before a
	// switch that failed. Leaves the switch_back record alone.
	restore bool
	// noMemory: a success is not written to this network's memory — the
	// caller already has (the side probe that just proved the route is
	// the measurement; this attempt is its hand-over to the tunnel).
	noMemory bool
	// variant / ladder: the connect ladder (connect_ladder.go). variant
	// nil is the variant in use for the route on this network (or the
	// plain route); non-nil is exactly that one. ladder: an extra of a
	// pass, after the route's own attempt was charged in it — the
	// route's cooldown is not checked, and a failure is the variant's
	// alone (never the route's, the relay's or the family's).
	variant *routeVariant
	ladder  bool
}

// connectOutcome is what one attempt at one route came to. result is
// the vocabulary of the automatic connect's `tried` list.
type connectOutcome struct {
	result   string
	family   string
	category diagnostics.Category
	// refused: the connect_refused code, when result is "refused".
	refused string
	// obs: the last failed attempt of the connection check, when result
	// is "not_carrying". In memory only; it can carry addresses.
	obs diagnostics.Observation
	err error
	// setupMs: for "carried", the time from starting the instance to
	// the first completed round trip.
	setupMs int
}

// connectRouteLocked is one attempt to connect one route: the refusals,
// the engine instance, the connection check, and the record of how it
// went. engine_set_route is one call of it; the automatic connect is one
// call per candidate.
//
// Called with Core.mu held and returns with it held. The lock is
// RELEASED for the connection check (seconds), so the diagnostics
// pollers, SetMode and — above all — ClearRoute do not wait for it; a
// ClearRoute, a manual SetRoute or a newer automatic connect during it
// takes the engine, and this call comes back "cancelled" having recorded
// nothing.
func (c *Core) connectRouteLocked(routeID string, o connectOpts) connectOutcome {
	// Every way out of this function before anything is started goes
	// through prepareRouteOpts, which keeps the reason (as a closed
	// code) for the diagnostics blob: on Android the returned error
	// reaches nobody.
	row, body, err := c.prepareAttemptLocked(routeID, &o)
	if err != nil {
		code := ConnectRefusedOther
		var rr *routeRefusal
		if errors.As(err, &rr) {
			code = rr.code
		}
		if o.record {
			logRouteRefused(routeID, err, c.activeRoute)
		}
		return connectOutcome{result: AutoResultRefused, refused: code, err: err}
	}
	family := row.TransportFamily
	if c.shuttingDown {
		return connectOutcome{result: AutoResultCancelled, family: family, err: ErrConnectCancelled}
	}
	if o.manual {
		c.autoStopLocked(false)
	}
	// Every refusal is behind us: from here this call REPLACES whatever
	// is running, so whatever was being proved or watched belongs to the
	// route it replaces. Not a line earlier — a refused SetRoute leaves
	// the connected route up, and abandoning its liveness loop there
	// left it "Connected" (or "failed", for good) with nothing ever
	// checking it again.
	c.check.abandon()
	c.check.setRefused(ConnectRefusedNone, "")
	if !o.restore {
		c.check.setSwitchBack(SwitchBack{})
	}
	c.routeEpoch++
	epoch := c.routeEpoch
	if prev := c.activeRoute; prev != "" && prev != routeID {
		engine.LogInfo(fmt.Sprintf("route switch from=%s to=%s family=%s", engine.LogID(prev), engine.LogID(routeID), engine.LogID(family)))
	}
	c.pm.Attempt(routeID, family)
	started := time.Now()
	if err := c.driver.Start(context.Background(), body); err != nil {
		// Start failed: there is no instance. Classified from the error
		// text alone — a config or start-up error has no phase.
		cat := diagnostics.Classify(err.Error())
		c.setActiveLocked(routeID, family)
		c.attemptStartFailedLocked(routeID, family, cat, err.Error(), o)
		return connectOutcome{result: AutoResultStartFailed, family: family, category: cat, err: err}
	}
	// The instance is up and has dialled nothing. From here until
	// ClearRoute (or the teardown of a failed proof), any refresh that
	// cannot ride it must FAIL rather than egress from the device's real
	// address — see refresh.ErrTunnelRequired for the leak this closes.
	// Note this deliberately fires even on platforms that have no
	// tunnel-aware dialer yet: on those, scheduled refresh stops working
	// while connected, which is the intended trade.
	// A walk for a new relay address (relaypack_recover.go) that may
	// still hold a connection open from the real address ends here, not
	// a few seconds after a live tunnel is beside it.
	c.cancelRecoverLocked()
	refresh.SetTunnelRequired(true)
	c.setActiveLocked(routeID, family)
	c.pm.Verifying()
	c.check.set(RouteCheckVerifying, "")
	pctx, cancel := context.WithCancel(context.Background())
	c.check.mu.Lock()
	c.check.cancelProof = cancel
	c.check.mu.Unlock()
	proofCfg := c.proofCfg
	if o.auto {
		proofCfg.StopAtUnreachedRelay = true
		proofCfg.TimeHelloStop = true // the connect ladder reads it
	}
	c.mu.Unlock()

	res := c.driver.Prove(pctx, proofCfg)
	cancel()

	c.mu.Lock()
	if c.routeEpoch != epoch || res.Cancelled {
		// ClearRoute or another connect took the engine while this
		// proof ran. The state is theirs; nothing was learned about the
		// route, and nothing is recorded.
		return connectOutcome{result: AutoResultCancelled, family: family, err: ErrConnectCancelled}
	}
	if !res.OK {
		cat := res.Category()
		reason := c.attemptProofFailedLocked(routeID, family, cat, res, o)
		return connectOutcome{result: AutoResultNotCarrying, family: family, category: cat, obs: res.Observation,
			err: &routeFailure{routeID: routeID, category: cat, reason: reason}}
	}
	setupMs := setupOf(time.Since(started), res)
	// The running route's latest proof, until its first liveness check
	// (the move to the best route compares against it: connect_best.go).
	c.speed.lastCheck = time.Duration(setupMs) * time.Millisecond
	c.routeUpLocked(routeID, family, res)
	c.startLivenessLocked()
	if !o.noMemory {
		c.rememberOutcome(attemptMemKey(routeID, o), netmem.RouteOutcome{Carried: true, HasSetup: true, SetupMs: setupMs, Slow: res.Slow})
	}
	c.variantCarriedLocked(routeID, o)
	// A host that turned tunnelled refresh on is pointed at THIS
	// instance's inlet: it may not know this instance exists.
	rearmTunnelRefresh()
	return connectOutcome{result: AutoResultCarried, family: family, setupMs: setupMs}
}

// ClearRoute is engine_clear_route. It stops whatever is running or
// being checked and resets the connection state to "no route" — and
// when it finds nothing to stop it changes nothing a reader can see:
// the verdict of a connect that already failed or was refused stays in
// the diagnostics (see below).
func ClearRoute() error {
	c := mustCore()
	// Before taking the lock: a connection check in flight must be
	// abandoned, not waited for (it is bounded in seconds, and a
	// Disconnect tap that hangs for them is the complaint behind
	// end-to-end rig's finding O-2).
	c.check.abandon()
	c.mu.Lock()
	defer c.mu.Unlock()
	// Again, now that the lock is held: a connect that was between "the
	// instance is up" and "the check has started" when the line above
	// ran has registered its check since, and would otherwise run it to
	// the end against an engine this call is about to stop.
	c.check.abandon()
	c.routeEpoch++
	// An explicit disconnect ends the automatic connect, whatever else
	// this call finds. A pass in flight is abandoned (and counts as
	// something stopped); the verdict of a pass that already FAILED is
	// kept, for the same reason the failed connect's verdict is.
	autoWasTrying := c.autoStopLocked(true)
	// Did this call find anything to stop? Read before the driver is
	// stopped, under Core.mu (every transition out of "nothing running"
	// is made under it). A check that was in flight a moment ago still
	// reads verifying here — the SetRoute it belonged to records nothing
	// once it is cancelled — so it counts as something stopped.
	st, _, running := c.check.snapshot()
	nothingRunning := !autoWasTrying && (st == RouteCheckNone || (st == RouteCheckFailed && !running))
	stopped, stoppedFamily := c.activeRoute, c.activeFamily
	if err := c.driver.Stop(); err != nil {
		return err
	}
	c.setActiveLocked("", "")
	if stopped != "" {
		engine.LogInfo(fmt.Sprintf("route down route=%s family=%s result=disconnected", engine.LogID(stopped), engine.LogID(stoppedFamily)))
	}
	// No route: there is no tunnel to betray, so direct egress is
	// permitted again (bootstrap has to start somewhere).
	refresh.SetTunnelRequired(false)
	if nothingRunning {
		// Nothing was running and nothing was being checked, so there is
		// nothing this call disconnected — and what the diagnostics say
		// about the LAST connect (it failed, and why; or it was refused,
		// and why) is still the truth. It must survive this call: a host
		// that tears its own plumbing down after a connect that did not
		// come up calls ClearRoute as part of that (the Android VPN
		// service does, on every such connect, before the page has
		// polled once), and wiping the verdict there left the person
		// with "Press to connect." and no reason. The verdict ends where
		// it always did: at the next SetRoute that gets past its
		// refusals, and when the cooldown the failure started runs out
		// (expireFailedConnect).
		return nil
	}
	c.check.set(RouteCheckNone, "")
	// This call stopped something, so it is a disconnect, and a
	// disconnected engine reports no refusal: whatever was refused
	// earlier is not being asked for any more. (A refusal used to be
	// kept through a ClearRoute that came within five seconds of it,
	// for a host that tore everything down after a refused switch. No
	// host does: the Android service asks engine_route_precheck first
	// and a refused switch touches nothing. The only ClearRoute left in
	// that window was the person's own Disconnect, after which the
	// refusal stood for good.)
	c.check.setRefused(ConnectRefusedNone, "")
	c.check.setSwitchBack(SwitchBack{})
	c.auto.reset()
	c.pm.Disconnect()
	// Posture axis: a user-initiated disconnect always returns to
	// PostureNoRoute. The transition `EventDisconnected → NoRoute`
	// is legal from every active posture in LegalTransitions.
	c.advancePosture(pathmanager.EventDisconnected, pathmanager.PostureNoRoute)
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

// ProbeUnimplemented is the sentinel the probe ABI returns while the
// real probes (engine/probe.go, wired in Phase 1C) don't exist yet. The
// UI maps it to an "unavailable" tile instead of a fake success — a stub
// that returned 0 (ok) made the Status page claim every probe passed.
const ProbeUnimplemented = -1000

// probeStub is the Phase 1B probe placeholder. Until real probes land it
// reports "unimplemented" rather than a fabricated ok/latency.
func probeStub(_ int) int {
	return ProbeUnimplemented
}

// StatsRedacted is engine_stats_redacted.
//
// `bytes_in` / `bytes_out` are NULL when this build cannot count bytes
// (engine.HasByteAccounting == false, which is every build today —
// including the singbox one, whose platformInterface.bytesIn/bytesOut
// are declared "reserved for the stats follow-up phase" and never
// written). This is the same measured/unmeasured rule
// ThroughputSnapshot follows, applied to the other surface that reads
// driver.Stats().
//
// It matters more here than on the Connection page: this blob is what a
// user exports and hands to a helper. A helper reading `bytes_in: 0`
// concludes "the tunnel carried nothing", which is a diagnosis. `null`
// says "nobody counted", which is the truth. Do not restore the zero.
// Backlog CM-1 is the real counter.
func StatsRedacted() (string, error) {
	c := mustCore()
	in, out, err := c.driver.Stats()
	if err != nil {
		return "", err
	}
	var inVal, outVal any // nil marshals as JSON null
	if engine.HasByteAccounting {
		inVal, outVal = in, out
	}
	body, _ := json.Marshal(map[string]any{
		"bytes_in":  inVal,
		"bytes_out": outVal,
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
	c.expireFailedConnect()
	routeCheckState, routeCheckCat, routeRunning := c.check.snapshot()
	connectRefused, connectRefusedRoute := c.check.refusal()
	activeRoute, activeFamily := c.activeRouteFromMemory()
	// A damaged store was set aside and the person has imported again:
	// there is nothing left to tell them.
	if len(routes) > 0 && c.storeRecovered.CompareAndSwap(true, false) {
		c.store.ClearRecoveryPending()
	}
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
		"posture": c.pm.Posture(),
		"why":     c.pm.LastReason(),
		// Connection check (route_check.go). `route_check` is ""
		// (no route), "verifying" (the engine instance is up and the
		// route has NOT yet carried a round trip — a UI must not show
		// this as connected), "ok", "degraded" (connected, too slow to
		// call usable) or "failed". `route_check_category` is the
		// taxonomy category behind "failed" / "degraded", else "".
		// Always present. Both are closed vocabularies.
		"route_check":          routeCheckState,
		"route_check_category": string(routeCheckCat),
		// `route_running`: true exactly while an engine instance for a
		// route is up. It tells the two "failed" apart: false = the
		// connect failed, the instance was torn down and NOTHING will
		// retry (a UI must not say "connecting"); true = a connected
		// route stopped carrying, its instance is up and is re-checked
		// every recheck_interval_s. Always present.
		"route_running": routeRunning,
		// `connect_refused`: why the last engine_set_route was refused
		// before anything was started — "" (it was not), or one of
		// "needs_new_file" (the route came from a file made before
		// files carried signed server addresses), "cooldown", "revoked",
		// "expired", "other". Closed vocabulary, always present; cleared
		// by the next set_route that is not refused and by a clear_route
		// that disconnects a running route (one that finds nothing
		// running leaves it). It is also what a refusing
		// engine_route_precheck records.
		// `connect_refused_route` is the route id it was about.
		"connect_refused":       connectRefused,
		"connect_refused_route": connectRefusedRoute,
		// `active_route` / `active_route_family`: the route whose engine
		// instance is running right now (being checked, connected, or
		// connected and failing its liveness check) and its transport
		// family; "" when nothing is running. Served from the engine's
		// MEMORY, never from the route store: a UI that asks the store
		// which route is active shows "no route selected" over a working
		// tunnel the moment the store cannot answer. Always present.
		"active_route":        activeRoute,
		"active_route_family": activeFamily,
		// `auto`: the automatic connect (engine_connect_auto,
		// connect_auto.go) — {state, mode, trying, index, total, tried,
		// verdict, route_id, family, order}. From memory only; always
		// present. `state` is "idle", "trying", "connected" or "failed";
		// `mode` is true while the engine is the one choosing the route.
		"auto": c.auto.block(),
		// `relay_recovery`: the engine's own walk for a new relay
		// address when the connected route went dead, or the one the
		// person asked for (engine_relaypack_refresh) —
		// {state, trigger, packs, outcome, bucket}. From memory only;
		// always present. See relaypack_recover.go.
		"relay_recovery": c.recover.block(),
		// `survey`: the check of the other routes beside the tunnel
		// (survey.go) — {state, trigger, checking, total, done, seq,
		// stop_reason, results}. state is "idle", "waiting", "checking",
		// "done" or "stopped"; trigger "auto" or "user"; seq counts the
		// results that changed what is remembered (a page re-reads the
		// route list when it moves). From memory only; always present.
		"survey": c.survey.block(),
		// `network`: what the HOST last said about the network the device
		// is on (engine_network_facts) — {from_host, kind, validated,
		// metered}. from_host false: no host has said anything, and the
		// other three are "", -1, -1. kind is "wifi", "cellular",
		// "ethernet", "vpn", "other" or "none"; validated / metered are
		// 1, 0 or -1 (unknown). The network's identity is never here:
		// see current_network_id. Always present.
		"network": hostFacts().block(),
		// `switch_back`: the last manual switch went to a route that
		// carried nothing and the engine went back to the route that was
		// connected — {failed_route, failed_family, category,
		// restored_route, restored}. failed_route "" when there is
		// nothing to report. Always present.
		"switch_back": c.check.getSwitchBack(),
		// `store_recovered`: true when the route store was found damaged
		// at start, was set aside (kept on disk under a dated name) and
		// replaced by an empty one — the person must import their file
		// again. Stays true across restarts until they have. Always
		// present.
		"store_recovered": c.storeRecovered.Load(),
		// `recent_errors`: the last engine calls that failed, newest
		// last — {time, call, text, count}. In memory only; the text is
		// an error CLASS run through the log scrubber (no addresses,
		// credentials or tokens). See export_errors.go. Always present.
		"recent_errors": recentErrors(),
		// Which data plane this binary actually links: "singbox" (real,
		// can carry traffic) or "none" (the deterministic Stub — this
		// binary CANNOT tunnel and SetRoute refuses). A GUI reading
		// "none" must not offer Connect as if it would work. Compile-
		// time fact, never a probe. See core/abi/dataplane.go.
		"data_plane":  DataPlaneKind(),
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
		// (default false).
		//
		// `experimental_routes_skipped` is how many experimental-family
		// routes the LAST automatic connect left out because the gate
		// was off — a snapshot, not a cumulative counter, and 0 until
		// an automatic pass has run. A route picked by hand is never
		// gated and never counted. See the matching note on
		// Core.experimentalFamiliesEnabled.
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
		// Phase 3D refraction-family hooks, corrected in Wave 5.
		// Both compile-in booleans are now constant FALSE and
		// all three route fields are permanently the empty
		// string, because this binary contains no psiphon and no
		// conjure implementation and — unlike every other
		// compile-in flag here — never will: psiphon is a third
		// party's network you hand off to rather than host, and
		// conjure needs a cooperating ISP running a refraction
		// station. `refraction_compiled.go` carries the vendor-
		// tree audit; `bundle/go/bundle/types.go` carries the
		// protocol-level reasons on the enum values themselves.
		//
		// The fields stay in the blob rather than being deleted:
		// they are a documented shape (specs/psiphon-route-v1.md,
		// specs/conjure-route-v1.md, specs/engine-abi-v1.md), the
		// soak rig reads them, and a permanently-empty field that
		// a reader can check beats a field that vanished.
		// `conjure_phantom_in_use` retains its locked redaction
		// contract — if it ever carried a value it would be the
		// 8-byte-SHA-256-hex hash, never the raw IP.
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
	c := loadedCore()
	if c == nil {
		panic(errors.New("abi: not initialized — call Init first"))
	}
	return c
}

// pmCooldownUntil returns the per-route cooldown expiry the pathmanager
// FSM just assigned, or the zero time when the failure class carries no
// cooldown (auth_failed and the other non-cooldown categories). It reads
// the live Manager rather than re-deriving the duration, so the durable
// column and the in-memory FSM cannot disagree about when a route
// becomes selectable again.
func pmCooldownUntil(c *Core, routeID string) time.Time {
	if c == nil || c.pm == nil {
		return time.Time{}
	}
	for _, h := range c.pm.RouteHealth() {
		if h.RouteID == routeID {
			return h.CooldownUntil
		}
	}
	return time.Time{}
}
