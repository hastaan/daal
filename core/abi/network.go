package abi

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"daal/core/budget"
	"daal/core/netmem"
	"daal/core/pathmanager"
)

// Phase 2C: per-network memory. The single new release ABI symbol
// is engine_network_changed (release surface 36 → 37). The full
// V2.4 spec lives in specs/network-memory-v1.md.
//
// State invariants enforced here:
//
//   - Raw SSID / carrier strings are arguments to NetworkChanged
//     ONLY. They are hashed on entry; the hash is the only
//     identifier that crosses the package boundary.
//   - Mode change does NOT bump the budget session epoch
//     (2A-Polish) and neither does network change (2A-Polish
//     carry-over).
//   - The active network ID the engine starts on is netmem.SentinelUnset;
//     the first NetworkChanged() call swaps in real per-network state.

// netmemSingleton wraps the lazily-created netmem.Store so tests +
// production share the seam. Reset on Shutdown.
type netmemSingleton struct {
	mu            sync.Mutex
	store         *netmem.Store
	activeNetwork string
}

var globalNetmem = &netmemSingleton{activeNetwork: netmem.SentinelUnset}

// netmemStore returns the netmem.Store, lazy-creating it on first
// use bound to the global core's routestore. Returns nil if
// the Core is not initialised yet.
func netmemStore() *netmem.Store {
	globalNetmem.mu.Lock()
	defer globalNetmem.mu.Unlock()
	if globalNetmem.store != nil {
		return globalNetmem.store
	}
	c := loadedCore()
	if c == nil || c.store == nil {
		return nil
	}
	globalNetmem.store = netmem.New(c.store)
	return globalNetmem.store
}

// activeNetworkID returns the engine's currently bound network ID.
func activeNetworkID() string {
	globalNetmem.mu.Lock()
	defer globalNetmem.mu.Unlock()
	return globalNetmem.activeNetwork
}

// resetNetmemForShutdown is called from Shutdown to drop the
// singleton + revert the active-network sentinel.
func resetNetmemForShutdown() {
	globalNetmem.mu.Lock()
	defer globalNetmem.mu.Unlock()
	globalNetmem.store = nil
	globalNetmem.activeNetwork = netmem.SentinelUnset
}

// seedNetmemForInit is called from Init AFTER the core has been
// constructed. It primes the budget engine and pathmanager with
// the sentinel network ID so all 2C-aware code paths agree on the
// "no real network yet" identity until the first NetworkChanged.
func seedNetmemForInit() {
	c := loadedCore()
	if c == nil {
		return
	}
	if c.pm != nil {
		c.pm.SetActiveNetwork(netmem.SentinelUnset)
	}
	if eng := budgetEngineIfPresent(); eng != nil {
		eng.SetActiveNetwork(netmem.SentinelUnset)
	}
}

// NetworkChanged is engine_network_changed. Phase 2C.
//
// Accepts the platform's view of the current network: kind ("wifi",
// "cell", "eth", "unknown"), an opaque carrier string (cell carrier
// name on mobile, empty otherwise), and an opaque ssid string (Wi-Fi
// SSID on Wi-Fi, empty otherwise). All three are hashed at the
// entry of this function; the raw values are NOT stored, NOT logged,
// and NOT surfaced through any other ABI function.
//
// The function:
//
//  1. Captures the current network's per-route hourly budget
//     usage and per-route health into a netmem.Snapshot, persisted
//     under the OUTGOING network ID. (No-op if outgoing == incoming.)
//  2. Reads the snapshot for the INCOMING network ID, if present.
//  3. Restores mode + per-route budget counters + posture state.
//  4. Updates the budget engine + pathmanager active-network labels.
//  5. Returns a JSON status: { network_id, mode, restored_routes,
//     fresh }.
//
// `fresh: true` ⇔ first time the engine has seen this hashed ID.
// MUST NOT bump the budget session epoch.
func NetworkChanged(kind, carrier, ssid string) (string, error) {
	c := mustCore()
	k := netmem.Kind(kind)
	if !netmem.IsValidKind(k) {
		return "", fmt.Errorf("abi: invalid network kind %q", kind)
	}
	incoming := netmem.HashID(k, carrier, ssid)
	// Discard the raw inputs as soon as the hash is computed. The
	// privacy bar (V0.1) is "raw SSID NEVER leaves this function";
	// the only identifier carried forward is the hash.
	carrier, ssid = "", ""
	_ = carrier
	_ = ssid

	store := netmemStore()
	if store == nil {
		return "", fmt.Errorf("abi: netmem store unavailable (engine not initialised)")
	}

	now := nowUTC()

	// 1. Persist the OUTGOING network's snapshot (best-effort).
	outgoing := activeNetworkID()
	if outgoing != "" && outgoing != incoming && outgoing != netmem.SentinelUnset {
		captureAndPersist(store, outgoing, c, now)
	}

	// 2. Read the INCOMING network's snapshot.
	snap, err := store.Get(incoming)
	fresh := false
	if err != nil {
		fresh = true
		snap = netmem.Snapshot{}
	}

	// 3. Restore. Mode goes through SetMode so the posture axis
	// follows. Budget counters seed via budget.Engine.RestoreNetwork.
	// RouteHealth restore is intentionally additive (see note below).
	restored := 0
	if snap.Mode != "" {
		// SetMode validates and rejects 2D's "lifeline-strict" at
		// 2C — if a previously-saved snapshot carries the 2D mode
		// and we're running on a 2C build, swallow the rejection
		// silently and fall through to whatever mode the core
		// currently has.
		_ = SetMode(snap.Mode)
	}
	if eng := budgetEngineIfPresent(); eng != nil {
		restored = eng.RestoreNetwork(snap.BudgetUsage, snap.BudgetBucket)
	}

	// 4. Switch active-network labels on every 2C-aware subsystem.
	globalNetmem.mu.Lock()
	globalNetmem.activeNetwork = incoming
	globalNetmem.mu.Unlock()
	c.pm.SetActiveNetwork(incoming)
	if eng := budgetEngineIfPresent(); eng != nil {
		eng.SetActiveNetwork(incoming)
	}

	// 5. If this is a brand-new network, persist a stub snapshot
	// so subsequent All() / diagnostics calls see it.
	if fresh {
		stub := netmem.Snapshot{
			Mode:     c.mode,
			LastSeen: now,
		}
		_ = store.Put(incoming, stub, now)
	}

	body, _ := json.Marshal(map[string]any{
		"network_id":      incoming,
		"mode":            c.mode,
		"restored_routes": restored,
		"fresh":           fresh,
	})
	return string(body), nil
}

// captureAndPersist snapshots the current engine state for the
// OUTGOING network and writes it to the netmem store. Called from
// NetworkChanged before the swap; idempotent on failure (a write
// error is swallowed — the user's correctness bar is "incoming
// state takes effect", not "outgoing state perfectly preserved").
func captureAndPersist(store *netmem.Store, outID string, c *Core, now time.Time) {
	snap := netmem.Snapshot{
		Mode: c.mode,
	}
	if eng := budgetEngineIfPresent(); eng != nil {
		usage, bucket := eng.CaptureNetwork()
		snap.BudgetUsage = usage
		snap.BudgetBucket = bucket
	}
	// Carry the posture-axis route health forward so a return roam
	// restores the same per-route picture the user saw last time.
	if c.pm != nil {
		rh := c.pm.RouteHealth()
		if len(rh) > 0 {
			snap.RouteHealth = make(map[string]netmem.RouteHealthSlim, len(rh))
			for _, h := range rh {
				snap.RouteHealth[h.RouteID] = netmem.RouteHealthSlim{
					Posture:         string(c.pm.Posture()),
					CooldownReason:  string(h.CooldownReason),
					CooldownUntil:   h.CooldownUntil,
					BudgetExhausted: h.BudgetExhausted,
				}
			}
		}
	}
	_ = store.Put(outID, snap, now)
}

// ForgetNetwork is engine_forget_network. NOT exported as a release
// ABI symbol at 2C — exposed via the desktop "Forget this network"
// affordance through a Tauri command that calls into this Go func
// over the soak/cshared bridge in 2C-Rig (or via a future ABI add
// at 2D). For 2C the function is package-internal.
func ForgetNetwork(networkID string) error {
	store := netmemStore()
	if store == nil {
		return fmt.Errorf("abi: netmem store unavailable")
	}
	return store.Forget(networkID)
}

// allNetworks returns the hashed network IDs the engine has seen.
// For diagnostics + tests.
func allNetworks() ([]string, error) {
	store := netmemStore()
	if store == nil {
		return nil, nil
	}
	return store.All()
}

// Compile-time guards: NetworkChanged depends on these external
// types existing with the expected signatures.
var (
	_ = (&pathmanager.Manager{}).SetActiveNetwork
	_ = (&budget.Engine{}).SetActiveNetwork
)
