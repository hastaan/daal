package abi

// Phase 3E. WASM transport-slot ABI surface. Two new
// release-surface getters (release symbols 46 + 47) are wired
// in `wasm_export.go` (cshared) and `wasm_gomobile.go`. This
// file owns the engine-side state and the JSON serializers
// the export-shims call.
//
// Locked invariants (see specs/wasm-transport-v1.md):
//
//   - The WASM kill-switch pubkey is engine-immutable for the
//     session — it is set at Init from the host caller's
//     trusted material and never swapped at runtime.
//     `engine_wasm_kill_switch_pubkey` returns the hex
//     encoding (lowercase 64 chars) or an empty string when
//     unconfigured / `-tags no_wasm` builds.
//   - The loaded-modules snapshot is a shape-stable JSON
//     array; absent modules render as `[]`. The empty-array
//     guarantee matches the 3D `route_health[]` rule —
//     callers can pre-allocate.
//   - Outcome enum is closed (5 values, exported by
//     `core/wasm.AllOutcomes`); a new outcome at 3F+ is a
//     security-review-gated change.

import (
	"encoding/json"
	"errors"
	"sync"

	"daal/core/wasm"
)

// wasmState bundles the engine-internal WASM state. Lives on a
// package-level singleton so Init wires it once and the
// diagnostics renderer reads it without holding the Core
// mutex.
type wasmState struct {
	mu                          sync.Mutex
	loader                      *wasm.Loader
	verifier                    *wasm.KillSwitchVerifier
	loadedModules               []wasmLoadedModuleSnapshot
	lastDialOutcome             string
	wasmKillSwitchedCountCached int
}

// wasmLoadedModuleSnapshot is the per-module shape surfaced by
// `engine_loaded_wasm_modules` and the diagnostics field
// `loaded_wasm_modules`. Locked at 3E.
type wasmLoadedModuleSnapshot struct {
	Slug         string `json:"slug"`
	SHA256Prefix string `json:"sha256_prefix"`
	LoadedAt     string `json:"loaded_at"`
}

// globalWasm is initialised lazily; nil → "engine has not
// touched the WASM slot yet this session," which renders as
// `loaded_wasm_modules: []` and `wasm_kill_switched_count: 0`.
var globalWasm = &wasmState{}

// WASMKillSwitchPubkeyHex is the public Go-side surface for
// `engine_wasm_kill_switch_pubkey`. Lowercase hex, empty
// string under `-tags no_wasm` or when no key was injected.
//
// The release symbol resolves to this function (see
// `wasm_export.go`).
func WASMKillSwitchPubkeyHex() string {
	if !wasmCompiledIn {
		return ""
	}
	v := globalWasm.verifier
	if v == nil {
		return ""
	}
	return v.PubkeyHex()
}

// WASMLoadedModulesJSON returns a JSON array of
// `wasmLoadedModuleSnapshot` representing modules currently
// loaded by the engine. Empty array when none. Always valid
// JSON; never returns an error in production paths.
//
// The release symbol resolves to this function.
func WASMLoadedModulesJSON() string {
	if !wasmCompiledIn {
		return "[]"
	}
	globalWasm.mu.Lock()
	snap := append([]wasmLoadedModuleSnapshot(nil), globalWasm.loadedModules...)
	globalWasm.mu.Unlock()
	if snap == nil {
		snap = []wasmLoadedModuleSnapshot{}
	}
	body, err := json.Marshal(snap)
	if err != nil {
		return "[]"
	}
	return string(body)
}

// RecordLoadedWasmModule is invoked by the WASM family handler
// when a module loads successfully. The diagnostic surface
// updates immediately — callers do NOT need to wait for the
// next rank pass.
func RecordLoadedWasmModule(slug, sha256Hex, loadedAt string) error {
	if !wasmCompiledIn {
		return errors.New("abi: wasm vendor tree excluded")
	}
	if slug == "" || len(sha256Hex) < 8 {
		return errors.New("abi: invalid module slug or hash")
	}
	globalWasm.mu.Lock()
	defer globalWasm.mu.Unlock()
	// Replace any existing entry for the same slug (re-load
	// case) rather than duplicating.
	idx := -1
	for i, m := range globalWasm.loadedModules {
		if m.Slug == slug {
			idx = i
			break
		}
	}
	entry := wasmLoadedModuleSnapshot{
		Slug:         slug,
		SHA256Prefix: sha256Hex[:8],
		LoadedAt:     loadedAt,
	}
	if idx >= 0 {
		globalWasm.loadedModules[idx] = entry
	} else {
		globalWasm.loadedModules = append(globalWasm.loadedModules, entry)
	}
	return nil
}

// ClearLoadedWasmModules is invoked on engine_clear_route or
// at module-unload time. Wipes the in-memory snapshot so the
// diagnostics surface returns `[]`.
func ClearLoadedWasmModules() {
	if !wasmCompiledIn {
		return
	}
	globalWasm.mu.Lock()
	globalWasm.loadedModules = nil
	globalWasm.mu.Unlock()
}

// RecordWasmDialOutcome is invoked by the WASM family handler
// at the end of every Dial. The outcome string MUST be one of
// the closed v1 list (`wasm.IsKnownOutcome`); unknown values
// are rejected to keep the diagnostic surface enumerable.
func RecordWasmDialOutcome(outcome string) error {
	if !wasmCompiledIn {
		return errors.New("abi: wasm vendor tree excluded")
	}
	if !wasm.IsKnownOutcome(outcome) {
		return errors.New("abi: unknown wasm dial outcome (closed enum)")
	}
	globalWasm.mu.Lock()
	globalWasm.lastDialOutcome = outcome
	globalWasm.mu.Unlock()
	return nil
}

// wasmLoadedModulesForDiagnostics returns the loaded modules
// snapshot in a shape suitable for json.Marshal on the
// diagnostics map. Always non-nil (empty slice → JSON `[]`).
func wasmLoadedModulesForDiagnostics() []wasmLoadedModuleSnapshot {
	if !wasmCompiledIn {
		return []wasmLoadedModuleSnapshot{}
	}
	globalWasm.mu.Lock()
	defer globalWasm.mu.Unlock()
	if len(globalWasm.loadedModules) == 0 {
		return []wasmLoadedModuleSnapshot{}
	}
	return append([]wasmLoadedModuleSnapshot(nil), globalWasm.loadedModules...)
}

// LastWasmDialOutcome returns the most recent dial outcome
// surfaced through `last_wasm_module_dial_outcome` in
// diagnostics. Empty string until the first Dial completes.
func LastWasmDialOutcome() string {
	globalWasm.mu.Lock()
	defer globalWasm.mu.Unlock()
	return globalWasm.lastDialOutcome
}

// WasmKillSwitchedCount returns the count of distinct
// (sha256) entries the engine currently treats as killed.
// Reads through to the verifier's secrets-KV-backed counter
// when available; falls back to a cached zero on the no-wasm
// build.
func WasmKillSwitchedCount() int {
	if !wasmCompiledIn {
		return 0
	}
	v := globalWasm.verifier
	if v == nil {
		return 0
	}
	n, err := v.KillSwitchedCount()
	if err != nil {
		// Cache & fall back; never surface a sql error in
		// diagnostics.
		globalWasm.mu.Lock()
		defer globalWasm.mu.Unlock()
		return globalWasm.wasmKillSwitchedCountCached
	}
	globalWasm.mu.Lock()
	globalWasm.wasmKillSwitchedCountCached = n
	globalWasm.mu.Unlock()
	return n
}

// SetWASMKillSwitchVerifier wires a verifier into the engine.
// The host caller invokes this once during `engine_init` (or a
// dedicated platform-bridge entry point) with a verifier
// constructed from the embedded kill-switch pubkey + the
// shared loader + the routestore-backed secrets KV. Subsequent
// calls are rejected to preserve the immutable-key invariant.
func SetWASMKillSwitchVerifier(v *wasm.KillSwitchVerifier) error {
	if !wasmCompiledIn {
		return errors.New("abi: wasm vendor tree excluded")
	}
	globalWasm.mu.Lock()
	defer globalWasm.mu.Unlock()
	if globalWasm.verifier != nil {
		return errors.New("abi: kill-switch verifier already set")
	}
	globalWasm.verifier = v
	return nil
}

// SetWASMLoader wires a loader into the engine for the family
// handler to consult on module load. Safe to call once.
func SetWASMLoader(l *wasm.Loader) error {
	if !wasmCompiledIn {
		return errors.New("abi: wasm vendor tree excluded")
	}
	globalWasm.mu.Lock()
	defer globalWasm.mu.Unlock()
	if globalWasm.loader != nil {
		return errors.New("abi: loader already set")
	}
	globalWasm.loader = l
	return nil
}

// resetWasmStateForShutdown clears the package-level singleton
// so a subsequent Init starts clean. Mirrors
// `resetSchedulerForShutdown` etc.
func resetWasmStateForShutdown() {
	globalWasm.mu.Lock()
	defer globalWasm.mu.Unlock()
	globalWasm.loadedModules = nil
	globalWasm.lastDialOutcome = ""
	globalWasm.wasmKillSwitchedCountCached = 0
	globalWasm.loader = nil
	globalWasm.verifier = nil
}
