//go:build no_wasm

package abi

import (
	"encoding/json"
	"testing"
)

// Phase 3E. Excluder-build smoke tests.
//
// Under `-tags no_wasm` the wazero vendor tree is absent and
// the engine MUST refuse to load WASM modules (rather than
// papering over the absence). The diagnostics surface stays
// shape-stable: `wasm_compiled_in` flips false, the other
// three fields render their zero defaults.

func TestExcluder_DiagnosticsShapeStable(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "info"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Shutdown() })
	body, err := ExportDiagnostics()
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(body), &raw); err != nil {
		t.Fatal(err)
	}
	if got, ok := raw["wasm_compiled_in"].(bool); !ok || got {
		t.Errorf("wasm_compiled_in: got %v; want false", raw["wasm_compiled_in"])
	}
	if mods, ok := raw["loaded_wasm_modules"].([]any); !ok || len(mods) != 0 {
		t.Errorf("loaded_wasm_modules: got %v; want []", raw["loaded_wasm_modules"])
	}
	if got, ok := raw["wasm_kill_switched_count"].(float64); !ok || got != 0 {
		t.Errorf("wasm_kill_switched_count: got %v; want 0", raw["wasm_kill_switched_count"])
	}
	if got := raw["last_wasm_module_dial_outcome"]; got != "" {
		t.Errorf("last_wasm_module_dial_outcome: got %v; want empty", got)
	}
}

func TestExcluder_PubkeyHexEmpty(t *testing.T) {
	if got := WASMKillSwitchPubkeyHex(); got != "" {
		t.Errorf("WASMKillSwitchPubkeyHex under no_wasm: got %q; want empty", got)
	}
}

func TestExcluder_LoadedModulesIsEmptyArray(t *testing.T) {
	body := WASMLoadedModulesJSON()
	if body != "[]" {
		t.Errorf("WASMLoadedModulesJSON under no_wasm: got %q; want []", body)
	}
}
