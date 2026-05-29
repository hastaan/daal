//go:build !no_wasm

package abi

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"

	"daal/core/wasm"
)

// initForWasmTest spins up an engine session against a fresh
// state-dir. Mirrors the helper pattern in masque_test.go etc.
func initForWasmTest(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	if err := Init(dir, "info"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Shutdown() })
}

// TestEngineVersion_3FBump — assert the engine reports the
// current version (3F bumps it from 3E's 0.8.0+v3-wasm to
// 0.9.0+v3-share). Locked invariant: this string is what the
// distribution layer keys off when assembling release
// notes / changelogs.
func TestEngineVersion_3FBump(t *testing.T) {
	if got, want := VersionString(), "daal-core 0.9.0+v3-share"; got != want {
		t.Errorf("VersionString = %q; want %q", got, want)
	}
}

// TestExportDiagnostics_3EFieldsAlwaysPresent — the four new
// 3E fields are always present in the diagnostics JSON, with
// shape-stable defaults: `wasm_compiled_in` true (default
// build), `loaded_wasm_modules` empty array, count 0,
// outcome empty.
func TestExportDiagnostics_3EFieldsAlwaysPresent(t *testing.T) {
	initForWasmTest(t)
	body, err := ExportDiagnostics()
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(body), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{
		"wasm_compiled_in",
		"loaded_wasm_modules",
		"wasm_kill_switched_count",
		"last_wasm_module_dial_outcome",
	} {
		if _, ok := raw[key]; !ok {
			t.Errorf("missing diagnostics field: %s", key)
		}
	}
	if got, ok := raw["wasm_compiled_in"].(bool); !ok || !got {
		t.Errorf("wasm_compiled_in: got %v; want true", raw["wasm_compiled_in"])
	}
	if mods, ok := raw["loaded_wasm_modules"].([]any); !ok || len(mods) != 0 {
		t.Errorf("loaded_wasm_modules default: got %v; want []", raw["loaded_wasm_modules"])
	}
	if got, ok := raw["wasm_kill_switched_count"].(float64); !ok || got != 0 {
		t.Errorf("wasm_kill_switched_count default: got %v; want 0", raw["wasm_kill_switched_count"])
	}
	if got := raw["last_wasm_module_dial_outcome"]; got != "" {
		t.Errorf("last_wasm_module_dial_outcome default: got %v; want empty", got)
	}
}

// TestRecordLoadedWasmModule_RoundTrip — recording a load
// surfaces the slug + sha256 prefix in the diagnostic field.
func TestRecordLoadedWasmModule_RoundTrip(t *testing.T) {
	initForWasmTest(t)
	const sha = "deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe"
	if err := RecordLoadedWasmModule("hello-https", sha, "2026-04-28T18:00:00Z"); err != nil {
		t.Fatal(err)
	}
	body, _ := ExportDiagnostics()
	var raw map[string]any
	_ = json.Unmarshal([]byte(body), &raw)
	mods := raw["loaded_wasm_modules"].([]any)
	if len(mods) != 1 {
		t.Fatalf("expected 1 module; got %d", len(mods))
	}
	m := mods[0].(map[string]any)
	if m["slug"] != "hello-https" {
		t.Errorf("slug: got %v", m["slug"])
	}
	if m["sha256_prefix"] != sha[:8] {
		t.Errorf("sha256_prefix: got %v want %s", m["sha256_prefix"], sha[:8])
	}

	// Calling Clear wipes the snapshot.
	ClearLoadedWasmModules()
	body, _ = ExportDiagnostics()
	_ = json.Unmarshal([]byte(body), &raw)
	if mods := raw["loaded_wasm_modules"].([]any); len(mods) != 0 {
		t.Errorf("after clear: got %v; want []", mods)
	}
}

// TestRecordWasmDialOutcome_ClosedEnum — only the v1 outcome
// strings are accepted; the surface stays enumerable.
func TestRecordWasmDialOutcome_ClosedEnum(t *testing.T) {
	initForWasmTest(t)
	for _, out := range []wasm.DialOutcome{
		wasm.OutcomeOK, wasm.OutcomeFuelExhausted,
		wasm.OutcomeMemoryCap, wasm.OutcomeDialTimeout,
		wasm.OutcomeHostCallbackError,
	} {
		if err := RecordWasmDialOutcome(string(out)); err != nil {
			t.Errorf("RecordWasmDialOutcome(%s): %v", out, err)
		}
	}
	if err := RecordWasmDialOutcome("certified_organic"); err == nil {
		t.Error("unknown outcome should be rejected")
	}
	if got := LastWasmDialOutcome(); got != "host_callback_error" {
		t.Errorf("LastWasmDialOutcome: got %q; want host_callback_error", got)
	}
}

// TestSetWASMKillSwitchVerifier_PubkeyHexSurfaces — wiring a
// verifier with a pubkey makes the public hex surface
// available, both via the Go-side getter and the diagnostics
// JSON (the JSON does NOT carry the pubkey at 3E — it lives
// behind a dedicated release symbol — but the Go-side getter
// should round-trip).
func TestSetWASMKillSwitchVerifier_PubkeyHexSurfaces(t *testing.T) {
	initForWasmTest(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	v := wasm.NewKillSwitchVerifier(pub, wasm.NewLoader(), nil)
	if err := SetWASMKillSwitchVerifier(v); err != nil {
		t.Fatal(err)
	}
	got := WASMKillSwitchPubkeyHex()
	if len(got) != 64 || strings.ContainsAny(got, "GHIJKLMNOPQRSTUVWXYZ") {
		t.Errorf("WASMKillSwitchPubkeyHex: got %q (want 64 lowercase hex)", got)
	}
}

// TestWASMLoadedModulesJSON_AlwaysValidJSON — even on a fresh
// engine with no modules loaded, the function returns valid
// JSON `[]` (callers can pre-allocate).
func TestWASMLoadedModulesJSON_AlwaysValidJSON(t *testing.T) {
	initForWasmTest(t)
	body := WASMLoadedModulesJSON()
	var arr []any
	if err := json.Unmarshal([]byte(body), &arr); err != nil {
		t.Fatalf("not valid JSON: %v (%q)", err, body)
	}
	if len(arr) != 0 {
		t.Errorf("default: got %v; want []", arr)
	}
}
