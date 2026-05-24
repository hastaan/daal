//go:build cshared

package abi

import "C"

import "unsafe"

// engine_wasm_kill_switch_pubkey is the Phase 3E release ABI
// symbol 46 (release surface 45 → 46). Returns the hex-encoded
// project-controlled WASM kill-switch pubkey, or an empty
// string if unconfigured / `-tags no_wasm` build.
//
// The caller is responsible for the buffer (same convention as
// engine_export_diagnostics): pass a buffer + size, the engine
// writes the NUL-terminated string into it. Returns the number
// of bytes written, or -1 on internal error.
//
// See specs/wasm-kill-switch-v1.md.

//export engine_wasm_kill_switch_pubkey
func engine_wasm_kill_switch_pubkey(out unsafe.Pointer, outLen C.int) C.int {
	body := WASMKillSwitchPubkeyHex()
	return copyOut(body, out, outLen)
}

// engine_loaded_wasm_modules is the Phase 3E release ABI
// symbol 47 (release surface 46 → 47). Returns a JSON array
// snapshot of currently-loaded modules:
//
//	[{"slug":"hello-https","sha256_prefix":"a1b2c3d4","loaded_at":"…"}, …]
//
// Empty array `[]` under `-tags no_wasm` or when no modules
// are loaded.
//
// See specs/wasm-transport-v1.md "Diagnostics".

//export engine_loaded_wasm_modules
func engine_loaded_wasm_modules(out unsafe.Pointer, outLen C.int) C.int {
	body := WASMLoadedModulesJSON()
	return copyOut(body, out, outLen)
}
