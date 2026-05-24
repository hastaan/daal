//go:build !no_wasm

// Phase 3E. The wasmCompiledIn flag reflects whether the
// running binary includes the wazero vendor tree. Builds that
// pass `-tags no_wasm` flip this flag to false (see
// wasm_compiled_excluded.go); distributors who cannot ship the
// wazero vendor tree use that tag.
//
// The flag is surfaced in diagnostics as `wasm_compiled_in`.
// Locked at 3E per specs/wasm-transport-v1.md "Compile-in flag".

package abi

const wasmCompiledIn = true
