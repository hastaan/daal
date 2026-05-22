//go:build no_wasm

// Phase 3E. `-tags no_wasm` builds exclude the wazero vendor
// tree. The flag is surfaced in diagnostics; the engine refuses
// to load WASM modules when the flag is false rather than
// papering over the missing vendor tree.

package abi

const wasmCompiledIn = false
