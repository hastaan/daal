//go:build gomobile

package abi

// Phase 3E. Gomobile-side wrappers for the two new release
// ABI symbols. The Java/Swift sides see them as instance
// methods on `DaalCore`.

// WasmKillSwitchPubkeyHex returns the hex-encoded project-
// controlled WASM kill-switch pubkey, or "" when unconfigured /
// the binary was built with `-tags no_wasm`.
func (h *DaalCore) WasmKillSwitchPubkeyHex() string {
	return WASMKillSwitchPubkeyHex()
}

// LoadedWasmModulesJSON returns a JSON array of currently-
// loaded WASM modules. Always valid JSON (empty array `[]`
// when none).
func (h *DaalCore) LoadedWasmModulesJSON() string {
	return WASMLoadedModulesJSON()
}
