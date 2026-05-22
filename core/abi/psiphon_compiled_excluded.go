//go:build no_psiphon

// Phase 3D. `-tags no_psiphon` builds exclude the vendored
// psiphon-tunnel-core tree (GPLv3 isolation discipline). The
// flag is surfaced in diagnostics; the engine refuses to
// activate psiphon routes when the flag is false rather than
// papering over the missing vendor tree.

package abi

const psiphonCompiledIn = false
