//go:build !no_psiphon

// Phase 3D. The psiphonCompiledIn flag reflects whether the
// running binary includes the vendored psiphon-tunnel-core
// tree. Builds that pass `-tags no_psiphon` flip this flag to
// false (see psiphon_compiled_excluded.go); release builds for
// the GPLv3-isolation-required distribution path use that tag.
//
// The flag is surfaced in diagnostics as `psiphon_compiled_in`.
// Locked at 3D per specs/psiphon-route-v1.md "Compile-in flag".

package abi

const psiphonCompiledIn = true
