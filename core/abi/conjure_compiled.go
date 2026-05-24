// Phase 3D. The conjureCompiledIn flag reflects whether the
// running binary includes the vendored gotapdance tree.
// Conjure has no equivalent of `-tags no_psiphon` — its
// vendored tree is Apache-2.0 and ships unconditionally — so
// the flag is a constant true. We still expose it in
// diagnostics for symmetry with `psiphon_compiled_in` (and so
// that future build-tag conditioning could flip it without
// reshaping the diagnostics JSON).
//
// Locked at 3D per specs/conjure-route-v1.md "Compile-in flag".

package abi

const conjureCompiledIn = true
