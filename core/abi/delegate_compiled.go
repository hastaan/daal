//go:build !no_delegate_share

// Phase 3F. The delegateShareCompiledIn flag reflects whether
// the running binary carries the `core/delegate` re-share
// surface. Builds that pass `-tags no_delegate_share` flip
// this flag to false (see delegate_compiled_excluded.go);
// distributors who must strip the share surface use that tag.
//
// Surfaced in diagnostics as `delegate_share_compiled_in`.
// Locked at 3F per specs/delegate-keys-v1.md "Compile-in flag".

package abi

const delegateShareCompiledIn = true
