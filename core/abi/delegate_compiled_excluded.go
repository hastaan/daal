//go:build no_delegate_share

// Phase 3F. `-tags no_delegate_share` builds exclude the
// re-share surface entirely. The flag is surfaced in
// diagnostics; the engine returns the
// `identity_unavailable` outcome for engine_redistribute_route
// rather than papering over the missing surface.

package abi

const delegateShareCompiledIn = false
