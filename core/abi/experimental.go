package abi

// Phase 3A. Experimental-families gate.
//
// The flag is a per-engine boolean, default-OFF, that admits
// routes whose `transport_family` is at Experimental maturity
// (per `specs/transport-families-v1.md`). Persisted in the
// secrets KV under key `experimental_families_enabled`. Survives
// session epochs (it is a user preference, not session state).
// Cleared only by an explicit user toggle through
// `engine_set_experimental_families_enabled`.
//
// Locked invariants:
//   - Mode change does NOT clear it.
//   - Network change does NOT clear it.
//   - Unlock does NOT clear it.
//   - No cooldown clears it.
//   - No auto-promotion clears it.
//   - The gate is per-engine, NOT per-network. Per-network
//     experimental decisions are deliberately NOT a feature; the
//     resulting cross-product would be a privacy fingerprint
//     surface for the censor.

const experimentalFamiliesEnabledKey = "experimental_families_enabled"

// SetExperimentalFamiliesEnabled is the Go-layer setter. The
// cshared / gomobile facades translate to int return values; this
// function is what the rest of the engine, tests, and the
// platform UIs (when wired through gomobile) consume.
func SetExperimentalFamiliesEnabled(enabled bool) {
	c := mustCore()
	c.mu.Lock()
	c.experimentalFamiliesEnabled = enabled
	c.mu.Unlock()
	// Persist asynchronously to avoid holding the mu while doing
	// secrets-KV crypto. A failure to persist is logged-only by
	// the routestore; the in-memory flag stays authoritative for
	// the current process.
	val := []byte("0")
	if enabled {
		val = []byte("1")
	}
	if c.store != nil {
		_ = c.store.PutSecret(experimentalFamiliesEnabledKey, val)
	}
}

// ExperimentalFamiliesEnabled reports the current flag value.
// Pure read; consults only the in-memory state.
func ExperimentalFamiliesEnabled() bool {
	c := mustCore()
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.experimentalFamiliesEnabled
}

// loadExperimentalFamiliesEnabled is the Init-time daaltor. The
// flag is read from the secrets KV; missing keys default to
// `false` (the V0 user-conservative default per
// specs/transport-families-v1.md "Experimental gate"). Errors
// fall through to the default; the engine never refuses to start
// over a missing-or-corrupt experimental-gate value.
func loadExperimentalFamiliesEnabled(c *Core) {
	if c == nil || c.store == nil {
		return
	}
	body, err := c.store.GetSecret(experimentalFamiliesEnabledKey)
	if err != nil || len(body) == 0 {
		c.mu.Lock()
		c.experimentalFamiliesEnabled = false
		c.mu.Unlock()
		return
	}
	c.mu.Lock()
	c.experimentalFamiliesEnabled = body[0] == '1'
	c.mu.Unlock()
}

// SetExperimentalRoutesSkipped is the pathmanager-side hook
// consumed at the start of every rank pass to surface the
// per-pass count in diagnostics. Snapshot, not cumulative.
func SetExperimentalRoutesSkipped(n int) {
	c := mustCore()
	c.mu.Lock()
	c.experimentalRoutesSkipped = n
	c.mu.Unlock()
}
