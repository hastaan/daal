package pathmanager

// Phase 3A. Experimental-families filter step.
//
// The 3A spec inserts a new filter step in the rank pipeline
// BEFORE trust / budget / network-memory:
//
//   shortlist = routes_for_active_network()
//   shortlist = experimental_filter(shortlist)        // NEW (3A)
//   shortlist = trust_filter(shortlist)
//   shortlist = budget_filter(shortlist)
//   shortlist = network_memory_filter(shortlist)
//   shortlist = mode_filter(shortlist)
//   return rank(shortlist)
//
// The filter is pure: it does not mutate input, does not read
// external state, and returns the kept routes plus the count of
// dropped routes. The caller (the engine layer in `core/abi`)
// surfaces the count as `experimental_routes_skipped` in
// diagnostics; the count is also a signal to the 2G burn-
// pressure detector that auto-promotion MUST NOT consider an
// experimental-only network as a "burned" network (the detector
// consults `SkippedFamilies()` which is exclusively failure-
// driven cooldowns; experimental skips do not enter that
// ledger).
//
// `IsExperimentalFn` is supplied by the caller so this package
// stays free of `core/routestore` imports. The canonical
// implementation is `routestore.IsExperimentalFamily`.

// IsExperimentalFn returns true for families at Experimental
// maturity per specs/transport-families-v1.md. Supplied by the
// caller; the canonical implementation is
// `core/routestore.IsExperimentalFamily`.
type IsExperimentalFn func(family string) bool

// ExperimentalFilter drops every route whose family is at
// Experimental maturity when `gateOpen` is false. Returns the
// kept slice (possibly equal to the input) and the count of
// dropped routes. With `gateOpen == true`, the input is returned
// unchanged and `dropped == 0`.
//
// Pure: no state mutation, no allocations on the gate-open path.
func ExperimentalFilter(rs []Route, gateOpen bool, isExperimental IsExperimentalFn) ([]Route, int) {
	if gateOpen {
		return rs, 0
	}
	if isExperimental == nil {
		// Caller did not supply a predicate; conservative default
		// is to keep everything (no filtering happens). This
		// branch is exercised only by unit tests; production
		// callers always pass routestore.IsExperimentalFamily.
		return rs, 0
	}
	out := make([]Route, 0, len(rs))
	dropped := 0
	for _, r := range rs {
		if isExperimental(r.Family) {
			dropped++
			continue
		}
		out = append(out, r)
	}
	return out, dropped
}

// RankWithExperimentalGate is the 3A entry point that composes
// the experimental filter with the existing 2D mode-aware ranker.
// Returns the ranked slice and the count of routes dropped by the
// experimental filter (the caller surfaces this in diagnostics).
//
// Behaviour:
//
//   - With `gateOpen == true`: byte-identical to RankWithView
//     (which falls back to Rank when view is nil).
//   - With `gateOpen == false`: experimental-maturity routes are
//     dropped BEFORE the mode-aware ranker sees them; the
//     ranker's existing behaviour for stable-maturity routes is
//     unchanged.
func RankWithExperimentalGate(rs []Route, mode string, view NetworkView, gateOpen bool, isExperimental IsExperimentalFn) ([]Route, int) {
	filtered, dropped := ExperimentalFilter(rs, gateOpen, isExperimental)
	return RankWithView(filtered, mode, view), dropped
}
