package budget

// modeFactor is the V2.2 mode multiplier table. Lifeline tightens
// both axes to ~1/3 of the published cap (roadmap V2.5 says "~3×
// tighter"; we use 0.33 as the canonical multiplier). Normal and
// Bulk pass through unchanged. Bulk does NOT enlarge caps; it
// unlocks bulk-capable routes via the `modes_allowed` filter that
// pathmanager.Rank consumes.
//
// `lifeline-strict` (Phase 2D) shares the multiplier with `lifeline`;
// it differs only in pathmanager-side behaviour (stability-biased
// ranker, bulk-capable refused for general traffic, refresh gate,
// permanent banner). The budget engine itself stays mode-policy-free
// — it only counts bytes.
var modeFactor = map[string]float64{
	"lifeline":        0.33,
	"normal":          1.0,
	"bulk":            1.0,
	"lifeline-strict": 0.33,
}

// ModeFactor returns the multiplier for mode. Unknown modes default
// to 1.0 (defensive — invalid modes are rejected at the
// engine_set_mode boundary, but a stale Snapshot read could still
// surface one).
func ModeFactor(mode string) float64 {
	if f, ok := modeFactor[mode]; ok {
		return f
	}
	return 1.0
}

// applyFactor multiplies a cap by f. 0 (unlimited) stays 0; finite
// caps are scaled and rounded toward zero.
func applyFactor(c uint64, f float64) uint64 {
	if c == 0 {
		return 0
	}
	return uint64(float64(c) * f)
}

// EffectiveCap returns the per-route cap after applying the active
// mode's multiplier. The route's tag is read from the bound store.
// If the route is unknown or untagged, returns a zero-value Cap
// (treated as unlimited by Add).
//
// EffectiveCap is the read-side view; Add itself inlines the same
// computation under e.mu to avoid mutex re-entry.
func (e *Engine) EffectiveCap(routeID, mode string) Cap {
	e.mu.Lock()
	tag, _, _, err := e.store.GetRouteBudget(routeID)
	e.mu.Unlock()
	if err != nil {
		return Cap{}
	}
	full, capErr := FullCapFor(tag)
	if capErr != nil {
		return Cap{}
	}
	f := ModeFactor(mode)
	eff := full
	eff.Hourly = applyFactor(full.Hourly, f)
	eff.Session = applyFactor(full.Session, f)
	// ModesAllowed is mode-independent metadata; pass through the
	// defensive copy from FullCapFor.
	return eff
}
