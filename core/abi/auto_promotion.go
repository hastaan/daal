package abi

import (
	"time"

	"daal/core/burnpressure"
	"daal/core/pathmanager"
)

// SetAutoPromotion is the Go-layer setter for the 2G auto-promotion
// flag. The flag survives session epochs; it is a user preference,
// not session state. Returns nil; the cshared/gomobile facades
// translate to int return.
func SetAutoPromotion(enabled bool) {
	c := mustCore()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.autoPromotionEnabled = enabled
}

// AutoPromotionEnabled reports the current flag.
func AutoPromotionEnabled() bool {
	c := mustCore()
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.autoPromotionEnabled
}

// EvaluateAutoPromotion is consulted by the scheduler on every
// Tick. It runs the burn-pressure detector against the current
// pathmanager skipped-family snapshot and, if the verdict says
// "promote" AND auto-promotion is enabled AND the user has not
// manually overridden in the same hour-bucket AND the detector has
// not already fired in the same hour-bucket, flips the engine into
// `lifeline-strict` via the auto-path (which does NOT stamp the
// manual-override hour).
//
// Returns the verdict for diagnostic purposes; the scheduler does
// not act on the return value (the flip, if any, has already
// happened).
func EvaluateAutoPromotion(now time.Time) burnpressure.Verdict {
	c := mustCore()
	c.mu.Lock()
	enabled := c.autoPromotionEnabled
	mode := c.mode
	manualHour := c.manualOverrideHour
	lastFired := c.autoPromotionLastFiredHour
	c.mu.Unlock()

	if !enabled {
		return burnpressure.Verdict{}
	}
	if mode == "lifeline-strict" {
		// Already there; nothing to promote.
		return burnpressure.Verdict{}
	}
	hour := now.Truncate(time.Hour)
	if !manualHour.IsZero() && manualHour.Equal(hour) {
		// User manually changed mode in this hour; back off.
		return burnpressure.Verdict{}
	}
	if !lastFired.IsZero() && lastFired.Equal(hour) {
		// Already fired this hour; debounce.
		return burnpressure.Verdict{}
	}

	skipped := c.pm.SkippedFamilies()
	proj := make([]burnpressure.Skipped, 0, len(skipped))
	for _, s := range skipped {
		proj = append(proj, burnpressure.Skipped{
			Family:     s.Family,
			Until:      s.Until,
			LadderStep: s.LadderStep,
		})
	}
	verdict := burnpressure.Evaluate(now, proj)
	if !verdict.ShouldPromote {
		return verdict
	}
	// Fire: flip via the auto path and stamp the lastFired hour.
	c.mu.Lock()
	c.autoPromotionLastFiredHour = hour
	c.mu.Unlock()
	_ = setModeAuto("lifeline-strict")
	return verdict
}

// AutoPromotionLastFiredAt is the diagnostic projection of the
// last hour-bucket at which auto-promotion fired in this engine
// session. Zero time means "never fired this session".
func AutoPromotionLastFiredAt() time.Time {
	c := mustCore()
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.autoPromotionLastFiredHour
}

// pathmanagerSkipped is a tiny adapter to keep the burnpressure
// package decoupled from `core/pathmanager`. The compile-time
// reference here forces the `pathmanager` import below to be used
// even if the helper signature changes — keeping the dep graph
// honest.
var _ = pathmanager.SkippedFamily{}
