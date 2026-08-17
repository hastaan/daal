//go:build gomobile

package abi

import "time"

// Phase 2F gomobile facade for the in-engine scheduler.

func (h *DaalCore) SchedulerStatus() (string, error) { return SchedulerStatus() }

// SchedulerTick mirrors the cshared `engine_scheduler_tick` symbol
// (scheduler_export.go) for gomobile hosts: one scheduler.Tick at the
// host's wall clock, which is what makes the per-row ProfileUpdateMin
// cadence, the revocation/bootstrap cadence and the Phase 2G
// burn-pressure auto-promotion actually fire. Until this existed the
// gomobile surface was read-only (SchedulerStatus), so a mobile host
// could *observe* that a refresh was overdue and had no way to make
// one happen.
//
// It returns an int (0 ok / -1 not-ready-or-failed) rather than an
// error, following the LifecycleEvent precedent in
// lifecycle_gomobile.go: the caller is a timer pump, and a host that
// has to catch an exception every 60 s while the engine happens to be
// uninitialized will end up wrapping the call in a swallow-everything
// try/catch, which is strictly worse than a return code. Non-fatal by
// construction — a dropped tick costs at most one cadence period.
func (h *DaalCore) SchedulerTick() int {
	if err := SchedulerTick(time.Now().UTC()); err != nil {
		return -1
	}
	return 0
}
