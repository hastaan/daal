//go:build gomobile

package abi

// Phase 2F gomobile facade for the in-engine scheduler.

func (h *DaalCore) SchedulerStatus() (string, error) { return SchedulerStatus() }
