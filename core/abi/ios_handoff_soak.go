//go:build soak

package abi

import (
	"sync/atomic"
	"time"
)

// Phase 2E: soak-only knobs that drive the
// `ios-wireguard-handoff` scenario. They model what the iOS Swift
// bridge does (sample TASK_VM_INFO.phys_footprint, cross a 38 MiB
// watermark, perform a one-way handoff to boringtun) without
// requiring an actual iOS device.
//
// Release builds DO NOT compile this file. Both knobs surface
// only as `-tags soak` ABI exports; the diagnostics fields they
// drive (`wg_subengine_memory_kib`, `wg_subengine_handoff_at`)
// are also gated on `-tags soak` via build-tag-isolated
// readers — see ios_handoff_diag.go.

// wgMemoryKiB is a fake RSS gauge the rig writes through
// `engine_soak_set_wg_memory_kib`.
var wgMemoryKiB atomic.Int64

// wgHandoffAtUnix is the unix-second timestamp of a forced
// handoff. Zero means "no handoff has happened in this engine
// session".
var wgHandoffAtUnix atomic.Int64

// SetWGMemoryKiB sets the simulated WG-subengine RSS in KiB.
// Used by the rig to model crossing the 38 MiB watermark.
func SetWGMemoryKiB(kib int64) {
	wgMemoryKiB.Store(kib)
}

// ForceWGHandoff stamps the handoff timestamp to "now" (real or
// simulated wall-clock per nowUTC). One-way: a second call simply
// overwrites the timestamp; the rig asserts the field appears at
// all, not that it appears exactly once.
func ForceWGHandoff() {
	wgHandoffAtUnix.Store(nowUTC().Unix())
}

// readWGHandoffSoak is consulted by the diagnostics renderer when
// `-tags soak` is active. Returns (kib, handoffAt) where
// handoffAt is zero if no handoff has been forced.
//
// Linked into the diagnostics build via ios_handoff_diag.go.
func readWGHandoffSoak() (int64, time.Time) {
	kib := wgMemoryKiB.Load()
	at := wgHandoffAtUnix.Load()
	if at == 0 {
		return kib, time.Time{}
	}
	return kib, time.Unix(at, 0).UTC()
}
