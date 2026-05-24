package abi

import (
	"sync/atomic"
	"time"
)

// clockOverride, when non-zero, is the unix-seconds wall-clock the
// engine pretends is "now". It is settable ONLY through the
// build-tag-gated `engine_set_now_unix` ABI export, which lives in
// `clock_soak.go` and is compiled in only when `-tags soak` is set.
//
// Release builds never expose a way to change this value. The atomic
// is read by every time-using path in this package (and through the
// `Now func() time.Time` hooks the rest of core takes from this
// package), so a single set propagates across `core/refresh`,
// `core/bootstrap` orchestration here, share, and the importer.
//
// Default zero means "use real wall clock".
var clockOverride atomic.Int64

// nowUTC returns the current simulated UTC time. It is the single
// source of truth for time inside the abi package.
func nowUTC() time.Time {
	if v := clockOverride.Load(); v != 0 {
		return time.Unix(v, 0).UTC()
	}
	return time.Now().UTC()
}

// resetClockForShutdown clears any soak override on engine_shutdown so
// a subsequent engine_init in the same process starts fresh. Called
// from Shutdown unconditionally; harmless on release builds where the
// override is always zero anyway.
func resetClockForShutdown() {
	clockOverride.Store(0)
}
