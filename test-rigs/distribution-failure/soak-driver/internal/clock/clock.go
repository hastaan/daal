// Package clock implements an accelerated wall-clock for the soak rig.
//
// The production engine carries `Now func() time.Time` injection points
// in `core/refresh`, `core/bootstrap`, and `core/pathmanager` (already
// landed in Phase 1.5A). The soak's `-tags soak` engine library
// additionally exposes `engine_set_now_unix(int64)` which sets a
// process-wide clock override consulted by every subsequent ABI call.
//
// This package is the rig-side mirror: it tracks simulated time in
// integer-seconds, advances it by simulated days, and exposes the
// current value to (a) the engine through the soak-only ABI and
// (b) the rig's own internal HTTP origins (so a "valid_until" check
// matches across both halves).
package clock

import (
	"sync"
	"time"
)

// Clock is the accelerated wall-clock the soak driver hands to every
// component (origins, censor fixture, scheduler).
type Clock struct {
	mu  sync.Mutex
	now time.Time
}

// New returns a clock starting at the given simulated wall time.
// The simulated start is intentionally a deterministic literal so two
// runs of the same scenario produce byte-identical artifacts (modulo
// hour-bucket offsets, which are also deterministic).
func New(start time.Time) *Clock {
	return &Clock{now: start.UTC()}
}

// Default starts at 2026-04-26T00:00:00Z — the date this phase began.
func Default() *Clock {
	return New(time.Date(2026, 4, 26, 0, 0, 0, 0, time.UTC))
}

// Now returns the current simulated time.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the simulated clock forward by d. Negative durations
// panic to surface bugs early.
func (c *Clock) Advance(d time.Duration) {
	if d < 0 {
		panic("clock: cannot advance by negative duration")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// AdvanceTo moves the clock to t. Earlier times panic.
func (c *Clock) AdvanceTo(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if t.Before(c.now) {
		panic("clock: cannot rewind")
	}
	c.now = t.UTC()
}

// SimulatedDay returns the number of complete simulated days since the
// clock's starting time.
func (c *Clock) SimulatedDay() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return int(c.now.Sub(time.Date(c.now.Year(), c.now.Month(), c.now.Day(), 0, 0, 0, 0, time.UTC)).Hours()/24) + 0
}
