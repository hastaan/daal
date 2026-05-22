package abi

import (
	"errors"
	"time"
)

// LifecycleEvent enumerates the iOS Network Extension state
// transitions the Swift bridge can surface into the engine. The
// set is closed at v1; new tokens require an ABI spec amendment
// (the Go layer rejects unknown tokens with ErrUnknownLifecycle so
// a future Swift version cannot silently ship a token the engine
// doesn't classify).
//
// Tokens are documented in `specs/ios-build-v1.md`. The semantics:
//
//   - "will_sleep": the NE process is being suspended. The engine
//     should NOT bump the session epoch (suspension is not a new
//     session); refreshes in flight are allowed to be cancelled by
//     the OS.
//   - "did_wake": the NE process resumed. The engine should NOT
//     reset cooldown counters (sleep does not "heal" a burned
//     route). The bridge will follow up with engine_network_changed
//     if the network has actually changed.
//   - "memory_pressure_warning": the NE is approaching its memory
//     ceiling. The engine should NOT take action by itself — the
//     Swift bridge owns the WireGuard sub-engine handoff. The
//     event is recorded so the diagnostics surface explains
//     subsequent route behavior to a human operator.
const (
	LifecycleWillSleep      = "will_sleep"
	LifecycleDidWake        = "did_wake"
	LifecycleMemoryPressure = "memory_pressure_warning"
)

// ErrUnknownLifecycle is returned by LifecycleEvent for tokens
// outside the locked v1 set.
var ErrUnknownLifecycle = errors.New("abi: unknown lifecycle event")

// LifecycleEvent is the Go-layer entry point for the
// `engine_lifecycle_event` ABI surface. The Swift bridge calls
// this once per state transition. Returns ErrUnknownLifecycle for
// out-of-set tokens; callers map this to a -1 ABI return.
//
// The function is intentionally side-effect-light: the engine
// records the event for diagnostics and nothing else. Real
// reactions (cooldown adjustments, refresh deferral) happen in
// the path manager and the refresher when they consult diagnostics
// state, NOT here. This keeps the bridge / engine boundary clean.
func LifecycleEvent(token string) error {
	switch token {
	case LifecycleWillSleep, LifecycleDidWake, LifecycleMemoryPressure:
		// known
	default:
		return ErrUnknownLifecycle
	}
	c := mustCore()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastLifecycleEvent = token
	c.lastLifecycleAt = nowUTC()
	return nil
}

// LifecycleSnapshot is the gomobile-friendly return shape for
// LastLifecycleEvent. gomobile bind rejects multi-value returns
// where the second value isn't `error`, so we return a struct.
type LifecycleSnapshot struct {
	Token string
	At    time.Time
}

// LastLifecycleEvent is the diagnostics-side accessor. Returns
// a zero-valued LifecycleSnapshot if the bridge has never fired
// an event in this engine session (the typical state on
// Linux/Android/desktop).
func LastLifecycleEvent() LifecycleSnapshot {
	c := mustCore()
	c.mu.Lock()
	defer c.mu.Unlock()
	return LifecycleSnapshot{Token: c.lastLifecycleEvent, At: c.lastLifecycleAt}
}
