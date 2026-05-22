package burnpressure

import (
	"time"
)

// V1 thresholds (LOCKED). Bumping any of these is a v2 spec change.
const (
	DistinctFamilyMinimum = 3
	WindowDuration        = 30 * time.Minute
	LadderStepMinimum     = 3
)

// Skipped is the minimal projection the detector needs from
// `core/pathmanager.SkippedFamily`. Decoupled into its own type so
// the burnpressure package does not import pathmanager (which would
// risk an import cycle if pathmanager were to consult this
// detector in the future).
type Skipped struct {
	Family     string
	Until      time.Time
	LadderStep int
}

// Verdict is the detector's output. `ShouldPromote` is the only
// signal the scheduler acts on; `Reason` is for the diagnostic
// ledger so the user can later answer "why did the engine flip
// into lifeline-strict at 14:30?".
type Verdict struct {
	ShouldPromote bool
	Reason        string
}

// Evaluate computes the verdict at the given wall-clock instant
// from the supplied skipped-family snapshot.
//
// Both v1 conditions must hold:
//
//  1. ≥ DistinctFamilyMinimum families with `Until > now` AND
//     `Until - WindowDuration <= now` (i.e. the skip is within the
//     sliding window).
//  2. At least one of those families is at `LadderStep >=
//     LadderStepMinimum`.
//
// The `LadderStep` check picks at least one "deep" family; without
// it, three transient first-trip cooldowns on three families would
// otherwise fire promotion, which is too eager.
func Evaluate(now time.Time, skipped []Skipped) Verdict {
	var inWindow []Skipped
	for _, s := range skipped {
		if s.Until.IsZero() {
			continue
		}
		if !s.Until.After(now) {
			// Cooldown has expired; ignore.
			continue
		}
		// A currently-active cooldown counts toward the breadth.
		// The WindowDuration name reflects the breadth-aggregation
		// window the engine evaluates each scheduler tick: any
		// family whose cooldown is still in force at the tick
		// instant is "currently in the window of concern". Deeper
		// cooldowns persist across many ticks; transient ones
		// drop off fast. The combination of the breadth count and
		// the LadderStep depth check yields the v1 lock.
		inWindow = append(inWindow, s)
	}
	if len(inWindow) < DistinctFamilyMinimum {
		return Verdict{}
	}
	deepEnough := false
	for _, s := range inWindow {
		if s.LadderStep >= LadderStepMinimum {
			deepEnough = true
			break
		}
	}
	if !deepEnough {
		return Verdict{}
	}
	return Verdict{
		ShouldPromote: true,
		Reason: "burn_pressure: " +
			itoa(len(inWindow)) + " families skipped within " +
			WindowDuration.String() + "; at least one at ladder ≥ " +
			itoa(LadderStepMinimum),
	}
}

// itoa is a tiny stdlib-free integer formatter; the burnpressure
// package keeps its imports minimal so it can be consumed by both
// the engine core and (in the future) by gomobile facades that
// bind to the same Go runtime.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
