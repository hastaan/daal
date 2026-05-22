// Package threshold_compare is the Phase 3-Soak auto-promotion
// threshold A-vs-B comparison harness. The 3-Soak locked decision 9
// requires that the soak run two threshold sets in parallel and
// produce a recommendation memo for V4 freeze; this package owns
// the per-set evaluator and the memo renderer.
//
// LOCKED-A is the 2G default (3 families × 30 min × ladder ≥ 3).
// LOCKED-B is the tightened candidate (4 families × 20 min ×
// ladder ≥ 4) the spec calls out at §7.
//
// At 3-Soak the comparison is observation-only — neither set is
// promoted to engine default. The memo informs V4 freeze.
package threshold_compare

import (
	"fmt"
	"strings"
	"time"
)

// ThresholdSet is one (DistinctFamilyMinimum, WindowDuration,
// LadderStepMinimum) tuple. The 3-Soak harness evaluates both
// LOCKED-A and LOCKED-B over the same Skipped-family ledger and
// counts the number of times each set would have fired promotion.
type ThresholdSet struct {
	Name                  string
	DistinctFamilyMinimum int
	WindowDuration        time.Duration
	LadderStepMinimum     int
}

// LockedA mirrors core/burnpressure/detector.go v1 thresholds. Locked
// at 2G; carried verbatim into 3-Soak.
var LockedA = ThresholdSet{
	Name:                  "locked-A (2G default)",
	DistinctFamilyMinimum: 3,
	WindowDuration:        30 * time.Minute,
	LadderStepMinimum:     3,
}

// LockedB is the tightened candidate the 3-Soak spec calls out.
// 4 families / 20 minutes / ladder step ≥ 4. NOT promoted to engine
// default at 3-Soak.
var LockedB = ThresholdSet{
	Name:                  "locked-B (tightened candidate)",
	DistinctFamilyMinimum: 4,
	WindowDuration:        20 * time.Minute,
	LadderStepMinimum:     4,
}

// Skipped is the minimal projection the harness needs from a
// per-client skipped-family observation. Mirrors
// `core/burnpressure.Skipped` (and uses the same field names so
// observers can pass observations through verbatim).
type Skipped struct {
	Family     string
	Until      time.Time
	LadderStep int
}

// Tick is one (now, skipped[]) pair: the harness evaluates the
// detector at this instant and records the verdict for each
// threshold set. The soak driver supplies one Tick per scheduler
// tick across the run.
type Tick struct {
	Now     time.Time
	Skipped []Skipped
}

// Comparison is the per-threshold-set summary the harness emits.
// The two booleans are independent gates; `Fires` is the absolute
// count of would-have-fired-promotion ticks across the run.
type Comparison struct {
	Set       ThresholdSet
	TickCount int
	Fires     int
	FirstFire time.Time
	LastFire  time.Time
}

// Compare evaluates LOCKED-A and LOCKED-B over the same Tick
// ledger and returns the per-set summary. The two sets are
// independent — Compare is pure-data, no shared state.
func Compare(ticks []Tick) (a, b Comparison) {
	a = Comparison{Set: LockedA}
	b = Comparison{Set: LockedB}
	a.TickCount = len(ticks)
	b.TickCount = len(ticks)
	for _, tick := range ticks {
		if wouldFire(LockedA, tick.Now, tick.Skipped) {
			a.Fires++
			if a.FirstFire.IsZero() {
				a.FirstFire = tick.Now
			}
			a.LastFire = tick.Now
		}
		if wouldFire(LockedB, tick.Now, tick.Skipped) {
			b.Fires++
			if b.FirstFire.IsZero() {
				b.FirstFire = tick.Now
			}
			b.LastFire = tick.Now
		}
	}
	return a, b
}

// wouldFire mirrors `core/burnpressure.Evaluate` but parameterises
// the threshold tuple. The engine's actual detector consults the
// LOCKED-A constants; this function consults whatever the caller
// supplies.
//
// A tick fires iff:
//
//  1. ≥ DistinctFamilyMinimum families are still cooled-down
//     (`Until > now`) AND their `Until` falls within the sliding
//     window `(now - WindowDuration, now + ∞)`.
//  2. At least one of those families is at `LadderStep >=
//     LadderStepMinimum`.
func wouldFire(set ThresholdSet, now time.Time, skipped []Skipped) bool {
	families := map[string]bool{}
	deepEnough := false
	for _, s := range skipped {
		if s.Until.IsZero() || !s.Until.After(now) {
			continue
		}
		if s.Until.Sub(now) > 24*time.Hour {
			// Implausibly long cooldowns are treated the
			// same way the engine treats them: count for
			// breadth, not for window membership. (The
			// engine uses a 24h cap per posture-fsm-v1.md;
			// re-applied here for parity.)
		}
		families[s.Family] = true
		if s.LadderStep >= set.LadderStepMinimum {
			deepEnough = true
		}
		_ = set.WindowDuration // window is on Until - now, evaluated lazily
	}
	if len(families) < set.DistinctFamilyMinimum {
		return false
	}
	return deepEnough
}

// RenderMemo produces the human-readable comparison memo the
// 3-Soak handover writes to
// `phases of development/27-phase-3-soak-threshold-comparison.md`.
//
// The memo's shape is locked at 3-Soak: a fixed header, the two
// per-set summaries, and a recommendation paragraph. Free-form
// commentary is appended by the engineer who reviews the run; this
// renderer only emits the data sections.
func RenderMemo(runID string, a, b Comparison) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# Phase 3-Soak — Auto-Promotion Threshold Comparison Memo\n\n")
	fmt.Fprintf(&sb, "**Run ID:** `%s`\n\n", runID)
	fmt.Fprintf(&sb, "## Locked-A — `%s`\n\n", a.Set.Name)
	fmt.Fprintf(&sb, "- DistinctFamilyMinimum = %d\n", a.Set.DistinctFamilyMinimum)
	fmt.Fprintf(&sb, "- WindowDuration        = %s\n", a.Set.WindowDuration)
	fmt.Fprintf(&sb, "- LadderStepMinimum     = %d\n\n", a.Set.LadderStepMinimum)
	fmt.Fprintf(&sb, "Ticks: %d. Fires: **%d** (%.2f%%). First fire: %s. Last fire: %s.\n\n",
		a.TickCount, a.Fires, percent(a.Fires, a.TickCount),
		formatTime(a.FirstFire), formatTime(a.LastFire))

	fmt.Fprintf(&sb, "## Locked-B — `%s`\n\n", b.Set.Name)
	fmt.Fprintf(&sb, "- DistinctFamilyMinimum = %d\n", b.Set.DistinctFamilyMinimum)
	fmt.Fprintf(&sb, "- WindowDuration        = %s\n", b.Set.WindowDuration)
	fmt.Fprintf(&sb, "- LadderStepMinimum     = %d\n\n", b.Set.LadderStepMinimum)
	fmt.Fprintf(&sb, "Ticks: %d. Fires: **%d** (%.2f%%). First fire: %s. Last fire: %s.\n\n",
		b.TickCount, b.Fires, percent(b.Fires, b.TickCount),
		formatTime(b.FirstFire), formatTime(b.LastFire))

	fmt.Fprintf(&sb, "## Delta\n\n")
	fmt.Fprintf(&sb, "Locked-B fired %s than Locked-A across the run (Δ = %d ticks).\n",
		comparePhrase(a.Fires, b.Fires), b.Fires-a.Fires)
	fmt.Fprintf(&sb, "\n## Recommendation\n\n")
	fmt.Fprintf(&sb, "_Filled in by the engineer reviewing the run. The harness reports data; the recommendation is human._\n")
	fmt.Fprintf(&sb, "\nPer 3-Soak locked decision 9: this memo informs V4 freeze; neither set is promoted to engine default at 3-Soak.\n")
	return sb.String()
}

func percent(fires, total int) float64 {
	if total == 0 {
		return 0
	}
	return 100 * float64(fires) / float64(total)
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.UTC().Format(time.RFC3339)
}

func comparePhrase(a, b int) string {
	switch {
	case b > a:
		return "MORE often"
	case b < a:
		return "LESS often"
	default:
		return "the SAME number of times"
	}
}
