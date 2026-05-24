// Package burnpressure is the Phase 2G auto-promotion detector.
//
// It consumes the per-network family-escalation ladder
// (`SkippedFamily.LadderStep` from `core/pathmanager`) and emits a
// `Verdict` indicating whether the engine should auto-promote into
// `lifeline-strict` mode. The detector is consulted by the
// scheduler on every Tick (cadence already set by Phase 2F).
//
// V1 thresholds (locked):
//
//   - DistinctFamilyMinimum   = 3
//   - WindowDuration          = 30 * time.Minute
//   - LadderStepMinimum       = 3        // 24 h family cooldown
//
// Both conditions must hold simultaneously for promotion to fire:
//
//  1. ≥ DistinctFamilyMinimum families are currently skipped
//     (i.e. their `SkippedFamily.Until` is in the future) within a
//     sliding WindowDuration on the active network.
//  2. At least one of those families is at LadderStep ≥
//     LadderStepMinimum.
//
// These values are deliberately conservative. The whole point of
// auto-promotion is to react to a real burn event — a single
// transient cooldown should NEVER promote. v2 may revise these
// based on OONI / Censored Planet field data; for v1 they are
// hard constants regression-locked by `TestThresholdsLocked`.
//
// The detector is purely a function of read-only diagnostics
// inputs. It does not flip the engine's mode — that is the
// scheduler's job, and the scheduler honours the manual override
// stamped by the user-facing `engine_set_mode` ABI path.
package burnpressure
