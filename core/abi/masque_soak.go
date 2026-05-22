//go:build soak

package abi

import "sync"

// Phase 3C: soak-only knobs for the `masque-udp-failover` and
// `masque-lifeline-rung` scenarios. These knobs model the
// "MASQUE sub-mode burned for the next N attempts" signal the
// 2G classifier would otherwise carry; they let the soak rig
// drive the chooseSubmode cascade's step-6 drop-to-lifeline
// branch without needing an actual classifier-burned route.
//
// Release builds do NOT compile this file; the soak engine is
// always built with `-tags soak`.

var (
	masqueBurnMu        sync.Mutex
	masqueBurnSubmode   string
	masqueBurnRemaining int
)

// MarkMasqueSubmodeBurned sets a sticky "burned for the next N
// activations" signal for `submode`. Passing attempts == 0
// clears the signal. The masque handler's chooseSubmode reads
// this through `IsMasqueSubmodeBurned` which decrements the
// counter on each consultation.
func MarkMasqueSubmodeBurned(submode string, attempts int) {
	masqueBurnMu.Lock()
	defer masqueBurnMu.Unlock()
	if attempts <= 0 {
		masqueBurnSubmode = ""
		masqueBurnRemaining = 0
		return
	}
	masqueBurnSubmode = submode
	masqueBurnRemaining = attempts
}

// IsMasqueSubmodeBurned reports whether `submode` is currently
// flagged as burned, decrementing the remaining-attempts
// counter on a hit. Returns false once the counter reaches 0.
//
// Test-only: the masque handler does NOT consult this directly
// in a release build — chooseSubmode takes a Route.H2Burned bool
// as input and the engine wires that through the 2G classifier.
// The soak rig calls this knob to assert the engine's state
// rather than to drive selection.
func IsMasqueSubmodeBurned(submode string) bool {
	masqueBurnMu.Lock()
	defer masqueBurnMu.Unlock()
	if masqueBurnRemaining <= 0 || masqueBurnSubmode != submode {
		return false
	}
	masqueBurnRemaining--
	return true
}
