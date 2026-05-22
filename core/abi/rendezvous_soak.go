//go:build soak

package abi

import "sync"

// Phase 3B: soak-only knobs for the `snowflake-broker-burn` and
// `push-rendezvous-opt-in` scenarios. The 3B handover noted these
// would land alongside the soak-engine dispatch wiring; they live
// here behind `-tags soak` so the release binary never compiles
// them.
//
// MarkRendezvousChannelBurned models the "channel returns errors
// for the next N attempts" signal the rendezvous Selector would
// see through real Solicitor failures. The Selector itself
// consults the rendezvous package's own state machine; the soak
// knob tracks the same fact for the rig's invariant ledger.
//
// SimulatePushPayload models the FCM/APNS data-message inbound;
// the rig calls this with (bridge, fp) shorthand and the engine
// wraps it into the 3B push path. The full crypto round-trip
// (canonical-JSON + ed25519) is exercised through
// `EngineDeliverPushPayload` in the engine tests; here we record
// only that the rig fired the simulated payload, which is
// sufficient for the soak invariant ledger.

var (
	rendezvousBurnMu       sync.Mutex
	rendezvousBurnChannel  string
	rendezvousBurnAttempts int

	simulatedPushMu       sync.Mutex
	simulatedPushBridge   string
	simulatedPushFP       string
	simulatedPushReceived bool
)

// MarkRendezvousChannelBurned sets the sticky "channel burned for
// the next N attempts" signal for `channelID`. attempts == 0
// clears.
func MarkRendezvousChannelBurned(channelID string, attempts int) {
	rendezvousBurnMu.Lock()
	defer rendezvousBurnMu.Unlock()
	if attempts <= 0 {
		rendezvousBurnChannel = ""
		rendezvousBurnAttempts = 0
		return
	}
	rendezvousBurnChannel = channelID
	rendezvousBurnAttempts = attempts
}

// IsRendezvousChannelBurned reports whether channelID is
// currently flagged, decrementing on a hit.
func IsRendezvousChannelBurned(channelID string) bool {
	rendezvousBurnMu.Lock()
	defer rendezvousBurnMu.Unlock()
	if rendezvousBurnAttempts <= 0 || rendezvousBurnChannel != channelID {
		return false
	}
	rendezvousBurnAttempts--
	return true
}

// SimulatePushPayload records that the rig fired a simulated
// FCM/APNS payload for (bridge, fp). The engine inspects this
// state via PopSimulatedPushPayload in its assertion path.
func SimulatePushPayload(bridge, fpHex string) {
	simulatedPushMu.Lock()
	defer simulatedPushMu.Unlock()
	simulatedPushBridge = bridge
	simulatedPushFP = fpHex
	simulatedPushReceived = true
}

// PopSimulatedPushPayload returns the most recent simulated
// payload, marking it consumed. Returns (bridge, fp, ok).
func PopSimulatedPushPayload() (string, string, bool) {
	simulatedPushMu.Lock()
	defer simulatedPushMu.Unlock()
	if !simulatedPushReceived {
		return "", "", false
	}
	simulatedPushReceived = false
	return simulatedPushBridge, simulatedPushFP, true
}
