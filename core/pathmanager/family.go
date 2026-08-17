package pathmanager

import (
	"time"

	"daal/core/diagnostics"
)

// familyBackoffLadder is the V2.3 exponential-backoff ladder for
// family-level cooldowns: 5min, 15min, 1h, 4h, 24h, capped.
// Roadmap V2.3 verbatim.
var familyBackoffLadder = []time.Duration{
	5 * time.Minute,
	15 * time.Minute,
	1 * time.Hour,
	4 * time.Hour,
	24 * time.Hour,
}

// FamilyCooldownStep returns the duration for ladder step n
// (1-indexed). n ≤ 0 returns 0; n > len(ladder) clamps to the cap.
func FamilyCooldownStep(n int) time.Duration {
	if n <= 0 {
		return 0
	}
	if n > len(familyBackoffLadder) {
		n = len(familyBackoffLadder)
	}
	return familyBackoffLadder[n-1]
}

// IsFamilyClass reports whether a V0.3 cooldown category should fire
// a family cooldown immediately at ladder step 1, bypassing the
// per-route 3-failure trigger.
//
// Hybrid policy (Phase 2B locked):
//   - TLS-SNI / cert-block, UDP-unavailable, QUIC-unavailable are
//     network-wide indicators: a single failure means the entire
//     family is blocked on this network. Fire family cooldown
//     immediately at step 1.
//   - tcp_reset, tls_handshake_failed, tcp_connect_timeout,
//     dns_timeout, dns_poisoned are per-route indicators: cooldown
//     the failing route immediately, but only fire family cooldown
//     after 3 consecutive failures on the same family within 1 h
//     (preserves 2A's behaviour for these classes).
func IsFamilyClass(c diagnostics.Category) bool {
	switch c {
	case diagnostics.TLSSNIOrCertBlockSuspected,
		diagnostics.UDPUnavailable,
		diagnostics.QUICUnavailable:
		return true
	}
	return false
}
