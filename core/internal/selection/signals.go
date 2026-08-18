package selection

import "sort"

// NetworkSignal is the FRP-3 selector-owned vocabulary covering the 9
// v2.3.4 network signals listed in supplement §13.3. The vocabulary
// is FROZEN at FRP-3 (invariant 25): adding a new signal in a later
// phase is allowed; renaming or removing one is a breaking change
// requiring a spec_version bump on selection-v1.
//
// The 5 signals that arise from error-string classification also
// appear as diagnostics.Category constants
// (DNSBogon, UDPCollapsed, QUICCollapsed, SNIRst, OriginUnhealthy)
// — see core/diagnostics/classify.go. The remaining 4 are
// probe-derived state aggregations (cdn_wide_failure requires
// "2+ candidates failed across 3+ networks", etc.) and live ONLY
// here.
type NetworkSignal string

const (
	// 5 also mirrored in diagnostics.Category:
	SignalDNSBogonDetected NetworkSignal = "dns_bogon_detected"
	SignalUDPCollapsed     NetworkSignal = "udp_collapsed"
	SignalQUICCollapsed    NetworkSignal = "quic_collapsed"
	SignalSNIRst           NetworkSignal = "sni_rst"
	SignalOriginUnhealthy  NetworkSignal = "origin_unhealthy"

	// 4 selector-only (no diagnostics.Category counterpart):
	SignalProtocolWhitelistMode     NetworkSignal = "protocol_whitelist_mode"
	SignalCDNHostnameBlocked        NetworkSignal = "cdn_hostname_blocked"
	SignalCDNWideFailure            NetworkSignal = "cdn_wide_failure"
	SignalStatefulReassemblyPresent NetworkSignal = "stateful_reassembly_present"
)

// AllSignals returns the 9 signals in lexicographic order. Used for
// vocabulary-freeze tests and for serialisation determinism.
func AllSignals() []NetworkSignal {
	out := []NetworkSignal{
		SignalCDNHostnameBlocked,
		SignalCDNWideFailure,
		SignalDNSBogonDetected,
		SignalOriginUnhealthy,
		SignalProtocolWhitelistMode,
		SignalQUICCollapsed,
		SignalSNIRst,
		SignalStatefulReassemblyPresent,
		SignalUDPCollapsed,
	}
	// Defensive: ensure sorted (the constants above are already
	// in alphabetical order, but the test below pins it).
	sort.SliceStable(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// IsKnownSignal reports whether s is one of the 9 frozen v2.3.4
// signals. Used by serialisation paths to reject unknown values.
func IsKnownSignal(s NetworkSignal) bool {
	switch s {
	case SignalDNSBogonDetected,
		SignalUDPCollapsed,
		SignalQUICCollapsed,
		SignalSNIRst,
		SignalOriginUnhealthy,
		SignalProtocolWhitelistMode,
		SignalCDNHostnameBlocked,
		SignalCDNWideFailure,
		SignalStatefulReassemblyPresent:
		return true
	}
	return false
}

// SignalStrings returns a sorted []string projection suitable for
// embedding in Explanation.NetworkSignals.
func SignalStrings(sig []NetworkSignal) []string {
	out := make([]string, len(sig))
	for i, s := range sig {
		out[i] = string(s)
	}
	sort.Strings(out)
	return out
}

// SignalForCategory maps a diagnostics.Category value onto the
// NetworkSignal it is the same fact as, for the 5 signals that have a
// counterpart. Returns ok=false for the other ~17 categories and for
// the 4 selector-only signals, which are probe-derived aggregations
// (`cdn_wide_failure` needs "2+ candidates failed across 3+ networks")
// and cannot be produced from a single classified error at all.
//
// The parameter is a plain string rather than a diagnostics.Category so
// this package keeps its "no dependencies outside netmem/routestore"
// property; the two vocabularies are pinned against each other by
// TestSignalForCategory_CoversTheFiveMirroredCategories.
//
// WHY THIS EXISTS. The 5 mirrored signals were declared in two places
// and derivable from neither: the selector's Input.NetworkSignals had
// no producer anywhere in the tree, so every Decide call in production
// ran with an empty signal set — which silently disables the
// UDP-collapse penalty in rankCandidate and the degraded race plan in
// PlanRace. This is the conversion that makes an already-measured
// failure classification legible to the selector.
func SignalForCategory(category string) (NetworkSignal, bool) {
	switch category {
	case "dns_bogon":
		return SignalDNSBogonDetected, true
	case "udp_collapsed":
		return SignalUDPCollapsed, true
	case "quic_collapsed":
		return SignalQUICCollapsed, true
	case "sni_rst":
		return SignalSNIRst, true
	case "origin_unhealthy":
		return SignalOriginUnhealthy, true
	}
	return "", false
}

// SignalsFromCategories maps a batch of classified failure categories
// onto the deduplicated, lexicographically sorted signal set they
// imply. Unmapped categories are dropped silently — that is the point
// of the closed vocabulary.
//
// Determinism matters here beyond tidiness: the result is embedded in
// Explanation.NetworkSignals, which diagnostics exports and which the
// FRP-6 explanation fixtures compare byte-for-byte.
func SignalsFromCategories(categories []string) []NetworkSignal {
	seen := map[NetworkSignal]bool{}
	out := []NetworkSignal{}
	for _, c := range categories {
		if sig, ok := SignalForCategory(c); ok && !seen[sig] {
			seen[sig] = true
			out = append(out, sig)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
