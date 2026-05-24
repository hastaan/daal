package selection

import (
	"sort"
	"testing"
)

// TestAllSignals_VocabularyFrozen pins the 9 v2.3.4 signals at FRP-3.
// Adding a new signal in a later phase REQUIRES updating this test
// AND bumping the spec_version on selection-v1.md. Renaming or
// removing one is a breaking change.
func TestAllSignals_VocabularyFrozen(t *testing.T) {
	want := []NetworkSignal{
		"cdn_hostname_blocked",
		"cdn_wide_failure",
		"dns_bogon_detected",
		"origin_unhealthy",
		"protocol_whitelist_mode",
		"quic_collapsed",
		"sni_rst",
		"stateful_reassembly_present",
		"udp_collapsed",
	}
	got := AllSignals()
	if len(got) != len(want) {
		t.Fatalf("vocabulary size changed: got %d signals, want %d", len(got), len(want))
	}
	for i, s := range want {
		if got[i] != s {
			t.Errorf("signal[%d]: got %q want %q (vocabulary order changed?)", i, got[i], s)
		}
	}
}

// TestAllSignals_SortedAscending pins the canonical-sort property
// of AllSignals so callers may rely on the deterministic order
// without re-sorting.
func TestAllSignals_SortedAscending(t *testing.T) {
	all := AllSignals()
	if !sort.SliceIsSorted(all, func(i, j int) bool { return all[i] < all[j] }) {
		t.Errorf("AllSignals must return sorted vocabulary; got %v", all)
	}
}

// TestIsKnownSignal_AllNineRecognised asserts every member of
// AllSignals() is recognised; an unknown literal is rejected.
func TestIsKnownSignal_AllNineRecognised(t *testing.T) {
	for _, s := range AllSignals() {
		if !IsKnownSignal(s) {
			t.Errorf("IsKnownSignal(%q) = false; want true", s)
		}
	}
	if IsKnownSignal("not_a_real_signal") {
		t.Error("IsKnownSignal should reject unknown literal")
	}
	if IsKnownSignal("") {
		t.Error("IsKnownSignal should reject empty string")
	}
}

// TestSignalStrings_StableSort pins the deterministic order of
// the []string projection used by Explanation.NetworkSignals.
func TestSignalStrings_StableSort(t *testing.T) {
	in := []NetworkSignal{
		SignalUDPCollapsed,
		SignalCDNWideFailure,
		SignalSNIRst,
	}
	out := SignalStrings(in)
	want := []string{"cdn_wide_failure", "sni_rst", "udp_collapsed"}
	if len(out) != len(want) {
		t.Fatalf("len mismatch: got %d want %d", len(out), len(want))
	}
	for i, s := range want {
		if out[i] != s {
			t.Errorf("[%d] got %q want %q", i, out[i], s)
		}
	}
}
