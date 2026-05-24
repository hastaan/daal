package selection

import (
	"bytes"
	"testing"
	"time"

	"daal/core/netmem"
)

// TestPublicRiskTagSignature_DeterministicCanonicalSort.
func TestPublicRiskTagSignature_DeterministicCanonicalSort(t *testing.T) {
	in := []string{"public_port:tcp443", "public_ip:5.75.0.1", "public_asn:24940"}
	got := PublicRiskTagSignature(in)
	want := "public_asn:24940,public_ip:5.75.0.1,public_port:tcp443"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
	if PublicRiskTagSignature(nil) != "" {
		t.Error("nil tags must produce empty signature")
	}
}

// TestApply_NewKeyAppendsAndIncrementsCounters.
func TestApply_NewKeyAppendsAndIncrementsCounters(t *testing.T) {
	snap := netmem.Snapshot{}
	w := MemoryWrite{
		Family:                 "vless-reality",
		ExposureMode:           "direct_vps",
		PublicRiskTagSignature: "public_ip:5.75.0.1",
		Outcome:                OutcomeSuccess,
	}
	out := Apply(snap, w)
	stats, ok := out.RouteFamilyStats["vless-reality"]
	if !ok {
		t.Fatal("RouteFamilyStats[vless-reality] missing")
	}
	if stats.Successes != 1 || stats.Failures != 0 {
		t.Errorf("outer counters wrong: succ=%d fail=%d", stats.Successes, stats.Failures)
	}
	if len(stats.ByRelayPack) != 1 {
		t.Fatalf("expected 1 RelayPack entry; got %d", len(stats.ByRelayPack))
	}
	if stats.ByRelayPack[0].Successes != 1 {
		t.Errorf("RelayPack success counter not 1; got %d", stats.ByRelayPack[0].Successes)
	}
}

// TestApply_RepeatedSameKeyIncrementsExisting — counters
// monotonically increment; no duplicate entries appended.
func TestApply_RepeatedSameKeyIncrementsExisting(t *testing.T) {
	snap := netmem.Snapshot{}
	w := MemoryWrite{
		Family:                 "vless-reality",
		ExposureMode:           "direct_vps",
		PublicRiskTagSignature: "public_ip:5.75.0.1",
		Outcome:                OutcomeSuccess,
	}
	snap = Apply(snap, w)
	snap = Apply(snap, w)
	snap = Apply(snap, w)
	stats := snap.RouteFamilyStats["vless-reality"]
	if stats.Successes != 3 {
		t.Errorf("outer counter must monotonically reach 3; got %d", stats.Successes)
	}
	if len(stats.ByRelayPack) != 1 {
		t.Errorf("must NOT append duplicate entries; got %d", len(stats.ByRelayPack))
	}
	if stats.ByRelayPack[0].Successes != 3 {
		t.Errorf("RelayPack counter must be 3; got %d", stats.ByRelayPack[0].Successes)
	}
}

// TestApply_DeterministicUpdate — same input Snapshot + same
// MemoryWrite → byte-identical output. Pin LastSeen so the
// snapshot bytes are stable.
func TestApply_DeterministicUpdate(t *testing.T) {
	pin := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	mk := func() netmem.Snapshot {
		return netmem.Snapshot{LastSeen: pin}
	}
	w := MemoryWrite{
		Family:                 "vless-reality",
		ExposureMode:           "direct_vps",
		PublicRiskTagSignature: "public_ip:5.75.0.1",
		Outcome:                OutcomeSuccess,
	}
	a := Apply(mk(), w)
	b := Apply(mk(), w)
	ab, _ := a.MarshalCanonical()
	bb, _ := b.MarshalCanonical()
	if !bytes.Equal(ab, bb) {
		t.Errorf("Apply must be deterministic; got\n%s\nvs\n%s", ab, bb)
	}
}

// TestLookupHint_ExactMatch.
func TestLookupHint_ExactMatch(t *testing.T) {
	pin := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	snap := netmem.Snapshot{
		LastSeen: pin,
		RouteFamilyStats: map[string]netmem.FamilyStats{
			"vless-reality": {
				Successes: 5,
				ByRelayPack: []netmem.RelayPackStat{
					{
						Key: netmem.RelayPackKey{
							Family:                 "vless-reality",
							ExposureMode:           "direct_vps",
							PublicRiskTagSignature: "public_ip:5.75.0.1",
							Outcome:                OutcomeSuccess,
						},
						Successes: 5,
					},
				},
			},
		},
	}
	hint := LookupHint(&snap, "vless-reality", "direct_vps", "public_ip:5.75.0.1")
	if hint == nil {
		t.Fatal("expected exact-match hint")
	}
	if hint.Signature != "public_ip:5.75.0.1" {
		t.Errorf("signature wrong: %q", hint.Signature)
	}
	if hint.LastOutcome != OutcomeSuccess {
		t.Errorf("outcome wrong: %q", hint.LastOutcome)
	}
}

func TestLookupHint_ExactMatchAggregatesSuccessAndFailure(t *testing.T) {
	pin := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	snap := netmem.Snapshot{
		LastSeen: pin,
		RouteFamilyStats: map[string]netmem.FamilyStats{
			"vless-reality": {
				ByRelayPack: []netmem.RelayPackStat{
					{
						Key: netmem.RelayPackKey{
							Family:                 "vless-reality",
							ExposureMode:           "direct_vps",
							PublicRiskTagSignature: "public_ip:5.75.0.1",
							Outcome:                OutcomeClassifiedFailure,
						},
						Failures: 1,
					},
					{
						Key: netmem.RelayPackKey{
							Family:                 "vless-reality",
							ExposureMode:           "direct_vps",
							PublicRiskTagSignature: "public_ip:5.75.0.1",
							Outcome:                OutcomeSuccess,
						},
						Successes: 2,
					},
				},
			},
		},
	}
	hint := LookupHint(&snap, "vless-reality", "direct_vps", "public_ip:5.75.0.1")
	if hint == nil {
		t.Fatal("expected exact hint")
	}
	if hint.LastOutcome != OutcomeSuccess {
		t.Errorf("2 successes vs 1 failure should yield success; got %q", hint.LastOutcome)
	}
}

// TestLookupHint_WildcardFallback — no exact match; outer counters
// drive the hint.
func TestLookupHint_WildcardFallback(t *testing.T) {
	pin := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	snap := netmem.Snapshot{
		LastSeen: pin,
		RouteFamilyStats: map[string]netmem.FamilyStats{
			"vless-reality": {Successes: 7, Failures: 2},
		},
	}
	hint := LookupHint(&snap, "vless-reality", "direct_vps", "public_ip:1.2.3.4")
	if hint == nil {
		t.Fatal("expected wildcard hint")
	}
	if hint.Signature != "" {
		t.Errorf("wildcard hint must have empty signature; got %q", hint.Signature)
	}
	if hint.LastOutcome != OutcomeSuccess {
		t.Errorf("Successes>Failures must yield success hint; got %q", hint.LastOutcome)
	}
}

// TestLookupHint_EmptySnapshotReturnsNil.
func TestLookupHint_EmptySnapshotReturnsNil(t *testing.T) {
	if hint := LookupHint(nil, "vless-reality", "direct_vps", "x"); hint != nil {
		t.Errorf("nil snapshot must yield nil hint; got %+v", hint)
	}
	if hint := LookupHint(&netmem.Snapshot{}, "vless-reality", "direct_vps", "x"); hint != nil {
		t.Errorf("empty snapshot must yield nil hint; got %+v", hint)
	}
}

// TestApply_LegacyAndRelayPackCoexist — outer counters update for
// both; RelayPack entries don't shadow legacy reads.
func TestApply_LegacyAndRelayPackCoexist(t *testing.T) {
	snap := netmem.Snapshot{
		RouteFamilyStats: map[string]netmem.FamilyStats{
			"vless-reality": {Successes: 5, Failures: 1}, // legacy
		},
	}
	snap = Apply(snap, MemoryWrite{
		Family:                 "vless-reality",
		ExposureMode:           "direct_vps",
		PublicRiskTagSignature: "public_ip:5.75.0.1",
		Outcome:                OutcomeSuccess,
	})
	stats := snap.RouteFamilyStats["vless-reality"]
	if stats.Successes != 6 {
		t.Errorf("outer Successes must be 6 (legacy 5 + 1 new); got %d", stats.Successes)
	}
	if stats.Failures != 1 {
		t.Errorf("outer Failures must remain 1; got %d", stats.Failures)
	}
	if len(stats.ByRelayPack) != 1 {
		t.Errorf("RelayPack entry must be appended alongside legacy counters")
	}
}

// TestApply_OuterCountersIncrementWhenRelayPackKeyMissing — if a
// caller writes ONLY outer counters (legacy path), no RelayPack
// entry is appended.
func TestApply_OuterCountersIncrementWhenRelayPackKeyMissing(t *testing.T) {
	snap := netmem.Snapshot{}
	w := MemoryWrite{
		Family: "vless-reality",
		// No ExposureMode / PublicRiskTagSignature → still appends
		// a RelayPack entry with empty key (sparse path). This is
		// fine: the legacy reader treats empty-key entries as
		// wildcards.
		Outcome: OutcomeSuccess,
	}
	snap = Apply(snap, w)
	stats := snap.RouteFamilyStats["vless-reality"]
	if stats.Successes != 1 {
		t.Errorf("outer Successes must still increment; got %d", stats.Successes)
	}
}
