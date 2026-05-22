package selection

import (
	"sort"
	"strings"

	"daal/core/netmem"
)

// Outcome enumerates the per-network memory outcomes the FRP-3
// selector records. Locked vocabulary at FRP-3.
const (
	OutcomeSuccess           = "success"
	OutcomeClassifiedFailure = "classified_failure"
)

// PublicRiskTagSignature returns the canonical-sorted-comma-joined
// public_risk_tags string used to key per-network memory entries.
// Pure function; same input → same output across processes and
// platforms.
//
// Sorted ascending; empty input → "".
func PublicRiskTagSignature(tags []string) string {
	if len(tags) == 0 {
		return ""
	}
	cp := make([]string, len(tags))
	copy(cp, tags)
	sort.Strings(cp)
	return strings.Join(cp, ",")
}

// MemoryWrite is one entry the caller emits to update per-network
// memory after a race outcome. The caller applies these updates to
// the netmem.Snapshot via Apply (below) and then persists.
type MemoryWrite struct {
	Family                 string
	ExposureMode           string
	PublicRiskTagSignature string
	Outcome                string
}

// LookupHint returns a *MemoryHint when a per-network memory entry
// matches `(family, exposure_mode, signature)` exactly, OR when a
// wildcard (family, "", "") family-level entry exists. Wildcard
// fallback is the legacy non-RelayPack path.
//
// Last-seen-Unix is taken from the parent Snapshot's LastSeen
// (single timestamp across all entries; FRP-3 does not store
// per-key timestamps to keep the wire shape unchanged).
//
// `exposureMode` and `signature` may be empty for legacy candidates;
// the lookup gracefully degrades.
func LookupHint(snap *netmem.Snapshot, family, exposureMode, signature string) *MemoryHint {
	if snap == nil || snap.Empty() {
		return nil
	}
	stats, ok := snap.RouteFamilyStats[family]
	if !ok {
		return nil
	}
	// Pass 1: exact (family, exposure_mode, signature). Aggregate
	// success/failure rows because the FRP-2 shape stores Outcome
	// in the key rather than as a timestamped last-event row.
	var exactSuccesses, exactFailures uint64
	for _, rp := range stats.ByRelayPack {
		if rp.Key.Family != family {
			continue
		}
		if rp.Key.ExposureMode != exposureMode {
			continue
		}
		if rp.Key.PublicRiskTagSignature != signature {
			continue
		}
		exactSuccesses += rp.Successes
		exactFailures += rp.Failures
	}
	if exactSuccesses > 0 || exactFailures > 0 {
		out := OutcomeClassifiedFailure
		if exactSuccesses >= exactFailures {
			out = OutcomeSuccess
		}
		return &MemoryHint{
			Signature:    signature,
			LastOutcome:  out,
			LastSeenUnix: snap.LastSeen.Unix(),
		}
	}
	// Pass 2: wildcard fallback. If the candidate has no signature
	// yet (legacy or not-yet-seen on this network), the outer
	// FamilyStats counters still hint "we've seen this family
	// before".
	if stats.Successes == 0 && stats.Failures == 0 {
		return nil
	}
	last := OutcomeClassifiedFailure
	if stats.Successes > stats.Failures {
		last = OutcomeSuccess
	}
	return &MemoryHint{
		Signature:    "",
		LastOutcome:  last,
		LastSeenUnix: snap.LastSeen.Unix(),
	}
}

// Apply writes a MemoryWrite onto a Snapshot. Pure: takes a
// Snapshot value and returns a new Snapshot with the increment
// applied. The original is not mutated; the caller persists the
// returned value.
//
// Determinism contract: same input Snapshot + same MemoryWrite →
// identical output Snapshot bytes (modulo LastSeen, which the
// caller may set to a fixed time for tests). Repeated calls
// monotonically increment counters.
func Apply(snap netmem.Snapshot, w MemoryWrite) netmem.Snapshot {
	if snap.RouteFamilyStats == nil {
		snap.RouteFamilyStats = map[string]netmem.FamilyStats{}
	}
	stats := snap.RouteFamilyStats[w.Family]

	// Outer (legacy) counters always increment.
	switch w.Outcome {
	case OutcomeSuccess:
		stats.Successes++
	case OutcomeClassifiedFailure:
		stats.Failures++
	}

	// Inner ByRelayPack: find existing key or append.
	key := netmem.RelayPackKey{
		Family:                 w.Family,
		ExposureMode:           w.ExposureMode,
		PublicRiskTagSignature: w.PublicRiskTagSignature,
		Outcome:                w.Outcome,
	}
	found := false
	for i, rp := range stats.ByRelayPack {
		if rp.Key == key {
			switch w.Outcome {
			case OutcomeSuccess:
				stats.ByRelayPack[i].Successes++
			case OutcomeClassifiedFailure:
				stats.ByRelayPack[i].Failures++
			}
			found = true
			break
		}
	}
	if !found {
		st := netmem.RelayPackStat{Key: key}
		switch w.Outcome {
		case OutcomeSuccess:
			st.Successes = 1
		case OutcomeClassifiedFailure:
			st.Failures = 1
		}
		stats.ByRelayPack = append(stats.ByRelayPack, st)
		// Sort by canonical key tuple so the slice serialises
		// deterministically across regenerations.
		sort.SliceStable(stats.ByRelayPack, func(i, j int) bool {
			return relayPackKeyLess(stats.ByRelayPack[i].Key, stats.ByRelayPack[j].Key)
		})
	}

	snap.RouteFamilyStats[w.Family] = stats
	return snap
}

// relayPackKeyLess provides a total ordering on RelayPackKey for
// deterministic ByRelayPack serialisation. Order: Family, then
// ExposureMode, then PublicRiskTagSignature, then Outcome.
func relayPackKeyLess(a, b netmem.RelayPackKey) bool {
	if a.Family != b.Family {
		return a.Family < b.Family
	}
	if a.ExposureMode != b.ExposureMode {
		return a.ExposureMode < b.ExposureMode
	}
	if a.PublicRiskTagSignature != b.PublicRiskTagSignature {
		return a.PublicRiskTagSignature < b.PublicRiskTagSignature
	}
	return a.Outcome < b.Outcome
}
