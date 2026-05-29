package netmem

import (
	"encoding/json"
	"sort"
	"time"
)

// FamilyStats is the per-route-family success/failure counter for a
// single network. Roadmap V2.4 bullet "route-family-level
// success/failure counts per network".
//
// FRP-2 (Phase 30): widened with optional sparse per-RelayPack-key
// sub-counters so the FRP-3 selector can read mode-aware per-network
// success memory keyed on
// `(family × exposure_mode × public_risk_tag_signature × outcome)`
// per supplement §13.4. The outer (family-keyed) counters are
// preserved for legacy entries; FRP-3 prefers entries with matching
// `public_risk_tag_signature` and falls back to the outer counters
// otherwise.
//
// Wire-compat: ByRelayPack uses `omitempty`, so pre-FRP-2 snapshots
// round-trip byte-identical (no `"by_relay_pack": null` injected).
type FamilyStats struct {
	Successes   uint64          `json:"successes"`
	Failures    uint64          `json:"failures"`
	ByRelayPack []RelayPackStat `json:"by_relay_pack,omitempty"`
}

// RelayPackKey is the FRP-2-widened netmem dimension. Sparse: only
// populated when the FRP-3 selector records a RelayPack-aware
// outcome. Legacy entries (no RelayPack) leave this struct
// zero-valued; readers treat zero-valued keys as wildcard fall-through.
//
// Field semantics:
//   - Family: the route family the outcome was observed against
//     (e.g. "vless-reality"). Cross-checked against the outer
//     RouteFamilyStats key.
//   - ExposureMode ∈ {direct_vps, cdn_fronted, ""}. "" = wildcard.
//   - PublicRiskTagSignature: canonical-sorted-and-comma-joined
//     `public_risk_tags[]` of the candidate that produced the
//     outcome. Computed by FRP-3 at write time. "" = wildcard.
//   - Outcome ∈ {success, classified_failure, ""}.
type RelayPackKey struct {
	Family                 string `json:"family,omitempty"`
	ExposureMode           string `json:"exposure_mode,omitempty"`
	PublicRiskTagSignature string `json:"public_risk_tag_signature,omitempty"`
	Outcome                string `json:"outcome,omitempty"`
}

// RelayPackStat is the per-key (key, successes, failures) tuple
// stored in FamilyStats.ByRelayPack. FRP-3 is the writer.
type RelayPackStat struct {
	Key       RelayPackKey `json:"key"`
	Successes uint64       `json:"successes"`
	Failures  uint64       `json:"failures"`
}

// RouteHealthSlim is the persisted projection of pathmanager's
// RouteHealth row — only what's needed to restore last-known good
// state. Reasons are V0.3 categories (string).
type RouteHealthSlim struct {
	Posture         string    `json:"posture"`
	CooldownReason  string    `json:"cooldown_reason,omitempty"`
	CooldownUntil   time.Time `json:"cooldown_until,omitempty"`
	BudgetExhausted bool      `json:"budget_exhausted,omitempty"`
}

// Snapshot is the per-network memory blob serialised as canonical
// JSON. Stable across versions: adding a field is allowed, removing
// or renaming requires a v2 spec.
type Snapshot struct {
	// Mode last active on this network. One of {"lifeline",
	// "normal", "bulk"} at 2C; widens to "lifeline-strict" at 2D.
	Mode string `json:"mode"`

	// LastSeen is updated on every Put. Drives the 30-day Sweep.
	LastSeen time.Time `json:"last_seen"`

	// RouteFamilyStats — per-family success/failure counts. Sparse:
	// only families that have been exercised on this network appear.
	RouteFamilyStats map[string]FamilyStats `json:"route_family_stats,omitempty"`

	// RouteHealth — per-route current FSM at swap-out time.
	RouteHealth map[string]RouteHealthSlim `json:"route_health,omitempty"`

	// BudgetUsage — per-route consumed bytes for THE LAST observed
	// hour bucket. Restored on reconnect IF the bucket is still
	// current; if the bucket has rolled, Snapshot.applyBucket()
	// discards.
	BudgetUsage  map[string]uint64 `json:"budget_usage,omitempty"`
	BudgetBucket time.Time         `json:"budget_bucket,omitempty"`

	// Network-diagnosis indicators — V0.3 + V2.4 roadmap bullets.
	UDPProbeOK  bool      `json:"udp_probe_ok,omitempty"`
	UDPProbeAt  time.Time `json:"udp_probe_at,omitempty"`
	DNSPoisoned bool      `json:"dns_poisoned,omitempty"`

	// Phase 3B. The rendezvous channel that most recently
	// completed a successful Solicit on THIS network. Empty
	// string means "no winner recorded on this network." The
	// 3B Selector consults this field as a soft hint: with a
	// recorded winner, the Selector fires that channel at t=0
	// regardless of bundle-supplied or per-engine-overridden
	// priority. The hint is per-network and never leaves the
	// device. See specs/network-memory-v1.md "Phase 3B widening"
	// and specs/rendezvous-channels-v1.md.
	LastWinningRendezvousChannel string `json:"last_winning_rendezvous_channel,omitempty"`

	// Phase 3C. The MASQUE sub-mode that most recently
	// completed a successful Dial on THIS network. One of
	// {"masque_h3_quic", "masque_h2_connect", "masque_lifeline"}
	// or "" (no record). The 3C masque handler's chooseSubmode
	// cascade consults this field as a soft hint: with a
	// recorded value, the handler biases the start rung to it
	// (step 3 of the cascade), running before the per-session
	// UDP probe. The hint is per-network and never leaves the
	// device. See specs/network-memory-v1.md "Phase 3C widening"
	// and specs/masque-ladder-v1.md.
	LastUsedMasqueSubmode string `json:"last_used_masque_submode,omitempty"`
}

// Empty reports whether the snapshot has no observed data. A fresh
// Get() that misses returns (Snapshot{}, false); callers may also
// call Empty() defensively after Get to know whether they should
// treat the network as fresh.
func (s Snapshot) Empty() bool {
	return s.Mode == "" &&
		s.LastSeen.IsZero() &&
		len(s.RouteFamilyStats) == 0 &&
		len(s.RouteHealth) == 0 &&
		len(s.BudgetUsage) == 0 &&
		!s.UDPProbeOK && s.UDPProbeAt.IsZero() &&
		!s.DNSPoisoned &&
		s.LastWinningRendezvousChannel == "" &&
		s.LastUsedMasqueSubmode == ""
}

// MarshalCanonical returns the canonical-JSON encoding (sorted keys
// at every level). The package uses encoding/json with map keys
// already sorted by stdlib; the wrapper exists so future
// non-stdlib serialisers preserve the contract.
func (s Snapshot) MarshalCanonical() ([]byte, error) {
	// encoding/json's map handling sorts keys lexicographically,
	// which is what we want. Round-trip through Marshal to keep
	// the contract explicit.
	return json.Marshal(s)
}

// UnmarshalSnapshot parses a canonical-JSON-encoded Snapshot. Empty
// input returns a zero-value Snapshot, no error.
func UnmarshalSnapshot(b []byte) (Snapshot, error) {
	var s Snapshot
	if len(b) == 0 {
		return s, nil
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return Snapshot{}, err
	}
	return s, nil
}

// SortedFamilies returns the family keys in deterministic order;
// useful for tests and diagnostics rendering.
func (s Snapshot) SortedFamilies() []string {
	out := make([]string, 0, len(s.RouteFamilyStats))
	for k := range s.RouteFamilyStats {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
