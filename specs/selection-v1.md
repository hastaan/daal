# Selection Brain v1

## Status

LOCKED at FRP-3 (Phase 31). This document is the formal contract for the
Daal deterministic local-brain selector (`core/internal/selection/`). It
is the consumer of the RelayPack schema (`specs/relaypack-v1.md`) and the
writer of the per-network memory (`specs/network-memory-v1.md`, FRP-2
widening).

ABI: zero new symbols. FRP-3 locks the `Explanation` JSON wire format
here but does not modify `core/abi`; FRP-4a / FRP-6 route it through the
existing diagnostics export path.

Engine line: `daal-core 0.9.0+v3-share`, ABI = 48.

---

## §1. Scope and relation to RelayPack + netmem

The selector is **the brain**. Given:

- a set of `RouteRow` instances (from `core/routestore`),
- a `netmem.Snapshot` (from `core/netmem`),
- a list of active `NetworkSignal`s (from probes),
- a user-selected `Mode` and the current spec `Phase`,
- a wall-clock `time.Time` (injected),

it produces:

- a `*Candidate` pick (or nil if no candidates),
- a `[]Candidate` shortlist (≤3),
- a `RacePlan` (number of racemates, stagger ms, sequential bit),
- an `*Explanation` (locked JSON wire shape, see §8).

The selector is a **pure function** (§9). It never opens a network
connection (§10). It does not write to disk. The caller is responsible
for executing the race plan, observing the outcome, and invoking
`PropagateCooldown` + `Apply` after the fact.

Relationship to other specs:

- `specs/relaypack-v1.md`: defines the bundle-side schema. The 9 RelayPack
  fields on `RouteRow` (`exposure_mode`, `family_class`, `probing_risk_class`,
  `public_risk_tags`, `origin_risk_tags`, `modifiers_json`, `relaypack_id`,
  `freshness_url`, `shared_risk_graph_json`) are projected into `Candidate`
  by `ProjectFromRouteRow` (one parse per row).
- `specs/network-memory-v1.md`: defines the netmem snapshot shape. The
  selector is the *writer* of `FamilyStats.ByRelayPack`. The on-wire shape
  is FRP-2; the writer semantics (sort key, dedup, monotonic counters)
  are pinned here.
- `specs/sbp-v1.md`: signed-bundle wire format (consumed indirectly).

---

## §2. Pipeline

```
probe results -+
RouteRows -----+--> ProjectFromRouteRow --> []Candidate
NetMem snap --+                              |
              |                              v
              |                         Shortlist (≤3, soft diversity + hard cdn rule)
              |                              |
              |                              v
              |                          PlanRace
              |                              |
              |                              v
              +------------------------> Decide() builds *Explanation
                                              |
                                              v
                                          Output{Pick, Shortlist, Race, Explanation}

[caller executes race; collects outcome]

failed candidate +                       PropagateCooldown(failed, signal, peers, now)
signal           +-->                          --> CooldownPlan{OnCandidate, OnSiblings}
peers            +
                                         Apply(snap, MemoryWrite{...}) --> snap'
```

Steps:

1. **Project**: `ProjectFromRouteRow` reads 9 RelayPack columns + parses
   `shared_risk_graph_json` once into `[]SharedRiskEdge`.
2. **Rank + shortlist**: candidates receive a deterministic `RankScore`
   from probing risk, active signals, and per-network memory. The race
   policy chooses the shortlist size (1/2/3), then
   `Shortlist(cands, size, phase)` applies the hard cdn-cohabitation rule
   and the soft diversity scoring (§5).
3. **Race plan**: `PlanRace(shortlist, mode, signals)` chooses 1/2/3 racemates
   and 0 or 400 ms stagger (§6).
4. **Explanation**: `Decide` populates `*Explanation` with pick, staggered
   shortlist positions, network signals (canonicalised + sorted), memory
   hint for the leader, and a stable single-sentence reason.
5. **Caller race**: the engine races the shortlist; on outcome it emits:
   - `PropagateCooldown(failed, signal, peers, now)` (§4) producing the
     mode-aware cooldown plan,
   - `Apply(snap, MemoryWrite{...})` (§7-write) updating the network memory
     monotonically and deterministically.

---

## §3. Rule library

Verbatim from supplement §13.3, normalised to the 9-signal vocabulary
(§7).

| Signal                       | Meaning                                                     | Source                                         |
|------------------------------|-------------------------------------------------------------|------------------------------------------------|
| dns_bogon_detected           | DNS resolver returns a bogon / RFC1918 / loopback for an external host | `diagnostics.Category.DNSBogon`               |
| udp_collapsed                | All UDP probes time out or are reset                        | `diagnostics.Category.UDPCollapsed`           |
| quic_collapsed               | QUIC handshakes fail across multiple endpoints              | `diagnostics.Category.QUICCollapsed`          |
| sni_rst                      | TLS handshake aborted on ClientHello SNI                    | `diagnostics.Category.SNIRst`                  |
| origin_unhealthy             | CDN-fronted origin returns 5xx / RST / timeouts             | `diagnostics.Category.OriginUnhealthy`        |
| protocol_whitelist_mode       | Probe set indicates only known-good protocols pass          | selector-only aggregation                      |
| cdn_hostname_blocked         | CDN edge serves but specific hostname is blocked            | selector-only aggregation                      |
| cdn_wide_failure             | All hostnames on a given CDN fail                           | selector-only aggregation                      |
| stateful_reassembly_present  | Active probes consistent with a stateful middlebox          | selector-only aggregation                      |

`origin_unhealthy` is **explicitly excluded** from `IsCensorshipClass`
(operator hygiene, not censorship — supplement §13.4).

---

## §4. Cooldown propagation table

Mode-aware, asymmetric. The "failing candidate" column lists what is cooled
on the candidate that just failed; the "siblings" column lists what is
propagated to other candidates in the same RelayPack bundle that share a
relevant tag.

| Signal                       | Mode         | Failing-candidate cooldowns                                    | Sibling propagation                              |
|------------------------------|--------------|----------------------------------------------------------------|--------------------------------------------------|
| (implicit) tcp_rst           | direct_vps   | public_ip:* 5min · public_asn:* 30min · public_provider:* 30min | public_ip:* + public_asn:* + public_provider:* (per-prefix durations) |
| sni_rst                      | direct_vps   | sni:* 30min                                                    | sni:* 30min                                      |
| sni_rst                      | cdn_fronted  | sni:* + public_domain:* + host:* (each 30min, NOT cdn:*)        | public_domain:* 30min                            |
| cdn_hostname_blocked         | cdn_fronted  | public_domain:* + host:* + sni:* (each 30min, NOT cdn:*)        | public_domain:* 30min                            |
| **origin_unhealthy**         | cdn_fronted  | **only origin_* tags 60min**                                   | **none — asymmetry pin (invariant 20)**          |
| cdn_wide_failure             | cdn_fronted  | cdn:* 60min                                                    | cdn:* 60min (every sibling on the same CDN)      |
| udp_collapsed                | any          | udp_gated:true 30min (if candidate is UDP-gated)               | udp_gated:true 30min (every UDP-gated sibling)   |
| dns_bogon_detected           | any          | (preference shift; no cooldowns)                               | n/a                                              |
| quic_collapsed               | any          | (preference shift; no cooldowns)                               | n/a                                              |
| protocol_whitelist_mode      | any          | (preference shift; no cooldowns)                               | n/a                                              |
| stateful_reassembly_present  | any          | (preference shift; no cooldowns)                               | n/a                                              |

**The asymmetry pin (invariant 20)**: `origin_unhealthy` is operator
hygiene. If propagation fired, a single unhealthy origin would knock out
the entire CDN edge surface for 60 minutes. The `TestAsymmetry_OriginVsCDNWide`
test pair locks this contract.

`cdn:*` is **never** cooled on `sni_rst` or `cdn_hostname_blocked`. The CDN
edge itself is not the failing surface; the hostname is.

---

## §5. Soft-diversity shortlisting algorithm

`Shortlist(cands, size, phase) []Candidate` selects up to `size` candidates
from `cands` such that:

- **Hard rule**: no two candidates share any `cdn:*` public-risk-tag
  (supplement v2.3.5 §13.1).
- **Soft preferences**, in descending weight:
  1. (V1.6+) Mode mixing: prefer adding a `cdn_fronted` candidate when
     `direct_vps` is already picked (and vice-versa). Worth +1000 in the
     scorer.
  2. `public_ip:*` diversity: +500.
  3. `public_domain:*` diversity: +250.
  4. Protocol family diversity: +100.
  5. `sni:*` diversity: +60.
  6. `probing_risk_class` diversity: +30.
  7. `public_port:*` diversity: +10.
- **Tie-break**: `RouteID` lex order, byte-stable across runs.

V1.5 path: the +1000 mode-mixing bonus is **inert** (invariant 19); only
soft preferences 2–7 contribute. This is the dominant single-VPS V1.5
case where all candidates share `public_ip:*` and the shortlist is driven
by protocol family / SNI / probing risk class.

The leader (`shortlist[0]`) is the highest-ranked eligible candidate.
`RouteID` is only the deterministic tie-break. Successive picks maximise
candidate rank plus diversity score against the already-picked set.

---

## §6. Race policy

`PlanRace(shortlist, mode, signals) RacePlan` returns:

- `Racemates`: number of candidates raced in parallel.
- `StaggerMs`: ms between racemate starts (0 when sequential).
- `Sequential`: true when racing is disallowed.

Defaults and overrides:

| Condition                                            | Racemates | StaggerMs | Sequential |
|------------------------------------------------------|-----------|-----------|-----------|
| `mode == lifeline-strict`                            | 1         | 0         | true      |
| every shortlist member has `probing_risk_class:high`  | 1         | 0         | true      |
| `signals` contains `stateful_reassembly_present`      | min(2, len(shortlist)) | 400 | false |
| default                                              | 3 (capped to len(shortlist)) | 400 | false |

Default 3/400ms is the supplement §15 "anti-burn race plan": probe up to
three candidates with 400 ms gaps so a fast leader returns before the
slower probes start, minimising tag exposure.

---

## §7. Network signal vocabulary

Frozen at FRP-3. 9 signals total (invariant 25):

```go
const (
    SignalDNSBogonDetected          NetworkSignal = "dns_bogon_detected"
    SignalUDPCollapsed              NetworkSignal = "udp_collapsed"
    SignalQUICCollapsed             NetworkSignal = "quic_collapsed"
    SignalSNIRst                    NetworkSignal = "sni_rst"
    SignalOriginUnhealthy           NetworkSignal = "origin_unhealthy"
    SignalProtocolWhitelistMode     NetworkSignal = "protocol_whitelist_mode"
    SignalCDNHostnameBlocked        NetworkSignal = "cdn_hostname_blocked"
    SignalCDNWideFailure            NetworkSignal = "cdn_wide_failure"
    SignalStatefulReassemblyPresent NetworkSignal = "stateful_reassembly_present"
)
```

The first 5 mirror `diagnostics.Category` (set by `Classify` on raw error
strings). The other 4 are aggregations the selector observes from probe
results and never appear as `diagnostics.Category` (invariant 26).

`AllSignals()` returns the 9 in canonical sort order; `IsKnownSignal`
rejects anything outside the set.

### Per-network memory writes

`Apply(snap, write) Snapshot`:

- always increments outer `FamilyStats.Successes` / `Failures`,
- finds OR appends a `RelayPackStat` keyed by
  `(Family, ExposureMode, PublicRiskTagSignature, Outcome)`,
- sorts `ByRelayPack` lexicographically on the canonical key tuple
  for byte-stable serialisation,
- never decrements counters (monotonic),
- same input + same `MemoryWrite` produces byte-identical output bytes.

`PublicRiskTagSignature(tags)` is the canonical-sorted-comma-joined string
of the candidate's `public_risk_tags`; it is the second-half of the netmem
key.

---

## §8. The `Explanation` struct

Locked at FRP-3. JSON field names and order are part of the spec_version=1
contract. Bumping requires a new `selection-v2.md`.

```json
{
  "pick": {
    "route_id": "...",
    "family": "...",
    "exposure_mode": "...",
    "family_class": "...",
    "probing_risk_class": "..."
  },
  "shortlist": [
    {"route_id": "...", "position": 0, "started_at_ms": 0,   "outcome": "success"},
    {"route_id": "...", "position": 1, "started_at_ms": 400, "outcome": "not_started"},
    {"route_id": "...", "position": 2, "started_at_ms": 800, "outcome": "not_started"}
  ],
  "failures": [
    {"route_id": "...", "classification": "tcp_reset", "tag": "public_ip:..."}
  ],
  "active_cooldowns": [
    {"tag": "...", "expires_at_unix": 1767225900, "reason": "..."}
  ],
  "network_signals": ["dns_bogon_detected", "udp_collapsed"],
  "memory_hint": {
    "signature": "public_ip:...,public_port:tcp443",
    "last_outcome": "success",
    "last_seen_unix": 1767225600
  },
  "reason": "Used vless-reality on the leader VPS; secondary protocol siblings staggered.",
  "decision_id": "...",
  "phase": "V1.5"
}
```

Slice fields (`shortlist`, `failures`, `active_cooldowns`, `network_signals`)
are pre-allocated to non-nil empty slices so the wire shape never includes
`null`. `memory_hint` is `omitempty` (`*MemoryHint` nil when no memory was
consulted).

FRP-3 does not export this struct through `core/abi`. FRP-4a / FRP-6 wire
the locked JSON through the existing diagnostics export path.

---

## §9. Determinism guarantees

- Pure function: `Decide(in)` calls only stdlib, `core/netmem` reads, and
  the selector's own pure functions.
- No clock reads: the wall-clock `time.Time` is supplied via `Input.Now`
  and propagated to `Apply` / `PropagateCooldown` by the caller.
- No goroutines, no channels, no `sync.Mutex`.
- Sort order: every slice the selector produces is sorted on a canonical
  key (`RouteID`, then secondary axes). `sort.SliceStable` is used so
  reorderings between runs are impossible.
- Property tests:
  - Idempotency (1000 trials)
  - cdn-cohabitation hard rule (500 trials, both phases)
  - origin_unhealthy never propagates (500 trials, random topologies)
  - Apply monotonicity (200 trials, random write sequences)

---

## §10. Position B contract

The selector is read-only against the network. Invariant 24 is enforced
by `TestSelectionPathHasNoNetwork` which scans every non-test `.go` file
in `core/internal/selection/` for forbidden tokens:

- `"net/http"`
- `net.Dial(`
- `net.DialTimeout(`
- `http.Client`
- `http.Get(`
- `http.Post(`
- `http.NewRequest`
- `tls.Dial(`

Comments are stripped before scanning so doc strings discussing what
the selector does *not* do don't trigger false positives.

There is no telemetry. There is no project-owned probe. There is no
inference from network state to provider identity. The selector reads
RouteRows and writes a `MemoryWrite`; that is the entire surface.

---

## §11. Cross-references

- `specs/relaypack-v1.md` — RelayPack schema producer (FRP-1).
- `specs/network-memory-v1.md` — per-network memory store (FRP-2 widening).
- `specs/sbp-v1.md` — base bundle format.
- `phases of development/31-phase-frp-3-selection-brain.md` — phase doc with 26 invariants.
- `daal-roadmap-v3-supplement-diaspora-helper.md` §13, §15 — design rationale.
- `core/internal/selection/` — implementation.
- `specs/test-vectors/explanation/` — 7 deterministic golden fixtures (regenerated by `core/cmd/explanation-fixtures`).
