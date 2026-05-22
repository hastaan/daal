# Phase 31 (FRP-3) — Selection Brain + `Explanation` Struct

**Status:** SHIPPED on 2026-05-03. FRP-4a / FRP-6 gate verdict: **PASS**. Handover at `docs/handovers/frp-3-handover.md`.
**Roadmap line:** *"Selection brain enhancements: mode-aware shortlist + cooldown propagation per §13.4 + per-network-memory key change (`family × exposure_mode × public_risk_tag_signature`). Mode-aware rules referencing `cdn_fronted` are present and tested as no-ops at V1.5; they become live at V1.6."* — `daal-roadmap-v3-supplement-diaspora-helper.md` §21.1
**Supplement target:** v2.3.7.
**Engine version target:** `daal-core 0.9.0+v3-share` **(UNCHANGED — selector logic phase).**
**ABI release surface target:** **48** **(UNCHANGED — selector lives in `core/internal/selection/`, not exported).**
**Maturity:** code phase. Largest single phase in the FRP track. Lands the deterministic local brain.
**Predecessor:** Phase 30 (FRP-2) — must produce the test-vector corpus FRP-3 binds against.
**Successor:** Phase 32 (FRP-4a) and Phase 35 (FRP-6) — both consume the locked `Explanation` struct.

## 1. Strategic frame (verbatim from the supplement)

> **§13 Client Selection Policy — the local brain.** The selector is what turns RelayPack breadth into actual reliability. Deterministic local policy. No ML. No phone-home. Aligned with the existing `family.go`, `fsm.go`, `network.go`, `auto_promotion.go`, and `classify.go` machinery. The selection pipeline runs probe → filter → diversity-shortlist → race → classify → cool-down-propagate → remember → explain on every network change.
>
> **§15.1 The four anti-burn rules.** Never race the entire shortlist in parallel; never repeatedly retry a blocked family; never use high-scarcity paths for bulk traffic; never expose all candidates as equal.

FRP-3's job is to land the deterministic local brain end-to-end: mode-aware diversity-shortlist (§13.1, soft-diversity rule from v2.3.5), §13.3 selector rules, §13.4 cooldown propagation table (with the asymmetry between `public_risk_tags` and `origin_risk_tags`), the per-network-memory key change to `family × exposure_mode × public_risk_tag_signature`, anti-burn race policy (§15), and the locked `Explanation` struct that FRP-6 binds UI to. **`cdn_fronted` rules are wired but tested as no-ops at V1.5** (no `cdn_fronted` candidates yet); they become live at FRP-8.

## 2. Locked answers

| Question | Locked answer |
|---|---|
| Selector code location | **`core/internal/selection/`** (new Go-private package within the `daal/core` module per `core/go.mod`). Subfiles: `pipeline.go`, `shortlist.go`, `cooldown.go`, `signals.go`, `candidate.go`, `explain.go`, `network_memory.go`, `race.go` (consumes FRP-2's extended `core/netmem/` entry-value shape — `Snapshot.RouteFamilyStats[*].ByRelayPack` — NOT a parallel SQLite table). |
| Existing files to integrate with | `core/pathmanager/family.go`, `core/pathmanager/fsm.go` (pkg name is `pathmanager`, not `path-manager`), `core/netmem/store.go`, `core/netmem/snapshot.go`, `core/abi/auto_promotion.go`, `core/diagnostics/classify.go`. (FRP-0 audit confirms paths.) |
| Diversity rule | Soft per supplement v2.3.5 §13.1: hard prohibition only for `cdn:*` siblings; soft preference for `public_ip:*` and `public_domain:*`; secondary axes (protocol, SNI, `probing_risk_class`, port) when single-VPS RelayPack. Mode mixing always preferred when both modes exist. |
| Cooldown propagation table | Per supplement §13.4 verbatim. Asymmetric: `public_risk_tag` failure propagates to siblings sharing the tag; `origin_*` failure on `cdn_fronted` does NOT propagate to public surfaces (operator hygiene). |
| Default shortlist size | **3** candidates (per §15.2). **1** in lifeline-strict mode. **2** when active-probe shape detected. |
| Race head-start | **400 ms** between leader and runner-up. Third only if both fail. (Per §15.1 rule 1.) |
| Network memory key | `(network_hash, family, exposure_mode, public_risk_tag_signature, outcome)`. Persists in `core/netmem/`'s extended entry-value shape (FRP-2 widens; no separate SQLite table). |
| `Explanation` struct visibility | Public Go struct in `core/internal/selection/explain.go`. **FRP-3 does NOT modify `core/abi/`.** The struct is a locked JSON schema. FRP-4a / FRP-6 (engine integration + UI) route the schema through the EXISTING `engine_export_diagnostics` symbol via the diagnostics export path — no new ABI symbol added at any phase. |
| `cdn_fronted` rule wiring at V1.5 | Rules present but always inert (no `cdn_fronted` candidate exists in V1.5 RelayPacks; RP004 in FRP-1 rejects them). Tests assert rules are no-ops by running them against `cdn_fronted` candidate fixtures and verifying behavior matches the spec. |
| Network signal vocabulary | Per supplement §13.3 + §13.4: `dns_bogon_detected`, `protocol_whitelist_mode`, `udp_collapsed`, `quic_collapsed`, `sni_rst`, `cdn_hostname_blocked`, `cdn_wide_failure`, `origin_unhealthy`, `stateful_reassembly_present`. Locked at FRP-3; consumers added in later phases (e.g. `cdn_*` signals fully consumed at FRP-8). |
| Failure classification | `core/diagnostics/classify.go` extended with **5** new categories (`DNSBogon`, `UDPCollapsed`, `QUICCollapsed`, `SNIRst`, `OriginUnhealthy`) — those that arise from error-string classification only. The remaining 4 of the 9 v2.3.4 signals (`ProtocolWhitelistMode`, `CDNHostnameBlocked`, `CDNWideFailure`, `StatefulReassemblyPresent`) are probe-derived state aggregations and live exclusively in the selector-owned `core/internal/selection/signals.go::NetworkSignal` vocabulary — they are NOT added to `diagnostics.Category`. Existing taxonomy preserved. `OriginUnhealthy` is operator-hygiene and excluded from `IsCensorshipClass`. |
| Network memory writer semantics | FRP-3 is the writer of `core/netmem/Snapshot.RouteFamilyStats[*].ByRelayPack` (FRP-2 schema). Determinism contract: same input Snapshot + same outcome → same output Snapshot bytes. Repeated outcomes monotonically increment counters (NOT a byte-identical re-write of the entry). Outer `FamilyStats.Successes`/`Failures` counters also incremented for legacy compat. |
| Telemetry | Zero. No counters. No event sinks. The `Explanation` struct is locked here and later routed through the existing diagnostics export (already a no-telemetry surface per Position B). Per-network memory is local-only (per supplement §13.2 "Telemetry-free"). |
| Determinism | The selector is a pure function of (probe results, RelayPack candidates, network memory state, current time) → (shortlist, race plan, decision). Property-tested. |

## 3. Locked invariants

Tracks invariants 1–16 inherited. Phase-specific:

17. **Pure-function selector.** Inputs in, decision out; no hidden state, no global counters, no time-since-process-start dependence (clock is an injected parameter).
18. **No new release symbols.** ABI count stays 48; selector lives in `internal/`.
19. **`cdn_fronted` rules wired at V1.5.** Tested as no-ops against `cdn_fronted` fixtures because no candidate of that mode exists yet at V1.5; lifted automatically at FRP-8.
20. **Cooldown asymmetry preserved.** `origin_*` failures on `cdn_fronted` candidates DO NOT propagate to `public_risk_tags` of siblings sharing the same origin. Verified by an explicit test pair.
21. **Race policy enforced.** Default 3-candidate shortlist, 400 ms stagger, sequential in lifeline-strict, 2-shortlist on active-probe shape. Verified by property tests.
22. **`Explanation` struct is the locked UI contract.** Fields enumerated in §5 below; FRP-6 binds against this exact shape.
23. **Per-network memory key shape locked.** `family × exposure_mode × public_risk_tag_signature`. Lessons generalize across deployments per supplement §13.1 step 7.
24. **Position B preserved.** No telemetry; no probe of any external endpoint owned by the project; no inference call to any service. Verified by `core/internal/selection/opsec_test.go`.
25. **Network signal vocabulary frozen at FRP-3.** Adding a new signal in a later phase is allowed; renaming an existing one is a breaking change requiring a `spec_version` discussion. The 9 signals locked here.
26. **No reliance on `cell_scope`.** Cell-aware selection is FRP-11; the selector treats `CellScope == nil` as the V1.5 default and never reads `cell_scope.cell_id` in pipeline logic.

## 4. Sub-task breakdown

| #  | Task |
|----|------|
| 0  | Replace any prior FRP-3 stub with this locked spec at `phases of development/31-phase-frp-3-selection-brain.md`. |
| 1  | Read inputs end-to-end: supplement §13.1, §13.2, §13.3, §13.4, §13.5, §13.6, §15; existing `core/pathmanager/family.go`, `core/pathmanager/fsm.go`, `core/netmem/store.go`, `core/netmem/snapshot.go`, `core/diagnostics/classify.go`; FRP-2 handover (§"Test-vector corpus" for the contract). |
| 2  | Author `core/internal/selection/explain.go` with the locked `Explanation` struct (§5 below). |
| 3  | Author `core/internal/selection/shortlist.go`. ~120 lines per supplement §13.5 hint ("new ~80-line function"; with soft-diversity logic from v2.3.5 §13.1 it grows to ~120). Implements step 3 of the pipeline (diversity-shortlist + secondary axes + mode mixing). |
| 4  | Author `core/internal/selection/cooldown.go`. ~80 lines per supplement §13.5 ("new ~50-line function"; with asymmetry-aware propagation it grows to ~80). Implements step 6 of the pipeline (mode-aware cooldown propagation per §13.4 table). |
| 5  | Extend `core/diagnostics/classify.go` with the 5 error-string-backed categories (`DNSBogon`, `UDPCollapsed`, `QUICCollapsed`, `SNIRst`, `OriginUnhealthy`). Keep the remaining 4 probe-derived signals selector-owned in `core/internal/selection/signals.go`. Preserve existing classifications. |
| 6  | Author `core/internal/selection/network_memory.go`. Reads `core/netmem/`'s extended entry shape (FRP-2's widening); writes new entries; computes `public_risk_tag_signature` deterministically (canonical-sort + comma-join). |
| 7  | Author `core/internal/selection/pipeline.go`. ~150 lines. Orchestrates the pre-race decision path: project → rank with per-network memory → filter/shortlist → race plan → explain. Post-race helpers (`PropagateCooldown`, `Apply`) remain pure functions the caller invokes after observing an outcome. |
| 8  | Author `core/internal/selection/race.go`. ~60 lines. Anti-burn race policy: default 3, lifeline-strict 1, probe-shape 2; 400 ms stagger; third only if first two fail. |
| 9  | Test corpus binds: write `core/internal/selection/pipeline_test.go` driving FRP-2's vectors at `specs/test-vectors/relaypack/` end-to-end. Each vector exercises a different selector path; expected `Explanation` outputs locked. |
| 10 | Property tests: `core/internal/selection/property_test.go` using `testing/quick` or hand-rolled generators. Properties: determinism (same inputs ⇒ same decision), idempotence (selector run twice in row ⇒ same decision), shortlist-size bounds, no-self-cooldown (a candidate's failure cools its own tags but doesn't repeatedly increase its own cooldown). |
| 11 | Asymmetry test pair: explicit test that an `origin_*` failure on a `cdn_fronted` candidate does NOT propagate to siblings sharing the same `origin_*`; corresponding test that a `cdn:cloudflare` failure DOES propagate to all siblings carrying that tag. |
| 12 | Final regression sweep: `cd core && go build ./... && go test ./internal/selection/... ./pathmanager/... ./netmem/... ./diagnostics/...`; `cd bundle/go && go build ./... && go test ./bundle/...` (regression-only — no FRP-3 changes there); `nm` returns 48; `Explanation` shape verified by FRP-6's planned UI test stub (a tiny test in `core/internal/selection/explain_test.go` asserting the struct's JSON shape against a golden file at `specs/test-vectors/explanation/`); FRP-4a / FRP-6 gate verdict; handover written. |

## 5. `Explanation` struct (locked, the UI contract)

```go
package selection

// Explanation is the UI-binding contract. FRP-6 (recipient UX) renders this
// struct verbatim in EN/FA. Field names and JSON tags are locked.
type Explanation struct {
    // Picked candidate (route_id) and the reason in one sentence.
    Pick           PickedCandidate `json:"pick"`

    // Shortlist actually raced (in race order).
    Shortlist      []ShortlistEntry `json:"shortlist"`

    // Failures classified during this decision.
    Failures       []FailureRecord  `json:"failures"`

    // Cooldowns currently active that influenced this decision.
    ActiveCooldowns []CooldownEntry `json:"active_cooldowns"`

    // Network signals observed during the probe.
    NetworkSignals  []string        `json:"network_signals"`

    // Network-memory hint that influenced shortlisting (if any).
    MemoryHint     *MemoryHint      `json:"memory_hint,omitempty"`

    // Plain-language reason. Single sentence. Localizable. No identifiers.
    // Example: "Used REALITY because UDP is blocked on this network."
    Reason         string          `json:"reason"`

    // Decision identifier (deterministic; for log correlation).
    DecisionID     string          `json:"decision_id"`

    // Phase in which the decision was made (V15 | V16 | V2 | post-V2).
    Phase          string          `json:"phase"`
}

type PickedCandidate struct {
    RouteID        string `json:"route_id"`
    Family         string `json:"family"`
    ExposureMode   string `json:"exposure_mode"`
    FamilyClass    string `json:"family_class"`
    ProbingRisk    string `json:"probing_risk_class"`
}

type ShortlistEntry struct {
    RouteID        string `json:"route_id"`
    Position       int    `json:"position"`           // 0 = leader; 1 = runner-up; 2 = third
    StartedAtMs    int    `json:"started_at_ms"`      // ms after pipeline start
    Outcome        string `json:"outcome"`            // success | failed | not_started
}

type FailureRecord struct {
    RouteID        string `json:"route_id"`
    Classification string `json:"classification"`     // sni_rst | udp_collapsed | origin_unhealthy | ...
    Tag            string `json:"tag,omitempty"`      // tag attributed (e.g. public_ip:5.75.x.x)
}

type CooldownEntry struct {
    Tag            string `json:"tag"`
    ExpiresAtUnix  int64  `json:"expires_at_unix"`
    Reason         string `json:"reason"`             // network signal that started it
}

type MemoryHint struct {
    Signature      string `json:"signature"`          // family|exposure_mode|public_risk_tag_signature
    LastOutcome    string `json:"last_outcome"`
    LastSeenUnix   int64  `json:"last_seen_unix"`
}
```

## 6. Cooldown propagation table (locked, mirrors supplement §13.4)

| Signal | Mode | Cool down | Propagate to siblings sharing... | UI hint |
|---|---|---|---|---|
| TCP RST on connect | direct_vps | `public_ip:*` (5m) + `public_asn:*` (30m) + `public_provider:*` (30m) | `public_ip` (common in V1.5; one event) and `public_asn` / `public_provider` | "L3 floating-IP swap recommended" |
| `sni_rst` | direct_vps | `sni:*` (30m) | exact `sni:*` | "L2 change SNI/dest" |
| `sni_rst` | cdn_fronted | `sni:*`, `host:*`, `public_domain:*` (30m); NOT `cdn:*` | `public_domain:*` | "Hostname rotation" |
| `path_pattern_blocked` | cdn_fronted | `ws_path_fp:*` (30m) | exact `ws_path_fp:*` | "Public-path rotation" |
| `origin_unhealthy` (522/525/526) | cdn_fronted | `origin_*` only | **none** | "Origin repair (not censorship)" |
| `cdn_wide_failure` | cdn_fronted | `cdn:cloudflare` (60m) | every sibling carrying `cdn:cloudflare` | "Cloudflare blocked; using direct routes" |
| `udp_collapsed` | any | all `udp_gated:true` (30m) | every `udp_gated:true` | "Skip Hysteria2/TUIC/WG until network changes" |
| `quic_collapsed` | any | demote QUIC-only (preference shift, not cooldown) | n/a | "Prefer TCP-based siblings" |
| `protocol_whitelist_mode` | any | demote UDP regardless of UDP probe | n/a | "Prefer HTTPS-shaped TCP siblings" |
| `stateful_reassembly_present` | any | `probing_risk_class:high` (60m) | n/a | "Prefer low-probing-risk routes" |

## 7. Architectural detail — the soft-diversity algorithm

Per supplement v2.3.5 §13.1:

1. Compute the candidate set after step 2 (filter).
2. Pick the highest-ranked candidate as the leader.
3. For each subsequent slot (up to shortlist size):
   - **Hard rule**: skip any candidate sharing a `cdn:*` tag with any candidate already on the shortlist.
   - **Soft rule (preference)**: prefer a candidate that does NOT share `public_ip:*` or `public_domain:*` with any candidate already on the shortlist.
   - **Fallback rule**: when the only remaining candidates share `public_ip:*` (single-VPS V1.5 default), select using secondary axes — protocol family (`vless-reality` vs `websocket-tls` vs `naive` vs UDP siblings), inner SNI (`sni:`), `probing_risk_class`, port. Maximize secondary-axis distance.
   - **Mode mixing** (V1.6+): always prefer mixing `direct_vps` and `cdn_fronted` candidates when both are available.
4. Cap shortlist at the size determined by `race.go` (3 / 1 / 2).

Single-VPS V1.5 worked example: a RelayPack with [vless-reality, websocket-tls, naive, hysteria2] all sharing `public_ip:5.75.x.x` produces a shortlist of [vless-reality (leader, low probing-risk), websocket-tls (runner-up, different protocol family), hysteria2 (third, UDP — different `public_port`)]. `naive` is skipped not because of risk-tag overlap (the soft rule allows it) but because the shortlist size cap is 3; the 4th slot is unused. A subsequent `public_ip:5.75.x.x` failure is treated as one correlated event by `cooldown.go` (cools the whole tag once; doesn't fire 3 separate cooldowns).

## 8. Network signals — wiring in diagnostics + selector

Only the 5 error-string-backed signals are added to the existing classify taxonomy. The remaining 4 are selector-owned probe aggregations in `core/internal/selection/signals.go`. Each signal has:
- A detection rule (e.g. `dns_bogon_detected`: DNS A/AAAA returns RFC-1918, loopback, or 0.0.0.0 for a known-popular host).
- A consumer (e.g. `udp_collapsed` → `cooldown.go` cools `udp_gated:true` for 30 min).
- A test fixture in either `core/diagnostics/classify_test.go` (classifier-backed) or `core/internal/selection/signals_test.go` / selector tests (selector-owned).

## 9. Build matrix at FRP-3 exit

```
$ cd core && gofmt -l ./...                                    # no output
$ cd core && go build ./...                                    # green
$ cd core && go test ./...                                     # green
$ cd core && go test -count=1 -race ./internal/selection/...   # ≥40 new tests; race detector clean
$ cd core && go test -count=1 -run TestVectors ./internal/selection/...   # ≥15 RelayPack vectors green
$ nm /tmp/libdaalcore.so | grep ' T engine_' | wc -l         # 48 (UNCHANGED)
$ cd core && go test -count=1 -run TestPropertyDeterminism ./internal/selection/...  # green
$ cd core && go test -count=1 -run TestAsymmetry ./internal/selection/...  # pair green
$ cd core && go test -count=1 -run TestExplanationGoldenFile ./internal/selection/...   # specs/test-vectors/explanation/*.json match
```

## 10. Spec deliverables

**1 NEW:**
- `specs/selection-v1.md` — formal selector spec. ~10 pages: pipeline diagram, rule library (verbatim from §13.3), cooldown propagation table (§13.4), shortlist algorithm (§5 above), `Explanation` struct (§5 above), determinism guarantees, network-signal vocabulary.

**1 AMENDED:**
- `specs/relaypack-v1.md` — gains a §"Selector consumer" cross-reference pointing at `specs/selection-v1.md`.

**Test-vector seeds:**
- `specs/test-vectors/explanation/*.json` — golden files for `Explanation` struct shape, one per selector code path that reaches the selector. Validator-rejection RelayPack vectors do not need empty Explanation goldens. Used by FRP-6 when the UI is implemented.

## 11. Out of scope (deferred)

- UI rendering of `Explanation` — **FRP-6.**
- `cdn_fronted` candidates exercised live (rules tested as no-ops here) — **FRP-8.**
- `cell_scope` consumption — **FRP-11.**
- Modifier consumption (FakeSNI etc.) — **FRP-12.**
- Real-DPI burn classifier (mentioned for V4 in 3-Soak handover) — V4.
- Auto-promotion threshold tuning — V4 per 3-Soak comparison memo.

## 12. Handover requirements

The FRP-3 handover must contain:

1. Status: SHIPPED. Date.
2. New file list at `core/internal/selection/`.
3. Test counts: unit tests, property tests, vector-driven tests, asymmetry tests.
4. `nm` count = 48 unchanged.
5. `Explanation` struct golden-file count.
6. `specs/selection-v1.md` page count.
7. Test-vector pass list (FRP-2 corpus + new explanation vectors).
8. FRP-4a + FRP-6 gate verdict.
9. Open follow-ups: any field FRP-6 will need that `Explanation` struct missed; any selector hook the deploy phase (FRP-4a) will need.

## 13. Track ordering rationale

FRP-3 is the largest phase in the V1.5 portion of the track because the selector is the brain: every later phase either produces inputs to it (FRP-4a/4b/5/8) or consumes its outputs (FRP-6). Locking the `Explanation` struct here, before any UI exists, forces the UI to be a thin renderer rather than an interpretation layer. The `cdn_fronted`-rules-tested-as-no-ops discipline at V1.5 means FRP-8 lifts the validator restriction (RP004) and the rules go live without any selector code change — the wiring is paid for once.

End — locked at FRP-track planning. Next: FRP-4a (publisher deploy core).
