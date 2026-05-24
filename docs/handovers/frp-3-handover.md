# FRP-3 Handover — Selection Brain

**Phase**: 31 (FRP-3, selection brain)
**Engine line**: `daal-core 0.9.0+v3-share`
**ABI**: 48 (unchanged from FRP-2)
**Status**: SHIPPED across 5 commits.
**Spec**: `specs/selection-v1.md`

This document is the operator-facing summary of what FRP-3 ships, what it
does NOT ship, and what the next phase (FRP-4) inherits.

---

## What shipped

### Code

- **`core/internal/selection/`** (NEW Go-private package, 11 files):
  - `doc.go` — package overview.
  - `explain.go` — locked `Explanation` struct + subtypes (`PickedCandidate`,
    `ShortlistEntry`, `FailureRecord`, `CooldownEntry`, `MemoryHint`).
    `NewExplanation(decisionID, phase)` initialises non-nil empty slices.
    `MarshalCanonical()` is the single canonical encoder.
  - `signals.go` — frozen 9-signal `NetworkSignal` vocabulary.
  - `candidate.go` — `Candidate` projection from `routestore.RouteRow` with
    one-pass `SharedRiskGraphJSON` parse, derived `UDPGated` flag.
  - `shortlist.go` — `Shortlist` with highest-ranked leader selection,
    hard cdn-cohabitation rule, and 7-axis soft diversity scoring (mode
    mixing, public_ip, public_domain, protocol family, sni, probing_risk,
    port).
  - `cooldown.go` — `PropagateCooldown` mode-aware asymmetric propagation;
    asymmetry pin (origin_unhealthy NEVER propagates).
  - `race.go` — `PlanRace` with default 3/400ms anti-burn race plan and
    overrides for lifeline-strict / stateful_reassembly / all-high-probing.
  - `network_memory.go` — `Apply` writer (monotonic, byte-deterministic),
    `LookupHint` (exact match + wildcard fallback), `PublicRiskTagSignature`.
  - `pipeline.go` — `Decide(Input) Output` pure entry point.
  - `opsec_test.go` — `TestSelectionPathHasNoNetwork` enforces Position B.

- **`core/diagnostics/classify.go`** (extended): 5 new categories
  (`DNSBogon`, `UDPCollapsed`, `QUICCollapsed`, `SNIRst`, `OriginUnhealthy`).
  `OriginUnhealthy` is excluded from `IsCensorshipClass` (operator hygiene
  per supplement §13.4).

- **`core/cmd/explanation-fixtures/`** (NEW): deterministic golden generator.
  `cd core && go run ./cmd/explanation-fixtures` regenerates all 7 fixtures
  byte-identically from the same source code.

### Spec

- **`specs/selection-v1.md`**: full spec body.
- **`specs/relaypack-v1.md`**: cross-reference to selector consumer added at
  commit 0.
- **`phases of development/31-phase-frp-3-selection-brain.md`**: 26
  invariants reconciled at commit 0.

### Test corpus

- **`specs/test-vectors/explanation/`** (7 deterministic goldens):
  - `empty-decision.json` (V1.5)
  - `single-vps-pick.json` (V1.5; V1.5 single-VPS dominant case)
  - `single-vps-with-sni.json` (V1.5; SNI diversity axis dominates)
  - `cooldown-propagation.json` (V1.5; TCP RST propagation)
  - `origin-unhealthy-isolated.json` (V1.6; asymmetry pin)
  - `mixed-mode-v16.json` (V1.6; mode-mixing bonus dominates)
  - `udp-collapsed.json` (V1.5; preference-shift signal surfaced)

- **No new RelayPack corpus**: the existing 16 FRP-2 vectors at
  `specs/test-vectors/relaypack/` are the input-side corpus. The 7
  selector-path vectors are bound in `core/internal/selection/corpus_test.go`.

### Tests

`cd core && go test -count=1 ./internal/selection/...` runs **69 cases** across
9 test files, including:

- 7 explanation goldens (round-trip every JSON in `specs/test-vectors/explanation/`).
- 4 signal vocabulary pins.
- 5 candidate projection tests.
- 8 shortlist tests (single-VPS fallbacks, hard cdn rule, V1.5/V1.6 phase
  gating, determinism over 100 trials).
- 13 cooldown tests (every signal × mode combination + signed-graph boundary).
- 5 race-plan tests.
- 9 netmem-writer tests.
- 10 pipeline integration tests, including netmem-influenced leader choice and
  race-policy-visible shortlist sizing.
- 4 property tests with **2200 total trials** (idempotency × 1000,
  cdn-cohabitation × 500, origin-unhealthy-never-propagates × 500,
  Apply monotonicity × 200).
- 7 corpus binding cases.
- 1 asymmetry pair (`TestAsymmetry_OriginVsCDNWide`).
- 1 opsec test (Position B enforced).

`cd core && go test -count=1 ./...` (full sweep): all packages green;
ABI-test 48 symbols.

---

## What did NOT ship (deferred to FRP-4 or later)

- **No new ABI symbols**: invariant 18. FRP-3 locks the Explanation JSON
  shape but does not export it through `core/abi/`. FRP-4a / FRP-6 wire the
  JSON through the existing diagnostics export path without adding a new
  symbol.
- **No bundle generation**: that's `core/share` (FRP-2 SHIPPED), not the
  selector.
- **No probe execution**: the selector consumes probe results; the probe
  framework lives elsewhere (FRP-3-Soak SHIPPED).
- **No race execution**: the selector returns a `RacePlan`; the engine
  scheduler executes it.
- **No cooldown application**: `PropagateCooldown` returns a `CooldownPlan`;
  the caller writes it back to RouteRows.
- **No persistence**: `Apply` is a pure function on `netmem.Snapshot`; the
  caller persists the returned snapshot.

---

## Invariants pinned (26 total)

1–16 inherited from earlier phases (engine_line, ABI=48, no
deterministic-clock skew, etc.).

17. **Pure-function selector**: `Decide(in) Output` reads only `in`.
18. **No new ABI symbols** at FRP-3.
19. **`cdn_fronted` is no-op at V1.5**: the +1000 mode-mixing bonus is
    inert; `Shortlist` never prefers a `cdn_fronted` candidate at V1.5.
20. **Cooldown asymmetry**:
    - `origin_*` cooldowns NEVER propagate to siblings.
    - `cdn:*` cooldowns from `cdn_wide_failure` DO propagate.
    - This is the load-bearing pin: `TestAsymmetry_OriginVsCDNWide`.
21. **Race plan: 3/1/2 + 400 ms stagger** per supplement §15.
22. **`Explanation` struct LOCKED**: JSON wire shape is part of
    `selection-v1.md`; bumping requires `selection-v2.md`.
23. **netmem key shape**:
    `(Family, ExposureMode, PublicRiskTagSignature, Outcome)`.
24. **Position B**: no `net.Dial` / `net/http` / `tls.Dial` in the
    selector tree (`TestSelectionPathHasNoNetwork`).
25. **9-signal vocabulary FROZEN**: extending requires `selection-v2`.
26. **No `cell_scope`**: the selector knows nothing about ISP/MNO
    boundaries; supplement §13.5 explicitly defers cell-scope inference
    to V2+.

---

## Build matrix at exit

```
cd core && go build ./internal/selection/... ./diagnostics/... ./cmd/explanation-fixtures   # green
cd core && go test  -count=1 ./internal/selection/...                                       # 69 tests, all PASS
cd core && go test  -count=1 ./diagnostics/...                                              # PASS
cd core && go test  -count=1 ./...                                                          # full sweep green
```

ABI count: 48 (unchanged).

---

## What FRP-4 inherits

FRP-4a (desktop UI) and FRP-4b (Android UI) inherit:

- The locked `Explanation` JSON schema. They render it; they do NOT mutate
  the field set.
- The 7 deterministic goldens at `specs/test-vectors/explanation/` as the
  cross-language reference fixtures (Tauri TS / Kotlin / Swift).
- The existing diagnostics ABI path as the future carrier for Explanation
  JSON (FRP-3 did NOT add new symbols).

FRP-6 (recipient UX) inherits:

- The `network_signals` vocabulary frozen at 9 entries; localised strings
  in EN/FA must cover all 9.
- The `Explanation.reason` plain-language sentence pattern; the renderer
  may rewrite for locale but must not lose the pick.

V2.5 (lifeline mode) inherits:

- The `Mode` vocabulary (`lifeline` / `lifeline-strict` / `normal` /
  `bulk`) and the `PlanRace` overrides; lifeline-strict is the V2.5
  policy escape hatch.

---

## Operator quick-start

To regenerate the 7 explanation goldens:

```
cd core && go run ./cmd/explanation-fixtures
```

To verify nothing has drifted:

```
cd core && go test -count=1 ./internal/selection/...
```

To run only the asymmetry pin in isolation (the load-bearing test):

```
cd core && go test -count=1 -run TestAsymmetry_OriginVsCDNWide ./internal/selection/...
```

To run only the property tests:

```
cd core && go test -count=1 -run TestProperty_ ./internal/selection/...
```

---

## Co-authors

Authored by Droid (Anthropic) under direct supervision; reviewed at each
commit boundary by the project lead. All commits include the
`Co-authored-by: factory-droid[bot]` footer.
