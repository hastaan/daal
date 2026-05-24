# Phase 2 — Survivability + iOS (Umbrella)

## Roadmap Coverage

V2 in full: route budgets, mode budgets, the cooldown FSM,
per-network memory, the lifeline-strict local-only mode, the 1000-client success-
metric soak, and iOS bring-up. This document is the umbrella that
ties together the seven V2 sub-phases.

## Goal

Make Daal survivable on a hostile network and shipping on every
platform we promise. By the end of V2 the engine version is
`daal-core 0.5.x+survivability`, the release ABI surface is **37**,
and a 1000-client × 30-day lab soak reproduces the V2 success
metric exactly as written in `daal-roadmap-v3.md`:

> *no route is burned (defined as: classifier-detected and dropped
> by the simulated DPI) faster than the directory's natural
> rotation cadence. The path manager rotates routes correctly,
> enforces budgets, and surfaces understandable failure reasons.
> iOS TestFlight build is live, re-sign-survivable, and
> re-distributable through AltStore.*

The 2G phase doc translates the four sub-clauses of the metric
into the four pass criteria the verifier asserts.

## Sub-phases (locked, scheduler-first order)

1. **2F — In-Engine Auto-Refresh Scheduler** ✅ **DONE**
   `12-phase-2f-scheduler.md` — surface 35, version
   `daal-core 0.5.0+survivability`. V2 entry-criterion
   (in-engine 30-day soak parity) met in lab.

2. **2A — Route Budget Engine** ✅ **DONE** — surface 35 → 36, new
   `engine_set_route_budget`. `13-phase-2a-route-budgets.md`.
   Daal middleware authoritative for byte counting. Per-route
   hourly caps from V2.1. `auth_failed` exempt.

3. **2A-Polish — Per-Session Caps + `modes_allowed` Pre-Positioning**
   (NEXT) — surface stays at **36**.
   `13b-phase-2a-polish.md`. Adds the per-session column of the
   V2.1 cap table (200 MiB / 500 MiB / 2 GiB / unlimited), encodes
   `modes_allowed` per tag (read by 2B), wires `engine_init` as
   the canonical session boundary. No new ABI. Lands as a
   faithfulness fix against the roadmap V2.1 table.

4. **2B — Mode Budgets + V2.3 8-State FSM** — surface stays at
   **36**. `14-phase-2b-mode-budgets-fsm.md`. Mode multipliers
   (lifeline 0.33×, normal 1.0×, bulk unlocks `bulk-capable`
   via the `modes_allowed` filter). The V2.3 canonical 8-state
   FSM at the *application-posture* layer
   (`NoRoute / BootstrapDiscovery / ImportedActive / SharedActive /
   Recovery / Lifeline / OfflineSharing / Experimental`).
   Per-route cooldown reasons keyed strictly to the V0.3
   failure taxonomy.

5. **2C — Per-Network Memory** — surface 36 → **37**, new
   `engine_network_changed`. `15-phase-2c-network-memory.md`.
   `SHA-256(carrier|ssid)[:8]` truncated network ID; SSID is
   hashed at the boundary, never seen again. Encrypted at rest.

6. **2D — Lifeline Mode Strict Variant (Local Policy Only)** —
   surface stays at **37**. `16-phase-2d-lifeline-mode.md`.
   Local-only behavioural changes per roadmap V2.5: 0.33× budget
   factor, stability-biased ranker, `bulk-capable` refused for
   general traffic, background subscription refresh gated to
   expiry-only / user-trigger, permanent banner. **No
   relay-route filter** — the V3.7 server-side relay is
   explicitly NOT shipped at V2. The new mode is named
   `lifeline-strict` at the engine boundary (NOT `lifeline-only`,
   which is a V2.1 budget *tag*); the user-visible UI label may
   read "Lifeline mode" or "Lifeline (local-only)" per the
   roadmap.

7. **2G — V2 Success-Metric Soak** — surface stays at **37**.
   `17-phase-2g-1k-user-soak.md`. 1000 synthetic clients × 30
   simulated days × ~50-route emergency directory × 48 h refresh
   cadence. **Roadmap-canonical pass criterion**: for every route
   in the directory, classifier-detected burn time ≥ directory
   refresh cadence.

8. **2E — iOS Bring-Up** — surface stays at **37**.
   `18-phase-2e-ios.md`. `NEPacketTunnelProvider` +
   `Libbox.xcframework` + boringtun WireGuard sub-engine
   fallback for the ~50 MiB NE memory ceiling + AltStore re-sign +
   TestFlight. Gated on Apple infrastructure access.

## Cross-cutting items to interleave around 2G

- **CC.1** External audit before V2 broad rollout (after 2G green).
- **CC.2** CycloneDX SBOM in CI for every shipping artifact.
- **CC.7** Persian wordlist lexicographer commissioning (lands
  before 2G's UI strings touch real users).
- **CC.8** Five named incident runbooks (publisher-key compromise,
  bootstrap-pointer takedown, mass auth-failure burn, platform-store
  removal, partner-relay shutdown) — all five before V2 ship.

## Carry-over from V1.5

- All four 1.5C-Polish items closed; see
  `11-phase-1-5c-polish.handover.md`.
- 1.5C carry-overs that remain after 2F:
  - Real-bundle directory / IPFS happy-path responses for the soak
    rig (continuing into 2G as part of the burn-event sweep).
  - Pointer-rotation envelope happy-path test through the
    directory channel (lands as part of 2G's scenario sweep).

## Engine version policy

| Phase | Version |
|---|---|
| 2F        | `daal-core 0.5.0+survivability` |
| 2A        | `0.5.0+survivability` (no bump) |
| 2A-Polish | `0.5.0+survivability` (no bump; additive widening only) |
| 2B        | `0.5.0+survivability` (no bump) |
| 2C        | `0.5.0+survivability` (no bump; new ABI is additive) |
| 2D        | `0.5.0+survivability` (no bump) |
| 2G  | `0.5.0+survivability` (no engine change) |
| 2E  | `0.5.0+survivability` (no engine change; iOS packaging only) |

A single `0.5.0+survivability` covers all of V2 because every
addition is append-only. A future regression that requires a
breaking change forces `0.6.x`.

## V2 ship gate

V2 ships when:
1. `nm libdaalcore.so | grep -c '^[0-9a-f]\+ T engine_'` = **37**
   on every release artifact.
2. `cargo test --workspace` (desktop) green.
3. `go test ./...` green across `core`, `bundle`, `soak-driver`,
   `lab-driver`.
4. `soak-driver run-30d --mode in-engine` ALL SCENARIOS PASSED
   (regression).
5. `soak-driver run-burn --clients 1000 --duration 30d
   --directory-refresh 48h --pool-size 50` ALL FOUR
   AGGREGATE METRICS PASSED — primary metric is the
   roadmap-canonical *for-every-route burn interval ≥ directory
   refresh cadence* comparison; secondary is rotation
   correctness; tertiary is budget enforcement; quaternary is
   V0.3 failure-reason coverage.
6. iOS TestFlight build distributed; AltStore re-sign smoke
   passed OR documented waiver.
7. CC.1, CC.2, CC.7, CC.8 closed.

## Handover to Phase 3

Phase 3 (`19-phase-3-ecosystem-integrations.md`) receives a stable
cross-platform engine. New transport families plug into the existing
trust / budget / FSM / diagnostics surfaces. No architectural changes
are expected at the engine seam.
