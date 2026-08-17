# Daal Phases of Development

This folder turns `daal-roadmap-v3.md` into implementation phases with clear goals, scope, exit criteria, and handover expectations.

## Regular Practice

At the start of every phase and every major implementation session:

1. Re-read `daal-roadmap-v3.md`.
2. Re-read the current phase document.
3. Check the previous phase handover notes.
4. Confirm the phase goal, non-goals, and exit criteria.
5. Keep a short implementation spec for the current phase only.
6. End the phase with a handover note: completed work, test commands, artifacts, limitations, and next-phase blockers.

## Phase Order

1.  `00-master-execution-plan.md`
2.  `01-phase-0a-foundation.md`
3.  `02-phase-0b-bundle-and-trust-core.md`
4.  `03-phase-0c-censor-lab-and-measurement.md`
5.  `04-phase-1a-publisher-cli.md`
6.  `05-phase-1b-android-bootstrap-mvp.md`
7.  `06-phase-1c-offline-sharing.md`
8.  `07-phase-1d-bootstrap-directory.md`
9.  `08-phase-1-5-reliability-and-desktop.md` (V1.5 umbrella)
10. `08-phase-1-5a-reliability-hardening.md`
11. `09-phase-1-5b-desktop-port.md`
12. `10-phase-1-5c-blackout-soak.md`
13. `11-phase-1-5c-polish.md`
14. `09-phase-2-ios-survivability.md` (V2 umbrella)
15. `12-phase-2f-scheduler.md`           — V2 entry, scheduler-first
16. `13-phase-2a-route-budgets.md`       — hourly cap engine
17. `13b-phase-2a-polish.md`             — per-session caps + `modes_allowed` (faithfulness fix)
18. `14-phase-2b-mode-budgets-fsm.md`    — V2.3 8-state posture + V0.3 cooldown reasons
19. `15-phase-2c-network-memory.md`
20. `16-phase-2d-lifeline-mode.md`       — local-only behaviour; NO relay filter
21. `17-phase-2g-1k-user-soak.md`        — V2 success-metric soak (directory-rotation comparison)
22. `18-phase-2e-ios.md`                 — V2 ship gate; boringtun WG sub-engine fallback
23. `19-phase-3-ecosystem-integrations.md`
24. `11-cross-cutting-governance-and-v4.md`

The V3 phase docs themselves (`20-phase-3a` … `27-phase-3-soak`) were
missing from this index until 2026-08-17:

  * `20-phase-3a-webtunnel-scaffold.md`
  * `21-phase-3b-snowflake-rendezvous.md`
  * `22-phase-3c-masque-ladder.md`
  * `23-phase-3d-refraction-hooks.md`
  * `24-phase-3e-wasm-transport.md`
  * `25-phase-3f-one-tap-share.md`
  * `26-phase-3g-lifeline-relay.md`
  * `27-phase-3-soak-success-metric.md` (+ `27-phase-3-soak-threshold-comparison.md`)

### FRP / RelayPack track (post-3-Soak; implementation arm of `daal-roadmap-v3-supplement-diaspora-helper.md`)

The FRP track is a continuation of the closed V3 surface. The engine
`Version` constant in `core/abi/abi.go` stays `daal-core 0.9.0+v3-share`
across the **entire** FRP track per supplement — that part still holds.

The companion claim that **ABI=48 is preserved across the entire FRP track
(no engine release symbols are added at any FRP-N phase)** is **no longer
true** and should not be relied on as an invariant. The release surface is
**58** as of 2026-08-17. Symbols were added — the append-only rule held (no
existing signature or semantic changed), but the count did not freeze. See
the ABI ledger at the end of `specs/engine-abi-v1.md` for the authoritative
list and the regeneration command.
`spec_version` bumps at FRP-1 (RelayPack schema land) and FRP-7.5 (sub-key
cert chain). Milestone tagging (V1.5 / V1.6 / V2 / V3) is recorded in closure
specs and packaging tags only — never in the engine `Version` constant. The
track sequence and locked invariants live in `specs/frp-track-v1.md`. FRP-N
phases follow the same per-phase loop (locked spec → bounded scope → tests →
handover) as the V0–V3 phases above.

25. `28-phase-frp-0-roadmap-reconciliation.md`     — FRP track entry; no-code reconciliation + audit
26. `29-phase-frp-1-relaypack-schema.md`           — RelayPack spec + bundle schema (`spec_version` bump)
27. `30-phase-frp-2-import-store-preservation.md`  — importer + store widening; `specs/test-vectors/relaypack/`
28. `31-phase-frp-3-selection-brain.md`            — mode-aware shortlist + cooldown propagation; `Explanation` struct
29. `32-phase-frp-4a-publisher-deploy-core.md`     — `publisher/deploy/`, Hetzner adapter, cloud-init, health endpoint
30. `33-phase-frp-5-desktop-wizard.md`             — Tauri wizard screens 0–3 LIVE; screens 4–6 disabled shells; publisher key + OperatorRecord (status `pre-provision`)
31. `34-phase-frp-4b-direct-deploy-integration.md` — wizard screens 4–6 wired LIVE (provision + sign + QR); signed direct RelayPack
32. `35-phase-frp-6-recipient-ux.md`               — Android + desktop recipient UX bound to FRP-3 `Explanation`
33. `36-phase-frp-7-direct-rotation-pilot-soak.md` — L1–L6 ladder + V1.5 pilot soak; `specs/v1-5-closure-v1.md`
34. `37-phase-frp-7-5-publisher-subkey-chain.md`   — sub-key cert chain; remove root-key-touch on rotation
35. `38-phase-frp-8-v1-6-cdn-fronted.md`           — `cdn_fronted` mode + freshness endpoint
36. `39-phase-frp-9-v1-6-cdn-soak.md`              — V1.6 soak; `specs/v1-6-closure-v1.md`
37. `40-phase-frp-10-v2-multi-provider.md`         — Vultr + Stark adapters; mgmt-plane API
38. `41-phase-frp-11-trusted-cells.md`             — `specs/cell-v1.md` + `specs/cell-closure-v1.md`
39. `42-phase-frp-12-modifier-framework.md`        — per-modifier flag + censor-lab pass record
40. `43-phase-frp-13-public-directory.md`          — gated; requires `specs/cell-closure-v1.md`
41. `44-phase-frp-14-pack-to-person.md`            — per-recipient credentials + `.sbpx` envelope; SHIPPED
42. `45-gap-dataplane-and-delivery.md`             — in-process sing-box + Android VpnService; SHIPPED (exit gate met 2026-08-15)

### D track (rename, GUI rebuild, landing site)

Runs alongside the FRP track; not numerically ordered with it.

43. `D-1-rename-and-repo-migration.md`   — hydra → Daal rename + public repo; SHIPPED
44. `D-2-gui-rebuild-v2.md`              — unified React GUI (supersedes `D-2-gui-rebuild.md`); SHIPPED
45. `D-3-landing-site-and-downloads.md`  — GitHub Pages landing site + downloads; SHIPPED

The numeric prefix is for filesystem ordering and historical
continuity, not strict chronology. Read in the list-order above for
the chronological flow.

**Next up:** smart route selection — wiring `core/internal/selection`
into the connect path (backlog item B1). Nothing is in flight.

## Non-Negotiable Principles

- Zero trust: no route, IP, CDN, publisher, field result, or protocol is assumed valid by default.
- Signed supply chain: routes, publishers, directories, revocations, and transport modules must be signed and expiring.
- No telemetry: no automatic client-side analytics, identifiers, network-success reporting, or crash uploads.
- Local-first learning: network diagnosis and route scoring happen on-device.
- Deterministic path manager: no opaque ML route selection.
- Testability first: every phase must produce fixtures, contracts, or replayable scenarios.
- Cross-cutting work is not optional: audits, reproducible builds, ops security, localization, incident response, and sustainability must be tracked beside feature phases.
- Track-level closure records: V3 closed under `specs/v3-closure-v1.md`. The FRP track produces `specs/v1-5-closure-v1.md` (FRP-7), `specs/v1-6-closure-v1.md` (FRP-9), and `specs/cell-closure-v1.md` (FRP-11). V1.5 HOLD may coexist with FRP-7.5 engineering work; V1.5 SHIPPED gates V1.6 production rollout. V1.6 closure gates FRP-10, and cell closure gates FRP-13. Calendar-driven launch is the failure mode this discipline prevents.
