# Phase 36 (FRP-7) — Direct-VPS Rotation + V1.5 Pilot Soak

**Status:** SHIPPED 2026-05-03 (engineering surface). V1.5 closure HOLD pending live pilot.
**Roadmap line:** *"Gate to V1.6. Five real FRPs in a closed pilot have provisioned VPSes; their families' Daal clients have stayed online for at least 7 consecutive days; at least one rotation event (any direct-mode ladder level) has been observed to recover under 60 seconds; the mode-aware schema has been exercised end-to-end (validator → importer → store → selector → UI) with `direct_vps` candidates."* — `daal-roadmap-v3-supplement-diaspora-helper.md` §21.1
**Supplement target:** v2.3.7.
**Engine version target:** `daal-core 0.9.0+v3-share` **(UNCHANGED — supplement holds the engine `Version` constant through V1.5; the `+v1.5` semver suffix is a packaging tag carried in build metadata, NOT a change to `core/abi/abi.go`'s `Version` constant).**
**ABI release surface target:** **48** **(UNCHANGED — V1.5 schema lives in bundle metadata; engine ABI unaffected).**
**Maturity:** soak gate. V1.5 closure phase. Produces `specs/v1-5-closure-v1.md`.
**Predecessor:** Phase 35 (FRP-6) — recipient UX shipped.
**Successor:** Phase 37 (FRP-7.5) — sub-key cert chain hardening before V1.6 expansion.

## 1. Strategic frame (verbatim from the supplement)

> **§14.1 Direct-mode rotation ladder.** L1 regenerate credentials (~90 s redeploy at V1.5 / ~5 s mgmt-API at V2). L2 change TLS / route parameters (~90 s / ~20 s). L3 move floating IP (~10 s — most common rotation, both phases). L4 move datacenter (~3 min). L5 move provider (~2 min). L6 change protocol mix (~3 min).
>
> **§22.1 V1.5 success metric.** A diaspora user in Berlin who has never used Hetzner before installs Daal desktop, opens the wizard, and has a working RelayPack provisioned within 10 minutes. Their parent in Tehran scans the resulting QR code on their Daal Android client and is online within 60 seconds. Both sides remain operational without project intervention for at least 7 consecutive days. The selector demonstrably switches candidates at least once during the 7 days, and explains the switch in plain language to the recipient.

FRP-7's engineering job is to wire the live rotation logic (L1–L6 ladder per supplement §14.1) into the wizard UI, ship the synthetic V1.5 soak rig, and produce `specs/v1-5-closure-v1.md` (mirror of `specs/v3-closure-v1.md`). The live 5-FRP pilot is operational and keeps the V1.5 closure record in HOLD until it passes; that closure gates V1.6 production rollout, not FRP-7.5 implementation start. **The engine `Version` constant in `core/abi/abi.go` is NOT changed here** — the supplement holds it at `daal-core 0.9.0+v3-share` through V1.5; the V1.5 designation is a build-metadata / packaging tag only.

## 2. Locked answers

| Question | Locked answer |
|---|---|
| Rotation logic location | `publisher/deploy/rotation/`. Wraps `Provider.Reprovision` (FRP-4a) + `Provider.AssignFloatingIP` (FRP-4a) + `Provider.Decommission` (FRP-4a). |
| Rotation UI binding | The "Rotate" button on FRP-5's screen 6 (currently disabled-shell) is wired live at FRP-7. Surfaces selector-recommended ladder level + override. |
| Selector → rotation handoff | FRP-3's `Explanation` carries the cooldown reasons; FRP-7 adds a thin `recommendation` engine that maps cooldown classifications to ladder levels per supplement §13.4 + §14.1. |
| L3 fast path | Hetzner floating-IP swap via `hcloud-go.FloatingIP.Assign/Unassign` (~10 s). Only L3 has wall-clock advantage at V1.5. |
| L1/L2/L4/L5/L6 | All redeploy paths at V1.5 (~90 s – 3 min). Code-shape collapses to `Provider.Reprovision` with different `ReprovisionOpts`. |
| Pilot recruitment | 5 FRPs (3–25 family members each). Selection criteria: real Iranian families, real diaspora helpers, signed pilot consent. Recruitment process documented in private appendix per supplement §20.6 (not in this phase doc). |
| Pilot duration | Minimum 7 consecutive days per supplement §22.1; soft target 14 days; hard ceiling 30 days. |
| Pilot success criteria | Per supplement §22.1: provisioning ≤10 min; family online ≤60 s; ≥7 days continuous; ≥1 rotation observed; mode-aware schema exercised end-to-end. All five must be PASS. |
| Pilot failure handling | If any criterion fails, V1.5 closure is HOLD (not BLOCKED). Failure analysis goes into `specs/v1-5-closure-v1.md` `Carry-overs to V1.5b` section. FRP-7.5 engineering may still proceed after FRP-7 engineering ship; V1.6 production rollout stays gated until closure passes. |
| Engine `Version` constant | UNCHANGED. Stays `daal-core 0.9.0+v3-share` in `core/abi/abi.go` through V1.5 per the supplement. ABI surface unchanged at 48. The "V1.5 release" is recorded in `specs/v1-5-closure-v1.md` and a packaging tag, not in the engine constant. |
| `specs/v1-5-closure-v1.md` content | Mirrors `specs/v3-closure-v1.md` shape: locked surface (48), engine version, shipped phases (FRP-1..FRP-6), pilot results, carry-overs, V1.6 unblock criterion. |
| Telemetry during pilot | Position B preserved. Pilot data is collected by the FRPs *manually* through structured forms; family-side data is consented and minimal (online/offline timestamps; NO route-level data). |
| Soak rig | Reuses `test-rigs/distribution-failure/` infrastructure with new V1.5 scenarios. Synthetic load only; real pilot is separate. |

## 3. Locked invariants

Tracks invariants 1–16 inherited. Phase-specific:

17. **L3 floating-IP path is wall-clock < 15 s end-to-end.** Verified by a soak-rig scenario `v1-5-l3-fast-path.json` and by pilot.
18. **Pilot consent is signed.** Each pilot FRP signs a consent form per supplement §20.6. Family-side consent is collected by the FRP, not by the project. No project-side personal data of family members.
19. **No telemetry from family-side clients.** Pilot data is FRP-collected and project-anonymized.
20. **Engine `Version` constant in `core/abi/abi.go` is NOT changed at FRP-7.** Supplement holds it at `daal-core 0.9.0+v3-share` through V1.5. ABI=48 unchanged.
21. **`specs/v1-5-closure-v1.md` is mandatory exit artefact.** Even on HOLD, the spec ships; HOLD just means the V1.5 status field reads "HOLD" instead of "SHIPPED".
22. **Position B preserved.** Verified by Tauri allowlist + Android `OPSecTest.kt` carry-forward + pilot consent forms making "no project-side telemetry" explicit.
23. **Selector → rotation recommendation is auditable.** The wizard shows the recommendation reason ("Single-IP burn detected; recommending L3 floating-IP swap (~10 s)"); the FRP can override.
24. **Rotation is reversible.** A rotated VPS can be reverted via `Provider.Decommission` + re-`Provision`. (The cost is operational time, not data loss; OperatorRecord history is preserved.)
25. **Pilot scope is closed, not public.** No advertising, no public listing, no aggregation. Per supplement §20.6.

## 4. Sub-task breakdown

| #  | Task |
|----|------|
| 0  | Replace any prior FRP-7 stub with this locked spec at `phases of development/36-phase-frp-7-direct-rotation-pilot-soak.md`. |
| 1  | Read inputs end-to-end: supplement §14.1, §14.2, §14.3, §22.1; FRP-3 handover (Explanation struct cooldown classifications); FRP-4a handover (Provider interface); FRP-5 handover (rotation UI shell). |
| 2  | Author `publisher/deploy/rotation/recommender.go`. Maps cooldown classifications (FRP-3 `Explanation.failures[]`) to ladder levels per supplement §14.1 + §13.4. Pure function; tests cover all 9 network signals + 6 ladder levels. |
| 3  | Author `publisher/deploy/rotation/executor.go`. Wraps Provider methods. Idempotent. For L3: `Provider.AssignFloatingIP`. For L1/L2/L4/L5/L6: `Provider.Reprovision` with appropriate `ReprovisionOpts`. |
| 4  | Wire wizard rotation UI at FRP-5 screen 6: enable the button; render the recommendation reason; show override dropdown for ladder levels; surface progress; emit fresh `.sbp` to staging dir on success (re-runs FRP-4b's binder). |
| 5  | Author L3 fast-path soak scenario `test-rigs/distribution-failure/scenarios/v1-5-l3-fast-path.json`. Asserts wall-clock < 15 s. |
| 6  | Author 6 V1.5 soak scenarios at `test-rigs/distribution-failure/scenarios/v1-5-*.json`: `v1-5-7-day-stay-online`, `v1-5-1-rotation-under-60s`, `v1-5-mode-aware-schema-end-to-end`, `v1-5-provisioning-under-10min`, `v1-5-family-online-under-60s`, `v1-5-l3-fast-path` (above). |
| 7  | Author `--scenarios v1-5-superset` selector in `cmd/soak-driver/main.go`. v2-superset stays 26; v3-superset stays 31; v1-5-superset is **6** (V1.5 metrics only — additive, the V1.5 work does not regress V2/V3 metrics; v2-superset and v3-superset remain green). |
| 8  | Run synthetic soak: `soak-driver run --scenarios v1-5-superset --duration 7d --seed 42`. Capture ledger; verify all 6 scenarios PASS. |
| 9  | Recruit 5 pilot FRPs per private appendix process (out-of-tree; FRP-7 references the recruitment doc but the recruitment work is operational, not code). |
| 10 | Run the live 7-day pilot. Capture FRP-side observations + family-side anonymized timestamps. |
| 11 | If pilot PASSES all 5 supplement §22.1 criteria: update `specs/v1-5-closure-v1.md` to status SHIPPED and tag the V1.5 packaging release. **DO NOT modify `core/abi/abi.go`'s `Version` constant** — supplement holds it at `daal-core 0.9.0+v3-share`. If HOLD: keep `specs/v1-5-closure-v1.md` at HOLD + carry-overs; V1.6 production remains gated. |
| 12 | Final regression sweep: synthetic soak GREEN; v2-superset stays 26 GREEN; v3-superset stays 31 GREEN; closure spec exists; FRP-7.5 engineering gate verdict; handover. |

## 5. Recommendation map (locked)

Mapping from FRP-3 `Explanation.failures[]` cooldown classifications to ladder level recommendations:

| Cooldown classification | Recommended ladder level | Wall-clock V1.5 |
|---|---|---|
| `public_ip:` cooled (TCP RST on connect) | **L3** floating-IP swap | ~10 s |
| `public_asn:` / `public_provider:` cooled | **L4** move datacenter | ~3 min |
| Provider account suspended / DC outage | **L5** move provider | ~2 min |
| `sni:` cooled (sni_rst, direct_vps) | **L2** change SNI/dest | ~90 s |
| Credential leak / hygiene | **L1** regen credentials | ~90 s |
| Whole protocol family burned | **L6** change protocol mix | ~3 min |
| `cdn_*` cooled at V1.5 | not applicable (V1.5 has no cdn_fronted) | n/a |
| `udp_collapsed` (network signal) | **L6** change protocol mix to TCP-only | ~3 min |

The wizard UI shows: *"Single-IP burn detected. Recommend L3 (~10 s, floating-IP swap). [Override ▼]"*

## 6. V1.5 success metric — operational form

Per supplement §22.1, restated as falsifiable assertions:

1. **Provisioning ≤10 min**: `time.Since(wizard.start) ≤ 10 minutes` for ≥4 of 5 pilot FRPs.
2. **Family online ≤60 s**: `time.Between(family.scan, family.connected) ≤ 60 seconds` for ≥4 of 5 pilot families.
3. **≥7 days continuous**: family-side anonymized session timestamps show ≥7 consecutive days with ≥99% uptime windows.
4. **≥1 rotation observed**: at least one pilot family experienced a selector-driven candidate switch within the soak window; the recipient saw a plain-language explanation per FRP-6 expanded view.
5. **End-to-end schema exercise**: validator (FRP-1) → importer (FRP-2) → selector (FRP-3) → UI (FRP-6) confirmed exercised for `direct_vps` candidates by the soak ledger and pilot logs.

PASS = all five PASS. HOLD = any FAIL.

## 7. `specs/v1-5-closure-v1.md` content (locked shape)

Mirrors `specs/v3-closure-v1.md`:

```
# V1.5 Closure Record v1

Locked surface: 48 (UNCHANGED through V1.5).
Locked engine Version: daal-core 0.9.0+v3-share (UNCHANGED — supplement holds the engine `Version` constant through V1.5).
Status: SHIPPED | HOLD.

Shipped phases:
- FRP-0 roadmap reconciliation (Phase 28).
- FRP-1 RelayPack schema (Phase 29).
- FRP-2 import + store preservation (Phase 30).
- FRP-3 selection brain (Phase 31).
- FRP-4a publisher deploy core (Phase 32).
- FRP-5 desktop wizard (Phase 33).
- FRP-4b direct-deploy integration (Phase 34).
- FRP-6 recipient UX (Phase 35).
- FRP-7 direct rotation + V1.5 pilot soak (Phase 36).

V1.5 success metric: PASSED | HOLD per §22.1 of the supplement.

Pilot results:
- N FRPs recruited.
- Provisioning median: M minutes.
- Family-online median: K seconds.
- Days continuous: D days.
- Rotation events: R observed.

Carry-overs to V1.6 (or V1.5b in HOLD case):
- ...

What did NOT change at V1.5: ABI surface, bundle format (RelayPack is a profile of .sbp), trust ladder, V2/V3 success metrics.
```

## 8. Build matrix at FRP-7 exit

```
$ cd publisher/deploy/rotation && go build ./... && go test ./...
$ cd test-rigs/distribution-failure/soak-driver && go build ./...
$ soak-driver run --scenarios v1-5-superset --duration 7d --seed 42
   # all 6 scenarios PASS
$ soak-driver run --scenarios v2-superset                              # 26 PASS (no regression)
$ soak-driver run --scenarios v3-superset                              # 31 PASS (no regression)
$ nm /tmp/libdaalcore.so | grep ' T engine_' | wc -l                  # 48 (UNCHANGED)
$ # On PASS:
$ grep -E '^const Version' core/abi/abi.go                             # daal-core 0.9.0+v3-share (UNCHANGED — supplement holds through V1.5)
$ ls specs/v1-5-closure-v1.md                                          # exists, status SHIPPED
$ # On HOLD:
$ grep -E '^const Version' core/abi/abi.go                             # daal-core 0.9.0+v3-share (UNCHANGED)
$ ls specs/v1-5-closure-v1.md                                          # exists, status HOLD
```

## 9. Spec deliverables

**1 NEW:**
- `specs/v1-5-closure-v1.md` — V1.5 closure record (mirror of `specs/v3-closure-v1.md`).

**1 AMENDED:**
- `specs/blackout-soak-rig-v1.md` — gains V1.5 scenario list.

**0 AMENDED on PASS in `core/abi/`** — engine `Version` constant in `core/abi/abi.go` stays `daal-core 0.9.0+v3-share` per supplement.

## 10. Out of scope (deferred)

- V2 in-box mgmt API (fast L1/L2 ~5 s / ~20 s) — V2 (FRP-10).
- Cell-aware rotation (peer can serve while FRP rotates) — **FRP-11.**
- `cdn_fronted` rotation table — **FRP-8.**
- Sub-key rotation — **FRP-7.5.**
- Real-DPI burn classifier — V4.

## 11. Handover requirements

The FRP-7 handover must contain:

1. Status: SHIPPED | HOLD. Date.
2. New file paths under `publisher/deploy/rotation/`.
3. Recommender test result (all 9 signals × 6 levels matrix).
4. Synthetic soak ledger (v1-5-superset).
5. Pilot recruitment count + criteria + sign-off.
6. Pilot run summary (per FRP, anonymized).
7. V1.5 success metric — five-line PASS / FAIL table.
8. `nm` count = 48 unchanged.
9. Engine `Version` constant value (must read `daal-core 0.9.0+v3-share` — UNCHANGED).
10. `specs/v1-5-closure-v1.md` attached.
11. FRP-7.5 engineering gate verdict and V1.5 closure/HOLD state.
12. Open follow-ups: any sub-key cert work surfaced by the pilot.

## 12. Track ordering rationale

FRP-7 is the V1.5 closure-path phase. Putting the pilot soak here (rather than later in the FRP track) means: (a) the pilot results inform whether FRP-7.5's sub-key cert chain is urgent; (b) V1.5 does not go to production release until evidence exists; (c) the closure-record discipline (mirror of V3 closure) prevents calendar-driven launch — V1.6 production starts only when V1.5 closes.

End — locked at FRP-track planning. Next: FRP-7.5 (publisher sub-key chain).
