# Phase 39 (FRP-9) — V1.6 CDN-Fronted Alpha Soak

**Status:** SHIPPED 2026-05-04 (engineering surface). Closure HOLD pending the live 2-FRP × 14-day alpha pilot.
**Roadmap line:** *"V1.6 alpha soak. Small-N validation (2 pilot RelayPacks) demonstrating `cdn_fronted` candidates survive DNS-only A leaks (synthetic), origin-IP scans (synthetic), and at least one public-surface rotation via the freshness endpoint with no QR re-scan + at least one origin-only rotation with zero family-visible event. NOT the V2 gate — the V2 gate per supplement §21.2 requires 20+ FRPs running cdn_fronted in production, observed CDN-wide-failure recovery, and observed origin-IP-leak recovery; that scale is reached in a sustained production rollout AFTER FRP-9 completes."* — `daal-roadmap-v3-supplement-diaspora-helper.md` §21.2 + §22.2
**Supplement target:** v2.3.8 (FRP-9 closure adds §14.6 — Operator rotation levels for cdn_fronted; documents L7/L8/L9 audit-log numbering).
**Engine `Version` target:** `daal-core 0.9.0+v3-share` **(UNCHANGED — supplement holds engine `Version` constant; V1.6 is a packaging-tag milestone).**
**ABI release surface target:** **48** **(UNCHANGED).**
**Maturity:** alpha soak. Produces `specs/v1-6-closure-v1.md` recording alpha completion. **Engineering-shipped is not closure-shipped** — FRP-9's code + synthetic rig now exist, but FRP-10 remains gated on `specs/v1-6-closure-v1.md` flipping to SHIPPED with status "alpha-pass". The supplement §21.2 production-scale V2 gate (20+ FRPs in production) flips later, in a separate operational window outside this FRP-track phase doc's scope.
**Predecessor:** Phase 38 (FRP-8) — CDN provisioning + freshness endpoint shipped.
**Successor:** Phase 40 (FRP-10) — V2 multi-provider; FRP-10 begins after V1.6 alpha-pass closure record. Supplement §21.2 production-scale V2 gate is a separate operational milestone beyond this FRP track.

## 1. Strategic frame (per supplement §22.2 + §21.2)

Supplement §22.2 is the **V1.6 success metric** — phrased operationally for the smallest pilot that proves the §11.7 hardening template + freshness-endpoint flow actually work end-to-end. FRP-9 implements that pilot at small N (2 RelayPacks, 14 days). The §11.7 hardening behaviours, the public-surface rotation path, and the origin-only rotation path all need to be proven *once* before they can scale; that's what FRP-9 is for.

Supplement §21.2 separately defines the **V2 gate**: *"20+ FRPs running `cdn_fronted` candidates in production. At least one observed CDN-wide failure event (real or simulated) recovered from by the selector falling back to `direct_vps` siblings without operator intervention. At least one observed origin-IP-leak event (real or simulated, e.g. a deliberate misconfiguration) handled by the V1.6 origin-repair path without exposing the family. No direct-mode regressions vs the V1.5 gate."* That gate is **operational** — it requires sustained production rollout after FRP-9, recruitment of 20+ FRPs, and observation in the wild over time. It is NOT a coding phase and NOT this FRP-track phase doc's responsibility.

FRP-9 produces `specs/v1-6-closure-v1.md` recording alpha completion (PASS / HOLD). FRP-10 (V2 multi-provider) starts once that closure record is SHIPPED. The §21.2 production-scale V2 gate is monitored separately and triggers V2 *production rollout*, distinct from V2 *code phases*.

## 2. Locked answers

| Question | Locked answer |
|---|---|
| Pilot scope | 2 FRPs (alpha — smaller than V1.5 because V1.6 is incremental over V1.5; recruitment from V1.5 graduates). 14-day soak. **NOT the V2 production gate** — that gate is "20+ FRPs in production" per supplement §21.2 and lives outside this phase doc. |
| New scenarios | 7 V1.6 CDN scenarios at `test-rigs/distribution-failure/scenarios/v1-6-*.json`. |
| Soak superset | `--scenarios v1-6-superset` selects the 7 V1.6 scenarios. v1-5-superset stays 6; v2-superset stays 26; v3-superset stays 31. |
| Synthetic DNS-only A leak test | A scenario that introduces a DNS-only A record post-deploy and confirms RP022 detection + selector demotion. |
| Synthetic origin-IP scan | A scenario where a "scanner" tries to reach origin IP directly without Cloudflare client cert; AOP rejects; recipient unaffected. |
| Cloudflare hostname-block simulation | Scenario blocks the `cdn:` cohort tag; selector falls back to direct-VPS sibling per FRP-3 §13.4. |
| Public-surface rotation test | Scenario rotates Cloudflare hostname; freshness JSON updated; recipient picks up via opportunistic poll; no QR re-scan. |
| Origin-only rotation test | Scenario swaps origin IP under stable Cloudflare hostname; recipient never sees a route change; RelayPack not republished. |
| Pilot success criteria | Per supplement §22.2: 14-day continuous operation; `cdn_fronted` dominant; ≥1 public-surface rotation; ≥1 origin-only rotation with no family event. All four PASS for both pilot FRPs. |
| Telemetry | Position B preserved. Pilot data is FRP-collected (same as V1.5). |
| Engine `Version` constant | UNCHANGED. Stays `daal-core 0.9.0+v3-share` per supplement. V1.6 alpha is recorded in `specs/v1-6-closure-v1.md` and a packaging tag, not in `core/abi/abi.go`. |
| Closure record | `specs/v1-6-closure-v1.md`. Mirror shape of `specs/v1-5-closure-v1.md`. |

## 3. Locked invariants

Tracks invariants 1–16 inherited. Phase-specific:

17. **Public-surface rotation ≠ origin-only rotation.** Public-surface = TIC-visible tag changes (hostname, public-path). Origin-only = TIC-invisible (origin IP swap behind unchanged hostname). Both must be demonstrated separately.
18. **Freshness endpoint atomic-swap PROVEN with real recipients.** Synthetic test PASS at FRP-8; live pilot PASS at FRP-9.
19. **No QR re-scan during V1.6 rotations.** Pinned publisher key suffices; freshness endpoint atomically swaps the bundle. Verified by pilot.
20. **Engine ABI=48 unchanged.** All V1.6 work is in publisher/Helper layer + bundle layer + UI layer.
21. **`specs/v1-6-closure-v1.md` is mandatory exit artefact.** Even on HOLD, the spec ships.
22. **Position B preserved.** FRP-collected, anonymized pilot reports.
23. **§13.4 cdn-fronted cooldown rules empirically tested.** They were unit-tested at FRP-3 and integration-tested at FRP-8; FRP-9's pilot exercises them on real network signals from real Iran-side recipients.
24. **No engine release symbols added.** ABI count stays 48.

## 4. Sub-task breakdown

| #  | Task |
|----|------|
| 0  | Replace any prior FRP-9 stub with this locked spec at `phases of development/39-phase-frp-9-v1-6-cdn-soak.md`. |
| 1  | Read inputs end-to-end: supplement §11.7, §13.4, §14.4, §14.5, §22.2; FRP-8 handover; FRP-3 cooldown table. |
| 2  | **SHIPPED:** Author 7 V1.6 scenarios at `test-rigs/distribution-failure/scenarios/v1-6-*.json`: `v1-6-cdn-dominant-route`, `v1-6-dns-only-a-leak-detected`, `v1-6-origin-ip-scan-rejected`, `v1-6-cf-hostname-blocked-fallback`, `v1-6-public-surface-rotation`, `v1-6-origin-only-rotation`, `v1-6-freshness-atomic-swap`. |
| 3  | **SHIPPED:** Wire `--scenarios v1-6-superset` selector in `cmd/soak-driver/main.go` and lock its count at 7. |
| 4  | **SHIPPED:** Wire V1.6 rig-local `engine_actions` dispatchers and `internal/v16verifier`; synthetic run is now available to operations as the engineering-controlled gate. |
| 5  | **PENDING OPS:** Recruit 2 pilot FRPs from V1.5 graduates per private appendix process. |
| 6  | **PENDING OPS:** Run live 14-day pilot with `cdn_fronted` candidates as dominant route. Capture FRP observations + family anonymized timestamps + freshness-endpoint poll counters. |
| 7  | **PENDING OPS:** Verify all §22.2 success criteria for both pilot FRPs using `docs/pilot/frp-9-pilot-template.md` + `internal/v16verifier`. |
| 8  | **PENDING OPS:** If PASS, append a `## Closure run YYYY-MM-DD` section to `specs/v1-6-closure-v1.md`, flip status to SHIPPED (alpha-pass), tag the V1.6 packaging release, and set FRP-10 gate = PASS. **DO NOT modify `core/abi/abi.go`'s `Version` constant.** If HOLD, append the hold reason and keep FRP-10 gate = HOLD. |
| 9  | **SHIPPED:** Confirm v1-5-superset (6), v2-superset (26), v3-superset (31) stay green — no regressions from V1.6 work. |
| 10 | **SHIPPED:** Confirm `nm` returns 48. |
| 11 | **SHIPPED:** Author `specs/v1-6-closure-v1.md` with HOLD status and engineering deliverables. |
| 12 | **SHIPPED:** Final regression sweep + handover at `docs/handovers/frp-9-handover.md`; live pilot summary remains pending. |

## 5. V1.6 success metric — operational form

Per supplement §22.2:

1. **14-day continuous operation**: Each pilot RelayPack online ≥99% over 14 days, with `cdn_fronted` as the dominant family-served route (≥60% of family-side connection time).
2. **Synthetic DNS-only A leak survived**: scenario `v1-6-dns-only-a-leak-detected` PASS — wizard refuses or RP022 warns; recipient unaffected.
3. **Synthetic origin-IP scan survived**: scenario `v1-6-origin-ip-scan-rejected` PASS — AOP rejects bare-IP TLS handshakes; family unaffected.
4. **Public-surface rotation**: ≥1 hostname-or-path change delivered via freshness endpoint with no QR re-scan, observed in pilot.
5. **Origin-only rotation**: ≥1 origin-IP swap (hostname unchanged) executed; family-side timeline shows zero connection event during the swap.

PASS = all five PASS for both pilot FRPs. HOLD = any FAIL.

## 6. `specs/v1-6-closure-v1.md` content (locked shape)

Mirror of `specs/v1-5-closure-v1.md`:

```
# V1.6 Closure Record v1

Locked surface: 48 (UNCHANGED through V1.6).
Locked engine Version: daal-core 0.9.0+v3-share (UNCHANGED — supplement holds engine `Version` constant; V1.6 is a packaging-tag milestone).
Status: SHIPPED (alpha-pass) | HOLD.

V2 gate (per supplement §21.2): 20+ FRPs in production cdn_fronted, at least one observed CDN-wide failure recovered, at least one observed origin-IP-leak handled. Tracked operationally outside this closure record.

Shipped phases:
- ... FRP-1..FRP-7 (V1.5 closure prerequisites).
- FRP-7.5 publisher sub-key chain (Phase 37).
- FRP-8 V1.6 CDN-fronted (Phase 38).
- FRP-9 V1.6 CDN soak (Phase 39).

V1.6 success metric: PASSED | HOLD per §22.2 of the supplement.

Pilot results:
- N FRPs.
- cdn_fronted dominant-route share: P%.
- Public-surface rotations observed: R.
- Origin-only rotations observed: O.
- Freshness atomic swaps: S (cumulative across pilot).

Carry-overs to V2 (or V1.6b in HOLD case):
- ...

What did NOT change at V1.6: ABI surface (48), trust ladder, V2/V3 success metrics, modifier rejection, cell rejection.
```

## 7. Build matrix at FRP-9 exit

```
$ soak-driver run --engine /tmp/daal-soak-engine-soak --out /tmp/daal-v1-6-soak --scenarios v1-6-superset --simulated-days 14  # 7/7 PASS
$ soak-driver run --engine /tmp/daal-soak-engine-soak --out /tmp/daal-v1-5-soak --scenarios v1-5-superset --simulated-days 14  # 6/6 PASS (no regression)
$ soak-driver run --engine /tmp/daal-soak-engine-soak --out /tmp/daal-v2-soak --scenarios v2-superset --simulated-days 14      # 26 PASS (no regression)
$ soak-driver run --engine /tmp/daal-soak-engine-soak --out /tmp/daal-v3-soak --scenarios v3-superset --simulated-days 14      # 31 PASS (no regression)
$ nm /tmp/libdaalcore.so | grep ' T engine_' | wc -l                     # 48 (UNCHANGED)
$ # On PASS:
$ grep -E '^const Version' core/abi/abi.go                                 # daal-core 0.9.0+v3-share (UNCHANGED)
$ ls specs/v1-6-closure-v1.md                                              # exists, status HOLD until live alpha pilot
```

## 8. Spec deliverables

**1 NEW:** `specs/v1-6-closure-v1.md`.
**1 NEW:** `docs/pilot/frp-9-pilot-template.md`.
**1 AMENDED:** `docs/pilot/consent-template.md` — gains V1.6 CDN supplement.
**1 AMENDED:** `specs/blackout-soak-rig-v1.md` — gains V1.6 scenario list + `v16verifier`.
**0 AMENDED in `core/abi/`** — engine `Version` constant in `core/abi/abi.go` stays `daal-core 0.9.0+v3-share` per supplement.

## 9. Out of scope (deferred)

- Cell-level cdn_fronted soak (cell peers serving each other's `cdn_fronted` candidates) — **FRP-11.**
- Multi-provider firewall for CDN (Vultr/Stark CDN paths) — **FRP-10.**
- Real Iranian DPI burn classifier — V4.

## 10. Handover requirements

Per V1.5 closure handover shape: status (alpha-pass / HOLD), pilot results, §22.2 success metric table, alpha soak ledger, `nm`=48, engine `Version` constant value (must read `daal-core 0.9.0+v3-share` — UNCHANGED), `specs/v1-6-closure-v1.md` attached, FRP-10 gate verdict, plus an explicit note that the supplement §21.2 V2 production-scale gate (20+ FRPs in production) is **operational** and tracked outside this phase doc.

## 11. Track ordering rationale

FRP-9 is the V1.6 ship gate. Closure-record discipline mirrors V1.5: V2 (multi-provider) cannot start until V1.6 closure is recorded, even if V1.6 takes longer than expected to settle.

End — locked. Next: FRP-10 (V2 multi-provider).
