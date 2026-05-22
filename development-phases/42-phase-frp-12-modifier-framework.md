# Phase 42 (FRP-12) — Modifier Framework (Reserved Slots)

**Status:** SHIPPED 2026-05-05 — framework lands; zero PASS records (locked invariant 37); first concrete-modifier PASS deferred to a post-track follow-on phase.
**Roadmap line:** *"Per-modifier opt-in framework with explicit per-modifier flag + censor-lab pass record before any modifier (`client_desync`, `tls_fragment`) is allowed at validator gate. The `modifiers[]` array carries packet-mutation modifiers (FakeSNI / TCP desync, TLS fragmentation) that the recipient applies to outgoing packets; distinct from `exposure_mode` which describes the endpoint the recipient connects to."* — supplement §11.6 (field-techniques table) + §12.1 + §12.2.2.bis; FRP-1 RP013 (validator-rejected at V1.5/V1.6) — `phases of development/29-phase-frp-1-relaypack-schema.md`.
**Supplement target:** v2.3.11.
**Engine `Version` target:** `daal-core 0.9.0+v3-share` **(UNCHANGED — supplement holds engine `Version` constant).**
**ABI release surface target:** **48** **(UNCHANGED).**
**Maturity:** framework-only phase. Adds the per-modifier validator framework. **Zero modifiers ship as PASS at this phase** — RP013 stays effectively a hard reject for all modifiers because no `specs/modifiers/<id>.md` carries a PASS record. Concrete modifier enablement (the first `client_desync` PASS, the first `tls_fragment` PASS) lives in **separate follow-on phases** outside this FRP track.
**Predecessor:** Phase 41 (FRP-11) — trusted cells.
**Successor:** Phase 43 (FRP-13) — public directory; not blocked on modifiers but ordered after for review-load reasons.

## 1. Strategic frame (per supplement §11.6 + §12.2.2.bis)

The supplement reserves a per-candidate `modifiers[]` array for **packet-mutation behaviours** the recipient applies to outgoing packets — distinct from `exposure_mode` (which describes the endpoint the recipient connects to). Two modifier kinds are reserved by name in v2.3.5+:

* `client_desync` — FakeSNI / TCP desync. Linux-desktop-only (raw-socket capability). Bumps the candidate's effective `probing_risk_class` upward. Mobile platforms reject at importer.
* `tls_fragment` — TLS fragmentation / packet mutation. Reserved name; semantics defined in censor-lab review.

A third reserved name, `serverless_external`, is **NOT a modifier** — it is an `exposure_mode` enum value (a real new endpoint type, not a packet mutation). This phase doc does NOT touch `serverless_external` enablement; that lives in a separate post-V2 phase that lifts FRP-1's RP004-equivalent for the new enum value.

The supplement at §11.6 + §12.2.2.bis says: validators at V1.5 + V1.6 reject any non-empty `modifiers[]` array; modifiers exist as reserved schema slots so a future RelayPack carrying them parses cleanly into typed structs; the rejection is a runtime gate, not a parse error.

FRP-12's job: ship the per-modifier framework that **conditionally** lifts the validator hard-reject. The framework is **opt-in per modifier kind**; modifiers without a censor-lab pass record stay rejected. **At FRP-12 ship, zero modifier kinds carry a PASS record** — the framework lands; the first concrete modifier (likely `client_desync`, after Linux-desktop-only censor-lab validation) ships in a separate follow-on phase outside this FRP track.

## 2. Locked answers

| Question | Locked answer |
|---|---|
| Modifier framework location | `publisher/deploy/modifiers/` (new subpackage). |
| Per-modifier metadata location | `specs/modifiers/<modifier-id>.md` — one file per modifier. Carries: id, description, sing-box reference, censor-lab pass record (date, methodology, observed safety on Iranian DPI), validator behavior at each phase. |
| Censor-lab pass record shape | Documented test plan + observed Iranian network result + signed-off review. Format locked in `specs/modifiers/_template.md`. |
| Validator integration | FRP-1 RP013 lifts conditionally at FRP-12 — only for modifier `kind` values that have a corresponding `specs/modifiers/<kind>.md` AND that file's `pass_record.status = "PASS"`. Unknown `kind` values stay hard-rejected; PENDING `kind` values stay hard-rejected. |
| Reserved kinds at FRP-12 ship | `client_desync` (PENDING — Linux-desktop-only censor-lab validation pending) and `tls_fragment` (PENDING — semantics + censor-lab review pending). Both stay hard-rejected by validator. |
| Phase gating | Each modifier carries `min_phase` (V1.5 / V1.6 / V2 / V3). Even with PASS record, a modifier won't be accepted before its `min_phase`. |
| Platform gating | Each modifier carries `platforms[]` listing platforms where it is permitted. `client_desync` is Linux-desktop-only; `core/trust.StoreAdapter.SaveImport` preflights modifier-bearing routes via `core/internal/selection.RejectByPlatform` before persistence. At FRP-12 ship the default policy is fail-closed because zero kinds are PASS; future PASS phases wire a concrete policy. |
| Sample modifier | At ship of FRP-12, exactly **zero** modifier kinds are PASS. The framework is shipped; the first concrete modifier (likely `client_desync` for Linux desktop, after censor-lab validation) ships in a follow-on phase outside this FRP track. |
| RelayPack-side opt-in | Per-candidate `_relaypack.modifiers[]` slot accepts modifier IDs (additive; existing slot from FRP-1). Validator checks each ID against the framework. |
| Recipient UI | A new "Modifier opt-in" toggle in expanded route view; off by default. The recipient sees which modifiers are active per candidate. |
| Telemetry | None. Modifier outcomes are recorded by the FRP through the standard 3F revocation/cooldown channels, not by project-side telemetry. |

## 3. Locked invariants

Tracks invariants 1–16 inherited. Phase-specific:

17. **Zero modifier kinds ship as PASS at FRP-12.** The framework lands; the first PASS record lands separately, after censor-lab review.
18. **Unknown / PENDING modifier kinds stay hard-rejected.** Validator rule RP013 only lifts for explicitly PASS-recorded kinds.
19. **Per-modifier `min_phase` enforced.** A modifier with `min_phase: V2` is rejected at V1.5/V1.6 even if PASS.
20. **Per-modifier `platforms[]` enforced at importer/store boundary.** `StoreAdapter.SaveImport` rejects modifier-bearing routes before persistence with `IMP_MODIFIER_PLATFORM`; disallowed platforms reject regardless of validator state.
21. **Modifier carry is per-candidate.** Not per-RelayPack-wide. A bad modifier on candidate A doesn't burn candidates B, C, D.
22. **Recipient UI default off.** Modifiers are opt-in; users see which are active and can disable one per candidate.
23. **Censor-lab pass record is reviewable.** Each `specs/modifiers/<kind>.md` includes the methodology, raw observation, and reviewer sign-off.
24. **No engine release symbols added.** ABI count stays 48.
25. **Position B preserved.** No project-side modifier outcome telemetry.
26. **`exposure_mode: serverless_external` is NOT in scope.** That's a separate `exposure_mode` enum value (endpoint type), not a packet-mutation modifier; its enablement is a separate post-V2 phase that lifts FRP-1's RP004-equivalent.

## 4. Sub-task breakdown

| #  | Task |
|----|------|
| 0  | Replace any prior FRP-12 stub with this locked spec at `phases of development/42-phase-frp-12-modifier-framework.md`. |
| 1  | Read inputs end-to-end: supplement §11.6 (field-techniques table), §12.1, §12.2.2.bis; FRP-1 RP013; sing-box modifier docs (external). |
| 2  | Author `specs/modifiers/_template.md` — locked template for per-modifier docs: `kind`, `description`, `singbox_ref` (where applicable), `pass_record: {status, methodology, observed, reviewer, date}`, `min_phase`, `platforms[]`, `validator_behavior`. |
| 3  | Author **placeholder** `specs/modifiers/client_desync.md` with `pass_record.status = "PENDING"`, `platforms = ["linux-desktop"]`, full methodology + observed sections empty/TBD. (Reserves the slot; validator still rejects.) |
| 3b | Author **placeholder** `specs/modifiers/tls_fragment.md` with `pass_record.status = "PENDING"`, `platforms = []` (TBD — defined in censor-lab review), methodology + observed empty/TBD. (Reserves the slot; validator still rejects.) |
| 4  | Author `publisher/deploy/modifiers/registry.go` — reads `specs/modifiers/*.md` at build time; emits a Go map of `<kind> → ModifierMeta`. Build-time generation; not runtime. |
| 5  | Extend FRP-1 validator (rule RP013): for each `_relaypack.modifiers[]` entry, look up `kind` in registry; reject if not registered; reject if `pass_record.status != "PASS"`; reject if validator-`Phase` ordinal < `min_phase` ordinal. Keep the original "unknown kinds rejected" baseline. |
| 6  | Extend importer/store boundary to enforce `platforms[]`: reject modifier-bearing routes before persistence on a disallowed platform, regardless of validator state. (`StoreAdapter` reads runtime platform; validator does not.) |
| 7  | Wire wizard surface: per-candidate "Modifiers" line on screen 6 of FRP-5 wizard, surfacing which (if any) modifier kinds are active. At FRP-12 ship: always reads "none active" because every kind is PENDING. EN + FA. |
| 8  | Wire recipient UI: per-candidate "Active modifiers" line in the FRP-6 expanded "Why this route" view. EN + FA. Toggle stub for future — per supplement §22.1 the recipient UI line at FRP-12 ship reads "Modifiers: none active" because every kind is PENDING. |
| 9  | Author tests: ≥15 covering: unknown `kind` rejected; PENDING `kind` rejected; PASS `kind` accepted at correct phase (use a test-only synthetic PASS record fixture, NOT a real PASS in `specs/modifiers/`); PASS `kind` rejected before `min_phase`; phase-ordinal comparison correct at V1.5 / V1.6 / V2 / V3; importer rejects on disallowed platform; per-candidate scoping; UI surface displays "none active" at framework-only ship. |
| 10 | Document the censor-lab review process in `docs/modifier-review-process.md` — methodology, sign-off process, reviewer pool, refresh cadence. |
| 11 | Verify zero PASS records at FRP-12 ship: `rg "status.*PASS" specs/modifiers/*.md | grep -v _template.md` returns empty (PENDING records may exist; PASS must be empty). |
| 12 | Final regression sweep: `cd publisher && go build ./... && go test ./deploy/modifiers/...`; `cd core && go build ./... && go test ./...`; `cd bundle/go && go build ./... && go test ./bundle/...` (regression-only); v1-5-superset (6), v1-6-superset (7), v2-superset (26), v2-cell-superset (≥10), v3-superset (31) all PASS; `nm`=48; engine `Version` UNCHANGED; FRP-13 gate verdict; handover. |

## 5. Per-modifier spec template (locked at `specs/modifiers/_template.md`)

```markdown
# Modifier: <kind>

## Identity
- **kind**: <kind>            # e.g. client_desync, tls_fragment
- **sing-box reference**: <link if applicable; "n/a" for raw-socket modifiers>

## Description
<2-paragraph plain-language description of what the recipient does to outgoing packets>

## Pass record
- **status**: PENDING | PASS | REJECTED | DEPRECATED
- **methodology**: <test plan>
- **observed**: <result on Iranian DPI; date; ASN; raw notes>
- **reviewer**: <who reviewed>
- **date**: <YYYY-MM-DD>

## Phase gating
- **min_phase**: V1.5 | V1.6 | V2 | V3

## Platform gating
- **platforms**: array of {linux-desktop, windows-desktop, macos-desktop, android, ios}
  Importer rejects candidate carrying this modifier on a disallowed platform.

## Validator behavior
At each phase, what the validator does when this modifier appears:
- **V1.5**: <accept|reject> — <reason>
- **V1.6**: ...
- **V2**: ...
- **V3**: ...

## Risk notes
<notes on what burns when this modifier mis-fires; effect on probing_risk_class>

## References
<links>
```

## 6. Build matrix at FRP-12 exit

```
$ cd publisher && go build ./deploy/modifiers/...                # green (under daal/publisher module)
$ cd publisher && go test ./deploy/modifiers/...                 # ≥15 tests
$ ls specs/modifiers/*.md                                          # _template.md, client_desync.md, tls_fragment.md
$ rg "status.*PASS" specs/modifiers/*.md | grep -v _template.md   # empty (zero PASS records)
$ # Validator regression
$ /tmp/daal-publish verify <modifier-with-unknown-kind>.sbp      # rejects
$ /tmp/daal-publish verify <modifier-with-PENDING-kind>.sbp      # rejects
$ # Soak supersets unchanged
$ soak-driver run --scenarios v1-5-superset                       # 6 PASS
$ soak-driver run --scenarios v1-6-superset                       # 7 PASS
$ soak-driver run --scenarios v2-superset                         # 26 PASS
$ soak-driver run --scenarios v2-cell-superset                    # ≥10 PASS
$ soak-driver run --scenarios v3-superset                         # 31 PASS
$ nm /tmp/libdaalcore.so | grep ' T engine_' | wc -l            # 48 (UNCHANGED)
$ grep -E '^const Version' core/abi/abi.go                        # daal-core 0.9.0+v3-share (UNCHANGED)
```

## 7. Spec deliverables

**3 NEW:**
- `specs/modifiers/_template.md` — locked template for per-modifier docs.
- `specs/modifiers/client_desync.md` — reserved-slot doc, `pass_record.status: PENDING`.
- `specs/modifiers/tls_fragment.md` — reserved-slot doc, `pass_record.status: PENDING`.

**1 AMENDED:**
- `specs/relaypack-v1.md` — gains a §"Modifier framework" cross-reference describing how `_relaypack.modifiers[]` is validated.

**1 NEW process doc:**
- `docs/modifier-review-process.md` — censor-lab review methodology + reviewer pool + sign-off process.

**0 AMENDED in `core/abi/`** — engine `Version` constant in `core/abi/abi.go` stays `daal-core 0.9.0+v3-share`.

## 8. Out of scope (deferred)

- The first concrete modifier PASS (likely `client_desync` for Linux-desktop) — separate phase after FRP-12, after censor-lab review.
- `exposure_mode: serverless_external` enablement — separate post-V2 phase that lifts the FRP-1 RP004-equivalent for the new enum value; NOT a modifier framework concern.
- Cross-modifier interaction analysis — separate research phase, not a code phase.
- Cell-aware modifier propagation — V3 candidate.

## 9. Handover requirements

Status, new file paths under `publisher/deploy/modifiers/` and `specs/modifiers/`, validator integration test pass, "zero PASS records shipped" confirmation (`rg "status.*PASS" specs/modifiers/*.md` empty), platform-gating importer test result, recipient UI screenshots showing "Modifiers: none active", `nm`=48, engine `Version` constant value (must read `daal-core 0.9.0+v3-share` — UNCHANGED), FRP-13 gate verdict.

## 10. Track ordering rationale

FRP-12 after FRP-11 because the cell closure record (FRP-11's deliverable) is what FRP-13 actually depends on; FRP-12 is parallel-ready and just ordered after for review-load reasons (cells touch many files; modifiers touch few; doing them sequentially keeps each phase reviewable). FRP-13 doesn't depend on FRP-12 directly — but ordering cells → modifiers → public-directory means each layer's review is digestible.

End — locked. Next: FRP-13 (public directory, gated).
