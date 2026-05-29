# Phase 28 (FRP-0) — Roadmap Reconciliation + Code Audit

**Status:** SHIPPED on 2026-05-02. **NO CODE PHASE.** FRP-1 gate is `PASS` after the 2026-05-02 unlock pass (`/usr/local/go/bin/go` core tests green, c-shared ABI count 48, supplement `RouteRow` erratum patched).
**Roadmap line:** *"V1.5 FRP MVP (direct-VPS only). … RelayPack profile shipped with `iran-default` toolbox profile, all candidates `exposure_mode: direct_vps`."* — `daal-roadmap-v3-supplement-diaspora-helper.md` §21.1
**Supplement target:** v2.3.7 (text-lock-ready; version identifier is the durable pin, commit hash intentionally elided since it changes with each amendment).
**Engine version target:** `daal-core 0.9.0+v3-share` **(UNCHANGED — reconciliation phase).**
**ABI release surface target:** **48** **(UNCHANGED from 3F / 3-Soak).**
**Maturity:** track-entry gate. Phase 28 lands the FRP / RelayPack track into the existing phase system as the implementation arm of `daal-roadmap-v3-supplement-diaspora-helper.md`. It produces audit artifacts only; it does not produce engine code, Rust code, Tauri code, or Kotlin code.

## 1. Strategic frame (verbatim from the supplement)

> **§21 Phase placement — V1.5, V1.6, V2, V3 mapping.**
>
> §21.1 V1.5 — FRP MVP (direct-VPS only). Hetzner-only. Desktop only (Tauri). One-family-at-a-time. No cells. No federation. Direct VPS only — `cdn_fronted` candidates ship at V1.6.
>
> §21.2 V1.6 — CDN milestone. `cdn_fronted` candidates ship, with the §11.7 hardening template enforced. Cloudflare wizard path. Origin CA + Authenticated Origin Pulls + provider-firewall-locked-to-CF-edge-ranges + public-path-rewrite indirection. Mode-aware rotation UI (§14.4). Still Hetzner-only; still desktop-only; still no cells; still no federation. The new feature is exposure-mode diversity, not new providers or new trust scaling.
>
> §21.3 V2 — Trusted cells + federation primitives + multi-provider + mobile.
>
> §21.4 V3 — Public directory (gated).

The supplement is text-lock-ready (v2.3.7). Phase 28's job is to convert that text-lock into an executable phase queue.

## 2. Locked answers

| Question | Locked answer |
|---|---|
| FRP-track ordering | `FRP-0, FRP-1, FRP-2, FRP-3, FRP-4a, FRP-5, FRP-4b, FRP-6, FRP-7, FRP-7.5, FRP-8, FRP-9, FRP-10, FRP-11, FRP-12, FRP-13` (16 phases at prefixes `28..43`) |
| Audit depth | **Hybrid** — per-module summary table (15 rows) + per-file detail only where a gap is found |
| Track-spec shape | **Hybrid** — closure-record core (tabular, terse) + appendix with dependency graph and open-questions log |
| Evidence bar | **Command-output-backed** (matches `27-phase-3-soak-success-metric.handover.md` style; falsifiable) |
| Code in Phase 28 | **NONE.** No engine code, no Rust, no Tauri, no Kotlin, no test fixtures, no scenarios. `git diff --name-only` after Phase 28 ships must show only `phases of development/*.md`, `specs/frp-track-v1.md`, and the README. |
| `spec_version` bump | Lands at **FRP-1** (RelayPack spec + bundle schema), not FRP-0. |
| `freshness_url` slot | Additive in the same already-bumped `Manifest` slot at FRP-8; no further `spec_version` bump. |
| Closure records | `specs/v1-5-closure-v1.md` produced at FRP-7; `specs/v1-6-closure-v1.md` produced at FRP-9; `specs/cell-closure-v1.md` produced at FRP-11. Mirrors of `specs/v3-closure-v1.md`. |

## 3. Locked invariants (16)

1. **ABI surface stays 48.** No new release symbols. Verified at FRP-track exit; preserved phase-by-phase. Phase 28 verifies it currently holds via `nm libdaalcore.so | grep ' T engine_' | wc -l = 48`.
2. **Engine `Version` stays `daal-core 0.9.0+v3-share`.** Verified by `core/abi/abi.go:44` grep. The FRP track does not bump the engine `Version` constant; milestone tagging (V1.5, V1.6, V2, V3) lives in closure specs and packaging tags only.
3. **No new release symbols added at any FRP-N phase before FRP-1's `spec_version` bump.** Mode-aware shortlist + cooldown propagation hooks land inside existing engine surfaces, not as new exported functions.
4. **v2-superset stays 26; v3-superset stays 31; 3-Soak unaffected.** The FRP track introduces no new soak scenarios at Phase 28; later phases may add `--scenarios frp-superset` selectors but never modify v2/v3-superset rosters.
5. **Bundle format stays `.sbp`.** RelayPack is a *profile* of the existing format, not a new format. No new file-magic, no new container, no `.sbp2`.
6. **Per-candidate metadata destination is `RouteManifestEntry.FamilySpecificConfig._relaypack`** (the existing `json.RawMessage` opaque-JSON slot at `bundle/go/bundle/types.go:209`). FRP-1 lands the parser; FRP-2 lands the importer/store wiring. Round-trips cleanly through canonicalisation as raw bytes.
7. **Bundle-level new top-level `Manifest` slot is update-required at FRP-1.** The `spec_version` integer is bumped there, not earlier. The slot follows the established widening pattern (3A `kill_switches`, 3B `rendezvous_hints`, 3E `transport_modules`, 3F `redistribution_chain`/`delegate_caps`).
8. **`freshness_url` is additive within the same already-bumped slot at FRP-8** (no further `spec_version` bump). The supplement v2.3.7 §3.2 records this contract.
9. **Position B preserved.** No telemetry added by any FRP-N phase. The freshness endpoint is FRP-controlled, NOT a Daal-project endpoint; recipients poll opportunistically; no client-side analytics.
10. **`udp_gated` field reused** (no `udp_required` invented). The supplement explicitly preserves this convention from prior phases.
11. **No new transport-family enum values.** RelayPack candidates use existing transport families; the new schema is metadata around them.
12. **The supplement's v2.3.7 schema is the lock target.** `exposure_mode := direct_vps | cdn_fronted | serverless_external` (endpoint types only); `modifiers[]` is the orthogonal packet-mutation array (§12.2.2.bis).
13. **`modifiers[]` validator-rejected at V1.5 and V1.6** (FRP-1 through FRP-9 inclusive). FRP-12 is the framework that lets specific modifiers ship, per-kind, after censor-lab validation.
14. **FRP-12 modifier framework gates each modifier kind individually.** Per-kind feature flag + per-kind censor-lab pass record. Lifting the validator-reject is per-modifier, never blanket.
15. **FRP-13 (public directory) requires a closure record** (mirror of `specs/v3-closure-v1.md`) before it starts. Calendar-driven launch is the failure mode this prevents. Supplement §17.2's gate is the criterion.
16. **Phase 28 ships no executable code.** Verified by `git diff --name-only HEAD~1 HEAD` reviewing only the four track-entry files.

## 4. Sub-task breakdown (12 sub-tasks)

| #  | Task |
|----|------|
| 0  | Replace any prior FRP-0 stub with this locked spec at `phases of development/28-phase-frp-0-roadmap-reconciliation.md`. |
| 1  | Read the §6 required-reading list end-to-end. Roadmap, supplement (v2.3.7), this folder's README, the 27-phase-3-soak handover, the intel research note, the relevant core/bundle/import/store/path-manager/diagnostics/netmem code, the three client trees (`client-android/`, `client-desktop/`, `client-ios/`). |
| 2  | Produce per-module status matrix (15 rows). Schema in §5 below. Each row carries: present?, has-RelayPack-awareness?, gap-class, evidence command, gate-to-FRP-N. |
| 3  | For every row whose gap-class ≠ `none`, drill to per-file detail (specific paths + line numbers where the gap manifests). Per-file detail is the *only* place per-file granularity is required; rows with `gap-class: none` stop at module summary. |
| 4  | Produce missing-specs list with proposed paths: `specs/relaypack-v1.md` (FRP-1), `specs/selection-v1.md` (FRP-3), `specs/frp-track-v1.md` (FRP-0), `specs/cell-v1.md` (FRP-11), `specs/federation-primitives-v1.md` (FRP-11; per supplement §17.1 / §21.4 V2 deliverable), `specs/v1-5-closure-v1.md` (FRP-7), `specs/v1-6-closure-v1.md` (FRP-9), `specs/cell-closure-v1.md` (FRP-11), `specs/public-directory-v1.md` (FRP-13; supplement-blessed name — NO version-prefix). Plus the per-modifier framework reserved-slot docs at `specs/modifiers/_template.md`, `specs/modifiers/client_desync.md` (Linux-desktop only, PENDING), and `specs/modifiers/tls_fragment.md` (PENDING) (FRP-12). Each row: spec name, owning FRP-N phase, status (`missing` / `draft` / `locked`). |
| 5  | Produce missing-UI surfaces list. Desktop: FRP-5 wizard screens 0-6, FRP-6 trust prompt, "why this route" surface, RelayPack explanation, EN/FA copy. Android: recipient import flow, route-health surface, rotation banner, RelayPack explanation. iOS: post-V3 placeholder confirming nothing is owed at V1.5/V1.6. |
| 6  | Produce invariant-preservation table. For every locked invariant in §3, the command + expected output that proves it currently holds. Captured into the handover with actual command outputs. Examples: `nm libdaalcore.so | grep ' T engine_' | wc -l` → `48`; `grep -E '^const Version' core/abi/abi.go` → `Version = "daal-core 0.9.0+v3-share"`; `ls bundle/go/bundle/types.go` shows the file at the cited line; `git grep -n udp_gated bundle/go/bundle/` confirms reuse. |
| 7  | Lock FRP-1..FRP-13 sequence — fill `specs/frp-track-v1.md` (hybrid shape) using the user's revised order: FRP-0, FRP-1, FRP-2, FRP-3, FRP-4a, FRP-5, FRP-4b, FRP-6, FRP-7, FRP-7.5, FRP-8, FRP-9, FRP-10, FRP-11, FRP-12, FRP-13. Each phase row carries: roadmap line, scope summary, exit criteria summary, what-it-locks-for-next-phase. |
| 8  | Produce dependency graph (Mermaid `flowchart`) showing the cross-phase edges. At minimum: FRP-2 → FRP-3 (contract test vector at `specs/test-vectors/relaypack/`); FRP-3 → FRP-6 (`Explanation` struct binds UI); FRP-5 → FRP-4b (publisher key + `freshness_url` slot binds deploy); FRP-7 → FRP-7.5 → FRP-8 (V1.5 ships, sub-key chain hardens, V1.6 starts); FRP-9 → FRP-10 (V1.6 closure gates V2 multi-provider); FRP-11 → FRP-13 (cell closure record gates public directory). |
| 9  | Open-decisions log — at minimum 6 questions to lock before each downstream phase starts. Examples: spec_version target integer; exact `Manifest`-slot field name (`relay_pack`? `relaypack`? `relay_pack_v1`?); freshness JSON schema details; FRP-7 pilot recruitment count and selection criteria; first post-track modifier to lift validator-reject for (post-FRP-12 follow-on phase; FRP-12 itself ships zero PASS records); FRP-13 directory gate criteria. Each question: status `open` / `locked` / `deferred` and target phase to resolve. |
| 10 | Update `phases of development/README.md` — add 16 lines to the *Phase Order* list mapping prefixes `28..43` to FRP-0..FRP-13. Additive only; existing rows unchanged. Add a paragraph clarifying the FRP track is a continuation of the closed V3 surface. |
| 11 | Write the handover at `phases of development/28-phase-frp-0-roadmap-reconciliation.handover.md` with command-output evidence for §3 invariants and the §4.6 invariant-preservation table. |
| 12 | Final review: confirm zero code touched (`git diff --name-only` shows only the four track-entry files); produce go/no-go verdict on FRP-1 (`PASS` / `HOLD` / `BLOCKED`). |

## 5. Per-module status matrix template

The matrix sub-task 4.2 produces. 15 rows minimum.

| Module path | Present? | Has RelayPack awareness? | Gap class | Evidence command | Gate to FRP-N |
|---|---|---|---|---|---|
| `bundle/go/bundle/` | y/n | y/n | none / metadata-strip / missing-spec / missing-UI / missing-feature | shell command + expected output | FRP-1 |
| `bundle/go/importer/` | y/n | y/n | … | `ls bundle/go/importer/` | FRP-2 |
| `bundle/go/publisher/` | y/n | y/n | … | … | FRP-1, FRP-4a |
| `core/abi/` | y/n | y/n | … (engine `Version` constant lives at `core/abi/abi.go:44`; auto-promotion at `core/abi/auto_promotion.go`) | `grep -E '^const Version' core/abi/abi.go` | FRP-2, FRP-3 |
| `core/trust/` | y/n | y/n | … (`StoreAdapter` boundary in `state.go`; no `migrations/` subdir — schema is inline) | `ls core/trust/` | FRP-2 |
| `core/routestore/` | y/n | y/n | … (where `RouteRow` actually lives at `store.go:127`; inline schema at `schema.go:7`) | `ls core/routestore/` | FRP-2 |
| `core/pathmanager/` | y/n | y/n | … (package name is `pathmanager`, NO hyphen) | `ls core/pathmanager/` | FRP-3 |
| `core/budget/` | y/n | y/n | … | … | FRP-3 |
| `core/diagnostics/` | y/n | y/n | … | … | FRP-3, FRP-6 |
| `core/netmem/` | y/n | y/n | … (`store.go` + `snapshot.go` — encrypted-KV pattern via `core/keyvault/`) | `ls core/netmem/` | FRP-2, FRP-3 |
| `publisher/deploy/` | y/n (expected: NO) | y/n | missing-feature | `ls publisher/deploy/ 2>&1` | FRP-4a, FRP-10 |
| `publisher/cell/` | y/n (expected: NO) | y/n | missing-feature | `ls publisher/cell/ 2>&1` | FRP-11 |
| `client-android/` | y/n | y/n | … | … | FRP-6, FRP-10 |
| `client-desktop/tauri/` | y/n | y/n | … (Tauri layout: `tauri/src/` JS + `tauri/src-tauri/` Rust) | `ls client-desktop/tauri/` | FRP-5, FRP-6 |
| `client-ios/` | y/n | y/n | placeholder (post-V3 per supplement §21.5) | `ls client-ios/` | post-V3 |
| `specs/` | y | n | missing-spec | `ls specs/relaypack-v1.md specs/selection-v1.md 2>&1` | FRP-1, FRP-3 |
| `test-rigs/` | y | n | missing-fixture | `ls specs/test-vectors/relaypack/ 2>&1` | FRP-2 |

Gap classes:
- **`none`** — module exists, has RelayPack awareness, no work owed at any FRP-N.
- **`metadata-strip`** — module exists but drops fields the supplement requires (e.g. importer that loses `_relaypack`).
- **`missing-spec`** — module exists but the spec naming its contract does not.
- **`missing-UI`** — module exists at the data layer but no user-facing surface yet.
- **`missing-feature`** — module is absent end-to-end and an FRP-N phase must create it.

## 6. Required reading

Audit reads (in order):

1. `/home/daal/daal-roadmap-v3.md` — strategic source of truth.
2. `/home/daal/daal-roadmap-v3-supplement-diaspora-helper.md` — v2.3.7 supplement, the FRP track's primary input.
3. `/home/daal/phases of development/README.md` — phase-system convention.
4. `/home/daal/phases of development/27-phase-3-soak-success-metric.handover.md` — closure of V3-share; locks ABI=48 and engine `Version`.
5. `/home/daal/research/intel-and-some-working-methods.md` — field-technique intel; informs FRP-12 modifier framework gating.
6. Core code:
   - `/home/daal/bundle/go/bundle/` — `.sbp` parser, signer, canonical, `RouteManifestEntry`, `Manifest`. Specifically `bundle/go/bundle/types.go:209` for the `FamilySpecificConfig` slot. Parse + verify entry points at `bundle/go/bundle/sbp.go` (`ParseSBP` line 32, `VerifyBundle` line 137).
   - `/home/daal/bundle/go/importer/` — `.sbp` → store import path; FRP-2 widens this.
   - `/home/daal/bundle/go/publisher/` — publisher CLI primitives.
   - `/home/daal/core/abi/` — release surface; engine `Version` constant at `core/abi/abi.go:44`; auto-promotion at `core/abi/auto_promotion.go`.
   - `/home/daal/core/trust/` — `StoreAdapter` boundary at `state.go` (NOT `RouteRow`'s home; FRP-2 extends this interface with a `*RelayPackMeta` parameter).
   - `/home/daal/core/routestore/` — `RouteRow` actually lives here at `store.go:127`; inline schema at `schema.go:7`. NO `core/trust/migrations/` subdir exists; schema is inline per the codebase pattern.
   - `/home/daal/core/pathmanager/` — selection primitives (`family.go`, `fsm.go`); package name is `pathmanager`, NO hyphen.
   - `/home/daal/core/budget/` — 2A byte budget engine; informs FRP-3.
   - `/home/daal/core/diagnostics/` — `engine_export_diagnostics`; informs FRP-3 `Explanation` shape.
   - `/home/daal/core/netmem/` — 2C network memory (`store.go` + `snapshot.go`, encrypted-KV via `core/keyvault/`); FRP-2 widens the entry-value shape, NOT a parallel SQLite table.
7. Client code (module-level read; per-file only where a gap surfaces):
   - `/home/daal/client-android/`
   - `/home/daal/client-desktop/tauri/` (Tauri layout: `tauri/src/` JS + `tauri/src-tauri/` Rust).
   - `/home/daal/client-ios/`
8. Existing specs to confirm cross-references resolve:
   - `/home/daal/specs/sbp-v1.md`, `/home/daal/specs/engine-abi-v1.md`, `/home/daal/specs/v3-closure-v1.md`, `/home/daal/specs/blackout-soak-rig-v1.md`, `/home/daal/specs/transport-families-v1.md`, `/home/daal/specs/scheduler-v1.md`, `/home/daal/specs/route-budgets-v1.md`, `/home/daal/specs/android-client-v1.md`, `/home/daal/specs/publisher-cli-v1.md`.

## 7. Out of scope (deferred to FRP-1+)

- **No `spec_version` bump.** FRP-1's job.
- **No content for `specs/relaypack-v1.md` beyond the empty stub.** FRP-1's job.
- **No content for `specs/selection-v1.md`.** FRP-3's job.
- **No engine code, Rust code, Tauri code, Kotlin code, Swift code.**
- **No UI work.**
- **No test fixtures, scenarios, or vectors.** `specs/test-vectors/relaypack/` is FRP-2.
- **No actual gap fixes.** Phase 28 surfaces gaps; downstream phases close them. If the audit reveals a gap not anticipated by the supplement, it is recorded in the open-decisions log, not fixed in Phase 28.

## 8. Build matrix at FRP-0 exit

Phase 28 produces no compiled artifacts. Exit gate is *the audit artifacts exist and the FRP-1 gate verdict is recorded*. The build matrix is purely file-existence + git checks:

```
$ ls "phases of development/28-phase-frp-0-roadmap-reconciliation.md"     # exists
$ ls "phases of development/28-phase-frp-0-roadmap-reconciliation.handover.md"  # exists, populated
$ ls specs/frp-track-v1.md                                                # exists, populated
$ git diff --name-only
phases of development/28-phase-frp-0-roadmap-reconciliation.handover.md
phases of development/28-phase-frp-0-roadmap-reconciliation.md
phases of development/29-phase-frp-1-relaypack-schema.md
specs/frp-track-v1.md
$ # no executable code touched; verified
```

The handover-side regression sweep additionally captures the §3 invariant commands' actual outputs (matching `27-phase-3-soak-success-metric.handover.md` *Final regression sweep* shape).

## 9. Spec deliverables

**1 NEW:**
- `specs/frp-track-v1.md` — closure-record core + dependency-graph appendix + open-decisions appendix.

**0 AMENDED.** (FRP-N phase docs do not yet exist; nothing to amend.)

The supplement (`daal-roadmap-v3-supplement-diaspora-helper.md`) is **NOT amended** by Phase 28. It is the input, not the output. If the audit surfaces something the supplement got wrong, it goes into Phase 28's open-decisions log, and the supplement is amended in a separate v2.3.7 patch — not in Phase 28's commit.

## 10. Handover requirements

The handover at `phases of development/28-phase-frp-0-roadmap-reconciliation.handover.md` must contain:

1. **Status:** `SHIPPED` (or `LOCKED, NOT YET SHIPPED` if the audit work has not run).
2. **Per-module matrix** populated end-to-end (15+ rows; gap-class assigned to each).
3. **Per-file detail** for every row with `gap-class ≠ none`.
4. **Missing-specs list** with FRP-N ownership.
5. **Missing-UI list** with FRP-N ownership.
6. **Invariant-preservation table** with actual command outputs for all 16 §3 invariants.
7. **Dependency graph** (Mermaid render).
8. **Open-decisions log** with status and target-phase-to-resolve for each entry.
9. **Files added / modified** block (mirror of 27-phase-3-soak handover).
10. **Final regression sweep** (file-existence + git checks; the §8 build matrix output).
11. **FRP-1 gate verdict** — `PASS` / `HOLD` / `BLOCKED` with one-paragraph justification.
12. **Next phase** pointer to FRP-1.

## 11. Track ordering rationale

The user's revised order is:

```
FRP-0  audit
FRP-1  RelayPack spec + bundle schema   (spec_version bumps here)
FRP-2  importer + store preservation     (lands the metadata that FRP-3 will read)
FRP-3  selection brain + Explanation     (binds the data layer; locks UI contract)
FRP-4a publisher deploy core             (provider/deploy/health/cloud-init; no key binding yet)
FRP-5  desktop wizard                    (generates publisher key + reserves freshness URL slot)
FRP-4b direct-mode deploy integration    (binds wizard's keys to deploy-core; signs direct RelayPack)
FRP-6  recipient UX                      (binds to FRP-3 Explanation struct)
FRP-7  rotation + V1.5 pilot soak        (produces specs/v1-5-closure-v1.md)
FRP-7.5 publisher sub-key cert chain     (hardens long-running FRP key hygiene before V1.6 expands surface)
FRP-8  V1.6 CDN + freshness endpoint     (cdn_fronted ships; freshness_url is additive)
FRP-9  V1.6 CDN soak                     (produces specs/v1-6-closure-v1.md)
FRP-10 V2 multi-provider + mgmt API
FRP-11 trusted cells + federation        (produces specs/cell-closure-v1.md)
FRP-12 field-tech modifier framework     (per-modifier flag + censor-lab gate)
FRP-13 public directory                  (gated; requires cell-closure-v1.md)
```

The non-obvious ordering choices and their justifications:

- **FRP-4a → FRP-5 → FRP-4b** (split publisher deploy). The wizard generates the publisher key. Deploy needs the key to sign the RelayPack. Splitting deploy lets deploy-core land independently (provider interface, Hetzner adapter, cloud-init template, health endpoint) while the key-binding step (4b) waits for the wizard to ship.
- **No freshness service at V1.5.** The supplement is explicit (§21.1, §21.2): V1.5 is direct-VPS only; the freshness endpoint is V1.6 (FRP-8). The wizard at FRP-5 reserves the `freshness_url` slot so it round-trips through canonicalisation, but no FRP infrastructure publishes to it until FRP-8.
- **FRP-7.5 between V1.5 ship and V1.6 start.** Phase 1A's handover (`04-phase-1a-publisher-cli.handover.md`) flagged "bundle-go cert chain" as a deferred Phase 1.5 candidate. Long-running FRPs *will* rotate sub-keys; without verifier-side cert chain that requires root-key touches in the field. FRP-7.5 is the right phase to fix that — after V1.5 ships (so the bug is real), before V1.6 expands the deploy surface (so we don't compound it).
- **FRP-12 before FRP-13.** Modifiers are post-V2 per the supplement (§11.6, §12.2.2.bis). The framework that lets each modifier kind opt-in (with feature flag + censor-lab pass record) must exist before the public directory ships, because the directory is the place modifier-bearing RelayPacks would be most exposed to abuse.
- **FRP-13 requires `specs/cell-closure-v1.md`** (FRP-11's output). This mirrors how V3 required `specs/v3-closure-v1.md` before V4 unblocked. Calendar-driven launch is the failure mode this prevents; supplement §17.2's gate is the criterion.

End — locked at FRP-track kickoff. Next session: execute §4 sub-tasks.
