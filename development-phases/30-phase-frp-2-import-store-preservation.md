# Phase 30 (FRP-2) — Import + Store Preservation

**Status:** SHIPPED on 2026-05-02. FRP-3 gate verdict: **PASS**. Handover at `30-phase-frp-2-import-store-preservation.handover.md`.
**Roadmap line:** *"Generic import path drops V3 metadata. `RouteRow` has fields for MASQUE, Psiphon, Conjure, WASM, rendezvous, redistribution; the import path may not preserve the v2.3.4 mode-aware tag arrays into `RouteRow`. The RelayPack import lands these fields in the store."* — `daal-roadmap-v3-supplement-diaspora-helper.md` §13.6
**Supplement target:** v2.3.7.
**Engine version target:** `daal-core 0.9.0+v3-share` **(UNCHANGED — store-widening phase).**
**ABI release surface target:** **48** **(UNCHANGED — `RouteRow` is internal; store widening adds columns, not release symbols).**
**Maturity:** code phase. Closes one of the three V1.5 code-side gaps named in supplement §13.6.
**Predecessor:** Phase 29 (FRP-1) — must lock the `_relaypack` and `relay_pack` shapes.
**Successor:** Phase 31 (FRP-3) — consumes the `RouteRow` extensions to drive mode-aware shortlist + cooldown.

## 1. Strategic frame (verbatim from the supplement)

> **§13.6 Code gaps to close.** The current code has the foundation but not the full pipeline. The supplement commits to closing three specific gaps in V1.5: (1) Generic import path drops V3 metadata. The import path may not preserve the mode-aware tag arrays into `RouteRow`. The RelayPack import lands these fields in the store. The selector's mode-aware rules are wired up at V1.5 even though only `direct_vps` candidates exist. (2) Direct `trojan://` and `vmess://` imports become `other`. Acceptable for FRP-emitted RelayPacks. (3) Normal mode does not yet weigh per-network success memory. V1.5 brings normal mode in line so per-network winners (now keyed on `family × exposure_mode × public_risk_tag_signature`) influence the shortlist in ordinary use.

FRP-2's job is gap (1) and (3): widen the importer (`bundle/go/importer/importer.go` and the `StoreAdapter` boundary in `core/trust/state.go`), widen `RouteRow` (which lives in `core/routestore/store.go` per the actual codebase, NOT in `core/trust/`), update the inline schema in `core/routestore/schema.go`, extend the per-network memory layer in `core/netmem/` (NOT a parallel SQLite table — see §2 below), seed the contract test corpus at `specs/test-vectors/relaypack/` that FRP-3 will consume. **Gap (2) is filed for V2 generic-subscription work** and is out of scope for FRP-2. **No selector logic.** FRP-3 wires consumers.

## 2. Locked answers

| Question | Locked answer |
|---|---|
| Import path location | `bundle/go/importer/importer.go` (parse) → `core/trust/state.go` `StoreAdapter` interface (insertion boundary) → `core/routestore/store.go` `RouteRow` (storage struct) → `core/routestore/schema.go` (inline migration helpers; the codebase does NOT use a separate `core/trust/migrations/` directory — schema lives inline in `schema.go`). |
| `RouteRow` fields to add | `ExposureMode`, `FamilyClass`, `ProbingRiskClass`, `PublicRiskTags []string`, `OriginRiskTags []string`, `Modifiers []byte` (raw JSON; reserved post-V2; importer rejects non-empty per FRP-1 RP013), `RelayPackID`, `FreshnessURL` (empty at V1.5; populated at V1.6 import). |
| `RouteRow` migration shape | Additive columns; sentinel-empty defaults (`''` / `'[]'`) matching the existing 3A–3F additive-ALTER pattern. Pre-existing rows have empty/sentinel values in the new columns; RelayPack-aware code paths treat empty as "non-RelayPack route" and fall through to the legacy selector path (preserves FRP-1 invariant 23: old bundles keep working). **Amended at FRP-2 execution:** earlier draft language said "NULL"; the codebase pattern is sentinel-empty `NOT NULL` defaults, not true SQL NULL. |
| Schema migration mechanism | Inline in `core/routestore/schema.go` (matches the codebase's existing pattern). FRP-2 adds an `addRelayPackFieldsV1` migration step that runs once on first open of an existing DB; the `routestore` package's existing migration sequence handles forward-compat. **No separate `core/trust/migrations/` directory** — that path does not exist; the docs's previous reference was wrong. |
| Importer behavior on validator error | Hard reject the bundle. The user-facing surface (FRP-6) shows the validator's lint code from `specs/relaypack-v1.md` codebook. |
| Importer behavior on legacy non-RelayPack `.sbp` | Unchanged. Bundle imports normally; `RouteRow` new columns hold sentinel-empty values (`''` / `'[]'`); selector falls through to legacy path. |
| Test-vector corpus expansion | FRP-1 seeded 6 vectors. FRP-2 expands to ≥16 (round-trip cases, importer rejection cases, store schema migration cases, including the RP021 freshness-url gate). |
| Per-network memory key extension | **Extends `core/netmem/store.go` (the existing netmem layer), NOT a new SQLite `network_memory_v2` table.** Daal's pattern favours keyvault / private state for network memory; the existing netmem `store.go` is an encrypted KV (`core/keyvault/`-backed). FRP-2 widens the netmem entry value shape to include the new key components `(family, exposure_mode, public_risk_tag_signature)` while preserving the existing `network_hash` outer key. Backward compat: legacy entries (without the new components) read back as wildcards on the new dimensions; FRP-3's selector treats them as fall-through hints. |
| `tofu_friend` interaction | Untouched. RelayPack fields are orthogonal to trust-state machinery. |
| Re-import idempotence | Re-importing the same `.sbp` produces the same `RouteRow` rows (no duplicates, no field churn). Verified by an importer fixture test. |
| Netmem schema extension | Lazy. Existing netmem entries decoded with the legacy shape continue to work; new writes carry the extended value shape; readers (FRP-3 selector) prefer entries with matching `public_risk_tag_signature` when present, fall back to legacy entries otherwise. No data deletion; no parallel table. |

## 3. Locked invariants

Tracks invariants 1–16 inherited from `28-phase-frp-0-roadmap-reconciliation.md` §3. Phase-specific:

17. **No release symbols added.** All work is store-internal; ABI count stays 48.
18. **`RouteRow` widening is additive.** Existing columns unchanged in shape and semantics.
19. **SQLite migration is reversible.** A `DOWN` script exists; covered by a test that round-trips `UP → DOWN → UP`.
20. **Re-import idempotence preserved.** Importing the same bundle twice produces equal row sets.
21. **Old bundles keep working.** A non-RelayPack `.sbp` imports unchanged; new columns hold sentinel-empty values (`''` / `'[]'`); selector falls through to legacy path (verified by a fixture in `specs/test-vectors/relaypack/legacy-non-relaypack.sbp`).
22. **`ModifiersJSON` column exists at the store layer as canonical-JSON TEXT (`modifiers_json`).** Codebase-convention naming; no struct exposed to the selector (per FRP-1 RP013 the validator hard-rejects non-empty modifiers at V1.5; the column holds `''` at V1.5/V1.6). FRP-12 adds the consumer.
23. **Position B preserved.** Importer never opens a network connection; freshness URL is recorded as a string only, not fetched at import time. Verified by `opsec_test.go` grep.
24. **Test-vector corpus is the contract.** FRP-3 consumes the corpus FRP-2 produces; any importer change in a later phase that breaks a vector is a contract violation.

## 4. Sub-task breakdown

| #  | Task |
|----|------|
| 0  | Replace any prior FRP-2 stub with this locked spec at `phases of development/30-phase-frp-2-import-store-preservation.md`. |
| 1  | Read inputs end-to-end: FRP-0 handover §"Per-module matrix" entries for `bundle/go/importer/`, `core/trust/`, `core/routestore/`, `core/netmem/`; supplement §13.6; FRP-1 handover (canonical `_relaypack` shape); existing schema in `core/routestore/schema.go`; existing netmem layout in `core/netmem/store.go` + `snapshot.go`. |
| 2  | Confirm the actual call graph from `.sbp` parse → `bundle/go/importer/importer.go` → `core/trust/state.go` `StoreAdapter` → `core/routestore/store.go` `RouteRow` insertion. (FRP-0 names paths; FRP-2 verifies and narrows.) |
| 3  | Extend the inline schema in `core/routestore/schema.go`: append 9 forward-only `ALTER TABLE … ADD COLUMN … TEXT NOT NULL DEFAULT '…'` entries to the existing `migrations` slice (sentinel-empty defaults; mirrors 3A–3F). Idempotent on re-open per the existing ALTER-IGNORE pattern. |
| 4  | Extend `RouteRow` struct in `core/routestore/store.go` with the 9 fields (per §5 below). Bundle-level metadata (`RelayPackID`, `FreshnessURL`, `SharedRiskGraphJSON`) is denormalised onto every per-route row for read-locality at the FRP-3 selector boundary. |
| 5  | Extend the importer call site (`bundle/go/importer/importer.go`) to: call **`bundle/go/relaypackvalidate.Validate(parsed, ValidateOpts{Phase: PhaseV15})`** **once per bundle, unconditionally, after `VerifyBundle` and before the first-seen trust prompt** (this catches RP001 = route-level `_relaypack` with no bundle slot). Reuse the same helper inside the persistence path as a defensive guard for direct `AcceptTrustPrompt` callers. On `*ValidationError`, return `VerdictRejected` with `Reason = "relaypack_" + code`. Then, when `Manifest.RelayPack != nil`, call `bundle.ParseRelayPackEntry(r.FamilySpecificConfig)` per route and build a `RelayPackMeta` carrying both per-candidate fields and bundle-level fields denormalised from `parsed.Manifest.RelayPack`. Pass the meta through the existing `RouteInput`. |
| 6  | Extend `RouteInput` in `bundle/go/importer/` with `RelayPack *RelayPackMeta` (nullable). Extend `core/trust/state.go::SaveImport` to copy the 9 fields onto the constructed `RouteRow` when non-nil. The `SaveImport` and other `StoreAdapter` method signatures are unchanged (the new field is on the per-route input struct). Selector reads via the existing `GetRoute` (no new method needed). |
| 7  | Idempotence test: import the same `.sbp` twice; assert equal row sets including new RelayPack columns. |
| 8  | Schema-extension test: open a legacy DB (no RelayPack columns); confirm migration runs idempotently; insert RelayPack rows; confirm round-trip read returns identical bytes; close DB; re-open with same code; confirm no double-migration. |
| 9  | Expand `specs/test-vectors/relaypack/` to ≥16 vectors. Add: `legacy-non-relaypack.sbp` (no `_relaypack`); `mixed-relaypack-direct-only.sbp` (3 direct_vps siblings, single VPS); `mixed-relaypack-direct-and-cdn.sbp` (V1.6 candidate; importer must reject at V1.5 phase); `idempotent-reimport.sbp` (same bundle imported twice); plus importer-rejection cases for validator lint codes including RP021. Each with `.expected.json` describing post-import state. |
| 10 | Per-network memory schema extension. Extend the netmem entry value in `core/netmem/snapshot.go` with the optional `(family, exposure_mode, public_risk_tag_signature)` triplet. Backward-compat: legacy entries (decoding without the triplet) still parse cleanly. Add fixture test: legacy entries readable; new entries written; mixed reads work. |
| 11 | OPSEC test: extend or add `core/routestore/import_opsec_test.go` ensuring no `net/http` / `net.Dial` / `http.Client` references in the routestore + importer code paths. (FRP-2 must preserve the property `04-phase-1a-publisher-cli.handover.md` §"Decisions worth carrying forward" point 5 established for `daal-publish`.) |
| 12 | Final regression sweep: `cd bundle/go && go build ./... && go test ./bundle/...`; `cd core && go build ./... && go test ./routestore/... ./trust/... ./netmem/...`; `nm` returns 48; engine `Version` UNCHANGED; all 16 vectors green; FRP-3 gate verdict; handover written. |

## 5. `RouteRow` extension (locked, FRP-2 amended)

```go
// core/routestore/store.go - additive fields at end of RouteRow:
type RouteRow struct {
    // ... existing fields preserved ...

    // RelayPack profile (added v1.5 / FRP-2). All sentinel-empty for
    // non-RelayPack routes (codebase convention; matches 3A–3F).
    ExposureMode        string   // exposure_mode             — '' for non-RelayPack
    FamilyClass         string   // family_class              — '' for non-RelayPack
    ProbingRiskClass    string   // probing_risk_class        — '' for non-RelayPack
    PublicRiskTags      []string // public_risk_tags_json     — '[]' default
    OriginRiskTags      []string // origin_risk_tags_json     — '[]' default
    ModifiersJSON       string   // modifiers_json            — canonical JSON of []Modifier; '' at V1.5/V1.6
    RelayPackID         string   // relay_pack_id             — bundle-level, denormalised
    FreshnessURL        string   // freshness_url             — bundle-level, denormalised; '' at V1.5 (RP021 enforced upstream)
    SharedRiskGraphJSON string   // shared_risk_graph_json    — bundle-level, canonical JSON of []SharedRiskEdge; '[]' default
}
```

**Naming note (deviation from the planning draft):** the field for the modifiers blob is `ModifiersJSON string` (not `Modifiers []byte`). This matches the codebase's existing opaque-JSON column convention (`FamilySpecificConfigJSON`, `RendezvousPriorityJSON`, `ConjurePhantomSubnetsJSON`, `ConjureDecoyPoolJSON`).

**Bundle-level vs per-candidate.** Three of the nine fields are bundle-level metadata read from `Manifest.RelayPack`: `RelayPackID`, `FreshnessURL`, `SharedRiskGraphJSON`. The importer denormalises them onto every per-route `RouteRow` so the FRP-3 selector reads them locally without a join. (Mirrors the 3F pattern of denormalising publisher-declared `redistribution_policy` per route.)

The `[]string` fields and `SharedRiskGraphJSON` are stored as canonical-JSON-encoded TEXT in SQLite (consistent with how `core/routestore/store.go` already handles tag-shaped columns).

A separate `RelayPackMeta` struct lives in `bundle/go/importer/` so the bundle-side parser produces it and legacy callers do not need to know about RelayPack fields:

```go
// bundle/go/importer/importer.go
type RelayPackMeta struct {
    ExposureMode        string
    FamilyClass         string
    ProbingRiskClass    string
    PublicRiskTags      []string
    OriginRiskTags      []string
    ModifiersJSON       string
    RelayPackID         string   // bundle-level; same value on every candidate
    FreshnessURL        string   // bundle-level; same value on every candidate; '' at V1.5
    SharedRiskGraphJSON string   // bundle-level; same value on every candidate
}

// RouteInput is extended with a nullable *RelayPackMeta (nil = legacy path).
type RouteInput struct {
    // ... existing fields ...
    RelayPack *RelayPackMeta
}
```

The `core/trust/state.go::SaveImport` signature is unchanged. It reads `r.RelayPack` from each `RouteInput` and copies the 9 fields onto the constructed `RouteRow` when non-nil; `nil` produces all-zero (sentinel-empty) values.

## 6. Netmem entry-value extension (locked — extends `core/netmem/`, NOT a new SQLite table)

The existing netmem store at `core/netmem/store.go` keys entries on a network hash and persists encrypted-KV values via `core/keyvault/`. FRP-2 widens the entry value shape:

```go
// core/netmem/snapshot.go - additive fields on the entry value struct:
type Entry struct {
    // ... existing fields preserved ...

    // RelayPack-aware memory (added v1.5 / FRP-2)
    Family                  string  // optional; "" = legacy
    ExposureMode            string  // optional; "" = legacy
    PublicRiskTagSignature  string  // canonical-sorted comma-joined; "" = legacy
    Outcome                 string  // success | classified_failure; "" = legacy
}
```

`PublicRiskTagSignature` is the canonical-sorted-and-joined `public_risk_tags[]` of the candidate that produced the outcome, computed by FRP-3's selector at write time. Backward compat: legacy entries decode with empty strings on the new fields; FRP-3's reader treats those as wildcard-match fall-through hints. No data migration; no parallel table.

## 7. Test-vector corpus (locked, FRP-2 expansion)

Total = 16 vectors. Each is `{name}.sbp` + `{name}.expected.json` describing the cross-phase validator outcome.

| Vector | Mode | Purpose |
|---|---|---|
| `direct-vps-minimal` (FRP-1 seed) | direct_vps | minimal positive case |
| `direct-vps-with-sni` (FRP-1 seed) | direct_vps | with `sni:*` and `public_domain:*` (allowed per RP008-009) |
| `cdn-fronted-minimal` (FRP-1 seed) | cdn_fronted | minimal positive case at V1.6 |
| `cdn-fronted-with-origin` (FRP-1 seed) | cdn_fronted | with full `origin_*` set |
| `modifier-rejected` (FRP-1 seed) | any | non-empty `modifiers[]`; RP013 rejection |
| `legacy-flat-tags-rejected` (FRP-1 seed) | n/a | pre-v2.3.4 schema; RP017 rejection |
| `legacy-non-relaypack` (FRP-2 new) | n/a | `.sbp` without `_relaypack`; imports normally; new columns sentinel-empty |
| `mixed-relaypack-direct-only` (FRP-2 new) | direct_vps | single-VPS V1.5 default; 3 candidates sharing `public_ip:*` |
| `mixed-relaypack-direct-and-cdn` (FRP-2 new) | mixed | V1.6 candidate; importer rejects at `Phase: V15` (RP004) |
| `idempotent-reimport` (FRP-2 new) | direct_vps | same bundle imported twice; row count unchanged |
| `cdn-fronted-no-cdn-tag-rejected` (FRP-2 new) | cdn_fronted | RP005 (V1.6) / RP004 (V1.5) rejection |
| `cdn-fronted-no-origin-tag-rejected` (FRP-2 new) | cdn_fronted | RP006 (V1.6) / RP004 (V1.5) rejection |
| `direct-vps-with-cdn-tag-rejected` (FRP-2 new) | direct_vps | RP009 rejection |
| `direct-vps-with-origin-tag-rejected` (FRP-2 new) | direct_vps | RP010 rejection |
| `single-candidate-relaypack-rejected` (FRP-2 new) | direct_vps | one candidate; RP014 rejection (≥2 vps-native required) |
| `bundle-with-freshness-url-v15-rejected` (FRP-2 new) | direct_vps | non-empty `Manifest.relay_pack.freshness_url` at V1.5; RP021 rejection (lifted at V1.6 by FRP-8) |

## 8. Build matrix at FRP-2 exit

```
$ cd bundle/go && go build ./relaypackvalidate/... ./importer/... # green
$ cd bundle/go && go test  ./relaypackvalidate/... ./importer/... # green; validator 40 + 24 = 64 sub-tests + new importer tests
$ cd core && go build ./routestore/... ./trust/... ./netmem/...   # green
$ cd core && go test  ./routestore/... ./trust/... ./netmem/...   # green; new RouteRow + netmem + import tests
$ cd publisher && go test ./...                                   # green; publisher CLI updated to neutral validator
$ ls specs/test-vectors/relaypack/*.sbp | wc -l                   # 16
$ nm /tmp/libdaalcore.so | grep ' T engine_' | wc -l             # 48 (UNCHANGED)
$ grep -E '^const Version' core/abi/abi.go                        # daal-core 0.9.0+v3-share (UNCHANGED)
$ # Schema-extension check (9 new columns)
$ sqlite3 /tmp/test.db ".schema routes" | grep -cE 'exposure_mode|family_class|probing_risk_class|public_risk_tags_json|origin_risk_tags_json|modifiers_json|relay_pack_id|freshness_url|shared_risk_graph_json'   # 9
$ # No parallel netmem SQLite table
$ sqlite3 /tmp/test.db ".tables" | grep -i network_memory         # NO network_memory_v2
$ # Asymmetric guards intact
$ ! rg -n 'daal/publisher' bundle/go/                            # exit non-zero
$ ! rg -n 'daal/publisher' core/                                 # exit non-zero
$ # OPSEC: no network on import path
$ ! rg -nE 'net\.Dial|http\.Client|"net/http"' bundle/go/importer/ core/trust/ core/routestore/ --type go --glob '!*_test.go'  # exit non-zero
```

## 9. Spec deliverables

**0 NEW.** (`specs/test-vectors/relaypack/` is a corpus; FRP-1 created the directory.)

**1 AMENDED:**
- `specs/relaypack-v1.md` — gains a §"Importer behaviour" section documenting the FRP-2 rules (idempotence, lazy migration of legacy rows, reject-on-validator-error before first trust prompt, sentinel-empty columns for non-RelayPack bundles).

## 10. Out of scope (deferred)

- Selector consumption of the new columns — **FRP-3.**
- Generic-subscription `trojan://` / `vmess://` parsing fix — supplement §13.6 gap (2); deferred to V2 generic-subscription work.
- UI surfaces (importer error display, RelayPack-aware route browser) — **FRP-6.**
- `freshness_url` consumer (polling, signature verification) — **FRP-8.**
- `cell_scope` consumer — **FRP-11.**
- Modifier consumer — **FRP-12.**
- Any deletion / cleanup of pre-RelayPack netmem entries — never. They are wildcard-readable forever.

## 11. Handover requirements

The FRP-2 handover must contain:

1. Status: SHIPPED. Date.
2. New `RouteRow` columns enumerated.
3. Netmem entry-value extension diff attached (extends `core/netmem/snapshot.go`; no parallel table).
4. Routestore inline-schema extension test result; first-open migration runs once and is idempotent on re-open.
5. Test-vector count (≥16); per-vector pass / fail / expected-rejection.
6. Importer OPSEC grep result (zero `net.Dial` / `http.Client` matches outside `_test.go`).
7. `nm` count = 48 unchanged.
8. Idempotence test result.
9. FRP-3 gate verdict.
10. Open follow-ups: any field FRP-3 will need that FRP-2 missed; any selector hook the `StoreAdapter` interface should expose that's not yet there.

## 12. Track ordering rationale

FRP-2 between FRP-1 and FRP-3 because the schema (FRP-1) has to land before the store widens (FRP-2), and the store (FRP-2) has to widen before the selector (FRP-3) can consume the new fields. Skipping FRP-2 and letting FRP-3 build the selector against in-memory test fixtures (no real importer/store path) was considered and rejected: the supplement §13.6 specifically calls "generic import path drops V3 metadata" out as the V1.5-blocking gap, and a selector that "passes" against synthetic candidates while the real importer silently strips fields would fail at the V1.5 pilot soak (FRP-7) in the most expensive way possible. FRP-2's `specs/test-vectors/relaypack/` corpus is the contract that prevents that drift: FRP-3 binds against the corpus, not against in-memory mocks.

## 13. Architectural correction at FRP-2 execution time

The FRP-1 asymmetric-guard invariant (`! rg -n 'daal/publisher' bundle/go/` and the same in `core/`) and the FRP-2 task-5 wording ("call FRP-1 validator") were in conflict because the validator lives in `publisher/deploy/relaypack/`. **Resolution:** the validator package is moved to `bundle/go/relaypackvalidate/` (no shim left behind; publisher CLI updated to import from the new path). Both publisher and importer call the same validator. The asymmetric guard is preserved. V1.5 importer remains semantically strict.

**Validator invocation contract.** The importer calls `relaypackvalidate.Validate(parsed, ValidateOpts{Phase: PhaseV15})` **once per bundle, unconditionally**, immediately after `VerifyBundle`. The unconditional call catches RP001 (route-level `_relaypack` carried without the bundle-level `relay_pack` slot) — without it, that case would silently bypass validation and leave inconsistent state. On `*ValidationError`, the importer returns `VerdictRejected` with `Reason = "relaypack_" + code` so the FRP-6 UI surface can render the lint code.

**Bundle-level metadata.** `RelayPackID`, `FreshnessURL`, and `SharedRiskGraphJSON` are bundle-wide; the importer copies them onto every per-route `RouteRow` for read-locality at the FRP-3 selector boundary. This denormalisation is consistent with how 3F denormalised publisher-declared `redistribution_policy` per route.

**Sentinel-empty defaults, not NULL.** Earlier draft text said new columns are `NULL`. The codebase pattern for additive columns is `TEXT NOT NULL DEFAULT ''` / `'[]'`; both sentinels read back identically and avoid SQL-NULL-vs-empty-string ambiguity at the row scanner.

End — locked at FRP-track planning. Next: FRP-3 (selection brain).
