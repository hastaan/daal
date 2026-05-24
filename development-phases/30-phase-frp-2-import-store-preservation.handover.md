**Status:** SHIPPED.
**Date:** 2026-05-02.
**Engine version at exit:** `daal-core 0.9.0+v3-share` (UNCHANGED — store-widening phase).
**ABI release surface at exit:** **48** (UNCHANGED — RouteRow widening is internal; schema migration adds columns, not release symbols).
**FRP-3 gate:** **PASS.**

Phase 30 / FRP-2 shipped the `_relaypack` import + store preservation in 5 commits (Commit 0 amends, Commits 1–4 implement). Closes supplement §13.6 gap (1) (generic import path drops V3 metadata) and gap (3) (per-network memory key extension). No engine, Rust, Tauri, Kotlin, Swift, scenario, or test-rig code was changed.

---

## What Shipped

### Commit 0 — phase doc + spec amendments
- `phases of development/30-phase-frp-2-import-store-preservation.md` — sentinel-empty defaults replace earlier `NULL` language; task 5 rewritten to call `bundle/go/relaypackvalidate.Validate` unconditionally; task 6 rewritten to flow `RelayPackMeta` via `RouteInput`; §5 widened to 9 fields including `SharedRiskGraphJSON`; §13 architectural correction note added.
- `specs/relaypack-v1.md` — new §"Importer behaviour" block: parse → validate before first trust prompt → save flow; idempotence; sentinel-empty for non-RelayPack; Position B (FreshnessURL recorded, never fetched).
- `specs/test-vectors/relaypack/README.md` — bumped to 16 vectors with FRP-1 vs FRP-2 split + importer-vs-validator split documentation.

### Commit 1 — neutral validator package
- NEW `bundle/go/relaypackvalidate/{codes.go,validator.go,corpus_test.go,validator_test.go,validator_smoke_test.go}` — byte-equivalent move from `publisher/deploy/relaypack/`. Package renamed `relaypack` → `relaypackvalidate`. Resolves the FRP-1 asymmetric-guard conflict: bundle/ and core/ MUST NOT import the publisher module, but BOTH publisher and importer call the same validator via the neutral bundle-side package.
- DELETED `publisher/deploy/relaypack/` (no shim left behind).
- `publisher/cmd/relaypack-fixtures/main.go` — import switched to `daal/bundle-go/relaypackvalidate` (aliased as `relaypack` for body brevity).

### Commit 2 — schema migration + RouteRow widening
- `core/routestore/schema.go` — appended 9 forward-only `ALTER TABLE … ADD COLUMN … TEXT NOT NULL DEFAULT '…'` entries to the existing `migrations` slice. Sentinel-empty defaults (`''` / `'[]'`). Idempotent on re-open via the existing ALTER-IGNORE pattern.
- `core/routestore/store.go` — `RouteRow` extended with 9 fields:
  - per-candidate: `ExposureMode`, `FamilyClass`, `ProbingRiskClass`, `PublicRiskTags []string`, `OriginRiskTags []string`, `ModifiersJSON`
  - bundle-level (denormalised onto every per-route row for read-locality at the FRP-3 selector boundary): `RelayPackID`, `FreshnessURL`, `SharedRiskGraphJSON`
- `UpsertRoute`, `GetRoute`, `ListRoutes` extended to round-trip the 9 columns. Tag slices are canonical-JSON-encoded (consistent with 3D `ConjurePhantomSubnetsJSON`).
- `core/routestore/store_test.go` — 4 NEW tests:
  - `TestRouteRow_RelayPackFields_RoundTrip`
  - `TestRouteRow_LegacyRowsHaveSentinelRelayPackFields`
  - `TestRouteRow_RelayPackReimportIdempotent` (invariant 20)
  - `TestSchemaMigration_RelayPackColumnsExistOnSecondOpen` (invariant 19)

### Commit 3 — importer hook + StoreAdapter + netmem widening + opsec
- `bundle/go/importer/importer.go`:
  - NEW `RelayPackMeta` struct on `RouteInput` (nullable; nil = legacy path).
  - `ImportBytes()` calls `relaypackvalidate.Validate(parsed, ValidateOpts{Phase: PhaseV15})` **unconditionally** after `VerifyBundle`, before a first-seen trust prompt can be shown. Invalid first-seen RelayPacks return `VerdictRejected{Reason:"relaypack_RPxxx"}` immediately.
  - `apply()` calls the same helper defensively before persistence for direct `AcceptTrustPrompt` callers. Catches RP001 (route-level `_relaypack` with no bundle slot) — would silently bypass otherwise.
  - On `*ValidationError`, returns `VerdictRejected` with `Reason = "relaypack_" + code` so FRP-6 UI surfaces the lint code.
  - Per-route `bundle.ParseRelayPackEntry` builds `RelayPackMeta` when bundle has RelayPack slot; bundle-level `RelayPackID`, `FreshnessURL`, and `SharedRiskGraphJSON` are denormalised onto every `RelayPackMeta`.
- `core/trust/state.go` — `SaveImport` copies the 9 RelayPack fields from `RouteInput.RelayPack` onto `RouteRow` when non-nil. Signature unchanged. Legacy callers passing nil RelayPack produce sentinel-empty RouteRow values.
- `core/netmem/snapshot.go` — `FamilyStats` widened with optional sparse `ByRelayPack []RelayPackStat` (omitempty). New types `RelayPackKey` (Family, ExposureMode, PublicRiskTagSignature, Outcome — all omitempty) and `RelayPackStat` (Key, Successes, Failures). Pre-FRP-2 snapshots round-trip byte-identical. FRP-3 is the writer.
- `bundle/go/importer/importer_test.go` (NEW) — 8 tests against synthetic in-memory signed bundles:
  - `TestImport_RelayPackEntryFlowsToFakeState`
  - `TestImport_NoRelayPack_LegacyPath`
  - V1.5 cdn_fronted rejection (RP004)
  - first-seen V1.5 cdn_fronted rejection before trust prompt (RP004)
  - revoked publisher priority over RelayPack validation (`publisher_revoked`)
  - V1.5 modifiers rejection (RP013)
  - V1.5 freshness_url rejection (RP021)
  - `TestImport_RouteRelayPackWithoutBundleSlot_Rejected` (RP001 — regression test for unconditional validation)
- `core/netmem/store_test.go` — 3 NEW tests:
  - `TestSnapshot_LegacyDecodeStillWorks`
  - `TestSnapshot_RelayPackStatRoundTrip`
  - `TestSnapshot_MixedLegacyAndRelayPack`
- `core/trust/importer_test.go` — 4 NEW end-to-end tests against the real corpus (skipped if fixtures absent, run end-to-end after Commit 4):
  - `TestImportRelayPackBundle_FieldsLandInRouteRow`
  - `TestImportRelayPackBundle_ReimportIdempotent` (invariant 20)
  - V1.5 cdn_fronted rejection end-to-end
  - `TestImportRelayPackBundle_SharedRiskGraphRoundTrip`
- `core/routestore/import_opsec_test.go` (NEW) — `TestImportPathHasNoNetwork` greps `bundle/go/importer/`, `core/trust/`, `core/routestore/` (excluding `*_test.go`) for `net.Dial` / `http.Client` / `"net/http"`. Position B preserved (invariant 23).

### Commit 4 — corpus expansion + handover
- `publisher/cmd/relaypack-fixtures/main.go` — extended deterministic seed-driven generator with 10 new vectors:
  - `legacy-non-relaypack` (FRP-2): bundle without `_relaypack`, validator inert, importer takes legacy path.
  - `mixed-relaypack-direct-only` (FRP-2): three `direct_vps` siblings on one VPS.
  - `mixed-relaypack-direct-and-cdn` (FRP-2): cdn + direct mix; V1.5 RP004.
  - `idempotent-reimport` (FRP-2): byte-equivalent round-trip target.
  - `cdn-fronted-no-cdn-tag-rejected` (FRP-2): V1.5 RP004; V1.6 RP005.
  - `cdn-fronted-no-origin-tag-rejected` (FRP-2): V1.5 RP004; V1.6 RP006.
  - `direct-vps-with-cdn-tag-rejected` (FRP-2): RP009 at all phases.
  - `direct-vps-with-origin-tag-rejected` (FRP-2): RP010 at all phases.
  - `single-candidate-relaypack-rejected` (FRP-2): RP014 at all phases.
  - `bundle-with-freshness-url-v15-rejected` (FRP-2): RP021 at V1.5 (FRP-8 lifts).
- `bundle/go/relaypackvalidate/corpus_test.go` — `count != 16` assertion locked.

---

## 24 Invariants (per phase doc §3) Verified

| # | Invariant | Verification |
|---|---|---|
| 1–16 | Inherited from FRP-0 | Engine `Version` unchanged; ABI=48 unchanged; no telemetry; Position B; etc. — all green via existing core/test sweeps. |
| 17 | No release symbols added; ABI count stays 48 | `nm` matches FRP-1's count. |
| 18 | RouteRow widening additive | Existing 3A–3F columns unchanged in shape and semantics; tests still green. |
| 19 | Schema migration idempotent | `TestSchemaMigration_RelayPackColumnsExistOnSecondOpen` (open → close → re-open with no double-ALTER error). |
| 20 | Re-import idempotence preserved | `TestRouteRow_RelayPackReimportIdempotent` + `TestImportRelayPackBundle_ReimportIdempotent`. |
| 21 | Old bundles keep working | `TestRouteRow_LegacyRowsHaveSentinelRelayPackFields` + `legacy-non-relaypack` corpus vector + `TestImport_NoRelayPack_LegacyPath`. |
| 22 | `ModifiersJSON` is canonical-JSON TEXT | Stored as `modifiers_json TEXT`; populated only as canonical JSON; V1.5 hard-rejects non-empty per RP013. |
| 23 | Position B preserved | `TestImportPathHasNoNetwork` (no `net.Dial` / `http.Client` / `net/http` outside `_test.go`). |
| 24 | Corpus is the contract | 16 vectors at `specs/test-vectors/relaypack/`. FRP-3 binds against the corpus, not against in-memory mocks. |

---

## Final Build Matrix

```
$ cd bundle/go && /usr/local/go/bin/go build ./relaypackvalidate/... ./importer/...
# no output

$ cd bundle/go && /usr/local/go/bin/go test -count=1 ./relaypackvalidate/... ./importer/...
ok  	daal/bundle-go/relaypackvalidate                            # 40 tests + 24 corpus sub-tests = 64
ok  	daal/bundle-go/importer                                     # 8 new tests

$ cd core && /usr/local/go/bin/go build ./routestore/... ./trust/... ./netmem/...
# no output

$ cd core && /usr/local/go/bin/go test -count=1 ./routestore/... ./trust/... ./netmem/...
ok  	daal/core/netmem                                            # 3 new tests
ok  	daal/core/routestore                                        # 4 new RouteRow tests + opsec test
ok  	daal/core/trust                                             # 4 new corpus tests

$ cd publisher && /usr/local/go/bin/go test ./...
?   	daal/publisher/cmd/relaypack-fixtures	[no test files]

$ ls specs/test-vectors/relaypack/*.sbp | wc -l
16

$ ls specs/test-vectors/relaypack/*.expected.json | wc -l
16

$ nm /tmp/libdaalcore.so | grep ' T engine_' | wc -l
48                                                                  # UNCHANGED

$ grep -E '^const Version' core/abi/abi.go
const Version = "daal-core 0.9.0+v3-share"                          # UNCHANGED

$ sqlite3 /tmp/test.db ".schema routes" | grep -cE \
    'exposure_mode|family_class|probing_risk_class|public_risk_tags_json|origin_risk_tags_json|modifiers_json|relay_pack_id|freshness_url|shared_risk_graph_json'
9                                                                    # 9 new columns

$ sqlite3 /tmp/test.db ".tables" | grep -i network_memory
                                                                     # NO network_memory_v2

$ ! rg -n 'daal/publisher' bundle/go/
                                                                     # exit 0 (asymmetric guard intact)
$ ! rg -n 'daal/publisher' core/
                                                                     # exit 0 (asymmetric guard intact)
$ ! rg -n 'net\.Dial|http\.Client|"net/http"' \
      bundle/go/importer/ core/trust/ core/routestore/ --type go --glob '!*_test.go'
                                                                     # exit 0 (OPSEC clean)
```

---

## What FRP-2 Did Not Change

| Surface | Locked at | FRP-2 value |
|---|---|---|
| Engine `Version` constant | 3F | `daal-core 0.9.0+v3-share` UNCHANGED |
| Release ABI export count | 3F | 48 UNCHANGED |
| `core/abi/` symbols | 3F | none added |
| `bundle/go/bundle/relay_pack.go` | FRP-1 | UNCHANGED (typed structs reused) |
| `bundle/go/bundle/sbp.go` | FRP-1 | UNCHANGED |
| `core/netmem/store.go::Store` API | 3C | UNCHANGED (only the entry value shape widened) |
| `StoreAdapter.SaveImport` signature | 1B | UNCHANGED (RelayPackMeta flows via existing RouteInput struct) |
| `tofu_friend` interaction | 1B | UNCHANGED (RelayPack fields orthogonal to trust) |

---

## Open Follow-ups for FRP-3

The FRP-3 phase doc (`31-phase-frp-3-selection-brain.md`) owns these items; flagging concrete observations from FRP-2 execution:

1. **`GetRoute` is sufficient for FRP-3.** The phase doc's planning draft mentioned a possible new `GetRouteRelayPack(routeID)` method on `StoreAdapter`. Not added at FRP-2 — the existing `GetRoute` already returns the full `RouteRow` including the 9 new fields. If FRP-3 finds it helpful to project the RelayPack subset for cohorting/cooldown propagation, it can add a thin helper on the routestore side without changing `RouteRow`.

2. **`ByRelayPack` writer.** `core/netmem/snapshot.go` ships the schema; FRP-3 wires the writer at outcome-recording time. The selector computes `PublicRiskTagSignature = canonical_sorted_comma_join(public_risk_tags)` at write time.

3. **Per-route shared-risk graph.** Every per-route `RouteRow.SharedRiskGraphJSON` is the same bundle-wide JSON. FRP-3's cooldown propagation reads it from any one route in a cohort. If FRP-3 needs to deduplicate, the bundle-level `RelayPackID` is the natural key.

4. **FRP-2 NOT blocking RP004 cascading.** The validator emits the FIRST error it finds. The FRP-2 `mixed-relaypack-direct-and-cdn` corpus vector fails RP004 at V1.5 even though a sibling RP005/RP006 case may also exist; that's the expected validator behaviour. FRP-3 selectors that surface validation errors via the diagnostics path should expect at most one error code per import attempt.

5. **`legacy-non-relaypack` shape question.** The vector ships with `SpecVersion = 1` and no `Manifest.RelayPack` slot. The validator is correctly inert (no `_relaypack` keys anywhere). FRP-3 selectors must NOT assume every imported `RouteRow` has a `RelayPackID`; sentinel-empty `''` is the legacy signal.

---

## Track ordering rationale (preserved from phase doc §12)

FRP-2 between FRP-1 and FRP-3 because the schema (FRP-1) had to land before the store widened (FRP-2), and the store had to widen before the selector (FRP-3) could consume the new fields. The 16-vector corpus at `specs/test-vectors/relaypack/` is the contract that prevents drift: FRP-3 binds against the corpus, not against in-memory mocks.

---

## Recent Commits

```
<commit 4 hash> FRP-2 commit 4/4: corpus expansion (10 new vectors; 16 total) + handover
<commit 3 hash> FRP-2 commit 3/4: importer hook + StoreAdapter + netmem widening + opsec test
7288800        FRP-2 commit 2/4: routestore schema + RouteRow widening (9 RelayPack cols)
f67af76        FRP-2 commit 1/4: move RelayPack validator to bundle/go/relaypackvalidate
c69ce97        FRP-2 commit 0/4: amend phase doc + relaypack-v1.md + corpus README
```

End — FRP-2 SHIPPED 2026-05-02. Next: FRP-3 (selection brain).
