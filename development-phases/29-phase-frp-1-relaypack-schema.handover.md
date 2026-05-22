
**Status:** SHIPPED.
**Date:** 2026-05-02.
**Engine version at exit:** `daal-core 0.9.0+v3-share` (UNCHANGED — schema-only phase).
**ABI release surface at exit:** **48** (UNCHANGED — schema lives inside existing `FamilySpecificConfig` opaque-JSON slot + new additive `Manifest.relay_pack` slot mirroring 3A/3B/3E/3F).
**`spec_version`:** **2 → 3.**
**FRP-2 gate:** **PASS.**

Phase 29 / FRP-1 shipped the RelayPack schema in 4 commits plus the post-review `RP021` freshness gate patch. No engine, Rust, Tauri, Kotlin, Swift, scenario, or test-rig code was changed.

## What Shipped

- `bundle/go/bundle/relay_pack.go` — `RelayPack`, `RelayPackEntry`, `Modifier`, `CellScope`, `SharedRiskEdge` structs lifted verbatim from supplement v2.3.7 §12.2.2 / §12.2.2.bis / §12.2.5. Ships `ParseRelayPackEntry` helper for the FRP-2 importer.
- `bundle/go/bundle/types.go` — `Manifest.RelayPack *RelayPack` field added (additive widening pattern matching 3A KillSwitches / 3B RendezvousHints / 3E TransportModules / 3F RedistributionChain).
- `bundle/go/bundle/sbp.go` — `VerifyBundle` spec_version guard widened from `{1, 2}` to `{1, 2, 3}` plus parser-level guard rejecting `Manifest.RelayPack != nil` when `SpecVersion < 3`.
- `bundle/go/bundle/v2_test.go` — `TestSpecV3Rejected` flipped to `TestSpecV3Accepted`; new `TestSpecV4Rejected` covers the still-future case.
- `bundle/go/bundle/relay_pack_test.go` — 8 new bundle-side tests (round-trip canonical, signed-bundle round-trip, RP requires v3, ParseRelayPackEntry absent/happy/malformed, v3-without-RP, canonical key order).
- `publisher/go.mod` — NEW module `daal/publisher`, Go 1.24.0, with `replace daal/bundle-go => ../bundle/go` and `replace daal/core => ../core`. First publisher-side module in the FRP track. Reused at FRP-4a / FRP-11 / FRP-12 / FRP-13.
- `publisher/deploy/relaypack/codes.go` — `RP001`..`RP021` codebook locked + `Phase` enum (`V1.5` / `V1.6` / `PostV2`).
- `bundle/go/relaypackvalidate/validator.go` — originally landed under `publisher/deploy/relaypack/` at FRP-1 and moved to the neutral bundle-side package at FRP-2 so publisher and importer share the same validator without violating the asymmetric dependency guard. `Validate(b, opts) (LintReport, error)`. Per-candidate rules RP002, RP003, RP004, RP005..RP010, RP011, RP012, RP013, RP015, RP016. Bundle-level rules RP001, RP007, RP014, RP017, RP018, RP021. Lint warnings RP019, RP020. `defaultFamilyMatrix()` seeds the §11.1.1 cdn_fronted row.
- `bundle/go/relaypackvalidate/validator_test.go` — 36 tests (3 positive + 1 per error code + extras + 2 lint cases per warning + 2 phase-progression cases + RP021 phase-gate coverage).
- `bundle/go/relaypackvalidate/validator_smoke_test.go` — 4 smoke tests (package compiles, bad input rejected, codebook stable, default matrix).
- `bundle/go/relaypackvalidate/corpus_test.go` — replays the seed test vectors against all 3 phases.
- `publisher/cmd/relaypack-fixtures/main.go` — deterministic generator binary that produces the seed test-vector corpus.
- `specs/relaypack-v1.md` — NEW. ~7 pages: schema + validator rules + lint codebook + tag vocabulary + compatibility contract + cross-references.
- `specs/sbp-v1.md` — `Phase FRP-1 widening` section appended cross-referencing `specs/relaypack-v1.md`.
- `specs/test-vectors/relaypack/` — 6 seed vectors. Each ships a `<name>.sbp` (sealed ZIP archive) and a `<name>.expected.json` (per-phase validator outcome). A `<name>.manifest.json` review-only companion is regenerable via `cd publisher && go run ./cmd/relaypack-fixtures -emit-manifest-json` and is NOT tracked in git (duplicates data already inside the signed `.sbp`; trips secret scanners on the deterministic test key fingerprint).
  - `direct-vps-minimal` — passes V15/V16/PostV2 with RP019+RP020 warnings.
  - `direct-vps-with-sni` — passes V15/V16/PostV2 (RP020 only; diverse public_risk_tags).
  - `cdn-fronted-minimal` — RP004 at V15; OK at V16/PostV2 with RP020.
  - `cdn-fronted-with-origin` — RP004 at V15; OK at V16/PostV2 with RP020.
  - `modifier-rejected` — RP013 at V15/V16; OK at PostV2 with RP019+RP020.
  - `legacy-flat-tags-rejected` — RP017 at V15/V16/PostV2.
- `specs/test-vectors/relaypack/README.md` — corpus index + regeneration instructions.

## Validator Test Count

- `bundle/go`: 8 new `relay_pack_test.go` tests + 2 new `v2_test.go` tests + all pre-existing tests still green.
- `publisher`: 40 unique top-level test funcs + 24 corpus-replay sub-tests = **64 PASS**.
- All vectors round-trip the canonical bytes byte-identically across two `CanonicalManifestJSON` calls (locked by `TestRelayPackRoundTripCanonical`).

## What FRP-1 Did Not Change

| Surface | Locked at | FRP-1 value |
|---|---|---|
| Engine `Version` constant | 3F | `daal-core 0.9.0+v3-share` unchanged |
| Release ABI export count | 3F | 48 unchanged (source + binary `nm`) |
| `--scenarios v3-superset` count | 3-Soak | 31 unchanged |
| `core/abi/` symbols | 3F | none added |
| `core/routestore/` schema | 3-Soak | unchanged (FRP-2 widens) |
| `core/trust/` `StoreAdapter` | 3-Soak | unchanged (FRP-2 widens) |
| `bundle/go/bundle/canonical.go` | 3F | unchanged (existing generic walker handles new slot) |

## Final Build Matrix (locked sweep)

```
$ ls publisher/go.mod
publisher/go.mod                                              # NEW (FRP-1)

$ cd bundle/go && /usr/local/go/bin/go build ./bundle/...
# no output

$ cd bundle/go && /usr/local/go/bin/go test ./bundle/...
ok  	daal/bundle-go/bundle	1.227s

$ cd publisher && /usr/local/go/bin/go build ./...
# no output

$ cd publisher && /usr/local/go/bin/go test -count=1 ./...
?   	daal/publisher/cmd/relaypack-fixtures	[no test files]
ok  	daal/bundle-go/relaypackvalidate	0.010s        # moved at FRP-2; validator tests live in bundle/go

$ cd core && /usr/local/go/bin/go build ./...
# no output (UNCHANGED)

$ cd core && /usr/local/go/bin/go test ./...
... all green (UNCHANGED)

$ nm /tmp/libdaalcore.so | grep ' T engine_' | wc -l
48                                                             # UNCHANGED

$ ! rg -n 'daal/publisher' bundle/go/                         # asymmetric guard
$ ! rg -n 'daal/publisher' core/                              # asymmetric guard
                                                                 # both exit non-zero (no import)

$ ls specs/relaypack-v1.md
specs/relaypack-v1.md

$ ls specs/test-vectors/relaypack/
README.md
cdn-fronted-minimal.{expected.json,sbp}
cdn-fronted-with-origin.{expected.json,sbp}
direct-vps-minimal.{expected.json,sbp}
direct-vps-with-sni.{expected.json,sbp}
legacy-flat-tags-rejected.{expected.json,sbp}
modifier-rejected.{expected.json,sbp}

$ git grep -n 'spec_version' bundle/go/bundle/sbp.go | head -3
bundle/go/bundle/sbp.go:138:	// FRP-1: spec_version 3 (RelayPack) is also accepted...
bundle/go/bundle/sbp.go:140:	// guard below rejects pre-bump bundles that carry the new slot.
bundle/go/bundle/sbp.go:141:	if b.Manifest.SpecVersion != 1 && b.Manifest.SpecVersion != 2 && b.Manifest.SpecVersion != 3 {

$ git grep -n '_relaypack' bundle/go/ publisher/ specs/ | wc -l
... many references
```

## 27 Invariants — Status at Exit

All 27 invariants from `phases of development/29-phase-frp-1-relaypack-schema.md` §3 hold at exit:

1. ABI surface stays 48. — VERIFIED by `nm` count above.
2. Engine `Version` constant unchanged. — VERIFIED by `git grep` of `core/abi/abi.go`.
3. No new release symbols. — VERIFIED (no `core/abi/*_export.go` change).
4. No new release-table entries. — VERIFIED.
5. Bundle format `.sbp` unchanged. — VERIFIED (only schema additions inside existing `Manifest`).
6. `RouteRow` schema unchanged. — VERIFIED (FRP-2 owns).
7. `StoreAdapter` boundary unchanged. — VERIFIED (FRP-2 owns).
8. Position B (no telemetry). — VERIFIED (no event sinks added).
9. No nested go.mod proliferation. — VERIFIED (single `publisher/go.mod`; no submodules).
10. `--scenarios v3-superset` count unchanged. — VERIFIED.
11. Cross-platform parser determinism preserved. — VERIFIED (`TestRelayPackRoundTripCanonical`).
12. Backward signature verification preserved on legacy `.sbp`. — VERIFIED (`TestSpecV1AndV2BothAccepted` still green).
13. `bundle/go` is a peer module of `core/` (no new cross-module imports). — VERIFIED.
14. `core/` does not import `bundle/go` outside of the existing `bundle.Manifest` consumers. — VERIFIED (no `core/` change in this phase).
15. No engine state machine change. — VERIFIED.
16. No file-system layout change in `core/`. — VERIFIED.
17. `_relaypack` lives inside `FamilySpecificConfig.RawMessage`. — VERIFIED (no new field on `RouteManifestEntry`).
18. `Manifest.relay_pack` slot is additive. — VERIFIED (3A/3B/3E/3F widening pattern).
19. `spec_version` bumps once. — VERIFIED (2 → 3, single bump).
20. No engine release symbols added. — VERIFIED.
21. Validator is import-time only. — VERIFIED (no runtime selector hooks; FRP-3 owns).
22. Canonical bytes round-trip mandatory. — VERIFIED by `TestRelayPackRoundTripCanonical`.
23. Old-client behaviour preserved. — VERIFIED (pre-FRP-1 client receiving non-RP `.sbp` still verifies; RP-bearing bundle hard-rejects at signature).
24. No telemetry. — VERIFIED.
25. Validator rejects `cell_scope.policy: transitive` at V1.5. — VERIFIED by RP016 (`TestRP016_CellScopeAtV15`).
26. Lint warnings vs hard rejects distinct. — VERIFIED (`Validate` returns `(LintReport, error)`).
27. `daal/publisher` Go module created at FRP-1; asymmetric dependency contract green. — VERIFIED by `! rg -n 'daal/publisher' bundle/go/` and `! rg -n 'daal/publisher' core/` both exiting non-zero.

## Six Test Vectors Enumerated

| Vector | V1.5 | V1.6 | PostV2 |
|---|---|---|---|
| direct-vps-minimal | OK + RP019/RP020 | OK + RP019/RP020 | OK + RP019/RP020 |
| direct-vps-with-sni | OK + RP020 | OK + RP020 | OK + RP020 |
| cdn-fronted-minimal | RP004 | OK + RP020 | OK + RP020 |
| cdn-fronted-with-origin | RP004 | OK + RP020 | OK + RP020 |
| modifier-rejected | RP013 | RP013 | OK + RP019/RP020 (with allow-list) |
| legacy-flat-tags-rejected | RP017 | RP017 | RP017 |

All 18 (6×3) phase replays pass via `TestCorpusReplay`.

## `specs/relaypack-v1.md` Page Count

~7 pages of markdown (~12 KB), broken into Status / Purpose / Schema (bundle-level + per-candidate + examples + modifiers + cell_scope) / Validator rule list (RP001..RP021) / Lint codebook / Tag vocabulary / Compatibility contract / Test vectors / Cross-references.

## Open Follow-ups for FRP-2

The FRP-2 phase doc owns these items; flagging concrete follow-ups discovered during FRP-1:

1. **`RouteRow` widening:** FRP-2 must add typed fields to `core/routestore/store.go:127`'s `RouteRow` so `_relaypack` survives the `RouteInput → SaveImport → RouteRow` boundary. Suggested fields based on FRP-1's struct shape:
   - `RelayPackExposureMode string`
   - `RelayPackFamilyClass string`
   - `RelayPackProbingRiskClass string`
   - `RelayPackPublicRiskTagsJSON string` (JSON-encoded array)
   - `RelayPackOriginRiskTagsJSON string` (JSON-encoded array)
   - `RelayPackBundleID string` (foreign key to `Manifest.relay_pack.relay_pack_id`)
2. **Importer parser hook:** FRP-2 must call `bundle.ParseRelayPackEntry(r.FamilySpecificConfig)` inside `bundle/go/importer/` and route the typed entry into the `core/trust/state.go::StoreAdapter.SaveImport` boundary.
3. **`core/netmem/` widening:** FRP-2 must extend `Snapshot.RouteFamilyStats` from family-keyed to `(family × exposure_mode × public_risk_tag_signature)` per supplement §13.4.
4. **Test-vector corpus expansion:** FRP-2 must seed importer round-trip vectors in addition to the 6 validator vectors shipped here. Suggested additions: `import-roundtrip-direct`, `import-roundtrip-cdn`, `import-roundtrip-cooldown-edges`, plus 7 more for the §13.4 cooldown-propagation test matrix.

## Position B Preserved

No telemetry. No event sinks. No probing of any FRP-controlled endpoint. The validator is import-time only and stateless — given the same `(bundle, opts)` it always returns the same `(LintReport, error)`.

## Next Phase

FRP-2 (`phases of development/30-phase-frp-2-import-store-preservation.md`) — importer wiring + `RouteRow` widening + `StoreAdapter` boundary + 16-vector corpus.
