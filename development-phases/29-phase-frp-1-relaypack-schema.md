# Phase 29 (FRP-1) — RelayPack Spec + Bundle Schema

**Status:** SHIPPED on 2026-05-02. FRP-2 gate verdict: **PASS**. Handover at `29-phase-frp-1-relaypack-schema.handover.md`.
**Roadmap line:** *"`specs/relaypack-v1.md` (locks the full v2.3.5 mode-aware schema; §12.2.2 + §12.2.2.bis)."* — `daal-roadmap-v3-supplement-diaspora-helper.md` §21.1
**Supplement target:** v2.3.7.
**Engine version target:** `daal-core 0.9.0+v3-share` **(UNCHANGED — schema-only phase).**
**ABI release surface target:** **48** **(UNCHANGED — schema lives inside existing `FamilySpecificConfig` opaque-JSON slot).**
**Maturity:** schema phase. Bumps `spec_version` (the only place in the FRP track where a `Manifest`-level slot is added).
**Predecessor:** Phase 28 (FRP-0) — must ship the per-module matrix and FRP-1 gate verdict.
**Successor:** Phase 30 (FRP-2) — consumes the parsed `_relaypack` sub-object and the new `Manifest` slot.

## 1. Strategic frame (verbatim from the supplement)

> **§12.2 The RelayPack profile — what the profile adds beyond plain `.sbp`.** Per-candidate metadata is carried inside the existing `RouteManifestEntry.FamilySpecificConfig` `json.RawMessage` slot as a `_relaypack` sub-object so the bytes round-trip through old parsers' canonicalisation cleanly. The `_relaypack` sub-object carries `exposure_mode`, `family_class`, `probing_risk_class`, `modifiers[]`, `public_risk_tags[]`, `origin_risk_tags[]`. Bundle-level metadata (`relay_pack_id`, the bundle-wide shared-risk graph, cell-scope defaults, and the V1.6 `freshness_url` slot) is a new optional top-level slot on `Manifest`, in the same shape as 3A's `kill_switches`, 3B's `rendezvous_hints`, 3E's `transport_modules`, and 3F's `redistribution_chain` / `delegate_caps`.

FRP-1's job is to land the profile on disk: the per-candidate `_relaypack` parser, the new bundle-level `Manifest` slot (additive widening pattern matching 3A/3B/3E/3F), the validator (moved to `bundle/go/relaypackvalidate/validator.go` at FRP-2 so importer and publisher share one neutral package), the `spec_version` bump, and `specs/relaypack-v1.md`. Schema/types helpers live alongside in `bundle/go/bundle/types.go` (canonical bytes contract) and `bundle/go/bundle/sbp.go` (parse hooks). **No selector code, no importer code, no UI code.** Those phases land at FRP-2 and FRP-3.

Because the validator lives under `publisher/`, and the repo has no root `go.mod` / `go.work` (existing modules are per-tree: `bundle/go/go.mod`, `core/go.mod`, one `go.mod` per `cmd/<binary>/`), **FRP-1 — not FRP-4a — creates the new `publisher/go.mod`** (module path `daal/publisher`) covering the entire `publisher/` subtree. FRP-4a, FRP-11, FRP-12, and FRP-13 all reuse this single module; no nested `go.mod` files.

## 2. Locked answers

| Question | Locked answer |
|---|---|
| Schema version target | Supplement v2.3.7 §12.2.2 + §12.2.2.bis verbatim. `exposure_mode := direct_vps \| cdn_fronted \| serverless_external`; `modifiers[]` orthogonal. |
| Per-candidate metadata destination | `RouteManifestEntry.FamilySpecificConfig._relaypack` (existing `json.RawMessage` slot at `bundle/go/bundle/types.go:209`). NOT a new first-class field on `RouteManifestEntry`. |
| Bundle-level new slot name | `relay_pack` (singular). Carries `relay_pack_id`, `shared_risk_graph`, optional cell-scope defaults, optional `freshness_url` (empty at V1.5; populated at FRP-8). |
| Pattern reference for the new slot | 3A `kill_switches`, 3B `rendezvous_hints`, 3E `transport_modules`, 3F `redistribution_chain` / `delegate_caps`. Same widening shape; same backward-compat contract. |
| `spec_version` bump | Yes, here (FRP-1). FRP-0 audit confirmed current accepted/default value is 2; FRP-1 target is 3. |
| Go-module root for `publisher/` | **FRP-1 creates the new module at `publisher/go.mod`** (module path `daal/publisher`, Go 1.24.0 to match existing modules). Replace directives: `replace daal/bundle-go => ../bundle/go` and `replace daal/core => ../core` mirroring the existing pattern in `core/go.mod`. The publisher module imports `daal/bundle-go` (for `bundle.Bundle`, `bundle.RouteManifestEntry`, signing primitives) and MAY import `daal/core` for narrow needs (e.g. `core/abi` constants); `bundle/` and `core/` MUST NOT import `daal/publisher` (asymmetric: publisher is downstream of both). The same module is reused at FRP-4a (`publisher/deploy/`), FRP-11 (`publisher/cell/`), FRP-12 (`publisher/deploy/modifiers/`), and FRP-13 (`publisher/directory/`). No nested `go.mod` files under `publisher/`. |
| Validator location | `bundle/go/relaypackvalidate/validator.go` after the FRP-2 architectural correction. FRP-1 initially landed the validator under `publisher/deploy/relaypack/`; FRP-2 moved it to the neutral bundle-side package so publisher and importer share one validator without `bundle/go` or `core` importing `daal/publisher`. |
| Validator severity | Hard reject on schema violation (returns typed error; bundle import fails). Lint-class warnings (e.g. all-shared `public_ip`) are surfaced separately and do not block. |
| Modifier reservation at V1.5 / V1.6 | Validator hard-rejects any non-empty `modifiers[]` array. Lifted per-modifier at FRP-12. |
| Exposure-mode reservation at V1.5 / V1.6 | Validator hard-rejects `exposure_mode: serverless_external`. Validator hard-rejects `exposure_mode: cdn_fronted` at V1.5; lifts to allow at FRP-8 (V1.6). |
| Direct-mode tag rules | Per supplement v2.3.7 §12.2.2: must carry `public_ip:*`; may carry `public_domain:*`, `host:*`, `sni:*`; must NOT carry `cdn:*` or any `origin_*`. |
| CDN-mode tag rules | Per supplement v2.3.7 §12.2.2: must carry at least one `cdn:*` AND at least one `origin_*`. Family must appear `yes` or `conditional` in §11.1.1's `cdn_fronted` column. |
| Legacy `shared_risk_tags` handling | Hard reject with explicit error message naming v2.3.5 schema and pointing at `specs/relaypack-v1.md`. |
| Test-vector format | Canonical `.sbp` round-trip pairs at `specs/test-vectors/relaypack/` (FRP-2 expands the corpus; FRP-1 seeds the minimum 6 vectors documented below). |
| Backward compatibility for old clients | `_relaypack` survives via `json.RawMessage` (no parser change needed for old clients). The new `Manifest` slot is update-required: pre-V1.5 verifier rejects the signature on a RelayPack-bearing bundle and prompts user to update. Same contract as 3A/3B/3E/3F. |

## 3. Locked invariants

Tracks invariants 1–16 inherited from `28-phase-frp-0-roadmap-reconciliation.md` §3. Phase-specific:

17. **`_relaypack` lives inside `FamilySpecificConfig.RawMessage`.** No new field on `RouteManifestEntry` itself.
18. **The new `Manifest.relay_pack` slot is additive.** Mirrors 3A/3B/3E/3F widening pattern; covered by `bundle/go/bundle/canonical.go` deterministically.
19. **`spec_version` bumps once.** All later FRP-N additions to the same `relay_pack` slot (`freshness_url` at FRP-8, cell-scope defaults at FRP-11) are field-level additions inside the already-bumped slot; no further `spec_version` bump.
20. **No engine release symbols added.** ABI count stays 48; verified by `nm libdaalcore.so | grep ' T engine_' | wc -l = 48` at phase exit.
21. **Validator is import-time only.** No runtime selector hooks here — those land at FRP-3.
22. **Canonical bytes round-trip is mandatory.** A `_relaypack`-bearing bundle re-canonicalised must produce byte-identical output; verified by an explicit round-trip test.
23. **Old-client behaviour preserved.** A pre-V1.5 client receiving a non-RelayPack `.sbp` continues to verify and import it unchanged; a pre-V1.5 client receiving a RelayPack-bearing bundle hard-rejects at signature verification (because the new top-level `Manifest` slot is part of the canonical signed payload). Update-required failure mode is the same as 3A/3B/3E/3F.
24. **No telemetry.** No counters, no event sinks, no probe of any FRP-controlled endpoint at validator time. Position B preserved.
25. **Validator rejects `cell_scope.policy: transitive` at V1.5.** Cells are V2 (FRP-11); transitive policy is rejected with an explicit error.
26. **Lint warnings vs hard rejects are distinct.** `Validator.Validate(b) -> (LintReport, error)`: error means import fails; lint report is surfaced to the FRP and never blocks import. Documented in `specs/relaypack-v1.md`.
27. **`daal/publisher` Go module is created at FRP-1.** The repo has no root `go.mod` and no `go.work`; existing modules are per-tree (`bundle/go/`, `core/`, `cmd/<binary>/`). FRP-1 creates `publisher/go.mod` (module path `daal/publisher`, Go 1.24.0) with `replace daal/bundle-go => ../bundle/go` and `replace daal/core => ../core`. FRP-2 moves the validator out of this module to `bundle/go/relaypackvalidate/`; FRP-4a, FRP-11, FRP-12, and FRP-13 still reuse the single publisher module for deploy/cell/modifier/directory work. No nested `go.mod` files under `publisher/`. Dependency direction: `publisher → bundle` and `publisher → core`; **`bundle/` and `core/` MUST NOT import `daal/publisher`** (asymmetric: publisher is downstream of both). CI-equivalent guards: `cd publisher && go build ./...` succeeds; `! rg -n 'daal/publisher' bundle/go/` returns non-zero; `! rg -n 'daal/publisher' core/` returns non-zero.

## 4. Sub-task breakdown

| #  | Task |
|----|------|
| 0  | Replace any prior FRP-1 stub with this locked spec at `phases of development/29-phase-frp-1-relaypack-schema.md`. |
| 1  | Read inputs end-to-end: supplement §3.2, §12.1, §12.2, §12.2.2, §12.2.2.bis, §12.2.6, §13.6, §21.1; `specs/sbp-v1.md`; `bundle/go/bundle/types.go` (esp. `RouteManifestEntry`, `FamilySpecificConfig`, `Manifest`); `bundle/go/bundle/canonical.go`; `bundle/go/bundle/sign.go`; FRP-0 handover invariant table. |
| 2  | Re-confirm the FRP-0 baseline that current accepted/default `spec_version` is 2; set target to 3. |
| 3  | Add `bundle/go/bundle/relay_pack.go` defining the `RelayPack` struct (top-level Manifest slot fields) and the `RelayPackEntry` struct (per-candidate `_relaypack` sub-object fields). Both with `json:"..."` tags matching supplement §12.2.2 / §12.2.2.bis exactly. Round-trip-friendly. |
| 4  | Extend `bundle/go/bundle/types.go` `Manifest` struct with `RelayPack *RelayPack \`json:"relay_pack,omitempty"\`` (nil for non-RelayPack bundles). |
| 5  | Extend `bundle/go/bundle/canonical.go` to canonicalise the new slot deterministically (sorted keys, stable array ordering). Tests: a `RelayPack`-bearing bundle re-canonicalised yields byte-identical output. |
| 6  | Bump `spec_version` constant (FRP-0 records the value); add a parser guard that rejects pre-bump bundles only when they would otherwise carry the new slot. |
| 6.5| **Create the new Go module at `publisher/go.mod`** (module path `daal/publisher`, `go 1.24.0`). Add `replace daal/bundle-go => ../bundle/go` and `replace daal/core => ../core`. Run `cd publisher && go mod tidy`. This MUST happen before sub-task 7 because the validator import chain pulls `daal/bundle-go`. FRP-4a, FRP-11, FRP-12, and FRP-13 all reuse this module. |
| 7  | Implement the RelayPack validator. Final package home after FRP-2: `bundle/go/relaypackvalidate/validator.go`. Function signature: `func Validate(b *bundle.Bundle, opts ValidateOpts) (LintReport, error)`. Opts include `Phase` enum (`V15`, `V16`, `PostV2`) so the same validator binary is used across phases. |
| 8  | Validator rule set (one rule per `_relaypack` constraint, enumerated in §5 below). Each rule is its own function; each emits a typed error code per `specs/relaypack-v1.md` lint codebook. Hard-reject errors return `error`; soft warnings accumulate in the `LintReport`. |
| 9  | Tests at `bundle/go/relaypackvalidate/validator_test.go`: one positive-case test per supplement §12.2.2 example (direct_vps and cdn_fronted) plus one negative-case test per validator rule. Minimum 25 tests. |
| 10 | Seed `specs/test-vectors/relaypack/` with 6 baseline vectors (direct-vps minimal, direct-vps with sni, cdn-fronted minimal, cdn-fronted with origin set, modifier-rejected post-V2, legacy-flat-tags-rejected). Each vector is `{name}.sbp` + `{name}.expected.json`. |
| 11 | Write `specs/relaypack-v1.md`. ~6 pages per supplement §12.4. Includes: schema (verbatim from §12.2.2 + §12.2.2.bis); validator rule list (one entry per rule with error code + example); lint codebook; tag vocabulary (open extension model per §12.2.2 "tag vocabulary"); compatibility contract (old-client behavior). |
| 12 | Final regression sweep: `cd bundle/go && go build ./bundle/... && go test ./bundle/...`; `cd publisher && go build ./... && go test ./...`; asymmetric-dependency guards green (`! rg -n 'daal/publisher' bundle/go/`; `! rg -n 'daal/publisher' core/`); `nm /tmp/libdaalcore.so \| grep ' T engine_' \| wc -l` returns `48`; all 6 test vectors round-trip; FRP-2 gate verdict (PASS / HOLD / BLOCKED); handover written. |

## 5. RelayPack schema (locked, for `bundle/go/bundle/relay_pack.go`)

### 5.1. Per-candidate sub-object (inside `FamilySpecificConfig._relaypack`)

```go
type RelayPackEntry struct {
    ExposureMode      string         `json:"exposure_mode"`              // direct_vps | cdn_fronted | serverless_external
    FamilyClass       string         `json:"family_class"`               // vps-native | vps-possible | external-ecosystem
    ProbingRiskClass  string         `json:"probing_risk_class"`         // low | moderate | high
    Modifiers         []Modifier     `json:"modifiers,omitempty"`        // empty at V1.5 / V1.6; reserved post-V2
    PublicRiskTags    []string       `json:"public_risk_tags"`           // what TIC sees
    OriginRiskTags    []string       `json:"origin_risk_tags"`           // operator-only; empty for direct_vps
    CellScope         *CellScope     `json:"cell_scope,omitempty"`       // V2 cell metadata; nullable at V1.5
}

type Modifier struct {
    Kind             string `json:"kind"`                                // client_desync | tls_fragment (post-V2)
    Platform         string `json:"platform,omitempty"`                  // e.g. linux_desktop_only
    ProbingRiskClass string `json:"probing_risk_class,omitempty"`        // overrides candidate's probing class
}

type CellScope struct {
    CellID       string `json:"cell_id,omitempty"`
    CellJoinFP   string `json:"cell_join_fp,omitempty"`
    CellMaxDepth int    `json:"cell_max_depth,omitempty"`
}
```

### 5.2. Bundle-level slot (inside `Manifest.relay_pack`)

```go
type RelayPack struct {
    RelayPackID      string            `json:"relay_pack_id"`            // one per FRP-provisioned VPS
    SharedRiskGraph  []SharedRiskEdge  `json:"shared_risk_graph"`        // computed by Helper, signed
    CellScopeDefault *CellScope        `json:"cell_scope_default,omitempty"` // V2; nullable at V1.5
    FreshnessURL     string            `json:"freshness_url,omitempty"`  // V1.6 (FRP-8); empty at V1.5
}

type SharedRiskEdge struct {
    Tag       string   `json:"tag"`              // e.g. "public_ip:5.75.x.x"
    Members   []string `json:"members"`          // candidate IDs sharing this tag
}
```

### 5.3. Validator rule list (locked)

| Rule ID | Severity | Description |
|---|---|---|
| `RP001` | error | `_relaypack` sub-object present requires the bundle's `Manifest.relay_pack` to be non-nil. |
| `RP002` | error | `exposure_mode` must be one of the enum. Unknown values rejected. |
| `RP003` | error | `serverless_external` rejected at `Phase: V15` and `Phase: V16`. |
| `RP004` | error | `cdn_fronted` rejected at `Phase: V15`. |
| `RP005` | error | `cdn_fronted` candidate must carry ≥1 `cdn:*` tag in `public_risk_tags`. |
| `RP006` | error | `cdn_fronted` candidate must carry ≥1 `origin_*` tag in `origin_risk_tags`. |
| `RP007` | error | `cdn_fronted` family must appear `yes` or `conditional` in supplement §11.1.1's `cdn_fronted` column. (Validator carries the locked table.) |
| `RP008` | error | `direct_vps` candidate must carry ≥1 `public_ip:*` tag. |
| `RP009` | error | `direct_vps` candidate must NOT carry any `cdn:*` tag. |
| `RP010` | error | `direct_vps` candidate must NOT carry any `origin_*` tag. |
| `RP011` | error | `family_class` must be one of `vps-native | vps-possible | external-ecosystem`. |
| `RP012` | error | `probing_risk_class` must be one of `low | moderate | high`. |
| `RP013` | error | Non-empty `modifiers[]` rejected at `Phase: V15` and `Phase: V16`. (FRP-12 lifts per-modifier.) |
| `RP014` | error | Bundle must contain ≥2 `vps-native` candidates (one-candidate RelayPacks defeat the purpose). |
| `RP015` | error | `family_class: external-ecosystem` rejected for any FRP-self-hosted candidate. |
| `RP016` | error | `cell_scope.policy: transitive` rejected at `Phase: V15`. |
| `RP017` | error | Legacy flat `shared_risk_tags` array on `RouteManifestEntry` rejected with explicit pointer to v2.3.5 schema. |
| `RP018` | error | Bundle-level `relay_pack.shared_risk_graph` must reference only candidate IDs that exist in the bundle. |
| `RP021` | error | Bundle-level `relay_pack.freshness_url` must be empty at `Phase: V15`; FRP-8 lifts non-empty values at `Phase: V16`. |
| `RP019` | warn | All candidates share every `public_risk_tag` (no diversity at all). FRP nudge: "add a CDN front, a second VPS, or a different provider." |
| `RP020` | warn | Bundle has no `udp_gated:true` candidates AND no UDP-shaped candidates of any kind. |

## 6. Build matrix at FRP-1 exit

```
$ ls publisher/go.mod                                          # NEW: module daal/publisher (created by sub-task 6.5)
$ cd bundle/go && gofmt -l ./bundle                            # no output
$ cd publisher && gofmt -l ./...                               # no output (NEW publisher module)
$ cd bundle/go && go build ./bundle/...                        # green (Manifest.RelayPack slot + spec_version bump)
$ cd bundle/go && go test ./bundle/...                         # ≥10 new bundle-side tests pass (canonical round-trip; spec_version guard)
$ cd publisher && go build ./deploy/relaypack/...              # green (NEW: validator under daal/publisher module)
$ cd publisher && go test ./deploy/relaypack/...               # ≥25 new validator tests pass
$ cd core && go build ./...                                    # unchanged green
$ cd core && go test ./...                                     # unchanged green
$ nm /tmp/libdaalcore.so | grep ' T engine_' | wc -l          # 48 (UNCHANGED)
$ ls specs/relaypack-v1.md                                     # exists
$ # Asymmetric-dependency guard (publisher is downstream of bundle + core):
$ ! rg -n 'daal/publisher' bundle/go/                         # MUST exit non-zero
$ ! rg -n 'daal/publisher' core/                              # MUST exit non-zero
$ ls specs/test-vectors/relaypack/                             # 6 vectors
$ git grep -n 'spec_version' bundle/go/bundle/types.go         # bumped value
$ git grep -n '_relaypack' bundle/go/                          # exists in tests + relay_pack.go
```

## 7. Spec deliverables

**1 NEW:**
- `specs/relaypack-v1.md` — locks the schema + validator rules + lint codebook + compatibility contract.

**1 AMENDED:**
- `specs/sbp-v1.md` — gains a `RelayPack profile` cross-reference section pointing at `specs/relaypack-v1.md`.

**Test-vector corpus seeded:**
- `specs/test-vectors/relaypack/direct-vps-minimal.sbp` + `.expected.json`
- `specs/test-vectors/relaypack/direct-vps-with-sni.sbp` + `.expected.json`
- `specs/test-vectors/relaypack/cdn-fronted-minimal.sbp` + `.expected.json`
- `specs/test-vectors/relaypack/cdn-fronted-with-origin.sbp` + `.expected.json`
- `specs/test-vectors/relaypack/modifier-rejected.sbp` + `.expected.json`
- `specs/test-vectors/relaypack/legacy-flat-tags-rejected.sbp` + `.expected.json`

## 8. Out of scope (deferred)

- Importer wiring (`bundle/go/importer/importer.go` parse → `core/trust/state.go` `StoreAdapter` boundary → `core/routestore/store.go` `RouteRow` widening + `core/routestore/schema.go` inline migration → `core/netmem/` entry-value extension) — **FRP-2.**
- Selector hooks consuming `_relaypack` — **FRP-3.**
- Validator `Phase: V16` lifting `cdn_fronted` — handled by FRP-8 setting `Phase: V16` at validator-call sites.
- Validator `freshness_url` non-empty acceptance — handled by FRP-8.
- `cell_scope.policy: transitive` validator-allow — **FRP-11.**
- Per-modifier validator-allow — **FRP-12.**
- UI surfaces — **FRP-5 (wizard) / FRP-6 (recipient).**

## 9. Handover requirements

The FRP-1 handover must contain:

1. Status: SHIPPED. Date.
2. `spec_version` before/after.
3. New file paths added (per §3-§5 above).
4. Validator test count (`go test -count=1 -run TestRelayPackValidator ./bundle/go/publisher/...` output).
5. Round-trip test result (canonical bytes byte-identical).
6. `nm` count = 48 unchanged.
7. Six test vectors enumerated; expected behavior per vector.
8. `specs/relaypack-v1.md` page count.
9. FRP-2 gate verdict (PASS / HOLD / BLOCKED).
10. Open follow-ups for FRP-2 (specifically: the field set in `RouteRow` that FRP-2 must add).

## 10. Track ordering rationale

FRP-1 is first because the schema is the contract every later phase consumes. The `Explanation` struct (FRP-3), the wizard's RelayPack output (FRP-5), the deploy bind (FRP-4b), the freshness endpoint (FRP-8), the cell metadata (FRP-11) — all reference fields defined here. Landing the schema-only phase first means downstream phases can write tests against locked structures rather than against a moving target. The schema lives in `bundle/go/bundle/`, not in `core/abi/`, so FRP-1 introduces zero new release symbols and ABI=48 is preserved untouched until V1.5 actually ships at FRP-7.

End — locked at FRP-track planning. Next: FRP-2 (import + store preservation).
