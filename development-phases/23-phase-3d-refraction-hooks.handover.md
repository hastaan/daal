
## Status

**SHIPPED.** All 10 sub-tasks landed. Engine version
`daal-core 0.7.3+v3-transport`. Release ABI count **45**
(45 → 45; **no new release symbols** — append-only invariant
preserved). Two new transport families (`psiphon`, `conjure`),
both Experimental at first ship.

## Roadmap line

V3.4 ("Refraction-family hooks: Psiphon + Conjure"). The 3D
landing wires Daal to two refraction-class upstream libraries:
`psiphon-tunnel-core` (GPLv3, isolated behind `-tags
no_psiphon`) and `gotapdance` (Apache-2.0, ships
unconditionally). Daal does NOT operate refraction
infrastructure — these are publisher-supplied stations and
phantom pools.

## What landed

### Engine

- **`core/transports/psiphon/`** — new package, stdlib-only.
  - `FamilyID = "psiphon"`.
  - `Handler.Dial(ctx, route, blob)` accepts the opaque
    publisher bundle blob bytes and hands them to the
    upstream library callback. The callback shape keeps the
    package free of the `psiphon-tunnel-core` import until
    the upstream dialer wires in.
- **`core/transports/conjure/`** — new package, stdlib-only.
  - `FamilyID = "conjure"`.
  - `HashPhantom(rawIP)` helper renders the 8-byte SHA-256
    truncation, hex-encoded (16 chars). Used by the diagnostic-
    redaction path; reused at the abi boundary so the raw IP
    NEVER leaves the conjure transport package.
  - `Handler.Dial(ctx, route, phantomConfig)` accepts the
    phantom-pool / station-pubkey / decoy-pool config and
    surfaces the chosen phantom IP in `Conn.PhantomInUseHash`.
- **Routestore widening** (4 new columns; additive ALTERs).
  - `psiphon_bundle_blob` (`BLOB`, default `X''`).
  - `conjure_phantom_subnets_json` (`TEXT`, default `''`).
  - `conjure_station_pubkey_hex` (`TEXT`, default `''`).
  - `conjure_decoy_pool_json` (`TEXT`, default `''`).
  - `RouteRow` widened; nil `[]byte` → empty fix in `UpsertRoute`,
    `Get`, `List` (canonical regression in
    `TestUpsertRoute_3DFieldsRoundTrip`). Non-clobber discipline
    preserved for engine-recorded state.
- **Family registry.**
  - New `IsOpportunistic` field on the family registration
    record. `psiphon: false`. `conjure: true`. **`masque: true`**
    (retroactive 3D annotation; the 3C special-case in the
    auto-promotion detector now reads from the registry).
  - `IsOpportunisticFamily(familyID)` helper for the auto-
    promotion detector.
- **Bundle parser.**
  - 4 new optional `routes[]` fields:
    `psiphon_bundle_blob_b64` (base64; decoded length
    `[256, 65536]`), `conjure_phantom_subnets` (CIDR list;
    floors `/24` IPv4, `/32` IPv6), `conjure_station_pubkey`
    (64 hex chars), `conjure_decoy_pool` (RFC 1123 hostnames).
  - 6 new errors:
    `ErrPsiphonBlobOnNonPsiphonRoute`,
    `ErrPsiphonBlobMalformed`,
    `ErrConjureFieldOnNonConjureRoute`,
    `ErrConjurePhantomSubnetsMalformed`,
    `ErrConjureStationPubkeyMalformed`,
    `ErrConjureDecoyPoolMalformed`.
  - **Soft-validation discipline.** Empty fields on a
    psiphon/conjure route are accepted at parse time (mirrors
    3A `family_specific_config` and 3C `masque_endpoint`
    rules). The engine filters at activation time.
- **ABI.**
  - **No new release-surface symbols** at 3D. The release
    surface stays at **45**.
  - Engine `Version` bumps to `daal-core 0.7.3+v3-transport`.
  - 5 new diagnostic fields, always present:
    - `psiphon_compiled_in: bool` — `false` when built with
      `-tags no_psiphon`; `true` otherwise.
    - `conjure_compiled_in: bool` — constant `true` at 3D
      (reserved for future build-tag conditioning).
    - `psiphon_active_route: string` — most recently
      activated psiphon route ID this session.
    - `conjure_active_route: string` — most recently
      activated conjure route ID this session.
    - `conjure_phantom_in_use: string` — 8-byte SHA-256
      truncation of the raw phantom IP, hex-encoded.
      Raw IP NEVER appears in diagnostics.
  - Package-internal entry points:
    `RecordPsiphonActiveRoute(routeID)`,
    `RecordConjureActivation(routeID, rawPhantomIP)`,
    `PsiphonActiveRoute()`, `ConjureActiveRoute()`,
    `ConjurePhantomInUseHash()`. Called by the in-process
    transport handlers and by the soak-engine RPC dispatcher
    (soak builds only).
  - `psiphon_compiled.go` / `psiphon_compiled_excluded.go`
    build-tag-conditional shims drive the
    `psiphon_compiled_in` flag.
  - `conjure_compiled.go` constant-true shim (no excluder
    twin at 3D — Apache-2.0 vendor tree ships
    unconditionally).

### Publisher CLI

- **`daal-publish psiphon-bundle`** — wraps an upstream
  Psiphon publisher bundle blob into a `routes[]` entry stub.
  Validates size envelope `[256, 65536]`. Default
  scarcity `normal`; `--scarcity emergency` is **rejected**
  (locked decision: emergency-class is the bootstrap-pool
  budget). Default route ID `ps-<8-byte-SHA-256-prefix>`.
- **`daal-publish conjure-bridge`** — emits a `routes[]`
  entry stub for a Conjure station + phantom-pool selection.
  Validates phantom-subnet floors (`/24` IPv4, `/32` IPv6),
  64-hex station pubkey, RFC 1123 decoy hostnames. Default
  scarcity `experimental`. Default route ID
  `cj-<8-hex-station-pubkey-prefix>`.
- Both commands inherit the no-network-socket OPSEC invariant.

### Bundle (Go module)

- `RouteManifestEntry` widened with the 4 new fields.
- 7 round-trip tests in `bundle/go/bundle/v3d_test.go`.
- Publisher helpers in `bundle/go/publisher/psiphon.go` and
  `bundle/go/publisher/conjure.go` (with their own test files).
- Wired into `cmd/daal-publish/main.go` with help-line entries.

### Soak rig

- **2 new scenarios** (3D ship-gate parity tier widens
  19 → **21**):
  - `psiphon-blob-rotation` — exercises psiphon activation
    lifecycle and the locked NOT-opportunistic invariant on
    day 14.
  - `conjure-phantom-pool` — exercises conjure activation
    lifecycle, the canonical `no_raw_phantom_ip_leak_in_diagnostics`
    invariant on day 3, and the IS-opportunistic invariant
    on day 20.
- **2 new soak-only RPC dispatch paths** in
  `cmd/daal-soak-engine/main.go`:
  `soak-record-psiphon-active-route`,
  `soak-record-conjure-activation`.
- **2 new soak-driver client methods** in
  `internal/client/client.go`:
  `SoakRecordPsiphonActiveRoute`,
  `SoakRecordConjureActivation`.
- **2 new dispatch cases** in `internal/soak/soak.go`:
  `soak_record_psiphon_active_route`,
  `soak_record_conjure_activation`.
- **1 new privacy invariant** in `internal/invariants/invariants.go`:
  `ruleNoRawPhantomIPLeakInDiagnostics` — asserts the raw IP
  supplied to a `soak_record_conjure_activation` action does
  NOT appear in `engine_export_diagnostics`. Mirrors the 2C
  SSID and 2D PIN no-leak invariants.

### Specs

- **2 new specs:**
  - `specs/psiphon-route-v1.md` — locked invariants,
    bundle-format widening, diagnostics, publisher CLI,
    engine-side activation, soak coverage.
  - `specs/conjure-route-v1.md` — phantom-pool floors,
    HASHED phantom-IP diagnostics, publisher CLI, soak
    coverage.
- **8 amended specs:**
  - `specs/sbp-v1.md` — Phase 3D widening section + parser
    error vocabulary widening.
  - `specs/transport-families-v1.md` — psiphon/conjure rows
    bolded in the family table; 3D amendment section
    introducing `IsOpportunistic`.
  - `specs/route-object-v1.md` — 4 new route fields documented.
  - `specs/engine-abi-v1.md` — Phase 3D additions section,
    no new release symbols, 5 new diagnostics fields,
    canonical regressions.
  - `specs/publisher-cli-v1.md` — `psiphon-bundle` +
    `conjure-bridge` subcommand sections.
  - `specs/routestore-v1.md` — Phase 3D additions section
    (4 new ALTERs).
  - `specs/failure-taxonomy-v1.md` — psiphon/conjure cosmetic
    surfaces mapped onto existing V0 categories (no new V0
    category at 3D).
  - `specs/blackout-soak-rig-v1.md` — v2-superset count
    19 → 21 + 3D scenarios documented.

## Locked decisions (12)

1. ABI append-only; +0 release symbols at 3D.
2. Daal does NOT operate refraction infrastructure.
3. Both families Experimental at first ship.
4. GPLv3 isolation: `-tags no_psiphon` excluder.
5. Psiphon NOT opportunistic; Conjure IS — new
   `IsOpportunistic` family-registration field; retroactive
   masque annotation.
6. No new V0 failure categories (cosmetic-only widening).
7. No per-network-memory bias for refraction at 3D.
8. Opaque blob carriage for Psiphon (size sanity
   `[256, 65536]` bytes).
9. Conjure phantom-pool floors LOCKED: `/24` IPv4, `/32` IPv6.
10. `conjure_phantom_in_use` diagnostic HASHED (8-byte
    SHA-256).
11. Trust ladder unchanged.
12. `UpsertRoute` non-clobber discipline preserved.

## Canonical regressions (post-3D)

Engine:
- `core/abi/refraction_test.go::TestDiagnostics_AlwaysCarryRefractionFields`
- `core/abi/refraction_test.go::TestRecordPsiphonActiveRoute_RoundTrips`
- `core/abi/refraction_test.go::TestRecordConjureActivation_HashesPhantomIP`
- `core/abi/refraction_test.go::TestRecordConjureActivation_DifferentIPsHashDifferently`
- `core/abi/refraction_test.go::TestPsiphonCompiledInFlag_TruePerDefault`
- `core/abi/refraction_test.go::TestVersionStringIs073`
- `core/transports/psiphon/psiphon_test.go::*` (5 tests)
- `core/transports/conjure/conjure_test.go::*` (8 tests)
- `core/routestore/store_test.go::TestUpsertRoute_3DFieldsRoundTrip`
- `core/routestore/family_test.go::TestIsOpportunisticFamily_3DLockedClassification`

Bundle:
- `bundle/go/bundle/v3d_test.go::*` (7 tests)
- `bundle/go/publisher/psiphon_test.go::*` (4 tests)
- `bundle/go/publisher/conjure_test.go::*` (5 tests)

Soak:
- `psiphon-blob-rotation` scenario (v2-superset).
- `conjure-phantom-pool` scenario (v2-superset).
- `no_raw_phantom_ip_leak_in_diagnostics` invariant.

## Build matrix verified

- `cd /home/daal/core && go build ./...` — green.
- `cd /home/daal/core && go build -tags no_psiphon ./abi/...`
  — green (compile-in flag flips correctly).
- `cd /home/daal/core && go test ./...` — green.
- `cd /home/daal/bundle/go && go build ./... && go test ./...`
  — green.
- `cd /home/daal/cmd/daal-soak-engine && go build -tags soak ./...`
  — green.
- `cd /home/daal/test-rigs/distribution-failure/soak-driver && go build ./... && go test ./...`
  — green.

## Carry-overs (V3-wide; deferred from 3D)

- Wire bundle importer → trust adapter → routestore for
  `RendezvousPriority`, `MasqueEndpoint`, Psiphon blob,
  Conjure fields → 3-Soak.
- Family-level kill-switch publisher key + delta format → 3E.
- Generalised `core/ladder/` (lift the masque sub-mode
  cascade abstraction) → 3E.
- Per-network-memory bias for refraction families →
  conditional at 3-Soak (deferred at 3D per locked decision 7).

## Next phase

**3E — `transport_module` family (WATER ABI / WASM transports).**
ABI release surface 45 → 46 expected (one new symbol for the
WASM module loader). Adds `kill_switches[]` consumption (the
field was reserved at 3A but unused through 3D).
