## Status

**SHIPPED.** All 10 sub-tasks landed. Engine version
`daal-core 0.8.0+v3-wasm`. Release ABI count **47**
(45 → 47; **+2 new release symbols**, append-only invariant
preserved). One new transport family (`transport_module`),
Experimental at first ship. New WASM kill-switch publisher
key (CC.4 hardware-token custody) and `secrets_kv` keyspace.

## Roadmap line

V3.5 ("WASM transport slot — WATER-style sandboxed
transport"). The 3E landing wires Daal to the wazero pure-Go
runtime and binds modules to the WATER v1 host ABI (Operator
Foundation's WASM Anti-Censorship Transport ABI). The vendored
runtime is Apache-2.0 and ships unconditionally; a
`-tags no_wasm` excluder is supported for builds that wish to
strip the runtime entirely (the two release symbols still
emit, with the empty surface).

## What landed

### Engine

- **`core/wasm/`** — new package, wazero-bound.
  - `Loader` + `Module` types; WATER v1 host ABI (`dial`,
    `read`, `write`, `close`).
  - Resource caps locked at 3E: 16 MiB memory, 1e9 fuel
    per dial, 5 s wall-clock per dial, ≤ 4 MiB per module,
    ≤ 16 MiB total bundle.
  - `Dial(ctx, route, slug)` driver; closed dial-outcome
    enum (`ok`, `fuel_exhausted`, `memory_cap`,
    `dial_timeout`, `host_callback_error`).
  - `KillSwitchVerifier` — Ed25519-verifies signed
    `(slug, sha256, generation)` deltas under the engine's
    embedded pubkey; persists killed sha256s to
    `secrets_kv:wasm_killed:*`; daaltes on boot;
    monotonic generation watermark in
    `secrets_kv:wasm_killed:_generation`.
  - `wasm_excluded.go` / `killswitch_excluded.go` —
    `-tags no_wasm` shims (return `ErrCompiledOut`; the
    diagnostics flag flips to `false`).
  - 10 unit tests + 8 kill-switch tests + the
    `TestPublisherCanonicalPayload_RoundTrips` regression
    that locks byte-for-byte equality between the
    publisher CLI and engine canonical payloads.

- **Routestore widening** (1 new column; additive ALTER):
  - `transport_module_slug` (`TEXT`, default `''`).
  - `RouteRow` widened; non-clobber discipline preserved
    (`TestUpsertRoute_3EFieldsRoundTrip` covers
    `wasm_killed` non-clobber).
  - Two new `secrets_kv` namespaces:
    `wasm_killed:<sha256-hex>` and
    `wasm_killed:_generation`.

- **Family registry.**
  - `transport_module` family registered as Experimental
    and **NOT opportunistic** (parity with `psiphon`).
  - `TestFamilyMaturity_3ETransportModuleIsExperimentalAndNonOpportunistic`
    locks the classification.

- **Bundle parser.**
  - 1 new top-level array: `transport_modules[]`
    (`TransportModuleEntry`).
  - 1 new `routes[]` field: `transport_module_slug`
    (REQUIRED on `transport_module` routes; rejected on
    other families).
  - 1 reserved top-level array: `wasm_kill_switch_deltas[]`
    (carries signed kill-switch entries; locked shape).
  - 5 new errors:
    `ErrWasmModuleMissing`,
    `ErrWasmModuleSHAMismatch`,
    `ErrWasmModuleOversize`,
    `ErrWasmModuleSlugInvalid`,
    `ErrWasmModuleDuplicateSlug`.
  - Soft-validation discipline preserved: a route whose
    slug is unknown is skipped; bundle-level errors
    reject wholesale.

- **ABI.**
  - **Two new release-surface symbols** (release 46 + 47;
    append-only invariant preserved):
    - `engine_wasm_kill_switch_pubkey()` — buffer-style
      cshared. Returns the engine-immutable Ed25519
      pubkey (32 raw bytes).
    - `engine_loaded_wasm_modules()` — buffer-style
      cshared. Returns
      `[{slug, sha256_prefix, loaded_at}, …]` JSON.
  - Engine `Version` bumps to `daal-core 0.8.0+v3-wasm`.
  - 4 new diagnostic fields, always present:
    - `wasm_compiled_in: bool` — `false` under
      `-tags no_wasm`; `true` otherwise.
    - `loaded_wasm_modules: [{slug, sha256_prefix,
      loaded_at}]`.
    - `wasm_kill_switched_count: int`.
    - `last_wasm_module_dial_outcome: string` (closed
      enum).
  - Package-internal entry points:
    `RecordLoadedWasmModule`, `ClearLoadedWasmModules`,
    `RecordWasmDialOutcome`,
    `SetWASMKillSwitchVerifier`, `SetWASMLoader`,
    `LastWasmDialOutcome`, `WasmKillSwitchedCount`. Used
    by the in-process loader and the soak-engine RPC
    dispatcher.
  - `wasm_compiled.go` / `wasm_compiled_excluded.go`
    build-tag-conditional shims drive the
    `wasm_compiled_in` flag.
  - `Shutdown` resets the per-process WASM state to
    survive the engine reset hooks.
  - **Internal helpers:** `abi.PutSecret`,
    `abi.GetSecret`, `abi.ListSecretKeys` — thin
    forwarders to the routestore for soak-harness use;
    NOT part of the release ABI surface.

### Publisher CLI

- **`daal-publish wasm-module`** — wraps a `.wasm` blob
  into a `transport_modules[]` entry stub plus a paired
  `routes[]` entry stub. Validates: 4 MiB cap, slug regex
  `[a-z0-9_-]{3,32}`, scarcity (`emergency` rejected).
  Default route ID `tm-<slug>`; default validity 7 d.
- **`daal-publish wasm-killswitch`** — signs a
  `(slug, sha256, generation)` tuple under a supplied
  Ed25519 private key (raw 64 bytes or hex-encoded). The
  canonical payload is byte-for-byte identical to the
  engine verifier's input. Generation MUST be > 0.
- Both commands inherit the no-network-socket OPSEC
  invariant.

### Bundle (Go module)

- `TransportModuleEntry` shape locked.
- `KillSwitchEntry` locked at the publisher-canonical shape.
- `Manifest.TransportModules`, `RouteManifestEntry.TransportModuleSlug`
  fields added.
- 8 v3e tests in `bundle/go/bundle/v3e_test.go`.
- Publisher helpers in `bundle/go/publisher/wasm.go` (with 8
  test cases).
- Wired into `cmd/daal-publish/main.go` with help-line
  entries.

### Soak rig

- **2 new scenarios** (3E ship-gate parity tier widens
  21 → **23**):
  - `wasm-hello-transport` — exercises the WASM
    activation lifecycle, the resource caps, and the
    "fuel exhaustion is NOT a kill-switch" invariant.
  - `wasm-kill-switch` — exercises the project-controlled
    signed-delta kill-switch and the canonical regression
    `no_unloaded_module_appears_in_diagnostics`. Asserts
    the kill-switch is per-module (a different unkilled
    module loads cleanly) and that the killed-set
    persists across sessions via
    `secrets_kv:wasm_killed:*`.
- **3 new soak-only RPC dispatch paths** in
  `cmd/daal-soak-engine/main.go`:
  - `soak-load-wasm-module` (slug, sha256).
  - `soak-publish-wasm-killswitch-delta`
    (slug, sha256, generation) — signed in-process by the
    soak harness's lazy-generated keypair (NOT the
    production CC.4 key); calls the engine's verifier
    `Apply`.
  - `soak-record-wasm-outcome` (outcome).
- **3 new soak-driver client methods** in
  `internal/client/client.go`: `SoakLoadWasmModule`,
  `SoakPublishWasmKillswitchDelta`,
  `SoakRecordWasmOutcome`.
- **3 new dispatch cases** in `internal/soak/soak.go`:
  `soak_load_wasm_module`,
  `soak_publish_wasm_killswitch_delta`,
  `soak_record_wasm_outcome`.

### Specs

- **2 new specs:**
  - `specs/wasm-transport-v1.md` — locked invariants
    (WATER v1 ABI, resource caps, slug regex, no
    promotion, excludable), entry shape, route-field
    addition, diagnostics, ABI symbols.
  - `specs/wasm-kill-switch-v1.md` — single project key
    at v1, append-only generation watermark, canonical
    signing payload (locked byte-for-byte), entry shape,
    per-module sha256 keying, daalte-on-boot, no
    rescinds at v1, fuel-vs-kill-switch separation,
    `no_unloaded_module_appears_in_diagnostics` invariant.

- **8 amended specs:**
  - `specs/sbp-v1.md` — Phase 3E widening section + 5 new
    errors documented.
  - `specs/transport-families-v1.md` — `transport_module`
    row promoted from "(planned)" to bolded ship-row;
    Phase 3E amendment section.
  - `specs/route-object-v1.md` — `transport_module_slug`
    documented; non-clobber rule called out.
  - `specs/engine-abi-v1.md` — Phase 3E additions section
    (2 new release symbols, 4 new diagnostics fields,
    canonical regressions).
  - `specs/publisher-cli-v1.md` — `wasm-module` +
    `wasm-killswitch` subcommand sections.
  - `specs/routestore-v1.md` — Phase 3E additions section
    (1 new ALTER + 2 new `secrets_kv` keyspaces).
  - `specs/failure-taxonomy-v1.md` — 7 cosmetic surfaces
    mapped onto existing V0 categories (no new V0
    category at 3E); fuel-exhaustion classification
    locked.
  - `specs/blackout-soak-rig-v1.md` — v2-superset count
    21 → 23 + 3E scenarios documented + 3 new soak RPCs.

## Locked decisions (12)

1. ABI append-only; +2 release symbols at 3E (45 → 47).
2. wazero is the only WASM runtime supported at 3E.
3. Hello-world + fuel-hog modules in soak.
4. Single new kill-switch project key (CC.4 hardware-token
   custody).
5. WATER v1 ABI only.
6. Resource caps: 16 MiB / 1e9 fuel / 5 s timeouts;
   ≤ 4 MiB/module; ≤ 16 MiB total bundle.
7. `transport_module` Experimental at first ship; NOT
   opportunistic.
8. `-tags no_wasm` excluder. With the tag, both release
   symbols still emit (empty surface).
9. No new V0 failure categories (cosmetic-only widening).
10. Soft-validation discipline preserved: per-route +
    per-entry rejects; bundle-level rejects only on
    structural errors.
11. UpsertRoute non-clobber discipline preserved (slug is
    in the non-clobber list).
12. Trust ladder unchanged.

## Canonical regressions (post-3E)

Engine:
- `core/wasm/wasm_test.go::*` (10 tests)
- `core/wasm/killswitch_test.go::*` (8 tests +
  `TestPublisherCanonicalPayload_RoundTrips`)
- `core/abi/wasm_test.go::*` (6 tests, build-tagged
  `!no_wasm`)
- `core/abi/wasm_excluded_test.go::*` (3 tests, build-tagged
  `no_wasm`)
- `core/abi/rendezvous_test.go::TestVersionStringIncludesV3Transport`
  (asserts `0.8.0+v3-wasm`)
- `core/routestore/store_test.go::TestUpsertRoute_3EFieldsRoundTrip`
- `core/routestore/family_test.go::TestFamilyMaturity_3ETransportModuleIsExperimentalAndNonOpportunistic`

Bundle:
- `bundle/go/bundle/v3e_test.go::*` (8 tests)
- `bundle/go/publisher/wasm_test.go::*` (8 tests)

Soak:
- `wasm-hello-transport` scenario (v2-superset).
- `wasm-kill-switch` scenario (v2-superset).
- `no_unloaded_module_appears_in_diagnostics` invariant
  (canonical regression: a killed module's slug or sha256
  prefix MUST NOT surface in `loaded_wasm_modules`).

## Build matrix verified

- `cd /home/daal/core && go build ./...` — green.
- `cd /home/daal/core && go build -tags no_wasm ./abi/...`
  — green (compile-in flag flips correctly; both release
  symbols still emit).
- `cd /home/daal/core && go build -tags no_psiphon ./abi/...`
  — green.
- `cd /home/daal/core && go build -tags "no_psiphon no_wasm" ./abi/...`
  — green.
- `cd /home/daal/core && go test ./...` — green.
- `cd /home/daal/core && go test -tags no_wasm ./abi/... ./wasm/...`
  — green.
- `cd /home/daal/bundle/go && go build ./... && go test ./...`
  — green.
- `cd /home/daal/cmd/daal-soak-engine && go build -tags soak ./...`
  — green.
- `cd /home/daal/test-rigs/distribution-failure/soak-driver && go build ./... && go test ./...`
  — green.
- `cd /home/daal/core && go build -buildmode=c-shared -tags cshared -o /tmp/libdaalcore.so ./cmd/libdaalcore` —
  green.
- `nm -D /tmp/libdaalcore.so | grep ' T engine_' | wc -l` =
  **47** ✅ (was 45 at 3D).
- Same with `-tags "cshared no_wasm"` = 47 (both new
  symbols still emit).

## Carry-overs (V3-wide; deferred from 3E)

- Wire bundle importer → trust adapter → routestore for
  `TransportModules`, `TransportModuleSlug`, and
  `WasmKillSwitchDeltas` → 3-Soak.
- Family-level kill-switch publisher key + delta format
  (kill the entire `psiphon` or `masque` family in one
  delta) → 3F.
- Generalised `core/ladder/` (lift the masque sub-mode
  cascade abstraction) → V4 (3E did not need it).
- Per-network-memory bias for WASM transports → V4.

## Next phase

**3F — One-tap "send working routes" with delegate keys.**
ABI release surface 47 → 48 expected (one new symbol for
delegate-key issuance). Reuses the WASM kill-switch verifier
shape (3E precedent) for family-level kill-switches.
