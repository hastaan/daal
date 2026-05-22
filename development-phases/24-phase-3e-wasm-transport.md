# Phase 3E — WASM Transport Slot (WATER)

**Roadmap line:** V3.5 — "WASM transport slot — research → production gating."
**Status:** **SHIPPED.** All 10 sub-tasks landed.
**Engine version:** `daal-core 0.8.0+v3-wasm`.
**ABI release surface:** 45 → **47** (+2 symbols, append-only;
`nm libdaalcore.so | grep ' T engine_' | wc -l` = 47 verified).
**Handover:** `phases of development/24-phase-3e-wasm-transport.handover.md`.

## Roadmap coverage

A signed WASM module slot in the engine, conformant with WATER
(Operator Foundation's WASM Anti-Censorship Transport spec).
Modules are distributed as signed `.sbp` bundles with a new
`transport_module` route family, loaded into the engine via a
`wazero` runtime hosted by the Go core, enabled only for the
Experimental route family in user UI, and gated by a kill-switch
the project can flip remotely.

**This is the V3 success-metric milestone** — *"We shipped a new
transport without an app update."* 3E is also the first time a
project-signed kill-switch delta lands in the engine; the pattern
3F will reuse for family-level kill-switches.

## Locked decisions (12 invariants for 3E)

1. **ABI append-only.** +2 release symbols at 3E; surface 45 → 47.
2. **Runtime is `wazero`** (pure-Go, no CGo). Locked.
3. **First-shipping modules:** an HTTPS-shaped hello-world (TCP-443
   dial via the host callback) AND a deliberately-too-much-fuel
   module to exercise the fuel cap. Both ship in the soak.
4. **Kill-switch key:** a *single new* project signing key dedicated
   to WASM kill-switches only. Distinct from the bootstrap-directory
   key. Hardware-token-protected per CC.4.
5. **WATER v1 ABI only.** Module exports: `_start`,
   `water_transport_dial`, `water_transport_read`,
   `water_transport_write`, `water_transport_close`. Module imports
   from host: `water_log`, `water_clock_unix`, `water_random_fill`
   (deterministic in soak builds). No filesystem, no host network —
   the module dials through a host-supplied callback.
6. **Resource caps locked at 3E:**
   memory 16 MiB; fuel 10⁹ instructions per `dial`; 1 instance per
   route per session; module load timeout 5 s; total module bytes
   ≤ 4 MiB per module, ≤ 16 MiB total in a bundle.
7. **Experimental-only.** WASM modules are gated by the 3A
   experimental-families flag AND tagged Experimental in the family
   registry. Promotion to non-experimental is a roadmap-level
   decision (V4+).
8. **`-tags no_wasm` excluder.** Mirrors 3D's `no_psiphon` pattern.
   Distributors who cannot ship the wazero vendor tree pass
   `no_wasm`; the `wasm_compiled_in` diagnostic flips to false; the
   engine refuses to load modules.
9. **No new V0 failure categories.** WASM failures map onto existing
   categories (`route_unsupported` for unloaded module,
   `tcp_handshake_failed` aggregate for upstream dial fail,
   `engine_crash` for fuel-cap / memory-cap kills). Cosmetic-only
   widening.
10. **Soft-validation discipline preserved.** Empty
    `transport_module_slug` on a `transport_module` route is accepted
    at parse time (matches 3C/3D pattern); engine filters at
    activation.
11. **`UpsertRoute` non-clobber discipline preserved.** Engine-recorded
    module-state lives in `secrets_kv`, never overwritten by bundle
    re-import.
12. **Trust ladder unchanged** — WASM modules are signed by their
    publisher's existing key (TOFU); the kill-switch key only
    revokes, never approves.

## Sub-task breakdown (10 sub-tasks)

| #  | Task                                                                                              |
|----|---------------------------------------------------------------------------------------------------|
| 1  | `core/wasm/` package: Loader + Module + WATER v1 host ABI binding (wazero); resource caps + tests; `-tags no_wasm` excluder |
| 2  | Family registry: register `transport_module` family; `IsOpportunistic = false`; Experimental maturity; tests |
| 3  | Kill-switch: new key custody doc + `core/wasm/killswitch.go` verifier + secrets_kv cache + refresh hook + tests |
| 4  | Bundle parser: `transport_modules[]` + `routes[].transport_module_slug` + 5 new errors + ~8 v3e tests |
| 5  | Routestore: 1 ALTER (`transport_module_slug`) + RouteRow widening + non-clobber discipline + round-trip test |
| 6  | ABI: 2 new release symbols + 4 new diagnostics fields; engine version 0.7.3 → 0.8.0; tests           |
| 7  | Publisher CLI: `wasm-module` + `wasm-killswitch` subcommands + tests                              |
| 8  | Soak: 2 scenarios (`wasm-hello-transport`, `wasm-kill-switch`) + dispatch + invariant + v2-superset 21 → 23 |
| 9  | Specs: 2 NEW (`wasm-transport-v1.md`, `wasm-kill-switch-v1.md`) + 8 AMENDED                       |
| 10 | Handover doc + final regression sweep (`nm` count = 47, all tag combinations)                     |

## ABI additions

```
// Release symbol 46
const char* engine_wasm_kill_switch_pubkey(void);
//   Returns the hex-encoded WASM kill-switch publisher pubkey so a
//   UI can show "kill-switches signed by: ABCD…" for audit.
//   Empty string under -tags no_wasm. Always succeeds.

// Release symbol 47
const char* engine_loaded_wasm_modules(void);
//   Returns a JSON array snapshot of currently-loaded modules:
//   [{"slug":"hello-https","sha256_prefix":"a1b2c3d4","loaded_at":"…"}, …]
//   Empty array under -tags no_wasm or when no modules loaded.
```

Diagnostics widen with **4 always-present fields**:

| Field                            | Type   | Default                                            | Notes |
|----------------------------------|--------|----------------------------------------------------|-------|
| `wasm_compiled_in`               | bool   | `true` (default build); `false` under `-tags no_wasm` | mirrors 3D shape |
| `loaded_wasm_modules`            | array  | `[]`                                                | snapshot, not cumulative |
| `wasm_kill_switched_count`       | int    | `0`                                                 | running count of modules refused this session |
| `last_wasm_module_dial_outcome`  | string | `""`                                                | one of `ok` / `fuel_exhausted` / `memory_cap` / `dial_timeout` / `host_callback_error` / `""` |

## Bundle-format widening (SBP-v1, additive)

Top-level entry:

```jsonc
"transport_modules": [
  {
    "slug": "hello-https",
    "sha256": "<64 hex>",
    "wasm_blob_b64": "<base64; decoded ≤ 4 MiB>",
    "min_engine_version": "0.8.0",
    "optional_capabilities": []
  }
]
```

`routes[]` widening: 1 new optional field `transport_module_slug`.
Only meaningful on `transport_module` family routes; rejected on
other families. 5 new errors:
`ErrTransportModuleSlugOnNonModuleRoute`,
`ErrTransportModuleSlugMalformed`,
`ErrTransportModulesEntryMalformed`,
`ErrTransportModuleHashMismatch`,
`ErrTransportModuleOversize`.

## Resource caps (locked v1)

| Cap                                   | Value                                            | Failure mode                       |
|---------------------------------------|--------------------------------------------------|------------------------------------|
| Module wasm bytes                     | ≤ 4 MiB per module; ≤ 16 MiB total in bundle    | parser rejects                     |
| Module memory                         | 16 MiB                                           | runtime kills; outcome `memory_cap` |
| Fuel per `dial`                       | 10⁹ instructions                                 | runtime kills; outcome `fuel_exhausted` |
| Dial timeout                          | 5 s                                              | host kills; outcome `dial_timeout`  |
| Module load timeout                   | 5 s                                              | loader rejects; module excluded     |
| Instances per route per session       | 1                                                | enforced by Loader                  |
| Host network surface                  | TCP/443 dial only                                | other addresses rejected by host callback |

## Kill-switch protocol

The project signs `(publisher_fingerprint, slug, sha256, generation)`
tuples with a dedicated WASM kill-switch key. The engine fetches
deltas on the existing pointer-rotation refresh path, verifies the
signature against the embedded kill-switch pubkey, and caches the
killed (slug,sha256) under `wasm_killed:<sha256>` in `secrets_kv`.
A killed module is refused at every subsequent load attempt.

Kill-switch deltas are append-only within a generation; rescinds are
NOT supported at v1 (a kill-switch is a one-way safety valve).

## Soak coverage

**`wasm-hello-transport`** (~14 days): enables the experimental gate,
loads the HTTPS-shaped hello-world, drives 100 dials (≥ 95 % `ok`),
loads the deliberately-too-much-fuel module (outcome
`fuel_exhausted`; module unloaded; `wasm_kill_switched_count` does
NOT increment — fuel is not a kill-switch), and clears modules.

**`wasm-kill-switch`** (~14 days): loads hello-world; project signs
and publishes a kill-switch delta; engine refreshes, verifies,
refuses to load on next session; `wasm_kill_switched_count` ≥ 1;
the killed sha256 prefix MUST NOT appear in `loaded_wasm_modules`
(canonical regression `no_unloaded_module_appears_in_diagnostics`);
a *different* unkilled module loads cleanly (kill-switch is
per-module, not blanket).

`--scenarios v2-superset` widens 21 → **23**.

## Spec deliverables

**2 NEW:**

- `specs/wasm-transport-v1.md`
- `specs/wasm-kill-switch-v1.md`

**8 AMENDED:**

`specs/transport-families-v1.md`, `specs/sbp-v1.md`,
`specs/route-object-v1.md`, `specs/engine-abi-v1.md`,
`specs/publisher-cli-v1.md`, `specs/routestore-v1.md`,
`specs/failure-taxonomy-v1.md`, `specs/blackout-soak-rig-v1.md`.

## Out of scope (deferred to V4+ or 3F)

- Custom (non-WATER) WASM ABI.
- Module marketplace / discovery; modules ride the publisher channel.
- Module hot-reload; replacement requires a new session.
- Promotion to non-experimental.
- Family-level kill-switches (3F).
- Per-network-memory bias for WASM transports.
- Generalised `core/ladder/` package (revisit at V4).

## Build matrix at 3E exit

- `cd core && go build ./...` — green.
- `cd core && go build -tags no_wasm ./abi/...` — green; flag flips false.
- `cd core && go build -tags "no_psiphon no_wasm" ./abi/...` — green.
- `cd core && go test ./...` — green (default + each tag combination).
- `cd bundle/go && go build ./... && go test ./...` — green.
- `cd cmd/daal-soak-engine && go build -tags soak ./...` — green.
- `cd test-rigs/distribution-failure/soak-driver && go build ./... && go test ./...` — green.
- `nm libdaalcore.so | grep ^engine_ | wc -l` = **47**.

## Handover to 3F

3F (one-tap "send working routes") receives:

- A stable WASM transport slot at Experimental maturity.
- A precedent — the WASM kill-switch publisher key — for project-
  controlled signed deltas. 3F's family-level kill-switches reuse
  the verifier shape, the `secrets_kv` cache namespace, and the
  diagnostics-surface convention.
- ABI release surface 47, append-only invariant intact.
- Engine version `daal-core 0.8.0+v3-wasm` (V3 success metric line).
