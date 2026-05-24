
**Phase:** 3E
**Status:** Locked at 3E. Experimental.
**Roadmap line:** V3.5 — "WASM transport slot (WATER-style sandboxed transport)."
**Engine version:** `daal-core 0.8.0+v3-wasm`.
**ABI release surface:** 45 → **47** (+2 symbols; append-only invariant preserved).

---

## Scope

Adds a sandboxed WASM transport slot that lets the project
ship new transports as signed `.wasm` modules without an
engine release. Modules are loaded by the
[wazero](https://github.com/tetratelabs/wazero) pure-Go runtime
and bind to the WATER v1 host ABI (Operator Foundation's WASM
Anti-Censorship Transport ABI). The runtime is the **only**
WASM runtime supported at 3E.

Modules ride inside the existing publisher channel as a new
manifest top-level array `transport_modules[]`; routes refer to
their module by `transport_module_slug`. The
`transport_module` family is **Experimental** (auto-promotion
NEVER selects it; tap-Connect MUST opt in with the experimental
gate).

This spec does NOT cover the kill-switch surface — see
[wasm-kill-switch-v1.md](wasm-kill-switch-v1.md).

---

## Locked invariants

1. **WATER v1 ABI only.** Modules import a closed set of host
   functions: `dial(host_ptr, host_len, port) -> conn_id`,
   `read(conn_id, ptr, len) -> n`, `write(conn_id, ptr, len)
   -> n`, `close(conn_id)`. No filesystem, no clock, no
   environment, no syscalls. This is the v1 ABI; future
   versions are NEW family slots, not amendments.

2. **Resource caps (locked at 3E):**
   - Memory: 16 MiB per instance, hard cap.
   - Fuel: 1e9 instructions per dial attempt.
   - Wall-clock: 5 s per dial attempt.
   - Per-module size: ≤ 4 MiB compiled.
   - Total bundle ceiling: ≤ 16 MiB across all modules.

3. **Closed dial-outcome enum (5):** `ok`, `fuel_exhausted`,
   `memory_cap`, `dial_timeout`, `host_callback_error`. Other
   outcomes MUST be classified into one of these or rejected.
   Engines MUST NOT extend the enum without a new spec phase.

4. **Per-module deterministic compile.** A module's
   `sha256_hex` MUST match the SHA-256 of its `wasm_blob_b64`
   bytes; engines verify on load. Mismatch → bundle rejected.

5. **Slug regex (locked):** `[a-z0-9_-]{3,32}`. The same regex
   is enforced by the publisher CLI, the bundle parser, the
   route-store column, and the WASM loader.

6. **No promotion.** `transport_module` is Experimental at 3E.
   The maturity ladder does NOT promote it. Promotion requires
   a new spec phase.

7. **Excludable.** Build with `-tags no_wasm` to compile out
   the wazero runtime entirely. With the tag, all loads return
   `ErrCompiledOut`; the diagnostics field
   `wasm_compiled_in` flips to `false`; the two release
   symbols are still present (they emit the empty surface).

8. **Soft-validation discipline preserved.** A bundle whose
   `transport_modules[]` array is malformed is rejected
   wholesale; routes that *reference* a missing module slug
   are skipped (per-route soft validation), not the whole
   bundle. This matches the ladder used by every other 3.x
   transport family.

9. **UpsertRoute non-clobber preserved.** The Phase 3E
   `transport_module_slug` column is included in the
   non-clobber list: an UpsertRoute that supplies the empty
   string MUST NOT erase a previously-set slug. The same
   discipline applied at 3D for psiphon/conjure-only fields.

---

## Module entry shape

```json
{
  "slug":              "hello-https",
  "sha256":            "<64-hex>",
  "wasm_blob_b64":     "<base64 of compiled .wasm>",
  "min_engine_version":"0.8.0",
  "optional_capabilities": []
}
```

`optional_capabilities` is reserved for V4 (e.g.
`"udp_dial"`, `"hostname_override"`); 3E engines refuse any
non-empty value to keep the v1 ABI a closed set.

## Route entry additions

A route in family `transport_module` MUST set
`transport_module_slug` (the slug of an entry in the bundle's
`transport_modules[]`):

```json
{
  "id":                   "tm-hello-https",
  "transport_family":     "transport_module",
  "scarcity_class":       "experimental",
  "transport_module_slug":"hello-https",
  "valid_from":           "...",
  "valid_until":          "...",
  ...
}
```

A route whose `transport_module_slug` is unknown to the
loaded bundle is **skipped** (soft-validated out); other
routes are unaffected.

## Diagnostics

Four new fields land on the existing diagnostics object:

- `wasm_compiled_in` (bool): `true` unless `-tags no_wasm`.
- `loaded_wasm_modules` (array of
  `{slug, sha256_prefix, loaded_at}`): the modules currently
  loaded into the wazero runtime. `sha256_prefix` is the first
  16 hex chars (8 bytes) — never the full hash, never the
  blob.
- `wasm_kill_switched_count` (int): the cardinality of the
  killed-sha256 set the engine has daalted from
  `secrets_kv:wasm_killed:*` plus any deltas applied this
  session.
- `last_wasm_module_dial_outcome` (closed enum, see invariant
  3): the most recent dial outcome the WASM transport
  recorded, or empty string at boot.

## ABI surface (release symbols 46 + 47)

- `engine_wasm_kill_switch_pubkey()` (release 46) —
  buffer-style cshared. Returns the engine-immutable
  Ed25519 public key (32 bytes raw) for the WASM kill-switch
  surface. Allows host UIs to display the publisher
  fingerprint.
- `engine_loaded_wasm_modules()` (release 47) —
  buffer-style cshared. Returns a JSON array
  `[{slug, sha256_prefix, loaded_at}, …]` matching the
  `loaded_wasm_modules` diagnostic field.

Both symbols are present under `-tags no_wasm` (they emit the
empty surface).

## Out of scope (deferred)

- Custom (non-WATER) WASM ABI.
- Module hot-reload (replacement requires a new session).
- Promotion to non-experimental.
- Module marketplace / discovery (rides the publisher channel).
- Family-level kill-switches (3F).
- Per-network-memory bias for WASM transports.

## Cross-references

- [wasm-kill-switch-v1.md](wasm-kill-switch-v1.md)
- [transport-families-v1.md](transport-families-v1.md)
- [sbp-v1.md](sbp-v1.md)
- [route-object-v1.md](route-object-v1.md)
- [routestore-v1.md](routestore-v1.md)
- [engine-abi-v1.md](engine-abi-v1.md)
- [publisher-cli-v1.md](publisher-cli-v1.md)
- [failure-taxonomy-v1.md](failure-taxonomy-v1.md)
- [blackout-soak-rig-v1.md](blackout-soak-rig-v1.md)
