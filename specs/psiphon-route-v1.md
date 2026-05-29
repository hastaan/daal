# psiphon-route-v1

**Phase:** 3D
**Status:** Locked at 3D. Experimental.
**Roadmap line:** V3.4 — "Refraction-family hooks (Psiphon + Conjure)."
**Engine version:** `daal-core 0.7.3+v3-transport`.
**ABI release surface:** 45 → **45** (no new symbols; append-only invariant preserved).

---

## Scope

Adds `psiphon` as a transport family. A `psiphon` route carries an
**opaque publisher-bundle blob** that the upstream
`psiphon-tunnel-core` library understands; Daal does NOT parse the
blob's internal structure. The engine ships the vendored
`psiphon-tunnel-core` tree under GPLv3, isolated behind the
`-tags no_psiphon` build excluder so distributors who cannot ship
GPLv3 can produce a Daal binary without that vendor tree (the
`psiphon_compiled_in` diagnostic flag flips to `false`, and the
engine refuses to activate psiphon routes rather than papering over
the missing tree).

Psiphon is **NOT opportunistic**: the auto-promotion detector (2G)
MUST NOT promote a network whose only available family is psiphon.
This is the dual of the conjure family (which IS opportunistic) and
of masque (which IS opportunistic). The locked decision is recorded
on the family registry's `IsOpportunistic` field at 3D.

---

## Locked invariants

1. **Opaque-blob carriage.** Daal reads the bundle blob bytes from
   the SBP manifest, applies a size-envelope sanity check
   (256 bytes ≤ size ≤ 65536 bytes), base64-decodes to bytes, and
   passes the bytes verbatim to the upstream library. Daal does
   NOT inspect, sign, or re-encode the blob.

2. **GPLv3 isolation.** The vendored psiphon-tunnel-core tree is
   gated behind the `-tags no_psiphon` excluder; release builds
   for distributors who ship under that tag report
   `psiphon_compiled_in: false` and refuse psiphon-route activation.
   The flag is surfaced verbatim in `engine_export_diagnostics`.

3. **Not opportunistic.** Auto-promotion (2G) MUST NOT promote a
   network whose only available family is psiphon. The engine's
   family registry's `IsOpportunistic` field is `false` for
   psiphon, `true` for conjure (3D), `true` for masque
   (retroactive 3D annotation).

4. **No emergency-class routes.** The publisher CLI's
   `psiphon-bundle` subcommand rejects `--scarcity emergency`
   because emergency-class capacity is the bootstrap pool budget
   and a psiphon route cannot share that budget without burning
   the publisher's quota.

5. **Soft-validation discipline at parse time.** Like the 3C
   `masque_endpoint` field and the 3A `family_specific_config`
   field, an empty `psiphon_bundle_blob_b64` on a psiphon route
   is NOT a parse-time rejection — a publisher MAY pre-publish a
   route stub before wiring up the upstream bundle. The engine
   filters such routes at activation time.

6. **Append-only ABI.** No new release-surface symbols are added
   at 3D. The `RecordPsiphonActiveRoute` Go-level entry point is
   package-internal (called by the in-process psiphon handler at
   activation time, and by the soak-engine RPC dispatcher for
   the rig); it is NOT a release ABI symbol.

---

## Bundle-format widening (SBP-v1, additive)

| Field                       | Type    | Required for `psiphon` | Notes                                                                |
|-----------------------------|---------|------------------------|----------------------------------------------------------------------|
| `psiphon_bundle_blob_b64`   | string  | recommended            | base64-decoded bytes MUST be in [256, 65536]; rejected on non-psiphon routes. |

The field is rejected at parse time if it appears on a route whose
`transport_family` is anything other than `psiphon`
(`ErrPsiphonBlobOnNonPsiphonRoute`). When present on a psiphon
route, the base64 MUST decode and the decoded length MUST satisfy
the size envelope (`ErrPsiphonBlobMalformed`).

---

## Diagnostics

`engine_export_diagnostics` adds three psiphon-related fields,
**always present** in the JSON output:

| Field                    | Type    | Default | Notes                                                                  |
|--------------------------|---------|---------|------------------------------------------------------------------------|
| `psiphon_compiled_in`    | bool    | `true`  | `false` when built with `-tags no_psiphon`; never carries a URL or IP. |
| `psiphon_active_route`   | string  | `""`    | Most recently activated psiphon route ID this session; `""` when no activation. |
| (shared)                 |         |         | The `experimental_routes_skipped` (3A) and `experimental_families_enabled` (3A) fields apply. |

The fields are session-scoped snapshots, not cumulative counters.
`engine_clear_route` clears `psiphon_active_route`.

---

## Publisher CLI (`daal-publish psiphon-bundle`)

```
daal-publish psiphon-bundle \
  --psiphon-blob path/to/upstream.bundle \
  --validity 7d \
  --scarcity normal \
  --out psiphon-stub.json
```

The subcommand reads the upstream bundle bytes, applies the size
envelope, base64-encodes the bytes, and emits a `routes[]` entry
stub with `transport_family = "psiphon"`. The default route ID
is `ps-<8-byte-SHA-256-prefix>`; the `--scarcity emergency` flag
is rejected.

Daal never opens a network socket from the publisher CLI; the
upstream bundle is supplied to the publisher out-of-band by
Psiphon Inc.'s tooling and merely wrapped here.

---

## Engine-side activation

When the path manager selects a psiphon route, the in-process
psiphon handler:

1. Checks `psiphonCompiledIn`. If `false`, the route is filtered
   with the V0 failure category (no new categories at 3D).
2. Decodes the bundle blob from the SBP manifest (already validated
   at import time).
3. Hands the blob to the vendored `psiphon-tunnel-core` library to
   establish a tunnel.
4. Calls `abi.RecordPsiphonActiveRoute(routeID)` so the diagnostic
   surfaces the active route.

On `engine_clear_route` the handler calls
`abi.RecordPsiphonActiveRoute("")` to clear the field.

---

## Soak coverage

`psiphon-blob-rotation` (3D scenario) drives:

- Day 1: enable experimental-families gate.
- Day 3: rig sends `soak_record_psiphon_active_route` for
  `soak-psiphon-1`; diagnostics MUST surface the route.
- Day 7: rig clears the active route; diagnostics MUST clear.
- Day 14: rig moves to a network whose only family is psiphon;
  the auto-promotion detector MUST NOT promote.

---

## See also

- `specs/transport-families-v1.md` (family taxonomy + maturity).
- `specs/sbp-v1.md` "Phase 3D widening" (bundle format).
- `specs/conjure-route-v1.md` (sister family, opportunistic).
- `specs/engine-abi-v1.md` "Phase 3D" (diagnostics widening).
- `specs/publisher-cli-v1.md` "Phase 3D" (`psiphon-bundle`).
