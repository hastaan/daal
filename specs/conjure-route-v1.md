# conjure-route-v1

**Phase:** 3D
**Status:** **SUPERSEDED at Wave 5 — the family is `unsupported`,
not experimental, and cannot become otherwise without a network
operator.** Conjure is refraction networking: it requires a
COOPERATING ISP running a station on a transit link it owns,
answering for unused addresses in its own space. A publisher
renting a VPS has neither, so there is nothing to deploy.
gotapdance has never been in `core/go.mod`. `conjure_compiled_in`
is now constant `false` and `RecordConjureActivation` refuses a
non-empty route ID. Kept as the record of a decision, not a plan.
See `docs/transport-family-inventory.md`.
**Roadmap line:** V3.4 — "Refraction-family hooks (Psiphon + Conjure)."
**Engine version:** `daal-core 0.7.3+v3-transport`.
**ABI release surface:** 45 → **45** (no new symbols; append-only invariant preserved).

---

## Scope

Adds `conjure` as a transport family. A `conjure` route specifies
a station + phantom-pool + decoy pool that the upstream
`gotapdance` library uses to register a Conjure session and bind
to a phantom IP. The vendored gotapdance tree is Apache-2.0 and
ships unconditionally (no `-tags no_conjure` excluder is
required at 3D).

Conjure is **opportunistic**: the auto-promotion detector (2G)
MAY promote a network whose only available family is conjure.
This is the dual of the psiphon family (which is NOT
opportunistic) and aligns with masque's retroactive 3D
opportunistic annotation.

---

## Locked invariants

1. **Phantom-pool prefix-length floors.** The publisher and the
   bundle parser BOTH refuse phantom subnets with prefix length
   smaller than `/24` for IPv4 and `/32` for IPv6. Implausibly
   broad pools are a publisher mistake (e.g. typo for a single
   IP) and the floors are defence-in-depth — they do NOT mean
   the engine binds to a /24 of phantoms; the gotapdance
   library binds to a single IP per session, drawn from the
   pool.

2. **Phantom-IP HASHING in diagnostics.** The
   `conjure_phantom_in_use` diagnostic field carries the
   8-byte SHA-256 truncation of the raw phantom IP, hex-encoded
   (16 hex chars). The raw IP NEVER appears in diagnostics.
   This satisfies the V0.1 + CC.6 redaction invariant for the
   conjure family the same way `current_network_id` (2C) and
   `psiphon_active_route` (3D) satisfy it for their respective
   families. The hashing happens at the abi-package boundary
   (`RecordConjureActivation` recomputes the hash from the raw
   IP rather than trusting the caller to pre-hash, keeping the
   redaction boundary explicit and easy to audit).

3. **Opportunistic.** The family registry's
   `IsOpportunistic` field is `true` for conjure (3D), `false`
   for psiphon (3D), `true` for masque (retroactive 3D
   annotation). The auto-promotion detector (2G) consults the
   field at the family-filter step.

4. **Soft-validation discipline at parse time.** Empty
   `conjure_phantom_subnets` / `conjure_station_pubkey` /
   `conjure_decoy_pool` on a conjure route are NOT parse-time
   rejections — a publisher MAY pre-publish a route stub
   before wiring up the station. The engine filters such
   routes at activation time. This matches the 3C
   `masque_endpoint` and 3D `psiphon_bundle_blob_b64` rules.

5. **Defence-in-depth field placement.** Any of the conjure
   fields on a non-conjure route is a parse-time rejection
   (`ErrConjureFieldOnNonConjureRoute`) — keeps the
   `routes[]` shape unambiguous, matching the 3C
   `masque_endpoint` rule.

6. **Append-only ABI.** No new release-surface symbols are
   added at 3D. The `RecordConjureActivation` /
   `ConjurePhantomInUseHash` Go-level entry points are
   package-internal.

---

## Bundle-format widening (SBP-v1, additive)

| Field                      | Type     | Required for `conjure` | Notes                                                                          |
|----------------------------|----------|------------------------|--------------------------------------------------------------------------------|
| `conjure_phantom_subnets`  | string[] | recommended            | CIDR list; floors `/24` IPv4, `/32` IPv6; rejected on non-conjure routes.      |
| `conjure_station_pubkey`   | string   | recommended            | 32 bytes hex (64 hex chars); rejected on non-conjure routes.                   |
| `conjure_decoy_pool`       | string[] | optional               | RFC 1123 hostnames; empty list ⇒ upstream picks defaults.                      |

Per-field error vocabulary at parse time:
`ErrConjureFieldOnNonConjureRoute`, `ErrConjurePhantomSubnetsMalformed`,
`ErrConjureStationPubkeyMalformed`, `ErrConjureDecoyPoolMalformed`.

---

## Diagnostics

`engine_export_diagnostics` adds three conjure-related fields,
**always present** in the JSON output:

| Field                    | Type   | Default | Notes                                                                   |
|--------------------------|--------|---------|-------------------------------------------------------------------------|
| `conjure_compiled_in`    | bool   | **`false`** | **Wave 5: constant `false`.** It claimed an "Apache-2.0 vendored tree that ships unconditionally"; gotapdance is not in the module graph, directly or indirectly. Never carries a URL or IP. |
| `conjure_active_route`   | string | `""`    | Most recently activated conjure route ID this session.                 |
| `conjure_phantom_in_use` | string | `""`    | 8-byte-SHA-256-hex of the raw phantom IP. Raw IP NEVER appears.        |

The fields are session-scoped snapshots. `engine_clear_route`
clears `conjure_active_route` AND `conjure_phantom_in_use`.

---

## Publisher CLI (`daal-publish conjure-bridge`)

```
daal-publish conjure-bridge \
  --station-pubkey 0123…cdef \
  --phantom-subnets 192.122.190.0/24,2001:48a8:687f::/48 \
  --decoy-pool www.example.com,static.example.org \
  --validity 7d \
  --out conjure-stub.json
```

The subcommand validates the prefix-length floors, the 64-hex
station pubkey, and the RFC 1123 hostnames in the decoy pool,
and emits a `routes[]` entry stub with
`transport_family = "conjure"`. The default scarcity class is
`experimental` (the family ships at Experimental maturity at 3D).

---

## Engine-side activation

When the path manager selects a conjure route, the in-process
conjure handler:

1. Decodes the phantom subnets, station pubkey, and decoy pool
   from the SBP manifest (already validated at import time).
2. Hands the configuration to the vendored gotapdance library
   to register a Conjure session and bind to a phantom IP.
3. Calls `abi.RecordConjureActivation(routeID, rawPhantomIP)`.
   The abi package HASHES the raw IP at the boundary; only the
   hash surfaces in diagnostics.

On `engine_clear_route` the handler calls
`abi.RecordConjureActivation("", "")` to clear both fields.

---

## Soak coverage

`conjure-phantom-pool` (3D scenario) drives:

- Day 1: enable experimental-families gate.
- Day 3: rig drives `soak_record_conjure_activation` with
  raw IP `192.122.190.42`; diagnostics MUST surface the route
  AND a 16-hex-char hash; the raw IP MUST NOT appear anywhere
  in diagnostics. The `no_raw_phantom_ip_leak_in_diagnostics`
  invariant is the canonical regression.
- Day 7: rig drives a second activation with a different raw
  IP; the resulting hash MUST differ from day 3.
- Day 14: rig clears the activation; diagnostics MUST clear
  both fields.
- Day 20: rig moves to a network whose only family is conjure;
  the auto-promotion detector MAY promote (locked-at-3D
  opportunistic invariant).

---

## See also

- `specs/transport-families-v1.md` (family taxonomy + maturity).
- `specs/sbp-v1.md` "Phase 3D widening" (bundle format).
- `specs/psiphon-route-v1.md` (sister family, NOT opportunistic).
- `specs/engine-abi-v1.md` "Phase 3D" (diagnostics widening).
- `specs/publisher-cli-v1.md` "Phase 3D" (`conjure-bridge`).
