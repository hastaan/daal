# Phase 3D — Psiphon / Conjure / Refraction Hooks — SPEC

**Status:** Locked at the start of Phase 3D (post-3C). Ready
for implementation.
**Roadmap line:** V3.4 — "Psiphon / Conjure / refraction
hooks."
**Engine version (target):** `daal-core 0.7.3+v3-transport`.
**ABI release surface:** **45 → 45** (no new release ABI symbols
at 3D — both families plug into the existing path manager and
route activation surfaces).
**Maturity at first ship:** both families enter at
`Experimental` per the 3A taxonomy.

## Strategic frame (verbatim from the roadmap)

> "Daal does not run refraction infrastructure; it consumes
> it. Pursue partnerships with Merit Network / University of
> Colorado Boulder / Psiphon-the-org for capacity sharing."

3D is a **vendoring + carriage** sub-phase, not an
infrastructure-operations sub-phase. The project ships the
client-side handlers; the routes themselves are signed by
existing operator publishers (Psiphon Inc., Merit Network,
UCB, partner NGOs) using the publisher-key model from V0/V1.5.

If a refraction partnership falls through, the family ships as
**documentation only**: users with their own bundles from the
partner can still use the family. The directory at V1.5 will
not advertise a Daal-operated refraction backbone because we
are not operating one.

---

## What lands at 3D

### Two new transport families

- **`psiphon`** — vendored from
  `Psiphon-Inc/psiphon-tunnel-core` (GPLv3). Daal-hosted
  Psiphon routes use Psiphon's publisher-signed bundles; the
  Daal bundle parser carries Psiphon's bundle as an opaque
  blob the same way it carries any other publisher artifact.
  The wire-shape decision (meek-https / unfronted-meek /
  obfuscated-ssh / fronted-meek / quic-impersonate) is made
  inside the Psiphon library; Daal does not second-guess it.
- **`conjure`** — vendored from
  `refraction-networking/gotapdance` (Apache-2.0). Conjure
  registers the user's flow with a Tap-Dance station so that
  innocuous traffic to a phantom IPv4/IPv6 address is
  refracted into the censor-circumvention overlay. Phantom
  addresses rotate across a publisher-supplied subnet pool.

Both families enter the closed `transport-families-v1.md`
taxonomy at Experimental maturity and live behind the 3A
experimental gate (`engine_set_experimental_families_enabled`).

### Family-level kill-switch (3A's reservation activates)

3A reserved the bundle-level `kill_switches[]` slot. 3D is
**still NOT** the trigger that lights it up — the project-
level kill-switch publisher key ships at 3E (per the 3A
caveat). 3D respects the existing route-level revocation flow
unchanged: an operator who needs to disable a Psiphon or
Conjure route signs a `revocation.json` entry that the bundle
parser refuses on import (pre-existing V1.5.2 path).

### License isolation (`-tags no_psiphon`)

- `psiphon-tunnel-core` is **GPLv3**. The vendored copy is
  carried under that license; the build system isolates
  Psiphon symbols behind a `psiphon` build tag so the family
  can be **excluded** from a build via `-tags no_psiphon`.
  Builds for distribution channels where GPL incorporation is
  undesirable (e.g., Apple App Store distribution under the
  conservative interpretation) ship without Psiphon support.
- `gotapdance` is **Apache-2.0**. No license isolation needed.
  Conjure is unconditionally compiled.
- The convention parallels the 3B `-tags no_snowflake`
  precedent: when the family is excluded, every route of that
  family is filtered as-if `experimental_min_engine_version`
  failed (silent skip in the rank pass; route still lists in
  "All routes" with a "not available in this build" badge).

---

## Architecture

### Engine packages

```
core/transports/psiphon/
  psiphon.go            FamilyID="psiphon"; Handler.Dial
  psiphon_blob.go       opaque blob carriage + validation
  psiphon_test.go       handshake stub + blob round-trip (build-tag-gated)

core/transports/conjure/
  conjure.go            FamilyID="conjure"; Handler.Dial
  phantom_pool.go       phantom-IPv6/IPv4 rotation logic
  conjure_test.go       phantom rotation + station-pin tests
```

Both packages sit at the same architectural layer as
`core/transports/snowflake/` (3B) and `core/transports/masque/`
(3C). Each is a thin shim that:

1. Validates the bundle's family-specific config.
2. Resolves the upstream library's primary call surface (a
   single `Dial(ctx, route) → net.Conn` style adapter).
3. Routes failures through the existing 2G burn classifier and
   `failure-taxonomy-v1.md` mappings.

The packages deliberately do NOT import the upstream libraries
directly in their Go imports — the upstream library is wired
in through a `Dialer` callback the engine layer provides at
init time, the same pattern 3B used for the WebRTC dialer in
`core/transports/snowflake/`. This keeps the package
unit-testable without `psiphon-tunnel-core` or `gotapdance` in
scope.

### Routestore widening (additive)

```sql
ALTER TABLE routes ADD COLUMN psiphon_bundle_blob       BLOB    NOT NULL DEFAULT x'';
ALTER TABLE routes ADD COLUMN conjure_phantom_subnets   TEXT    NOT NULL DEFAULT '[]';
ALTER TABLE routes ADD COLUMN conjure_station_pubkey    TEXT    NOT NULL DEFAULT '';
ALTER TABLE routes ADD COLUMN conjure_decoy_pool        TEXT    NOT NULL DEFAULT '';
```

- `psiphon_bundle_blob` — the opaque Psiphon publisher bundle
  bytes. `BLOB`, not `TEXT`, because Psiphon's bundle is
  binary-canonical (CBOR-shaped). The engine handler decrypts
  + validates inside the Psiphon library; Daal never
  inspects the contents.
- `conjure_phantom_subnets` — JSON array of CIDR strings for
  the phantom pool. Validated at parse time (must be valid
  IPv4 or IPv6 CIDRs).
- `conjure_station_pubkey` — Conjure station's curve25519
  public key, hex-encoded. Pinned per route; rotation
  requires a new bundle.
- `conjure_decoy_pool` — JSON array of decoy hostnames the
  Conjure registration will appear to be talking to.

`UpsertRoute` carries the new fields through. Empty defaults
preserve backward compatibility — every pre-3D route
deserialises with empty Psiphon/Conjure fields and continues
to function. Old store rows round-trip through Get/List.

### Bundle parser (sbp-v1 widening)

Adds **four optional fields** on `manifest.routes[]`:

```jsonc
{
  "id": "ps-example",
  "transport_family": "psiphon",
  "scarcity_class": "normal",
  "config_path": "profiles/ps-example.json",
  "valid_from": "...",
  "valid_until": "...",
  "psiphon_bundle_blob_b64": "<base64-encoded Psiphon bundle>"
}
```

```jsonc
{
  "id": "cj-example",
  "transport_family": "conjure",
  "scarcity_class": "experimental",
  "config_path": "profiles/cj-example.json",
  "valid_from": "...",
  "valid_until": "...",
  "conjure_phantom_subnets": ["192.122.190.0/24", "2001:48a8:687f::/48"],
  "conjure_station_pubkey": "a3f2...32 bytes hex",
  "conjure_decoy_pool": ["www.example.com", "static.example.org"]
}
```

**Validation rules (locked at 3D):**

- `psiphon_bundle_blob_b64` MUST NOT appear on routes whose
  `transport_family` is anything other than `"psiphon"`.
  Rejection: `ErrPsiphonBlobOnNonPsiphonRoute`.
- When present, the base64 MUST decode and the decoded bytes
  MUST be in [256, 65536] bytes (size sanity — Psiphon
  bundles are typically 4–16 KB; <256 is malformed; >64 KB is
  refused as resource-exhaustion guard). Rejection:
  `ErrPsiphonBlobMalformed`.
- The decoded bytes are NOT parsed by Daal's bundle parser.
  Validation is structural only; semantic validation happens
  inside the `psiphon-tunnel-core` library at Dial time.
- `conjure_*` fields MUST NOT appear on routes whose
  `transport_family` is anything other than `"conjure"`.
  Rejection: `ErrConjureFieldOnNonConjureRoute`.
- When present, `conjure_phantom_subnets` MUST be a non-empty
  array of valid CIDR strings (IPv4 OR IPv6); each CIDR's
  prefix length MUST be ≥ 24 for IPv4 and ≥ 32 for IPv6
  (defence in depth — refuse implausibly broad pools).
  Rejection: `ErrConjurePhantomSubnetsMalformed`.
- `conjure_station_pubkey` MUST be 32 bytes hex (64 hex
  characters). Rejection: `ErrConjureStationPubkeyMalformed`.
- `conjure_decoy_pool` MAY be empty; when non-empty, every
  entry MUST parse as a hostname (RFC 1123). Rejection:
  `ErrConjureDecoyPoolMalformed`.

**JSON-additive forward compatibility:** 3A / 3B / 3C clients
reading a 3D bundle ignore the new fields silently. The
bundle round-trips through Build → Parse → Verify on all four
versions.

### Engine handler integration

#### Psiphon

`Handler.Dial(ctx, route, blobBytes) → net.Conn`. The
upstream `psiphon-tunnel-core` library is wired through a
`PsiphonDialer` callback the engine layer provides at init
time. The callback signature is opaque to Daal:

```go
// In core/transports/psiphon/psiphon.go
type Handler struct {
    Dialer PsiphonDialer
}

type PsiphonDialer func(ctx context.Context, blob []byte) (net.Conn, error)

func (h *Handler) Dial(ctx context.Context, route *Route) (net.Conn, error) {
    if h.Dialer == nil {
        return nil, ErrFamilyHandlerUnavailable
    }
    if len(route.PsiphonBlob) == 0 {
        return nil, ErrPsiphonBlobMissing
    }
    return h.Dialer(ctx, route.PsiphonBlob)
}
```

Failure semantics map onto V0.3 categories per "Failure
taxonomy" below.

#### Conjure

Conjure's flow is two-step: register-then-tunnel. The library
exposes a single `Dial` that does both internally. Daal's
shim:

```go
// In core/transports/conjure/conjure.go
type Handler struct {
    Dialer ConjureDialer
}

type ConjureDialer func(
    ctx context.Context,
    phantomSubnets []string,
    stationPubkey []byte,
    decoyPool []string,
) (net.Conn, error)

func (h *Handler) Dial(ctx context.Context, route *Route) (net.Conn, error) {
    if h.Dialer == nil {
        return nil, ErrFamilyHandlerUnavailable
    }
    return h.Dialer(ctx,
        route.ConjurePhantomSubnets,
        route.ConjureStationPubkey,
        route.ConjureDecoyPool,
    )
}
```

The phantom-pool rotation logic is **inside the upstream
library**. If phantom IP A is detected and dropped by the DPI
mid-session, the upstream library reaches into its phantom
pool and selects another. Daal's shim observes this through
the `failure_category` returned on Dial errors and feeds the
2G burn classifier as usual.

The `phantom_pool.go` helper in Daal's shim parses CIDRs at
Dial time (defence in depth — the bundle parser already
validated, but Dial-time parse keeps the upstream call
contract explicit) and forwards the parsed list as strings to
the upstream `ConjureDialer`.

### Path manager integration

Both families register through the existing 3A registration
surface. The path manager's rank pipeline is unchanged:

```
shortlist = routes_for_active_network()
shortlist = experimental_filter(shortlist)        // 3A — drops psiphon + conjure when gate is OFF
shortlist = trust_filter(shortlist)
shortlist = budget_filter(shortlist)
shortlist = network_memory_filter(shortlist)
shortlist = mode_filter(shortlist)
return rank(shortlist)
```

No new rank step at 3D. Both families inherit the 3A
experimental-gate skip-ledger entry on filter.

### Auto-promotion (2G) interaction

- **Psiphon is NOT opportunistic.** Auto-promotion (2G) MAY
  promote a network whose only available family is `psiphon`
  IF the user has opted into experimental families. Psiphon
  is operationally a steady-state family (Psiphon-the-org's
  protocols are battle-tested at scale).
- **Conjure IS opportunistic.** Same posture as MASQUE — auto-
  promotion never promotes a network whose only available
  family is `conjure`. Refraction stations are partner-
  operated and capacity-rated for displacement, not for
  steady state.

The 2G detector consumes the family taxonomy as documented in
`transport-families-v1.md`. 3D adds a `is_opportunistic`
boolean to the family registration row:

```go
// In core/routestore/family.go
type Family struct {
    ID                     string
    Maturity               Maturity
    AutoPromotionEligible  bool   // existing 3A field
    IsOpportunistic        bool   // NEW at 3D
}

// Registrations
{ID: "psiphon", Maturity: Experimental, AutoPromotionEligible: true,  IsOpportunistic: false}
{ID: "conjure", Maturity: Experimental, AutoPromotionEligible: false, IsOpportunistic: true}
{ID: "masque",  Maturity: Experimental, AutoPromotionEligible: false, IsOpportunistic: true}  // 3C, retroactive
```

The retroactive `IsOpportunistic` annotation on `masque`
preserves the 3C invariant ("auto-promotion never promotes a
masque-only network"). The 2G detector consults the new field
when computing burn-pressure-promotion eligibility.

---

## Failure taxonomy

Both families map onto existing V0 categories. **No new V0
categories at 3D** (consistent with 3A / 3B / 3C). The
cosmetic surfaces:

### Psiphon

| Cosmetic surface           | V0 category               | When it fires                                                          |
|----------------------------|---------------------------|------------------------------------------------------------------------|
| `psiphon_bundle_invalid`   | `bundle_signature_invalid`| Psiphon library rejects the bundle (parse / signature / expiry).      |
| `psiphon_handshake_failed` | `tls_handshake_failed`    | Upstream meek-https / fronted-meek handshake fails at TLS.            |
| `psiphon_unreachable`      | `tcp_connect_timeout`     | Every protocol attempt inside the bundle times out at TCP.            |
| `psiphon_protocol_blocked` | `tcp_reset`               | Upstream library reports protocol-class detection (RST mid-handshake).|

### Conjure

| Cosmetic surface             | V0 category             | When it fires                                                       |
|------------------------------|-------------------------|---------------------------------------------------------------------|
| `conjure_station_unreachable`| `tcp_connect_timeout`   | Tap-Dance station registration TCP connect times out.               |
| `conjure_registration_failed`| `tls_handshake_failed`  | Registration TLS to a decoy site fails or returns no station ack.   |
| `conjure_phantom_blocked`    | `tcp_reset`             | All phantom IPs in the pool RST mid-session.                        |
| `conjure_phantom_exhausted`  | `tcp_connect_timeout`   | Phantom pool exhausted in this session; no usable IP remaining.     |

The cosmetic surface widens the diagnostics ring buffer; the
V0 category is what the path manager and cooldown FSM
consume.

---

## ABI

**Zero new release ABI symbols at 3D.** Both families plug
into the existing path manager + route activation surfaces;
the upstream library callbacks are wired in at engine init
time (in-process Go config, not ABI surface).

`engine_export_diagnostics` widens additively at 3D with:

```jsonc
{
  ...,
  "psiphon_compiled_in":  true,        // false in -tags no_psiphon builds
  "conjure_compiled_in":  true,
  "psiphon_active_route": "",          // route_id of the currently active psiphon route, or "" if none
  "conjure_active_route": "",          // route_id of the currently active conjure route, or "" if none
  "conjure_phantom_in_use": ""         // last phantom IP used (HASHED — see Privacy below), or ""
}
```

Privacy details:
- `psiphon_compiled_in` and `conjure_compiled_in` are
  **always present** to make the build-time licensing posture
  inspectable from diagnostics (operator-debugging value;
  zero PII).
- `psiphon_active_route` and `conjure_active_route` are local
  route IDs — never the bundle-blob bytes, never destinations.
- `conjure_phantom_in_use` carries the **first 8 bytes of
  SHA-256(phantom_ip)** rendered as 16 hex chars. The user is
  entitled to see "Conjure rotated phantoms" without the
  diagnostic carrying the actual IP. Pattern parallels the
  V2.4 hashed network ID.

Release surface stays at **45**. Engine version bumps to
`daal-core 0.7.3+v3-transport` to mark the new families
(precedent: 3A/3B/3C all bumped on family additions; 2E did
NOT bump because it was platform-integration only).

---

## Bundle library

### Go (`bundle/go/bundle/`)

- `types.go` — `RouteManifestEntry` gains four new optional
  fields:
  - `PsiphonBundleBlobB64 string \`json:"psiphon_bundle_blob_b64,omitempty"\``
  - `ConjurePhantomSubnets []string \`json:"conjure_phantom_subnets,omitempty"\``
  - `ConjureStationPubkey  string \`json:"conjure_station_pubkey,omitempty"\``
  - `ConjureDecoyPool      []string \`json:"conjure_decoy_pool,omitempty"\``
- `sbp.go` — new `validate3DRouteFields(routes)` step in the
  parse pipeline, invoked after the 3C step. Rejection error
  surface as enumerated above.
- `errors.go` — five new errors:
  - `ErrPsiphonBlobOnNonPsiphonRoute`
  - `ErrPsiphonBlobMalformed`
  - `ErrConjureFieldOnNonConjureRoute`
  - `ErrConjurePhantomSubnetsMalformed`
  - `ErrConjureStationPubkeyMalformed`
  - `ErrConjureDecoyPoolMalformed`
- `v3d_test.go` — ~7 tests:
  1. Psiphon route round-trip (Build → Parse → Verify).
  2. Conjure route round-trip.
  3. Reject psiphon blob on non-psiphon route.
  4. Reject malformed (size out of range) psiphon blob.
  5. Reject conjure phantom subnets too broad.
  6. Reject conjure station pubkey wrong length.
  7. Reject conjure decoy pool with malformed hostname.

### Rust (`bundle/rs/bundle/`) — parity

The Rust bundle library mirrors the Go field set + validation
behaviour at parity time. Cross-language test vectors live in
`specs/test-vectors/3d/` (NEW).

---

## Publisher CLI

Two new subcommands; OPSEC invariants from V1.6 hold (no
network sockets opened during publish-side operations).

### `daal-publish psiphon-bundle`

Wraps an upstream Psiphon publisher bundle into a Daal
`routes[]` entry stub. The Psiphon side bundle is produced by
Psiphon Inc.'s tooling and supplied to the operator out of
band; this subcommand is only the carriage.

```
daal-publish psiphon-bundle
    --psiphon-blob <path-to-psiphon-bundle-bytes>
    --route-id <id>                   (optional; defaults to ps-<bundle-checksum-prefix>)
    --validity 7d                     (optional)
    --scarcity normal                 (default; psiphon supports up to bulk-capable)
    --caveat-fa-ir <persian text>     (optional)
    --out <path>
```

Validation:
- Refuses if blob bytes are <256 or >65536.
- Refuses if `--scarcity emergency` (Psiphon is NOT an
  emergency-pool family — those are the Tier 2 seeds).
- The emitted route stub carries `transport_family:
  "psiphon"`, `psiphon_bundle_blob_b64: <base64>`, and
  `family_specific_config: {}` (reserved).

### `daal-publish conjure-bridge`

Generates a `routes[]` entry stub for a Conjure station + a
phantom-pool selection.

```
daal-publish conjure-bridge
    --station-pubkey <hex>            (32 bytes; matches the deployed station)
    --phantom-subnets <CIDR,CIDR,...> (REQUIRED; must validate)
    --decoy-pool <host,host,...>      (optional)
    --route-id <id>                   (optional; defaults to cj-<station-fp-prefix>)
    --validity 7d                     (optional)
    --scarcity experimental           (default; conjure caps at experimental until partnership confirms)
    --caveat-fa-ir <persian text>     (optional)
    --out <path>
```

Validation:
- Refuses if a phantom subnet's prefix is broader than /24
  (IPv4) or /32 (IPv6).
- Refuses if station pubkey is not 32 bytes hex.
- Refuses if a decoy host fails RFC 1123.

### Tests (`bundle/go/publisher/`)

- `psiphon_test.go` — ~4 tests (happy path, blob too small,
  blob too big, non-emergency scarcity check).
- `conjure_test.go` — ~5 tests (happy path, broad subnet
  reject, malformed pubkey reject, malformed decoy reject,
  phantom IPv4+IPv6 mixed acceptance).

---

## Soak

### Two new scenarios

- `psiphon-handshake.json` — uses a stub Psiphon-protocol
  shim (the real Psiphon bundle is not exercised in soak; the
  shim stays inside Daal's bundle parser and route-state
  machine). Rig assertions:
  1. The bundle round-trips through Build → Parse → Verify on
     all 1k synthetic clients.
  2. Routes activate through the shim.
  3. A `psiphon-bundle-burn` invariant ledger entry is
     produced when the shim simulates an upstream protocol
     block.
- `conjure-phantom-rotation.json` — the engine rotates
  through phantom-IPv6 decoy addresses correctly when the
  active phantom is detected and dropped by the simulated
  DPI. Rig assertions:
  1. After phantom IP X is burned (rig action
     `soak-burn-conjure-phantom`), the next Dial returns a
     different phantom from the pool.
  2. The pool exhausts deterministically (after N attempts =
     pool size, rig sees `conjure_phantom_exhausted`).
  3. `conjure_phantom_in_use` diagnostic is hashed (regression
     against the privacy invariant).

### Soak driver

- `client.go` adds `SoakBurnPsiphonBundle(routeID)` and
  `SoakBurnConjurePhantom(routeID, phantomHash)`.
- `soak.go` adds dispatch cases `soak-burn-psiphon-bundle`
  and `soak-burn-conjure-phantom`.
- `--scenarios v2-superset` whitelist widens **19 → 21**.

### Soak engine (cmd/daal-soak-engine)

Two new dispatch cases:

```go
case "soak-burn-psiphon-bundle":
    var a struct { RouteID string `json:"route_id"` }
    abi.MarkPsiphonBundleBurned(a.RouteID, /*attempts=*/3)
case "soak-burn-conjure-phantom":
    var a struct { RouteID string `json:"route_id"`; PhantomHash string `json:"phantom_hash"` }
    abi.MarkConjurePhantomBurned(a.RouteID, a.PhantomHash, /*attempts=*/3)
```

New `core/abi/refraction_soak.go` (`-tags soak`):

```go
//go:build soak

package abi

// MarkPsiphonBundleBurned / MarkConjurePhantomBurned hold the
// transient soak-only burn signals the rig consults through
// `IsPsiphonBundleBurned` / `IsConjurePhantomBurned`.
//
// Same shape as 3B's rendezvous_soak.go and 3C's masque_soak.go.
```

---

## Spec deliverables

**New (2):**

- `specs/psiphon-route-v1.md` — opaque-blob carriage; how
  Psiphon's publisher key relates to Daal's trust ladder; the
  GPLv3 licensing implications + `-tags no_psiphon` excluder;
  failure category mapping; soak coverage; out-of-scope.
- `specs/conjure-route-v1.md` — phantom-IPv6/IPv4 decoy
  semantics; the rotation algorithm; the partner station
  operational model; failure category mapping; soak coverage;
  out-of-scope.

**Amended (8):**

- `specs/transport-families-v1.md` — psiphon + conjure rows in
  the family taxonomy table; new `is_opportunistic` field on
  the family registration; retroactive masque opportunistic
  annotation.
- `specs/sbp-v1.md` — four new optional `routes[]` fields and
  their validation rules.
- `specs/publisher-cli-v1.md` — `psiphon-bundle` and
  `conjure-bridge` subcommands.
- `specs/engine-abi-v1.md` — diagnostics widening (5 new
  fields); ABI surface stays 45 (zero new symbols); engine
  version bump to 0.7.3.
- `specs/route-object-v1.md` — four new optional fields on the
  Route runtime object.
- `specs/routestore-v1.md` — four new ALTERs; secrets-KV usage
  unchanged.
- `specs/network-memory-v1.md` — no new fields (Psiphon and
  Conjure do NOT participate in the per-network-memory bias
  model at 3D; reasoning below in "Locked invariants").
- `specs/failure-taxonomy-v1.md` — psiphon and conjure
  cosmetic surfaces appended; no new V0 categories.

---

## Locked invariants for 3D

1. **ABI append-only; +0 release symbols at 3D.** Both
   families plug into existing path manager + activation
   surfaces.
2. **Daal does NOT operate refraction infrastructure.**
   Psiphon network = Psiphon Inc. Conjure stations = Merit /
   UCB / partner. The roadmap caveat is held strictly.
3. **Both families enter at Experimental.** The 3A
   experimental gate filters them OFF by default.
4. **GPLv3 isolation.** `-tags no_psiphon` excluder; Conjure
   is unconditionally compiled (Apache-2.0).
5. **Psiphon is NOT opportunistic; Conjure IS.** The
   `IsOpportunistic` family-registration field gates 2G
   auto-promotion eligibility.
6. **No new V0 failure categories.** Cosmetic-only widening.
7. **No per-network-memory bias for refraction families at
   3D.** The chooser cascade pattern from 3C (which biased
   MASQUE start rung from netmem) does not extend to
   refraction at 3D — Psiphon's protocol-class selection is
   an upstream-library private decision; Conjure's phantom
   choice is an upstream-library private decision. A 3D
   `Snapshot` widening would be premature optimization without
   measurement evidence.
8. **Opaque blob carriage for Psiphon.** Daal's bundle
   parser does NOT inspect Psiphon bundle bytes. Psiphon's own
   library is the canonical validator. Defence in depth =
   structural size checks only at the Daal layer.
9. **Conjure phantom pool prefix-length floors are LOCKED.**
   /24 (IPv4) and /32 (IPv6). A future spec revision MAY
   widen; 3D does not.
10. **`conjure_phantom_in_use` diagnostic is hashed.** Same
    pattern as the V2.4 network ID. Never the raw phantom IP.
11. **Trust ladder unchanged.** A Psiphon route signed by
    Psiphon Inc.'s publisher key is `Trusted Provider` per
    the existing trust UI; the user does NOT get a Psiphon-
    specific second prompt beyond the experimental-gate
    explainer modal from 3A.
12. **`UpsertRoute` MUST NOT clobber engine-recorded state.**
    The 3D ALTERs add new columns; the non-clobber discipline
    from 3B (`last_winning_rendezvous_channel`) and 3C
    (`masque_submode:<route_id>` secrets-KV) extends — there
    are no engine-recorded fields to clobber at 3D, but the
    discipline is documented for future-proofing.

---

## Out of scope at 3D

- **Operating any refraction infrastructure ourselves.**
  V4 work, candidate workstream "a" in the roadmap.
- **Conjure deployment partnership negotiation.** The
  partnership is a precondition; the engineering work
  proceeds whether or not the partnership lands. If no
  partnership at 3D ship, the Conjure family is still
  shippable (for users with their own bundles from a
  partner-operated station).
- **Per-station Conjure load balancing.** Single-station per
  bundle at 3D. Multi-station per bundle is V4.
- **Psiphon protocol-class selection from Daal side.** The
  upstream library makes that decision.
- **Psiphon-specific trust UI.** The 3A trust ladder applies
  unchanged.
- **Phantom-IP rotation policy at the Daal layer.** The
  upstream library's policy applies.
- **Family-level kill-switch publisher key + delta format.**
  Reserved at 3A; lights up at 3E.

---

## Tests at 3D

| Package                          | New tests | Notes                                                          |
|----------------------------------|-----------|----------------------------------------------------------------|
| `core/transports/psiphon`        | ~5        | Dialer-callback shim; blob-missing reject; build-tag exclusion |
| `core/transports/conjure`        | ~6        | phantom rotation; pool exhaustion; station pubkey pin          |
| `core/routestore`                | +1 (3D)   | round-trip + UpsertRoute non-clobber                           |
| `core/abi` refraction            | ~4        | diagnostics shape; build-tag-aware fields                      |
| `bundle/go/bundle` (3D)          | ~7        | enumerated above                                               |
| `bundle/go/publisher` (3D)       | ~9        | enumerated above                                               |
| `cmd/daal-soak-engine`          | builds    | new dispatch cases compile both with/without `-tags soak`      |
| Soak driver                      | builds    | 2 new scenarios; v2-superset 19 → 21                           |

A `-tags no_psiphon` build of the engine MUST compile and run
the full V1 / V2 / 3A / 3B / 3C / 3D test suite (Psiphon
package skipped via build tag). All previous tests stay green.

---

## Exit criteria (3D ship gate)

1. `psiphon` and `conjure` families registered in the 3A
   transport-family taxonomy with locked maturity and locked
   `IsOpportunistic` flags.
2. Both families plug into the trust UI without modification.
3. Family-level revocation flow respected (route-level
   `revocation.json` per V1.5.2 — kill-switch publisher key
   defers to 3E).
4. Both new soak scenarios PASS.
5. `-tags no_psiphon` build option works.
6. `specs/psiphon-route-v1.md` and `specs/conjure-route-v1.md`
   shipped.
7. `nm`-counted release ABI surface remains **45** (zero new
   release symbols).
8. Engine version bumped to `daal-core
   0.7.3+v3-transport`.
9. Bundle Go + Rust libraries cross-validate every 3D test
   vector byte-for-byte.

---

## Sub-task plan (10 sub-tasks)

| # | Task                                                                                                         |
|---|--------------------------------------------------------------------------------------------------------------|
| 1 | `core/transports/psiphon/` skeleton package + Dialer callback + opaque blob plumbing + ~5 tests             |
| 2 | `core/transports/conjure/` skeleton package + phantom-pool helper + Dialer callback + ~6 tests              |
| 3 | Routestore: 4 new ALTERs; `RouteRow` widened; UpsertRoute / Get / List carry-through; +1 round-trip test    |
| 4 | Family registry: add `IsOpportunistic` field; register psiphon / conjure; retroactive masque annotation     |
| 5 | Bundle parser: `validate3DRouteFields`; 5 new errors; v3d_test.go ~7 tests                                  |
| 6 | Publisher CLI: `psiphon-bundle` + `conjure-bridge` subcommands; ~9 tests                                    |
| 7 | ABI diagnostics widening (5 new fields, build-tag aware); engine version bump 0.7.2 → 0.7.3; +~4 tests      |
| 8 | Soak: 2 new scenarios; client + soak.go dispatch; soak-engine dispatch (+ `refraction_soak.go` -tags soak)  |
| 9 | Specs: NEW `psiphon-route-v1.md` + `conjure-route-v1.md`; AMEND 8 specs                                     |
|10 | Handover doc `23-phase-3d-refraction-hooks.handover.md` + final regression sweep                            |

Sub-task ordering follows the 3B / 3C precedent: skeleton
packages first (testable in isolation); routestore + family
registry next (storage layer ready before importer wiring);
bundle parser + CLI next (creates the bundles the engine will
consume); ABI diagnostics last (consumes everything below);
soak + specs + handover close the phase.

---

## Carry-overs to V4

- Multi-station Conjure (per-station load balancing).
- Operating a Conjure station at the project (V4 candidate
  workstream "a"; funding-dependent).
- Per-network-memory bias for refraction-family sub-mode
  selection (deferred from 3D — needs measurement evidence).
- Psiphon protocol-class telemetry visibility (CC.6 forbids
  it; revisited only if CC.6 is ever revised, which it
  isn't — locked).

---

## Handover (forward) to 3E

3E (WASM transport slot) receives:

- The closed family taxonomy at 6 entries (vless-reality,
  naive, websocket-tls, hysteria2, tuic, shadowsocks,
  tor-bridge, wireguard, amneziawg, webtunnel, snowflake,
  masque, **psiphon**, **conjure**, plus the V0 `other`
  forward-compat token).
- The `IsOpportunistic` family-registration field as the
  template for WASM modules' analogous flag.
- The license-isolation pattern (`-tags no_psiphon`) as the
  template for `-tags no_wasm` if 3E needs to support builds
  without `wasmtime`.
- The opaque-blob carriage pattern (Psiphon) as the template
  for WASM-module bytecode carriage in `transport_module`
  routes.
- ABI release surface = **45**; append-only.
- Engine version `daal-core 0.7.3+v3-transport`.
- Family-level kill-switch publisher key + delta format
  STILL deferred from 3A; lights up at 3E.
