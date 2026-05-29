# Signed Bundle Package (`.sbp`) v1

## Status

Draft for V0 freeze. **Phase 1.5A bumps `spec_version` from 1 to 2.**
**Phase 3A widens the `transport_family` enum semantics (the
*list* is unchanged — every V3 family already named in the V0
enum) and adds three optional `routes[]` fields plus one
reserved top-level entry.**
**Phase 3B adds an optional `routes[].rendezvous_priority` list
and a top-level `rendezvous_hints[]` slot for the multi-channel
rendezvous abstraction. No `spec_version` bump (additive).**

A v2 manifest is **forward-incompatible** with Phase 1A/1B/1C/1D
clients: the v1 verifier rejects v2 manifests as `bundle_corrupted`.
This is the intentional update signal — a Phase 1.5A bundle reaching an
older client tells the user to update the app. Phase 1.5A clients accept
both v1 and v2 (read-only) and write v2 by default; the publisher CLI
keeps emitting v1 only when invoked with `--legacy-v1`.

v2 adds these JSON-additive fields:

- `publisher.revocation_url` (string, https://) — where the client
  fetches this publisher's signed revocation list.
- `publisher.revocation_fingerprint_hex` (string, 64-char hex) — raw
  hex of the ed25519 public key that signs the revocation list. Phase
  1.5A treats this as a key pin rather than a fingerprint.
- `bundle.pointer_rotation_ref.path` — only meaningful in directory
  bundles; names the in-archive entry holding a project-root-signed
  pointer rotation envelope (see `pointer-rotation-v1.md`).

## Purpose

`.sbp` is Daal's signed offline route bundle format. It lets a publisher package one or more route profiles with provenance, expiry, scarcity metadata, and an Ed25519 signature.

## Archive Layout

An `.sbp` file is a ZIP archive:

```text
manifest.json       required
manifest.sig        required, Ed25519 signature over canonical manifest JSON
publisher.pub       required, 32-byte Ed25519 public key
profiles/           required when routes reference profiles
trust/              optional, key-rotation/cross-signing material
revocation.json     optional, signed revocation data
```

## Manifest Schema

```json
{
  "spec_version": 1,
  "publisher": {
    "name": "Example Publisher",
    "key_fingerprint_hex": "hex",
    "key_fingerprint_en": "word-word-word-word",
    "key_fingerprint_fa": "word-word-word-word",
    "key_fingerprint_visual": "data:image/svg+xml;base64,...",
    "key_created_at": "2026-01-15T00:00:00Z",
    "trust_class": "official|provider|community|unknown"
  },
  "bundle": {
    "id": "uuid",
    "type": "provider|friend_share|emergency|revocation|trust_update",
    "created_at": "2026-04-25T12:00:00Z",
    "expires_at": "2026-05-25T12:00:00Z",
    "previous_bundle_id": "uuid|null",
    "supersedes_keys": ["fingerprint"]
  },
  "routes": [
    {
      "id": "route-uuid",
      "scarcity_class": "emergency|low|normal|bulk-capable|lifeline-only|experimental",
      "transport_family": "vless-reality|naive|websocket-tls|hysteria2|tuic|snowflake|webtunnel|masque|shadowsocks|tor-bridge|wireguard|amneziawg|psiphon|conjure|transport_module|lifeline_relay|other",
      "config_path": "profiles/route-uuid.json",
      "valid_from": "2026-04-25T12:00:00Z",
      "valid_until": "2026-05-25T12:00:00Z",
      "udp_gated": false,
      "family_specific_config": {},
      "caveat_fa_ir": "",
      "experimental_min_engine_version": "",
      "rendezvous_priority": []
    }
  ],
  "kill_switches": [],
  "rendezvous_hints": []
}
```

### Phase 3A field semantics

The `routes[]` enum is the closed family taxonomy enforced by
`specs/transport-families-v1.md`. Adding a value is a roadmap-
level decision; the parser rejects unknown values with
`bundle_corrupted` (the V0 `other` value remains accepted for
forward compatibility but is never selected by the path
manager).

Three new optional `routes[]` fields ride this taxonomy:

- `family_specific_config: object` — opaque-to-routestore
  per-family configuration. The bundle parser validates the
  outer shape (must be an object); each family spec defines
  its own keys. WebTunnel keys
  (`webtunnel_secret_path`, `webtunnel_sni`, `webtunnel_alpn`)
  are documented in `specs/webtunnel-route-v1.md`. Default
  `{}`.
- `caveat_fa_ir: string` — overrides the family-default
  Iranian region caveat for this route. Optional. Default
  empty (the family's default caveat applies).
- `experimental_min_engine_version: string` — semver pin; if
  the engine is older, the route is filtered as if the
  experimental gate were OFF, regardless of the user's
  toggle. Optional. Default empty (no minimum). Validated as
  semver at parse time; malformed values reject the bundle
  as `bundle_corrupted`.

One new top-level entry — `kill_switches[]` — is reserved at
3A. The 3A parser accepts the field (must be an array if
present) but the engine ignores its contents until 3E. The 3E
spec (`wasm-kill-switch-v1.md`) will lock the entry's element
schema. Reserving the slot now avoids a v3 spec_version bump
at 3E.

### Phase 3B field semantics

One new optional `routes[]` field rides 3B's multi-channel
rendezvous abstraction:

- `rendezvous_priority: [string]` — channel IDs in fire
  order. Each entry MUST be a known channel ID per
  `specs/rendezvous-channels-v1.md` (one of
  `domain_fronted_broker`, `sqs`, `amp_cache`, `push`,
  `offline_hint`). Unknown values reject the bundle as
  `bundle_corrupted`. Optional. Default empty (the engine
  uses the family-default order: `["domain_fronted_broker",
  "amp_cache", "sqs", "offline_hint"]`).

One new top-level entry — `rendezvous_hints[]` — at 3B.
Each entry is:

```json
{
  "channel_id": "domain_fronted_broker",
  "payload": { ... channel-specific JSON ... },
  "signature_hex": "..."
}
```

The signature is over canonical-JSON-encoded
`{channel_id, payload}` and verifies against the bundle's
publisher key. Unknown `channel_id` values reject the bundle
as `bundle_corrupted`. Push-channel hints additionally carry:

- `payload.push_registry_url: string` (https://) — the
  publisher-operated registry the engine registers the device
  token with. See `specs/push-rendezvous-v1.md`.
- `payload.push_topic: string` — FCM/APNS topic the publisher
  sends rendezvous payloads on.

Both reservations are forward-compatible: a 3A client reading
a 3B bundle ignores the new fields silently.

## Canonical JSON

The signed bytes are canonical JSON:

- UTF-8 encoded.
- Object keys sorted lexicographically.
- No insignificant whitespace.
- Strings escaped according to JSON rules.
- Arrays preserve order.
- Timestamps use RFC3339 UTC strings.

## Validation Rules

Importers must reject bundles when:

- ZIP parsing fails.
- required files are missing.
- archive entries use absolute paths or `..` path traversal.
- `spec_version` is unsupported.
- `publisher.pub` is not a 32-byte Ed25519 public key.
- `manifest.sig` fails verification.
- bundle expiry is in the past.
- a route expiry is in the past.
- a route references a missing profile path.
- a route uses an unknown `transport_family` enum value (the V0
  `other` value is still accepted at parse time but is never
  selected by the path manager).
- a `routes[].family_specific_config` is present and is not
  a JSON object.
- a `routes[].experimental_min_engine_version` is present and
  fails to parse as semver.
- a WebTunnel route's `scarcity_class` is `bulk-capable`
  (rejected at parse time per `webtunnel-route-v1.md`).
- `kill_switches[]` is present and is not a JSON array.
- a `routes[].rendezvous_priority` entry is not a known channel ID
  (per `specs/rendezvous-channels-v1.md`).
- a `rendezvous_hints[]` entry has unknown `channel_id`,
  malformed `signature_hex`, or fails publisher-key
  verification (`bundle_signature_invalid`).
- a Snowflake route's `scarcity_class` is `bulk-capable`
  (rejected at parse time per `specs/snowflake-route-v1.md`).
- a `routes[].masque_endpoint` is present on a route whose
  `transport_family` is anything other than `"masque"`
  (`ErrMasqueEndpointOnNonMasqueRoute`; per
  `specs/masque-ladder-v1.md`).
- a `routes[].masque_endpoint` is present and not a parseable
  `https://host[:port]/path` URL with a non-empty path
  (`ErrMasqueEndpointMalformed`).
- a `routes[].psiphon_bundle_blob_b64` is present on a route
  whose `transport_family` is anything other than `"psiphon"`
  (`ErrPsiphonBlobOnNonPsiphonRoute`; per
  `specs/psiphon-route-v1.md`).
- a `routes[].psiphon_bundle_blob_b64` does not base64-decode
  to `[256, 65536]` bytes (`ErrPsiphonBlobMalformed`).
- any `routes[].conjure_*` field is present on a route whose
  `transport_family` is anything other than `"conjure"`
  (`ErrConjureFieldOnNonConjureRoute`; per
  `specs/conjure-route-v1.md`).
- a `routes[].conjure_phantom_subnets` entry fails the
  prefix-length floors (`/24` IPv4, `/32` IPv6) or fails to
  parse (`ErrConjurePhantomSubnetsMalformed`).
- a `routes[].conjure_station_pubkey` is present and not 64
  hex characters (`ErrConjureStationPubkeyMalformed`).
- a `routes[].conjure_decoy_pool` entry is not a valid RFC
  1123 hostname (`ErrConjureDecoyPoolMalformed`).
- a changed publisher key lacks a valid rotation chain.
- a revocation file marks the publisher or route revoked.

## Phase 3C widening

Adds one optional field on `routes[]`:

- `masque_endpoint: string` — publisher's MASQUE upstream URL
  (RFC 9298 / 9484 endpoint). MUST be `https://host[:port]/path`
  with a non-empty path. Only meaningful on `masque` routes;
  validated as above. Empty / absent on a `masque` route is
  accepted (the engine treats the route as having no usable
  endpoint and filters at activation time, matching the
  pre-published-stub workflow established in 3A's
  `family_specific_config` rule). See
  `specs/masque-ladder-v1.md` and `specs/route-object-v1.md`
  "Phase 3C".

The widening is JSON-additive: a 3A / 3B client reading a 3C
bundle ignores the new field silently and the bundle round-trips
through Build → Parse → Verify on both versions.

## Phase 3D widening

Adds four optional fields on `routes[]` for the refraction
families:

- `psiphon_bundle_blob_b64: string` — opaque base64-encoded
  upstream Psiphon publisher bundle bytes. Decoded length MUST
  be in `[256, 65536]`. Only meaningful on `psiphon` routes;
  rejected on other families. Empty on a psiphon route is
  accepted at parse time (engine filters at activation —
  matches the 3C stub-then-wire workflow). See
  `specs/psiphon-route-v1.md`.
- `conjure_phantom_subnets: string[]` — list of CIDRs forming
  the conjure phantom-pool. Floors locked at `/24` IPv4,
  `/32` IPv6. Only meaningful on `conjure` routes; rejected
  on other families. See `specs/conjure-route-v1.md`.
- `conjure_station_pubkey: string` — 64 hex chars (32 bytes)
  curve25519 station public key. Only meaningful on
  `conjure` routes.
- `conjure_decoy_pool: string[]` — RFC 1123 hostnames the
  upstream library may use as registration cover. Empty list
  ⇒ upstream picks defaults. Only meaningful on `conjure`
  routes.

The widening is JSON-additive: a 3A / 3B / 3C client reading a
3D bundle ignores the new fields silently and the bundle
round-trips through Build → Parse → Verify on all versions.

## Phase 3E widening

Adds one new top-level array, one optional `routes[]` field,
and an optional kill-switch deltas array.

- Top-level `transport_modules[]` — array of WASM module
  entries that the bundle ships in-band:
  ```json
  {
    "slug":              "[a-z0-9_-]{3,32}",
    "sha256":            "<64-hex>",
    "wasm_blob_b64":     "<base64 .wasm>",
    "min_engine_version":"<semver>",
    "optional_capabilities": []
  }
  ```
  Locked at 3E:
  - Slug regex `[a-z0-9_-]{3,32}`.
  - Per-module size ≤ 4 MiB; total bundle ≤ 16 MiB.
  - `sha256` MUST match `SHA-256(wasm_blob_b64 bytes)`.
  - Duplicate slugs MUST be rejected.
  - `optional_capabilities` MUST be empty at v1 (v2 reserves).
  - See `specs/wasm-transport-v1.md`.

- `routes[].transport_module_slug: string` — REQUIRED on
  routes whose `transport_family` is `"transport_module"`;
  REJECTED on other families. The slug MUST exist in the
  bundle's `transport_modules[]`. A route whose slug is
  unknown is **soft-validated out** (skipped); other routes
  are unaffected.

- Top-level `wasm_kill_switch_deltas[]` — array of signed
  kill-switch entries that the engine applies on import:
  ```json
  {
    "slug":       "<slug>",
    "sha256":     "<64-hex>",
    "generation": <uint64>,
    "signature":  "<base64-raw-std Ed25519 sig>"
  }
  ```
  Each entry is verified individually under the engine's
  embedded WASM kill-switch pubkey; rejected entries do NOT
  taint the bundle. See `specs/wasm-kill-switch-v1.md`.

Five new parse errors land at 3E (all rejecting per-route or
per-entry, soft-validation discipline preserved):

- `bundle_wasm_module_missing` — route references an unknown
  slug.
- `bundle_wasm_module_sha_mismatch` — entry sha256 ≠ SHA-256
  of the blob.
- `bundle_wasm_module_oversize` — single module > 4 MiB or
  total > 16 MiB.
- `bundle_wasm_module_slug_invalid` — slug fails the regex.
- `bundle_wasm_module_duplicate_slug` — two entries share a
  slug.

The widening is JSON-additive: a 3A–3D client reading a 3E
bundle silently ignores `transport_modules[]` and the new
`routes[]` field, and the bundle round-trips through Build →
Parse → Verify on all versions.

## Trust Semantics

Successful signature verification proves only that the bundle was signed by the included publisher key. It does **not** mean the publisher is trusted.

Unknown publishers enter TOFU flow. The user must explicitly accept the publisher or accept only the current bundle.

## Security Constraints

- No bundle import may create telemetry.
- No route is trusted solely because it connects successfully.
- No route is permanent; expiry is mandatory.
- Emergency routes must remain visibly labeled and budgeted by later phases.

## Phase 3F widening

Adds two optional `routes[]` fields and the `.sbp.share` shape
(a `.sbp` variant whose `bundle.type == "delegated_share"`).

- `routes[].redistribution_policy`: closed enum
  `{none, delegated_n, transitive}`. Empty / absent maps to
  `none` at the receiver (fail-closed).
- `routes[].redistribution_cap`: uint8 (0..255). Required when
  `redistribution_policy = "delegated_n"`; MUST be absent / 0
  for `none` and `transitive`.
- `redistribution_chain[]` and `delegate_caps[]`: top-level
  arrays present iff `bundle.type == "delegated_share"`.

Six new bundle errors:

- `ErrRedistributionPolicyMalformed`
- `ErrRedistributionCapMalformed`
- `ErrRedistributionChainBroken`
- `ErrRedistributionChainTooDeep` (depth > 5)
- `ErrRedistributionCapExceeded`
- `ErrRedistributionPolicyForbids`

See `delegate-keys-v1.md` for the full wire format and
`canonicalChainState` definition.

## Phase FRP-1 widening (RelayPack profile)

**FRP-1 bumps `spec_version` from 2 to 3** to land the RelayPack
profile per the diaspora-helper supplement v2.3.7 §12.2 + §21.1.
Verifier accepts `{1, 2, 3}`; producers default to v3 when
sealing a RelayPack-bearing bundle.

The RelayPack profile is a constraining schema layered over `.sbp`,
not a separate format. A v3 bundle that does NOT carry RelayPack
metadata is a regular `.sbp` (the new top-level slot is omitted, no
candidate carries `_relaypack`). A v3 bundle that DOES carry
RelayPack metadata adds:

- One new top-level `Manifest.relay_pack` slot with
  `relay_pack_id`, `shared_risk_graph[]`, optional
  `cell_scope_default`, and `freshness_url` (V1.6 only; empty at
  V1.5). Mirrors the additive widening pattern of 3A
  `kill_switches`, 3B `rendezvous_hints`, 3E `transport_modules`,
  and 3F `redistribution_chain` / `delegate_caps`.
- One per-candidate `_relaypack` sub-object inside the existing
  `RouteManifestEntry.FamilySpecificConfig` opaque-JSON slot
  (typed `json.RawMessage`). Bytes round-trip cleanly through
  canonicalisation in older parsers.

Old-client behaviour: a pre-FRP-1 client receiving a non-RelayPack
v3 `.sbp` would still fail signature verification because v3 is not
in the older `{1, 2}` accept set — this is the intentional
update-required signal, identical to the 1.5A v1→v2 transition.

Validator: `bundle/go/relaypackvalidate/validator.go` enforces
RP001..RP018/RP021/RP022/RP023 errors and RP019/RP020/RP024
warnings against a phase-aware `ValidateOpts.Phase` value
(V1.5 / V1.6 / PostV2).

See **`specs/relaypack-v1.md`** for the locked schema, validator rule
list, lint codebook, tag vocabulary, and compatibility contract.

### `freshness_url` field (FRP-8 lift at V1.6)

`Manifest.relay_pack.freshness_url` is reserved at FRP-1 and held
empty at V1.5 by RP021. **FRP-8 lifts the gate at `Phase: V16`**:
a non-empty FRP-controlled `https://` URL is allowed and
recommended. The freshness URL is FRP-controlled (NOT a
Daal-project hostname); BYO domain is the production-closure
default per the supplement §22.2. **`spec_version` does NOT
bump at FRP-8** — the slot is additive within the v3 bump.

Recipient-side fetch lives at `core/refresh/relaypack.go`. The
pure-policy "should we attempt a refresh now?" decision lives
at `core/internal/selection/freshness.go` (no sockets in
`core/internal/selection/`). See `specs/relaypack-v1.md`'s
"V1.6 CDN-fronted profile" section for the freshness JSON shape
(sub-key-aware) + verification chain.

## Phase FRP-7.5 widening (publisher sub-key chain)

**FRP-7.5 bumps `spec_version` from 3 to 4** to land the publisher
sub-key cert chain per `specs/v1-5-closure-v1.md` invariant 18.
Verifier accepts `{1, 2, 3, 4}`; producers default to v4 when
sealing a bundle whose signing key differs from the publisher root
(i.e. when the operator has rotated to a sub-key).

The sub-key chain is an additive in-archive entry. A v4 bundle
that does NOT carry a sub-key cert is a regular `.sbp` signed
directly by the root publisher key. A v4 bundle that DOES carry
one adds exactly one new entry:

- `trust/subkey-cert.json`: canonical-JSON `SubkeyCert` whose
  body fields are `v=1`, `kind="subkey_cert"`,
  `root_fingerprint_hex` (SHA-256 fingerprint of
  `publisher.pub`), `subkey_pub_hex` (32-byte Ed25519 public key,
  hex), `valid_from`, `valid_until` (RFC3339), `label`
  (free-form), and `signature_hex` (the root key's Ed25519
  signature over the canonical body with the `signature_hex` field
  stripped).

`bundle.VerifyBundle` walks `pub → cert → sub`:

  1. Parse archive. If `trust/subkey-cert.json` is **absent**,
     verify `manifest.json` directly against the publisher's
     `publisher.pub` (1A direct path; unchanged).
  2. If the cert is **present** and `spec_version >= 4`:
       a. Parse the SubkeyCert; reject `ErrSubkeyCertMalformed`
          on bad JSON or schema.
       b. Verify the cert's `root_fingerprint_hex` matches
          `PublisherFingerprint(publisher.pub)`
          (`ErrSubkeyCertRootMismatch`).
       c. Verify the cert's signature against `publisher.pub`
          (`ErrSubkeyCertBadSignature`); the canonical body for
          this signature excludes the `signature_hex` field.
       d. Enforce the validity window against the verifier's
          clock: reject `ErrSubkeyCertOutOfWindow` if
          `now < valid_from` or `now >= valid_until`.
       e. Verify `manifest.json`'s signature against the cert's
          `subkey_pub_hex`. Same rules as the direct path
          otherwise.
  3. If the cert is present but `spec_version < 4`:
     reject `ErrSubkeyCertSpecVersionTooOld`. (Pre-V1.5b verifiers
     reject v4 outright by the existing spec_version gate.)

**Five new bundle errors** (sentinel; `errors.Is`-friendly):

- `ErrSubkeyCertMalformed`
- `ErrSubkeyCertRootMismatch`
- `ErrSubkeyCertOutOfWindow`
- `ErrSubkeyCertBadSignature`
- `ErrSubkeyCertSpecVersionTooOld`

**Root-key touch elimination**: under v4, an operator can rotate
their RelayPack and sign with a freshly-minted 90-day sub-key
without ever opening the root publisher key. The wizard's
`subkey_rotate` Tauri command opens the root from the keystore,
spawns `daal-publish subkey rotate --json` (offline, no
network), and persists the new sub-key in the V004 `subkeys`
history table. From then on, `sign_relaypack` passes the active
sub-key private key to `daal-deploy bind-and-sign` via stdin and
passes the active cert via `--subkey-cert`; RelayPack rotations
therefore sign with the sub-key. The root touches disk only when
the operator chooses to mint a new sub-key.

**Old-client compatibility**: a v3 bundle (no sub-key cert)
verifies unchanged on V1.5b verifiers. A v4 bundle reaching a
pre-V1.5b verifier fails with the existing
`ErrUnsupportedSpec` — the intentional update-required
signal, identical to the 1.5A v1→v2 and FRP-1 v2→v3 transitions.

**Cert revocation**: out of scope for FRP-7.5 (forward-only
rotation). Revoking a compromised sub-key is the FRP-1
revocation list's job; rotating to a fresh sub-key (which the
75%/95% lifetime banner prompts for) supersedes the prior
sub-key on V1.5b clients via the `active=1` projection in the
V004 history table.

See `bundle/go/bundle/subkey_chain.go` for the wire-shape
mirror, `bundle/go/bundle/sbp.go::VerifyBundle` for the walk
implementation, `client-desktop/daal-wizard/src/commands.rs`
::`subkey_rotate` for the wizard surface, and
`specs/v1-5-closure-v1.md` for the V1.5 closure invariants this
phase locks down.
