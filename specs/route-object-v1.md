# Route Runtime Object v1

## Status

Draft for V0 freeze. **Phase 3A widens the schema additively
with three fields carried from the SBP-v1 manifest.**
**Phase 3B adds two additive fields: `rendezvous_priority`
(carried from SBP-v1 widening) and `last_winning_rendezvous_channel`
(engine-recorded; persists per-route across session epochs).**
**Phase 3C adds one additive field: `masque_endpoint` (carried
from SBP-v1 widening; only meaningful on `transport_family =
"masque"` routes).**
**Phase 3D adds four additive fields:
`psiphon_bundle_blob_b64`, `conjure_phantom_subnets`,
`conjure_station_pubkey`, `conjure_decoy_pool` (carried from
SBP-v1 widening; only meaningful on the matching family).**
**Phase 3E adds one additive field: `transport_module_slug`
(carried from SBP-v1 widening; REQUIRED on
`transport_family = "transport_module"` routes; rejected on
other families). The slug references an entry in the bundle's
top-level `transport_modules[]`. See
`specs/wasm-transport-v1.md`.**

## Purpose

`Route` is the local object visible to the path manager and UI. It intentionally exposes less than the underlying secret/config store.

## Schema

```json
{
  "route_id": "local-uuid",
  "transport_family": "vless-reality",
  "engine": "sing-box",
  "source_type": "official_bootstrap|trusted_provider|friend_shared|manual|subscription|experimental",
  "publisher_id": "ed25519-key-fingerprint-hex",
  "publisher_label": "Provider display name",
  "trust_state": "trusted|tofu|unknown|expired|revoked|changed_key",
  "scarcity_class": "emergency|low|normal|bulk-capable|experimental|lifeline-only",
  "modes_allowed": ["lifeline", "normal"],
  "expires_at": "2026-05-25T12:00:00Z",
  "imported_at": "2026-04-25T12:00:00Z",
  "last_success_bucket": "2026-04-25T14:00Z",
  "last_failure_bucket": "2026-04-25T13:00Z",
  "last_failure_category": "tcp_reset",
  "consecutive_failures": 0,
  "cooldown_until": null,
  "bytes_used_this_hour": 0,
  "bytes_used_this_session": 0,
  "user_note": "",
  "family_specific_config": {},
  "caveat_fa_ir": "",
  "experimental_min_engine_version": "",
  "rendezvous_priority": [],
  "last_winning_rendezvous_channel": "",
  "masque_endpoint": "",
  "psiphon_bundle_blob_b64": "",
  "conjure_phantom_subnets": [],
  "conjure_station_pubkey": "",
  "conjure_decoy_pool": [],
  "transport_module_slug": ""
}
```

The Phase 3A fields (`family_specific_config`, `caveat_fa_ir`,
`experimental_min_engine_version`) are populated from the
SBP-v1 manifest verbatim. They are opaque to the routestore;
only the family's engine handler interprets
`family_specific_config`, and only the trust UI renders
`caveat_fa_ir`. The `experimental_min_engine_version` field
gates the route at the pathmanager filter step described in
`specs/transport-families-v1.md`.

The Phase 3B fields:

- `rendezvous_priority: [string]` — carried verbatim from the
  SBP-v1 manifest. Consumed only by Snowflake-family routes
  (other families ignore). Empty → engine defaults to
  `["domain_fronted_broker", "amp_cache", "sqs", "offline_hint"]`.
- `last_winning_rendezvous_channel: string` — engine-recorded
  on a successful Solicit. Persists per-route across session
  epochs. Used by the Selector to bias the t=0 fire toward
  the historically successful channel on this route. Empty
  string means "no winner recorded yet."

The Phase 3C field:

- `masque_endpoint: string` — carried verbatim from the SBP-v1
  manifest's `routes[].masque_endpoint`. Only meaningful on
  `transport_family = "masque"` routes (other families have
  the field empty by parser invariant). MUST be a parseable
  `https://host[:port]/path` URL with a non-empty path when
  present. Empty on a MASQUE route means "no usable endpoint;
  the engine filters this route at activation time." See
  `specs/masque-ladder-v1.md`. The chosen sub-mode for a
  given activation does NOT live on the route object — it is
  per-session state inside the masque handler and per-network
  state in the netmem snapshot.

The Phase 3D fields:

- `psiphon_bundle_blob_b64: string` — carried verbatim from
  the SBP-v1 manifest. Only meaningful on
  `transport_family = "psiphon"` routes; the parser rejects
  the field on other families. Decoded length is in
  `[256, 65536]`. The bytes are opaque to Daal — only the
  vendored psiphon-tunnel-core library interprets them. See
  `specs/psiphon-route-v1.md`.
- `conjure_phantom_subnets: [string]` — list of CIDRs (floors
  `/24` IPv4 / `/32` IPv6) the conjure handler draws phantom
  IPs from. Only meaningful on `transport_family = "conjure"`
  routes.
- `conjure_station_pubkey: string` — 64 hex chars (32 bytes)
  curve25519 station pubkey. Only meaningful on conjure
  routes.
- `conjure_decoy_pool: [string]` — RFC 1123 decoy hostnames
  the upstream library MAY use as registration cover. Empty
  list ⇒ upstream picks defaults. Only meaningful on
  conjure routes. See `specs/conjure-route-v1.md`.

The chosen phantom IP for a conjure activation does NOT live
on the route object; it is per-session state in the conjure
handler, surfaced HASHED in
`engine_export_diagnostics.conjure_phantom_in_use`.

The Phase 3E field:

- `transport_module_slug: string` — carried verbatim from the
  SBP-v1 manifest's `routes[].transport_module_slug`.
  REQUIRED on `transport_family = "transport_module"` routes;
  the parser rejects the field on other families. Routes
  whose slug is unknown to the loaded bundle are
  soft-validated out (skipped). Locked at 3E:
  - The slug is included in the routestore's non-clobber
    list — an UpsertRoute that supplies the empty string MUST
    NOT erase a previously-set slug.
  - The slug never leaves the device.
  - The currently-loaded module (slug + sha256 prefix +
    loaded_at) is surfaced via the
    `loaded_wasm_modules` diagnostic field, NOT on the
    route object — multiple routes can share a single
    module.
  - The killed-set is keyed by sha256, NOT by slug; see
    `specs/wasm-kill-switch-v1.md`.

## Invariants

- `route_id` is local and never leaves the device.
- Trust state and network success are independent.
- `auth_failed` must not trigger censorship cooldown logic.
- Expired and revoked routes are disabled.
- User note never leaves the device.

## Not Stored Here

- full subscription URL,
- route secret material if avoidable,
- destination history,
- exact user location,
- exact network identity,
- exact timestamps finer than needed.

## Phase 3F: redistribution policy + cap

Two optional fields, persisted in the routestore as a single
TEXT column (`redistribution_policy`) carrying both the policy
and an optional uint8 cap encoded as `<policy>` or
`<policy>:<cap>`:

- `redistribution_policy`: closed enum
  `{"", "none", "delegated_n", "transitive"}`. Empty / unset
  is treated as "none" (fail-closed) at the engine.
- `redistribution_cap`: uint8 (0..255). Only meaningful when
  policy = `"delegated_n"`.

The device-local re-share counter lives separately under
`secrets_kv:delegate_share_counter:<route_id>` (uint8 ASCII
decimal). UpsertRoute MUST NOT clobber the counter (3D/3E-style
non-clobber discipline preserved). See `delegate-keys-v1.md`.
