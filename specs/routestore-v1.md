# Route Store v1

## Status

Phase 1B deliverable; extended additively in Phase 1.5A. Implementation:
`daal/core/routestore` (pure-Go, `modernc.org/sqlite`). Single source
of truth on the device.

## Phase 1.5A additions

Three new tables and three new columns on `publishers`:

```sql
ALTER TABLE publishers ADD COLUMN revocation_url        TEXT NOT NULL DEFAULT '';
ALTER TABLE publishers ADD COLUMN revocation_fp_hex     TEXT NOT NULL DEFAULT '';
ALTER TABLE publishers ADD COLUMN last_revocation_check TEXT NOT NULL DEFAULT '';

CREATE TABLE subscriptions (
    subscription_id        TEXT PRIMARY KEY,
    publisher_id           TEXT NOT NULL,             -- soft FK
    display_name           TEXT NOT NULL,
    url_secret_key         TEXT NOT NULL,
    profile_update_min     INTEGER NOT NULL DEFAULT 1440,
    profile_title          TEXT NOT NULL DEFAULT '',
    support_url            TEXT NOT NULL DEFAULT '',
    last_refresh_bucket    TEXT NOT NULL DEFAULT '',
    last_refresh_outcome   TEXT NOT NULL DEFAULT '',
    last_good_refresh_bkt  TEXT NOT NULL DEFAULT '',
    imported_at            TEXT NOT NULL
);

CREATE TABLE refresh_audit (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT NOT NULL,    -- subscription | revocation | directory | pointer_rotation
    ref_id      TEXT NOT NULL,
    bucket      TEXT NOT NULL,
    outcome     TEXT NOT NULL,
    bytes_in    INTEGER NOT NULL DEFAULT 0,
    via_tunnel  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE diagnostics_explain (
    bucket                 TEXT NOT NULL PRIMARY KEY,
    why_chose_route        TEXT NOT NULL DEFAULT '',
    skipped_families_json  TEXT NOT NULL DEFAULT '[]'
);
```

Two new key spaces in `secrets_kv` (no schema change):

| Key prefix | Holds |
|---|---|
| `subscription-url:<sub_id>` | the subscription URL, age-encrypted |
| `bootstrap-pointers:v1` | persisted pointer rotation set |

Migrations are forward-only and additive: existing stores apply the
ALTERs on first open and silently swallow "duplicate column" errors. No
data is rewritten.

## Files

```
<state_dir>/
  daal.db           sqlite database, mode 0600
  secrets.key        age X25519 identity, mode 0600
  pending/           directory of in-flight bundles awaiting trust prompt
                     (mode 0700; per-bundle file mode 0600)
```

## Schema

```sql
PRAGMA journal_mode = DELETE;
PRAGMA secure_delete = ON;
PRAGMA foreign_keys = ON;

CREATE TABLE publishers (...);   -- publisher_id (hex fp) PK
CREATE TABLE routes (...);       -- route_id (local UUID) PK
CREATE TABLE trust_audit (...);  -- append-only
CREATE TABLE secrets_kv (
    k TEXT PRIMARY KEY,
    v BLOB NOT NULL              -- age-encrypted ciphertext
);
```

Full DDL lives in `core/routestore/schema.go`.

## Encryption

- The secrets KV holds sing-box outbound JSON for each route, age-encrypted with the X25519 identity stored in `secrets.key`.
- The identity file is the device key. On Android it MAY be wrapped by `EncryptedSharedPreferences` in a future revision; the current Phase 1B build trusts the file system permission (mode `0600` inside an app-private directory).
- The `routes` table NEVER stores plaintext profile bytes.

## Time

- All on-disk timestamps are produced by `routestore.HourBucket(t)`.
- The format is `YYYY-MM-DDTHH:00:00Z`.
- Code MUST NOT write `time.Now()` directly to a row.

## Invariants

- Foreign key from `routes.publisher_id` to `publishers.publisher_id` is enforced.
- A route may be deleted; deletion of its publisher cascades to its routes.
- Trust transitions are append-only logged in `trust_audit`.
- Panic-wipe deletes both `daal.db` and `secrets.key` and zeros the in-process key bytes.
- The store is NOT shared across processes; the engine ABI singleton is the only writer.

## Migration

Schema changes after Phase 1B require:

1. A `PRAGMA user_version` bump.
2. An idempotent migration in `routestore.applySchema`.
3. A test that opens a database from the previous user_version and
   verifies the migration applies cleanly.

## Phase 3A additions

Three new columns on `routes` (additive ALTER):

```sql
ALTER TABLE routes ADD COLUMN family_specific_config_json    TEXT NOT NULL DEFAULT '{}';
ALTER TABLE routes ADD COLUMN caveat_fa_ir                   TEXT NOT NULL DEFAULT '';
ALTER TABLE routes ADD COLUMN experimental_min_engine_version TEXT NOT NULL DEFAULT '';
```

One new key in `secrets_kv` (no schema change):

| Key | Holds |
|---|---|
| `experimental_families_enabled` | `"1"` if the experimental gate is on, `"0"` otherwise |

## Phase 3B additions

Two new columns on `routes` (additive ALTER):

```sql
ALTER TABLE routes ADD COLUMN rendezvous_priority_json         TEXT NOT NULL DEFAULT '[]';
ALTER TABLE routes ADD COLUMN last_winning_rendezvous_channel  TEXT NOT NULL DEFAULT '';
```

Three new keys in `secrets_kv` (no schema change):

| Key | Holds |
|---|---|
| `rendezvous_priority` | JSON array of channel IDs; per-engine override of the bundle-supplied priority |
| `push_rendezvous_enabled` | `"1"` if push rendezvous is opt-in, `"0"` otherwise. Default `"0"` |
| `push_device_token` | The FCM/APNS device token (gomobile-only set; never round-trips through cshared) |

Migrations follow the 1.5A additive-only pattern in
`routestore.applySchema`; the ALTERs are appended to the
existing migration list and silently swallow "duplicate
column" errors on already-migrated stores.

## Phase 3C additions

One new column on `routes` (additive ALTER):

```sql
ALTER TABLE routes ADD COLUMN masque_endpoint TEXT NOT NULL DEFAULT '';
```

Two new key spaces in `secrets_kv` (no schema change):

| Key | Holds |
|---|---|
| `masque_submode_override` | The per-engine MASQUE sub-mode pin (one of `masque_h3_quic` / `masque_h2_connect` / `masque_lifeline`, OR empty for "no override") |
| `masque_submode:<route_id>` | The MASQUE sub-mode the engine most recently chose on routeID. Engine-recorded; persists per-route. |

`UpsertRoute` MUST NOT clobber engine-recorded state on
re-import. The `masque_submode:<route_id>` records are written
by `core/abi.RecordChosenMasqueSubmode` only — bundle imports
do not touch them. (The same non-clobber discipline applies to
3B's `last_winning_rendezvous_channel` column.)

## Phase 3D additions

Four new columns on `routes` (additive ALTERs); per-family
config carried verbatim from the SBP-v1 manifest:

```sql
ALTER TABLE routes ADD COLUMN psiphon_bundle_blob          BLOB    NOT NULL DEFAULT X'';
ALTER TABLE routes ADD COLUMN conjure_phantom_subnets_json TEXT    NOT NULL DEFAULT '';
ALTER TABLE routes ADD COLUMN conjure_station_pubkey_hex   TEXT    NOT NULL DEFAULT '';
ALTER TABLE routes ADD COLUMN conjure_decoy_pool_json      TEXT    NOT NULL DEFAULT '';
```

The conjure list-typed fields are persisted as JSON arrays
(rather than introducing a join table) — locked at 3D for
storage simplicity; a future schema rev MAY normalise. The
`UpsertRoute` non-clobber discipline applies: engine-recorded
state (e.g. activation snapshots) lives in `secrets_kv`, not
on the routes table, and is NEVER overwritten by bundle
re-import.

No new `secrets_kv` key spaces are added at 3D — refraction
diagnostics are session-scoped (in-memory only); the
compile-in flags are constants populated from build-tag-
conditional shims, not persisted.

## Phase 3E additions

One new column on `routes` (additive ALTER):

```sql
ALTER TABLE routes ADD COLUMN transport_module_slug TEXT NOT NULL DEFAULT '';
```

The slug is the foreign key into the bundle's
`transport_modules[]`. The routestore does NOT store the
WASM blob itself — blobs ride inside the bundle and are
loaded into the wazero runtime at engine startup. The
`UpsertRoute` non-clobber discipline applies: an UpsertRoute
that supplies the empty string MUST NOT erase a
previously-set slug.

Two new `secrets_kv` key spaces land at 3E (locked for the
WASM kill-switch surface):

- `secrets_kv:wasm_killed:<sha256-hex>` — one entry per
  killed sha256. Stores the JSON-serialised
  `KillSwitchEntry` (slug + sha256 + generation +
  signature). Daalted on engine boot and consulted on
  every WASM module load.
- `secrets_kv:wasm_killed:_generation` — monotonic
  watermark (uint64, big-endian 8 bytes). Engines reject
  any delta whose generation is ≤ the watermark.

The kill-switch keyspace is the FIRST `secrets_kv` namespace
introduced by a transport family — the precedent applies to
any future family-level kill-switch (3F).

## Soak-rig snapshots (Phase 1.5C)

The blackout soak driver
(`test-rigs/distribution-failure/soak-driver/`) takes a per-simulated-day
copy of `daal.db` named `daal.db.snapshot` for offline forensic
review. The schema is unchanged; the snapshot is just the file under a
new name. Snapshots are NEVER included in the rig's `public-bundle.zip`
output — they live only on the developer's machine.

## Security review

This document is updated alongside `docs/security/no-telemetry-review-phase-1b.md` (to be added as the Phase 1B closes).

## Phase 3F: redistribution policy column + share counter

One additive ALTER on `routes`:

```sql
ALTER TABLE routes ADD COLUMN redistribution_policy TEXT NOT NULL DEFAULT '';
```

Carries the (policy, cap) pair encoded as `<policy>` or
`<policy>:<cap>` for `delegated_n`. Empty in / empty out;
unknown shapes decode to `("none", 0)` (fail-closed).

The device-local re-share counter lives separately in the
`secrets_kv` table under the namespace
`delegate_share_counter:<route_id>` (uint8 ASCII decimal).
UpsertRoute MUST NOT clobber the counter — the column update
in the conflict-update clause overwrites the policy column
ONLY (3D/3E-style non-clobber). See `delegate-keys-v1.md`.
