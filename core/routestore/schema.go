// Package routestore is the on-device store for Route and Publisher rows
// plus an age-encrypted secret KV holding sing-box outbound JSON. It is the
// single source of truth on the device; the Android UI reads from it via
// the engine ABI, never directly.
package routestore

const schema = `
PRAGMA journal_mode=DELETE;
PRAGMA secure_delete=ON;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS publishers (
    publisher_id            TEXT PRIMARY KEY,
    display_name            TEXT NOT NULL,
    trust_level             TEXT NOT NULL,
    first_seen              TEXT NOT NULL,
    last_seen_bundle        TEXT NOT NULL,
    key_status              TEXT NOT NULL,
    rotation_chain_json     TEXT NOT NULL DEFAULT '[]',
    revocation_sources_json TEXT NOT NULL DEFAULT '[]',
    user_assigned_label     TEXT,
    revocation_url          TEXT NOT NULL DEFAULT '',
    revocation_fp_hex       TEXT NOT NULL DEFAULT '',
    last_revocation_check   TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS routes (
    route_id                TEXT PRIMARY KEY,
    transport_family        TEXT NOT NULL,
    engine                  TEXT NOT NULL,
    source_type             TEXT NOT NULL,
    publisher_id            TEXT NOT NULL REFERENCES publishers(publisher_id),
    publisher_label         TEXT NOT NULL DEFAULT '',
    trust_state             TEXT NOT NULL,
    scarcity_class          TEXT NOT NULL,
    modes_allowed_json      TEXT NOT NULL DEFAULT '[]',
    expires_at              TEXT NOT NULL,
    imported_at             TEXT NOT NULL,
    last_success_bucket     TEXT,
    last_failure_bucket     TEXT,
    last_failure_category   TEXT,
    consecutive_failures    INTEGER NOT NULL DEFAULT 0,
    cooldown_until          TEXT,
    bytes_used_this_hour    INTEGER NOT NULL DEFAULT 0,
    bytes_used_this_session INTEGER NOT NULL DEFAULT 0,
    user_note               TEXT
);

CREATE TABLE IF NOT EXISTS trust_audit (
    ts_bucket    TEXT NOT NULL,
    publisher_id TEXT NOT NULL,
    from_state   TEXT NOT NULL,
    to_state     TEXT NOT NULL,
    reason       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS secrets_kv (
    k TEXT PRIMARY KEY,
    v BLOB NOT NULL
);

-- Phase 1.5A: subscription refresh, audit, and "Why this route?" diagnostics.
-- Subscriptions can reference a publisher that has not been pinned yet
-- (e.g., the user adds a subscription pointing at a known publisher
-- before the first .sbp from that publisher arrives). The FK is therefore
-- soft: we record the publisher_id as a string but do not enforce it at
-- the SQL layer. Application code refuses to refresh a subscription
-- whose publisher row is absent.
CREATE TABLE IF NOT EXISTS subscriptions (
    subscription_id        TEXT PRIMARY KEY,
    publisher_id           TEXT NOT NULL,
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

CREATE TABLE IF NOT EXISTS refresh_audit (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT NOT NULL,
    ref_id      TEXT NOT NULL,
    bucket      TEXT NOT NULL,
    outcome     TEXT NOT NULL,
    bytes_in    INTEGER NOT NULL DEFAULT 0,
    via_tunnel  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS diagnostics_explain (
    bucket                 TEXT NOT NULL PRIMARY KEY,
    why_chose_route        TEXT NOT NULL DEFAULT '',
    skipped_families_json  TEXT NOT NULL DEFAULT '[]'
);
`

// migrations is a no-op-on-missing list of additive ALTERs we run on every
// open. SQLite has no native column-exists check; ALTER TABLE ADD COLUMN
// fails when the column is already present, which we ignore. This is the
// idiomatic forward-only migration pattern for additive columns.
var migrations = []string{
	"ALTER TABLE publishers ADD COLUMN revocation_url        TEXT NOT NULL DEFAULT ''",
	"ALTER TABLE publishers ADD COLUMN revocation_fp_hex     TEXT NOT NULL DEFAULT ''",
	"ALTER TABLE publishers ADD COLUMN last_revocation_check TEXT NOT NULL DEFAULT ''",

	// Phase 3A: SBP-v1 widening lands here as additive columns on
	// `routes`. See specs/transport-families-v1.md and
	// specs/sbp-v1.md for the field semantics.
	"ALTER TABLE routes ADD COLUMN family_specific_config_json     TEXT NOT NULL DEFAULT '{}'",
	"ALTER TABLE routes ADD COLUMN caveat_fa_ir                    TEXT NOT NULL DEFAULT ''",
	"ALTER TABLE routes ADD COLUMN experimental_min_engine_version TEXT NOT NULL DEFAULT ''",

	// Phase 3B: rendezvous priority + per-route winning-channel
	// persistence. See specs/rendezvous-channels-v1.md "Per-route
	// persistence" and specs/route-object-v1.md "Phase 3B".
	"ALTER TABLE routes ADD COLUMN rendezvous_priority_json        TEXT NOT NULL DEFAULT '[]'",
	"ALTER TABLE routes ADD COLUMN last_winning_rendezvous_channel TEXT NOT NULL DEFAULT ''",

	// Phase 3C: MASQUE endpoint URL carried verbatim from the
	// SBP-v1 manifest (`routes[].masque_endpoint`). The bundle
	// parser is the gatekeeper — only `transport_family =
	// "masque"` routes may carry a non-empty value, and the URL
	// must be `https://`. The routestore stores whatever it is
	// given; old data without this column round-trips with the
	// empty default. See specs/masque-ladder-v1.md and
	// specs/route-object-v1.md "Phase 3C".
	"ALTER TABLE routes ADD COLUMN masque_endpoint                 TEXT NOT NULL DEFAULT ''",

	// Phase 3D: Psiphon + Conjure refraction hooks. Four
	// additive columns covering both new families. See
	// specs/psiphon-route-v1.md, specs/conjure-route-v1.md,
	// and specs/sbp-v1.md "Phase 3D widening".
	//
	//   - psiphon_bundle_blob: the opaque upstream-Psiphon
	//     publisher bundle bytes. BLOB (not TEXT) because the
	//     Psiphon bundle is binary-canonical. Daal does not
	//     parse the contents; size sanity-checked at the
	//     bundle-parser layer (256 ≤ size ≤ 65536).
	//   - conjure_phantom_subnets_json: JSON array of CIDR
	//     strings. Validated at parse time (/24 IPv4 floor,
	//     /32 IPv6 floor).
	//   - conjure_station_pubkey_hex: 32-byte curve25519 station
	//     pubkey, hex-encoded (64 hex chars). Pinned per route;
	//     rotation requires a new bundle.
	//   - conjure_decoy_pool_json: JSON array of decoy hostnames
	//     (RFC 1123). MAY be empty; upstream then picks
	//     defaults.
	"ALTER TABLE routes ADD COLUMN psiphon_bundle_blob             BLOB NOT NULL DEFAULT x''",
	"ALTER TABLE routes ADD COLUMN conjure_phantom_subnets_json    TEXT NOT NULL DEFAULT '[]'",
	"ALTER TABLE routes ADD COLUMN conjure_station_pubkey_hex      TEXT NOT NULL DEFAULT ''",
	"ALTER TABLE routes ADD COLUMN conjure_decoy_pool_json         TEXT NOT NULL DEFAULT '[]'",

	// Phase 3E: WASM transport_module slot. One additive
	// column on `routes`; the loaded module's bytes do NOT
	// land here (they live in the bundle's transport_modules[]
	// table; the engine's wasm Loader holds the active module
	// in memory). The slug is the cross-reference key the
	// engine uses to resolve a route to a loaded module at
	// activation time. See specs/wasm-transport-v1.md and
	// specs/route-object-v1.md "Phase 3E".
	"ALTER TABLE routes ADD COLUMN transport_module_slug           TEXT NOT NULL DEFAULT ''",

	// Phase 3F: per-route redistribution policy + cap. ONE
	// additive TEXT column carrying the policy enum optionally
	// followed by `:<cap>` for the `delegated_n` case. The
	// wire forms are:
	//
	//   ""               (legacy / unset → engine treats as "none")
	//   "none"
	//   "delegated_n:10"
	//   "transitive"
	//
	// The device-local re-share counter lives separately in
	// `secrets_kv` under `delegate_share_counter:<route_id>` —
	// the routestore row holds only the publisher-declared
	// policy + cap from the SBP. See
	// specs/delegate-keys-v1.md and specs/route-object-v1.md
	// "Phase 3F".
	"ALTER TABLE routes ADD COLUMN redistribution_policy           TEXT NOT NULL DEFAULT ''",

	// FRP-2 (Phase 30): RelayPack profile additive columns.
	// Lifted from supplement v2.3.7 §12.2.2 / §12.2.2.bis /
	// §12.2.5 via the FRP-1 schema (`bundle/go/bundle/relay_pack.go`).
	// Eight per-candidate fields plus the bundle-level
	// `shared_risk_graph_json` denormalised onto every row for
	// read-locality at the FRP-3 selector boundary. All
	// sentinel-empty defaults so legacy non-RelayPack rows
	// round-trip unchanged. See specs/relaypack-v1.md and
	// `phases of development/30-phase-frp-2-import-store-preservation.md`.
	"ALTER TABLE routes ADD COLUMN exposure_mode                  TEXT NOT NULL DEFAULT ''",
	"ALTER TABLE routes ADD COLUMN family_class                   TEXT NOT NULL DEFAULT ''",
	"ALTER TABLE routes ADD COLUMN probing_risk_class             TEXT NOT NULL DEFAULT ''",
	"ALTER TABLE routes ADD COLUMN public_risk_tags_json          TEXT NOT NULL DEFAULT '[]'",
	"ALTER TABLE routes ADD COLUMN origin_risk_tags_json          TEXT NOT NULL DEFAULT '[]'",
	"ALTER TABLE routes ADD COLUMN modifiers_json                 TEXT NOT NULL DEFAULT ''",
	"ALTER TABLE routes ADD COLUMN relay_pack_id                  TEXT NOT NULL DEFAULT ''",
	"ALTER TABLE routes ADD COLUMN freshness_url                  TEXT NOT NULL DEFAULT ''",
	"ALTER TABLE routes ADD COLUMN shared_risk_graph_json         TEXT NOT NULL DEFAULT '[]'",
}
