-- V021: two more add-on kinds, the update notes (specs/update-ladder-v2.md,
-- docs/update-ladder-v2.md §4.1 and §4.3).
--
--   gittag   "Updates through GitHub": a public repository under the
--            publisher's GitHub account; its tags and files carry the
--            sealed notes (detail: owner, repo, seq, last write)
--   dnsnote  "Updates through DNS": six A records in the publisher's
--            Cloudflare zone carry the sealed standby address, for named
--            people only (detail: zone, last write)
--
-- SQLite cannot widen a CHECK, so the table is rebuilt with the same
-- columns in the same order (a publisher backup addresses them by name).
-- Nothing references relay_addons, so the DROP takes nothing with it.

CREATE TABLE relay_addons_v021 (
  id                 INTEGER PRIMARY KEY AUTOINCREMENT,
  operator_id        INTEGER NOT NULL REFERENCES operators(id) ON DELETE CASCADE,
  kind               TEXT    NOT NULL CHECK (kind IN ('standby','cdn','google','gittag','dnsnote')),
  state              TEXT    NOT NULL CHECK (state IN ('building','ready','promoted','removing')),
  provider_ids_json  TEXT    NOT NULL DEFAULT '{}',
  monthly_cost_cents INTEGER NOT NULL DEFAULT 0 CHECK (monthly_cost_cents >= 0),
  cost_currency      TEXT    NOT NULL DEFAULT '',
  secret_alias       TEXT    NOT NULL DEFAULT '',
  detail_json        TEXT    NOT NULL DEFAULT '{}',
  created_at_unix    INTEGER NOT NULL,
  updated_at_unix    INTEGER NOT NULL DEFAULT 0
);

INSERT INTO relay_addons_v021 (id, operator_id, kind, state, provider_ids_json,
    monthly_cost_cents, cost_currency, secret_alias, detail_json,
    created_at_unix, updated_at_unix)
  SELECT id, operator_id, kind, state, provider_ids_json,
    monthly_cost_cents, cost_currency, secret_alias, detail_json,
    created_at_unix, updated_at_unix
  FROM relay_addons;

DROP TABLE relay_addons;
ALTER TABLE relay_addons_v021 RENAME TO relay_addons;

CREATE INDEX idx_relay_addons_operator ON relay_addons (operator_id);

CREATE UNIQUE INDEX uniq_relay_addons_live_kind
    ON relay_addons (operator_id, kind) WHERE state <> 'promoted';
