-- V020: a removed person can be added again.
--
-- V009 made a Daal address unique per relay for the life of the book:
-- `UNIQUE (operator_id, pubkey_x25519_hex)`. Removing someone keeps
-- their row (revoked_at_unix set) for the "removed" fold and for renew,
-- which removes them from the relay again by name. So adding the same
-- address back after a removal hit that constraint — and only after a
-- fresh user had already been made on the relay.
--
-- The rule now: at most ONE LIVE row per address per relay. A removed
-- row keeps its name, its id and its dead credentials as history; a
-- re-add is a new person in every way — a fresh row id, a fresh `r<n>`
-- name from the counter (names are never reissued, V009) and fresh
-- credentials from the relay. Nothing keyed by the old id, name or
-- credentials can reach the new person, and nothing that touches the
-- old row (renew revokes removed names again) can bring the old file
-- back.
--
-- SQLite cannot drop a table constraint, so the table is rebuilt with
-- the same columns in the same order (a publisher backup addresses
-- them by name). `restore_unsettled` (V018) references recipients(id)
-- ON DELETE CASCADE and foreign keys are ON while migrations run, so
-- the DROP below would empty it: its rows are kept aside and put back.

CREATE TEMP TABLE v020_restore_unsettled AS SELECT * FROM restore_unsettled;

CREATE TABLE recipients_v020 (
    id                  INTEGER PRIMARY KEY,
    operator_id         INTEGER NOT NULL REFERENCES operators(id) ON DELETE CASCADE,
    name                TEXT    NOT NULL,
    display_name        TEXT    NOT NULL DEFAULT '',
    address_str         TEXT    NOT NULL,
    pubkey_x25519_hex   TEXT    NOT NULL,
    fingerprint_hex     TEXT    NOT NULL,
    vless_uuid          TEXT    NOT NULL,
    reality_short_id    TEXT    NOT NULL,
    hy2_password        TEXT    NOT NULL,
    naive_password      TEXT    NOT NULL,
    ws_path             TEXT    NOT NULL,
    provisioned_at_unix INTEGER NOT NULL,
    revoked_at_unix     INTEGER NOT NULL DEFAULT 0,
    creds_box_fp        TEXT    NOT NULL DEFAULT '',
    UNIQUE (operator_id, name)
);

INSERT INTO recipients_v020
    (id, operator_id, name, display_name, address_str, pubkey_x25519_hex,
     fingerprint_hex, vless_uuid, reality_short_id, hy2_password,
     naive_password, ws_path, provisioned_at_unix, revoked_at_unix, creds_box_fp)
SELECT id, operator_id, name, display_name, address_str, pubkey_x25519_hex,
       fingerprint_hex, vless_uuid, reality_short_id, hy2_password,
       naive_password, ws_path, provisioned_at_unix, revoked_at_unix, creds_box_fp
  FROM recipients;

DROP TABLE recipients;
ALTER TABLE recipients_v020 RENAME TO recipients;

CREATE INDEX idx_recipients_operator ON recipients (operator_id);
CREATE INDEX idx_recipients_address  ON recipients (address_str);
-- One live row per address per relay; removed rows are history.
CREATE UNIQUE INDEX idx_recipients_live_pubkey
    ON recipients (operator_id, pubkey_x25519_hex) WHERE revoked_at_unix = 0;

INSERT INTO restore_unsettled SELECT * FROM v020_restore_unsettled;
DROP TABLE v020_restore_unsettled;
