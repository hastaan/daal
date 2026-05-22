-- FRP-5 V001: operators + pin_attempts.
--
-- `operators.status` lifecycle:
--   pre-provision  (FRP-5 ship — wizard finalised, FRP-4b not yet run)
--   provisioned    (FRP-4b sets after Provider.Provision + BindAndSign)
--   decommissioned (FRP-4b/FRP-7 set on tear-down)
--
-- `operator_record_json` is the canonical-JSON shape of FRP-4a's
-- `provider.OperatorRecord` Go struct. At pre-provision the
-- server_id / public_ip / candidates / provisioned_at fields are
-- empty; FRP-4b populates them.

CREATE TABLE operators (
    id                            INTEGER PRIMARY KEY,
    status                        TEXT    NOT NULL DEFAULT 'pre-provision',
    operator_record_json          TEXT    NOT NULL,
    publisher_pub_hex             TEXT    NOT NULL,
    publisher_priv_keystore_alias TEXT    NOT NULL,
    cloud_provider                TEXT    NOT NULL,
    cloud_token_keystore_alias    TEXT    NOT NULL,
    created_at_unix               INTEGER NOT NULL,
    last_provisioned_at_unix      INTEGER,
    decommissioned_at_unix        INTEGER
);

CREATE INDEX idx_operators_pubhex ON operators (publisher_pub_hex);

CREATE TABLE pin_attempts (
    id              INTEGER PRIMARY KEY,
    attempt_at_unix INTEGER NOT NULL,
    success         INTEGER NOT NULL CHECK (success IN (0, 1))
);

CREATE INDEX idx_pin_attempts_at ON pin_attempts (attempt_at_unix);
