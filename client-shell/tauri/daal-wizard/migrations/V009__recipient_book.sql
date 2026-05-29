-- FRP-14 V009: Per-operator recipient book + per-recipient creds.
--
-- One operator (V2 box) can have up to 128 recipients. Each
-- recipient has:
--
--   * a branded `daal1…` address (the 32-byte X25519 public key,
--     bech32m-encoded, captured at recipient registration time).
--   * a per-server credential row holding the secrets that came
--     back from POST /users/provision. These secrets never leave
--     the publisher app outside an encrypted .sbpx wrapper.
--
-- Hard revoke (FRP-14 locked answer #3): when a recipient is
-- revoked, the row's `revoked_at_unix` is set; we keep the row for
-- audit (the publisher UI shows revoked recipients greyed out).
-- The on-box state is purged via the /users/revoke route +
-- SIGUSR2 kick wrapper.

CREATE TABLE recipients (
    id                  INTEGER PRIMARY KEY,
    operator_id         INTEGER NOT NULL REFERENCES operators(id) ON DELETE CASCADE,
    name                TEXT    NOT NULL,                   -- 'r<n>' matches the on-box name
    display_name        TEXT    NOT NULL DEFAULT '',        -- operator-chosen alias (eg. "Bahar")
    address_str         TEXT    NOT NULL,                   -- branded 'daal1…' bech32m address
    pubkey_x25519_hex   TEXT    NOT NULL,                   -- 64 hex chars; raw X25519 32-byte pub
    fingerprint_hex     TEXT    NOT NULL,                   -- sha256(pubkey) lowercase hex
    -- per-server credentials returned by POST /users/provision
    vless_uuid          TEXT    NOT NULL,
    reality_short_id    TEXT    NOT NULL,                   -- 8 hex chars
    hy2_password        TEXT    NOT NULL,
    naive_password      TEXT    NOT NULL,
    ws_path             TEXT    NOT NULL,
    provisioned_at_unix INTEGER NOT NULL,
    revoked_at_unix     INTEGER NOT NULL DEFAULT 0,
    UNIQUE (operator_id, name),
    UNIQUE (operator_id, pubkey_x25519_hex)
);

CREATE INDEX idx_recipients_operator ON recipients (operator_id);
CREATE INDEX idx_recipients_address  ON recipients (address_str);

-- per-operator counter used to mint the next `name` (r1, r2 …).
-- We track it in a separate row rather than re-scanning recipients
-- so a revoked-then-restored row doesn't recycle a name; once an
-- index is burned we don't reissue it.
CREATE TABLE recipient_name_counters (
    operator_id   INTEGER PRIMARY KEY REFERENCES operators(id) ON DELETE CASCADE,
    next_index    INTEGER NOT NULL DEFAULT 1
);
