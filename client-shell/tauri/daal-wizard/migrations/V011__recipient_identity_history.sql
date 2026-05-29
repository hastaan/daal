-- Device Custody B4 V011: identity rotation history + custody audit log.
--
-- Two tables, both single-row-per-event (no UPDATE after INSERT):
--
--   recipient_identity_history — every priv-key the recipient
--   has ever held, with the custody alias under which it is
--   wrapped. The CURRENT key lives in `recipient_identity` (V010)
--   under alias `recipient_priv_x25519`; on rotation we promote
--   the current row into this table under a versioned alias
--   `recipient_priv_x25519.v<n>` so `.sbpx` envelopes sealed to
--   any prior address can still be opened (grace decrypt).
--
--   custody_events — append-only audit log of custody-level
--   user actions: identity created, identity rotated, custody
--   locked, custody unlocked, panic_wipe armed. Shown read-only
--   in the Settings → Custody → History view. The log itself is
--   PII-free; only event kind + timestamp + a small JSON detail
--   object (e.g. {"new_address": "daal1…", "old_alias": "…"}).

CREATE TABLE recipient_identity_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    version         INTEGER NOT NULL,                    -- 1-based; v1 = first
    pubkey_x25519   BLOB    NOT NULL,
    keystore_alias  TEXT    NOT NULL,                    -- e.g. recipient_priv_x25519.v1
    address_str     TEXT    NOT NULL,
    fingerprint_hex TEXT    NOT NULL,
    created_at_unix INTEGER NOT NULL,                    -- when the key was originally created
    retired_at_unix INTEGER NOT NULL,                    -- when it was rotated out (this insert)
    UNIQUE (version),
    UNIQUE (keystore_alias)
);

CREATE INDEX idx_recipient_identity_history_retired
    ON recipient_identity_history (retired_at_unix);

CREATE TABLE custody_events (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    at_unix        INTEGER NOT NULL,
    kind           TEXT    NOT NULL,                     -- created|rotated|locked|unlocked|panic_wipe
    level          TEXT    NOT NULL DEFAULT '',          -- hardware|os_keystore|session_passphrase|''
    detail_json    TEXT    NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_custody_events_at ON custody_events (at_unix);
