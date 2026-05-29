-- FRP-14 Layer 3c V010: recipient-side X25519 identity.
--
-- One row, ever. The recipient app's local `daal1…` address is
-- backed by a Curve25519 keypair generated on first entry to the
-- "My Daal address" screen. The private key is sealed under a
-- PIN in the OS keystore (alias `recipient_priv_x25519`); only
-- the public key + derived address + fingerprint are persisted
-- in this DB.
--
-- v1 is intentionally non-rotatable: losing the phone means
-- losing the identity. See `specs/recipient-identity-v1.md`.

CREATE TABLE recipient_identity (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    pubkey_x25519   BLOB    NOT NULL,            -- raw 32 bytes
    keystore_alias  TEXT    NOT NULL DEFAULT 'recipient_priv_x25519',
    address_str     TEXT    NOT NULL,            -- cached daal1… (63 chars)
    fingerprint_hex TEXT    NOT NULL,            -- 16 lowercase hex chars
    created_at_unix INTEGER NOT NULL
);
