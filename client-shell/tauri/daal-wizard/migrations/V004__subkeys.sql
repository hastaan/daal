-- FRP-7.5 V004: publisher sub-key history.
--
-- Each row is one sub-key the FRP has minted under their root
-- publisher key. The currently-active sub-key (active=1) is the
-- one used by `daal-publish bundle --signing-priv …` for
-- subsequent rotations / re-signings — rotating to a fresh
-- sub-key inserts a new row (active=1) and flips the prior row
-- to active=0 inside one transaction.
--
-- The cert + priv files live on disk under the keystore
-- subkeys/ tree (publisher.Subkey writes them at mode 0o600);
-- the DB only stores paths + metadata. Reverting from a
-- compromised sub-key is a roadmap concern (FRP-7.5 ships
-- forward-only rotation; the revocation list at FRP-1 covers
-- compromise).
--
-- Invariant: at most one row per operator_id has active=1.
-- Backed by the partial-unique-index below.
--
-- Position B: the sub-key priv bytes themselves are NEVER
-- stored in the DB. SubkeyCertJSON is small enough to store
-- inline so the wizard can compute lifetime % without re-
-- reading the disk file.

CREATE TABLE subkeys (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    operator_id              INTEGER NOT NULL,
    subkey_fingerprint_hex   TEXT    NOT NULL,
    subkey_pub_path          TEXT    NOT NULL,
    subkey_priv_path         TEXT    NOT NULL,
    subkey_cert_path         TEXT    NOT NULL,
    cert_json                TEXT    NOT NULL,
    label                    TEXT    NOT NULL DEFAULT '',
    valid_from_unix          INTEGER NOT NULL,
    valid_until_unix         INTEGER NOT NULL,
    rotated_at_unix          INTEGER NOT NULL,
    active                   INTEGER NOT NULL DEFAULT 1
                                CHECK (active IN (0, 1)),
    FOREIGN KEY (operator_id) REFERENCES operators(id)
);

CREATE INDEX idx_subkeys_operator_active
    ON subkeys (operator_id, active);

CREATE INDEX idx_subkeys_valid_until
    ON subkeys (valid_until_unix);

CREATE UNIQUE INDEX uniq_active_subkey_per_operator
    ON subkeys (operator_id) WHERE active = 1;
