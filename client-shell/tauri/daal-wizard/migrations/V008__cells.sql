-- FRP-11 V008: Trusted cells.
--
-- Introduces three tables:
--
--   cells                       — one row per cell the operator
--                                 participates in (as admin or member).
--   operator_cell_membership    — join table linking the operator's
--                                 OperatorRecord to a cell.
--   cell_revocations            — cell-internal revocation list
--                                 observed locally.
--
-- Per FRP-11 locked answer #1, cell-admin keypairs are FRESH
-- per-admin Ed25519 keypairs, NEVER reused as publisher keys. They
-- are persisted into the wizard's encrypted keystore (the existing
-- secrets_kv mechanism); the alias for that entry is stored in
-- cells.admin_priv_alias when is_admin=1, otherwise empty.
--
-- Per FRP-11 locked answer #4, trust labels live in the engine-side
-- core/trust/labels store. The wizard writes through to that store
-- via core/trust/labels::Set; the wizard's own table here only
-- carries a non-secret advisory hint (cell.trust_label) so the
-- per-cell row in the wizard UI can render a name even when the
-- label store is briefly unavailable.

CREATE TABLE cells (
    id                       INTEGER PRIMARY KEY,
    cell_id                  TEXT    NOT NULL UNIQUE,
    membership_doc_json      TEXT    NOT NULL,
    delegation_doc_json      TEXT    NOT NULL,
    bundle_signer_priv_alias TEXT    NOT NULL,
    directory_url            TEXT    NOT NULL DEFAULT '',
    trust_label              TEXT    NOT NULL DEFAULT '',
    joined_at_unix           INTEGER NOT NULL,
    is_admin                 INTEGER NOT NULL CHECK (is_admin IN (0, 1)),
    admin_priv_alias         TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX idx_cells_cell_id ON cells (cell_id);

CREATE TABLE operator_cell_membership (
    id           INTEGER PRIMARY KEY,
    operator_id  INTEGER NOT NULL REFERENCES operators(id) ON DELETE CASCADE,
    cell_id      INTEGER NOT NULL REFERENCES cells(id)     ON DELETE CASCADE,
    UNIQUE (operator_id, cell_id)
);

CREATE TABLE cell_revocations (
    id                        INTEGER PRIMARY KEY,
    cell_id                   INTEGER NOT NULL REFERENCES cells(id) ON DELETE CASCADE,
    revoked_publisher_fp_hex  TEXT    NOT NULL,
    revocation_doc_json       TEXT    NOT NULL,
    observed_at_unix          INTEGER NOT NULL
);

CREATE INDEX idx_cell_revocations_cell_id ON cell_revocations (cell_id);
