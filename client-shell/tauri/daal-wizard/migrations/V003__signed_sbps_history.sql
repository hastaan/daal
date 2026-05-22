-- FRP-7 V003: rotation history for signed RelayPacks.
--
-- The `operators.signed_sbp_*` columns from V002 hold the
-- *currently active* bundle (fast-read projection for the
-- operator-list screen). V003 adds a full history table so:
--
--  1. Every successful rotation produces a fresh row (active=1)
--     and flips the prior row to active=0 inside one transaction.
--  2. `Revert` (the FRP-side undo button) walks the history table,
--     picks the most recent inactive row, flips it back to
--     active=1, and updates the V002 projection columns.
--  3. The rotation reason (one-line, identifier-free label
--     produced by the rotation recommender) is preserved so the
--     operator can read the rotation log.
--
-- Invariant: at most one row per operator_id has active=1. This is
-- enforced by application code (the rotation transaction); SQLite
-- partial-unique-index on (operator_id) WHERE active=1 backs it up.
--
-- Position B: the .sbp bytes themselves are NOT stored in the DB;
-- they live at <staging_dir>/<id>-<signed_at_unix>.sbp on disk.

CREATE TABLE signed_sbps (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    operator_id     INTEGER NOT NULL,
    signed_at_unix  INTEGER NOT NULL,
    sbp_path        TEXT    NOT NULL,
    sbp_sha256      TEXT    NOT NULL,
    relay_pack_id   TEXT    NOT NULL,
    route_count     INTEGER NOT NULL,
    rotation_reason TEXT    NOT NULL DEFAULT '',
    active          INTEGER NOT NULL DEFAULT 1
                      CHECK (active IN (0, 1)),
    FOREIGN KEY (operator_id) REFERENCES operators(id)
);

CREATE INDEX idx_signed_sbps_operator_active
    ON signed_sbps (operator_id, active);

CREATE INDEX idx_signed_sbps_signed_at
    ON signed_sbps (signed_at_unix);

-- At most one active row per operator (defence-in-depth; the
-- rotation transaction flips active=0 before insert active=1).
CREATE UNIQUE INDEX uniq_active_sbp_per_operator
    ON signed_sbps (operator_id) WHERE active = 1;
