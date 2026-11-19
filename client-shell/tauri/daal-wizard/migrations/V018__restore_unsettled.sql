-- V018: after a restore, people this phone must not re-create unasked
-- (PB-1). Per device, never backed up.
--
-- A backup is a snapshot. Someone removed on the old phone after the
-- backup was made is still in the restored list as not removed, and
-- the relay no longer knows them; "Renew everyone's files" would then
-- create them again with a fresh working file. So the restore writes
-- one row per person not removed, in the same transaction as its
-- commit, and nothing may create such a person on the relay until the
-- row says so:
--
--   unchecked  restored; the relay has not been asked yet.
--   ask        the relay was asked and does not know them: the person
--              using the phone must say whether they still should have
--              access. Skipped by renew, repack and rotation.
--   keep       answered "still should have access": treated as anyone
--              else from now on.
--   removed    answered "was removed": the recipient row is marked
--              removed in the same transaction; never created.
--
-- A person the relay does know when it is first asked has nothing to
-- settle: their row is deleted. A relay is settled when it has no
-- `unchecked` or `ask` row. People added after the restore never get a
-- row.
CREATE TABLE restore_unsettled (
  operator_id      INTEGER NOT NULL REFERENCES operators(id) ON DELETE CASCADE,
  recipient_id     INTEGER NOT NULL REFERENCES recipients(id) ON DELETE CASCADE,
  state            TEXT    NOT NULL CHECK (state IN ('unchecked','ask','keep','removed')),
  answered_at_unix INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (operator_id, recipient_id)
);
