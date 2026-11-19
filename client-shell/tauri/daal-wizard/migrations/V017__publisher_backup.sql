-- V017: publisher backup and restore (per device, never backed up).
--
-- last_backup_at_unix / last_backup_digest: when the last backup file
-- was made on this phone and the digest of the state it held, so the
-- screen can say "your backup is out of date" after people change.
--
-- restore_pending_nonce: a restore committed its rows but has not yet
-- written every file and key. Non-empty means no publisher operation
-- may run until `finish_pending_restore` completes it.
--
-- restored_at_unix / restored_backup_made_at_unix /
-- restore_notice_dismissed: the old-phone notice shown after a restore
-- until the person says they understood it.
--
-- words_changed_at_unix: new recovery words were confirmed after the
-- last backup, so that backup opens only with the old words and counts
-- as out of date until a new one is made. 0 = no change since.
--
-- share_unconfirmed_at_unix / share_unconfirmed_digest: a backup was
-- handed to another app and the person has not yet said it arrived.
-- Opening a share chooser proves nothing, so it is not the last backup
-- until they do.
CREATE TABLE publisher_backup_meta (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  last_backup_at_unix          INTEGER NOT NULL DEFAULT 0,
  last_backup_digest           TEXT    NOT NULL DEFAULT '',
  restore_pending_nonce        TEXT    NOT NULL DEFAULT '',
  restored_at_unix             INTEGER NOT NULL DEFAULT 0,
  restored_backup_made_at_unix INTEGER NOT NULL DEFAULT 0,
  restore_notice_dismissed     INTEGER NOT NULL DEFAULT 0 CHECK (restore_notice_dismissed IN (0,1)),
  words_changed_at_unix        INTEGER NOT NULL DEFAULT 0,
  share_unconfirmed_at_unix    INTEGER NOT NULL DEFAULT 0,
  share_unconfirmed_digest     TEXT    NOT NULL DEFAULT ''
);
INSERT INTO publisher_backup_meta (id) VALUES (1);
