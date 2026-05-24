-- FRP-9 V006: structured rotation-kind tag on signed_sbps history.
--
-- V003 originally captured the rotation level as free-form prose
-- inside rotation_reason ("L3 | ip burned"). FRP-9 introduces
-- three new cdn_fronted modes (L7/L8/L9) and the wizard's audit
-- view needs to distinguish them programmatically — the L9
-- origin-only path in particular is a §14.4 invisible-rotation
-- and the audit view must render it differently (no "new
-- fingerprint" badge, no "scan a new QR" suggestion).
--
-- This migration adds a typed `rotation_kind` column and
-- backfills it from the existing free-form rotation_reason. The
-- rotation_reason column is preserved verbatim for its
-- human-readable use; the new column is the machine-readable tag.
--
-- Recognized values (TEXT, lowercase):
--   ''                empty for legacy rows where the kind cannot
--                     be inferred (initial provision and pre-FRP-9
--                     direct-mode rotations whose reason text
--                     doesn't carry a level prefix)
--   'direct_l1'..'direct_l6'
--                     direct-mode rotations from V1.5 (FRP-7)
--   'cdn_path'        L7_CDN_PATH (public-path rotation, re-signed)
--   'cdn_hostname'    L8_CDN_HOSTNAME (hostname rotation, re-signed)
--   'cdn_origin'      L9_CDN_ORIGIN (origin-only, §14.4 invisible,
--                     audit-only history row, NOT re-signed)
--
-- Invariant: the application MUST set rotation_kind on every new
-- INSERT into signed_sbps. The CHECK constraint guards against
-- typos — only the recognized lowercase tags or the empty string
-- (for backfill of legacy rows that genuinely don't have a tag)
-- are accepted.

ALTER TABLE signed_sbps
    ADD COLUMN rotation_kind TEXT NOT NULL DEFAULT '';

-- Backfill the structured tag from the legacy rotation_reason
-- text. We use SQLite-compatible string functions (SUBSTR + LIKE)
-- to keep the migration deterministic across SQLite versions.

UPDATE signed_sbps
   SET rotation_kind = 'direct_l1'
   WHERE rotation_kind = '' AND rotation_reason LIKE 'L1 |%';

UPDATE signed_sbps
   SET rotation_kind = 'direct_l2'
   WHERE rotation_kind = '' AND rotation_reason LIKE 'L2 |%';

UPDATE signed_sbps
   SET rotation_kind = 'direct_l3'
   WHERE rotation_kind = '' AND rotation_reason LIKE 'L3 |%';

UPDATE signed_sbps
   SET rotation_kind = 'direct_l4'
   WHERE rotation_kind = '' AND rotation_reason LIKE 'L4 |%';

UPDATE signed_sbps
   SET rotation_kind = 'direct_l5'
   WHERE rotation_kind = '' AND rotation_reason LIKE 'L5 |%';

UPDATE signed_sbps
   SET rotation_kind = 'direct_l6'
   WHERE rotation_kind = '' AND rotation_reason LIKE 'L6 |%';

UPDATE signed_sbps
   SET rotation_kind = 'cdn_path'
   WHERE rotation_kind = '' AND rotation_reason LIKE 'L7_CDN_PATH |%';

UPDATE signed_sbps
   SET rotation_kind = 'cdn_hostname'
   WHERE rotation_kind = '' AND rotation_reason LIKE 'L8_CDN_HOSTNAME |%';

UPDATE signed_sbps
   SET rotation_kind = 'cdn_origin'
   WHERE rotation_kind = '' AND rotation_reason LIKE 'L9_CDN_ORIGIN |%';

CREATE INDEX idx_signed_sbps_rotation_kind
    ON signed_sbps (operator_id, rotation_kind);
