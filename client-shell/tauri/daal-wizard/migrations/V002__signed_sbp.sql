-- FRP-4b V002: track the latest signed RelayPack for each operator.
--
-- After bind-and-sign succeeds, the wizard records the SHA-256 of
-- the .sbp on the operator row (along with the relay_pack_id and
-- a UNIX timestamp). This lets the wizard show "last bind: <date>"
-- on the operator-list screen and lets cancel-and-cleanup detect
-- whether a sealed key still has a published bundle to invalidate.
--
-- The .sbp bytes themselves are NOT stored in the DB; the file
-- lives at <staging_dir>/<id>.sbp on disk and the wizard re-reads
-- it on demand for the QR-fountain stream.
--
-- All three columns are NULL until the first successful bind.

ALTER TABLE operators ADD COLUMN signed_sbp_sha256 TEXT;
ALTER TABLE operators ADD COLUMN signed_sbp_relay_pack_id TEXT;
ALTER TABLE operators ADD COLUMN signed_sbp_at_unix INTEGER;
