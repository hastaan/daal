-- V016: the publisher on their own — recover, renew, check, release.
--
-- recipients.creds_box_fp: the relay's management-TLS fingerprint at the
-- moment this person's credentials were minted. A rebuild gives the
-- relay a new fingerprint and a box that does not know anybody, so a
-- marker that differs from the current fingerprint is exactly "this
-- person's file stopped working when the server was replaced". Renew
-- re-creates such people (--replace) and leaves the rest alone
-- (--ensure), which is what makes pressing it twice safe.
--
-- operators.shared_box_fp: the same marker for the everyone file (r0).
--
-- last_health_json / last_health_at_unix: the last health check, so the
-- relay list can show it without re-running it and so the check runs at
-- most once every few minutes.
--
-- unreleased_addresses_json: addresses Daal reserved for a relay whose
-- server is gone but which could not be given back yet. They still cost
-- money; the relay card names them and offers to try again.
--
-- Backfill: rows predating V016 are stamped with the CURRENT
-- fingerprint, i.e. assumed fine. For a relay rebuilt before this
-- migration that is wrong, and the health check's people_missing is
-- what reveals it; renew is correct either way.
ALTER TABLE recipients ADD COLUMN creds_box_fp TEXT NOT NULL DEFAULT '';
UPDATE recipients SET creds_box_fp = COALESCE(
    (SELECT mgmt_tls_fingerprint FROM operators o WHERE o.id = recipients.operator_id), '');
ALTER TABLE operators ADD COLUMN shared_box_fp TEXT NOT NULL DEFAULT '';
UPDATE operators SET shared_box_fp = mgmt_tls_fingerprint;
ALTER TABLE operators ADD COLUMN last_health_json TEXT NOT NULL DEFAULT '';
ALTER TABLE operators ADD COLUMN last_health_at_unix INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operators ADD COLUMN unreleased_addresses_json TEXT NOT NULL DEFAULT '[]';
