-- V012: relay identity + helper-IP persistence.
--
-- nickname: the user's name for this relay. Until now the wizard's
-- `newLabel` field was typed and thrown away, and `publisherName`
-- lived only in React state, so two relays were indistinguishable in
-- the picker and every share-sheet staged to the same filename.
--
-- helper_ip: the publisher's outbound public IP, used to punch the
-- ephemeral cloud-firewall rule before each mgmt call. It was a
-- parameter on five commands with no storage anywhere, so it
-- evaporated on every relaunch and left buttons disabled for
-- invisible reasons.
--
-- helper_ip_source / helper_ip_at_unix are diagnostic only: they
-- record where the value came from ("auto" third-party echo,
-- "manual" typed by the user, "whoami" confirmed by the box) and
-- when, so a stale-allowlist bug report can be read without guessing.
-- Nothing branches on them.
ALTER TABLE operators ADD COLUMN nickname TEXT NOT NULL DEFAULT '';
ALTER TABLE operators ADD COLUMN helper_ip TEXT NOT NULL DEFAULT '';
ALTER TABLE operators ADD COLUMN helper_ip_source TEXT NOT NULL DEFAULT '';
ALTER TABLE operators ADD COLUMN helper_ip_at_unix INTEGER NOT NULL DEFAULT 0;
