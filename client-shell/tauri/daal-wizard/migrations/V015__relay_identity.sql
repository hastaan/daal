-- V015: what the relay says it is, and what the signed pack says it is.
--
-- WHY THIS EXISTS. A RelayPack commits every route to a signed endpoint:
-- the relay's REALITY public key, its TLS key pin, its cover host, the
-- digest of its shadowsocks server key. The publisher signs BEFORE the
-- first recipient exists, so that material has to come from the relay
-- itself (mgmt GET /identity). Two facts then have to outlive the call:
--
--   * `identity_json` — the relay's identity as last learned, so a
--     re-sign that must be fast (the address swap, whose whole value is
--     its 15-second budget) does not need another round trip to a relay
--     whose keys did not move. `box_fingerprint` is the management-TLS
--     fingerprint of the relay it was learned from: a rebuilt relay has
--     a new one, and a row that does not match the current record is
--     about a machine that no longer exists.
--   * `committed_json` — the identity the CURRENTLY SIGNED pack commits
--     to, exactly as bind-and-sign read it back out of the pack. When a
--     relay later answers with something else (a shadowsocks key that
--     did not exist at signing time, a cover host that moved), the
--     difference between the two is what tells the wizard to sign again
--     — instead of handing out files the recipient's app will refuse.
--
-- Nothing here is a secret. The shadowsocks server key is never stored:
-- only its digest, which is what the signed pack publishes anyway.
--
-- One row per relay; ON DELETE CASCADE like every table since V009.
CREATE TABLE relay_identity (
    operator_id       INTEGER PRIMARY KEY
                      REFERENCES operators(id) ON DELETE CASCADE,
    -- The identity document, in the shape `daal-deploy relay-identity`
    -- prints and `bind-and-sign --relay-identity` reads. '' = unknown.
    identity_json     TEXT    NOT NULL DEFAULT '',
    -- 'relay' — the relay stated it (GET /identity).
    -- 'reply' — derived from the relay-wide fields of a users-provision
    --           reply, for a relay whose software predates the route.
    identity_source   TEXT    NOT NULL DEFAULT '',
    box_fingerprint   TEXT    NOT NULL DEFAULT '',
    learned_at_unix   INTEGER NOT NULL DEFAULT 0,
    -- bind-and-sign's `committed_identity` for the active pack.
    committed_json    TEXT    NOT NULL DEFAULT '',
    committed_at_unix INTEGER NOT NULL DEFAULT 0,
    -- Families the active pack signed WITHOUT an endpoint (JSON array).
    uncommitted_json  TEXT    NOT NULL DEFAULT '[]',
    -- Digest of the last relay reply a heal was attempted for, so a
    -- reply the pack can never be made to match (a family the record
    -- does not carry) does not re-sign on every recipient.
    healed_for        TEXT    NOT NULL DEFAULT ''
);
