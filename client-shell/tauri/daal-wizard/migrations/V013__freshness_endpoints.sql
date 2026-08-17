-- V013: freshness endpoints (Wave 3 Step 8).
--
-- A freshness endpoint is a static-hosting location the publisher
-- controls, where two objects live: the signed freshness document
-- (which says "the pack you hold is stale, here is the new digest")
-- and a copy of the .sbp it points at. A recipient whose pack carries
-- the endpoint's public URL can therefore recover from a rotation
-- over the network instead of waiting for a courier.
--
-- WHY N ROWS AND NOT ONE COLUMN ON `operators`.
--
-- The URL is baked into a signed pack, so it is a fixed endpoint with
-- the same shelf life as any other fixed endpoint — arguably shorter,
-- because it is small, unique and pollable. A single URL is a
-- countdown, not a design. The publisher configures several, across
-- DISTINCT providers, and the recipient tries them in randomised
-- order. Note "distinct providers", not "distinct rows": two R2
-- buckets share a fate the day Cloudflare is nationally blocked, which
-- is why `kind` is stored and the UI counts kinds.
--
-- WHAT IS DELIBERATELY *NOT* IN THIS TABLE.
--
-- Credentials. An R2 secret access key and a GitHub PAT are cloud
-- WRITE credentials: whoever holds one can replace the document every
-- recipient trusts. They live under DeviceCustody like the publisher's
-- signing key, and this table stores only `secret_alias`, the custody
-- handle. The access-key *id* goes into custody too — it is half of a
-- credential pair and the operator record is a plaintext JSON blob
-- that gets copied into staging files on every rotation.
--
-- last_publish_* is the honesty ledger. The UI is forbidden from
-- claiming a publish succeeded on any other basis, so these columns
-- are written only from a real 2xx (ok=1) or a real failure (ok=0
-- with the provider's own message in `detail`). A row that has never
-- been published has at_unix=0, which renders as "never published" —
-- not as "fine".
CREATE TABLE IF NOT EXISTS freshness_endpoints (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    operator_id          INTEGER NOT NULL,
    -- 'r2' | 'ghpages'. The provider identity, used for the
    -- distinct-provider count as well as for dispatch.
    kind                 TEXT    NOT NULL,
    -- Operator-chosen ordering. Recipients randomise, so this is
    -- purely which one the UI lists first and which URL is offered
    -- to the pack binder while it accepts only one.
    position             INTEGER NOT NULL DEFAULT 0,
    -- Recipient-facing HTTPS URL of the freshness document itself,
    -- without a trailing slash. This is the string that goes into the
    -- pack's mirror set as `<kind>=<url>`, so it must be exactly what
    -- a recipient can GET.
    public_base_url      TEXT    NOT NULL,
    -- r2 routing (non-secret).
    account_id           TEXT    NOT NULL DEFAULT '',
    bucket               TEXT    NOT NULL DEFAULT '',
    key_prefix           TEXT    NOT NULL DEFAULT '',
    -- ghpages routing (non-secret).
    gh_owner             TEXT    NOT NULL DEFAULT '',
    gh_repo              TEXT    NOT NULL DEFAULT '',
    gh_path_prefix       TEXT    NOT NULL DEFAULT '',
    gh_branch            TEXT    NOT NULL DEFAULT '',
    -- DeviceCustody alias holding the credential JSON. Never the
    -- credential itself.
    secret_alias         TEXT    NOT NULL,
    created_unix         INTEGER NOT NULL,
    last_publish_at_unix INTEGER NOT NULL DEFAULT 0,
    last_publish_ok      INTEGER NOT NULL DEFAULT 0,
    last_publish_status  INTEGER NOT NULL DEFAULT 0,
    last_publish_detail  TEXT    NOT NULL DEFAULT '',
    -- The document URL that was last successfully published here.
    -- Empty until a publish lands. This is what the UI shows as
    -- "recipients can reach this", and it is derived from a real
    -- upload rather than from configuration.
    last_published_url   TEXT    NOT NULL DEFAULT '',
    FOREIGN KEY (operator_id) REFERENCES operators(id) ON DELETE CASCADE,
    -- One endpoint per provider, enforced in the schema rather than
    -- only in code. The unit of independence is the provider: two R2
    -- buckets in one Cloudflare account fall over together, so allowing
    -- a second row at the same provider would let the operator inflate
    -- the number the "single point of censorship" warning is computed
    -- from without buying any diversity at all.
    UNIQUE (operator_id, kind)
);

CREATE INDEX IF NOT EXISTS idx_freshness_endpoints_operator
    ON freshness_endpoints(operator_id, position, id);

-- The mirror set that is actually inside the pack recipients are
-- holding right now, as a JSON array of "<provider>=<url>" strings.
-- Written at sign time from the endpoint list, read by the UI to answer
-- the only question that matters after a rotation: "will the files
-- people already have repair themselves, or do I have to walk them
-- over?" Empty means no — including for every pack signed before this
-- feature existed, which is the common case and must never be dressed
-- up as "probably fine".
--
-- It is stored SEPARATELY from freshness_endpoints on purpose.
-- Configuring a mirror today does not change a bundle somebody
-- imported last month, so the UI must never infer one from the other.
ALTER TABLE operators ADD COLUMN freshness_mirrors_in_pack TEXT NOT NULL DEFAULT '';

-- Where the signed .sbp itself will be downloadable. The freshness
-- document's entire payload is "the pack changed, fetch it here", so
-- without this there is nothing to point at and no document can be
-- built. Separate from the mirror URLs because the pack and the
-- document are different objects with different sizes and different
-- change rates.
ALTER TABLE operators ADD COLUMN freshness_pack_url TEXT NOT NULL DEFAULT '';

-- The highest freshness-document sequence this wizard has published for
-- this relay.
--
-- WHY A PERSISTED COUNTER AND NOT THE CLOCK. The sequence is the whole
-- of the anti-rollback story: a recipient remembers the highest value it
-- has accepted and refuses anything below it, forever, across restarts.
-- Deriving it from the publish timestamp works only while the clock
-- moves forward. An NTP correction after a dead RTC, a restored VM
-- snapshot, or publishing from a second laptop whose clock lags all
-- produce a LOWER sequence than recipients already hold — and then every
-- one of them rejects every document until wall time catches up, for
-- hours or days, while this app reports a successful publish. Nothing on
-- either side would notice. A counter that only increments has to have
-- an owner; this column is it, and the CLI's --min-sequence is the
-- enforcement.
ALTER TABLE operators ADD COLUMN freshness_last_sequence INTEGER NOT NULL DEFAULT 0;
