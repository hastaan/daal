-- V019: the add-on ledger (docs/optional-addons-plan.md §5 X1,
-- specs/optional-addons-v1.md §2).
--
-- One row per optional add-on a relay has: a standby address, a way in
-- through Cloudflare, an update channel through Google. The row is what
-- the app knows it created, so it can say what bills, remove it, and
-- remove it with the relay. It is carried in the publisher backup: a
-- new phone must know what still bills and how to take it down.
--
--   kind     standby | cdn | google
--   state    building  setup started and has not finished (a killed app
--                      leaves this; the card offers removal)
--            ready     live, and in the signed pack
--            promoted  standby only: it became the relay's advertised
--                      address. Still billed; a new standby may be added
--            removing  removal started. The pack was already signed
--                      again without it; what is left may still bill
--   provider_ids_json  a JSON object of string -> string: the provider's
--                      ids of what Daal created (floating IP id, zone
--                      id, DNS record id, deployment id …). Never a
--                      secret, never a token.
--   monthly_cost_cents / cost_currency
--                      what the provider bills each month for it, as
--                      read when it was made (0 / '' = nothing Daal
--                      knows of, e.g. a domain the publisher bought)
--   secret_alias       the device-custody alias of the add-on's own
--                      secret (a Cloudflare token, a script write key),
--                      '' when it has none. The secret itself is never
--                      in this table.
--   detail_json        kind-specific, non-secret state (posture line,
--                      last test, mode …). Owned by the kind's module.
--
-- ON DELETE CASCADE: a relay that is forgotten takes its rows with it.
-- The cloud side is not touched by that; relay delete runs each kind's
-- teardown first (addons::before_relay_destroy).
CREATE TABLE relay_addons (
  id                 INTEGER PRIMARY KEY AUTOINCREMENT,
  operator_id        INTEGER NOT NULL REFERENCES operators(id) ON DELETE CASCADE,
  kind               TEXT    NOT NULL CHECK (kind IN ('standby','cdn','google')),
  state              TEXT    NOT NULL CHECK (state IN ('building','ready','promoted','removing')),
  provider_ids_json  TEXT    NOT NULL DEFAULT '{}',
  monthly_cost_cents INTEGER NOT NULL DEFAULT 0 CHECK (monthly_cost_cents >= 0),
  cost_currency      TEXT    NOT NULL DEFAULT '',
  secret_alias       TEXT    NOT NULL DEFAULT '',
  detail_json        TEXT    NOT NULL DEFAULT '{}',
  created_at_unix    INTEGER NOT NULL,
  updated_at_unix    INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_relay_addons_operator ON relay_addons (operator_id);

-- At most one add-on of each kind per relay that is not a promoted
-- standby: a promoted standby is the relay's address now, and the
-- publisher may rent a new standby beside it.
CREATE UNIQUE INDEX uniq_relay_addons_live_kind
    ON relay_addons (operator_id, kind) WHERE state <> 'promoted';
