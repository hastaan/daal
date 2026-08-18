-- Wave 6 V014: record, per rotation, whether the pack it superseded
-- can still reach a live relay.
--
-- WHY THIS EXISTS. V003 shipped `Revert` as "the FRP-side undo button":
-- walk the history, take the most recent inactive row, flip it back to
-- active=1. That is an undo of the DATABASE. It is not an undo of the
-- ROTATION, and on this ladder the two are almost never the same thing:
--
--   * L1, L2, L4, L5 and L6 all run reprovision + provision — they
--     DELETE the server and build a new one. The previous pack names a
--     server id, an address and a set of credentials that no longer
--     exist anywhere.
--   * L3 releases the address the relay moved off, in the same call,
--     right after the history row is committed. The previous pack names
--     an address that has gone back to the provider's pool and may
--     already be routing to another customer's box.
--   * L7 and L8 re-point the CDN. The previous pack names a path or a
--     hostname the CDN no longer serves.
--
-- In every one of those cases re-activating the previous row hands the
-- operator a signed, valid, correctly-dated .sbp that connects to
-- nothing — and does it under a button labelled "revert", which is the
-- worst possible moment to be wrong. There is exactly one case on the
-- current ladder where the previous pack does still work: an L3 that
-- moved OFF the server's own primary address. A primary address cannot
-- be released, so the relay keeps answering on it forever, and the
-- previous pack keeps connecting.
--
-- That distinction is knowable at rotation time and unknowable
-- afterwards, so it is recorded here rather than guessed at later.
--
-- `prior_pack_still_serves` states a FACT about the world at the moment
-- the rotation committed: does the endpoint the superseded pack names
-- still answer? The revert policy is derived from it in application
-- code (OperatorDb::revert_to_previous_sbp), not encoded here.
--
-- `prior_pack_dead_reason` is the operator-facing sentence for the 0
-- case. It is stored rather than derived at read time because the
-- reason depends on what the rotation actually did, and rows written by
-- earlier versions genuinely do not know.
--
-- BACKFILL IS DELIBERATELY CONSERVATIVE. Every pre-V014 row gets 0.
-- Their levels are recoverable from rotation_kind, and for the five
-- destroy-and-rebuild rungs plus the two CDN rungs 0 is also the
-- CORRECT answer — but for `direct_l3` it is unknowable (nothing
-- recorded whether the prior address was a floating IP or the server's
-- primary), and a wrong 1 here is a dead pack presented as a working
-- one. So all legacy rows are marked not-revertible, with a reason that
-- says why rather than pretending to a finding.

ALTER TABLE signed_sbps
    ADD COLUMN prior_pack_still_serves INTEGER NOT NULL DEFAULT 0
        CHECK (prior_pack_still_serves IN (0, 1));

ALTER TABLE signed_sbps
    ADD COLUMN prior_pack_dead_reason TEXT NOT NULL DEFAULT '';

UPDATE signed_sbps
   SET prior_pack_dead_reason =
       'this rotation was recorded before the wizard tracked whether the previous pack still reaches a live relay, so it cannot prove that it does'
 WHERE prior_pack_dead_reason = '';
