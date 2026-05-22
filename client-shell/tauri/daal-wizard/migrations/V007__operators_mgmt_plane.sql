-- FRP-10 V007: V2 mgmt-plane fields on operators.
--
-- The V1.5 column shape (V001) doesn't know about the V2 in-box
-- daal-relay-mgmt service introduced in supplement §9.5.2. The
-- wizard needs two persisted V2 facts per deploy:
--
--   1. The random listening port the wizard chose at provision
--      time and stamped into cloud-init (in [10000, 65000]).
--      Helper-side mgmt-plane client uses it to construct the
--      box URL. Cloud-provider firewall opens (callerIP, port)
--      for ~5 min per L1/L2 op.
--
--   2. The SHA-256 fingerprint of the box's self-signed leaf
--      cert (lowercase hex, 64 chars). The wizard pins this
--      against rec.MgmtTLSFingerprint at every mgmt-plane call;
--      mismatch = ErrFingerprintMismatch (see
--      publisher/deploy/mgmt/client.go). FRP-10 invariant 26
--      requires the pin be set per-deploy; an empty value means
--      either a V1.5 record (predates V2) or a torn deploy and
--      the Helper falls back to the FRP-7 redeploy path.
--
-- Both columns are NOT NULL with safe defaults so the migration
-- works on legacy rows. New V2 deploys overwrite both at
-- provision time. The application MUST set both for any V2
-- record before issuing a V2 fast-path rotation; the empty
-- defaults are explicit "this is a V1.5 record" flags.

ALTER TABLE operators
    ADD COLUMN mgmt_port INTEGER NOT NULL DEFAULT 0;

ALTER TABLE operators
    ADD COLUMN mgmt_tls_fingerprint TEXT NOT NULL DEFAULT '';

-- Index for the wizard's audit screen lookup-by-fingerprint
-- query (operator_db::lookup_by_mgmt_fingerprint), used when the
-- bootstrap-window relay publishes a fingerprint and we need to
-- reconcile it against the operator we just provisioned.
CREATE INDEX idx_operators_mgmt_fingerprint
    ON operators (mgmt_tls_fingerprint)
    WHERE mgmt_tls_fingerprint <> '';
