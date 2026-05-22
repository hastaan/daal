-- FRP-8 V005: per-operator Cloudflare front records.
--
-- Each row is one cdn_fronted candidate the FRP has provisioned
-- under their Hetzner origin. The wizard's CDN screen 2.5
-- creates a row per provisioned front; rotation updates the
-- public_path + worker_route_id in place; re-verification of
-- §11.7 hardening updates the attestation columns.
--
-- Position B (phase doc §13 rule 5):
--
--   * Only public CDN metadata lives in this table. Cloudflare
--     API tokens NEVER appear here — they live in the OS
--     keystore under `daal.cloudflare.<operator_id>.token`.
--   * Origin CA private key + AOP client cert private key live
--     on disk at mode 0o600 under
--     <staging>/cdn/<operator_id>/{origin_ca.key,aop_client.pem};
--     this table only records the file paths.
--   * The signed §11.7 attestation (origin_ca_fingerprint +
--     aop_enabled + firewall_id + dns_only_present) is recorded
--     here verbatim and emitted into the per-candidate
--     `_cdn_attestation` sub-object at bundle bind time.

CREATE TABLE cdn_fronts (
    id                        INTEGER PRIMARY KEY AUTOINCREMENT,
    operator_id               INTEGER NOT NULL,
    hostname                  TEXT    NOT NULL,
    zone_id                   TEXT    NOT NULL,
    public_path               TEXT    NOT NULL,
    origin_path               TEXT    NOT NULL,
    worker_route_id           TEXT    NOT NULL,
    origin_ca_fingerprint     TEXT    NOT NULL,
    origin_ca_cert_path       TEXT    NOT NULL,
    origin_ca_priv_path       TEXT    NOT NULL,
    aop_client_cert_path      TEXT    NOT NULL,
    aop_enabled               INTEGER NOT NULL DEFAULT 0
                                  CHECK (aop_enabled IN (0, 1)),
    firewall_id               TEXT    NOT NULL,
    dns_only_present          INTEGER NOT NULL DEFAULT 0
                                  CHECK (dns_only_present IN (0, 1)),
    edge_ranges_fetched_unix  INTEGER NOT NULL DEFAULT 0,
    last_verified_unix        INTEGER NOT NULL DEFAULT 0,
    created_unix              INTEGER NOT NULL,
    FOREIGN KEY (operator_id) REFERENCES operators(id)
);

CREATE INDEX idx_cdn_fronts_operator
    ON cdn_fronts (operator_id);

CREATE INDEX idx_cdn_fronts_hostname
    ON cdn_fronts (hostname);

CREATE INDEX idx_cdn_fronts_last_verified
    ON cdn_fronts (last_verified_unix);

-- An operator can have multiple cdn_fronts (e.g. Hetzner
-- staging + Hetzner production), but each (operator_id,
-- hostname) pair is unique.
CREATE UNIQUE INDEX uniq_cdn_fronts_operator_hostname
    ON cdn_fronts (operator_id, hostname);
