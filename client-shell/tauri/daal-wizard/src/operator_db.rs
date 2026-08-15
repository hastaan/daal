//! SQLite-backed OperatorRecord persistence.
//!
//! The wizard writes a `pre-provision` row to `operators` after
//! screen 3 (publisher key generated or imported). FRP-4b later
//! flips the row to `provisioned`. FRP-7 may flip it to
//! `decommissioned`.
//!
//! Schema migrations live in `../migrations/V###__name.sql` and are
//! embedded into the binary via `include_str!`. A `schema_migrations`
//! table tracks which versions have been applied; the runner is
//! idempotent.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DbError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("operator not found: id={0}")]
    NotFound(i64),
}

pub type Result<T> = std::result::Result<T, DbError>;

#[derive(Debug)]
struct Migration {
    version: i64,
    name: &'static str,
    sql: &'static str,
}

const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "operators",
        sql: include_str!("../migrations/V001__operators.sql"),
    },
    Migration {
        version: 2,
        name: "signed_sbp",
        sql: include_str!("../migrations/V002__signed_sbp.sql"),
    },
    Migration {
        version: 3,
        name: "signed_sbps_history",
        sql: include_str!("../migrations/V003__signed_sbps_history.sql"),
    },
    Migration {
        version: 4,
        name: "subkeys",
        sql: include_str!("../migrations/V004__subkeys.sql"),
    },
    Migration {
        version: 5,
        name: "cdn_fronts",
        sql: include_str!("../migrations/V005__cdn_fronts.sql"),
    },
    Migration {
        version: 6,
        name: "signed_sbps_rotation_kind",
        sql: include_str!("../migrations/V006__signed_sbps_rotation_kind.sql"),
    },
    Migration {
        version: 7,
        name: "operators_mgmt_plane",
        sql: include_str!("../migrations/V007__operators_mgmt_plane.sql"),
    },
    Migration {
        version: 8,
        name: "cells",
        sql: include_str!("../migrations/V008__cells.sql"),
    },
    Migration {
        version: 9,
        name: "recipient_book",
        sql: include_str!("../migrations/V009__recipient_book.sql"),
    },
    Migration {
        version: 10,
        name: "recipient_identity",
        sql: include_str!("../migrations/V010__recipient_identity.sql"),
    },
    Migration {
        version: 11,
        name: "recipient_identity_history",
        sql: include_str!("../migrations/V011__recipient_identity_history.sql"),
    },
];

/// `OperatorRow` mirrors a row of the `operators` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorRow {
    pub id: i64,
    pub status: String,
    pub operator_record_json: String,
    pub publisher_pub_hex: String,
    pub publisher_priv_keystore_alias: String,
    pub cloud_provider: String,
    pub cloud_token_keystore_alias: String,
    pub created_at_unix: i64,
    pub last_provisioned_at_unix: Option<i64>,
    pub decommissioned_at_unix: Option<i64>,
    /// FRP-4b: hex(sha256(.sbp bytes)) of the latest successful bind.
    pub signed_sbp_sha256: Option<String>,
    /// FRP-4b: relay_pack_id of the latest successful bind.
    pub signed_sbp_relay_pack_id: Option<String>,
    /// FRP-4b: unix-seconds timestamp of the latest successful bind.
    pub signed_sbp_at_unix: Option<i64>,
    /// FRP-10 V007: V2 mgmt-plane port chosen at provision time
    /// in [10000, 65000]. Zero = V1.5 record (no mgmt service).
    /// FRP-10 invariant 27 forbids a fixed constant; the wizard
    /// chose this per-deploy.
    pub mgmt_port: i64,
    /// FRP-10 V007: SHA-256 hex of the box's self-signed leaf
    /// cert (lowercase, 64 chars). Empty = V1.5 record. The
    /// Helper-side mgmt-plane client pins against this on every
    /// L1/L2 call (FRP-10 invariant 26).
    pub mgmt_tls_fingerprint: String,
}

/// `SignedSbpRow` mirrors a row of the V003 `signed_sbps` history
/// table. `active = true` ⇒ the currently-published bundle.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SignedSbpRow {
    pub id: i64,
    pub operator_id: i64,
    pub signed_at_unix: i64,
    pub sbp_path: String,
    pub sbp_sha256: String,
    pub relay_pack_id: String,
    pub route_count: i64,
    pub rotation_reason: String,
    pub active: bool,
    /// FRP-9 V006: machine-readable rotation kind tag. Empty
    /// string for legacy rows whose kind cannot be inferred.
    /// One of: "", "direct_l1".."direct_l6", "cdn_path",
    /// "cdn_hostname", "cdn_origin".
    #[serde(default)]
    pub rotation_kind: String,
}

/// `SubkeyRow` mirrors a row of the V004 `subkeys` history
/// table (FRP-7.5). `active = true` ⇒ the sub-key currently used
/// by the wizard for re-signing. Cert / priv / pub paths point
/// at the on-disk artefacts produced by `publisher.Subkey`; the
/// priv bytes themselves are NEVER stored in the DB.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SubkeyRow {
    pub id: i64,
    pub operator_id: i64,
    pub subkey_fingerprint_hex: String,
    pub subkey_pub_path: String,
    pub subkey_priv_path: String,
    pub subkey_cert_path: String,
    pub cert_json: String,
    pub label: String,
    pub valid_from_unix: i64,
    pub valid_until_unix: i64,
    pub rotated_at_unix: i64,
    pub active: bool,
}

/// `CdnFrontRow` mirrors a row of the V005 `cdn_fronts` table
/// (FRP-8). One row per cdn_fronted candidate the FRP has
/// provisioned; the wizard's CDN screen 2.5 inserts rows here
/// and the binder reads them at bundle bind time to populate
/// the per-candidate `_cdn_attestation` sub-object.
///
/// Position B (phase doc §13 rule 5): only public CDN metadata
/// lives here. The Cloudflare API token is in the OS keystore
/// (`daal.cloudflare.<operator_id>.token`); Origin CA priv +
/// AOP client cert priv are on disk at mode 0o600 and only
/// their paths are recorded.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CdnFrontRow {
    pub id: i64,
    pub operator_id: i64,
    pub hostname: String,
    pub zone_id: String,
    pub public_path: String,
    pub origin_path: String,
    pub worker_route_id: String,
    pub origin_ca_fingerprint: String,
    pub origin_ca_cert_path: String,
    pub origin_ca_priv_path: String,
    pub aop_client_cert_path: String,
    pub aop_enabled: bool,
    pub firewall_id: String,
    pub dns_only_present: bool,
    pub edge_ranges_fetched_unix: i64,
    pub last_verified_unix: i64,
    pub created_unix: i64,
}

/// `OperatorDb` is a thin wrapper over a SQLite connection with a
/// fixed migration set. Open via [`OperatorDb::open_at`].
pub struct OperatorDb {
    conn: Mutex<Connection>,
}

impl OperatorDb {
    /// Open the database at `path` (created if missing) and apply
    /// any pending migrations. Idempotent.
    pub fn open_at(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", &"WAL")?;
        conn.pragma_update(None, "foreign_keys", &"ON")?;
        let db = OperatorDb {
            conn: Mutex::new(conn),
        };
        db.run_migrations()?;
        Ok(db)
    }

    /// Open an in-memory DB for tests.
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.pragma_update(None, "foreign_keys", &"ON")?;
        let db = OperatorDb {
            conn: Mutex::new(conn),
        };
        db.run_migrations()?;
        Ok(db)
    }

    fn run_migrations(&self) -> Result<()> {
        let mut conn = self.conn.lock().unwrap();
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name    TEXT NOT NULL,
                applied_at_unix INTEGER NOT NULL
            )",
            [],
        )?;
        for m in MIGRATIONS {
            let already: Option<i64> = conn
                .query_row(
                    "SELECT version FROM schema_migrations WHERE version = ?1",
                    params![m.version],
                    |row| row.get(0),
                )
                .optional()?;
            if already.is_some() {
                continue;
            }
            let tx = conn.transaction()?;
            tx.execute_batch(m.sql)?;
            tx.execute(
                "INSERT INTO schema_migrations (version, name, applied_at_unix)
                 VALUES (?1, ?2, strftime('%s','now'))",
                params![m.version, m.name],
            )?;
            tx.commit()?;
        }
        Ok(())
    }

    /// Insert a fresh `pre-provision` operator row. Returns the new
    /// row's primary key.
    pub fn insert_pre_provision(
        &self,
        operator_record_json: &str,
        publisher_pub_hex: &str,
        publisher_priv_keystore_alias: &str,
        cloud_provider: &str,
        cloud_token_keystore_alias: &str,
        created_at_unix: i64,
    ) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO operators (
                status, operator_record_json,
                publisher_pub_hex, publisher_priv_keystore_alias,
                cloud_provider, cloud_token_keystore_alias,
                created_at_unix
            ) VALUES ('pre-provision', ?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                operator_record_json,
                publisher_pub_hex,
                publisher_priv_keystore_alias,
                cloud_provider,
                cloud_token_keystore_alias,
                created_at_unix,
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Replace an operator's `operator_record_json` blob.
    pub fn update_record_json(&self, id: i64, json: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let n = conn.execute(
            "UPDATE operators SET operator_record_json = ?1 WHERE id = ?2",
            params![json, id],
        )?;
        if n == 0 {
            return Err(DbError::NotFound(id));
        }
        Ok(())
    }

    /// Update the cloud-token keystore alias on an operator row.
    pub fn update_token_alias(&self, id: i64, alias: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let n = conn.execute(
            "UPDATE operators SET cloud_token_keystore_alias = ?1 WHERE id = ?2",
            params![alias, id],
        )?;
        if n == 0 {
            return Err(DbError::NotFound(id));
        }
        Ok(())
    }

    /// Update the publisher pubkey hex + privkey keystore alias on
    /// an operator row.
    pub fn update_publisher_columns(&self, id: i64, pub_hex: &str, priv_alias: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let n = conn.execute(
            "UPDATE operators SET publisher_pub_hex = ?1, publisher_priv_keystore_alias = ?2
             WHERE id = ?3",
            params![pub_hex, priv_alias, id],
        )?;
        if n == 0 {
            return Err(DbError::NotFound(id));
        }
        Ok(())
    }

    /// Read one operator row.
    pub fn get(&self, id: i64) -> Result<OperatorRow> {
        let conn = self.conn.lock().unwrap();
        let row = conn
            .query_row(
                "SELECT id, status, operator_record_json, publisher_pub_hex,
                        publisher_priv_keystore_alias, cloud_provider,
                        cloud_token_keystore_alias, created_at_unix,
                        last_provisioned_at_unix, decommissioned_at_unix,
                        signed_sbp_sha256, signed_sbp_relay_pack_id, signed_sbp_at_unix,
                        mgmt_port, mgmt_tls_fingerprint
                 FROM operators WHERE id = ?1",
                params![id],
                row_to_operator,
            )
            .optional()?;
        row.ok_or(DbError::NotFound(id))
    }

    /// Enumerate all operators, ordered by creation time descending.
    pub fn list(&self) -> Result<Vec<OperatorRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, status, operator_record_json, publisher_pub_hex,
                    publisher_priv_keystore_alias, cloud_provider,
                    cloud_token_keystore_alias, created_at_unix,
                    last_provisioned_at_unix, decommissioned_at_unix,
                    signed_sbp_sha256, signed_sbp_relay_pack_id, signed_sbp_at_unix,
                    mgmt_port, mgmt_tls_fingerprint
             FROM operators ORDER BY created_at_unix DESC",
        )?;
        let rows: std::result::Result<Vec<_>, _> = stmt.query_map([], row_to_operator)?.collect();
        Ok(rows?)
    }

    /// FRP-10 V007: stamp the V2 mgmt-plane port + TLS
    /// fingerprint on an operator row. Called by the wizard
    /// after the bootstrap-window relay publishes the box's
    /// self-signed leaf-cert fingerprint. `port` must be in
    /// [10000, 65000] (FRP-10 invariant 27); `fingerprint` must
    /// be 64 hex chars (lowercase). Empty/zero values are
    /// rejected — that means the wizard tried to flip a V1.5
    /// record into a V2 record without the relay handshake.
    pub fn record_mgmt_plane(&self, id: i64, port: i64, fingerprint: &str) -> Result<()> {
        if !(10000..=65000).contains(&port) {
            return Err(DbError::Sqlite(rusqlite::Error::InvalidParameterName(
                format!("mgmt_port {port} outside [10000, 65000]"),
            )));
        }
        let fp = fingerprint.trim().to_lowercase();
        if fp.len() != 64 || !fp.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(DbError::Sqlite(rusqlite::Error::InvalidParameterName(
                format!("mgmt_tls_fingerprint not 64 hex chars: len={}", fp.len()),
            )));
        }
        let conn = self.conn.lock().unwrap();
        let n = conn.execute(
            "UPDATE operators SET mgmt_port = ?1,
                                  mgmt_tls_fingerprint = ?2
             WHERE id = ?3",
            params![port, fp, id],
        )?;
        if n == 0 {
            return Err(DbError::NotFound(id));
        }
        Ok(())
    }

    /// FRP-4b: flip an operator row to `provisioned` and record
    /// the cloud-side completion timestamp.
    pub fn mark_provisioned(&self, id: i64, provisioned_at_unix: i64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let n = conn.execute(
            "UPDATE operators SET status = 'provisioned',
                                  last_provisioned_at_unix = ?1
             WHERE id = ?2",
            params![provisioned_at_unix, id],
        )?;
        if n == 0 {
            return Err(DbError::NotFound(id));
        }
        Ok(())
    }

    /// FRP-4b: stamp the latest signed-SBP metadata on an operator row.
    pub fn record_signed_sbp(
        &self,
        id: i64,
        sbp_sha256: &str,
        relay_pack_id: &str,
        at_unix: i64,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let n = conn.execute(
            "UPDATE operators SET signed_sbp_sha256 = ?1,
                                  signed_sbp_relay_pack_id = ?2,
                                  signed_sbp_at_unix = ?3
             WHERE id = ?4",
            params![sbp_sha256, relay_pack_id, at_unix, id],
        )?;
        if n == 0 {
            return Err(DbError::NotFound(id));
        }
        Ok(())
    }

    /// FRP-7: record a rotated `.sbp` in one transaction. Flips
    /// any prior active row for `operator_id` to active=0,
    /// inserts the new row at active=1, and updates the V002
    /// projection columns on the operator. Returns the new row id.
    ///
    /// Invariant 24 ("rotation is reversible"): a rollback path
    /// is the inverse of this op via [`revert_to_previous_sbp`].
    #[allow(clippy::too_many_arguments)]
    pub fn record_rotated_sbp(
        &self,
        operator_id: i64,
        signed_at_unix: i64,
        sbp_path: &str,
        sbp_sha256: &str,
        relay_pack_id: &str,
        route_count: i64,
        rotation_reason: &str,
    ) -> Result<i64> {
        let mut conn = self.conn.lock().unwrap();
        // Pre-check: operator must exist; return a clean NotFound
        // rather than letting the FK constraint surface as a
        // ConstraintViolation deep inside the tx.
        let exists: Option<i64> = conn
            .query_row(
                "SELECT id FROM operators WHERE id = ?1",
                params![operator_id],
                |r| r.get(0),
            )
            .optional()?;
        if exists.is_none() {
            return Err(DbError::NotFound(operator_id));
        }
        let tx = conn.transaction()?;
        // 1. mark prior active rows inactive
        tx.execute(
            "UPDATE signed_sbps SET active = 0
             WHERE operator_id = ?1 AND active = 1",
            params![operator_id],
        )?;
        // 2. insert the fresh row at active=1, deriving the V006
        // rotation_kind tag from the free-form reason text.
        let rotation_kind = derive_rotation_kind(rotation_reason);
        tx.execute(
            "INSERT INTO signed_sbps (
                operator_id, signed_at_unix, sbp_path, sbp_sha256,
                relay_pack_id, route_count, rotation_reason, active,
                rotation_kind
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8)",
            params![
                operator_id,
                signed_at_unix,
                sbp_path,
                sbp_sha256,
                relay_pack_id,
                route_count,
                rotation_reason,
                rotation_kind,
            ],
        )?;
        let new_id = tx.last_insert_rowid();
        // 3. project onto operators.signed_sbp_* fast-read columns
        let n = tx.execute(
            "UPDATE operators SET signed_sbp_sha256 = ?1,
                                  signed_sbp_relay_pack_id = ?2,
                                  signed_sbp_at_unix = ?3
             WHERE id = ?4",
            params![sbp_sha256, relay_pack_id, signed_at_unix, operator_id],
        )?;
        if n == 0 {
            return Err(DbError::NotFound(operator_id));
        }
        tx.commit()?;
        Ok(new_id)
    }

    /// FRP-9: record an origin-only rotation in the history
    /// table. Per supplement §14.4 the RelayPack is NOT re-signed;
    /// this method writes an `active=0` audit-only row so the
    /// wizard's history view distinguishes L9_CDN_ORIGIN from the
    /// re-signed L1–L8 rotations. The currently-active row is
    /// left active.
    ///
    /// Returns the new history row id.
    pub fn record_origin_only_rotation(
        &self,
        operator_id: i64,
        signed_at_unix: i64,
        rotation_reason: &str,
    ) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        // Pre-check: operator must exist.
        let exists: Option<i64> = conn
            .query_row(
                "SELECT id FROM operators WHERE id = ?1",
                params![operator_id],
                |r| r.get(0),
            )
            .optional()?;
        if exists.is_none() {
            return Err(DbError::NotFound(operator_id));
        }
        // Read the currently-active SBP so the audit row carries
        // a self-consistent (sbp_path, sha) pair pointing at the
        // bundle the family is still using.
        let prior: Option<(String, String, String, i64)> = conn
            .query_row(
                "SELECT sbp_path, sbp_sha256, relay_pack_id, route_count
                 FROM signed_sbps
                 WHERE operator_id = ?1 AND active = 1",
                params![operator_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        let (sbp_path, sbp_sha256, relay_pack_id, route_count) =
            prior.unwrap_or_else(|| (String::new(), String::new(), String::new(), 0));
        let rotation_kind = derive_rotation_kind(rotation_reason);
        conn.execute(
            "INSERT INTO signed_sbps (
                operator_id, signed_at_unix, sbp_path, sbp_sha256,
                relay_pack_id, route_count, rotation_reason, active,
                rotation_kind
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8)",
            params![
                operator_id,
                signed_at_unix,
                sbp_path,
                sbp_sha256,
                relay_pack_id,
                route_count,
                rotation_reason,
                rotation_kind,
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// FRP-7: revert to the most recent inactive history row for
    /// the given operator. Flips that row to active=1, marks the
    /// current active=0, and updates the V002 projection columns
    /// inside one transaction. Errors if no inactive history row
    /// exists.
    pub fn revert_to_previous_sbp(&self, operator_id: i64) -> Result<SignedSbpRow> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        // Pick the most recent inactive row (largest signed_at_unix).
        let target = tx
            .query_row(
                "SELECT id, operator_id, signed_at_unix, sbp_path, sbp_sha256,
                        relay_pack_id, route_count, rotation_reason, active,
                        rotation_kind
                 FROM signed_sbps
                 WHERE operator_id = ?1 AND active = 0
                 ORDER BY signed_at_unix DESC, id DESC LIMIT 1",
                params![operator_id],
                row_to_signed_sbp,
            )
            .optional()?;
        let target = target.ok_or(DbError::NotFound(operator_id))?;
        // Mark the current active row inactive.
        tx.execute(
            "UPDATE signed_sbps SET active = 0
             WHERE operator_id = ?1 AND active = 1",
            params![operator_id],
        )?;
        // Flip the target row to active.
        tx.execute(
            "UPDATE signed_sbps SET active = 1 WHERE id = ?1",
            params![target.id],
        )?;
        // Update the V002 projection.
        tx.execute(
            "UPDATE operators SET signed_sbp_sha256 = ?1,
                                  signed_sbp_relay_pack_id = ?2,
                                  signed_sbp_at_unix = ?3
             WHERE id = ?4",
            params![
                target.sbp_sha256,
                target.relay_pack_id,
                target.signed_at_unix,
                operator_id,
            ],
        )?;
        tx.commit()?;
        let mut restored = target;
        restored.active = true;
        Ok(restored)
    }

    /// FRP-7: enumerate the rotation history for an operator,
    /// most recent first.
    pub fn list_signed_sbps_history(&self, operator_id: i64) -> Result<Vec<SignedSbpRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, operator_id, signed_at_unix, sbp_path, sbp_sha256,
                    relay_pack_id, route_count, rotation_reason, active,
                    rotation_kind
             FROM signed_sbps
             WHERE operator_id = ?1
             ORDER BY signed_at_unix DESC, id DESC",
        )?;
        let rows: std::result::Result<Vec<_>, _> = stmt
            .query_map(params![operator_id], row_to_signed_sbp)?
            .collect();
        Ok(rows?)
    }

    /// FRP-7: read the currently-active history row, if any. Used
    /// by the wizard to render the latest QR canvas after a
    /// rotation or revert.
    pub fn active_signed_sbp(&self, operator_id: i64) -> Result<Option<SignedSbpRow>> {
        let conn = self.conn.lock().unwrap();
        let row = conn
            .query_row(
                "SELECT id, operator_id, signed_at_unix, sbp_path, sbp_sha256,
                        relay_pack_id, route_count, rotation_reason, active,
                        rotation_kind
                 FROM signed_sbps
                 WHERE operator_id = ?1 AND active = 1
                 LIMIT 1",
                params![operator_id],
                row_to_signed_sbp,
            )
            .optional()?;
        Ok(row)
    }

    // ---- V004 subkey rotation history (FRP-7.5) -------------------

    /// FRP-7.5: insert a fresh sub-key as the active sub-key and
    /// flip the prior active row (if any) to inactive, atomically.
    /// Returns the new row id.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_subkey_rotation(
        &self,
        operator_id: i64,
        subkey_fingerprint_hex: &str,
        subkey_pub_path: &str,
        subkey_priv_path: &str,
        subkey_cert_path: &str,
        cert_json: &str,
        label: &str,
        valid_from_unix: i64,
        valid_until_unix: i64,
        rotated_at_unix: i64,
    ) -> Result<i64> {
        let mut conn = self.conn.lock().unwrap();
        let exists: Option<i64> = conn
            .query_row(
                "SELECT id FROM operators WHERE id = ?1",
                params![operator_id],
                |row| row.get(0),
            )
            .optional()?;
        if exists.is_none() {
            return Err(DbError::NotFound(operator_id));
        }
        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE subkeys SET active = 0
             WHERE operator_id = ?1 AND active = 1",
            params![operator_id],
        )?;
        tx.execute(
            "INSERT INTO subkeys (
                operator_id, subkey_fingerprint_hex,
                subkey_pub_path, subkey_priv_path, subkey_cert_path,
                cert_json, label, valid_from_unix, valid_until_unix,
                rotated_at_unix, active
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 1)",
            params![
                operator_id,
                subkey_fingerprint_hex,
                subkey_pub_path,
                subkey_priv_path,
                subkey_cert_path,
                cert_json,
                label,
                valid_from_unix,
                valid_until_unix,
                rotated_at_unix,
            ],
        )?;
        let new_id = tx.last_insert_rowid();
        tx.commit()?;
        Ok(new_id)
    }

    /// FRP-7.5: read the currently-active sub-key, if any.
    pub fn active_subkey(&self, operator_id: i64) -> Result<Option<SubkeyRow>> {
        let conn = self.conn.lock().unwrap();
        let row = conn
            .query_row(
                "SELECT id, operator_id, subkey_fingerprint_hex,
                        subkey_pub_path, subkey_priv_path, subkey_cert_path,
                        cert_json, label, valid_from_unix, valid_until_unix,
                        rotated_at_unix, active
                 FROM subkeys
                 WHERE operator_id = ?1 AND active = 1
                 LIMIT 1",
                params![operator_id],
                row_to_subkey,
            )
            .optional()?;
        Ok(row)
    }

    /// FRP-7.5: enumerate the sub-key history for an operator,
    /// most recent first.
    pub fn list_subkey_history(&self, operator_id: i64) -> Result<Vec<SubkeyRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, operator_id, subkey_fingerprint_hex,
                    subkey_pub_path, subkey_priv_path, subkey_cert_path,
                    cert_json, label, valid_from_unix, valid_until_unix,
                    rotated_at_unix, active
             FROM subkeys
             WHERE operator_id = ?1
             ORDER BY rotated_at_unix DESC, id DESC",
        )?;
        let rows: std::result::Result<Vec<_>, _> = stmt
            .query_map(params![operator_id], row_to_subkey)?
            .collect();
        Ok(rows?)
    }

    /// FRP-8: insert (or replace via uniq_cdn_fronts_operator_hostname)
    /// a CDN front row. The wizard's CDN screen 2.5 calls this
    /// after `provider.ProvisionFront` returns successfully.
    #[allow(clippy::too_many_arguments)]
    pub fn upsert_cdn_front(&self, row: &CdnFrontRow) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO cdn_fronts (
                operator_id, hostname, zone_id,
                public_path, origin_path, worker_route_id,
                origin_ca_fingerprint, origin_ca_cert_path,
                origin_ca_priv_path, aop_client_cert_path,
                aop_enabled, firewall_id, dns_only_present,
                edge_ranges_fetched_unix, last_verified_unix,
                created_unix
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                       ?12, ?13, ?14, ?15, ?16)
             ON CONFLICT (operator_id, hostname) DO UPDATE SET
                zone_id = excluded.zone_id,
                public_path = excluded.public_path,
                origin_path = excluded.origin_path,
                worker_route_id = excluded.worker_route_id,
                origin_ca_fingerprint = excluded.origin_ca_fingerprint,
                origin_ca_cert_path = excluded.origin_ca_cert_path,
                origin_ca_priv_path = excluded.origin_ca_priv_path,
                aop_client_cert_path = excluded.aop_client_cert_path,
                aop_enabled = excluded.aop_enabled,
                firewall_id = excluded.firewall_id,
                dns_only_present = excluded.dns_only_present,
                edge_ranges_fetched_unix = excluded.edge_ranges_fetched_unix,
                last_verified_unix = excluded.last_verified_unix",
            params![
                row.operator_id,
                row.hostname,
                row.zone_id,
                row.public_path,
                row.origin_path,
                row.worker_route_id,
                row.origin_ca_fingerprint,
                row.origin_ca_cert_path,
                row.origin_ca_priv_path,
                row.aop_client_cert_path,
                row.aop_enabled as i64,
                row.firewall_id,
                row.dns_only_present as i64,
                row.edge_ranges_fetched_unix,
                row.last_verified_unix,
                row.created_unix,
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// FRP-8: list CDN front rows for an operator, most recent
    /// first.
    pub fn list_cdn_fronts(&self, operator_id: i64) -> Result<Vec<CdnFrontRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, operator_id, hostname, zone_id,
                    public_path, origin_path, worker_route_id,
                    origin_ca_fingerprint, origin_ca_cert_path,
                    origin_ca_priv_path, aop_client_cert_path,
                    aop_enabled, firewall_id, dns_only_present,
                    edge_ranges_fetched_unix, last_verified_unix,
                    created_unix
             FROM cdn_fronts
             WHERE operator_id = ?1
             ORDER BY created_unix DESC, id DESC",
        )?;
        let rows: std::result::Result<Vec<_>, _> = stmt
            .query_map(params![operator_id], row_to_cdn_front)?
            .collect();
        Ok(rows?)
    }

    /// FRP-9: fetch one row by id. Used by the FRP-9 rotate
    /// commands that need the current zone_id / hostname /
    /// public_path / origin_path before driving the live CDN API.
    pub fn get_cdn_front(&self, front_id: i64) -> Result<CdnFrontRow> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, operator_id, hostname, zone_id,
                    public_path, origin_path, worker_route_id,
                    origin_ca_fingerprint, origin_ca_cert_path,
                    origin_ca_priv_path, aop_client_cert_path,
                    aop_enabled, firewall_id, dns_only_present,
                    edge_ranges_fetched_unix, last_verified_unix,
                    created_unix
             FROM cdn_fronts WHERE id = ?1",
        )?;
        let mut rows = stmt.query_map(params![front_id], row_to_cdn_front)?;
        if let Some(row) = rows.next() {
            return Ok(row?);
        }
        Err(DbError::NotFound(front_id))
    }

    /// FRP-9: update mutable rotation fields on an existing row.
    /// Used by `rotate_cdn_path` (path + worker_route_id mutate) and
    /// `rotate_cdn_hostname` (hostname + zone_id + worker_route_id
    /// mutate). Origin-only rotation does NOT mutate any of these
    /// fields and should not call this method.
    pub fn update_cdn_front_rotation(
        &self,
        front_id: i64,
        hostname: &str,
        zone_id: &str,
        public_path: &str,
        worker_route_id: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let n = conn.execute(
            "UPDATE cdn_fronts
             SET hostname = ?2,
                 zone_id = ?3,
                 public_path = ?4,
                 worker_route_id = ?5
             WHERE id = ?1",
            params![front_id, hostname, zone_id, public_path, worker_route_id],
        )?;
        if n == 0 {
            return Err(DbError::NotFound(front_id));
        }
        Ok(())
    }

    /// FRP-8: update verification timestamps after a successful
    /// "Verify CDN posture" pass.
    pub fn touch_cdn_front_verification(
        &self,
        front_id: i64,
        edge_ranges_fetched_unix: i64,
        last_verified_unix: i64,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let n = conn.execute(
            "UPDATE cdn_fronts
             SET edge_ranges_fetched_unix = ?2,
                 last_verified_unix = ?3
             WHERE id = ?1",
            params![front_id, edge_ranges_fetched_unix, last_verified_unix],
        )?;
        if n == 0 {
            return Err(DbError::NotFound(front_id));
        }
        Ok(())
    }

    /// Delete an operator row. The caller is responsible for
    /// erasing any associated keystore aliases first.
    pub fn delete(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let n = conn.execute("DELETE FROM operators WHERE id = ?1", params![id])?;
        if n == 0 {
            return Err(DbError::NotFound(id));
        }
        Ok(())
    }

    /// Append a PIN attempt outcome.
    pub fn record_pin_attempt(&self, attempt_at_unix: i64, success: bool) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO pin_attempts (attempt_at_unix, success) VALUES (?1, ?2)",
            params![attempt_at_unix, success as i64],
        )?;
        Ok(())
    }

    /// Count failed PIN attempts strictly newer than `since_unix`.
    pub fn count_recent_failed_pins(&self, since_unix: i64) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM pin_attempts
             WHERE attempt_at_unix > ?1 AND success = 0",
            params![since_unix],
            |r| r.get(0),
        )?;
        Ok(n)
    }

    /// Default DB location: `~/.config/daal/operators.db` on Linux,
    /// equivalent on other OSes.
    pub fn default_path() -> PathBuf {
        if let Some(d) = dirs_next::config_dir() {
            return d.join("daal").join("operators.db");
        }
        std::env::temp_dir().join("daal").join("operators.db")
    }

    /// FRP-11 V008: insert a new cell row. The caller has already
    /// verified the membership doc's M-of-N admin quorum (the
    /// engine-side `bundle.VerifyCellMembershipQuorum` is the
    /// authoritative check; the wizard re-verifies on every
    /// status read). `is_admin = 1` ⇒ this operator holds an
    /// admin keypair and `admin_priv_alias` MUST be non-empty.
    pub fn insert_cell(&self, cell: &CellRow) -> Result<i64> {
        if cell.cell_id.is_empty() {
            return Err(DbError::Sqlite(rusqlite::Error::InvalidParameterName(
                "cell_id is empty".into(),
            )));
        }
        if cell.is_admin && cell.admin_priv_alias.is_empty() {
            return Err(DbError::Sqlite(rusqlite::Error::InvalidParameterName(
                "is_admin=1 requires admin_priv_alias".into(),
            )));
        }
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO cells (cell_id, membership_doc_json, delegation_doc_json,
                                bundle_signer_priv_alias, directory_url, trust_label,
                                joined_at_unix, is_admin, admin_priv_alias)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                cell.cell_id,
                cell.membership_doc_json,
                cell.delegation_doc_json,
                cell.bundle_signer_priv_alias,
                cell.directory_url,
                cell.trust_label,
                cell.joined_at_unix,
                if cell.is_admin { 1 } else { 0 },
                cell.admin_priv_alias,
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// FRP-11 V008: lookup a cell by its public cell_id string.
    pub fn lookup_cell(&self, cell_id: &str) -> Result<Option<CellRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, cell_id, membership_doc_json, delegation_doc_json,
                    bundle_signer_priv_alias, directory_url, trust_label,
                    joined_at_unix, is_admin, admin_priv_alias
             FROM cells WHERE cell_id = ?1",
        )?;
        let mut rows = stmt.query(params![cell_id])?;
        if let Some(r) = rows.next()? {
            return Ok(Some(CellRow {
                id: r.get(0)?,
                cell_id: r.get(1)?,
                membership_doc_json: r.get(2)?,
                delegation_doc_json: r.get(3)?,
                bundle_signer_priv_alias: r.get(4)?,
                directory_url: r.get(5)?,
                trust_label: r.get(6)?,
                joined_at_unix: r.get(7)?,
                is_admin: r.get::<_, i64>(8)? != 0,
                admin_priv_alias: r.get(9)?,
            }));
        }
        Ok(None)
    }

    /// FRP-11 V008: list all cells the operator has joined.
    pub fn list_cells(&self) -> Result<Vec<CellRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, cell_id, membership_doc_json, delegation_doc_json,
                    bundle_signer_priv_alias, directory_url, trust_label,
                    joined_at_unix, is_admin, admin_priv_alias
             FROM cells ORDER BY joined_at_unix DESC",
        )?;
        let rows: std::result::Result<Vec<_>, _> = stmt
            .query_map([], |r| {
                Ok(CellRow {
                    id: r.get(0)?,
                    cell_id: r.get(1)?,
                    membership_doc_json: r.get(2)?,
                    delegation_doc_json: r.get(3)?,
                    bundle_signer_priv_alias: r.get(4)?,
                    directory_url: r.get(5)?,
                    trust_label: r.get(6)?,
                    joined_at_unix: r.get(7)?,
                    is_admin: r.get::<_, i64>(8)? != 0,
                    admin_priv_alias: r.get(9)?,
                })
            })?
            .collect();
        Ok(rows?)
    }

    /// FRP-11 V008: link an OperatorRecord row to a cell row
    /// (operator_cell_membership join). Idempotent.
    pub fn link_operator_to_cell(&self, operator_id: i64, cell_id: i64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO operator_cell_membership (operator_id, cell_id)
             VALUES (?1, ?2)",
            params![operator_id, cell_id],
        )?;
        Ok(())
    }

    /// FRP-11 V008: append a cell-internal revocation observed
    /// locally. The caller has parsed the revocation doc against
    /// the cell's membership (admin-quorum-signed); this row is
    /// a local audit trail for the wizard's revocation panel.
    pub fn record_cell_revocation(
        &self,
        cell_id: i64,
        revoked_publisher_fp_hex: &str,
        revocation_doc_json: &str,
        observed_at_unix: i64,
    ) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO cell_revocations
                 (cell_id, revoked_publisher_fp_hex, revocation_doc_json, observed_at_unix)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                cell_id,
                revoked_publisher_fp_hex,
                revocation_doc_json,
                observed_at_unix
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    // -----------------------------------------------------------------
    // FRP-14: per-operator recipient book.
    // -----------------------------------------------------------------

    /// Reserves the next `r<n>` name for the supplied operator. The
    /// counter is monotonic across the operator's lifetime — even
    /// revoked recipients keep their index burned.
    pub fn reserve_recipient_name(&self, operator_id: i64) -> Result<String> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO recipient_name_counters (operator_id, next_index)
                 VALUES (?1, 1)
                 ON CONFLICT(operator_id) DO NOTHING",
            params![operator_id],
        )?;
        let next: i64 = conn.query_row(
            "SELECT next_index FROM recipient_name_counters WHERE operator_id = ?1",
            params![operator_id],
            |r| r.get(0),
        )?;
        conn.execute(
            "UPDATE recipient_name_counters SET next_index = next_index + 1 WHERE operator_id = ?1",
            params![operator_id],
        )?;
        Ok(format!("r{}", next))
    }

    /// Inserts a recipient row. Returns the new row id.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_recipient(&self, row: NewRecipientRow) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO recipients
                 (operator_id, name, display_name, address_str, pubkey_x25519_hex,
                  fingerprint_hex, vless_uuid, reality_short_id, hy2_password,
                  naive_password, ws_path, provisioned_at_unix)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                row.operator_id,
                row.name,
                row.display_name,
                row.address_str,
                row.pubkey_x25519_hex,
                row.fingerprint_hex,
                row.vless_uuid,
                row.reality_short_id,
                row.hy2_password,
                row.naive_password,
                row.ws_path,
                row.provisioned_at_unix,
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Marks a recipient as revoked.
    pub fn mark_recipient_revoked(&self, recipient_id: i64, revoked_at_unix: i64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE recipients SET revoked_at_unix = ?2 WHERE id = ?1",
            params![recipient_id, revoked_at_unix],
        )?;
        Ok(())
    }

    /// Hard-deletes a recipient row from the local roster. Unlike
    /// [`mark_recipient_revoked`] (which keeps the row for audit and
    /// greys it out in the UI), this removes the row entirely — used
    /// by the "remove from list" affordance once the recipient has
    /// already been revoked on the box. Scoped by `operator_id` so a
    /// stale id from another operator can never delete the wrong row.
    /// The per-operator name counter is deliberately NOT rewound: a
    /// burned `r<n>` index is never reissued (see V009's
    /// `recipient_name_counters` note). Returns
    /// [`DbError::NotFound`] when no matching row exists.
    pub fn delete_recipient(&self, operator_id: i64, recipient_id: i64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let affected = conn.execute(
            "DELETE FROM recipients WHERE id = ?1 AND operator_id = ?2",
            params![recipient_id, operator_id],
        )?;
        if affected == 0 {
            return Err(DbError::NotFound(recipient_id));
        }
        Ok(())
    }

    /// Lists all (live + revoked) recipients for an operator,
    /// most-recently-provisioned first.
    pub fn list_recipients(&self, operator_id: i64) -> Result<Vec<RecipientRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, operator_id, name, display_name, address_str, pubkey_x25519_hex,
                    fingerprint_hex, vless_uuid, reality_short_id, hy2_password,
                    naive_password, ws_path, provisioned_at_unix, revoked_at_unix
             FROM recipients WHERE operator_id = ?1 ORDER BY provisioned_at_unix DESC",
        )?;
        let rows = stmt.query_map(params![operator_id], |r| {
            Ok(RecipientRow {
                id: r.get(0)?,
                operator_id: r.get(1)?,
                name: r.get(2)?,
                display_name: r.get(3)?,
                address_str: r.get(4)?,
                pubkey_x25519_hex: r.get(5)?,
                fingerprint_hex: r.get(6)?,
                vless_uuid: r.get(7)?,
                reality_short_id: r.get(8)?,
                hy2_password: r.get(9)?,
                naive_password: r.get(10)?,
                ws_path: r.get(11)?,
                provisioned_at_unix: r.get(12)?,
                revoked_at_unix: r.get(13)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Returns the recipient row for (operator_id, recipient_id), if any.
    pub fn get_recipient(&self, operator_id: i64, recipient_id: i64) -> Result<Option<RecipientRow>> {
        let conn = self.conn.lock().unwrap();
        let row = conn
            .query_row(
                "SELECT id, operator_id, name, display_name, address_str, pubkey_x25519_hex,
                        fingerprint_hex, vless_uuid, reality_short_id, hy2_password,
                        naive_password, ws_path, provisioned_at_unix, revoked_at_unix
                 FROM recipients WHERE id = ?1 AND operator_id = ?2",
                params![recipient_id, operator_id],
                |r| {
                    Ok(RecipientRow {
                        id: r.get(0)?,
                        operator_id: r.get(1)?,
                        name: r.get(2)?,
                        display_name: r.get(3)?,
                        address_str: r.get(4)?,
                        pubkey_x25519_hex: r.get(5)?,
                        fingerprint_hex: r.get(6)?,
                        vless_uuid: r.get(7)?,
                        reality_short_id: r.get(8)?,
                        hy2_password: r.get(9)?,
                        naive_password: r.get(10)?,
                        ws_path: r.get(11)?,
                        provisioned_at_unix: r.get(12)?,
                        revoked_at_unix: r.get(13)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    /// Returns the count of live (non-revoked) recipients on an
    /// operator. Used to enforce the 128 cap client-side before
    /// hitting the box.
    pub fn count_live_recipients(&self, operator_id: i64) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        let c: i64 = conn.query_row(
            "SELECT COUNT(*) FROM recipients WHERE operator_id = ?1 AND revoked_at_unix = 0",
            params![operator_id],
            |r| r.get(0),
        )?;
        Ok(c)
    }

    // ---- FRP-14 Layer 3c: recipient-side identity (V010) ----

    /// Insert the singleton recipient_identity row. v1 forbids
    /// rewriting an existing row, so this uses INSERT … ON
    /// CONFLICT DO NOTHING and returns Ok(false) when the row
    /// already exists (Ok(true) on fresh insert).
    pub fn upsert_recipient_identity(
        &self,
        pubkey: &[u8; 32],
        address: &str,
        fingerprint_hex: &str,
        created_at_unix: i64,
    ) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let n = conn.execute(
            "INSERT INTO recipient_identity
                 (id, pubkey_x25519, keystore_alias, address_str,
                  fingerprint_hex, created_at_unix)
             VALUES (1, ?1, 'recipient_priv_x25519', ?2, ?3, ?4)
             ON CONFLICT(id) DO NOTHING",
            params![pubkey.as_slice(), address, fingerprint_hex, created_at_unix],
        )?;
        Ok(n == 1)
    }

    /// Read the singleton recipient_identity row, if any.
    pub fn get_recipient_identity(&self) -> Result<Option<RecipientIdentityRow>> {
        let conn = self.conn.lock().unwrap();
        let row = conn
            .query_row(
                "SELECT pubkey_x25519, keystore_alias, address_str,
                        fingerprint_hex, created_at_unix
                 FROM recipient_identity WHERE id = 1",
                [],
                |r| {
                    let pub_blob: Vec<u8> = r.get(0)?;
                    Ok(RecipientIdentityRow {
                        pubkey_x25519: pub_blob,
                        keystore_alias: r.get(1)?,
                        address_str: r.get(2)?,
                        fingerprint_hex: r.get(3)?,
                        created_at_unix: r.get(4)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    // --- Device Custody B4 V011 ------------------------------------

    /// Replace `recipient_identity` (id=1) in one transaction:
    ///   1. demote the current row to `recipient_identity_history`
    ///      under the supplied `retire_alias` (e.g.
    ///      `recipient_priv_x25519.v2`) at `retired_at_unix`.
    ///   2. overwrite id=1 with the new pub/address/fingerprint
    ///      (alias stays `recipient_priv_x25519`).
    ///
    /// Returns the version number assigned to the demoted row.
    ///
    /// Caller (recipient_identity::rotate) is responsible for
    /// re-wrapping the OLD priv-key under `retire_alias` BEFORE
    /// calling this so the history alias resolves on disk; and
    /// for re-wrapping the NEW priv-key under
    /// `recipient_priv_x25519` AFTER the swap.
    pub fn rotate_recipient_identity(
        &self,
        retire_alias: &str,
        new_pub: &[u8; 32],
        new_address: &str,
        new_fingerprint_hex: &str,
        new_created_at_unix: i64,
        retired_at_unix: i64,
    ) -> Result<i64> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        // Current row must exist.
        let cur: (Vec<u8>, String, String, i64) = tx.query_row(
            "SELECT pubkey_x25519, address_str, fingerprint_hex, created_at_unix
             FROM recipient_identity WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )?;
        // Next version: max(history.version)+1, or 1 if empty.
        let next_version: i64 = tx
            .query_row(
                "SELECT COALESCE(MAX(version), 0) + 1 FROM recipient_identity_history",
                [],
                |r| r.get(0),
            )
            .unwrap_or(1);
        tx.execute(
            "INSERT INTO recipient_identity_history
                 (version, pubkey_x25519, keystore_alias, address_str,
                  fingerprint_hex, created_at_unix, retired_at_unix)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                next_version,
                cur.0,
                retire_alias,
                cur.1,
                cur.2,
                cur.3,
                retired_at_unix
            ],
        )?;
        tx.execute(
            "UPDATE recipient_identity
             SET pubkey_x25519 = ?1, address_str = ?2,
                 fingerprint_hex = ?3, created_at_unix = ?4
             WHERE id = 1",
            params![
                new_pub.as_slice(),
                new_address,
                new_fingerprint_hex,
                new_created_at_unix
            ],
        )?;
        tx.commit()?;
        Ok(next_version)
    }

    /// List the rotation history (most-recent retirement first).
    pub fn list_recipient_identity_history(
        &self,
    ) -> Result<Vec<RecipientIdentityHistoryRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, version, pubkey_x25519, keystore_alias,
                    address_str, fingerprint_hex, created_at_unix,
                    retired_at_unix
             FROM recipient_identity_history
             ORDER BY retired_at_unix DESC, id DESC",
        )?;
        let rows = stmt
            .query_map([], |r| {
                let pub_blob: Vec<u8> = r.get(2)?;
                Ok(RecipientIdentityHistoryRow {
                    id: r.get(0)?,
                    version: r.get(1)?,
                    pubkey_x25519_hex: hex_encode(&pub_blob),
                    keystore_alias: r.get(3)?,
                    address_str: r.get(4)?,
                    fingerprint_hex: r.get(5)?,
                    created_at_unix: r.get(6)?,
                    retired_at_unix: r.get(7)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Append one row to the custody_events audit log. `kind` is
    /// one of: created, rotated, locked, unlocked, panic_wipe.
    pub fn insert_custody_event(
        &self,
        at_unix: i64,
        kind: &str,
        level: &str,
        detail_json: &str,
    ) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO custody_events (at_unix, kind, level, detail_json)
             VALUES (?1, ?2, ?3, ?4)",
            params![at_unix, kind, level, detail_json],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// List recent custody events, newest first. `limit` caps the
    /// row count (use 200 for the UI default).
    pub fn list_custody_events(&self, limit: i64) -> Result<Vec<CustodyEventRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, at_unix, kind, level, detail_json
             FROM custody_events ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt
            .query_map(params![limit], |r| {
                Ok(CustodyEventRow {
                    id: r.get(0)?,
                    at_unix: r.get(1)?,
                    kind: r.get(2)?,
                    level: r.get(3)?,
                    detail_json: r.get(4)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Device Custody B5: enumerate every non-empty `keystore`
    /// alias referenced anywhere in the wizard DB. Used by
    /// `panic_wipe` to call `Keystore::forget` against the OS
    /// keyring before deleting the DB itself.
    ///
    /// The publisher-key alias and the cloud-token alias on the
    /// `operators` table cover the bulk of secrets. Cells (V008)
    /// reference a bundle-signer priv alias and (when admin) an
    /// admin priv alias.
    pub fn list_all_keystore_aliases(&self) -> Result<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut aliases: Vec<String> = Vec::new();
        let mut push = |s: String| {
            if !s.is_empty() {
                aliases.push(s);
            }
        };
        // operators
        let mut stmt = conn.prepare(
            "SELECT publisher_priv_keystore_alias, cloud_token_keystore_alias
             FROM operators",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;
        for row in rows {
            let (a, b) = row?;
            push(a);
            push(b);
        }
        // cells (V008)
        if let Ok(mut stmt) = conn.prepare(
            "SELECT bundle_signer_priv_alias, admin_priv_alias FROM cells",
        ) {
            if let Ok(rows) = stmt.query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            }) {
                for row in rows.flatten() {
                    push(row.0);
                    push(row.1);
                }
            }
        }
        Ok(aliases)
    }
}

/// Lowercase hex encoder shared by history-row mirrors.
fn hex_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{:02x}", byte));
    }
    s
}

/// FRP-14: input for `OperatorDb::insert_recipient`.
#[derive(Debug, Clone)]
pub struct NewRecipientRow {
    pub operator_id: i64,
    pub name: String,
    pub display_name: String,
    pub address_str: String,
    pub pubkey_x25519_hex: String,
    pub fingerprint_hex: String,
    pub vless_uuid: String,
    pub reality_short_id: String,
    pub hy2_password: String,
    pub naive_password: String,
    pub ws_path: String,
    pub provisioned_at_unix: i64,
}

/// FRP-14: recipient row as returned by `OperatorDb::list_recipients`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientRow {
    pub id: i64,
    pub operator_id: i64,
    pub name: String,
    pub display_name: String,
    pub address_str: String,
    pub pubkey_x25519_hex: String,
    pub fingerprint_hex: String,
    pub vless_uuid: String,
    pub reality_short_id: String,
    pub hy2_password: String,
    pub naive_password: String,
    pub ws_path: String,
    pub provisioned_at_unix: i64,
    pub revoked_at_unix: i64,
}

/// FRP-14 Layer 3c V010: singleton recipient identity row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientIdentityRow {
    pub pubkey_x25519: Vec<u8>,
    pub keystore_alias: String,
    pub address_str: String,
    pub fingerprint_hex: String,
    pub created_at_unix: i64,
}

/// Device Custody B4 V011: one row per rotated-out recipient
/// identity, oldest first. Allows `.sbpx` import to grace-decrypt
/// using any prior priv-key.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RecipientIdentityHistoryRow {
    pub id: i64,
    pub version: i64,
    pub pubkey_x25519_hex: String,
    pub keystore_alias: String,
    pub address_str: String,
    pub fingerprint_hex: String,
    pub created_at_unix: i64,
    pub retired_at_unix: i64,
}

/// Device Custody B4 V011: an append-only audit event for the
/// Settings → Custody → History view.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CustodyEventRow {
    pub id: i64,
    pub at_unix: i64,
    pub kind: String,
    pub level: String,
    pub detail_json: String,
}

/// FRP-11 V008: cell row mirror for the wizard UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CellRow {
    pub id: i64,
    pub cell_id: String,
    pub membership_doc_json: String,
    pub delegation_doc_json: String,
    pub bundle_signer_priv_alias: String,
    pub directory_url: String,
    pub trust_label: String,
    pub joined_at_unix: i64,
    pub is_admin: bool,
    pub admin_priv_alias: String,
}

/// V006: derive the structured rotation_kind tag from the
/// free-form rotation_reason text the caller supplied. Recognises
/// the "L<n>[_<TAG>] | <reason>" prefix produced by
/// rotate_execute and maps each level to its tag. Returns ""
/// when the reason text doesn't start with a recognized prefix
/// (e.g. provisioning rows in tests).
fn derive_rotation_kind(reason: &str) -> &'static str {
    if reason.starts_with("L1 |") {
        "direct_l1"
    } else if reason.starts_with("L2 |") {
        "direct_l2"
    } else if reason.starts_with("L3 |") {
        "direct_l3"
    } else if reason.starts_with("L4 |") {
        "direct_l4"
    } else if reason.starts_with("L5 |") {
        "direct_l5"
    } else if reason.starts_with("L6 |") {
        "direct_l6"
    } else if reason.starts_with("L7_CDN_PATH |") {
        "cdn_path"
    } else if reason.starts_with("L8_CDN_HOSTNAME |") {
        "cdn_hostname"
    } else if reason.starts_with("L9_CDN_ORIGIN |") {
        "cdn_origin"
    } else {
        ""
    }
}

fn row_to_signed_sbp(row: &rusqlite::Row<'_>) -> rusqlite::Result<SignedSbpRow> {
    let active_int: i64 = row.get(8)?;
    // V006 added `rotation_kind` as the 10th column. Older
    // queries that don't request it pass through the
    // OptionalExtension fallback ("" empty string).
    let rotation_kind: String = row.get::<_, Option<String>>(9)?.unwrap_or_default();
    Ok(SignedSbpRow {
        id: row.get(0)?,
        operator_id: row.get(1)?,
        signed_at_unix: row.get(2)?,
        sbp_path: row.get(3)?,
        sbp_sha256: row.get(4)?,
        relay_pack_id: row.get(5)?,
        route_count: row.get(6)?,
        rotation_reason: row.get(7)?,
        active: active_int == 1,
        rotation_kind,
    })
}

fn row_to_subkey(row: &rusqlite::Row<'_>) -> rusqlite::Result<SubkeyRow> {
    let active_int: i64 = row.get(11)?;
    Ok(SubkeyRow {
        id: row.get(0)?,
        operator_id: row.get(1)?,
        subkey_fingerprint_hex: row.get(2)?,
        subkey_pub_path: row.get(3)?,
        subkey_priv_path: row.get(4)?,
        subkey_cert_path: row.get(5)?,
        cert_json: row.get(6)?,
        label: row.get(7)?,
        valid_from_unix: row.get(8)?,
        valid_until_unix: row.get(9)?,
        rotated_at_unix: row.get(10)?,
        active: active_int == 1,
    })
}

fn row_to_cdn_front(row: &rusqlite::Row<'_>) -> rusqlite::Result<CdnFrontRow> {
    let aop_int: i64 = row.get(11)?;
    let dns_only_int: i64 = row.get(13)?;
    Ok(CdnFrontRow {
        id: row.get(0)?,
        operator_id: row.get(1)?,
        hostname: row.get(2)?,
        zone_id: row.get(3)?,
        public_path: row.get(4)?,
        origin_path: row.get(5)?,
        worker_route_id: row.get(6)?,
        origin_ca_fingerprint: row.get(7)?,
        origin_ca_cert_path: row.get(8)?,
        origin_ca_priv_path: row.get(9)?,
        aop_client_cert_path: row.get(10)?,
        aop_enabled: aop_int == 1,
        firewall_id: row.get(12)?,
        dns_only_present: dns_only_int == 1,
        edge_ranges_fetched_unix: row.get(14)?,
        last_verified_unix: row.get(15)?,
        created_unix: row.get(16)?,
    })
}

fn row_to_operator(row: &rusqlite::Row<'_>) -> rusqlite::Result<OperatorRow> {
    Ok(OperatorRow {
        id: row.get(0)?,
        status: row.get(1)?,
        operator_record_json: row.get(2)?,
        publisher_pub_hex: row.get(3)?,
        publisher_priv_keystore_alias: row.get(4)?,
        cloud_provider: row.get(5)?,
        cloud_token_keystore_alias: row.get(6)?,
        created_at_unix: row.get(7)?,
        last_provisioned_at_unix: row.get(8)?,
        decommissioned_at_unix: row.get(9)?,
        signed_sbp_sha256: row.get(10)?,
        signed_sbp_relay_pack_id: row.get(11)?,
        signed_sbp_at_unix: row.get(12)?,
        mgmt_port: row.get(13)?,
        mgmt_tls_fingerprint: row.get(14)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_db_applies_v001() {
        let db = OperatorDb::open_in_memory().unwrap();
        let v: i64 = db
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT version FROM schema_migrations WHERE version = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(v, 1);
    }

    #[test]
    fn migrations_are_idempotent() {
        let db = OperatorDb::open_in_memory().unwrap();
        db.run_migrations().unwrap();
        let count: i64 = db
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE version = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "V001 must record exactly once");
    }

    #[test]
    fn insert_get_list_delete_round_trip() {
        let db = OperatorDb::open_in_memory().unwrap();
        let id = db
            .insert_pre_provision(
                r#"{"provider":"hetzner"}"#,
                "deadbeef",
                "daal.publisher.1.priv",
                "hetzner",
                "daal.cloud.1.token",
                1_700_000_000,
            )
            .unwrap();
        let row = db.get(id).unwrap();
        assert_eq!(row.status, "pre-provision");
        assert_eq!(row.publisher_pub_hex, "deadbeef");
        let all = db.list().unwrap();
        assert_eq!(all.len(), 1);
        db.delete(id).unwrap();
        assert!(db.list().unwrap().is_empty());
    }

    #[test]
    fn delete_unknown_id_errors() {
        let db = OperatorDb::open_in_memory().unwrap();
        let err = db.delete(999).unwrap_err();
        match err {
            DbError::NotFound(999) => (),
            e => panic!("unexpected error: {e:?}"),
        }
    }

    #[test]
    fn pin_attempt_count() {
        let db = OperatorDb::open_in_memory().unwrap();
        db.record_pin_attempt(100, false).unwrap();
        db.record_pin_attempt(200, false).unwrap();
        db.record_pin_attempt(300, true).unwrap();
        assert_eq!(db.count_recent_failed_pins(50).unwrap(), 2);
        assert_eq!(db.count_recent_failed_pins(150).unwrap(), 1);
        assert_eq!(db.count_recent_failed_pins(250).unwrap(), 0);
    }

    #[test]
    fn fresh_db_applies_v002() {
        let db = OperatorDb::open_in_memory().unwrap();
        let v: i64 = db
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT version FROM schema_migrations WHERE version = 2",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(v, 2);
    }

    #[test]
    fn record_signed_sbp_round_trip() {
        let db = OperatorDb::open_in_memory().unwrap();
        let id = db
            .insert_pre_provision("{}", "ab", "k1", "hetzner", "t1", 1)
            .unwrap();
        let row = db.get(id).unwrap();
        assert!(row.signed_sbp_sha256.is_none());
        db.record_signed_sbp(id, "abc123", "rp-xx", 9_999).unwrap();
        let row2 = db.get(id).unwrap();
        assert_eq!(row2.signed_sbp_sha256.as_deref(), Some("abc123"));
        assert_eq!(row2.signed_sbp_relay_pack_id.as_deref(), Some("rp-xx"));
        assert_eq!(row2.signed_sbp_at_unix, Some(9_999));
    }

    #[test]
    fn mark_provisioned_flips_status() {
        let db = OperatorDb::open_in_memory().unwrap();
        let id = db
            .insert_pre_provision("{}", "ab", "k1", "hetzner", "t1", 1)
            .unwrap();
        db.mark_provisioned(id, 1234).unwrap();
        let row = db.get(id).unwrap();
        assert_eq!(row.status, "provisioned");
        assert_eq!(row.last_provisioned_at_unix, Some(1234));
    }

    // ---- V003 signed_sbps history ---------------------------------

    #[test]
    fn fresh_db_applies_v003() {
        let db = OperatorDb::open_in_memory().unwrap();
        let v: i64 = db
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT version FROM schema_migrations WHERE version = 3",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(v, 3);
    }

    #[test]
    fn v003_migrations_are_idempotent() {
        let db = OperatorDb::open_in_memory().unwrap();
        db.run_migrations().unwrap(); // idempotent re-run
        let count: i64 = db
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE version = 3",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "V003 must record exactly once");
    }

    #[test]
    fn record_rotated_sbp_inserts_active_and_flips_prior() {
        let db = OperatorDb::open_in_memory().unwrap();
        let op = db
            .insert_pre_provision("{}", "ab", "k1", "hetzner", "t1", 1)
            .unwrap();
        // First rotation
        let row1_id = db
            .record_rotated_sbp(op, 1_000, "/staging/a.sbp", "sha-a", "rp-a", 3, "L1 first")
            .unwrap();
        // Second rotation flips the first row to inactive
        let row2_id = db
            .record_rotated_sbp(op, 2_000, "/staging/b.sbp", "sha-b", "rp-b", 4, "L3 swap")
            .unwrap();
        assert_ne!(row1_id, row2_id);

        let history = db.list_signed_sbps_history(op).unwrap();
        assert_eq!(history.len(), 2, "history rows = {}", history.len());
        // Most-recent first
        assert_eq!(history[0].id, row2_id);
        assert!(history[0].active);
        assert_eq!(history[1].id, row1_id);
        assert!(!history[1].active);

        // Active getter
        let active = db.active_signed_sbp(op).unwrap().unwrap();
        assert_eq!(active.id, row2_id);
        assert_eq!(active.relay_pack_id, "rp-b");

        // Projection columns updated
        let opr = db.get(op).unwrap();
        assert_eq!(opr.signed_sbp_sha256.as_deref(), Some("sha-b"));
        assert_eq!(opr.signed_sbp_relay_pack_id.as_deref(), Some("rp-b"));
        assert_eq!(opr.signed_sbp_at_unix, Some(2_000));
    }

    #[test]
    fn unique_active_index_enforces_one_active_per_operator() {
        let db = OperatorDb::open_in_memory().unwrap();
        let op = db
            .insert_pre_provision("{}", "ab", "k1", "hetzner", "t1", 1)
            .unwrap();
        db.record_rotated_sbp(op, 1, "/a.sbp", "sa", "rp-a", 1, "")
            .unwrap();
        // Manually trying to insert a second active row outside the
        // transactional helper must fail the partial-unique-index.
        let conn = db.conn.lock().unwrap();
        let result = conn.execute(
            "INSERT INTO signed_sbps (
                operator_id, signed_at_unix, sbp_path, sbp_sha256,
                relay_pack_id, route_count, rotation_reason, active
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1)",
            params![op, 2, "/b.sbp", "sb", "rp-b", 1, ""],
        );
        assert!(result.is_err(), "expected unique-index violation");
    }

    #[test]
    fn revert_restores_prior_sbp() {
        let db = OperatorDb::open_in_memory().unwrap();
        let op = db
            .insert_pre_provision("{}", "ab", "k1", "hetzner", "t1", 1)
            .unwrap();
        db.record_rotated_sbp(op, 1_000, "/a.sbp", "sa", "rp-a", 1, "L1")
            .unwrap();
        db.record_rotated_sbp(op, 2_000, "/b.sbp", "sb", "rp-b", 1, "L3")
            .unwrap();
        // Revert: the prior row "rp-a" should be active again
        let restored = db.revert_to_previous_sbp(op).unwrap();
        assert_eq!(restored.relay_pack_id, "rp-a");
        assert!(restored.active);
        // Active projection should match
        let active = db.active_signed_sbp(op).unwrap().unwrap();
        assert_eq!(active.relay_pack_id, "rp-a");
        let opr = db.get(op).unwrap();
        assert_eq!(opr.signed_sbp_relay_pack_id.as_deref(), Some("rp-a"));
        assert_eq!(opr.signed_sbp_at_unix, Some(1_000));
    }

    #[test]
    fn revert_with_no_history_errors() {
        let db = OperatorDb::open_in_memory().unwrap();
        let op = db
            .insert_pre_provision("{}", "ab", "k1", "hetzner", "t1", 1)
            .unwrap();
        // Single rotation: no prior inactive row to restore
        db.record_rotated_sbp(op, 1_000, "/a.sbp", "sa", "rp-a", 1, "")
            .unwrap();
        let err = db.revert_to_previous_sbp(op).unwrap_err();
        match err {
            DbError::NotFound(id) if id == op => (),
            e => panic!("unexpected error: {e:?}"),
        }
    }

    #[test]
    fn record_rotated_sbp_unknown_operator_rolls_back() {
        let db = OperatorDb::open_in_memory().unwrap();
        let err = db
            .record_rotated_sbp(999, 1, "/a.sbp", "sa", "rp-a", 1, "")
            .unwrap_err();
        match err {
            DbError::NotFound(999) => (),
            e => panic!("unexpected error: {e:?}"),
        }
        // No half-applied rows should be visible.
        let conn = db.conn.lock().unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM signed_sbps", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0, "rolled-back tx must leave 0 rows");
    }

    #[test]
    fn open_at_path_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("operators.db");
        let db = OperatorDb::open_at(&path).unwrap();
        let _ = db
            .insert_pre_provision("{}", "ab", "k1", "hetzner", "t1", 1)
            .unwrap();
        drop(db);
        let db2 = OperatorDb::open_at(&path).unwrap();
        assert_eq!(db2.list().unwrap().len(), 1);
    }

    // ---- V004 subkey rotation history (FRP-7.5) -------------------

    #[test]
    fn fresh_db_applies_v004() {
        let db = OperatorDb::open_in_memory().unwrap();
        let v: i64 = db
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT version FROM schema_migrations WHERE version = 4",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(v, 4);
    }

    #[test]
    fn insert_subkey_rotation_flips_prior_active() {
        let db = OperatorDb::open_in_memory().unwrap();
        let op = db
            .insert_pre_provision("{}", "ab", "k1", "hetzner", "t1", 1)
            .unwrap();
        let id1 = db
            .insert_subkey_rotation(
                op,
                "fp1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "/sub/1.pub",
                "/sub/1.priv",
                "/sub/1.cert",
                "{\"v\":1}",
                "first",
                100,
                100 + 90 * 86400,
                100,
            )
            .unwrap();
        let id2 = db
            .insert_subkey_rotation(
                op,
                "fp2bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "/sub/2.pub",
                "/sub/2.priv",
                "/sub/2.cert",
                "{\"v\":1}",
                "second",
                200,
                200 + 90 * 86400,
                200,
            )
            .unwrap();
        assert_ne!(id1, id2);
        let history = db.list_subkey_history(op).unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].id, id2);
        assert!(history[0].active);
        assert_eq!(history[1].id, id1);
        assert!(!history[1].active);
        let active = db.active_subkey(op).unwrap().unwrap();
        assert_eq!(active.id, id2);
        assert_eq!(active.label, "second");
    }

    #[test]
    fn unique_active_subkey_per_operator() {
        let db = OperatorDb::open_in_memory().unwrap();
        let op = db
            .insert_pre_provision("{}", "ab", "k1", "hetzner", "t1", 1)
            .unwrap();
        // Direct INSERT bypassing the helper; should violate the
        // partial-unique-index after the second active=1 row.
        let mut conn = db.conn.lock().unwrap();
        let tx = conn.transaction().unwrap();
        tx.execute(
            "INSERT INTO subkeys (operator_id, subkey_fingerprint_hex,
                subkey_pub_path, subkey_priv_path, subkey_cert_path,
                cert_json, label, valid_from_unix, valid_until_unix,
                rotated_at_unix, active)
             VALUES (?1, 'fp1', 'p1', 'pr1', 'c1', '{}', 'first', 1, 2, 1, 1)",
            params![op],
        )
        .unwrap();
        let res = tx.execute(
            "INSERT INTO subkeys (operator_id, subkey_fingerprint_hex,
                subkey_pub_path, subkey_priv_path, subkey_cert_path,
                cert_json, label, valid_from_unix, valid_until_unix,
                rotated_at_unix, active)
             VALUES (?1, 'fp2', 'p2', 'pr2', 'c2', '{}', 'second', 1, 2, 2, 1)",
            params![op],
        );
        assert!(
            res.is_err(),
            "second active=1 row must violate unique index"
        );
    }

    /// FRP-9 V006: derive_rotation_kind maps every rotation level
    /// produced by rotate_execute to its structured tag. Unknown
    /// prefixes (legacy / non-rotation rows) yield empty string.
    #[test]
    fn derive_rotation_kind_maps_all_levels() {
        assert_eq!(derive_rotation_kind("L1 | foo"), "direct_l1");
        assert_eq!(derive_rotation_kind("L2 | sni blocked"), "direct_l2");
        assert_eq!(derive_rotation_kind("L3 | ip burned"), "direct_l3");
        assert_eq!(derive_rotation_kind("L4 | dc burned"), "direct_l4");
        assert_eq!(derive_rotation_kind("L5 | family burned"), "direct_l5");
        assert_eq!(derive_rotation_kind("L6 | toolbox swap"), "direct_l6");
        assert_eq!(
            derive_rotation_kind("L7_CDN_PATH | path burned"),
            "cdn_path"
        );
        assert_eq!(
            derive_rotation_kind("L8_CDN_HOSTNAME | host blocked"),
            "cdn_hostname"
        );
        assert_eq!(
            derive_rotation_kind("L9_CDN_ORIGIN | rebuilt vps"),
            "cdn_origin"
        );
        // Unknown / legacy / blank → empty.
        assert_eq!(derive_rotation_kind(""), "");
        assert_eq!(derive_rotation_kind("rebuilt vps"), "");
    }

    /// FRP-9 V006: record_rotated_sbp persists the structured
    /// rotation_kind alongside the free-form rotation_reason, and
    /// list_signed_sbps_history returns it. The audit-only L9
    /// path written via record_origin_only_rotation also carries
    /// the cdn_origin tag.
    #[test]
    fn record_rotated_sbp_persists_rotation_kind() {
        let db = OperatorDb::open_in_memory().unwrap();
        let op = db
            .insert_pre_provision("{}", "ab", "k1", "hetzner", "t1", 1)
            .unwrap();
        db.record_rotated_sbp(op, 1_000, "/a.sbp", "sa", "rp-a", 1, "L7_CDN_PATH | path")
            .unwrap();
        db.record_origin_only_rotation(op, 2_000, "L9_CDN_ORIGIN | rebuilt")
            .unwrap();
        let history = db.list_signed_sbps_history(op).unwrap();
        assert_eq!(history.len(), 2);
        // Most-recent first → L9 audit row, then L7.
        let l9 = history.iter().find(|r| !r.active).unwrap();
        let l7 = history.iter().find(|r| r.active).unwrap();
        assert_eq!(l9.rotation_kind, "cdn_origin");
        assert_eq!(l7.rotation_kind, "cdn_path");
    }

    // ---- FRP-10 V007 mgmt-plane fields ----------------------------

    #[test]
    fn fresh_db_applies_v007() {
        let db = OperatorDb::open_in_memory().unwrap();
        let v: i64 = db
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT version FROM schema_migrations WHERE version = 7",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(v, 7);
    }

    #[test]
    fn v007_legacy_rows_default_to_v15_markers() {
        let db = OperatorDb::open_in_memory().unwrap();
        let id = db
            .insert_pre_provision("{}", "ab", "k1", "hetzner", "t1", 1)
            .unwrap();
        let row = db.get(id).unwrap();
        assert_eq!(
            row.mgmt_port, 0,
            "V1.5 record must default to mgmt_port = 0"
        );
        assert_eq!(
            row.mgmt_tls_fingerprint, "",
            "V1.5 record must default to empty fingerprint"
        );
    }

    #[test]
    fn record_mgmt_plane_round_trips() {
        let db = OperatorDb::open_in_memory().unwrap();
        let id = db
            .insert_pre_provision("{}", "ab", "k1", "hetzner", "t1", 1)
            .unwrap();
        let fp = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        db.record_mgmt_plane(id, 42424, fp).unwrap();
        let row = db.get(id).unwrap();
        assert_eq!(row.mgmt_port, 42424);
        assert_eq!(row.mgmt_tls_fingerprint, fp);
    }

    #[test]
    fn record_mgmt_plane_lowercases_fingerprint() {
        let db = OperatorDb::open_in_memory().unwrap();
        let id = db
            .insert_pre_provision("{}", "ab", "k1", "hetzner", "t1", 1)
            .unwrap();
        let fp_upper = "ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890";
        db.record_mgmt_plane(id, 12345, fp_upper).unwrap();
        let row = db.get(id).unwrap();
        assert_eq!(row.mgmt_tls_fingerprint, fp_upper.to_lowercase());
    }

    #[test]
    fn record_mgmt_plane_rejects_bad_port() {
        let db = OperatorDb::open_in_memory().unwrap();
        let id = db
            .insert_pre_provision("{}", "ab", "k1", "hetzner", "t1", 1)
            .unwrap();
        let fp = "0".repeat(64);
        for &p in &[0i64, 1, 80, 443, 9999, 65001, 70000] {
            assert!(
                db.record_mgmt_plane(id, p, &fp).is_err(),
                "port {p} must be rejected"
            );
        }
    }

    #[test]
    fn record_mgmt_plane_rejects_bad_fingerprint() {
        let db = OperatorDb::open_in_memory().unwrap();
        let id = db
            .insert_pre_provision("{}", "ab", "k1", "hetzner", "t1", 1)
            .unwrap();
        // wrong length
        assert!(db.record_mgmt_plane(id, 42424, "deadbeef").is_err());
        // contains non-hex
        let bad = "z".repeat(64);
        assert!(db.record_mgmt_plane(id, 42424, &bad).is_err());
        // empty
        assert!(db.record_mgmt_plane(id, 42424, "").is_err());
    }

    #[test]
    fn record_mgmt_plane_unknown_id_errors() {
        let db = OperatorDb::open_in_memory().unwrap();
        let fp = "0".repeat(64);
        let err = db.record_mgmt_plane(999, 42424, &fp).unwrap_err();
        match err {
            DbError::NotFound(999) => (),
            e => panic!("unexpected error: {e:?}"),
        }
    }

    // ---- FRP-11 V008 cells ---------------------------------------

    fn sample_cell(suffix: &str) -> CellRow {
        CellRow {
            id: 0, // assigned by insert
            cell_id: format!("cell-{suffix}"),
            membership_doc_json: "{\"cell_id\":\"cell-1\"}".to_string(),
            delegation_doc_json: "{\"cell_id\":\"cell-1\"}".to_string(),
            bundle_signer_priv_alias: "cell-1.bundle-signer".to_string(),
            directory_url: "https://r2.example.com/cell/cell-1/directory.json".to_string(),
            trust_label: "".to_string(),
            joined_at_unix: 1735689600,
            is_admin: false,
            admin_priv_alias: "".to_string(),
        }
    }

    #[test]
    fn v008_migration_creates_cells_table() {
        let db = OperatorDb::open_in_memory().unwrap();
        let count: i64 = db
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE version = 8",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn insert_and_lookup_cell_round_trip() {
        let db = OperatorDb::open_in_memory().unwrap();
        let id = db.insert_cell(&sample_cell("a")).unwrap();
        let fetched = db.lookup_cell("cell-a").unwrap().unwrap();
        assert_eq!(fetched.id, id);
        assert_eq!(fetched.cell_id, "cell-a");
        assert_eq!(fetched.is_admin, false);
    }

    #[test]
    fn lookup_cell_missing_returns_none() {
        let db = OperatorDb::open_in_memory().unwrap();
        assert!(db.lookup_cell("nonexistent").unwrap().is_none());
    }

    #[test]
    fn insert_cell_rejects_empty_cell_id() {
        let db = OperatorDb::open_in_memory().unwrap();
        let mut c = sample_cell("a");
        c.cell_id = "".to_string();
        assert!(db.insert_cell(&c).is_err());
    }

    #[test]
    fn insert_cell_rejects_admin_without_priv_alias() {
        let db = OperatorDb::open_in_memory().unwrap();
        let mut c = sample_cell("a");
        c.is_admin = true;
        c.admin_priv_alias = "".to_string();
        assert!(db.insert_cell(&c).is_err());
    }

    #[test]
    fn insert_cell_admin_with_priv_alias_succeeds() {
        let db = OperatorDb::open_in_memory().unwrap();
        let mut c = sample_cell("a");
        c.is_admin = true;
        c.admin_priv_alias = "cell-a.admin-2".to_string();
        let id = db.insert_cell(&c).unwrap();
        let fetched = db.lookup_cell("cell-a").unwrap().unwrap();
        assert_eq!(fetched.id, id);
        assert!(fetched.is_admin);
        assert_eq!(fetched.admin_priv_alias, "cell-a.admin-2");
    }

    #[test]
    fn insert_cell_unique_cell_id_enforced() {
        let db = OperatorDb::open_in_memory().unwrap();
        db.insert_cell(&sample_cell("dup")).unwrap();
        assert!(db.insert_cell(&sample_cell("dup")).is_err());
    }

    #[test]
    fn list_cells_orders_by_joined_at_desc() {
        let db = OperatorDb::open_in_memory().unwrap();
        let mut a = sample_cell("a");
        a.joined_at_unix = 1000;
        let mut b = sample_cell("b");
        b.joined_at_unix = 2000;
        db.insert_cell(&a).unwrap();
        db.insert_cell(&b).unwrap();
        let list = db.list_cells().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].cell_id, "cell-b");
        assert_eq!(list[1].cell_id, "cell-a");
    }

    #[test]
    fn record_cell_revocation_round_trips() {
        let db = OperatorDb::open_in_memory().unwrap();
        let cell_id = db.insert_cell(&sample_cell("rev")).unwrap();
        let rev_id = db
            .record_cell_revocation(cell_id, "9f3a1c2b", "{\"sig\":\"...\"}", 1735690000)
            .unwrap();
        assert!(rev_id > 0);
        let count: i64 = db
            .conn
            .lock()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM cell_revocations", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    // -----------------------------------------------------------------
    // FRP-14 V009 recipient_book tests
    // -----------------------------------------------------------------

    fn sample_recipient(op_id: i64, idx: i64) -> NewRecipientRow {
        // Vary pubkey + fingerprint per idx so the UNIQUE
        // (operator_id, pubkey_x25519_hex) constraint isn't tripped
        // when fixtures share an operator.
        let byte = (idx & 0xff) as u8;
        let pk = format!("{:02x}", byte).repeat(32);
        let fp = format!("{:02x}", byte ^ 0xa5).repeat(32);
        NewRecipientRow {
            operator_id: op_id,
            name: format!("r{}", idx),
            display_name: format!("Recipient {}", idx),
            address_str: format!("daal1mock{}", idx),
            pubkey_x25519_hex: pk,
            fingerprint_hex: fp,
            vless_uuid: "00000000-0000-0000-0000-000000000000".to_string(),
            reality_short_id: "deadbeef".to_string(),
            hy2_password: "hy2pw".to_string(),
            naive_password: "naivepw".to_string(),
            ws_path: format!("/r{}/cafebabe", idx),
            provisioned_at_unix: 1_700_000_000 + idx,
        }
    }

    #[test]
    fn v009_migration_creates_recipients_tables() {
        let db = OperatorDb::open_in_memory().unwrap();
        let count: i64 = db
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE version = 9",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn reserve_recipient_name_is_monotonic_per_operator() {
        let db = OperatorDb::open_in_memory().unwrap();
        let op_id = db
            .insert_pre_provision("{}", "ab", "k1", "hetzner", "t1", 1)
            .unwrap();
        assert_eq!(db.reserve_recipient_name(op_id).unwrap(), "r1");
        assert_eq!(db.reserve_recipient_name(op_id).unwrap(), "r2");
        assert_eq!(db.reserve_recipient_name(op_id).unwrap(), "r3");
    }

    #[test]
    fn reserve_recipient_name_is_per_operator() {
        let db = OperatorDb::open_in_memory().unwrap();
        let op_a = db
            .insert_pre_provision("{}", "aa", "k1", "hetzner", "t1", 1)
            .unwrap();
        let op_b = db
            .insert_pre_provision("{}", "bb", "k2", "hetzner", "t2", 2)
            .unwrap();
        assert_eq!(db.reserve_recipient_name(op_a).unwrap(), "r1");
        assert_eq!(db.reserve_recipient_name(op_b).unwrap(), "r1");
        assert_eq!(db.reserve_recipient_name(op_a).unwrap(), "r2");
    }

    #[test]
    fn insert_and_list_recipient_round_trip() {
        let db = OperatorDb::open_in_memory().unwrap();
        let op_id = db
            .insert_pre_provision("{}", "ab", "k1", "hetzner", "t1", 1)
            .unwrap();
        let r_id = db.insert_recipient(sample_recipient(op_id, 1)).unwrap();
        assert!(r_id > 0);

        let list = db.list_recipients(op_id).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "r1");
        assert_eq!(list[0].display_name, "Recipient 1");
        assert_eq!(list[0].revoked_at_unix, 0);

        let fetched = db.get_recipient(op_id, r_id).unwrap().unwrap();
        assert_eq!(fetched.address_str, "daal1mock1");
    }

    #[test]
    fn unique_name_per_operator_enforced() {
        let db = OperatorDb::open_in_memory().unwrap();
        let op_id = db
            .insert_pre_provision("{}", "ab", "k1", "hetzner", "t1", 1)
            .unwrap();
        db.insert_recipient(sample_recipient(op_id, 1)).unwrap();
        // Reuse same name on the same operator.
        let dup = NewRecipientRow {
            pubkey_x25519_hex: "11".repeat(32),
            ..sample_recipient(op_id, 1)
        };
        assert!(db.insert_recipient(dup).is_err());
    }

    #[test]
    fn list_recipients_orders_by_provisioned_desc() {
        let db = OperatorDb::open_in_memory().unwrap();
        let op_id = db
            .insert_pre_provision("{}", "ab", "k1", "hetzner", "t1", 1)
            .unwrap();
        db.insert_recipient(sample_recipient(op_id, 1)).unwrap();
        db.insert_recipient(sample_recipient(op_id, 2)).unwrap();
        let list = db.list_recipients(op_id).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].name, "r2");
        assert_eq!(list[1].name, "r1");
    }

    #[test]
    fn mark_recipient_revoked_updates_row() {
        let db = OperatorDb::open_in_memory().unwrap();
        let op_id = db
            .insert_pre_provision("{}", "ab", "k1", "hetzner", "t1", 1)
            .unwrap();
        let r_id = db.insert_recipient(sample_recipient(op_id, 1)).unwrap();
        db.mark_recipient_revoked(r_id, 1_700_999_999).unwrap();
        let row = db.get_recipient(op_id, r_id).unwrap().unwrap();
        assert_eq!(row.revoked_at_unix, 1_700_999_999);
    }

    #[test]
    fn delete_recipient_removes_row_and_is_operator_scoped() {
        let db = OperatorDb::open_in_memory().unwrap();
        let op_id = db
            .insert_pre_provision("{}", "ab", "k1", "hetzner", "t1", 1)
            .unwrap();
        let r1 = db.insert_recipient(sample_recipient(op_id, 1)).unwrap();
        db.insert_recipient(sample_recipient(op_id, 2)).unwrap();

        db.delete_recipient(op_id, r1).unwrap();
        assert!(db.get_recipient(op_id, r1).unwrap().is_none());
        // The sibling row survives.
        assert_eq!(db.list_recipients(op_id).unwrap().len(), 1);

        // A wrong operator id (or an already-deleted id) is NotFound.
        match db.delete_recipient(op_id, r1).unwrap_err() {
            DbError::NotFound(id) if id == r1 => (),
            e => panic!("expected NotFound({r1}), got {e:?}"),
        }
    }

    #[test]
    fn count_live_recipients_excludes_revoked() {
        let db = OperatorDb::open_in_memory().unwrap();
        let op_id = db
            .insert_pre_provision("{}", "ab", "k1", "hetzner", "t1", 1)
            .unwrap();
        let r1 = db.insert_recipient(sample_recipient(op_id, 1)).unwrap();
        db.insert_recipient(sample_recipient(op_id, 2)).unwrap();
        db.insert_recipient(sample_recipient(op_id, 3)).unwrap();
        db.mark_recipient_revoked(r1, 1_701_000_000).unwrap();
        assert_eq!(db.count_live_recipients(op_id).unwrap(), 2);
    }

    // ---- FRP-14 Layer 3c V010: recipient_identity tests ----

    #[test]
    fn recipient_identity_get_returns_none_when_empty() {
        let db = OperatorDb::open_in_memory().unwrap();
        assert!(db.get_recipient_identity().unwrap().is_none());
    }

    #[test]
    fn recipient_identity_upsert_inserts_then_is_idempotent() {
        let db = OperatorDb::open_in_memory().unwrap();
        let pub1 = [11u8; 32];
        let inserted = db
            .upsert_recipient_identity(&pub1, "daal1abc", "fp1", 1_700_000_000)
            .unwrap();
        assert!(inserted, "first call should insert");

        // Second call with *different* bytes must be a no-op.
        let pub2 = [22u8; 32];
        let inserted2 = db
            .upsert_recipient_identity(&pub2, "daal1xyz", "fp2", 1_700_000_001)
            .unwrap();
        assert!(!inserted2, "second call must report no-insert");

        // Row must still be the *first* row.
        let row = db.get_recipient_identity().unwrap().unwrap();
        assert_eq!(row.pubkey_x25519, pub1.to_vec());
        assert_eq!(row.address_str, "daal1abc");
        assert_eq!(row.fingerprint_hex, "fp1");
        assert_eq!(row.keystore_alias, "recipient_priv_x25519");
        assert_eq!(row.created_at_unix, 1_700_000_000);
    }

    #[test]
    fn recipient_identity_check_constraint_forbids_id_other_than_1() {
        let db = OperatorDb::open_in_memory().unwrap();
        let conn = db.conn.lock().unwrap();
        let err = conn.execute(
            "INSERT INTO recipient_identity
                 (id, pubkey_x25519, keystore_alias, address_str,
                  fingerprint_hex, created_at_unix)
             VALUES (2, ?1, 'a', 'b', 'c', 0)",
            params![vec![0u8; 32]],
        );
        assert!(err.is_err(), "id=2 must violate CHECK(id=1)");
    }
}
