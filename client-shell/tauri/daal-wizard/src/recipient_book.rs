//! FRP-14: publisher-side recipient book.
//!
//! Each operator (V2 box) has a roster of up to 128 recipients.
//! For each recipient the publisher persists:
//!
//! * the recipient's branded `daal1…` address (their X25519
//!   public key, captured at registration time),
//! * the per-server credentials returned by
//!   `POST /users/provision`.
//!
//! Workflow:
//!
//! 1. **Add** (`provision`): operator types the recipient's
//!    `daal1…` address (or scans a QR), wizard validates, mints a
//!    monotonic `r<n>` name via [`OperatorDb::reserve_recipient_name`],
//!    calls `daal-deploy users-provision`, then inserts the row.
//!
//! 2. **Revoke** (`revoke`): wizard calls `daal-deploy users-revoke`,
//!    which removes the user from sing-box + runs the SIGUSR2 kick
//!    wrapper on the box. We then set `revoked_at_unix` on the local
//!    row so the UI can render it greyed-out.
//!
//! 3. **Resend** (`resend`): no box round-trip — rebuild the
//!    `.sbpx` envelope locally from the already-stored creds and
//!    return the path. Operator can deliver via any channel.
//!
//! 4. **List** (`list`): return the local roster, no box round-trip.
//!
//! Position B: this module never opens a network socket directly;
//! every box interaction goes through the CLI subprocess bridge.

use std::path::PathBuf;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD_NO_PAD as B64;
use base64::Engine;
use daal_recipient_addr as recipaddr;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::cli_bridge::{BridgeError, UsersListArgs, UsersProvisionArgs, UsersRevokeArgs};
use crate::commands::{WizardCtx, WizardError};
use crate::keystore::KeystoreError;
use crate::operator_db::{DbError, NewRecipientRow, RecipientRow};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipientSummary {
    pub id: i64,
    pub name: String,
    pub display_name: String,
    pub address_str: String,
    pub fingerprint_hex: String,
    pub provisioned_at_unix: i64,
    pub revoked_at_unix: i64,
    /// FRP-14 Layer 3b.5: filesystem path to the `.sbpx`
    /// envelope produced for this recipient. Empty string when
    /// no envelope has been written yet (e.g. revoked rows, or
    /// rows from before Layer 3b.5 landed).
    #[serde(default)]
    pub sbpx_path: String,
}

impl From<RecipientRow> for RecipientSummary {
    fn from(r: RecipientRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            display_name: r.display_name,
            address_str: r.address_str,
            fingerprint_hex: r.fingerprint_hex,
            provisioned_at_unix: r.provisioned_at_unix,
            revoked_at_unix: r.revoked_at_unix,
            sbpx_path: String::new(),
        }
    }
}

/// `recipient_provision` adds a new recipient to the operator's
/// roster. `address` MUST be a `daal1…` bech32m string OR a
/// `daal://daal1…` URI. `display_name` is the operator's free-form
/// alias (e.g. "Bahar"); it never leaves the publisher app.
pub fn recipient_provision(
    ctx: &WizardCtx,
    operator_id: i64,
    pin: &str,
    helper_ip: &str,
    address: &str,
    display_name: &str,
) -> Result<RecipientSummary, WizardError> {
    crate::commands::validate_pin(pin)?;

    let pub_key = decode_recipient_address(address)?;
    let fp_hex = recipaddr::fingerprint(&pub_key);
    let address_canonical = recipaddr::encode(&pub_key);

    // Cap check (mirrors the on-box 128 limit; FRP-14 invariant 7).
    let live = ctx
        .db
        .count_live_recipients(operator_id)
        .map_err(WizardError::Db)?;
    if live >= MAX_RECIPIENTS_PER_SERVER {
        return Err(WizardError::Pricing(format!(
            "max recipients ({}) reached on this server",
            MAX_RECIPIENTS_PER_SERVER
        )));
    }

    let row = ctx.db.get(operator_id).map_err(WizardError::Db)?;

    // Open keystore once for both publisher privkey + cloud token.
    let priv_bytes = match ctx.keystore.open(&row.publisher_priv_keystore_alias, pin) {
        Ok(b) => b,
        Err(KeystoreError::WrongPin) => {
            return Err(WizardError::Keystore(KeystoreError::WrongPin));
        }
        Err(e) => return Err(WizardError::Keystore(e)),
    };
    let priv_buf = Zeroizing::new(priv_bytes);

    let token_bytes = ctx
        .keystore
        .open(&row.cloud_token_keystore_alias, pin)
        .map_err(WizardError::Keystore)?;
    let token = Zeroizing::new(
        String::from_utf8(token_bytes).map_err(|e| WizardError::Pricing(format!("token: {e}")))?,
    );

    // Reserve next monotonic name (r1, r2, …) and write the
    // staged OperatorRecord JSON the subprocess reads.
    let name = ctx
        .db
        .reserve_recipient_name(operator_id)
        .map_err(WizardError::Db)?;
    let record_path = write_record_staging(ctx, operator_id, &row.operator_record_json)?;

    let creds = ctx
        .cli
        .run_users_provision(
            UsersProvisionArgs {
                record_path: &record_path,
                helper_ip,
                token: token.as_str(),
                name: &name,
            },
            priv_buf.as_slice(),
        )
        .map_err(map_bridge_err)?;
    let _ = std::fs::remove_file(&record_path);

    let inserted = ctx
        .db
        .insert_recipient(NewRecipientRow {
            operator_id,
            name: creds.name.clone(),
            display_name: display_name.to_string(),
            address_str: address_canonical,
            pubkey_x25519_hex: hex::encode(pub_key),
            fingerprint_hex: fp_hex,
            vless_uuid: creds.vless_uuid,
            reality_short_id: creds.reality_short_id,
            hy2_password: creds.hy2_password,
            naive_password: creds.naive_password,
            ws_path: creds.ws_path,
            provisioned_at_unix: creds.provisioned_at_unix,
        })
        .map_err(WizardError::Db)?;
    let row = ctx
        .db
        .get_recipient(operator_id, inserted)
        .map_err(WizardError::Db)?
        .ok_or_else(|| WizardError::Pricing("recipient row vanished after insert".into()))?;

    // FRP-14 Layer 3b.5: produce the per-recipient `.sbpx`
    // envelope alongside the row. The inner `.sbp` is the
    // operator-level Step-6 output (shared creds for now;
    // per-recipient inbound rewriting lands in Tier-2). The
    // envelope adds in-transit confidentiality and binds the
    // file to one recipient pubkey.
    //
    // We don't fail the whole provision if envelope wrap fails —
    // the box-side credentials are already live and the user can
    // still share the legacy `.sbp`. We just leave `sbpx_path`
    // empty and the UI surfaces that.
    let mut summary: RecipientSummary = row.into();
    let in_sbp_path = ctx.staging_dir.join(format!("{operator_id}.sbp"));
    if in_sbp_path.exists() {
        let out_path = ctx
            .staging_dir
            .join(format!("{operator_id}.{}.sbpx", summary.name));
        let recipient_pub_hex = hex::encode(pub_key);
        if let Ok(_res) = ctx.cli.run_users_pack_sbpx(
            crate::cli_bridge::UsersPackSbpxArgs {
                in_sbp_path: &in_sbp_path,
                recipient_pub_hex: &recipient_pub_hex,
                out_sbpx_path: &out_path,
            },
        ) {
            summary.sbpx_path = out_path.to_string_lossy().to_string();
        }
    }
    Ok(summary)
}

/// `recipient_revoke` revokes the recipient on the box (sing-box
/// rewrite + SIGUSR2 kick) and stamps `revoked_at_unix` on the
/// local row. Idempotent: revoking an already-revoked recipient
/// returns the existing row unchanged.
pub fn recipient_revoke(
    ctx: &WizardCtx,
    operator_id: i64,
    pin: &str,
    helper_ip: &str,
    recipient_id: i64,
) -> Result<RecipientSummary, WizardError> {
    crate::commands::validate_pin(pin)?;

    let r = ctx
        .db
        .get_recipient(operator_id, recipient_id)
        .map_err(WizardError::Db)?
        .ok_or_else(|| WizardError::Db(DbError::NotFound(recipient_id)))?;
    if r.revoked_at_unix != 0 {
        return Ok(r.into());
    }
    let op_row = ctx.db.get(operator_id).map_err(WizardError::Db)?;
    let priv_bytes = ctx
        .keystore
        .open(&op_row.publisher_priv_keystore_alias, pin)
        .map_err(WizardError::Keystore)?;
    let priv_buf = Zeroizing::new(priv_bytes);
    let token_bytes = ctx
        .keystore
        .open(&op_row.cloud_token_keystore_alias, pin)
        .map_err(WizardError::Keystore)?;
    let token = Zeroizing::new(
        String::from_utf8(token_bytes).map_err(|e| WizardError::Pricing(format!("token: {e}")))?,
    );

    let record_path = write_record_staging(ctx, operator_id, &op_row.operator_record_json)?;
    let resp = ctx
        .cli
        .run_users_revoke(
            UsersRevokeArgs {
                record_path: &record_path,
                helper_ip,
                token: token.as_str(),
                name: &r.name,
            },
            priv_buf.as_slice(),
        )
        .map_err(map_bridge_err)?;
    let _ = std::fs::remove_file(&record_path);

    ctx.db
        .mark_recipient_revoked(recipient_id, resp.revoked_at_unix)
        .map_err(WizardError::Db)?;
    let updated = ctx
        .db
        .get_recipient(operator_id, recipient_id)
        .map_err(WizardError::Db)?
        .ok_or_else(|| WizardError::Db(DbError::NotFound(recipient_id)))?;
    Ok(updated.into())
}

/// `recipient_list` returns the local roster (live + revoked).
pub fn recipient_list(
    ctx: &WizardCtx,
    operator_id: i64,
) -> Result<Vec<RecipientSummary>, WizardError> {
    let rows = ctx
        .db
        .list_recipients(operator_id)
        .map_err(WizardError::Db)?;
    Ok(rows
        .into_iter()
        .map(|r| {
            let name = r.name.clone();
            let mut s: RecipientSummary = r.into();
            // FRP-14 Layer 3b.5: surface the per-recipient .sbpx
            // path when it's on disk so the roster card can render
            // a Share button per recipient.
            let p = ctx.staging_dir.join(format!("{operator_id}.{}.sbpx", name));
            if p.exists() {
                s.sbpx_path = p.to_string_lossy().to_string();
            }
            s
        })
        .collect())
}

/// `recipient_list_remote` confirms the box's authoritative roster
/// matches the local one. Used for a "verify" button in the UI;
/// surfaces drift so the operator can re-sync.
pub fn recipient_list_remote(
    ctx: &WizardCtx,
    operator_id: i64,
    pin: &str,
    helper_ip: &str,
) -> Result<Vec<String>, WizardError> {
    crate::commands::validate_pin(pin)?;
    let row = ctx.db.get(operator_id).map_err(WizardError::Db)?;
    let priv_bytes = ctx
        .keystore
        .open(&row.publisher_priv_keystore_alias, pin)
        .map_err(WizardError::Keystore)?;
    let priv_buf = Zeroizing::new(priv_bytes);
    let token_bytes = ctx
        .keystore
        .open(&row.cloud_token_keystore_alias, pin)
        .map_err(WizardError::Keystore)?;
    let token = Zeroizing::new(
        String::from_utf8(token_bytes).map_err(|e| WizardError::Pricing(format!("token: {e}")))?,
    );
    let record_path = write_record_staging(ctx, operator_id, &row.operator_record_json)?;
    let users = ctx
        .cli
        .run_users_list(
            UsersListArgs {
                record_path: &record_path,
                helper_ip,
                token: token.as_str(),
            },
            priv_buf.as_slice(),
        )
        .map_err(map_bridge_err)?;
    let _ = std::fs::remove_file(&record_path);
    Ok(users.into_iter().map(|u| u.name).collect())
}

// -----------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------

const MAX_RECIPIENTS_PER_SERVER: i64 = 128;

/// Accepts a `daal1…` bech32m string OR a `daal://daal1…` URI.
fn decode_recipient_address(s: &str) -> Result<[u8; 32], WizardError> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(WizardError::Pricing("empty recipient address".into()));
    }
    if let Some(stripped) = trimmed.strip_prefix("daal://") {
        return recipaddr::decode(stripped)
            .map_err(|e| WizardError::Pricing(format!("recipient address: {e}")));
    }
    recipaddr::decode(trimmed)
        .map_err(|e| WizardError::Pricing(format!("recipient address: {e}")))
}

fn write_record_staging(
    ctx: &WizardCtx,
    operator_id: i64,
    record_json: &str,
) -> Result<PathBuf, WizardError> {
    std::fs::create_dir_all(&ctx.staging_dir)
        .map_err(|e| WizardError::Pricing(format!("mkdir staging: {e}")))?;
    let path = ctx.staging_dir.join(format!("{operator_id}.record.json"));
    std::fs::write(&path, record_json.as_bytes())
        .map_err(|e| WizardError::Pricing(format!("write record: {e}")))?;
    Ok(path)
}

fn map_bridge_err(e: BridgeError) -> WizardError {
    // Surface the full stderr from the daal-deploy subprocess so
    // the React layer can render the actual mgmt-plane / firewall /
    // routing failure to the operator. Until FRP-14 this was
    // collapsed into `WizardError::Pricing` which was misleading —
    // the bridge has nothing to do with cloud-provider pricing.
    WizardError::Subprocess(e.to_string())
}

// suppress unused-warning when an external crate (base64/Arc) isn't
// directly referenced in this module's public surface
#[allow(dead_code)]
fn _ensure_used(_: Arc<()>) -> String {
    B64.encode([])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli_bridge::{CliRunner, MockRunner, Pricing};
    use crate::keystore::Keystore;
    use crate::operator_db::OperatorDb;

    fn mk_ctx() -> (WizardCtx, Arc<MockRunner>, i64) {
        let db = Arc::new(OperatorDb::open_in_memory().unwrap());
        let dir = std::env::temp_dir().join(format!(
            "daal-frp14-keystore-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::create_dir_all(&dir);
        let keystore = Arc::new(Keystore::new_in_memory(&dir));
        let pin = "123456";
        // Mint a publisher key pair and pre-provision row.
        let priv_alias = "pub.priv".to_string();
        let token_alias = "cloud.tok".to_string();
        let priv_bytes = vec![0u8; 64];
        keystore.seal(&priv_alias, pin, &priv_bytes).unwrap();
        keystore.seal(&token_alias, pin, b"mock-token").unwrap();
        let op_id = db
            .insert_pre_provision(
                r#"{"region":"fsn1","server_type":"cx22","public_ip":"1.2.3.4","mgmt_port":42424}"#,
                "ab",
                &priv_alias,
                "hetzner",
                &token_alias,
                1_700_000_000,
            )
            .unwrap();
        let mock = Arc::new(MockRunner::new(Pricing {
            provider: "hetzner".into(),
            region: "fsn1".into(),
            server_type: "cx22".into(),
            hourly_eur: 0.0,
            monthly_eur: 0.0,
            included_traffic_tb_per_month: None,
            overage_eur_per_gb: None,
        }));
        let cli: Arc<dyn CliRunner> = mock.clone();
        let staging_dir = std::env::temp_dir().join(format!(
            "daal-frp14-recip-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::create_dir_all(&staging_dir);
        let custody: Arc<dyn crate::device_custody::DeviceCustody> = Arc::new(
            crate::device_custody::FileCustody::static_test(&dir).unwrap(),
        );
        let ctx = WizardCtx {
            db,
            keystore,
            staging_dir,
            cli,
            clock: Arc::new(|| 1_700_000_500),
            custody,
        };
        (ctx, mock, op_id)
    }

    fn sample_address() -> String {
        // 32-byte all-ones key, bech32m-encoded.
        let key = [0x11u8; 32];
        recipaddr::encode(&key)
    }

    #[test]
    fn provision_then_list_round_trips() {
        let (ctx, _mock, op_id) = mk_ctx();
        let summary =
            recipient_provision(&ctx, op_id, "123456", "1.2.3.4", &sample_address(), "Alice")
                .unwrap();
        assert_eq!(summary.name, "r1");
        assert_eq!(summary.display_name, "Alice");
        assert_eq!(summary.revoked_at_unix, 0);

        let list = recipient_list(&ctx, op_id).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "r1");
    }

    #[test]
    fn provision_rejects_bad_address() {
        let (ctx, _mock, op_id) = mk_ctx();
        let err = recipient_provision(&ctx, op_id, "123456", "1.2.3.4", "not-an-address", "Alice")
            .unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("recipient address"), "got: {msg}");
    }

    #[test]
    fn provision_uri_form_accepted() {
        let (ctx, _mock, op_id) = mk_ctx();
        let uri = format!("daal://{}", sample_address());
        let s = recipient_provision(&ctx, op_id, "123456", "1.2.3.4", &uri, "Bahar").unwrap();
        assert_eq!(s.address_str, sample_address());
    }

    #[test]
    fn revoke_flips_local_row_and_calls_box() {
        let (ctx, mock, op_id) = mk_ctx();
        let s = recipient_provision(&ctx, op_id, "123456", "1.2.3.4", &sample_address(), "Alice")
            .unwrap();
        let revoked = recipient_revoke(&ctx, op_id, "123456", "1.2.3.4", s.id).unwrap();
        assert!(revoked.revoked_at_unix > 0);

        // Idempotent.
        let revoked_again = recipient_revoke(&ctx, op_id, "123456", "1.2.3.4", s.id).unwrap();
        assert_eq!(revoked_again.revoked_at_unix, revoked.revoked_at_unix);

        // Mock runner saw the revoke call once (idempotent path
        // short-circuits the second call).
        let calls = mock.users_revoke_calls.lock().unwrap().clone();
        assert_eq!(calls, vec!["r1".to_string()]);
    }

    // The 128-recipient cap test runs argon2 once per insert through
    // the keystore (`seal`/`open`). To keep `cargo test --lib`
    // responsive, we seed the recipients directly through the DB and
    // only exercise the cap-check branch via the public API.
    #[test]
    fn cap_at_128_recipients() {
        let (ctx, _mock, op_id) = mk_ctx();
        for i in 1..=MAX_RECIPIENTS_PER_SERVER {
            let byte = (i & 0xff) as u8;
            let pk = format!("{:02x}", byte).repeat(32);
            let fp = format!("{:02x}", byte ^ 0xa5).repeat(32);
            ctx.db
                .insert_recipient(NewRecipientRow {
                    operator_id: op_id,
                    name: format!("r{}", i),
                    display_name: format!("seed-{}", i),
                    address_str: format!("daal1seed{}", i),
                    pubkey_x25519_hex: pk,
                    fingerprint_hex: fp,
                    vless_uuid: "00000000-0000-0000-0000-000000000000".into(),
                    reality_short_id: "deadbeef".into(),
                    hy2_password: "hy2".into(),
                    naive_password: "naive".into(),
                    ws_path: format!("/r{}/cafebabe", i),
                    provisioned_at_unix: 1_700_000_000 + i,
                })
                .unwrap();
        }
        let mut key = [0u8; 32];
        key[0] = 0xff;
        key[1] = 0xff;
        let extra = recipaddr::encode(&key);
        let err = recipient_provision(&ctx, op_id, "123456", "1.2.3.4", &extra, "y").unwrap_err();
        assert!(format!("{err:?}").contains("max recipients"));
    }
}
