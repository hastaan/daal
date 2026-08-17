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

use crate::cli_bridge::{BridgeError, UsersListArgs, UsersProvisionArgs, UsersRevokeArgs};
use crate::commands::{WizardCtx, WizardError};
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
    address: &str,
    display_name: &str,
) -> Result<RecipientSummary, WizardError> {
    // Fail on a missing helper IP before doing any work: without it
    // the firewall rule can't be punched and the subprocess would
    // burn 30 s to report "connection refused".
    let helper_ip = crate::commands::require_helper_ip(ctx, operator_id)?;

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

    // Both secrets come out of device custody.
    let priv_buf = crate::commands::custody_get(ctx, &row.publisher_priv_keystore_alias)?;
    let token = crate::commands::custody_get_string(ctx, &row.cloud_token_keystore_alias)?;

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
                helper_ip: &helper_ip,
                token: token.as_str(),
                name: &name,
            },
            priv_buf.as_slice(),
        )
        .map_err(map_bridge_err)?;
    let _ = std::fs::remove_file(&record_path);

    // FRP-14 Tier-2: build the creds JSON the pack step reads. Capture
    // BEFORE insert_recipient moves the cred fields. The relay's public
    // IP, reality pubkey, and tls pin come from the OperatorRecord
    // (read off the box over SSH at provision time) — the mgmt-response
    // creds carry empty box material on a box running a pre-Tier-2
    // released daal-relay-mgmt, so the record is the authoritative
    // source. `helper_ip` is the publisher's own WAN and is NOT the
    // server the client dials.
    let rec_val = serde_json::from_str::<serde_json::Value>(&row.operator_record_json)
        .unwrap_or(serde_json::Value::Null);
    let field = |k: &str| -> String {
        rec_val.get(k).and_then(|s| s.as_str()).unwrap_or("").to_string()
    };
    let relay_server_ip = field("public_ip");
    let mut creds_val = serde_json::to_value(&creds).unwrap_or(serde_json::Value::Null);
    if let Some(obj) = creds_val.as_object_mut() {
        // Prefer the record's box material; fall back to whatever the
        // mgmt response provided (non-empty once a Tier-2 release ships).
        let reality_pub = field("reality_public_key");
        let tls_pin = field("tls_cert_sha256");
        if !reality_pub.is_empty() {
            obj.insert("reality_public_key".into(), reality_pub.into());
        }
        if !tls_pin.is_empty() {
            obj.insert("tls_cert_sha256".into(), tls_pin.into());
        }
    }
    let creds_json = serde_json::to_string(&creds_val).unwrap_or_default();
    // The record's cover host, handed to the pack step as the fallback
    // for a box whose mgmt binary is too old to echo its own. See
    // UsersPackSbpxArgs::cover_sni.
    let record_cover_sni = field("cover_sni");

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

    // FRP-14 Tier-2: produce the per-recipient `.sbpx` envelope. The
    // inner `.sbp`'s profiles are rewritten with real client outbounds
    // for THIS recipient (creds_file + server), then age-wrapped and
    // bound to the recipient pubkey. Without the box connection material
    // (pre-Tier-2 box → empty reality_public_key) the rewrite fails
    // closed and we leave sbpx_path empty; the box-side creds are still
    // live, so the operator can retry after the box is updated.
    let mut summary: RecipientSummary = row.into();
    let in_sbp_path = ctx.staging_dir.join(format!("{operator_id}.sbp"));
    if in_sbp_path.exists() {
        let out_path = ctx
            .staging_dir
            .join(format!("{operator_id}.{}.sbpx", summary.name));
        let recipient_pub_hex = hex::encode(pub_key);
        // Stage the creds JSON for the subprocess; 0600, removed after.
        let creds_path = ctx.staging_dir.join(format!("{operator_id}.{}.creds.json", summary.name));
        let wrote_creds = std::fs::write(&creds_path, creds_json.as_bytes()).is_ok();
        let (creds_arg, server_arg): (Option<&std::path::Path>, Option<&str>) =
            if wrote_creds && !relay_server_ip.is_empty() {
                (Some(creds_path.as_path()), Some(relay_server_ip.as_str()))
            } else {
                (None, None)
            };
        if let Ok(_res) = ctx.cli.run_users_pack_sbpx(
            crate::cli_bridge::UsersPackSbpxArgs {
                in_sbp_path: &in_sbp_path,
                recipient_pub_hex: &recipient_pub_hex,
                out_sbpx_path: &out_path,
                creds_file_path: creds_arg,
                server: server_arg,
                cover_sni: Some(record_cover_sni.as_str()),
            },
        ) {
            summary.sbpx_path = out_path.to_string_lossy().to_string();
        }
        let _ = std::fs::remove_file(&creds_path);
    }
    Ok(summary)
}

/// `recipient_repack_sbpx` rebuilds the per-recipient `.sbpx` for a
/// recipient that is already on the roster.
///
/// # Why this is not "just call recipient_provision again"
///
/// [`recipient_provision`] has no upsert path. Re-running it for an
/// address already on the roster burns a fresh `r<n>` name, mints a
/// **new live user on the box**, and only then hits
/// `UNIQUE (operator_id, pubkey_x25519_hex)` and fails — leaving a
/// working credential set on the relay that the local roster does not
/// know about, cannot revoke, and which still counts against the
/// 128-recipient cap. Every retry adds another. The relay-detail
/// "Rebuild" affordance exists precisely for the case where
/// `run_users_pack_sbpx` failed closed (a pre-Tier-2 box with no
/// `reality_public_key`), so it needs a path that repairs rather than
/// duplicates.
///
/// This re-mints the recipient's **existing** name: best-effort revoke
/// (the box 409s on a name that already exists — the same idempotency
/// dance [`produce_shared_sbp`] does for `r0`), then provision under
/// the same name, then update the stored credentials in place and
/// repack. The recipient's identity — name, address, pubkey — is
/// untouched, so no row is duplicated and no name is burned.
///
/// The credentials do change, so any `.sbpx` already delivered to this
/// recipient stops working. That is inherent: the only reason to call
/// this is that no working `.sbpx` exists.
pub fn recipient_repack_sbpx(
    ctx: &WizardCtx,
    operator_id: i64,
    recipient_id: i64,
) -> Result<RecipientSummary, WizardError> {
    let r = ctx
        .db
        .get_recipient(operator_id, recipient_id)
        .map_err(WizardError::Db)?
        .ok_or_else(|| WizardError::Db(DbError::NotFound(recipient_id)))?;
    if r.revoked_at_unix != 0 {
        // Re-minting a revoked recipient would hand a live credential
        // back to someone the operator deliberately cut off.
        return Err(WizardError::Validation(
            "this recipient is revoked — add them again to give them access".into(),
        ));
    }

    let helper_ip = crate::commands::require_helper_ip(ctx, operator_id)?;
    let row = ctx.db.get(operator_id).map_err(WizardError::Db)?;

    // The signed .sbp is the input to the rewrite; without it there is
    // nothing to repack.
    let in_sbp_path = ctx.staging_dir.join(format!("{operator_id}.sbp"));
    if !in_sbp_path.exists() {
        return Err(WizardError::Pricing(
            "no signed bundle yet — build the relay pack first".into(),
        ));
    }

    let priv_buf = crate::commands::custody_get(ctx, &row.publisher_priv_keystore_alias)?;
    let token = crate::commands::custody_get_string(ctx, &row.cloud_token_keystore_alias)?;

    let record_path = write_record_staging(ctx, operator_id, &row.operator_record_json)?;
    let _ = ctx.cli.run_users_revoke(
        UsersRevokeArgs {
            record_path: &record_path,
            helper_ip: &helper_ip,
            token: token.as_str(),
            name: &r.name,
        },
        priv_buf.as_slice(),
    );
    let creds = ctx
        .cli
        .run_users_provision(
            UsersProvisionArgs {
                record_path: &record_path,
                helper_ip: &helper_ip,
                token: token.as_str(),
                name: &r.name,
            },
            priv_buf.as_slice(),
        )
        .map_err(map_bridge_err)?;
    let _ = std::fs::remove_file(&record_path);

    ctx.db
        .update_recipient_creds(
            operator_id,
            recipient_id,
            &creds.vless_uuid,
            &creds.reality_short_id,
            &creds.hy2_password,
            &creds.naive_password,
            &creds.ws_path,
            creds.provisioned_at_unix,
        )
        .map_err(WizardError::Db)?;

    // Same record-first precedence as recipient_provision: the box
    // material read over SSH at provision time beats whatever the mgmt
    // response carried.
    let rec_val = serde_json::from_str::<serde_json::Value>(&row.operator_record_json)
        .unwrap_or(serde_json::Value::Null);
    let field = |k: &str| -> String {
        rec_val.get(k).and_then(|s| s.as_str()).unwrap_or("").to_string()
    };
    let relay_server_ip = field("public_ip");
    if relay_server_ip.is_empty() {
        return Err(WizardError::Pricing(
            "operator record has no public_ip — reprovision the box".into(),
        ));
    }
    let mut creds_val = serde_json::to_value(&creds).unwrap_or(serde_json::Value::Null);
    if let Some(obj) = creds_val.as_object_mut() {
        let reality_pub = field("reality_public_key");
        let tls_pin = field("tls_cert_sha256");
        if !reality_pub.is_empty() {
            obj.insert("reality_public_key".into(), reality_pub.into());
        }
        if !tls_pin.is_empty() {
            obj.insert("tls_cert_sha256".into(), tls_pin.into());
        }
    }
    let creds_json = serde_json::to_string(&creds_val).unwrap_or_default();
    let record_cover_sni = field("cover_sni");

    let out_path = ctx
        .staging_dir
        .join(format!("{operator_id}.{}.sbpx", r.name));
    let creds_path = ctx
        .staging_dir
        .join(format!("{operator_id}.{}.creds.json", r.name));
    std::fs::write(&creds_path, creds_json.as_bytes())
        .map_err(|e| WizardError::Pricing(format!("stage creds: {e}")))?;
    let res = ctx.cli.run_users_pack_sbpx(crate::cli_bridge::UsersPackSbpxArgs {
        in_sbp_path: &in_sbp_path,
        recipient_pub_hex: &r.pubkey_x25519_hex,
        out_sbpx_path: &out_path,
        creds_file_path: Some(creds_path.as_path()),
        server: Some(relay_server_ip.as_str()),
        cover_sni: Some(record_cover_sni.as_str()),
    });
    let _ = std::fs::remove_file(&creds_path);
    // Unlike recipient_provision — which swallows this failure because
    // the recipient row and box user are the durable outcome — the pack
    // IS the outcome here, so a failure must surface.
    res.map_err(map_bridge_err)?;

    let updated = ctx
        .db
        .get_recipient(operator_id, recipient_id)
        .map_err(WizardError::Db)?
        .ok_or_else(|| WizardError::Db(DbError::NotFound(recipient_id)))?;
    let mut summary: RecipientSummary = updated.into();
    summary.sbpx_path = out_path.to_string_lossy().to_string();
    Ok(summary)
}

/// The fixed shared-user identity on the box. A plain shared `.sbp` bakes
/// this one credential set in, so ANY phone that imports the file can
/// connect — no per-recipient sealing. `r0` matches the box nameRegex.
pub const SHARED_USER_NAME: &str = "r0";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedSbpSummary {
    /// Filesystem path to the shareable shared `.sbp`.
    pub sbp_path: String,
    /// The relay public IP the routes dial (for display).
    pub server: String,
}

/// `produce_shared_sbp` mints (or re-mints) the shared `r0` user on the
/// box and rewrites the operator's signed `.sbp` (Step-6 output) with that
/// one credential set, producing a plaintext shared `.sbp` any phone can
/// import and connect. This is the default "share with the whole family"
/// artifact; the per-recipient `.sbpx` path (recipient_provision) stays as
/// the individually-revocable option.
pub fn produce_shared_sbp(
    ctx: &WizardCtx,
    operator_id: i64,
) -> Result<SharedSbpSummary, WizardError> {
    let helper_ip = crate::commands::require_helper_ip(ctx, operator_id)?;

    let row = ctx.db.get(operator_id).map_err(WizardError::Db)?;

    // The signed .sbp from Step 6 must exist before we can rewrite it.
    let in_sbp_path = ctx.staging_dir.join(format!("{operator_id}.sbp"));
    if !in_sbp_path.exists() {
        return Err(WizardError::Pricing(
            "no signed bundle yet — finish the Sign step first".into(),
        ));
    }

    // Both secrets come out of device custody.
    let priv_buf = crate::commands::custody_get(ctx, &row.publisher_priv_keystore_alias)?;
    let token = crate::commands::custody_get_string(ctx, &row.cloud_token_keystore_alias)?;

    // Mint the shared user on the box. /users/provision 409s if the name
    // already exists, so make the flow idempotent: best-effort revoke the
    // previous r0 first (ignore "not found"), then provision fresh. A
    // re-share therefore re-keys the shared user — older shared .sbp files
    // stop working, which is the correct behaviour for "rotate my relay".
    let record_path = write_record_staging(ctx, operator_id, &row.operator_record_json)?;
    let _ = ctx.cli.run_users_revoke(
        UsersRevokeArgs {
            record_path: &record_path,
            helper_ip: &helper_ip,
            token: token.as_str(),
            name: SHARED_USER_NAME,
        },
        priv_buf.as_slice(),
    );
    let creds = ctx
        .cli
        .run_users_provision(
            UsersProvisionArgs {
                record_path: &record_path,
                helper_ip: &helper_ip,
                token: token.as_str(),
                name: SHARED_USER_NAME,
            },
            priv_buf.as_slice(),
        )
        .map_err(map_bridge_err)?;
    let _ = std::fs::remove_file(&record_path);

    // Build the creds JSON the rewrite reads. Box-wide material
    // (reality pubkey, tls pin) falls back to the OperatorRecord when the
    // mgmt response omits it (pre-Tier-2 box); tls_cert_pem comes straight
    // from the mgmt response (needed for naive).
    let rec_val = serde_json::from_str::<serde_json::Value>(&row.operator_record_json)
        .unwrap_or(serde_json::Value::Null);
    let field = |k: &str| -> String {
        rec_val.get(k).and_then(|s| s.as_str()).unwrap_or("").to_string()
    };
    let relay_server_ip = field("public_ip");
    if relay_server_ip.is_empty() {
        return Err(WizardError::Pricing(
            "operator record has no public_ip — reprovision the box".into(),
        ));
    }
    let mut creds_val = serde_json::to_value(&creds).unwrap_or(serde_json::Value::Null);
    if let Some(obj) = creds_val.as_object_mut() {
        let reality_pub = field("reality_public_key");
        let tls_pin = field("tls_cert_sha256");
        if !reality_pub.is_empty() {
            obj.insert("reality_public_key".into(), reality_pub.into());
        }
        if !tls_pin.is_empty() {
            obj.insert("tls_cert_sha256".into(), tls_pin.into());
        }
    }
    let creds_json = serde_json::to_string(&creds_val).unwrap_or_default();
    let record_cover_sni = field("cover_sni");

    // Rewrite the .sbp's profiles with the shared creds → shared .sbp.
    let out_path = ctx.staging_dir.join(format!("{operator_id}.shared.sbp"));
    let creds_path = ctx.staging_dir.join(format!("{operator_id}.shared.creds.json"));
    std::fs::write(&creds_path, creds_json.as_bytes())
        .map_err(|e| WizardError::Pricing(format!("stage creds: {e}")))?;
    let res = ctx.cli.run_users_pack_sbp(crate::cli_bridge::UsersPackSbpArgs {
        in_sbp_path: &in_sbp_path,
        creds_file_path: &creds_path,
        server: &relay_server_ip,
        out_sbp_path: &out_path,
        cover_sni: Some(record_cover_sni.as_str()),
    });
    let _ = std::fs::remove_file(&creds_path);
    res.map_err(map_bridge_err)?;

    Ok(SharedSbpSummary {
        sbp_path: out_path.to_string_lossy().to_string(),
        server: relay_server_ip,
    })
}

/// `recipient_revoke` revokes the recipient on the box (sing-box
/// rewrite + SIGUSR2 kick) and stamps `revoked_at_unix` on the
/// local row. Idempotent: revoking an already-revoked recipient
/// returns the existing row unchanged.
pub fn recipient_revoke(
    ctx: &WizardCtx,
    operator_id: i64,
    recipient_id: i64,
) -> Result<RecipientSummary, WizardError> {
    let r = ctx
        .db
        .get_recipient(operator_id, recipient_id)
        .map_err(WizardError::Db)?
        .ok_or_else(|| WizardError::Db(DbError::NotFound(recipient_id)))?;
    if r.revoked_at_unix != 0 {
        // Idempotent: an already-revoked row needs no box round-trip,
        // so this path deliberately runs before the helper-IP check.
        return Ok(r.into());
    }
    let helper_ip = crate::commands::require_helper_ip(ctx, operator_id)?;
    let op_row = ctx.db.get(operator_id).map_err(WizardError::Db)?;
    let priv_buf = crate::commands::custody_get(ctx, &op_row.publisher_priv_keystore_alias)?;
    let token = crate::commands::custody_get_string(ctx, &op_row.cloud_token_keystore_alias)?;

    let record_path = write_record_staging(ctx, operator_id, &op_row.operator_record_json)?;
    let resp = ctx
        .cli
        .run_users_revoke(
            UsersRevokeArgs {
                record_path: &record_path,
                helper_ip: &helper_ip,
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

/// `recipient_delete` hard-removes a recipient from the local
/// roster. Where [`recipient_revoke`] tears down the on-box state
/// and stamps `revoked_at_unix` so the UI greys the row out, this is
/// the follow-up "remove from list" affordance that purges the
/// greyed-out row (and its leftover `.sbpx` envelope) for good. No
/// box round-trip: deletion is a local roster edit only.
///
/// Guarded: a still-live recipient (never revoked) must be revoked
/// FIRST. Deleting a live row here would silently orphan working
/// credentials on the box — the recipient could keep connecting and
/// the slot would stay burned — so we refuse with a validation error
/// the React layer turns into a "revoke before removing" prompt.
/// This mirrors the connection-safety rule elsewhere in the app:
/// tear down the active/live path before dropping its record.
pub fn recipient_delete(
    ctx: &WizardCtx,
    operator_id: i64,
    recipient_id: i64,
) -> Result<(), WizardError> {
    let r = ctx
        .db
        .get_recipient(operator_id, recipient_id)
        .map_err(WizardError::Db)?
        .ok_or_else(|| WizardError::Db(DbError::NotFound(recipient_id)))?;
    if r.revoked_at_unix == 0 {
        return Err(WizardError::Validation(
            "revoke this recipient before removing it from the roster".into(),
        ));
    }

    ctx.db
        .delete_recipient(operator_id, recipient_id)
        .map_err(WizardError::Db)?;

    // Best-effort unlink of the per-recipient `.sbpx` envelope left
    // in the staging dir (Layer 3b.5). Failure to remove is
    // non-fatal: the roster row is already gone, and the launch-time
    // sweep reaps orphaned staging files anyway.
    let sbpx = ctx
        .staging_dir
        .join(format!("{operator_id}.{}.sbpx", r.name));
    let _ = std::fs::remove_file(&sbpx);

    Ok(())
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
) -> Result<Vec<String>, WizardError> {
    let helper_ip = crate::commands::require_helper_ip(ctx, operator_id)?;
    let row = ctx.db.get(operator_id).map_err(WizardError::Db)?;
    let priv_buf = crate::commands::custody_get(ctx, &row.publisher_priv_keystore_alias)?;
    let token = crate::commands::custody_get_string(ctx, &row.cloud_token_keystore_alias)?;
    let record_path = write_record_staging(ctx, operator_id, &row.operator_record_json)?;
    let users = ctx
        .cli
        .run_users_list(
            UsersListArgs {
                record_path: &record_path,
                helper_ip: &helper_ip,
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
    //
    // `map_deploy_err` additionally promotes transport-shaped
    // failures to E_HELPER_IP_STALE so the UI re-detects the
    // publisher's public IP and retries once, instead of telling a
    // user whose phone just moved from Wi-Fi to cellular that their
    // relay is broken.
    crate::commands::map_deploy_err(e)
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
        // Mint a publisher key pair and pre-provision row.
        let priv_alias = "pub.priv".to_string();
        let token_alias = "cloud.tok".to_string();
        let op_id = db
            .insert_pre_provision(
                r#"{"region":"fsn1","server_type":"cpx12","public_ip":"1.2.3.4","mgmt_port":42424}"#,
                "ab",
                &priv_alias,
                "hetzner",
                &token_alias,
                1_700_000_000,
            )
            .unwrap();
        // V012: every mgmt-plane call reads the helper IP off the row,
        // so the fixture has to look like a relay whose IP was detected.
        db.set_helper_ip(op_id, "1.2.3.4", "manual", 1_700_000_000)
            .unwrap();
        let mock = Arc::new(MockRunner::new(Pricing {
            provider: "hetzner".into(),
            region: "fsn1".into(),
            server_type: "cpx12".into(),
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
        // Secrets live in custody now, not the legacy PIN store.
        custody.put(&priv_alias, &[0u8; 64]).unwrap();
        custody.put(&token_alias, b"mock-token").unwrap();
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
            recipient_provision(&ctx, op_id, &sample_address(), "Alice")
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
        let err = recipient_provision(&ctx, op_id, "not-an-address", "Alice")
            .unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("recipient address"), "got: {msg}");
    }

    #[test]
    fn provision_uri_form_accepted() {
        let (ctx, _mock, op_id) = mk_ctx();
        let uri = format!("daal://{}", sample_address());
        let s = recipient_provision(&ctx, op_id, &uri, "Bahar").unwrap();
        assert_eq!(s.address_str, sample_address());
    }

    #[test]
    fn revoke_flips_local_row_and_calls_box() {
        let (ctx, mock, op_id) = mk_ctx();
        let s = recipient_provision(&ctx, op_id, &sample_address(), "Alice")
            .unwrap();
        let revoked = recipient_revoke(&ctx, op_id, s.id).unwrap();
        assert!(revoked.revoked_at_unix > 0);

        // Idempotent.
        let revoked_again = recipient_revoke(&ctx, op_id, s.id).unwrap();
        assert_eq!(revoked_again.revoked_at_unix, revoked.revoked_at_unix);

        // Mock runner saw the revoke call once (idempotent path
        // short-circuits the second call).
        let calls = mock.users_revoke_calls.lock().unwrap().clone();
        assert_eq!(calls, vec!["r1".to_string()]);
    }

    #[test]
    fn delete_requires_revoke_first_then_purges_row() {
        let (ctx, _mock, op_id) = mk_ctx();
        let s = recipient_provision(&ctx, op_id, &sample_address(), "Alice")
            .unwrap();

        // A live (never-revoked) recipient cannot be removed.
        let err = recipient_delete(&ctx, op_id, s.id).unwrap_err();
        assert!(
            format!("{err:?}").contains("revoke this recipient before removing"),
            "got: {err:?}"
        );
        assert_eq!(recipient_list(&ctx, op_id).unwrap().len(), 1);

        // After revoke, the greyed-out row can be purged for good.
        recipient_revoke(&ctx, op_id, s.id).unwrap();
        recipient_delete(&ctx, op_id, s.id).unwrap();
        assert!(recipient_list(&ctx, op_id).unwrap().is_empty());

        // A second delete on the vanished row surfaces as NotFound.
        let err = recipient_delete(&ctx, op_id, s.id).unwrap_err();
        assert!(matches!(err, WizardError::Db(DbError::NotFound(id)) if id == s.id));
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
        let err = recipient_provision(&ctx, op_id, &extra, "y").unwrap_err();
        assert!(format!("{err:?}").contains("max recipients"));
    }

    #[test]
    fn repack_reuses_the_existing_box_user_and_writes_the_sbpx() {
        // Regression: the relay-detail "Rebuild" affordance used to call
        // recipient_provision again for an address already on the
        // roster. That has no upsert path — it burns a fresh r<n>, mints
        // a SECOND live user on the box, and only then violates
        // UNIQUE(operator_id, pubkey), leaving an orphan credential the
        // app can never revoke. Every retry added another.
        let (ctx, mock, op_id) = mk_ctx();
        // The signed bundle is the rewrite's input; recipient_provision
        // silently skips the pack when it is absent, which is exactly
        // the state that puts a Rebuild button on screen.
        let r = recipient_provision(&ctx, op_id, &sample_address(), "Alice").unwrap();
        assert_eq!(r.name, "r1");
        assert!(r.sbpx_path.is_empty(), "fixture should have no .sbp yet");

        std::fs::write(ctx.staging_dir.join(format!("{op_id}.sbp")), b"signed-bundle").unwrap();
        let before = mock.users_provision_calls.lock().unwrap().len();

        let repacked = recipient_repack_sbpx(&ctx, op_id, r.id).unwrap();

        assert_eq!(repacked.id, r.id, "must be the same roster row");
        assert_eq!(repacked.name, "r1", "must reuse the same box user");
        assert!(!repacked.sbpx_path.is_empty(), "the .sbpx is the outcome");
        assert!(std::path::Path::new(&repacked.sbpx_path).exists());
        // Exactly one more box user minted, and under the SAME name —
        // the revoke-then-provision dance, not a second identity.
        let calls = mock.users_provision_calls.lock().unwrap().clone();
        assert_eq!(calls.len(), before + 1, "{calls:?}");
        assert_eq!(calls.last().unwrap(), "r1");
        assert_eq!(*mock.users_revoke_calls.lock().unwrap(), vec!["r1"]);
        // And the roster still holds exactly one recipient.
        assert_eq!(recipient_list(&ctx, op_id).unwrap().len(), 1);
    }

    #[test]
    fn repack_refuses_a_revoked_recipient() {
        // Rebuilding for someone who was deliberately cut off would hand
        // them a working credential again.
        let (ctx, _mock, op_id) = mk_ctx();
        let r = recipient_provision(&ctx, op_id, &sample_address(), "Alice").unwrap();
        recipient_revoke(&ctx, op_id, r.id).unwrap();

        let err = recipient_repack_sbpx(&ctx, op_id, r.id).unwrap_err();
        assert!(format!("{err:?}").contains("revoked"), "got: {err:?}");
    }
}
