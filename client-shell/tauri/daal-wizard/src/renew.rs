//! D2: "Renew everyone's files" after the relay's server was replaced.
//!
//! A rebuild (L4/L5/L6) gives the relay a new machine that knows none of
//! the people the publisher had added, so every file handed out stopped
//! working — and the per-person "Replace their file" button could not
//! help: it asks the relay to re-key a person it has never heard of, and
//! the relay answers 404. The publisher was left pressing a button per
//! person that could not work.
//!
//! One action now re-creates every person who was not removed, in one
//! firewall window (`daal-deploy users-renew`), and rewrites their
//! files. Safe to press twice, because each person's credentials carry
//! the management fingerprint of the box they were minted on
//! (`recipients.creds_box_fp`, V016):
//!
//!   * marker current AND their file on this phone -> `--ensure`: left
//!     alone if the relay knows them, created if it does not;
//!   * anything else -> `--replace`: created fresh;
//!   * a removed person -> only ever `--revoke`. Never re-created.
//!
//! The everyone file (`r0`) follows the same rule with
//! `operators.shared_box_fp`, and only if it was ever made.

use serde::{Deserialize, Serialize};

use crate::cli_bridge::{verb_unknown, BridgeError, ProgressEvent, UsersRenewArgs};
use crate::commands::{
    coded, custody_get, custody_get_string, map_deploy_err, require_helper_ip, Result, WizardCtx,
    WizardError, E_DEPLOY_TOO_OLD, E_RELAY_TOO_OLD, E_RELAY_UNREACHABLE,
};
use crate::operator_db::RecipientRow;
use crate::recipient_book::SHARED_USER_NAME;

/// One person (or the everyone file) in the report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RenewItem {
    /// `None` = the everyone file.
    pub recipient_id: Option<i64>,
    pub name: String,
    pub display_name: String,
    /// `done` | `already_done` | `failed` | `not_attempted` |
    /// `removed_from_server`.
    pub status: String,
    /// `""` | `relay_unreachable` | `relay_full` | `relay_too_old` |
    /// `file_write_failed` | `signing_failed` | `other`.
    pub reason: String,
    /// The person's file, "" for the everyone file and failures.
    pub sbpx_path: String,
    /// Raw text, Details only.
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RenewReport {
    pub operator_id: i64,
    pub items: Vec<RenewItem>,
    pub everyone_file: Option<RenewItem>,
    pub all_done: bool,
}

/// `wizard://renew-event` payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RenewEvent {
    pub operator_id: i64,
    pub index: usize,
    pub total: usize,
    pub recipient_id: Option<i64>,
    pub display_name: String,
    pub status: String,
}

/// What to send the relay.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct RenewPlan {
    pub ensure: Vec<String>,
    pub replace: Vec<String>,
    pub revoke: Vec<String>,
}

/// Decide `--ensure` / `--replace` / `--revoke` for every row.
///
/// `has_file(name)` says whether `<op>.<name>.sbpx` is on this phone.
/// `shared` is `Some(marker)` when the everyone file exists.
pub(crate) fn plan(
    rows: &[RecipientRow],
    markers: &std::collections::HashMap<i64, String>,
    current_fp: &str,
    has_file: &dyn Fn(&str) -> bool,
    shared: Option<&str>,
) -> RenewPlan {
    let mut p = RenewPlan::default();
    for r in rows {
        if r.revoked_at_unix != 0 {
            // A removed person is only ever removed again.
            p.revoke.push(r.name.clone());
            continue;
        }
        let current = markers.get(&r.id).map(String::as_str) == Some(current_fp)
            && !current_fp.is_empty();
        if current && has_file(&r.name) {
            p.ensure.push(r.name.clone());
        } else {
            p.replace.push(r.name.clone());
        }
    }
    if let Some(marker) = shared {
        if marker == current_fp && !current_fp.is_empty() {
            p.ensure.push(SHARED_USER_NAME.into());
        } else {
            p.replace.push(SHARED_USER_NAME.into());
        }
    }
    p
}

fn reason_of(error_code: &str) -> &'static str {
    match error_code {
        "unreachable" => "relay_unreachable",
        "relay_full" => "relay_full",
        "too_old" => "relay_too_old",
        _ => "other",
    }
}

fn map_run_err(e: BridgeError) -> WizardError {
    if verb_unknown(&e) {
        return coded(
            E_DEPLOY_TOO_OLD,
            "the setup helper bundled with this app cannot renew everyone's files",
        );
    }
    match &e {
        BridgeError::SubprocessFailed { rc: 1, stderr } => coded(
            E_RELAY_UNREACHABLE,
            format!("the relay did not answer, so nothing was changed: {}", stderr.trim()),
        ),
        BridgeError::SubprocessFailed { rc: 3, stderr } => coded(E_RELAY_TOO_OLD, stderr.trim()),
        _ => map_deploy_err(e),
    }
}

/// `wizard_renew_everyone`.
pub fn renew_everyone(
    ctx: &WizardCtx,
    operator_id: i64,
    on_event: &mut dyn FnMut(RenewEvent),
) -> Result<RenewReport> {
    let row = ctx.db.get(operator_id)?;
    if row.status != "provisioned" {
        return Err(WizardError::Validation(
            "only a relay whose setup finished can renew files".into(),
        ));
    }
    let helper_ip = require_helper_ip(ctx, operator_id)?;
    let signed = ctx.staging_dir.join(format!("{operator_id}.sbp"));
    if !signed.exists() {
        return Err(WizardError::Validation(
            "this relay has no signed file yet; finish setting it up first".into(),
        ));
    }
    let priv_buf = custody_get(ctx, &row.publisher_priv_keystore_alias)?;
    let token = custody_get_string(ctx, &row.cloud_token_keystore_alias)?;

    let rows = ctx.db.list_recipients(operator_id)?;
    let markers = ctx.db.recipient_box_fps(operator_id)?;
    let current_fp = row.mgmt_tls_fingerprint.clone();
    let sbpx = |name: &str| ctx.staging_dir.join(format!("{operator_id}.{name}.sbpx"));
    let shared_path = ctx.staging_dir.join(format!("{operator_id}.shared.sbp"));
    let shared_marker = if shared_path.exists() {
        Some(ctx.db.shared_box_fp(operator_id)?)
    } else {
        None
    };
    let plan = plan(
        &rows,
        &markers,
        &current_fp,
        &|n| sbpx(n).exists(),
        shared_marker.as_deref(),
    );

    // Order the report: live people, then the everyone file. Removed
    // people appear only if the relay still had them.
    let live: Vec<&RecipientRow> = rows.iter().filter(|r| r.revoked_at_unix == 0).collect();
    let total = live.len() + usize::from(shared_marker.is_some());
    let index_of = |name: &str| -> Option<(usize, Option<i64>, String)> {
        if name == SHARED_USER_NAME {
            return shared_marker.as_ref().map(|_| (live.len(), None, String::new()));
        }
        live.iter()
            .position(|r| r.name == name)
            .map(|i| (i, Some(live[i].id), live[i].display_name.clone()))
    };
    let mut emit = |name: &str, status: &str| {
        if let Some((index, rid, display_name)) = index_of(name) {
            on_event(RenewEvent {
                operator_id,
                index,
                total,
                recipient_id: rid,
                display_name,
                status: status.into(),
            });
        }
    };

    let record_path =
        crate::recipient_book::write_record_staging(ctx, operator_id, &row.operator_record_json)?;
    let res = ctx.cli.run_users_renew(
        UsersRenewArgs {
            record_path: &record_path,
            helper_ip: &helper_ip,
            token: token.as_str(),
            ensure: &plan.ensure,
            replace: &plan.replace,
            revoke: &plan.revoke,
        },
        priv_buf.as_slice(),
        &mut |ev: ProgressEvent| {
            if ev.step == "renew_user" {
                let name = ev.extra.get("name").and_then(|v| v.as_str()).unwrap_or("");
                emit(name, "working");
            }
        },
    );
    let _ = std::fs::remove_file(&record_path);
    let out = res.map_err(map_run_err)?;

    let mut items: Vec<RenewItem> = live
        .iter()
        .map(|r| RenewItem {
            recipient_id: Some(r.id),
            name: r.name.clone(),
            display_name: r.display_name.clone(),
            status: "not_attempted".into(),
            ..Default::default()
        })
        .collect();
    let mut everyone = shared_marker.as_ref().map(|_| RenewItem {
        recipient_id: None,
        name: SHARED_USER_NAME.into(),
        status: "not_attempted".into(),
        ..Default::default()
    });

    for res in &out.results {
        // Removed people: report only that the relay dropped them.
        if let Some(rev) = rows
            .iter()
            .find(|r| r.name == res.name && r.revoked_at_unix != 0)
        {
            if res.ok && res.action == "revoked" {
                items.push(RenewItem {
                    recipient_id: Some(rev.id),
                    name: rev.name.clone(),
                    display_name: rev.display_name.clone(),
                    status: "removed_from_server".into(),
                    ..Default::default()
                });
            } else if !res.ok {
                // The relay may still let a removed person in: that is
                // never "all done", and the sheet must say who.
                items.push(RenewItem {
                    recipient_id: Some(rev.id),
                    name: rev.name.clone(),
                    display_name: rev.display_name.clone(),
                    status: "failed".into(),
                    reason: reason_of(&res.error_code).into(),
                    detail: res.error.clone(),
                    ..Default::default()
                });
            }
            continue;
        }
        let slot: &mut RenewItem = if res.name == SHARED_USER_NAME {
            match everyone.as_mut() {
                Some(e) => e,
                None => continue,
            }
        } else {
            match items.iter_mut().find(|i| i.name == res.name && i.recipient_id.is_some()) {
                Some(i) => i,
                None => continue,
            }
        };
        if !res.ok {
            slot.status = "failed".into();
            slot.reason = reason_of(&res.error_code).into();
            slot.detail = res.error.clone();
        } else if res.action == "kept" {
            slot.status = "already_done".into();
            if slot.recipient_id.is_some() {
                slot.sbpx_path = sbpx(&slot.name).to_string_lossy().to_string();
            }
        } else if res.action == "provisioned" {
            match res.creds.as_ref() {
                None => {
                    slot.status = "failed".into();
                    slot.reason = "other".into();
                    slot.detail = "the relay answered without credentials".into();
                }
                Some(creds) => {
                    store_and_write(ctx, operator_id, &row.operator_record_json, &rows, slot, creds)
                }
            }
        } else {
            slot.status = "failed".into();
            slot.reason = "other".into();
            slot.detail = format!("unexpected answer: {}", res.action);
        }
        let (name, status) = (slot.name.clone(), slot.status.clone());
        emit(&name, &status);
    }

    let fine = |s: &str| matches!(s, "done" | "already_done" | "removed_from_server");
    let all_done = items.iter().all(|i| fine(&i.status))
        && everyone.as_ref().map(|e| fine(&e.status)).unwrap_or(true);
    Ok(RenewReport {
        operator_id,
        items,
        everyone_file: everyone,
        all_done,
    })
}

/// Store fresh credentials (and, in the same statement, the box marker),
/// re-sign if the relay moved, and write the file.
fn store_and_write(
    ctx: &WizardCtx,
    operator_id: i64,
    record_json: &str,
    rows: &[RecipientRow],
    slot: &mut RenewItem,
    creds: &crate::cli_bridge::UserCredsResult,
) {
    if let Some(rid) = slot.recipient_id {
        // The file on this phone carries the credentials being replaced
        // and stops working the moment the relay mints new ones. Drop it
        // FIRST: if writing the new file fails below, the next press
        // must see "no file" and re-create this person (`--replace`),
        // not "current marker + a file" and keep the dead one.
        let stale = ctx
            .staging_dir
            .join(format!("{operator_id}.{}.sbpx", slot.name));
        let _ = std::fs::remove_file(&stale);
        if let Err(e) = ctx.db.update_recipient_creds(
            operator_id,
            rid,
            &creds.vless_uuid,
            &creds.reality_short_id,
            &creds.hy2_password,
            &creds.naive_password,
            &creds.ws_path,
            creds.provisioned_at_unix,
        ) {
            slot.status = "failed".into();
            slot.reason = "other".into();
            slot.detail = e.to_string();
            return;
        }
    }
    if let Err(e) =
        crate::relay_identity::heal_after_reply(ctx, operator_id, &creds.into(), &mut |_| {})
    {
        slot.status = "failed".into();
        slot.reason = "signing_failed".into();
        slot.detail = e.to_string();
        return;
    }
    let written = match slot.recipient_id {
        Some(rid) => {
            let Some(r) = rows.iter().find(|r| r.id == rid) else {
                return;
            };
            crate::recipient_book::merge_and_pack_sbpx(
                ctx,
                operator_id,
                &r.name,
                &r.pubkey_x25519_hex,
                creds,
                record_json,
            )
            .map(|p| p.to_string_lossy().to_string())
        }
        None => crate::recipient_book::rewrite_shared_sbp(ctx, operator_id, creds, record_json)
            .and_then(|_| {
                // Only a written everyone file is stamped: a failure
                // here means the next press replaces r0 again.
                ctx.db
                    .stamp_shared_box_fp(operator_id)
                    .map_err(WizardError::Db)?;
                Ok(String::new())
            }),
    };
    match written {
        Ok(path) => {
            slot.status = "done".into();
            slot.sbpx_path = path;
        }
        Err(e) => {
            slot.status = "failed".into();
            slot.reason = "file_write_failed".into();
            slot.detail = e.to_string();
        }
    }
}
