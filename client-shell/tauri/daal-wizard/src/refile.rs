//! "New files for everyone": after a person is removed, make each
//! remaining person's file again so the standby code can be wrapped
//! again (wave 2, owner-approved leftover 3).
//!
//! Why it is needed. The standby code is sent wrapped only when every
//! person on the relay holds a file of the relay's current update
//! generation (`addon_standby::code_to_send`). Removing a person who
//! held that generation moves the relay to the next one
//! (`addon_standby::load_update_state`), so until every remaining person
//! has a NEW file the code goes out in its plain form, which anyone who
//! reads the message can use.
//!
//! What it does. One firewall window (`daal-deploy users-renew`, the
//! same verb `renew::renew_everyone` uses) that:
//!   * `--replace`s every person not removed, so the relay answers with
//!     the person's complete credentials (this phone does not keep all
//!     of them, so a file cannot be made without asking the relay);
//!   * `--revoke`s every removed person once more, so a removal the relay
//!     missed is caught here, never undone;
//!   * leaves the everyone file alone (with one, the code is always
//!     plain: this command refuses).
//! Each new file is written through the per-person pack path
//! (`recipient_book::merge_and_pack_sbpx`), which puts the current
//! generation's secret in it and records the holder once the helper
//! confirms it.
//!
//! A person restored from a backup whom nobody has answered for yet is
//! skipped (`needs_answer`), exactly as the renew does (PB-1).
//!
//! Each person's previous file stops working once their new one is made:
//! the relay re-keys them. The sheet says so before it starts.
//!
//! Nothing here logs credentials, secrets, names of notes or addresses.

use serde::{Deserialize, Serialize};

use crate::cli_bridge::{verb_unknown, BridgeError, UsersRenewArgs};
use crate::commands::{
    coded, custody_get, custody_get_string, map_deploy_err, require_helper_ip, Result, WizardCtx,
    WizardError, E_DEPLOY_TOO_OLD, E_RELAY_TOO_OLD, E_RELAY_UNREACHABLE,
};
use crate::operator_db::RecipientRow;

/// One person in the report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RefileItem {
    pub recipient_id: i64,
    pub name: String,
    pub display_name: String,
    /// `done` | `failed` | `not_attempted` | `needs_answer`.
    pub status: String,
    /// `""` | `relay_unreachable` | `relay_full` | `relay_too_old` |
    /// `file_write_failed` | `signing_failed` | `restore_unanswered` |
    /// `other`.
    pub reason: String,
    /// The new file, "" unless `done`.
    pub sbpx_path: String,
    /// Raw text, Details only. Never a credential.
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RefileReport {
    pub operator_id: i64,
    /// The people not removed, in roster order.
    pub items: Vec<RefileItem>,
    /// A removed person the relay could not drop (it may still let them
    /// in): never "all done".
    pub removal_failed: Vec<RefileItem>,
    pub all_done: bool,
    /// The standby code is now sent wrapped. False when the relay has no
    /// standby address, or someone still lacks a new file.
    pub code_wrapped: bool,
}

/// Whether the relay has (or had) a file for everyone; any doubt is yes
/// (the same rule as `addon_standby::everyone_file`).
fn has_everyone_file(ctx: &WizardCtx, op: i64) -> bool {
    ctx.staging_dir.join(format!("{op}.shared.sbp")).exists()
        || ctx.db.shared_box_fp(op).map(|f| !f.is_empty()).unwrap_or(true)
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
            "the setup helper bundled with this app cannot make new files for everyone",
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

/// Whether the standby code would now go out wrapped.
fn code_wrapped(ctx: &WizardCtx, op: i64) -> bool {
    crate::addon_standby::key(
        ctx,
        crate::addon_standby::StandbyKeyInput { operator_id: op },
        &mut |_| {},
    )
    .map(|k| k.form == "wrapped")
    .unwrap_or(false)
}

/// `wizard_refile_people`.
pub fn refile_people(ctx: &WizardCtx, operator_id: i64) -> Result<RefileReport> {
    let row = ctx.db.get(operator_id)?;
    if row.status != "provisioned" {
        return Err(WizardError::Validation(
            "only a relay whose setup finished can make new files".into(),
        ));
    }
    if has_everyone_file(ctx, operator_id) {
        // With a file for everyone the code is always plain, so new
        // files would cut everyone off for nothing.
        return Err(WizardError::Validation(
            "this relay has a file for everyone, so its code is always sent in the plain form"
                .into(),
        ));
    }
    let signed = ctx.staging_dir.join(format!("{operator_id}.sbp"));
    if !signed.exists() {
        return Err(WizardError::Validation(
            "this relay has no signed file yet; finish setting it up first".into(),
        ));
    }

    let rows = ctx.db.list_recipients(operator_id)?;
    // Roster order: oldest first, as the people list shows them.
    let mut live: Vec<&RecipientRow> = rows.iter().filter(|r| r.revoked_at_unix == 0).collect();
    live.sort_by_key(|r| (r.provisioned_at_unix, r.id));
    if live.is_empty() {
        return Err(WizardError::Validation(
            "nobody is on this relay, so there is no file to make".into(),
        ));
    }
    let waiting = crate::restore_settle::blocked_before_create(ctx, operator_id)?;
    let mut items: Vec<RefileItem> = live
        .iter()
        .map(|r| RefileItem {
            recipient_id: r.id,
            name: r.name.clone(),
            display_name: r.display_name.clone(),
            status: if waiting.contains(&r.id) { "needs_answer" } else { "not_attempted" }.into(),
            reason: if waiting.contains(&r.id) { "restore_unanswered" } else { "" }.into(),
            ..Default::default()
        })
        .collect();
    let replace: Vec<String> = live
        .iter()
        .filter(|r| !waiting.contains(&r.id))
        .map(|r| r.name.clone())
        .collect();
    let revoke: Vec<String> = rows
        .iter()
        .filter(|r| r.revoked_at_unix != 0)
        .map(|r| r.name.clone())
        .collect();
    if replace.is_empty() {
        // Everyone left waits for an answer: no window is opened.
        return Ok(RefileReport {
            operator_id,
            items,
            removal_failed: Vec::new(),
            all_done: false,
            code_wrapped: code_wrapped(ctx, operator_id),
        });
    }

    let helper_ip = require_helper_ip(ctx, operator_id)?;
    let priv_buf = custody_get(ctx, &row.publisher_priv_keystore_alias)?;
    let token = custody_get_string(ctx, &row.cloud_token_keystore_alias)?;
    let record_path =
        crate::recipient_book::write_record_staging(ctx, operator_id, &row.operator_record_json)?;
    let res = ctx.cli.run_users_renew(
        UsersRenewArgs {
            record_path: &record_path,
            helper_ip: &helper_ip,
            token: token.as_str(),
            ensure: &[],
            replace: &replace,
            revoke: &revoke,
        },
        priv_buf.as_slice(),
        &mut |_| {},
    );
    let _ = std::fs::remove_file(&record_path);
    let out = res.map_err(map_run_err)?;

    let mut removal_failed = Vec::new();
    for res in &out.results {
        if let Some(gone) = rows
            .iter()
            .find(|r| r.name == res.name && r.revoked_at_unix != 0)
        {
            if !res.ok {
                removal_failed.push(RefileItem {
                    recipient_id: gone.id,
                    name: gone.name.clone(),
                    display_name: gone.display_name.clone(),
                    status: "failed".into(),
                    reason: reason_of(&res.error_code).into(),
                    detail: res.error.clone(),
                    ..Default::default()
                });
            }
            continue;
        }
        let Some(slot) = items
            .iter_mut()
            .find(|i| i.name == res.name && i.status == "not_attempted")
        else {
            continue;
        };
        if !res.ok {
            slot.status = "failed".into();
            slot.reason = reason_of(&res.error_code).into();
            slot.detail = res.error.clone();
            continue;
        }
        match (res.action.as_str(), res.creds.as_ref()) {
            ("provisioned", Some(creds)) => {
                let Some(r) = live.iter().find(|r| r.id == slot.recipient_id) else {
                    continue;
                };
                write_one(ctx, operator_id, &row.operator_record_json, r, slot, creds);
            }
            ("provisioned", None) => {
                slot.status = "failed".into();
                slot.reason = "other".into();
                slot.detail = "the relay answered without credentials".into();
            }
            (other, _) => {
                slot.status = "failed".into();
                slot.reason = "other".into();
                slot.detail = format!("unexpected answer: {other}");
            }
        }
    }

    let all_done = items.iter().all(|i| i.status == "done") && removal_failed.is_empty();
    if all_done {
        // Everyone holds a file of the relay as it is now, the update
        // switches' carriers included: the note rows' "people need a new
        // file" line is answered.
        crate::addon_notes::clear_people_before(ctx, operator_id);
    }
    Ok(RefileReport {
        operator_id,
        items,
        removal_failed,
        all_done,
        code_wrapped: code_wrapped(ctx, operator_id),
    })
}

/// `wizard_refile_removals`: the sheet's «Try again» under a removal the
/// relay did not confirm. One firewall window that only `--revoke`s the
/// removed people again: nobody is re-keyed, no file is made, and no
/// question is asked again. `items` is empty; `removal_failed` lists who
/// the relay still did not drop.
pub fn refile_removals(ctx: &WizardCtx, operator_id: i64) -> Result<RefileReport> {
    let row = ctx.db.get(operator_id)?;
    if row.status != "provisioned" {
        return Err(WizardError::Validation(
            "only a relay whose setup finished can be asked to drop someone".into(),
        ));
    }
    let rows = ctx.db.list_recipients(operator_id)?;
    let revoke: Vec<String> = rows
        .iter()
        .filter(|r| r.revoked_at_unix != 0)
        .map(|r| r.name.clone())
        .collect();
    let mut report = RefileReport {
        operator_id,
        all_done: true,
        ..Default::default()
    };
    if revoke.is_empty() {
        report.code_wrapped = code_wrapped(ctx, operator_id);
        return Ok(report);
    }
    let helper_ip = require_helper_ip(ctx, operator_id)?;
    let priv_buf = custody_get(ctx, &row.publisher_priv_keystore_alias)?;
    let token = custody_get_string(ctx, &row.cloud_token_keystore_alias)?;
    let record_path =
        crate::recipient_book::write_record_staging(ctx, operator_id, &row.operator_record_json)?;
    let res = ctx.cli.run_users_renew(
        UsersRenewArgs {
            record_path: &record_path,
            helper_ip: &helper_ip,
            token: token.as_str(),
            ensure: &[],
            replace: &[],
            revoke: &revoke,
        },
        priv_buf.as_slice(),
        &mut |_| {},
    );
    let _ = std::fs::remove_file(&record_path);
    let out = res.map_err(map_run_err)?;
    for res in &out.results {
        let Some(gone) = rows
            .iter()
            .find(|r| r.name == res.name && r.revoked_at_unix != 0)
        else {
            continue;
        };
        if !res.ok {
            report.removal_failed.push(RefileItem {
                recipient_id: gone.id,
                name: gone.name.clone(),
                display_name: gone.display_name.clone(),
                status: "failed".into(),
                reason: reason_of(&res.error_code).into(),
                detail: res.error.clone(),
                ..Default::default()
            });
        }
    }
    report.all_done = report.removal_failed.is_empty();
    report.code_wrapped = code_wrapped(ctx, operator_id);
    Ok(report)
}

/// Store the fresh credentials, sign again if the relay moved, and write
/// the person's new file (which carries the current secret).
fn write_one(
    ctx: &WizardCtx,
    operator_id: i64,
    record_json: &str,
    r: &RecipientRow,
    slot: &mut RefileItem,
    creds: &crate::cli_bridge::UserCredsResult,
) {
    // The file on this phone carries the credentials the relay just
    // replaced: drop it first, so a failure below reads "no file" (and
    // the person's row offers "Make their file again"), never a dead
    // file that looks ready.
    let stale = ctx
        .staging_dir
        .join(format!("{operator_id}.{}.sbpx", r.name));
    let _ = std::fs::remove_file(&stale);
    if let Err(e) = ctx.db.update_recipient_creds(
        operator_id,
        r.id,
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
    if let Err(e) =
        crate::relay_identity::heal_after_reply(ctx, operator_id, &creds.into(), &mut |_| {})
    {
        slot.status = "failed".into();
        slot.reason = "signing_failed".into();
        slot.detail = e.to_string();
        return;
    }
    match crate::recipient_book::merge_and_pack_sbpx(
        ctx,
        operator_id,
        &r.name,
        &r.pubkey_x25519_hex,
        creds,
        record_json,
    ) {
        Ok(p) => {
            slot.status = "done".into();
            slot.sbpx_path = p.to_string_lossy().to_string();
        }
        Err(e) => {
            slot.status = "failed".into();
            slot.reason = "file_write_failed".into();
            slot.detail = e.to_string();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicI64, Ordering};
    use std::sync::Arc;

    use crate::addons::{AddonKind, AddonState, NewAddon};
    use crate::cli_bridge::{CliRunner, MockRunner, Pricing};
    use crate::commands::{provision_run, publisher_keygen, select_profile, set_helper_ip, store_cloud_token};
    use crate::device_custody::{DeviceCustody, FileCustody};
    use crate::keystore::Keystore;
    use crate::operator_db::OperatorDb;
    use crate::recipient_book::{recipient_provision, recipient_revoke};

    const FP: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const TOKEN: &str = "hcloud-test-token-do-not-leak-0002";
    const SALT: &str = "AAECAwQFBgcICQoL";
    const SB_IP: &str = "203.0.113.20";

    struct Fx {
        ctx: WizardCtx,
        mock: Arc<MockRunner>,
        _dir: tempfile::TempDir,
    }

    fn record() -> String {
        serde_json::json!({
            "provider":"hetzner","server_id":"123","region":"fsn1",
            "server_type":"cx22","public_ip":"203.0.113.7",
            "toolbox_profile":"iran-default",
            "enabled_families":["vless-reality"],
            "publisher_pub_key":"ABEiM0RVZneImaq7zN3u/wARIjNEVWZ3iJmqu8zd7v8=",
            "mgmt_port":42424,
            "mgmt_tls_fingerprint":FP,
            "candidates":[{"family":"vless-reality"}],
            "provisioned_at":"2026-11-19T10:00:00Z",
            "freshness_url":""
        })
        .to_string()
    }

    fn fx() -> Fx {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(OperatorDb::open_in_memory().unwrap());
        let ks = Arc::new(Keystore::new_in_memory(dir.path()));
        let staging_dir = dir.path().join("staging");
        std::fs::create_dir_all(&staging_dir).unwrap();
        let mock = Arc::new(
            MockRunner::new(Pricing {
                provider: "hetzner".into(),
                region: "fsn1".into(),
                server_type: "cx22".into(),
                hourly_eur: 0.005,
                monthly_eur: 3.85,
                included_traffic_tb_per_month: None,
                overage_eur_per_gb: None,
            })
            .with_provision_record(record()),
        );
        let cli: Arc<dyn CliRunner> = mock.clone();
        let clock = Arc::new(AtomicI64::new(1_800_000_000));
        let custody: Arc<dyn DeviceCustody> =
            Arc::new(FileCustody::static_test(dir.path()).unwrap());
        let ctx = WizardCtx {
            db,
            keystore: ks,
            journal_dir: dir.path().join("state").join("provision-journal"),
            staging_dir,
            cli,
            clock: Arc::new(move || clock.load(Ordering::SeqCst)),
            custody,
        };
        Fx { ctx, mock, _dir: dir }
    }

    /// A finished relay with a signed file and a ready standby address.
    fn relay(f: &Fx) -> i64 {
        let id = store_cloud_token(&f.ctx, "hetzner", TOKEN, None).unwrap();
        select_profile(&f.ctx, id, "fsn1", "cx22", "iran-default", vec!["vless-reality".into()])
            .unwrap();
        publisher_keygen(&f.ctx, id).unwrap();
        set_helper_ip(&f.ctx, id, "198.51.100.1", "manual").unwrap();
        provision_run(&f.ctx, id, "", &mut |_| {}).unwrap();
        std::fs::write(f.ctx.staging_dir.join(format!("{id}.sbp")), b"signed-bundle").unwrap();
        f.ctx
            .db
            .record_signed_sbp(id, "sha-test", "rp-refile", 1_800_000_000)
            .unwrap();
        let mut rec: serde_json::Value =
            serde_json::from_str(&f.ctx.db.get(id).unwrap().operator_record_json).unwrap();
        rec["standby"] =
            serde_json::json!({"floating_ip_id":"fip-sb","ip":SB_IP,"mode":"sealed","salt":SALT});
        f.ctx.db.update_record_json(id, &rec.to_string()).unwrap();
        crate::addons::insert(
            &f.ctx,
            &NewAddon {
                operator_id: id,
                kind: Some(AddonKind::Standby),
                state: Some(AddonState::Ready),
                provider_ids: Default::default(),
                monthly_cost_cents: 300,
                cost_currency: "EUR".into(),
                secret_alias: String::new(),
                detail: None,
            },
        )
        .unwrap();
        id
    }

    fn address(byte: u8) -> String {
        daal_recipient_addr::encode(&[byte; 32])
    }

    fn form(f: &Fx, op: i64) -> String {
        crate::addon_standby::key(
            &f.ctx,
            crate::addon_standby::StandbyKeyInput { operator_id: op },
            &mut |_| {},
        )
        .unwrap()
        .form
    }

    /// `n` people on the relay, each with a file; the first one removed.
    fn people(f: &Fx, op: i64, n: u8) -> Vec<i64> {
        let ids: Vec<i64> = (1..=n)
            .map(|i| {
                let s = recipient_provision(&f.ctx, op, &address(i), &format!("P{i}")).unwrap();
                f.mock.box_users.lock().unwrap().insert(s.name.clone());
                s.id
            })
            .collect();
        ids
    }

    #[test]
    fn after_a_removal_new_files_for_the_rest_wrap_the_code_again() {
        for n in [2u8, 11] {
            let f = fx();
            let op = relay(&f);
            let ids = people(&f, op, n);
            assert_eq!(form(&f, op), "wrapped", "every person's file carries the secret");

            recipient_revoke(&f.ctx, op, ids[0]).unwrap();
            assert_eq!(form(&f, op), "plain", "a removed holder: plain until the rest have new files");

            let report = refile_people(&f.ctx, op).unwrap();
            let call = f.mock.users_renew_calls.lock().unwrap().last().cloned().unwrap();
            assert!(call.ensure.is_empty());
            assert_eq!(call.replace.len(), (n - 1) as usize, "everyone not removed, once");
            assert_eq!(call.revoke, vec!["r1".to_string()], "the removed person only ever revoked");
            assert_eq!(report.items.len(), (n - 1) as usize);
            assert!(report.items.iter().all(|i| i.recipient_id != ids[0]));
            for i in &report.items {
                assert_eq!(i.status, "done", "{i:?}");
                assert!(std::path::Path::new(&i.sbpx_path).exists());
            }
            assert!(report.all_done);
            assert!(report.code_wrapped);
            assert_eq!(form(&f, op), "wrapped");
        }
    }

    #[test]
    fn one_remaining_person_is_enough() {
        let f = fx();
        let op = relay(&f);
        let ids = people(&f, op, 2);
        recipient_revoke(&f.ctx, op, ids[1]).unwrap();
        let report = refile_people(&f.ctx, op).unwrap();
        assert_eq!(report.items.len(), 1);
        assert_eq!(report.items[0].recipient_id, ids[0]);
        assert!(report.all_done && report.code_wrapped);
    }

    #[test]
    fn a_failed_person_keeps_the_code_plain_and_is_reported() {
        let f = fx();
        let op = relay(&f);
        let ids = people(&f, op, 3);
        recipient_revoke(&f.ctx, op, ids[0]).unwrap();
        f.mock
            .renew_fail_names
            .lock()
            .unwrap()
            .insert("r3".into(), "relay_full".into());
        let report = refile_people(&f.ctx, op).unwrap();
        let failed = report.items.iter().find(|i| i.name == "r3").unwrap();
        assert_eq!((failed.status.as_str(), failed.reason.as_str()), ("failed", "relay_full"));
        assert!(!report.all_done);
        assert!(!report.code_wrapped, "r3 still holds the old generation");
    }

    #[test]
    fn a_removal_the_relay_could_not_make_is_never_all_done() {
        let f = fx();
        let op = relay(&f);
        let ids = people(&f, op, 2);
        recipient_revoke(&f.ctx, op, ids[0]).unwrap();
        f.mock.box_users.lock().unwrap().insert("r1".into());
        f.mock
            .renew_fail_names
            .lock()
            .unwrap()
            .insert("r1".into(), "unreachable".into());
        let report = refile_people(&f.ctx, op).unwrap();
        assert_eq!(report.removal_failed.len(), 1);
        assert_eq!(report.removal_failed[0].reason, "relay_unreachable");
        assert!(!report.all_done);
    }

    #[test]
    fn try_again_only_revokes_and_re_keys_nobody() {
        let f = fx();
        let op = relay(&f);
        let ids = people(&f, op, 2);
        recipient_revoke(&f.ctx, op, ids[0]).unwrap();
        f.mock.box_users.lock().unwrap().insert("r1".into());
        f.mock
            .renew_fail_names
            .lock()
            .unwrap()
            .insert("r1".into(), "unreachable".into());
        let first = refile_people(&f.ctx, op).unwrap();
        assert_eq!(first.removal_failed.len(), 1);
        let before = f.mock.users_renew_calls.lock().unwrap().len();

        // Still refused: reported again, nobody re-keyed.
        let again = refile_removals(&f.ctx, op).unwrap();
        assert_eq!(again.removal_failed.len(), 1);
        assert!(!again.all_done && again.items.is_empty());
        {
            let calls = f.mock.users_renew_calls.lock().unwrap();
            assert_eq!(calls.len(), before + 1);
            let last = calls.last().unwrap();
            assert!(last.replace.is_empty(), "nobody re-keyed: {:?}", last.replace);
            assert_eq!(last.revoke, vec!["r1".to_string()]);
        }
        // The relay drops them now.
        f.mock.renew_fail_names.lock().unwrap().clear();
        let ok = refile_removals(&f.ctx, op).unwrap();
        assert!(ok.all_done && ok.removal_failed.is_empty());
    }

    #[test]
    fn refused_with_a_file_for_everyone_or_nobody_left() {
        let f = fx();
        let op = relay(&f);
        let ids = people(&f, op, 1);
        std::fs::write(f.ctx.staging_dir.join(format!("{op}.shared.sbp")), b"x").unwrap();
        assert!(refile_people(&f.ctx, op).is_err());
        std::fs::remove_file(f.ctx.staging_dir.join(format!("{op}.shared.sbp"))).unwrap();
        recipient_revoke(&f.ctx, op, ids[0]).unwrap();
        assert!(refile_people(&f.ctx, op).is_err(), "nobody left");
        assert!(
            f.mock.users_renew_calls.lock().unwrap().is_empty(),
            "the relay is not touched"
        );
    }

    #[test]
    fn relay_failures_are_coded_and_change_nothing() {
        let f = fx();
        let op = relay(&f);
        let ids = people(&f, op, 2);
        recipient_revoke(&f.ctx, op, ids[0]).unwrap();
        let file = f.ctx.staging_dir.join(format!("{op}.r2.sbpx"));
        assert!(file.exists());
        *f.mock.users_renew_error.lock().unwrap() = Some((1, "dial tcp: timeout".into()));
        let e = refile_people(&f.ctx, op).unwrap_err().to_string();
        assert!(e.starts_with("E_RELAY_UNREACHABLE"), "{e}");
        assert!(file.exists(), "a relay that did not answer leaves the files alone");
        *f.mock.users_renew_error.lock().unwrap() =
            Some((2, "unknown subcommand \"users-renew\"".into()));
        let e = refile_people(&f.ctx, op).unwrap_err().to_string();
        assert!(e.starts_with("E_DEPLOY_TOO_OLD"), "{e}");
    }
}
