//! Tests for the publisher-alone wave (D1-D5, shell side), driven
//! through the real command functions against `MockRunner`. Nothing here
//! reaches a cloud API or a relay.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use crate::cli_bridge::{
    AccountAuditReport, AddressOutcome, AuditedResourceRow, BridgeError, CliRunner,
    DecommissionResult, KnownRelayRow, MockRunner, Pricing, ProgressEvent, ResourceRef,
};
use crate::commands::{
    copy_pasteable, list_operators, map_provision_err, provision_run, publisher_keygen,
    relay_destroy, select_profile, set_helper_ip, store_cloud_token, WizardCtx, WizardError,
};
use crate::device_custody::{DeviceCustody, FileCustody};
use crate::keystore::Keystore;
use crate::operator_db::OperatorDb;
use crate::provision_journal;
use crate::recipient_book::{recipient_provision, recipient_revoke};
use crate::setup_recovery::{
    account_check, account_cleanup, account_items, recovery_from_audit, setup_recovery,
    setup_remove_server,
};

const FP_A: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const FP_B: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
const TOKEN: &str = "hcloud-test-token-do-not-leak-0001";

struct Fx {
    ctx: WizardCtx,
    mock: Arc<MockRunner>,
    clock: Arc<AtomicI64>,
    _dir: tempfile::TempDir,
}

fn record(server_id: &str, fp: &str) -> String {
    serde_json::json!({
        "provider":"hetzner","server_id":server_id,"region":"fsn1",
        "server_type":"cx22","public_ip":"203.0.113.7",
        "toolbox_profile":"iran-default",
        "enabled_families":["vless-reality"],
        "publisher_pub_key":"ABEiM0RVZneImaq7zN3u/wARIjNEVWZ3iJmqu8zd7v8=",
        "mgmt_port":42424,
        "mgmt_tls_fingerprint":fp,
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
        .with_provision_record(record("123", FP_A)),
    );
    let cli: Arc<dyn CliRunner> = mock.clone();
    let clock = Arc::new(AtomicI64::new(1_800_000_000));
    let c2 = clock.clone();
    let custody: Arc<dyn DeviceCustody> = Arc::new(FileCustody::static_test(dir.path()).unwrap());
    let ctx = WizardCtx {
        db,
        keystore: ks,
        journal_dir: dir.path().join("state").join("provision-journal"),
        staging_dir,
        cli,
        clock: Arc::new(move || c2.load(Ordering::SeqCst)),
        custody,
    };
    Fx {
        ctx,
        mock,
        clock,
        _dir: dir,
    }
}

/// A relay row the wizard has taken up to "ready to build".
fn pre_provision(f: &Fx, token: &str) -> i64 {
    let id = store_cloud_token(&f.ctx, "hetzner", token, None).unwrap();
    select_profile(&f.ctx, id, "fsn1", "cx22", "iran-default", vec!["vless-reality".into()])
        .unwrap();
    publisher_keygen(&f.ctx, id).unwrap();
    set_helper_ip(&f.ctx, id, "198.51.100.1", "manual").unwrap();
    id
}

/// A relay whose setup finished, with a signed file.
fn provisioned(f: &Fx) -> i64 {
    let id = pre_provision(f, TOKEN);
    provision_run(&f.ctx, id, "", &mut |_| {}).unwrap();
    std::fs::write(f.ctx.staging_dir.join(format!("{id}.sbp")), b"signed-bundle").unwrap();
    f.ctx.db.record_signed_sbp(id, "sha-test", "rp-test", 1_800_000_000).unwrap();
    id
}

fn address(byte: u8) -> String {
    daal_recipient_addr::encode(&[byte; 32])
}

fn jpath(f: &Fx, id: i64) -> std::path::PathBuf {
    provision_journal::prepare(&f.ctx.journal_dir, id).unwrap()
}

const KILLED_AFTER_SERVER: &str = r#"{"v":1,"ev":"begin","seq":1,"ts":"2026-11-19T10:00:00Z","provider":"hetzner","region":"fsn1","relay_name":"daal-fsn1-0011223344556677","existing_server_id":"","mode":"create"}
{"v":1,"ev":"intent","seq":2,"ts":"x","kind":"server","name":"daal-fsn1-0011223344556677"}
{"v":1,"ev":"created","seq":3,"ts":"x","kind":"server","id":"123","name":"daal-fsn1-0011223344556677","public_ip":"203.0.113.7"}
"#;

fn coded_prefix(e: &WizardError) -> String {
    e.to_string()
}

// ---------------------------------------------------------------- D1

#[test]
fn provision_passes_a_journal_in_durable_storage_and_deletes_it_only_on_success() {
    let f = fx();
    let id = pre_provision(&f, TOKEN);
    provision_run(&f.ctx, id, "", &mut |_| {}).unwrap();
    let paths = f.mock.provision_journal_paths.lock().unwrap().clone();
    let want = provision_journal::journal_path(&f.ctx.journal_dir, id);
    assert_eq!(paths, vec![Some(want.clone())]);
    assert!(!want.starts_with(&f.ctx.staging_dir), "journal must not live in the swept staging dir");
    assert!(!want.exists(), "a saved setup leaves no journal");

    // A failed run keeps what it journalled.
    let id2 = pre_provision(&f, TOKEN);
    *f.mock.provision_journal_text.lock().unwrap() = Some(KILLED_AFTER_SERVER.into());
    *f.mock.provision_fail.lock().unwrap() = Some((1, "health timeout".into()));
    assert!(provision_run(&f.ctx, id2, "", &mut |_| {}).is_err());
    assert!(provision_journal::journal_path(&f.ctx.journal_dir, id2).exists());
}

#[test]
fn a_setup_that_finished_while_the_app_was_gone_is_saved_without_renting_again() {
    let f = fx();
    let id = pre_provision(&f, TOKEN);
    let j = jpath(&f, id);
    let done = format!(
        "{}{}\n",
        KILLED_AFTER_SERVER,
        serde_json::json!({"v":1,"ev":"done","seq":4,"ts":"x",
            "record": serde_json::from_str::<serde_json::Value>(&record("123", FP_A)).unwrap()})
    );
    std::fs::write(&j, done).unwrap();
    // The recovery card says so, read-only.
    let r = setup_recovery(&f.ctx, id).unwrap();
    assert_eq!(r.state, "finished_unsaved");
    assert!(r.can_finish_here);

    provision_run(&f.ctx, id, "", &mut |_| {}).unwrap();
    assert_eq!(*f.mock.provision_calls.lock().unwrap(), 0, "no child, no second server");
    let row = f.ctx.db.get(id).unwrap();
    assert_eq!(row.status, "provisioned");
    assert_eq!(row.mgmt_tls_fingerprint, FP_A);
    assert!(row.operator_record_json.contains("\"123\""));
    assert!(!j.exists());
}

#[cfg(unix)]
#[test]
#[allow(clippy::incompatible_msrv)]
fn a_locked_journal_means_a_setup_is_still_running() {
    let f = fx();
    let id = pre_provision(&f, TOKEN);
    let j = jpath(&f, id);
    std::fs::write(&j, KILLED_AFTER_SERVER).unwrap();
    let holder = std::fs::OpenOptions::new().append(true).open(&j).unwrap();
    holder.lock().unwrap();

    let e = provision_run(&f.ctx, id, "", &mut |_| {}).unwrap_err();
    assert!(coded_prefix(&e).starts_with("E_SETUP_RUNNING"), "{e}");
    assert_eq!(*f.mock.provision_calls.lock().unwrap(), 0);
    let r = setup_recovery(&f.ctx, id).unwrap();
    assert_eq!(r.state, "running");
    assert_eq!(r.server_id, "123");
    let e = relay_destroy(&f.ctx, id, true).unwrap_err();
    assert!(coded_prefix(&e).starts_with("E_SETUP_RUNNING"), "{e}");
    let e = setup_remove_server(&f.ctx, id).unwrap_err();
    assert!(coded_prefix(&e).starts_with("E_SETUP_RUNNING"), "{e}");
    assert!(f.mock.decommission_calls.lock().unwrap().is_empty());
    drop(holder);
    *f.mock.account_audit_result.lock().unwrap() = Some(audit(true, "123", vec![]));
    assert_eq!(setup_recovery(&f.ctx, id).unwrap().state, "server_running");
}

#[test]
fn a_refusal_because_the_server_exists_carries_its_id() {
    let f = fx();
    let id = pre_provision(&f, TOKEN);
    let ev: ProgressEvent = serde_json::from_value(serde_json::json!({
        "step":"provision_error","message":"exists","code":"server_exists","server_id":"777"
    }))
    .unwrap();
    *f.mock.provision_fail_events.lock().unwrap() = vec![ev];
    *f.mock.provision_fail.lock().unwrap() = Some((4, "server exists".into()));
    let e = provision_run(&f.ctx, id, "", &mut |_| {}).unwrap_err().to_string();
    assert!(e.starts_with("E_SERVER_EXISTS: 777"), "{e}");
}

#[test]
fn provision_exit_codes_map_to_their_own_meanings() {
    let fail = |rc: i32| BridgeError::SubprocessFailed {
        rc,
        stderr: "x".into(),
    };
    assert!(map_provision_err(fail(3), None).to_string().starts_with("E_NOT_SUPPORTED"));
    let busy: ProgressEvent = serde_json::from_value(
        serde_json::json!({"step":"provision_error","code":"journal_busy","message":""}),
    )
    .unwrap();
    assert!(map_provision_err(fail(5), Some(&busy))
        .to_string()
        .starts_with("E_SETUP_RUNNING"));
    // rc 3 is NOT "relay too old" here.
    assert!(!map_provision_err(fail(3), None).to_string().contains("E_RELAY_TOO_OLD"));
}

#[test]
fn deleting_an_interrupted_setup_finds_the_server_in_the_journal() {
    let f = fx();
    let id = pre_provision(&f, TOKEN);
    let j = jpath(&f, id);
    std::fs::write(&j, KILLED_AFTER_SERVER).unwrap();
    let rep = relay_destroy(&f.ctx, id, true).unwrap();
    assert!(rep.local_removed && !rep.retry_needed);
    let calls = f.mock.decommission_calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    let sent: serde_json::Value = serde_json::from_str(&calls[0].record_json).unwrap();
    assert_eq!(sent["server_id"], "123", "the record had no server id; the journal did");
    assert!(calls[0].release_addresses);
    assert!(!j.exists());
}

/// Run 1 set up the person's own server 77 and failed its health wait
/// (no rollback on a server they own); run 2 rented one, which was
/// rolled back.
const OWN_THEN_RENTED: &str = r#"{"v":1,"ev":"begin","seq":1,"ts":"2026-11-19T10:00:00Z","provider":"hetzner","region":"fsn1","relay_name":"daal-fsn1-0011223344556677","existing_server_id":"77","mode":"rebuild_yours"}
{"v":1,"ev":"intent","seq":2,"ts":"x","kind":"rebuild","id":"77","name":"my-own-box"}
{"v":1,"ev":"failed","seq":3,"ts":"x","code":"health_timeout","rolled_back":false}
{"v":1,"ev":"begin","seq":1,"ts":"2026-11-19T10:10:00Z","provider":"hetzner","region":"fsn1","relay_name":"daal-fsn1-0011223344556677","existing_server_id":"","mode":"create"}
{"v":1,"ev":"intent","seq":2,"ts":"x","kind":"server","name":"daal-fsn1-0011223344556677"}
{"v":1,"ev":"created","seq":3,"ts":"x","kind":"server","id":"456","name":"daal-fsn1-0011223344556677","public_ip":"203.0.113.9"}
{"v":1,"ev":"deleted","seq":4,"ts":"x","kind":"server","id":"456"}
{"v":1,"ev":"failed","seq":5,"ts":"x","code":"health_timeout","rolled_back":true}
"#;

#[test]
fn the_persons_own_server_is_named_and_deleted_only_when_they_say_so() {
    let f = fx();
    let id = pre_provision(&f, TOKEN);
    std::fs::write(jpath(&f, id), OWN_THEN_RENTED).unwrap();
    // The card names their server, although the last run was a rental.
    let rec = setup_recovery(&f.ctx, id).unwrap();
    assert_eq!((rec.state.as_str(), rec.server_origin.as_str()), ("server_running", "yours"));
    assert_eq!(rec.server_id, "77");
    assert!(f.mock.account_audit_record_calls.lock().unwrap().is_empty());

    // A delete that was not "Delete my server" never names it.
    let _ = relay_destroy(&f.ctx, id, true);
    let calls = f.mock.decommission_calls.lock().unwrap().clone();
    let sent: serde_json::Value = serde_json::from_str(&calls[0].record_json).unwrap();
    assert_eq!(sent["server_id"], "", "never the person's own server by default");
}

#[test]
fn delete_my_server_takes_the_persons_own_server_from_the_journal() {
    let f = fx();
    let id = pre_provision(&f, TOKEN);
    std::fs::write(jpath(&f, id), OWN_THEN_RENTED).unwrap();
    crate::commands::relay_destroy_with(&f.ctx, id, true, true).unwrap();
    let calls = f.mock.decommission_calls.lock().unwrap().clone();
    let sent: serde_json::Value = serde_json::from_str(&calls[0].record_json).unwrap();
    assert_eq!(sent["server_id"], "77");
}

#[test]
fn an_unanswered_server_create_leaves_the_id_empty_so_the_name_is_looked_up() {
    let f = fx();
    let id = pre_provision(&f, TOKEN);
    // Run 1 created 123 (gone since); run 2 asked for a server and was
    // killed before the answer was written: 456 may bill under the name.
    let text = format!(
        "{KILLED_AFTER_SERVER}{}\n{}\n",
        r#"{"v":1,"ev":"begin","seq":1,"ts":"2026-11-19T10:10:00Z","provider":"hetzner","region":"fsn1","relay_name":"daal-fsn1-0011223344556677","existing_server_id":"","mode":"create"}"#,
        r#"{"v":1,"ev":"intent","seq":2,"ts":"x","kind":"server","name":"daal-fsn1-0011223344556677"}"#,
    );
    std::fs::write(jpath(&f, id), text).unwrap();
    relay_destroy(&f.ctx, id, true).unwrap();
    let calls = f.mock.decommission_calls.lock().unwrap().clone();
    let sent: serde_json::Value = serde_json::from_str(&calls[0].record_json).unwrap();
    assert_eq!(
        sent["server_id"], "",
        "a stale id would make decommission delete 123 (gone) and skip the name lookup"
    );
}

#[test]
fn removing_only_the_server_keeps_the_relay_ready_to_start_again() {
    let f = fx();
    let id = pre_provision(&f, TOKEN);
    let j = jpath(&f, id);
    std::fs::write(&j, KILLED_AFTER_SERVER).unwrap();
    let rep = setup_remove_server(&f.ctx, id).unwrap();
    assert!(!rep.local_removed);
    let row = f.ctx.db.get(id).unwrap();
    assert_eq!(row.status, "pre-provision");
    assert!(!row.cloud_token_keystore_alias.is_empty(), "token kept for the next try");
    assert!(!j.exists());
    let sent = &f.mock.decommission_calls.lock().unwrap()[0];
    assert!(sent.record_json.contains("\"123\""));
}

fn res(kind: &str, id: &str, relay: &str, verdict: &str, billing: bool) -> AuditedResourceRow {
    serde_json::from_value(serde_json::json!({
        "kind":kind,"id":id,"name":format!("{relay}-{kind}"),"verdict":verdict,
        "billing":billing,"relay":relay,"address": if kind=="server" {"203.0.113.7"} else {""},
        "reclaimable": verdict=="orphan"
    }))
    .unwrap()
}

fn audit(complete: bool, known_live: &str, resources: Vec<AuditedResourceRow>) -> AccountAuditReport {
    AccountAuditReport {
        provider: "hetzner".into(),
        resources,
        server_list_complete: complete,
        warnings: vec!["run `daal-deploy account-reclaim` to delete".into()],
        known: vec![KnownRelayRow {
            relay: "daal-fsn1-0011223344556677".into(),
            live_server_id: known_live.into(),
            record_index: Some(0),
            ..Default::default()
        }],
    }
}

#[test]
fn recovery_states_from_the_account() {
    let relay = "daal-fsn1-0011223344556677";
    let running = recovery_from_audit(
        "hetzner",
        &audit(true, "123", vec![res("server", "123", relay, "in-use", true), res("ssh-key", "9", relay, "orphan", false)]),
        None,
        0,
    );
    assert_eq!(running.state, "server_running");
    assert!(running.can_finish_here);
    assert_eq!(running.billing, "yes");
    assert_eq!(running.public_ip, "203.0.113.7");
    assert_eq!(running.leftovers.len(), 2);

    let vultr = recovery_from_audit("vultr", &audit(true, "123", vec![]), None, 0);
    assert_eq!(vultr.state, "server_running");
    assert!(!vultr.can_finish_here, "vultr cannot re-image in place");

    let nothing = recovery_from_audit("hetzner", &audit(true, "", vec![]), None, 0);
    assert_eq!((nothing.state.as_str(), nothing.billing.as_str()), ("nothing_billing", "no"));

    let billing_ip = recovery_from_audit(
        "hetzner",
        &audit(true, "", vec![res("floating-ip", "42", relay, "unclaimed", true)]),
        None,
        0,
    );
    assert_eq!((billing_ip.state.as_str(), billing_ip.billing.as_str()), ("nothing_billing", "yes"));

    let unreadable = recovery_from_audit("hetzner", &audit(false, "", vec![]), None, 0);
    assert_eq!(unreadable.state, "unknown");
    assert_eq!(unreadable.check_error, "account_unreadable");
}

#[test]
fn recovery_reads_the_journal_and_the_account() {
    let f = fx();
    // Not started: nothing to recover.
    let id = pre_provision(&f, TOKEN);
    assert_eq!(setup_recovery(&f.ctx, id).unwrap().state, "nothing_billing");
    // A provisioned relay never has a recovery card.
    let p = provisioned(&f);
    assert_eq!(setup_recovery(&f.ctx, p).unwrap().state, "none");

    // The person's own server: no account query (it is unlabelled).
    let j = jpath(&f, id);
    std::fs::write(
        &j,
        r#"{"v":1,"ev":"begin","ts":"2026-11-19T10:00:00Z","mode":"rebuild_yours","existing_server_id":"55"}
"#,
    )
    .unwrap();
    let calls_before = f.mock.account_audit_record_calls.lock().unwrap().len();
    let r = setup_recovery(&f.ctx, id).unwrap();
    assert_eq!((r.state.as_str(), r.server_origin.as_str(), r.server_id.as_str()), ("server_running", "yours", "55"));
    assert!(r.started_at_unix > 0);
    assert_eq!(f.mock.account_audit_record_calls.lock().unwrap().len(), calls_before);

    // A killed create: the audit is handed this row's record with the
    // journal's server id filled in, and the staged file is gone after.
    std::fs::write(&j, KILLED_AFTER_SERVER).unwrap();
    *f.mock.account_audit_result.lock().unwrap() = Some(audit(true, "123", vec![]));
    let r = setup_recovery(&f.ctx, id).unwrap();
    assert_eq!(r.state, "server_running");
    let (_, tok, bodies) = f.mock.account_audit_record_calls.lock().unwrap().last().cloned().unwrap();
    assert_eq!(tok, TOKEN);
    assert_eq!(bodies.len(), 1);
    assert!(bodies[0].contains("\"123\""), "{}", bodies[0]);
    assert!(!r.details.is_empty(), "warnings go to details only");
    let audit_dir = f.ctx.staging_dir.join("audit");
    assert_eq!(std::fs::read_dir(audit_dir).unwrap().count(), 0, "staged records removed");

    // The account cannot be read.
    *f.mock.account_audit_error.lock().unwrap() = Some((1, "dial tcp: i/o timeout".into()));
    let r = setup_recovery(&f.ctx, id).unwrap();
    assert_eq!(r.state, "unknown");
    assert_eq!(r.check_error, "offline");
    // What this phone journalled is still listed for the cancel sheet,
    // without claiming anything about the bill.
    assert_eq!(r.billing, "unknown");
    assert_eq!((r.server_id.as_str(), r.server_origin.as_str()), ("123", "created"));
    assert!(r.leftovers.iter().any(|l| l.kind == "server" && l.id == "123" && l.billing), "{r:?}");
}

#[test]
fn recovery_without_a_token() {
    let f = fx();
    // A row whose token was never stored (or was forgotten).
    let id = f
        .ctx
        .db
        .insert_pre_provision(&record("", ""), "ab", "priv", "hetzner", "", 1)
        .unwrap();
    assert_eq!(setup_recovery(&f.ctx, id).unwrap().state, "none");
    std::fs::write(jpath(&f, id), KILLED_AFTER_SERVER).unwrap();
    let r = setup_recovery(&f.ctx, id).unwrap();
    assert_eq!((r.state.as_str(), r.check_error.as_str()), ("unknown", "no_token"));
}

#[test]
fn the_account_check_groups_rows_by_token_and_never_shows_it() {
    let f = fx();
    let a = provisioned(&f);
    let b = pre_provision(&f, TOKEN);
    let c = pre_provision(&f, "another-account-token-0002");
    let check = account_check(&f.ctx).unwrap();
    assert_eq!(check.accounts.len(), 2, "{check:?}");
    let first = &check.accounts[0];
    assert_eq!(first.relay_ids, vec![a, b]);
    assert_eq!(first.account_key, format!("hetzner:{a}"));
    assert_eq!(check.accounts[1].relay_ids, vec![c]);
    let json = serde_json::to_string(&check).unwrap();
    assert!(!json.contains(TOKEN) && !json.contains("another-account-token"));
    // Every row on the provider is handed as a record to every audit:
    // a record protects what it names, whichever account it is in.
    for (_, _, bodies) in f.mock.account_audit_record_calls.lock().unwrap().iter() {
        assert_eq!(bodies.len(), 3);
    }
}

#[test]
fn account_findings_and_what_may_be_deleted() {
    let mut status = std::collections::HashMap::new();
    status.insert(10i64, "provisioned".to_string());
    status.insert(11i64, "pre-provision".to_string());
    let report = AccountAuditReport {
        provider: "hetzner".into(),
        server_list_complete: true,
        warnings: vec![],
        known: vec![
            KnownRelayRow { relay: "relay-a".into(), live_server_id: "1".into(), record_index: Some(0), ..Default::default() },
            KnownRelayRow { relay: "relay-b".into(), record_index: Some(1), ..Default::default() },
        ],
        resources: vec![
            res("server", "1", "relay-a", "in-use", true),
            res("server", "2", "relay-a", "unclaimed", true),
            res("server", "3", "relay-b", "unclaimed", true),
            res("server", "4", "relay-z", "unclaimed", true),
            res("ssh-key", "5", "relay-a", "orphan", false),
            res("floating-ip", "6", "relay-z", "unclaimed", true),
            res("server", "7", "", "unproven", true),
        ],
    };
    let items = account_items(&report, &[10, 11], &status);
    let find = |id: &str| items.iter().find(|i| i.id == id).unwrap();
    assert_eq!(find("1").finding, "yours_in_use");
    assert!(!find("1").can_delete);
    assert_eq!(find("2").finding, "second_server_for_relay");
    assert!(find("2").can_delete);
    assert_eq!(find("3").finding, "unfinished_setup");
    assert!(!find("3").can_delete, "the setup card handles it");
    assert_eq!(find("3").belongs_to_relay_id, Some(11));
    assert_eq!(find("4").finding, "not_on_this_phone");
    assert!(find("4").can_delete);
    assert_eq!(find("5").finding, "leftover");
    assert!(find("5").can_delete);
    assert!(
        !find("6").can_delete,
        "a record still names an unclaimed address; reclaim would always keep it"
    );
    assert_eq!(find("7").finding, "cannot_tell");
    assert!(!find("7").can_delete);

    let mut incomplete = report.clone();
    incomplete.server_list_complete = false;
    assert!(account_items(&incomplete, &[10, 11], &status).iter().all(|i| !i.can_delete));
}

#[test]
fn cleanup_sends_only_what_was_ticked() {
    let f = fx();
    let a = provisioned(&f);
    let key = format!("hetzner:{a}");
    let e = account_cleanup(&f.ctx, "hetzner:999", &[]).unwrap_err();
    assert!(matches!(e, WizardError::Validation(_)));
    let items = vec![
        ResourceRef { kind: "server".into(), id: "4".into() },
        ResourceRef { kind: "floating-ip".into(), id: "6".into() },
    ];
    let rep = account_cleanup(&f.ctx, &key, &items).unwrap();
    let call = f.mock.account_reclaim_calls.lock().unwrap()[0].clone();
    assert_eq!(call.only, items);
    assert!(call.include_unclaimed_servers);
    assert_eq!(call.records.len(), 1);
    assert_eq!(rep.outcomes.len(), 2);
    assert_eq!(rep.outcomes[1].code, "released");

    // Keys-only cleanup never asks to delete servers.
    account_cleanup(&f.ctx, &key, &[ResourceRef { kind: "ssh-key".into(), id: "5".into() }]).unwrap();
    assert!(!f.mock.account_reclaim_calls.lock().unwrap()[1].include_unclaimed_servers);
}

#[test]
fn list_operators_says_which_setups_stopped_and_which_have_a_token() {
    let f = fx();
    let id = pre_provision(&f, TOKEN);
    let s = list_operators(&f.ctx).unwrap();
    assert!(s[0].has_cloud_token);
    assert!(!s[0].setup_interrupted);
    std::fs::write(jpath(&f, id), KILLED_AFTER_SERVER).unwrap();
    assert!(list_operators(&f.ctx).unwrap()[0].setup_interrupted);
}

// ---------------------------------------------------------------- D4

#[test]
fn an_address_that_could_not_be_released_keeps_the_relay_for_a_retry() {
    let f = fx();
    let id = provisioned(&f);
    *f.mock.decommission_result.lock().unwrap() = Some(DecommissionResult {
        server_deleted: true,
        ssh_key_deleted: true,
        firewall_deleted: true,
        addresses: vec![
            AddressOutcome { id: "42".into(), ip: "198.51.100.9".into(), code: "release_failed".into(), ..Default::default() },
            AddressOutcome { id: "43".into(), ip: "198.51.100.10".into(), code: "not_daal".into(), ..Default::default() },
        ],
        retry_needed: true,
        ..Default::default()
    });
    let rep = relay_destroy(&f.ctx, id, true).unwrap();
    assert!(rep.retry_needed && !rep.local_removed);
    assert_eq!(rep.addresses.len(), 2);
    let row = f.ctx.db.get(id).unwrap();
    assert_eq!(row.status, "decommissioned");
    let s = list_operators(&f.ctx).unwrap();
    assert_eq!(s[0].unreleased_addresses, vec!["198.51.100.9".to_string()]);

    // Try again: the server is already gone (counts as deleted), the
    // address goes this time, and the relay is removed.
    *f.mock.decommission_result.lock().unwrap() = Some(DecommissionResult {
        server_deleted: true,
        ssh_key_deleted: true,
        firewall_deleted: true,
        addresses: vec![AddressOutcome { id: "42".into(), ip: "198.51.100.9".into(), released: true, code: "released".into(), ..Default::default() }],
        ..Default::default()
    });
    let rep = relay_destroy(&f.ctx, id, true).unwrap();
    assert!(rep.local_removed && !rep.retry_needed);
    assert!(f.ctx.db.get(id).is_err());
}

#[test]
fn a_not_daal_address_does_not_block_removal() {
    let f = fx();
    let id = provisioned(&f);
    *f.mock.decommission_result.lock().unwrap() = Some(DecommissionResult {
        server_deleted: true,
        ssh_key_deleted: true,
        firewall_deleted: true,
        addresses: vec![AddressOutcome { id: "43".into(), ip: "198.51.100.10".into(), code: "not_daal".into(), ..Default::default() }],
        ..Default::default()
    });
    let rep = relay_destroy(&f.ctx, id, true).unwrap();
    assert!(rep.local_removed);
    assert_eq!(rep.addresses[0].code, "not_daal");
}

// ---------------------------------------------------------------- D2

struct People {
    op: i64,
    alice: i64,
    bob: i64,
    carol: i64,
}

/// alice: on the box, file on the phone. bob: on the box, no file.
/// carol: removed.
fn people(f: &Fx) -> People {
    let op = provisioned(f);
    let alice = recipient_provision(&f.ctx, op, &address(1), "Alice").unwrap();
    let bob = recipient_provision(&f.ctx, op, &address(2), "Bob").unwrap();
    let carol = recipient_provision(&f.ctx, op, &address(3), "Carol").unwrap();
    recipient_revoke(&f.ctx, op, carol.id).unwrap();
    assert!(std::path::Path::new(&alice.sbpx_path).exists());
    std::fs::remove_file(&bob.sbpx_path).unwrap();
    {
        let mut users = f.mock.box_users.lock().unwrap();
        users.insert(alice.name.clone());
        users.insert(bob.name.clone());
    }
    People {
        op,
        alice: alice.id,
        bob: bob.id,
        carol: carol.id,
    }
}

fn renew(f: &Fx, op: i64) -> crate::renew::RenewReport {
    crate::renew::renew_everyone(&f.ctx, op, &mut |_| {}).unwrap()
}

#[test]
fn every_credential_write_stamps_the_box_it_was_minted_on() {
    let f = fx();
    let p = people(&f);
    let fps = f.ctx.db.recipient_box_fps(p.op).unwrap();
    assert_eq!(fps[&p.alice], FP_A, "provision stamps");
    f.ctx.db.record_mgmt_plane(p.op, 42424, FP_B).unwrap();
    assert_eq!(f.ctx.db.count_people_needing_renewal(p.op).unwrap(), 2, "carol is removed, not counted");
    crate::relay_rotation::rotate_credentials(&f.ctx, p.op, "r1").unwrap();
    assert_eq!(f.ctx.db.recipient_box_fps(p.op).unwrap()[&p.alice], FP_B, "rotate stamps");
    crate::recipient_book::recipient_repack_sbpx(&f.ctx, p.op, p.bob).unwrap();
    assert_eq!(f.ctx.db.recipient_box_fps(p.op).unwrap()[&p.bob], FP_B, "repack stamps");
    assert_eq!(f.ctx.db.count_people_needing_renewal(p.op).unwrap(), 0);
}

#[test]
fn renew_ensures_the_current_replaces_the_rest_and_only_ever_revokes_the_removed() {
    let f = fx();
    let p = people(&f);
    let report = renew(&f, p.op);
    let call = f.mock.users_renew_calls.lock().unwrap()[0].clone();
    assert_eq!(call.ensure, vec!["r1".to_string()], "marker current and file present");
    assert_eq!(call.replace, vec!["r2".to_string()], "no file on this phone");
    assert_eq!(call.revoke, vec!["r3".to_string()]);
    assert!(!call.ensure.contains(&"r3".to_string()) && !call.replace.contains(&"r3".to_string()));
    let by = |id: i64| report.items.iter().find(|i| i.recipient_id == Some(id)).unwrap();
    assert_eq!(by(p.alice).status, "already_done");
    assert_eq!(by(p.bob).status, "done");
    assert!(std::path::Path::new(&by(p.bob).sbpx_path).exists());
    // carol was not on the box: absent, so not reported at all.
    assert!(report.items.iter().all(|i| i.recipient_id != Some(p.carol)));
    assert!(report.everyone_file.is_none(), "never made, so never sent");
    assert!(report.all_done);
}

#[test]
fn after_a_rebuild_renew_recreates_everyone_once_and_a_second_press_writes_nothing() {
    let f = fx();
    let p = people(&f);
    crate::recipient_book::produce_shared_sbp(&f.ctx, p.op).unwrap();
    // The rebuild: a new box with nobody on it, and a new mgmt key.
    f.mock.box_users.lock().unwrap().clear();
    f.ctx.db.record_mgmt_plane(p.op, 42424, FP_B).unwrap();
    // A revoked person still known to the old box is irrelevant now,
    // but put carol on the new box to prove she is removed, not kept.
    f.mock.box_users.lock().unwrap().insert("r3".into());

    let mut events = Vec::new();
    let report = crate::renew::renew_everyone(&f.ctx, p.op, &mut |e| events.push(e)).unwrap();
    let call = f.mock.users_renew_calls.lock().unwrap()[0].clone();
    assert!(call.ensure.is_empty(), "{call:?}");
    assert_eq!(call.replace, vec!["r1".to_string(), "r2".to_string(), "r0".to_string()]);
    assert_eq!(call.revoke, vec!["r3".to_string()]);
    assert!(report.all_done, "{report:?}");
    assert_eq!(report.everyone_file.as_ref().unwrap().status, "done");
    let carol = report.items.iter().find(|i| i.recipient_id == Some(p.carol)).unwrap();
    assert_eq!(carol.status, "removed_from_server");
    assert_eq!(f.ctx.db.count_people_needing_renewal(p.op).unwrap(), 0);
    assert_eq!(f.ctx.db.shared_box_fp(p.op).unwrap(), FP_B);
    assert!(events.iter().any(|e| e.status == "working"));
    assert!(events.iter().any(|e| e.status == "done" && e.recipient_id == Some(p.alice)));
    assert!(!f.mock.box_users.lock().unwrap().contains("r3"));

    // Second press: everybody is current and has a file -> ensure only,
    // and the box is not written to at all.
    let writes = f.mock.renew_box_writes.lock().unwrap().len();
    let again = renew(&f, p.op);
    let call2 = f.mock.users_renew_calls.lock().unwrap()[1].clone();
    assert_eq!(call2.ensure, vec!["r1".to_string(), "r2".to_string(), "r0".to_string()]);
    assert!(call2.replace.is_empty());
    assert_eq!(f.mock.renew_box_writes.lock().unwrap().len(), writes, "nobody re-keyed");
    assert!(again.items.iter().filter(|i| i.recipient_id != Some(p.carol)).all(|i| i.status == "already_done"));
}

#[test]
fn a_file_that_could_not_be_written_is_redone_on_the_next_press_and_only_that_one() {
    let f = fx();
    let p = people(&f);
    f.mock.box_users.lock().unwrap().clear();
    f.ctx.db.record_mgmt_plane(p.op, 42424, FP_B).unwrap();
    // Make the pack step fail for everybody: no public_ip in the record.
    let row = f.ctx.db.get(p.op).unwrap();
    let mut rec: serde_json::Value = serde_json::from_str(&row.operator_record_json).unwrap();
    rec["public_ip"] = "".into();
    f.ctx.db.update_record_json(p.op, &rec.to_string()).unwrap();
    let alice_file = f.ctx.staging_dir.join(format!("{}.r1.sbpx", p.op));
    assert!(alice_file.exists());

    let report = renew(&f, p.op);
    let alice = report.items.iter().find(|i| i.recipient_id == Some(p.alice)).unwrap();
    assert_eq!((alice.status.as_str(), alice.reason.as_str()), ("failed", "file_write_failed"));
    assert!(!alice_file.exists(), "the dead file must not count as written");
    assert!(!report.all_done);

    // Fix the record; the next press replaces exactly the people whose
    // file is missing (both, here) and nobody's file that exists.
    f.ctx.db.update_record_json(p.op, &row.operator_record_json).unwrap();
    renew(&f, p.op);
    let call = f.mock.users_renew_calls.lock().unwrap()[1].clone();
    assert_eq!(call.replace, vec!["r1".to_string(), "r2".to_string()]);
    assert!(alice_file.exists());
}

#[test]
fn renew_failures_are_coded() {
    let f = fx();
    let p = people(&f);
    *f.mock.users_renew_error.lock().unwrap() = Some((1, "dial tcp: timeout".into()));
    let e = crate::renew::renew_everyone(&f.ctx, p.op, &mut |_| {}).unwrap_err().to_string();
    assert!(e.starts_with("E_RELAY_UNREACHABLE"), "{e}");
    *f.mock.users_renew_error.lock().unwrap() = Some((2, "unknown subcommand \"users-renew\"".into()));
    let e = crate::renew::renew_everyone(&f.ctx, p.op, &mut |_| {}).unwrap_err().to_string();
    assert!(e.starts_with("E_DEPLOY_TOO_OLD"), "{e}");
    *f.mock.users_renew_error.lock().unwrap() = None;
    f.mock.renew_fail_names.lock().unwrap().insert("r2".into(), "relay_full".into());
    f.mock.box_users.lock().unwrap().remove("r2");
    let r = renew(&f, p.op);
    let bob = r.items.iter().find(|i| i.recipient_id == Some(p.bob)).unwrap();
    assert_eq!((bob.status.as_str(), bob.reason.as_str()), ("failed", "relay_full"));
    assert!(!r.all_done);
}

#[test]
fn a_removed_person_the_relay_could_not_drop_is_reported_and_not_all_done() {
    let f = fx();
    let p = people(&f);
    // carol (r3) was removed on the phone but the relay still has her,
    // and the removal call fails this time.
    f.mock.box_users.lock().unwrap().insert("r3".into());
    f.mock.renew_fail_names.lock().unwrap().insert("r3".into(), "unreachable".into());
    let r = renew(&f, p.op);
    let carol = r
        .items
        .iter()
        .find(|i| i.recipient_id == Some(p.carol))
        .expect("a failed removal is reported");
    assert_eq!((carol.status.as_str(), carol.reason.as_str()), ("failed", "relay_unreachable"));
    assert!(!r.all_done, "a removed person may still get in");
}

#[test]
fn renew_needs_a_finished_relay() {
    let f = fx();
    let id = pre_provision(&f, TOKEN);
    assert!(matches!(
        crate::renew::renew_everyone(&f.ctx, id, &mut |_| {}),
        Err(WizardError::Validation(_))
    ));
}

// ---------------------------------------------------------------- D3

#[test]
fn the_health_check_runs_at_most_every_ten_minutes_unless_asked() {
    let f = fx();
    let p = people(&f);
    let h = crate::relay_health::relay_health(&f.ctx, p.op, false).unwrap();
    assert!(!h.from_cache);
    assert_eq!(h.overall, "working", "{h:?}");
    assert_eq!(h.people_missing, Some(0));
    f.clock.fetch_add(599, Ordering::SeqCst);
    let h2 = crate::relay_health::relay_health(&f.ctx, p.op, false).unwrap();
    assert!(h2.from_cache);
    assert_eq!(f.mock.relay_health_calls.lock().unwrap().len(), 1);
    crate::relay_health::relay_health(&f.ctx, p.op, true).unwrap();
    assert_eq!(f.mock.relay_health_calls.lock().unwrap().len(), 2, "Check now always runs");
    f.clock.fetch_add(601, Ordering::SeqCst);
    // The rebuilt box lost bob: counted, not the removed carol.
    f.mock.box_users.lock().unwrap().remove("r2");
    let h3 = crate::relay_health::relay_health(&f.ctx, p.op, false).unwrap();
    assert!(!h3.from_cache);
    assert_eq!(h3.people_missing, Some(1));
    assert_eq!(h3.everyone_missing, Some(false), "no everyone file was made");
    assert_eq!(f.mock.relay_health_calls.lock().unwrap().clone(), vec![true, true, true]);
}

#[test]
fn health_verdicts() {
    use crate::cli_bridge::{
        CommittedIdentity, HealthManagementLeg, HealthServerLeg, HealthWayLeg, RelayHealthReport,
    };
    use crate::relay_health::{assess, Expectations};
    let committed = CommittedIdentity {
        reality_public_key: "rk".into(),
        tls_cert_sha256: "tls-a".into(),
        cover_sni: "www.example.org".into(),
        ..Default::default()
    };
    let report = |server: &str, mgmt: &str, tls: &str, users: Option<Vec<&str>>, ways: &[&str]| RelayHealthReport {
        v: 1,
        server: HealthServerLeg { state: server.into(), error: String::new() },
        management: HealthManagementLeg {
            state: mgmt.into(),
            error: if mgmt == "no_answer" { "dial tcp 1.2.3.4:42424: i/o timeout".into() } else { String::new() },
            identity: Some(serde_json::json!({"reality_public_key":"rk","tls_cert_sha256":tls,"cover_sni":"www.example.org"})),
            users: users.map(|u| u.into_iter().map(String::from).collect()),
        },
        ways: ways
            .iter()
            .map(|s| HealthWayLeg { family: "vless-reality".into(), port: 443, udp: false, state: (*s).into(), error: String::new() })
            .chain(std::iter::once(HealthWayLeg { family: "hysteria2".into(), port: 443, udp: true, state: "not_testable_here".into(), error: String::new() }))
            .collect(),
        ..Default::default()
    };
    let live = vec!["r1".to_string(), "r2".to_string()];
    let fams = vec!["vless-reality".to_string()];
    let exp = Expectations { live_names: &live, everyone_file_exists: true, committed: Some(&committed), record_families: &fams };

    let ok = assess(1, 0, &report("running", "answers", "tls-a", Some(vec!["r0", "r1", "r2"]), &["answers"]), &exp);
    assert_eq!(ok.overall, "working");
    assert_eq!((ok.keys_match, ok.people_missing, ok.everyone_missing), (Some(true), Some(0), Some(false)));

    let changed = assess(1, 0, &report("running", "answers", "tls-b", Some(vec!["r1"]), &["answers"]), &exp);
    assert_eq!(changed.keys_match, Some(false));
    assert_eq!(changed.overall, "partly");
    assert_eq!((changed.people_missing, changed.everyone_missing), (Some(1), Some(true)));

    let gone = assess(1, 0, &report("missing", "no_answer", "tls-a", None, &["no_answer"]), &exp);
    assert_eq!(gone.overall, "not_working");
    assert_eq!(gone.people_missing, None);

    let dark = assess(1, 0, &report("not_checked", "no_answer", "tls-a", None, &["no_answer"]), &exp);
    assert_eq!(dark.overall, "not_working");
    assert_eq!(dark.management_reason, "address_may_have_changed");
    assert!(dark.details.iter().any(|d| d.contains("timeout")), "raw text in details");

    // A rebuilt relay that answers everything but knows none of the
    // people is not working: every file handed out is dead.
    let empty_box = assess(1, 0, &report("running", "answers", "tls-a", Some(vec!["r0"]), &["answers"]), &exp);
    assert_eq!((empty_box.people_missing, empty_box.everyone_missing), (Some(2), Some(false)));
    assert_eq!(empty_box.overall, "partly");
    let only_everyone_missing =
        assess(1, 0, &report("running", "answers", "tls-a", Some(vec!["r1", "r2"]), &["answers"]), &exp);
    assert_eq!(only_everyone_missing.everyone_missing, Some(true));
    assert_eq!(only_everyone_missing.overall, "partly");
    // Only the UDP way (not testable from here): nothing was seen to
    // answer, so not "working".
    let udp_only = assess(1, 0, &report("running", "answers", "tls-a", Some(vec!["r0", "r1", "r2"]), &[]), &exp);
    assert_eq!(udp_only.overall, "partly");

    let nothing = assess(1, 0, &report("not_checked", "not_checked", "tls-a", None, &[]), &exp);
    assert_eq!(nothing.overall, "unknown");
}

#[test]
fn health_needs_a_finished_relay_and_a_new_enough_helper() {
    let f = fx();
    let id = pre_provision(&f, TOKEN);
    assert!(matches!(crate::relay_health::relay_health(&f.ctx, id, true), Err(WizardError::Validation(_))));
    let p = provisioned(&f);
    *f.mock.relay_health_error.lock().unwrap() = Some((2, "unknown subcommand: relay-health".into()));
    let e = crate::relay_health::relay_health(&f.ctx, p, true).unwrap_err().to_string();
    assert!(e.starts_with("E_DEPLOY_TOO_OLD"), "{e}");
}

// ---------------------------------------------------------------- D5

#[test]
fn one_persons_file_is_handed_out_only_while_they_are_on_the_relay() {
    let f = fx();
    let p = people(&f);
    let text = copy_pasteable(&f.ctx, p.op, &format!("recipient:{}", p.alice)).unwrap();
    assert!(!text.is_empty());
    let e = copy_pasteable(&f.ctx, p.op, &format!("recipient:{}", p.carol)).unwrap_err();
    assert!(matches!(e, WizardError::Validation(_)), "removed person: {e}");
    let e = copy_pasteable(&f.ctx, p.op, &format!("recipient:{}", p.bob)).unwrap_err();
    assert!(e.to_string().starts_with("E_FILE_MISSING"), "{e}");
    let e = copy_pasteable(&f.ctx, p.op, "recipient:99999").unwrap_err();
    assert!(matches!(e, WizardError::Validation(_)));
    let e = copy_pasteable(&f.ctx, p.op, "recipient:abc").unwrap_err();
    assert!(matches!(e, WizardError::Validation(_)));
}
