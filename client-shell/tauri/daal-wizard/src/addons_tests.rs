//! The add-on ledger (V019) and its plumbing, driven through the real
//! command functions against `MockRunner`. Nothing reaches a cloud API
//! or a relay.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use super::*;
use crate::cli_bridge::{verb_unknown, AddonCliRequest, CliRunner, MockRunner, Pricing};
use crate::commands::{
    provision_run, publisher_keygen, relay_destroy, select_profile, set_helper_ip,
    store_cloud_token, WizardCtx,
};
use crate::device_custody::{CustodyError, DeviceCustody, FileCustody};
use crate::keystore::Keystore;
use crate::operator_db::OperatorDb;

const FP: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const TOKEN: &str = "hcloud-addon-test-token-0001";
const CF_TOKEN: &[u8] = b"cf-addon-test-token-do-not-leak";

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
    let custody: Arc<dyn DeviceCustody> = Arc::new(FileCustody::static_test(dir.path()).unwrap());
    let ctx = WizardCtx {
        db: Arc::new(OperatorDb::open_in_memory().unwrap()),
        keystore: Arc::new(Keystore::new_in_memory(dir.path())),
        journal_dir: dir.path().join("state").join("provision-journal"),
        staging_dir,
        cli,
        clock: Arc::new(move || clock.fetch_add(1, Ordering::SeqCst)),
        custody,
    };
    Fx { ctx, mock, _dir: dir }
}

/// A relay whose setup finished.
fn provisioned(f: &Fx) -> i64 {
    let id = store_cloud_token(&f.ctx, "hetzner", TOKEN, None).unwrap();
    select_profile(&f.ctx, id, "fsn1", "cx22", "iran-default", vec!["vless-reality".into()])
        .unwrap();
    publisher_keygen(&f.ctx, id).unwrap();
    set_helper_ip(&f.ctx, id, "198.51.100.1", "manual").unwrap();
    provision_run(&f.ctx, id, "", &mut |_| {}).unwrap();
    id
}

fn standby(op: i64) -> NewAddon {
    NewAddon {
        operator_id: op,
        kind: Some(AddonKind::Standby),
        state: Some(AddonState::Ready),
        provider_ids: BTreeMap::from([("floating_ip_id".to_string(), "777".to_string())]),
        monthly_cost_cents: 300,
        cost_currency: "EUR".into(),
        ..Default::default()
    }
}

/// A CDN add-on with its token in custody under its own alias.
fn cdn_with_secret(f: &Fx, op: i64) -> AddonRow {
    let id = insert(
        &f.ctx,
        &NewAddon {
            operator_id: op,
            kind: Some(AddonKind::Cdn),
            state: Some(AddonState::Ready),
            ..Default::default()
        },
    )
    .unwrap();
    let alias = secret_alias(id, AddonKind::Cdn);
    f.ctx.custody.put(&alias, CF_TOKEN).unwrap();
    set_secret_alias(&f.ctx, id, &alias).unwrap();
    get(&f.ctx, id).unwrap()
}

fn noop() -> impl FnMut(AddonProgress) {
    |_| {}
}

// ------------------------------------------------------------ the table

#[test]
fn a_relay_starts_with_no_addons_and_lists_what_is_written() {
    let f = fx();
    let op = provisioned(&f);
    assert!(list(&f.ctx, op).unwrap().is_empty());

    let id = insert(&f.ctx, &standby(op)).unwrap();
    let rows = list(&f.ctx, op).unwrap();
    assert_eq!(rows.len(), 1);
    let r = &rows[0];
    assert_eq!((r.id, r.operator_id, r.kind, r.state), (id, op, AddonKind::Standby, AddonState::Ready));
    assert_eq!(r.provider_ids.get("floating_ip_id").map(String::as_str), Some("777"));
    assert_eq!((r.monthly_cost_cents, r.cost_currency.as_str()), (300, "EUR"));
    assert!(!r.has_secret);
    assert_eq!(r.detail, serde_json::json!({}));

    set_state(&f.ctx, id, AddonState::Removing).unwrap();
    set_detail(&f.ctx, id, &serde_json::json!({"mode":"sealed"})).unwrap();
    let r = get(&f.ctx, id).unwrap();
    assert_eq!(r.state, AddonState::Removing);
    assert_eq!(r.detail["mode"], "sealed");
    assert!(r.updated_at_unix >= r.created_at_unix);
}

#[test]
fn the_ui_sees_that_a_secret_exists_never_its_alias() {
    let f = fx();
    let op = provisioned(&f);
    let row = cdn_with_secret(&f, op);
    assert!(row.has_secret);
    let j = serde_json::to_value(&row).unwrap();
    assert_eq!(j["has_secret"], true);
    assert_eq!(j["kind"], "cdn");
    assert_eq!(j["state"], "ready");
    assert!(j.get("secret_alias").is_none(), "{j}");
    assert!(!j.to_string().contains("daal.addon."));
}

#[test]
fn one_live_addon_of_a_kind_per_relay_but_a_promoted_standby_does_not_count() {
    let f = fx();
    let op = provisioned(&f);
    let first = insert(&f.ctx, &standby(op)).unwrap();
    assert!(insert(&f.ctx, &standby(op)).is_err(), "a second live standby");
    // A Google channel beside it is fine.
    insert(
        &f.ctx,
        &NewAddon { operator_id: op, kind: Some(AddonKind::Google), ..Default::default() },
    )
    .unwrap();
    // Promoted: it is the relay's address now; a new standby may be rented.
    set_state(&f.ctx, first, AddonState::Promoted).unwrap();
    insert(&f.ctx, &standby(op)).unwrap();
    assert_eq!(list(&f.ctx, op).unwrap().len(), 3);
    // The database enforces it too, whatever the caller checks.
    let raw = f.ctx.db.with_conn(|c| {
        c.execute(
            "INSERT INTO relay_addons (operator_id, kind, state, created_at_unix)
             VALUES (?1, 'standby', 'building', 1)",
            rusqlite::params![op],
        )
    });
    assert!(raw.is_err());
}

#[test]
fn a_row_needs_a_kind_and_a_relay_that_exists() {
    let f = fx();
    let op = provisioned(&f);
    assert!(insert(&f.ctx, &NewAddon { operator_id: op, ..Default::default() }).is_err());
    assert!(insert(&f.ctx, &standby(op + 99)).is_err());
    assert!(list(&f.ctx, op + 99).is_err());
    assert!(get(&f.ctx, 4242).is_err());
    assert!(set_state(&f.ctx, 4242, AddonState::Ready).is_err());
}

#[test]
fn forgetting_an_addon_drops_its_row_and_its_secret_and_can_be_repeated() {
    let f = fx();
    let op = provisioned(&f);
    let row = cdn_with_secret(&f, op);
    forget(&f.ctx, row.id).unwrap();
    assert!(list(&f.ctx, op).unwrap().is_empty());
    assert!(matches!(f.ctx.custody.get(&row.secret_alias), Err(CustodyError::NotFound(_))));
    forget(&f.ctx, row.id).unwrap();
}

#[test]
fn a_relay_row_that_goes_takes_its_addon_rows_with_it() {
    let f = fx();
    let op = provisioned(&f);
    insert(&f.ctx, &standby(op)).unwrap();
    f.ctx.db.delete(op).unwrap();
    let n: i64 = f
        .ctx
        .db
        .with_conn(|c| c.query_row("SELECT COUNT(*) FROM relay_addons", [], |r| r.get(0)))
        .unwrap();
    assert_eq!(n, 0);
}

#[test]
fn panic_wipe_finds_an_addons_secret() {
    let f = fx();
    let op = provisioned(&f);
    let row = cdn_with_secret(&f, op);
    assert!(f.ctx.db.list_all_keystore_aliases().unwrap().contains(&row.secret_alias));
}

// ------------------------------------------------------------ the stubs

#[test]
fn every_addon_is_built_and_a_helper_without_its_verbs_changes_nothing() {
    let f = fx();
    let op = provisioned(&f);
    let c = &f.ctx;
    // The standby add-on is built (L-standby-pub): addon_standby_tests.rs.
    // The Google add-on is built (L-google-pub): addon_google_tests.rs.
    // The Cloudflare add-on is built (L-ui, B-7): addon_cdn_tests.rs. With
    // no `cdn-*` verb in the helper it says so, and nothing is made.
    use crate::addon_cdn as cdn;
    let e = cdn::set_token(
        c,
        cdn::CdnTokenInput { operator_id: op, token: "x".into(), zone: String::new() },
        &mut noop(),
    )
    .unwrap_err();
    assert!(e.to_string().starts_with("E_DEPLOY_TOO_OLD: "), "{e}");
    let e = cdn::build(c, cdn::CdnBuildInput { operator_id: op, zone: "example.com".into() }, &mut noop())
        .unwrap_err();
    assert!(e.to_string().starts_with("E_CDN_NO_TOKEN: "), "{e}");
    assert!(cdn::posture(c, cdn::CdnPostureInput { operator_id: op, test: true }, &mut noop()).is_err());
    assert!(cdn::set_plain_fallback(c, cdn::CdnPlainFallbackInput { operator_id: op, allow: true }, &mut noop())
        .is_err());
    assert!(list(c, op).unwrap().is_empty());
    assert_eq!(f.mock.addon_calls.lock().unwrap().len(), 1, "only the key check ran the helper");
}

#[test]
fn removing_a_kind_hands_the_row_to_its_module() {
    let f = fx();
    let op = provisioned(&f);
    // A Cloudflare row that never got as far as Cloudflare: nothing to
    // take down, so the row goes.
    let cdn = cdn_with_secret(&f, op);
    let sb = insert(&f.ctx, &standby(op)).unwrap();
    let g = insert(
        &f.ctx,
        &NewAddon { operator_id: op, kind: Some(AddonKind::Google), ..Default::default() },
    )
    .unwrap();
    // The standby kind is built; its removal is tested in addon_standby_tests.rs.
    let _ = sb;
    // The Google kind is built; its removal is tested in addon_google_tests.rs.
    let _ = g;
    let rep = remove(&f.ctx, cdn.id, &mut noop()).unwrap();
    assert!(rep.removed);
    assert_eq!(list(&f.ctx, op).unwrap().len(), 2);
    assert!(f.ctx.custody.get(&cdn.secret_alias).is_err(), "forgotten with its row");
    assert!(remove(&f.ctx, 4242, &mut noop()).is_err(), "no such add-on");
}

// ------------------------------------------------------------ relay delete

#[test]
fn deleting_a_relay_with_no_addons_is_as_before() {
    let f = fx();
    let op = provisioned(&f);
    let rep = relay_destroy(&f.ctx, op, true).unwrap();
    assert!(rep.server_deleted && rep.local_removed && !rep.retry_needed);
    assert!(rep.addons.is_empty());
    let j = serde_json::to_value(&rep).unwrap();
    assert_eq!(j["addons"], serde_json::json!([]));
}

#[test]
fn an_addon_that_cannot_be_taken_down_yet_keeps_the_relay_but_not_the_server() {
    let f = fx();
    let op = provisioned(&f);
    let cdn = cdn_with_secret(&f, op);
    // A front Cloudflare still holds, and a key to take it down with; the
    // helper here has no `cdn-remove`, so the teardown fails.
    set_detail(&f.ctx, cdn.id, &serde_json::json!({"front": {"hostname": "a.example.com", "zone_id": "z"}}))
        .unwrap();
    f.ctx.custody.put(&crate::commands::cloudflare_alias(op), CF_TOKEN).unwrap();
    let rep = relay_destroy(&f.ctx, op, true).unwrap();
    assert!(rep.server_deleted, "the server still goes: it is the biggest bill");
    assert!(!rep.local_removed);
    assert!(rep.retry_needed);
    assert_eq!(rep.addons.len(), 1);
    let o = &rep.addons[0];
    assert_eq!((o.addon_id, o.kind, o.removed, o.keeps_relay), (cdn.id, AddonKind::Cdn, false, true));
    assert_eq!(o.code, "failed");
    // The relay, the add-on and what removes it are all still here.
    assert_eq!(f.ctx.db.get(op).unwrap().status, "decommissioned");
    assert_eq!(list(&f.ctx, op).unwrap().len(), 1);
    assert_eq!(f.ctx.custody.get(&cdn.secret_alias).unwrap(), CF_TOKEN);

    // The same call is the retry; with the add-on gone it finishes.
    forget(&f.ctx, cdn.id).unwrap();
    let rep = relay_destroy(&f.ctx, op, true).unwrap();
    assert!(rep.local_removed && !rep.retry_needed && rep.addons.is_empty());
    assert!(f.ctx.db.get(op).is_err());
}

#[test]
fn forgetting_a_relay_here_only_says_which_addons_keep_running_and_drops_their_secrets() {
    let f = fx();
    let op = provisioned(&f);
    let cdn = cdn_with_secret(&f, op);
    let sb = insert(&f.ctx, &standby(op)).unwrap();
    let rep = relay_destroy(&f.ctx, op, false).unwrap();
    assert!(rep.local_removed && !rep.server_deleted);
    let codes: Vec<(i64, &str, bool)> =
        rep.addons.iter().map(|a| (a.addon_id, a.code.as_str(), a.keeps_relay)).collect();
    assert_eq!(codes, vec![(cdn.id, "left", false), (sb, "left", false)]);
    assert!(f.mock.decommission_calls.lock().unwrap().is_empty(), "no provider was asked");
    assert!(matches!(f.ctx.custody.get(&cdn.secret_alias), Err(CustodyError::NotFound(_))));
    let n: i64 = f
        .ctx
        .db
        .with_conn(|c| c.query_row("SELECT COUNT(*) FROM relay_addons", [], |r| r.get(0)))
        .unwrap();
    assert_eq!(n, 0);
}

// ------------------------------------------------------------ the helper

#[test]
fn the_mock_helper_does_not_know_an_addon_verb_until_told() {
    let f = fx();
    let e = f
        .mock
        .run_addon(AddonCliRequest::args(["standby", "add"]), &mut |_| {})
        .unwrap_err();
    assert!(verb_unknown(&e), "{e}");
    *f.mock.addon_reply.lock().unwrap() = Some(Box::new(|args, stdin| {
        assert_eq!(stdin, b"key-bytes");
        Ok(format!("{{\"verb\":\"{}\"}}", args.join(" ")).into_bytes())
    }));
    let out = f
        .mock
        .run_addon(
            AddonCliRequest {
                args: vec!["cdn-posture".into(), "--record-file".into(), "r.json".into()],
                secret_files: vec![("--token-file", "secret")],
                stdin: b"key-bytes",
                progress: false,
            },
            &mut |_| {},
        )
        .unwrap();
    assert_eq!(&out[..], br#"{"verb":"cdn-posture --record-file r.json"}"#);
    let calls = f.mock.addon_calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 2);
    assert!(!format!("{calls:?}").contains("secret"), "secrets are not recorded");
}

/// The real subprocess path: argv, a secret as a 0600 file that is gone
/// afterwards, stdin, progress lines, stdout, and a failure's stderr.
#[cfg(unix)]
#[test]
fn the_subprocess_helper_passes_secrets_as_files_and_streams_progress() {
    use crate::cli_bridge::SubprocessRunner;
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("fake-deploy");
    let seen = dir.path().join("seen");
    std::fs::write(
        &bin,
        format!(
            r#"#!/bin/sh
verb="$1"; shift
tok=""
prog=0
while [ $# -gt 0 ]; do
  case "$1" in
    --token-file) tok="$2"; shift ;;
    --progress-json) prog=1 ;;
  esac
  shift
done
if [ "$verb" = "fail" ]; then echo "relay said no" >&2; exit 4; fi
printf '%s' "$tok" > "{seen}"
[ "$prog" = 1 ] && echo '{{"step":"renting","message":"ok"}}' >&2
echo 'plain line' >&2
input=$(cat)
printf '{{"verb":"%s","token":"%s","stdin":"%s"}}' "$verb" "$(cat "$tok")" "$input"
"#,
            seen = seen.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o700)).unwrap();
    let r = SubprocessRunner::new(Some(bin));

    let mut steps = Vec::new();
    let out = r
        .run_addon(
            AddonCliRequest {
                args: vec!["standby".into()],
                secret_files: vec![("--token-file", "tok-123")],
                stdin: b"hello",
                progress: true,
            },
            &mut |ev| steps.push(ev.step),
        )
        .unwrap();
    assert_eq!(
        String::from_utf8(out.to_vec()).unwrap(),
        r#"{"verb":"standby","token":"tok-123","stdin":"hello"}"#
    );
    assert_eq!(steps, vec!["renting".to_string()]);
    let tok_path = std::fs::read_to_string(&seen).unwrap();
    assert!(!tok_path.is_empty());
    assert!(!std::path::Path::new(&tok_path).exists(), "the token file is gone");

    let e = r.run_addon(AddonCliRequest::args(["fail"]), &mut |_| {}).unwrap_err();
    match e {
        crate::cli_bridge::BridgeError::SubprocessFailed { rc, stderr } => {
            assert_eq!(rc, 4);
            assert!(stderr.contains("relay said no"));
        }
        other => panic!("{other}"),
    }
}
