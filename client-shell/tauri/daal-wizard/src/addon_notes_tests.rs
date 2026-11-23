//! The update notes, driven through the real functions against
//! `MockRunner`: the GitHub account (check, keep, refuse, forget), the
//! two switches (on, retry, off), the carriers member in a person's
//! file, and every write (filler, the document, the revealed key, the
//! app-open pass). Nothing reaches GitHub or Cloudflare: `note-gittag`
//! and `note-dns` are answered by `addon_reply` (their own behaviour
//! against fakes is tested in Go).

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use super::*;
use crate::cli_bridge::{CliRunner, MockRunner, Pricing};
use crate::commands::{
    custody_put, provision_run, publisher_keygen, select_profile, set_helper_ip, store_cloud_token,
    WizardCtx,
};
use crate::device_custody::{DeviceCustody, FileCustody};
use crate::keystore::Keystore;
use crate::operator_db::{NewRecipientRow, OperatorDb};

const FP: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const TOKEN: &str = "github_pat_11AAAAAAA0notarealtoken0000000000000000";
const CF: &str = "cf-token-notes-test-0001";
const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
/// A standby key (the standby tests' vector).
const KEY: &str = "000G40 R40M3 0E209 185WP 03H2G";

struct Fx {
    ctx: WizardCtx,
    mock: Arc<MockRunner>,
    now: Arc<AtomicI64>,
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
    let now = Arc::new(AtomicI64::new(1_800_000_000));
    let n2 = now.clone();
    let custody: Arc<dyn DeviceCustody> = Arc::new(FileCustody::static_test(dir.path()).unwrap());
    let ctx = WizardCtx {
        db: Arc::new(OperatorDb::open_in_memory().unwrap()),
        keystore: Arc::new(Keystore::new_in_memory(dir.path())),
        journal_dir: dir.path().join("state").join("provision-journal"),
        staging_dir,
        cli,
        clock: Arc::new(move || n2.load(Ordering::SeqCst)),
        custody,
    };
    Fx {
        ctx,
        mock,
        now,
        _dir: dir,
    }
}

/// A built relay with a signed pack (so it has an update secret).
fn relay(f: &Fx) -> i64 {
    let id = store_cloud_token(&f.ctx, "hetzner", "hcloud-notes-test-0001", None).unwrap();
    select_profile(&f.ctx, id, "fsn1", "cx22", "iran-default", vec!["vless-reality".into()]).unwrap();
    publisher_keygen(&f.ctx, id).unwrap();
    set_helper_ip(&f.ctx, id, "198.51.100.1", "manual").unwrap();
    provision_run(&f.ctx, id, "", &mut |_| {}).unwrap();
    f.ctx.db.record_signed_sbp(id, SHA, "rp-notes-test", 1).unwrap();
    id
}

fn person(f: &Fx, op: i64, n: u8) -> (i64, String) {
    let fp = format!("{:064x}", n);
    let id = f
        .ctx
        .db
        .insert_recipient(NewRecipientRow {
            operator_id: op,
            name: format!("r{n}"),
            display_name: String::new(),
            address_str: format!("daal1test{n}"),
            pubkey_x25519_hex: format!("{:064x}", 1000 + n as u32),
            fingerprint_hex: fp.clone(),
            vless_uuid: String::new(),
            reality_short_id: String::new(),
            hy2_password: String::new(),
            naive_password: String::new(),
            ws_path: String::new(),
            provisioned_at_unix: 1_800_000_000 + n as i64,
        })
        .unwrap();
    (id, fp)
}

fn noop() -> impl FnMut(AddonProgress) {
    |_| {}
}

type Seen = Arc<Mutex<Vec<(Vec<String>, Value)>>>;

/// A helper answering `note-gittag` / `note-dns` with `answer(verb, sub,
/// creds)`: Ok(stdout) or Err((rc, stdout)). Records argv and the creds.
fn helper(
    f: &Fx,
    mut answer: impl FnMut(&str, &str, &Value) -> std::result::Result<Value, (i32, Value)> + Send + 'static,
) -> Seen {
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let s2 = seen.clone();
    *f.mock.addon_reply.lock().unwrap() = Some(Box::new(move |args, stdin| {
        let creds: Value = serde_json::from_slice(stdin).unwrap_or(Value::Null);
        s2.lock().unwrap().push((args.to_vec(), creds.clone()));
        let verb = args.first().map(String::as_str).unwrap_or("");
        let sub = args.get(1).map(String::as_str).unwrap_or("");
        match answer(verb, sub, &creds) {
            Ok(v) => Ok(v.to_string().into_bytes()),
            // As the bridge does for a note verb: its stdout first.
            Err((rc, v)) => Err(BridgeError::SubprocessFailed {
                rc,
                stderr: format!("{v}\nnote: failed\n"),
            }),
        }
    }));
    seen
}

fn check_ok() -> Value {
    json!({"ok":true,"verb":"check","verdict":"ok","login":"notes-person","token_kind":"fine_grained",
           "unproven":["Administration: Read and write","Contents: Read and write","All repositories"],
           "expires_at":"2027-11-22T00:00:00Z","suggested_repo":"abcdefghijkl"})
}

fn publish_ok(seq: u64) -> Value {
    json!({"ok":true,"verb":"publish","changed":true,"reason":"","created_repo":seq == 1,"seq":seq,
           "highest_seq":seq,"epoch":2976,"micro":"filler","full":"filler","full_bucket":16384})
}

fn happy(f: &Fx) -> Seen {
    helper(f, |verb, sub, creds| match (verb, sub) {
        ("note-gittag", "check") => Ok(check_ok()),
        ("note-gittag", "publish") => Ok(publish_ok(creds["seq"].as_u64().unwrap_or(1))),
        ("note-dns", _) => Ok(json!({"ok":true,"verb":sub,"epoch":2976,"mode":"filler"})),
        _ => Err((2, json!({}))),
    })
}

fn connect_github(f: &Fx) {
    let c = github_connect(&f.ctx, GithubConnectInput { token: TOKEN.into() }, &mut noop()).unwrap();
    assert!(c.stored, "{c:?}");
}

fn connect_cloudflare(f: &Fx) {
    custody_put(&f.ctx, crate::addon_cdn::ACCOUNT_ALIAS, CF.as_bytes()).unwrap();
    custody_put(&f.ctx, crate::addon_cdn::ACCOUNT_ZONE_ALIAS, b"example.org").unwrap();
}

fn calls(seen: &Seen, verb: &str, sub: &str) -> Vec<Value> {
    seen.lock()
        .unwrap()
        .iter()
        .filter(|(a, _)| a.first().map(String::as_str) == Some(verb) && a.get(1).map(String::as_str) == Some(sub))
        .map(|(_, c)| c.clone())
        .collect()
}

fn no_secret_in_argv(seen: &Seen) {
    for (args, _) in seen.lock().unwrap().iter() {
        assert_eq!(&args[2..], ["--creds-file", "-"], "every input on stdin: {args:?}");
        for a in args {
            assert!(!a.contains(TOKEN) && !a.contains(CF), "a key in argv: {args:?}");
        }
    }
}

// ------------------------------------------------------------- the account

#[test]
fn a_github_key_is_checked_kept_and_forgotten() {
    let f = fx();
    let seen = happy(&f);
    assert_eq!(github_account(&f.ctx).unwrap(), GithubAccount::default());
    let c = github_connect(&f.ctx, GithubConnectInput { token: format!("  {TOKEN}\n") }, &mut noop()).unwrap();
    assert_eq!(c.verdict, "ok");
    assert!(c.stored);
    assert_eq!(c.login, "notes-person");
    assert_eq!(c.unproven.len(), 3);
    let creds = &calls(&seen, "note-gittag", "check")[0];
    assert_eq!(creds, &json!({"token": TOKEN}), "trimmed, alone, on stdin");
    no_secret_in_argv(&seen);

    let a = github_account(&f.ctx).unwrap();
    assert!(a.connected);
    assert_eq!(a.login, "notes-person");
    assert_eq!(a.token_kind, "fine_grained");
    assert_eq!(a.expires_at, "2027-11-22T00:00:00Z");
    assert_eq!(
        crate::commands::custody_get_string(&f.ctx, GITHUB_ACCOUNT_ALIAS).unwrap().as_str(),
        TOKEN
    );
    let wiped = f.ctx.db.list_all_keystore_aliases().unwrap();
    for al in GITHUB_ACCOUNT_ALIASES {
        assert!(wiped.iter().any(|w| w == al), "panic wipe erases {al}");
    }

    github_disconnect(&f.ctx).unwrap();
    assert!(!github_account(&f.ctx).unwrap().connected);
    for al in GITHUB_ACCOUNT_ALIASES {
        assert!(!crate::commands::custody_has(&f.ctx, al), "{al} forgotten");
    }
}

#[test]
fn a_github_key_that_cannot_do_the_job_is_named_and_never_kept() {
    let f = fx();
    let verdict = Arc::new(Mutex::new(0));
    let v2 = verdict.clone();
    let _ = helper(&f, move |_, _, _| {
        let mut n = v2.lock().unwrap();
        *n += 1;
        match *n {
            1 => Ok(json!({"ok":true,"verb":"check","verdict":"missing_permission","login":"x","token_kind":"classic","missing":["public_repo"]})),
            2 => Ok(json!({"ok":true,"verb":"check","verdict":"invalid"})),
            3 => Err((3, json!({"ok":false,"verb":"check","code":"invalid_token"}))),
            4 => Err((5, json!({"ok":false,"verb":"check","code":"rate_limited","retry_after_s":60}))),
            _ => Err((1, json!({"ok":false,"verb":"check","code":"network"}))),
        }
    });
    let c = github_connect(&f.ctx, GithubConnectInput { token: TOKEN.into() }, &mut noop()).unwrap();
    assert_eq!((c.verdict.as_str(), c.stored), ("missing_permission", false));
    assert_eq!(c.missing, vec!["public_repo".to_string()]);
    let c = github_connect(&f.ctx, GithubConnectInput { token: TOKEN.into() }, &mut noop()).unwrap();
    assert_eq!((c.verdict.as_str(), c.stored), ("invalid", false));
    let c = github_connect(&f.ctx, GithubConnectInput { token: TOKEN.into() }, &mut noop()).unwrap();
    assert_eq!((c.verdict.as_str(), c.stored), ("invalid", false));
    let c = github_connect(&f.ctx, GithubConnectInput { token: TOKEN.into() }, &mut noop()).unwrap();
    assert_eq!((c.verdict.as_str(), c.retry_after_s), ("rate_limited", 60));
    let e = github_connect(&f.ctx, GithubConnectInput { token: TOKEN.into() }, &mut noop()).unwrap_err();
    assert!(e.to_string().starts_with(E_GITTAG_UNREACHABLE), "{e}");
    assert!(!e.to_string().contains(TOKEN));
    assert!(!github_account(&f.ctx).unwrap().connected);
    assert!(matches!(
        github_connect(&f.ctx, GithubConnectInput { token: "  ".into() }, &mut noop()),
        Err(WizardError::EmptyToken)
    ));
}

// ------------------------------------------------------------ the switches

#[test]
fn the_github_switch_needs_the_account_and_a_signed_relay() {
    let f = fx();
    let seen = happy(&f);
    let op = relay(&f);
    let e = gittag_on(&f.ctx, NotesOnInput { operator_id: op }, &mut noop()).unwrap_err();
    assert!(e.to_string().starts_with(E_GITHUB_NO_ACCOUNT), "{e}");
    assert!(addons::list(&f.ctx, op).unwrap().is_empty(), "nothing made");

    connect_github(&f);
    let bare = store_cloud_token(&f.ctx, "hetzner", "hcloud-notes-test-0002", None).unwrap();
    let e = gittag_on(&f.ctx, NotesOnInput { operator_id: bare }, &mut noop()).unwrap_err();
    assert!(e.to_string().starts_with(E_NOTES_NO_PACK), "{e}");
    assert!(addons::list(&f.ctx, bare).unwrap().is_empty());
    assert!(calls(&seen, "note-gittag", "publish").is_empty());
}

#[test]
fn the_github_switch_makes_the_repository_and_new_files_name_it() {
    let f = fx();
    let seen = happy(&f);
    let op = relay(&f);
    let (_, fp) = person(&f, op, 1);
    connect_github(&f);
    assert!(carriers_member(&f.ctx, op).is_none(), "nothing on: no member");

    let row = gittag_on(&f.ctx, NotesOnInput { operator_id: op }, &mut noop()).unwrap();
    assert_eq!(row.kind, AddonKind::Gittag);
    assert_eq!(row.state, AddonState::Ready);
    assert_eq!(row.monthly_cost_cents, 0);
    let d = detail_of(&row);
    assert_eq!(d.owner, "notes-person");
    assert_eq!(d.repo.len(), 12);
    assert!(d.repo.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
    assert_eq!(d.seq, 1);
    assert_eq!(d.people_before, 1, "one person needs a new file");
    assert!(d.last_ok_at_unix > 0 && d.last_error.is_empty());

    let p = &calls(&seen, "note-gittag", "publish")[0];
    assert_eq!(p["token"], TOKEN);
    assert_eq!(p["owner"], "notes-person");
    assert_eq!(p["repo"], d.repo.as_str());
    assert_eq!(p["update_audience"], "people");
    assert_eq!(p["seq"], 1);
    assert_eq!(B64.decode(p["update_secret"].as_str().unwrap()).unwrap().len(), 32);
    assert!(p.get("standby_key").is_none(), "nothing revealed: filler");
    assert!(p.get("container_path").is_none(), "no document: filler");
    no_secret_in_argv(&seen);

    // The member, in a person's file and never in the Everyone file.
    let m = carriers_member(&f.ctx, op).unwrap();
    assert_eq!(m, json!({"v":1,"gittag":{"owner":"notes-person","repo":d.repo}}));
    let g = crate::addon_standby::people_secret_for_file(&f.ctx, op, &fp).unwrap().unwrap();
    let mut creds = json!({});
    g.add_to_creds(&mut creds);
    assert_eq!(creds["update_carriers"], m);
    assert_eq!(creds["update_secret"], p["update_secret"], "the files' secret is the one written under");
    let e = crate::addon_standby::everyone_secret_for_file(&f.ctx, op).unwrap().unwrap();
    let mut creds = json!({"update_carriers": "stale"});
    e.add_to_creds(&mut creds);
    assert!(creds.get("update_carriers").is_none(), "never in the Everyone file");

    // On again: nothing new.
    let again = gittag_on(&f.ctx, NotesOnInput { operator_id: op }, &mut noop()).unwrap();
    assert_eq!(again.id, row.id);
    assert_eq!(calls(&seen, "note-gittag", "publish").len(), 1);

    // Off: the repository stays (by hand), the row and the key go.
    let alias = addons::get(&f.ctx, row.id).unwrap().secret_alias;
    assert!(!alias.is_empty() && crate::commands::custody_has(&f.ctx, &alias));
    let r = addons::remove(&f.ctx, row.id, &mut noop()).unwrap();
    assert!(r.removed);
    assert_eq!(r.by_hand, vec!["github_repository".to_string()]);
    assert!(!crate::commands::custody_has(&f.ctx, &alias));
    // The next file clears what the phones hold: the member says no carrier.
    assert_eq!(carriers_member(&f.ctx, op), Some(json!({"v":1})));
    let mut creds = json!({});
    crate::addon_standby::people_secret_for_file(&f.ctx, op, &fp)
        .unwrap()
        .unwrap()
        .add_to_creds(&mut creds);
    assert_eq!(creds["update_carriers"], json!({"v":1}));
    // Another relay that never had a switch still makes files with no member.
    let other = relay(&f);
    assert!(carriers_member(&f.ctx, other).is_none());
}

#[test]
fn the_account_keys_are_on_the_panic_wipe_list() {
    let f = fx();
    let op = relay(&f);
    let wiped = f.ctx.db.list_all_keystore_aliases().unwrap();
    for al in [
        crate::addon_cdn::ACCOUNT_ALIAS,
        crate::addon_cdn::ACCOUNT_ZONE_ALIAS,
        crate::addon_cdn::ACCOUNT_EXTRA_ALIAS,
        crate::addon_google::ACCOUNT_KEY_ALIAS,
        crate::addon_google::ACCOUNT_URL_ALIAS,
    ] {
        assert!(wiped.iter().any(|w| w == al), "panic wipe erases {al}");
    }
    assert!(wiped.iter().any(|w| *w == notes_ever_on_alias(op)));
}

#[test]
fn a_refused_first_write_leaves_the_switch_to_try_again_with_the_same_repository() {
    let f = fx();
    let fail = Arc::new(Mutex::new(true));
    let f2 = fail.clone();
    let _ = helper(&f, move |verb, sub, creds| match (verb, sub) {
        ("note-gittag", "check") => Ok(check_ok()),
        ("note-gittag", "publish") if *f2.lock().unwrap() => Err((
            4,
            json!({"ok":false,"verb":"publish","code":"missing_permission","missing":["Administration"]}),
        )),
        ("note-gittag", "publish") => Ok(publish_ok(creds["seq"].as_u64().unwrap())),
        _ => Err((2, json!({}))),
    });
    let op = relay(&f);
    connect_github(&f);
    let e = gittag_on(&f.ctx, NotesOnInput { operator_id: op }, &mut noop()).unwrap_err();
    assert!(e.to_string().starts_with(E_GITTAG_REFUSED), "{e}");
    assert!(e.to_string().contains("Administration"));
    assert!(!e.to_string().contains(TOKEN));
    let row = row_for(&f.ctx, op, AddonKind::Gittag).unwrap().unwrap();
    assert_eq!(row.state, AddonState::Building);
    let d = detail_of(&row);
    assert_eq!(d.last_error, "missing_permission");
    assert!(carriers_member(&f.ctx, op).is_none(), "not on: no file names it");

    *fail.lock().unwrap() = false;
    let row2 = gittag_on(&f.ctx, NotesOnInput { operator_id: op }, &mut noop()).unwrap();
    assert_eq!(row2.id, row.id);
    assert_eq!(row2.state, AddonState::Ready);
    assert_eq!(detail_of(&row2).repo, d.repo, "the same repository");
    assert!(detail_of(&row2).last_error.is_empty());
}

#[test]
fn a_sequence_behind_the_repository_moves_past_it() {
    let f = fx();
    let seen = helper(&f, |verb, sub, creds| match (verb, sub) {
        ("note-gittag", "check") => Ok(check_ok()),
        ("note-gittag", "publish") if creds["seq"].as_u64() < Some(10) => {
            Err((6, json!({"ok":false,"verb":"publish","code":"seq_behind","highest_seq":9})))
        }
        ("note-gittag", "publish") => Ok(publish_ok(creds["seq"].as_u64().unwrap())),
        _ => Err((2, json!({}))),
    });
    let op = relay(&f);
    connect_github(&f);
    let row = gittag_on(&f.ctx, NotesOnInput { operator_id: op }, &mut noop()).unwrap();
    let seqs: Vec<u64> = calls(&seen, "note-gittag", "publish").iter().map(|c| c["seq"].as_u64().unwrap()).collect();
    assert_eq!(seqs, vec![1, 10]);
    assert_eq!(detail_of(&row).seq, 10);
    write_relay(&f.ctx, op);
    assert_eq!(calls(&seen, "note-gittag", "publish").last().unwrap()["seq"], 11);
}

#[test]
fn the_dns_switch_uses_the_cloudflare_account_and_takes_its_records_down() {
    let f = fx();
    let take_down = Arc::new(Mutex::new(false));
    let t2 = take_down.clone();
    let seen = helper(&f, move |verb, sub, _| match (verb, sub) {
        ("note-dns", "publish") => Ok(json!({"ok":true,"verb":"publish","epoch":2976,"mode":"filler"})),
        ("note-dns", "remove") if *t2.lock().unwrap() => Ok(json!({"ok":true,"verb":"remove"})),
        ("note-dns", "remove") => Err((1, json!({}))),
        _ => Err((2, json!({}))),
    });
    let op = relay(&f);
    let e = dnsnote_on(&f.ctx, NotesOnInput { operator_id: op }, &mut noop()).unwrap_err();
    assert!(e.to_string().starts_with(crate::addon_cdn::E_CDN_NO_TOKEN), "{e}");
    assert!(addons::list(&f.ctx, op).unwrap().is_empty());

    connect_cloudflare(&f);
    let row = dnsnote_on(&f.ctx, NotesOnInput { operator_id: op }, &mut noop()).unwrap();
    assert_eq!(row.state, AddonState::Ready);
    let p = &calls(&seen, "note-dns", "publish")[0];
    assert_eq!(p["cf_token"], CF);
    assert_eq!(p["zone"], "example.org");
    assert_eq!(p["update_audience"], "people");
    assert!(p.get("standby_key").is_none());
    no_secret_in_argv(&seen);
    assert_eq!(carriers_member(&f.ctx, op).unwrap(), json!({"v":1,"dns":{"zone":"example.org"}}));

    // Cloudflare cannot take the records down: the row stays to retry.
    let r = addons::remove(&f.ctx, row.id, &mut noop()).unwrap();
    assert!(!r.removed);
    assert_eq!(addons::get(&f.ctx, row.id).unwrap().state, AddonState::Removing);
    *take_down.lock().unwrap() = true;
    let r = addons::remove(&f.ctx, row.id, &mut noop()).unwrap();
    assert!(r.removed);
    let rm = calls(&seen, "note-dns", "remove");
    assert_eq!(rm.last().unwrap()["update_audience"], "people");
    assert!(addons::list(&f.ctx, op).unwrap().is_empty());
}

#[test]
fn a_switch_to_the_standby_is_revealed_and_the_document_carried() {
    let f = fx();
    let seen = happy(&f);
    let op = relay(&f);
    connect_github(&f);
    connect_cloudflare(&f);
    gittag_on(&f.ctx, NotesOnInput { operator_id: op }, &mut noop()).unwrap();
    dnsnote_on(&f.ctx, NotesOnInput { operator_id: op }, &mut noop()).unwrap();

    // The freshness document freshness::publish signed last, naming the
    // relay's pack, and the pack itself.
    let doc = json!({"kind":"daal-freshness-v1","sequence":7,"current_bundle_sha256":SHA,
                     "not_after":"2030-01-01T00:00:00Z","signature":"x"});
    std::fs::write(f.ctx.staging_dir.join(format!("freshness.{op}.json")), doc.to_string()).unwrap();
    // A switch to the standby (what addon_standby::promote leaves).
    let id = addons::insert(
        &f.ctx,
        &NewAddon {
            operator_id: op,
            kind: Some(AddonKind::Standby),
            state: Some(AddonState::Promoted),
            detail: Some(json!({"key": KEY})),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(id > 0);
    let container_seen = Arc::new(Mutex::new(None::<Value>));
    {
        // Read the container while the helper runs: it is gone after.
        let c2 = container_seen.clone();
        let inner = f.mock.addon_reply.lock().unwrap().take().unwrap();
        let inner = Arc::new(Mutex::new(inner));
        *f.mock.addon_reply.lock().unwrap() = Some(Box::new(move |args, stdin| {
            let creds: Value = serde_json::from_slice(stdin).unwrap_or(Value::Null);
            if let Some(p) = creds.get("container_path").and_then(Value::as_str) {
                *c2.lock().unwrap() = serde_json::from_slice(&std::fs::read(p).unwrap()).ok();
            }
            (inner.lock().unwrap())(args, stdin)
        }));
    }
    assert_eq!(write_relay(&f.ctx, op), (2, 0));

    let symbols = KEY.replace(' ', "");
    let g = calls(&seen, "note-gittag", "publish");
    let g = g.last().unwrap();
    assert_eq!(g["standby_key"], symbols.as_str());
    let k = crate::addon_standby::revealed_key(&f.ctx, op).unwrap();
    assert_eq!(g["standby_commit"], crate::addon_standby::standby_commit(&k).as_str());
    let path = g["container_path"].as_str().unwrap().to_string();
    assert!(!std::path::Path::new(&path).exists(), "the staged container is removed");
    let c = container_seen.lock().unwrap().clone().unwrap();
    assert_eq!(c["kind"], "daal-refresh-v2");
    assert_eq!(c["slot"].as_str().unwrap().len(), 16);
    assert_eq!(B64.decode(c["freshness"].as_str().unwrap()).unwrap(), doc.to_string().into_bytes());
    assert_eq!(c["standby_key"], symbols.as_str());
    assert!(c.get("pack").is_none(), "no pack file that matches: none carried");

    let d = calls(&seen, "note-dns", "publish");
    assert_eq!(d.last().unwrap()["standby_key"], symbols.as_str());
    let row = row_for(&f.ctx, op, AddonKind::Gittag).unwrap().unwrap();
    assert!(detail_of(&row).revealed && detail_of(&row).carried_document);

    // An expired document is not carried: the full note is filler.
    let old = json!({"current_bundle_sha256":SHA,"not_after":"2020-01-01T00:00:00Z"});
    std::fs::write(f.ctx.staging_dir.join(format!("freshness.{op}.json")), old.to_string()).unwrap();
    write_relay(&f.ctx, op);
    assert!(calls(&seen, "note-gittag", "publish").last().unwrap().get("container_path").is_none());
}

#[test]
fn a_failed_write_never_fails_the_caller_and_says_so_on_the_switch() {
    let f = fx();
    let down = Arc::new(Mutex::new(false));
    let d2 = down.clone();
    let _ = helper(&f, move |verb, sub, creds| match (verb, sub) {
        ("note-gittag", "check") => Ok(check_ok()),
        ("note-gittag", "publish") if *d2.lock().unwrap() => {
            Err((1, json!({"ok":false,"verb":"publish","code":"network"})))
        }
        ("note-gittag", "publish") => Ok(publish_ok(creds["seq"].as_u64().unwrap())),
        _ => Err((2, json!({}))),
    });
    let op = relay(&f);
    connect_github(&f);
    let row = gittag_on(&f.ctx, NotesOnInput { operator_id: op }, &mut noop()).unwrap();
    let ok_at = detail_of(&row).last_ok_at_unix;
    *down.lock().unwrap() = true;
    f.now.fetch_add(60, Ordering::SeqCst);
    assert_eq!(write_relay(&f.ctx, op), (1, 1));
    let d = detail_of(&addons::get(&f.ctx, row.id).unwrap());
    assert_eq!(d.last_error, "network");
    assert_eq!(d.last_ok_at_unix, ok_at);
    assert!(d.last_try_at_unix > ok_at);
    assert_eq!(addons::get(&f.ctx, row.id).unwrap().state, AddonState::Ready, "still on");
}

#[test]
fn the_app_open_pass_writes_once_per_epoch_and_retries_a_failure() {
    let f = fx();
    let down = Arc::new(Mutex::new(false));
    let d2 = down.clone();
    let seen = helper(&f, move |verb, sub, creds| match (verb, sub) {
        ("note-gittag", "check") => Ok(check_ok()),
        ("note-gittag", "publish") if *d2.lock().unwrap() => Err((1, json!({"code":"github"}))),
        ("note-gittag", "publish") => Ok(json!({"ok":true,"seq":creds["seq"],"epoch":1_800_000_000u64 / 604_800})),
        _ => Err((2, json!({}))),
    });
    let op = relay(&f);
    connect_github(&f);
    gittag_on(&f.ctx, NotesOnInput { operator_id: op }, &mut noop()).unwrap();
    let n = || calls(&seen, "note-gittag", "publish").len();
    assert_eq!(n(), 1);
    assert_eq!(tick(&f.ctx).unwrap(), NotesTickReport { written: 0, failed: 0 }, "written this epoch");
    assert_eq!(n(), 1);

    f.now.fetch_add(EPOCH_SECONDS, Ordering::SeqCst);
    *down.lock().unwrap() = true;
    assert_eq!(tick(&f.ctx).unwrap(), NotesTickReport { written: 1, failed: 1 });
    assert_eq!(tick(&f.ctx).unwrap().written, 0, "not straight away");
    *down.lock().unwrap() = false;
    f.now.fetch_add(RETRY_AFTER_SECONDS, Ordering::SeqCst);
    assert_eq!(tick(&f.ctx).unwrap(), NotesTickReport { written: 1, failed: 0 });
    assert_eq!(n(), 3);
}

#[test]
fn after_a_removal_notes_are_written_only_for_the_people_left() {
    let f = fx();
    let seen = happy(&f);
    let op = relay(&f);
    let (a_id, a) = person(&f, op, 1);
    let (_, b) = person(&f, op, 2);
    connect_github(&f);
    gittag_on(&f.ctx, NotesOnInput { operator_id: op }, &mut noop()).unwrap();
    for fp in [&a, &b] {
        let g = crate::addon_standby::people_secret_for_file(&f.ctx, op, fp).unwrap().unwrap();
        crate::addon_standby::record_holder(&f.ctx, op, fp, g.gen).unwrap();
    }
    f.ctx.db.mark_recipient_revoked(a_id, 1_800_000_100).unwrap();
    write_relay(&f.ctx, op);
    let last = calls(&seen, "note-gittag", "publish");
    assert_eq!(last.last().unwrap()["update_audience"], "people/2", "a holds people; never written again");
}

#[test]
fn relay_delete_takes_the_dns_records_down_and_keeps_nothing() {
    let f = fx();
    let seen = happy(&f);
    let op = relay(&f);
    connect_github(&f);
    connect_cloudflare(&f);
    gittag_on(&f.ctx, NotesOnInput { operator_id: op }, &mut noop()).unwrap();
    dnsnote_on(&f.ctx, NotesOnInput { operator_id: op }, &mut noop()).unwrap();
    let out = addons::before_relay_destroy(&f.ctx, op).unwrap();
    assert_eq!(out.len(), 2);
    assert!(out.iter().all(|o| o.removed && !o.keeps_relay), "{out:?}");
    assert_eq!(calls(&seen, "note-dns", "remove").len(), 1);
    assert!(addons::list(&f.ctx, op).unwrap().is_empty());
}

#[test]
fn the_kinds_round_trip_through_the_ledger() {
    for k in [AddonKind::Gittag, AddonKind::Dnsnote] {
        assert_eq!(AddonKind::parse(k.as_str()), Some(k));
        assert_eq!(serde_json::to_value(k).unwrap(), json!(k.as_str()));
    }
    assert!(owner_ok("notes-person") && !owner_ok("-x") && !owner_ok("a--b") && !owner_ok(""));
    let r = random_repo();
    assert_eq!(r.len(), 12);
    assert!(r.chars().next().unwrap().is_ascii_lowercase());
}

// ------------------------------------------------------------- the log line

fn write_lines() -> Vec<String> {
    WRITE_LINES.with(|l| l.borrow().clone())
}

#[test]
fn every_write_leaves_one_plain_line_and_never_a_name() {
    let f = fx();
    let fail_next = Arc::new(Mutex::new(false));
    let f2 = fail_next.clone();
    let _seen = helper(&f, move |verb, sub, creds| match (verb, sub) {
        ("note-gittag", "check") => Ok(check_ok()),
        ("note-gittag", "publish") if *f2.lock().unwrap() => Err((
            3,
            json!({"ok":false,"verb":"publish","code":"missing_permission","missing":["Administration"]}),
        )),
        ("note-gittag", "publish") => Ok(publish_ok(creds["seq"].as_u64().unwrap_or(1))),
        ("note-dns", "publish") => Ok(json!({"ok":true,"verb":"publish","epoch":2976,"mode":"filler",
            "created":6,"replaced":0,"kept":0,"removed":0})),
        _ => Err((2, json!({}))),
    });
    let op = relay(&f);
    connect_github(&f);
    connect_cloudflare(&f);
    WRITE_LINES.with(|l| l.borrow_mut().clear());

    let g = gittag_on(&f.ctx, NotesOnInput { operator_id: op }, &mut noop()).unwrap();
    let repo = detail_of(&g).repo;
    dnsnote_on(&f.ctx, NotesOnInput { operator_id: op }, &mut noop()).unwrap();
    *fail_next.lock().unwrap() = true;
    let (written, failed) = write_relay(&f.ctx, op);
    assert_eq!((written, failed), (2, 1));

    let lines = write_lines();
    assert_eq!(
        lines,
        vec![
            format!("[notes_write] op={op} kind=gittag outcome=ok changed=yes"),
            format!("[notes_write] op={op} kind=dnsnote outcome=ok changed=yes"),
            format!("[notes_write] op={op} kind=gittag outcome=missing_permission changed=no"),
            format!("[notes_write] op={op} kind=dnsnote outcome=ok changed=yes"),
        ],
        "one line per write attempt, in order"
    );
    for line in &lines {
        for secret in [TOKEN, CF, "notes-person", repo.as_str(), "example.org", "example", "Administration"] {
            assert!(!line.contains(secret), "{secret:?} in {line:?}");
        }
        assert!(!line.contains("github.com") && !line.contains("people"), "{line}");
    }
}

#[test]
fn the_line_keeps_only_a_code_word() {
    assert_eq!(
        write_line(7, AddonKind::Gittag, "already_published", false),
        "[notes_write] op=7 kind=gittag outcome=already_published changed=no"
    );
    // Whatever a helper answered, nothing but a closed word reaches it.
    assert_eq!(
        write_line(7, AddonKind::Dnsnote, "zone example.org/owner token=abc", true),
        "[notes_write] op=7 kind=dnsnote outcome=error changed=yes"
    );
    assert_eq!(write_line(1, AddonKind::Gittag, "", false), "[notes_write] op=1 kind=gittag outcome=error changed=no");
}

#[test]
fn each_attempt_logs_its_own_word() {
    let f = fx();
    let _seen = helper(&f, move |verb, sub, creds| match (verb, sub) {
        ("note-gittag", "check") => Ok(check_ok()),
        ("note-gittag", "publish") if creds["seq"].as_u64().unwrap_or(1) > 1 => Err((
            3,
            json!({"ok":false,"verb":"publish","code":"missing_permission","missing":["Administration"]}),
        )),
        ("note-gittag", "publish") => Ok(publish_ok(creds["seq"].as_u64().unwrap_or(1))),
        _ => Err((2, json!({}))),
    });
    let op = relay(&f);
    connect_github(&f);
    gittag_on(&f.ctx, NotesOnInput { operator_id: op }, &mut noop()).unwrap();
    // A refused write: the row keeps missing_permission.
    assert_eq!(write_relay(&f.ctx, op).1, 1);
    // The key goes; the next attempt fails before the helper runs.
    github_disconnect(&f.ctx).unwrap();
    let row = addons::list(&f.ctx, op).unwrap().into_iter().find(|r| r.kind == AddonKind::Gittag).unwrap();
    addons::set_secret_alias(&f.ctx, row.id, "").unwrap();
    WRITE_LINES.with(|l| l.borrow_mut().clear());
    assert_eq!(write_relay(&f.ctx, op).1, 1);
    let word = E_GITHUB_NO_ACCOUNT.to_ascii_lowercase();
    assert_eq!(
        write_lines(),
        vec![format!("[notes_write] op={op} kind=gittag outcome={word} changed=no")],
        "the second attempt says its own word, not the earlier missing_permission"
    );
    let row = addons::list(&f.ctx, op).unwrap().into_iter().find(|r| r.kind == AddonKind::Gittag).unwrap();
    assert_eq!(detail_of(&row).last_error, word);
}
