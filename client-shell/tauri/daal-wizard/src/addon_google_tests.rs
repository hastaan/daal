//! The Google update channel, driven through the real functions
//! against `MockRunner`: the account (Accounts → Google: the script by
//! hand, the hidden sign-in, the connect check, disconnect) and a
//! relay's switch (a slot, the mirror, the first update, off). Nothing
//! reaches Google: the `daal-deploy` verbs are answered by
//! `addon_reply` (their own behaviour against a fake Google is tested
//! in Go, `cli_addon_google_test.go`).

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use super::*;
use crate::cli_bridge::{CliRunner, MockRunner, Pricing};
use crate::commands::{
    provision_run, publisher_keygen, select_profile, set_helper_ip, store_cloud_token, WizardCtx,
};
use crate::device_custody::{DeviceCustody, FileCustody};
use crate::freshness::{self, FreshnessEndpointInput};
use crate::keystore::Keystore;
use crate::operator_db::OperatorDb;

const FP: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const DEPLOYMENT: &str = "AKfycbx0123456789abcdefghijklmn";
const BASE: &str = "https://script.google.com/macros/s/AKfycbx0123456789abcdefghijklmn/exec";

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
    Fx {
        ctx,
        mock,
        _dir: dir,
    }
}

fn provisioned(f: &Fx) -> i64 {
    let id = store_cloud_token(&f.ctx, "hetzner", "hcloud-google-test-0001", None).unwrap();
    select_profile(
        &f.ctx,
        id,
        "fsn1",
        "cx22",
        "iran-default",
        vec!["vless-reality".into()],
    )
    .unwrap();
    publisher_keygen(&f.ctx, id).unwrap();
    set_helper_ip(&f.ctx, id, "198.51.100.1", "manual").unwrap();
    provision_run(&f.ctx, id, "", &mut |_| {}).unwrap();
    id
}

fn noop() -> impl FnMut(AddonProgress) {
    |_| {}
}

/// Every call the helper saw: argv and stdin.
type Seen = Arc<Mutex<Vec<(Vec<String>, Vec<u8>)>>>;

/// A helper that answers each verb with `answer(verb, argv, stdin)`.
fn helper(
    f: &Fx,
    mut answer: impl FnMut(&str, &[String], &[u8]) -> crate::cli_bridge::Result<String> + Send + 'static,
) -> Seen {
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let s2 = seen.clone();
    *f.mock.addon_reply.lock().unwrap() = Some(Box::new(move |args, stdin| {
        s2.lock().unwrap().push((args.to_vec(), stdin.to_vec()));
        let verb = args.first().map(String::as_str).unwrap_or("");
        answer(verb, args, stdin).map(String::into_bytes)
    }));
    seen
}

fn ok_check(seq: u64) -> String {
    format!(
        r#"{{"ok":true,"via_front":true,"posted":true,"seq":{seq},"sha256":"{}","reason":""}}"#,
        "a".repeat(64)
    )
}

fn arg_after(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1).cloned())
}

/// A standard helper: every verb answers as a working script would.
fn happy_helper(f: &Fx) -> Seen {
    helper(f, |verb, args, _| match verb {
        "appsscript-script" => Ok(r#"{"code_gs":"// code","manifest_json":"{}"}"#.into()),
        "appsscript-account-check" => Ok(format!(
            r#"{{"ok":true,"via_front":true,"posted":true,"seq":1800000000000,"sha256":"{}","reason":"","url":"{}"}}"#,
            "b".repeat(64),
            arg_after(args, "--url").unwrap()
        )),
        "appsscript-check" => {
            let seq = arg_after(args, "--seq")
                .and_then(|s| s.parse().ok())
                .unwrap_or(77);
            Ok(ok_check(seq))
        }
        "appsscript-deploy" => Ok(format!(
            r#"{{"script_id":"1ScriptProject000000000001","deployment_id":"{DEPLOYMENT}","version":1,"url":"{BASE}"}}"#
        )),
        other => Err(BridgeError::SubprocessFailed {
            rc: 2,
            stderr: format!("unknown subcommand {other:?}\n"),
        }),
    })
}

fn google_row(f: &Fx, op: i64) -> AddonRow {
    row_for(&f.ctx, op).unwrap().expect("a google row")
}

fn calls_of(seen: &Seen, verb: &str) -> Vec<(Vec<String>, Vec<u8>)> {
    seen.lock()
        .unwrap()
        .iter()
        .filter(|c| c.0.first().map(String::as_str) == Some(verb))
        .cloned()
        .collect()
}

/// Accounts → Google by hand: copy the script, paste the address back.
fn connect_account(f: &Fx) -> GoogleAccount {
    account_script(&f.ctx, &mut noop()).unwrap();
    account_attach(
        &f.ctx,
        GoogleAccountAttachInput { url: format!(" {BASE}/ ") },
        &mut noop(),
    )
    .unwrap()
}

fn account_key_bytes(f: &Fx) -> Vec<u8> {
    f.ctx.custody.get(ACCOUNT_KEY_ALIAS).unwrap()
}

// --------------------------------------------------------------------
// The read token
// --------------------------------------------------------------------

/// The same vector as the Go side (`appsscript.TestReadTokenAndSlotURL`,
/// computed outside both with Python's hmac): key bytes 0..31, slot
/// "AAAAAAAAAAA".
#[test]
fn the_read_token_matches_the_script_and_the_helper() {
    let key: Vec<u8> = (0u8..32).collect();
    assert_eq!(read_token(&key, "AAAAAAAAAAA"), "IE3eTuAK8S6tNOQQlH44VQ");
    assert_eq!(
        slot_url(BASE, &key, "AAAAAAAAAAA"),
        format!("{BASE}?s=AAAAAAAAAAA&k=IE3eTuAK8S6tNOQQlH44VQ")
    );
    // RFC 4231 test case 2: the HMAC itself.
    assert_eq!(
        hex::encode(hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
    // A key longer than a block is hashed first (RFC 4231 test case 6).
    assert_eq!(
        hex::encode(hmac_sha256(
            &[0xaa; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First"
        )),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
    );
    let slot = new_slot();
    assert!(valid_slot(&slot) && slot != TEST_SLOT);
    assert!(valid_slot(TEST_SLOT));
}

#[test]
fn pasted_addresses_have_one_shape() {
    let id = "AKfycbx0123456789abcdefghij";
    let want = format!("https://script.google.com/macros/s/{id}/exec");
    for pasted in [
        format!("https://script.google.com/macros/s/{id}/exec"),
        format!("  https://script.google.com/macros/s/{id}/exec/ "),
        format!("https://script.google.com/macros/s/{id}/exec?usp=sharing#x"),
        format!("HTTPS://SCRIPT.GOOGLE.COM/macros/s/{id}/exec"),
    ] {
        assert_eq!(normalize_base(&pasted).unwrap(), want, "{pasted}");
    }
    for bad in [
        format!("http://script.google.com/macros/s/{id}/exec"),
        format!("https://script.google.com/macros/s/{id}/dev"),
        format!("https://script.google.com/a/macros/example.org/s/{id}/exec"),
        format!("https://script.google.com.evil.example/macros/s/{id}/exec"),
        "https://script.google.com/macros/s/short/exec".to_string(),
        "https://script.google.com/macros/s/has%2Fslash000000000000/exec".to_string(),
        "آدرس https://script.google.com/macros/s/AKfycbx0123456789abcdefghij/exec".to_string(),
    ] {
        assert!(normalize_base(&bad).is_err(), "{bad}");
    }
}

// --------------------------------------------------------------------
// The account
// --------------------------------------------------------------------

#[test]
fn the_script_carries_the_account_key_from_custody_never_from_argv() {
    let f = fx();
    let seen = happy_helper(&f);
    assert_eq!(account(&f.ctx).unwrap(), GoogleAccount::default());
    let s = account_script(&f.ctx, &mut noop()).unwrap();
    assert_eq!(s.code_gs, "// code");
    assert!(!format!("{s:?}").contains("// code"), "Debug leaves the script out");

    let key = account_key_bytes(&f);
    assert_eq!(key.len(), 32);
    let a = account(&f.ctx).unwrap();
    assert!(a.script_made && !a.connected && a.url.is_empty());
    let call = &calls_of(&seen, "appsscript-script")[0].0;
    let hexkey = hex::encode(&key);
    assert!(!call.iter().any(|a| a.contains(&hexkey)), "the key never goes in argv");
    assert!(!call.iter().any(|a| a == "--path-token"), "one script for every relay");

    // A second copy is the same script: one pasted already stays good.
    account_script(&f.ctx, &mut noop()).unwrap();
    assert_eq!(account_key_bytes(&f), key);
}

#[test]
fn connecting_by_hand_checks_the_address_before_it_counts() {
    let f = fx();
    let answer = Arc::new(Mutex::new(
        r#"{"ok":false,"via_front":false,"reason":"not_deployed","detail":"the answer is not from Daal's script"}"#
            .to_string(),
    ));
    let a2 = answer.clone();
    let seen = helper(&f, move |verb, _, _| match verb {
        "appsscript-script" => Ok(r#"{"code_gs":"x","manifest_json":"{}"}"#.into()),
        _ => Ok(a2.lock().unwrap().clone()),
    });
    let e = account_attach(&f.ctx, GoogleAccountAttachInput { url: BASE.into() }, &mut noop())
        .unwrap_err();
    assert!(e.to_string().contains("copy the script first"), "{e}");

    account_script(&f.ctx, &mut noop()).unwrap();
    let e = account_attach(
        &f.ctx,
        GoogleAccountAttachInput { url: "https://example.com/macros/s/x/exec".into() },
        &mut noop(),
    )
    .unwrap_err();
    assert!(e.to_string().starts_with("E_GOOGLE_BAD_ADDRESS: "), "{e}");
    assert!(calls_of(&seen, "appsscript-account-check").is_empty(), "no check of a bad address");

    let e = account_attach(&f.ctx, GoogleAccountAttachInput { url: BASE.into() }, &mut noop())
        .unwrap_err();
    assert!(e.to_string().starts_with("E_GOOGLE_CHECK_FAILED: not_deployed"), "{e}");
    let a = account(&f.ctx).unwrap();
    assert!(!a.connected && a.script_made, "not connected until the check passes");

    *answer.lock().unwrap() = format!(
        r#"{{"ok":true,"via_front":true,"posted":true,"seq":5,"sha256":"{}","reason":"","url":"{BASE}"}}"#,
        "c".repeat(64)
    );
    let a = account_attach(
        &f.ctx,
        GoogleAccountAttachInput { url: format!("{BASE}?usp=sharing") },
        &mut noop(),
    )
    .unwrap();
    assert!(a.connected && !a.script_made);
    assert_eq!(a.url, BASE);
    // The check got the normalised address and the key as a file.
    let check = calls_of(&seen, "appsscript-account-check").last().cloned().unwrap();
    assert_eq!(arg_after(&check.0, "--url").as_deref(), Some(BASE));
    assert!(!check.0.iter().any(|a| a.contains(&hex::encode(account_key_bytes(&f)))));
    assert_eq!(f.ctx.custody.get(ACCOUNT_URL_ALIAS).unwrap(), BASE.as_bytes());
}

#[test]
fn disconnect_forgets_the_account_and_relays_keep_theirs() {
    let f = fx();
    let op = provisioned(&f);
    let seen = happy_helper(&f);
    connect_account(&f);
    let row = turn_on(&f.ctx, GoogleOnInput { operator_id: op }, &mut noop()).unwrap();
    account_disconnect(&f.ctx).unwrap();
    assert_eq!(account(&f.ctx).unwrap(), GoogleAccount::default());
    assert!(f.ctx.custody.get(ACCOUNT_KEY_ALIAS).is_err());
    // The relay's channel still has its key, so it still publishes and
    // can still be turned off.
    assert!(has_write_key(&f.ctx, op));
    let r = addons::remove(&f.ctx, row.id, &mut noop()).unwrap();
    assert!(r.removed, "{r:?}");
    assert!(calls_of(&seen, "appsscript-check").len() >= 2);
    // A relay cannot turn it on with no account.
    let e = turn_on(&f.ctx, GoogleOnInput { operator_id: op }, &mut noop()).unwrap_err();
    assert!(e.to_string().starts_with("E_GOOGLE_NO_ACCOUNT: "), "{e}");
}

#[test]
fn sign_in_with_a_platform_token_passes_it_on_stdin_only() {
    let f = fx();
    let seen = happy_helper(&f);
    let token = Zeroizing::new("ya29.one-shot-token".to_string());
    let a = account_sign_in(&f.ctx, Some(token), &mut noop()).unwrap();
    assert!(a.connected);
    assert_eq!(a.url, BASE);

    let deploy = calls_of(&seen, "appsscript-deploy")[0].clone();
    assert!(!deploy.0.iter().any(|a| a.contains("ya29")), "the token never goes in argv");
    assert!(!deploy.0.iter().any(|a| a == "--path-token"));
    let stdin: serde_json::Value = serde_json::from_slice(&deploy.1).unwrap();
    assert_eq!(stdin["access_token"], "ya29.one-shot-token");
    // The same connect check as by hand.
    assert_eq!(
        arg_after(&calls_of(&seen, "appsscript-account-check")[0].0, "--url").as_deref(),
        Some(BASE)
    );
    // Nothing of the token is kept.
    for alias in ACCOUNT_ALIASES.iter().chain([&ACCOUNT_PARTIAL_ALIAS]) {
        if let Ok(v) = f.ctx.custody.get(alias) {
            assert!(!String::from_utf8_lossy(&v).contains("ya29"), "{alias}");
        }
    }
}

#[test]
fn a_partial_deploy_is_resumed_into_the_same_project() {
    let f = fx();
    let fail = Arc::new(Mutex::new(true));
    let f2 = fail.clone();
    let seen = helper(&f, move |verb, args, _| match verb {
        "appsscript-deploy" if *f2.lock().unwrap() => Err(BridgeError::SubprocessFailed {
            rc: 1,
            stderr: "E_GOOGLE_PARTIAL: script_id=1PartialProject0000000001 stage=version: apps script version: failed (HTTP 500)\n".into(),
        }),
        "appsscript-deploy" => Ok(format!(
            r#"{{"script_id":"1PartialProject0000000001","deployment_id":"{DEPLOYMENT}","version":1,"url":"{BASE}"}}"#
        )),
        _ => Ok(format!(
            r#"{{"ok":true,"via_front":true,"posted":true,"seq":9,"sha256":"{}","reason":"","url":"{}"}}"#,
            "d".repeat(64),
            arg_after(args, "--url").unwrap_or_default()
        )),
    });
    let tok = || Some(Zeroizing::new("ya29.t".to_string()));
    let e = account_sign_in(&f.ctx, tok(), &mut noop()).unwrap_err();
    assert!(e.to_string().starts_with("E_GOOGLE_PARTIAL: "), "{e}");
    assert!(!account(&f.ctx).unwrap().connected);

    *fail.lock().unwrap() = false;
    account_sign_in(&f.ctx, tok(), &mut noop()).unwrap();
    let second = calls_of(&seen, "appsscript-deploy")[1].clone();
    assert_eq!(
        arg_after(&second.0, "--script-id").as_deref(),
        Some("1PartialProject0000000001")
    );
    assert!(f.ctx.custody.get(ACCOUNT_PARTIAL_ALIAS).is_err(), "the partial project is forgotten once deployed");
}

#[test]
fn helper_errors_keep_their_code() {
    let f = fx();
    helper(&f, |_, _, _| {
        Err(BridgeError::SubprocessFailed {
            rc: 1,
            stderr: "E_GOOGLE_API_NOT_ENABLED: turn on the Apps Script API at script.google.com/home/usersettings, then try again\n".into(),
        })
    });
    let e = account_sign_in(&f.ctx, Some(Zeroizing::new("t".into())), &mut noop()).unwrap_err();
    assert!(e.to_string().starts_with("E_GOOGLE_API_NOT_ENABLED: "), "{e}");

    // An older helper without the verbs.
    *f.mock.addon_reply.lock().unwrap() = None;
    let e = account_script(&f.ctx, &mut noop()).unwrap_err();
    assert!(e.to_string().starts_with("E_DEPLOY_TOO_OLD: "), "{e}");
}

#[test]
fn desktop_sign_in_without_a_client_is_not_configured() {
    let f = fx();
    if desktop_client().is_some() {
        return; // a build with the client configured
    }
    assert!(!desktop_sign_in_configured(), "the UI must not offer it");
    let e = account_sign_in(&f.ctx, None, &mut noop()).unwrap_err();
    assert!(e.to_string().starts_with("E_GOOGLE_NOT_CONFIGURED: "), "{e}");
    assert!(f.mock.addon_calls.lock().unwrap().is_empty());
    assert!(!account(&f.ctx).unwrap().sign_in);
}

fn test_client() -> DesktopClient {
    DesktopClient {
        id: "123-test.apps.googleusercontent.com".into(),
        secret: "GOCSPX-not-confidential".into(),
        auth_endpoint: "https://accounts.example.test/auth".into(),
    }
}

fn query_param(url: &str, name: &str) -> String {
    let q = url.split_once('?').unwrap().1;
    q.split('&')
        .find_map(|kv| kv.strip_prefix(&format!("{name}=")))
        .map(|v| unpct(v).unwrap())
        .unwrap()
}

/// A browser that, once opened, sends `requests` (path and query) to
/// the redirect address in order. `{state}` is replaced with the
/// attempt's state.
fn browser(
    requests: Vec<String>,
    opened: Arc<Mutex<String>>,
) -> impl FnMut(&str) -> std::io::Result<()> {
    move |url: &str| {
        *opened.lock().unwrap() = url.to_string();
        let redirect = query_param(url, "redirect_uri");
        let state = query_param(url, "state");
        let addr = redirect.strip_prefix("http://").unwrap().to_string();
        let reqs: Vec<String> = requests
            .iter()
            .map(|r| r.replace("{state}", &state))
            .collect();
        std::thread::spawn(move || {
            for r in reqs {
                let mut s = TcpStream::connect(&addr).unwrap();
                write!(s, "GET {r} HTTP/1.1\r\nHost: {addr}\r\n\r\n").unwrap();
                let mut out = String::new();
                let _ = s.read_to_string(&mut out);
            }
        });
        Ok(())
    }
}

#[test]
fn desktop_loopback_sign_in_with_pkce() {
    let f = fx();
    let seen = happy_helper(&f);
    let opened = Arc::new(Mutex::new(String::new()));
    let mut open = browser(
        vec![
            "/favicon.ico".into(),
            "/?state=not-this-attempt&code=4%2Fstranger".into(),
            "/?state={state}&code=4%2Fthe-code&scope=x".into(),
        ],
        opened.clone(),
    );
    let a = account_sign_in_with(
        &f.ctx,
        SignIn::Desktop(test_client()),
        &mut open,
        Duration::from_secs(10),
        &mut noop(),
    )
    .unwrap();
    assert!(a.connected);

    let url = opened.lock().unwrap().clone();
    assert!(url.starts_with("https://accounts.example.test/auth?"));
    assert_eq!(query_param(&url, "scope"), SCOPES.join(" "));
    assert_eq!(query_param(&url, "code_challenge_method"), "S256");
    assert_eq!(
        query_param(&url, "access_type"),
        "online",
        "no refresh token is asked for"
    );
    assert!(query_param(&url, "redirect_uri").starts_with("http://127.0.0.1:"));

    let calls = seen.lock().unwrap().clone();
    let deploy = calls
        .iter()
        .find(|c| c.0[0] == "appsscript-deploy")
        .unwrap();
    let stdin: serde_json::Value = serde_json::from_slice(&deploy.1).unwrap();
    assert_eq!(
        stdin["code"], "4/the-code",
        "the stranger's code was ignored"
    );
    assert_eq!(stdin["client_id"], "123-test.apps.googleusercontent.com");
    assert_eq!(stdin["redirect_uri"], query_param(&url, "redirect_uri"));
    let verifier = stdin["code_verifier"].as_str().unwrap();
    assert_eq!(
        URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())),
        query_param(&url, "code_challenge")
    );
    assert!(stdin.get("access_token").is_none());
}

#[test]
fn desktop_sign_in_refused_or_abandoned() {
    let f = fx();
    happy_helper(&f);
    let mut open = browser(
        vec!["/?state={state}&error=access_denied".into()],
        Arc::new(Mutex::new(String::new())),
    );
    let e = account_sign_in_with(
        &f.ctx,
        SignIn::Desktop(test_client()),
        &mut open,
        Duration::from_secs(10),
        &mut noop(),
    )
    .unwrap_err();
    assert!(
        e.to_string().starts_with("E_GOOGLE_SIGN_IN_CANCELLED: "),
        "{e}"
    );

    let mut nobody = |_: &str| Ok(());
    let e = account_sign_in_with(
        &f.ctx,
        SignIn::Desktop(test_client()),
        &mut nobody,
        Duration::from_millis(300),
        &mut noop(),
    )
    .unwrap_err();
    assert!(
        e.to_string().starts_with("E_GOOGLE_SIGN_IN_CANCELLED: "),
        "{e}"
    );
    assert!(!f
        .mock
        .addon_calls
        .lock()
        .unwrap()
        .iter()
        .any(|a| a[0] == "appsscript-deploy"));
}

// --------------------------------------------------------------------
// A relay's switch
// --------------------------------------------------------------------

#[test]
fn a_relay_switch_without_the_account_changes_nothing() {
    let f = fx();
    let op = provisioned(&f);
    let seen = happy_helper(&f);
    let e = turn_on(&f.ctx, GoogleOnInput { operator_id: op }, &mut noop()).unwrap_err();
    assert!(e.to_string().starts_with("E_GOOGLE_NO_ACCOUNT: "), "{e}");
    assert!(row_for(&f.ctx, op).unwrap().is_none());
    assert!(f.ctx.db.list_freshness_endpoints(op).unwrap().is_empty());
    assert!(seen.lock().unwrap().is_empty());
    // A copied script with no address yet is not an account either.
    account_script(&f.ctx, &mut noop()).unwrap();
    let e = turn_on(&f.ctx, GoogleOnInput { operator_id: op }, &mut noop()).unwrap_err();
    assert!(e.to_string().starts_with("E_GOOGLE_NO_ACCOUNT: "), "{e}");
}

#[test]
fn turning_on_gives_the_relay_a_slot_and_a_mirror() {
    let f = fx();
    let op = provisioned(&f);
    let seen = happy_helper(&f);
    connect_account(&f);
    let row = turn_on(&f.ctx, GoogleOnInput { operator_id: op }, &mut noop()).unwrap();
    assert_eq!(row.state, AddonState::Ready);
    let d = detail_of(&row);
    assert!(valid_slot(&d.slot) && d.slot != TEST_SLOT);
    let key = account_key_bytes(&f);
    assert_eq!(d.url, slot_url(BASE, &key, &d.slot));
    assert_eq!(d.deployment_id, DEPLOYMENT);
    assert_eq!(row.provider_ids.get("slot"), Some(&d.slot));
    // The relay holds its own copy of the account key.
    assert!(row.has_secret);
    assert_ne!(row.secret_alias, ACCOUNT_KEY_ALIAS);
    assert_eq!(f.ctx.custody.get(&row.secret_alias).unwrap(), key);
    assert!(!row.detail.to_string().contains(&hex::encode(&key)), "no key in the row");

    // The first update went to the slot under a fresh number, and the
    // freshness counter moved past it.
    let check = calls_of(&seen, "appsscript-check").last().cloned().unwrap();
    assert_eq!(arg_after(&check.0, "--url").unwrap(), d.url);
    let seq: u64 = arg_after(&check.0, "--seq").unwrap().parse().unwrap();
    assert!(f.ctx.db.get(op).unwrap().freshness_last_sequence as u64 >= seq);
    assert!(d.posted_seq >= 1_800_000_000);
    assert!(!check.0.iter().any(|a| a.contains(&hex::encode(&key))));

    let st = freshness::status(&f.ctx, op).unwrap();
    assert_eq!(st.endpoints.len(), 1);
    assert_eq!(st.endpoints[0].kind, "appsscript");
    assert_eq!(st.endpoints[0].public_url, d.url);
    assert!(st.endpoints[0].has_credential);
    assert!(st.google_only);
    assert_eq!(st.min_mirrors, 1);
    // The table holds no secret of its own for it.
    let ep = f.ctx.db.list_freshness_endpoints(op).unwrap();
    assert_eq!(ep[0].secret_alias, "");
    // And the freshness panel cannot remove it behind the add-on's back.
    assert!(freshness::delete_endpoint(&f.ctx, ep[0].id).is_err());
    assert!(freshness::add_endpoint(
        &f.ctx,
        op,
        FreshnessEndpointInput {
            kind: "appsscript".into(),
            public_url: d.url.clone(),
            ..Default::default()
        }
    )
    .is_err());

    // On again: nothing more is done.
    let n = seen.lock().unwrap().len();
    let again = turn_on(&f.ctx, GoogleOnInput { operator_id: op }, &mut noop()).unwrap();
    assert_eq!(again.id, row.id);
    assert_eq!(seen.lock().unwrap().len(), n);
}

#[test]
fn two_relays_share_the_script_and_never_a_slot() {
    let f = fx();
    let a = provisioned(&f);
    let b = provisioned(&f);
    happy_helper(&f);
    connect_account(&f);
    let ra = turn_on(&f.ctx, GoogleOnInput { operator_id: a }, &mut noop()).unwrap();
    let rb = turn_on(&f.ctx, GoogleOnInput { operator_id: b }, &mut noop()).unwrap();
    let (da, db) = (detail_of(&ra), detail_of(&rb));
    assert_ne!(da.slot, db.slot);
    assert!(da.url.starts_with(BASE) && db.url.starts_with(BASE));
    assert_ne!(ra.secret_alias, rb.secret_alias);
}

#[test]
fn a_failed_first_update_takes_the_mirror_out_and_on_again_finishes() {
    let f = fx();
    let op = provisioned(&f);
    happy_helper(&f);
    connect_account(&f);
    let answer = Arc::new(Mutex::new(
        r#"{"ok":false,"reason":"unreachable","detail":"front: dial: timeout"}"#.to_string(),
    ));
    let a2 = answer.clone();
    helper(&f, move |_, _, _| Ok(a2.lock().unwrap().clone()));
    let e = turn_on(&f.ctx, GoogleOnInput { operator_id: op }, &mut noop()).unwrap_err();
    assert!(e.to_string().starts_with("E_GOOGLE_CHECK_FAILED: unreachable: front: dial"), "{e}");
    let row = google_row(&f, op);
    assert_eq!(row.state, AddonState::Building);
    let slot = detail_of(&row).slot;
    assert!(
        f.ctx.db.list_freshness_endpoints(op).unwrap().is_empty(),
        "not a mirror until it works"
    );

    *answer.lock().unwrap() = ok_check(5);
    let row = turn_on(&f.ctx, GoogleOnInput { operator_id: op }, &mut noop()).unwrap();
    assert_eq!(row.state, AddonState::Ready);
    assert_eq!(detail_of(&row).slot, slot, "the retry keeps the slot");
    assert_eq!(f.ctx.db.list_freshness_endpoints(op).unwrap().len(), 1);

    // A later check only fetches, against what was posted.
    let seen = helper(&f, |_, _, _| {
        Ok(r#"{"ok":false,"via_front":false,"reason":"wrong_content"}"#.into())
    });
    let c = check(&f.ctx, GoogleCheckInput { operator_id: op }, &mut noop()).unwrap();
    assert_eq!(c.reason, "wrong_content");
    let args = seen.lock().unwrap()[0].0.clone();
    assert!(args.contains(&"--expect-sha256".to_string()));
    assert!(!args.contains(&"--seq".to_string()), "a check of a ready channel sends nothing");
    assert_eq!(detail_of(&google_row(&f, op)).last_check_reason, "wrong_content");
}

fn ready_channel(f: &Fx, op: i64) -> AddonRow {
    connect_account(f);
    turn_on(&f.ctx, GoogleOnInput { operator_id: op }, &mut noop()).unwrap()
}

#[test]
fn turning_off_clears_the_slot_then_forgets_the_relays_key() {
    let f = fx();
    let op = provisioned(&f);
    let seen = happy_helper(&f);
    let row = ready_channel(&f, op);
    let url = detail_of(&row).url;
    let r = addons::remove(&f.ctx, row.id, &mut noop()).unwrap();
    assert!(r.removed, "{r:?}");
    assert!(r.by_hand.is_empty(), "nothing per relay to do in Google: {r:?}");
    assert!(row_for(&f.ctx, op).unwrap().is_none());
    assert!(f.ctx.custody.get(&row.secret_alias).is_err(), "the relay's copy is forgotten");
    assert!(f.ctx.db.list_freshness_endpoints(op).unwrap().is_empty());
    let last = seen.lock().unwrap().last().cloned().unwrap();
    assert_eq!(last.0[0], "appsscript-check");
    assert_eq!(arg_after(&last.0, "--url").unwrap(), url, "the relay's own slot");
    assert!(arg_after(&last.0, "--seq").is_some(), "the empty container went out");
    assert!(arg_after(&last.0, "--freshness-file").is_none());
    // The account is untouched.
    assert!(account(&f.ctx).unwrap().connected);
}

#[test]
fn a_remove_that_cannot_clear_keeps_the_key_for_the_retry() {
    let f = fx();
    let op = provisioned(&f);
    happy_helper(&f);
    let row = ready_channel(&f, op);
    helper(&f, |_, _, _| Ok(r#"{"ok":false,"reason":"unreachable"}"#.into()));
    let r = addons::remove(&f.ctx, row.id, &mut noop()).unwrap();
    assert!(!r.removed);
    assert!(r.warnings.iter().any(|w| w == "clear_failed:unreachable"), "{r:?}");
    let kept = google_row(&f, op);
    assert_eq!(kept.state, AddonState::Removing);
    assert!(f.ctx.custody.get(&kept.secret_alias).is_ok());
    let e = turn_on(&f.ctx, GoogleOnInput { operator_id: op }, &mut noop()).unwrap_err();
    assert!(e.to_string().contains("has not finished"), "{e}");

    happy_helper(&f);
    assert!(addons::remove(&f.ctx, row.id, &mut noop()).unwrap().removed);
}

#[test]
fn relay_delete_never_waits_on_the_channel() {
    let f = fx();
    let op = provisioned(&f);
    happy_helper(&f);
    let row = ready_channel(&f, op);
    helper(&f, |_, _, _| Ok(r#"{"ok":false,"reason":"unreachable"}"#.into()));
    let o = on_relay_delete(&f.ctx, &row);
    assert!(o.removed && !o.keeps_relay, "{o:?}");
    assert!(o.error.contains("unreachable"));
}

/// The channel is one more target of the freshness publish: the helper
/// gets its URL and its write key (as a file) with the other mirrors'
/// credentials, and its result is counted like theirs.
#[test]
fn freshness_publish_sends_to_the_channel() {
    let f = fx();
    let op = provisioned(&f);
    let seen = happy_helper(&f);
    ready_channel(&f, op);
    let before = seen.lock().unwrap().len();
    f.ctx
        .db
        .record_signed_sbp(op, &"d".repeat(64), "rp-g", 1_800_000_000)
        .unwrap();
    freshness::set_pack_url(&f.ctx, op, "https://packs.example.com/x.sbp").unwrap();

    // Alone (D-3).
    let r = freshness::publish(&f.ctx, op, &mut |_| {}).unwrap();
    assert_eq!(r.blocked_reason, "");
    assert_eq!(r.min_mirrors, 1);
    assert_eq!(r.succeeded, 1, "{r:?}");
    // No separate send: the channel rides publish-freshness.
    assert_eq!(seen.lock().unwrap().len(), before, "a separate appsscript-check ran");
    let call = f
        .mock
        .publish_freshness_calls
        .lock()
        .unwrap()
        .last()
        .cloned()
        .unwrap();
    assert!(
        call.mirrors[0].starts_with("appsscript=https://script.google.com/macros/s/"),
        "{:?}",
        call.mirrors
    );
    assert!(call.appsscript_url.starts_with("https://script.google.com/macros/s/"));
    assert!(call.appsscript_key_staged, "the write key did not reach the helper as a file");
    assert!(call.uploaded);
    // The signed pack goes in only when it is the file the note names.
    assert!(call.appsscript_pack.is_none());

    // Beside one other provider: both are targets of one publish.
    freshness::add_endpoint(
        &f.ctx,
        op,
        FreshnessEndpointInput {
            kind: "ghpages".into(),
            public_url: "https://o.github.io/r/f.json".into(),
            gh_owner: "o".into(),
            gh_repo: "r".into(),
            gh_path: "f.json".into(),
            gh_pat: "github_pat_test".into(),
            ..Default::default()
        },
    )
    .unwrap();
    let r = freshness::publish(&f.ctx, op, &mut |_| {}).unwrap();
    assert_eq!(r.blocked_reason, "");
    assert_eq!(r.succeeded, 2, "{r:?}");
    assert_eq!(r.min_mirrors, 2);

    // Beside two: all three count.
    freshness::add_endpoint(
        &f.ctx,
        op,
        FreshnessEndpointInput {
            kind: "r2".into(),
            public_url: "https://r2.example.com/f.json".into(),
            account_id: "acc".into(),
            bucket: "b".into(),
            object_key: "f.json".into(),
            access_key_id: "AKID".into(),
            secret_access_key: "r2-secret".into(),
            ..Default::default()
        },
    )
    .unwrap();
    let r = freshness::publish(&f.ctx, op, &mut |_| {}).unwrap();
    assert_eq!(r.blocked_reason, "");
    assert_eq!(r.succeeded, 3, "{r:?}");
    assert_eq!(r.min_mirrors, 2);
    let g = r.results.iter().find(|o| o.kind == "appsscript").unwrap();
    assert!(g.ok);
    assert_eq!(seen.lock().unwrap().len(), before, "a separate appsscript-check ran");
    // The pack recipients hold does not carry the channel alone yet;
    // with two other providers it does.
    let args = freshness::mirror_args(&f.ctx, op).unwrap();
    assert_eq!(args.len(), 3);
}
