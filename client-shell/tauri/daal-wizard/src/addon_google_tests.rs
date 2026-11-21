//! The Google update channel, driven through the real functions
//! against `MockRunner`. Nothing reaches Google: the `daal-deploy`
//! verbs are answered by `addon_reply` (their own behaviour against a
//! fake Google is tested in Go, `cli_addon_google_test.go`).

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

/// A standard helper: script, check (ok), deploy, clear.
fn happy_helper(f: &Fx) -> Seen {
    helper(f, |verb, args, _| match verb {
        "appsscript-script" => Ok(r#"{"code_gs":"// code","manifest_json":"{}"}"#.into()),
        "appsscript-check" => {
            let seq = arg_after(args, "--seq")
                .and_then(|s| s.parse().ok())
                .unwrap_or(77);
            Ok(ok_check(seq))
        }
        "appsscript-deploy" => Ok(format!(
            r#"{{"script_id":"1ScriptProject000000000001","deployment_id":"{DEPLOYMENT}","version":1,"url":"https://script.google.com/macros/s/{DEPLOYMENT}/exec?k={}"}}"#,
            arg_after(args, "--path-token").unwrap()
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

#[test]
fn the_script_carries_a_key_from_custody_never_from_argv() {
    let f = fx();
    let op = provisioned(&f);
    let seen = happy_helper(&f);
    let s = script(&f.ctx, GoogleScriptInput { operator_id: op }, &mut noop()).unwrap();
    assert_eq!(s.code_gs, "// code");
    assert!(
        !format!("{s:?}").contains("// code"),
        "Debug leaves the script out"
    );

    let row = google_row(&f, op);
    assert_eq!(row.state, AddonState::Building);
    assert!(row.has_secret);
    let key = f.ctx.custody.get(&row.secret_alias).unwrap();
    assert_eq!(key.len(), 32);
    let d = detail_of(&row);
    assert_eq!(d.path_token.len(), 22);
    let calls = seen.lock().unwrap().clone();
    let args = &calls[0].0;
    assert_eq!(arg_after(args, "--path-token").unwrap(), d.path_token);
    let hexkey = hex::encode(&key);
    assert!(
        !args.iter().any(|a| a.contains(&hexkey)),
        "the key never goes in argv"
    );
    assert!(!row.detail.to_string().contains(&hexkey), "nor in the row");

    // A second look gives the same script for the same relay.
    script(&f.ctx, GoogleScriptInput { operator_id: op }, &mut noop()).unwrap();
    let again = google_row(&f, op);
    assert_eq!(again.id, row.id);
    assert_eq!(f.ctx.custody.get(&again.secret_alias).unwrap(), key);
}

#[test]
fn path_b_attach_checks_then_becomes_a_mirror() {
    let f = fx();
    let op = provisioned(&f);
    let seen = happy_helper(&f);
    let bad = attach(
        &f.ctx,
        GoogleAttachInput {
            operator_id: op,
            url: format!("https://script.google.com/macros/s/{DEPLOYMENT}/exec"),
        },
        &mut noop(),
    )
    .unwrap_err();
    assert!(bad.to_string().contains("copy the script first"), "{bad}");

    script(&f.ctx, GoogleScriptInput { operator_id: op }, &mut noop()).unwrap();
    let e = attach(
        &f.ctx,
        GoogleAttachInput {
            operator_id: op,
            url: "https://example.com/macros/s/x/exec".into(),
        },
        &mut noop(),
    )
    .unwrap_err();
    assert!(e.to_string().starts_with("E_GOOGLE_BAD_ADDRESS: "), "{e}");

    let row = attach(
        &f.ctx,
        GoogleAttachInput {
            operator_id: op,
            url: format!(" https://script.google.com/macros/s/{DEPLOYMENT}/exec "),
        },
        &mut noop(),
    )
    .unwrap();
    assert_eq!(row.state, AddonState::Ready);
    assert_eq!(
        row.provider_ids.get("deployment_id").map(String::as_str),
        Some(DEPLOYMENT)
    );
    let d = detail_of(&row);
    assert_eq!(d.path, "B");
    assert_eq!(
        d.url,
        format!(
            "https://script.google.com/macros/s/{DEPLOYMENT}/exec?k={}",
            d.path_token
        )
    );
    assert!(d.posted_seq >= 1_800_000_000);

    // The check posted the empty container under a fresh number, and
    // the freshness counter moved past it.
    let check_call = seen
        .lock()
        .unwrap()
        .iter()
        .find(|c| c.0[0] == "appsscript-check")
        .cloned()
        .unwrap();
    assert_eq!(arg_after(&check_call.0, "--url").unwrap(), d.url);
    let seq: u64 = arg_after(&check_call.0, "--seq").unwrap().parse().unwrap();
    assert!(f.ctx.db.get(op).unwrap().freshness_last_sequence as u64 >= seq);

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
}

#[test]
fn a_failed_first_check_keeps_the_address_and_check_finishes_it() {
    let f = fx();
    let op = provisioned(&f);
    let answer = Arc::new(Mutex::new(
        r#"{"ok":false,"reason":"not_deployed","detail":"the answer is not from Daal's script"}"#
            .to_string(),
    ));
    let a2 = answer.clone();
    helper(&f, move |verb, _, _| match verb {
        "appsscript-script" => Ok(r#"{"code_gs":"x","manifest_json":"{}"}"#.into()),
        _ => Ok(a2.lock().unwrap().clone()),
    });
    script(&f.ctx, GoogleScriptInput { operator_id: op }, &mut noop()).unwrap();
    let e = attach(
        &f.ctx,
        GoogleAttachInput {
            operator_id: op,
            url: format!("https://script.google.com/macros/s/{DEPLOYMENT}/exec"),
        },
        &mut noop(),
    )
    .unwrap_err();
    assert!(
        e.to_string()
            .starts_with("E_GOOGLE_CHECK_FAILED: not_deployed"),
        "{e}"
    );
    let row = google_row(&f, op);
    assert_eq!(row.state, AddonState::Building);
    assert!(!detail_of(&row).url.is_empty());
    assert!(
        f.ctx.db.list_freshness_endpoints(op).unwrap().is_empty(),
        "not a mirror until it works"
    );

    *answer.lock().unwrap() = ok_check(5);
    let c = check(&f.ctx, GoogleCheckInput { operator_id: op }, &mut noop()).unwrap();
    assert!(c.ok && c.via_front && c.reason.is_empty());
    assert_eq!(google_row(&f, op).state, AddonState::Ready);
    assert_eq!(f.ctx.db.list_freshness_endpoints(op).unwrap().len(), 1);

    // A later check only fetches, against what was posted.
    let seen = helper(&f, |_, _, _| {
        Ok(r#"{"ok":false,"via_front":false,"reason":"wrong_content"}"#.into())
    });
    let c = check(&f.ctx, GoogleCheckInput { operator_id: op }, &mut noop()).unwrap();
    assert_eq!(c.reason, "wrong_content");
    let args = seen.lock().unwrap()[0].0.clone();
    assert!(args.contains(&"--expect-sha256".to_string()));
    assert!(
        !args.contains(&"--seq".to_string()),
        "a check of a ready channel sends nothing"
    );
    assert_eq!(
        detail_of(&google_row(&f, op)).last_check_reason,
        "wrong_content"
    );
}

#[test]
fn path_a_with_a_platform_token_passes_it_on_stdin_only() {
    let f = fx();
    let op = provisioned(&f);
    let seen = happy_helper(&f);
    let token = Zeroizing::new("ya29.one-shot-token".to_string());
    let row = sign_in(
        &f.ctx,
        GoogleSignInInput { operator_id: op },
        Some(token),
        &mut noop(),
    )
    .unwrap();
    assert_eq!(row.state, AddonState::Ready);
    let d = detail_of(&row);
    assert_eq!(d.path, "A");
    assert_eq!(d.script_id, "1ScriptProject000000000001");
    assert_eq!(
        row.provider_ids.get("script_id").map(String::as_str),
        Some("1ScriptProject000000000001")
    );

    let calls = seen.lock().unwrap().clone();
    let deploy = calls
        .iter()
        .find(|c| c.0[0] == "appsscript-deploy")
        .unwrap();
    assert!(
        !deploy.0.iter().any(|a| a.contains("ya29")),
        "the token never goes in argv"
    );
    let stdin: serde_json::Value = serde_json::from_slice(&deploy.1).unwrap();
    assert_eq!(stdin["access_token"], "ya29.one-shot-token");
    // Nothing of the token is kept.
    assert!(!row.detail.to_string().contains("ya29"));
    for a in f.ctx.db.list_all_keystore_aliases().unwrap_or_default() {
        if let Ok(v) = f.ctx.custody.get(&a) {
            assert!(!String::from_utf8_lossy(&v).contains("ya29"), "{a}");
        }
    }
}

#[test]
fn a_partial_deploy_is_resumed_into_the_same_project() {
    let f = fx();
    let op = provisioned(&f);
    let fail = Arc::new(Mutex::new(true));
    let f2 = fail.clone();
    let seen = helper(&f, move |verb, args, _| {
        match verb {
        "appsscript-deploy" if *f2.lock().unwrap() => Err(BridgeError::SubprocessFailed {
            rc: 1,
            stderr: "E_GOOGLE_PARTIAL: script_id=1PartialProject0000000001 stage=version: apps script version: failed (HTTP 500)\n".into(),
        }),
        "appsscript-deploy" => Ok(format!(
            r#"{{"script_id":"1PartialProject0000000001","deployment_id":"{DEPLOYMENT}","version":1,"url":"https://script.google.com/macros/s/{DEPLOYMENT}/exec?k={}"}}"#,
            arg_after(args, "--path-token").unwrap()
        )),
        _ => Ok(ok_check(9)),
    }
    });
    let tok = || Some(Zeroizing::new("ya29.t".to_string()));
    let e = sign_in(
        &f.ctx,
        GoogleSignInInput { operator_id: op },
        tok(),
        &mut noop(),
    )
    .unwrap_err();
    assert!(e.to_string().starts_with("E_GOOGLE_PARTIAL: "), "{e}");
    assert_eq!(
        detail_of(&google_row(&f, op)).partial_script_id,
        "1PartialProject0000000001"
    );

    *fail.lock().unwrap() = false;
    sign_in(
        &f.ctx,
        GoogleSignInInput { operator_id: op },
        tok(),
        &mut noop(),
    )
    .unwrap();
    let calls = seen.lock().unwrap().clone();
    let second = calls
        .iter()
        .filter(|c| c.0[0] == "appsscript-deploy")
        .nth(1)
        .unwrap();
    assert_eq!(
        arg_after(&second.0, "--script-id").as_deref(),
        Some("1PartialProject0000000001")
    );
    assert!(detail_of(&google_row(&f, op)).partial_script_id.is_empty());
}

#[test]
fn helper_errors_keep_their_code() {
    let f = fx();
    let op = provisioned(&f);
    helper(&f, |_, _, _| {
        Err(BridgeError::SubprocessFailed {
            rc: 1,
            stderr: "E_GOOGLE_API_NOT_ENABLED: turn on the Apps Script API at script.google.com/home/usersettings, then try again\n".into(),
        })
    });
    let e = sign_in(
        &f.ctx,
        GoogleSignInInput { operator_id: op },
        Some(Zeroizing::new("t".into())),
        &mut noop(),
    )
    .unwrap_err();
    assert!(
        e.to_string().starts_with("E_GOOGLE_API_NOT_ENABLED: "),
        "{e}"
    );

    // An older helper without the verbs.
    *f.mock.addon_reply.lock().unwrap() = None;
    let e = script(&f.ctx, GoogleScriptInput { operator_id: op }, &mut noop()).unwrap_err();
    assert!(e.to_string().starts_with("E_DEPLOY_TOO_OLD: "), "{e}");
}

#[test]
fn desktop_sign_in_without_a_client_is_not_configured() {
    let f = fx();
    let op = provisioned(&f);
    if desktop_client().is_some() {
        return; // a build with the client configured
    }
    let e = sign_in(
        &f.ctx,
        GoogleSignInInput { operator_id: op },
        None,
        &mut noop(),
    )
    .unwrap_err();
    assert!(
        e.to_string().starts_with("E_GOOGLE_NOT_CONFIGURED: "),
        "{e}"
    );
    assert!(f.mock.addon_calls.lock().unwrap().is_empty());
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
    let op = provisioned(&f);
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
    let row = sign_in_with(
        &f.ctx,
        GoogleSignInInput { operator_id: op },
        SignIn::Desktop(test_client()),
        &mut open,
        Duration::from_secs(10),
        &mut noop(),
    )
    .unwrap();
    assert_eq!(row.state, AddonState::Ready);

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
    let op = provisioned(&f);
    happy_helper(&f);
    let mut open = browser(
        vec!["/?state={state}&error=access_denied".into()],
        Arc::new(Mutex::new(String::new())),
    );
    let e = sign_in_with(
        &f.ctx,
        GoogleSignInInput { operator_id: op },
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
    let e = sign_in_with(
        &f.ctx,
        GoogleSignInInput { operator_id: op },
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

fn ready_channel(f: &Fx, op: i64) -> AddonRow {
    script(&f.ctx, GoogleScriptInput { operator_id: op }, &mut noop()).unwrap();
    attach(
        &f.ctx,
        GoogleAttachInput {
            operator_id: op,
            url: format!("https://script.google.com/macros/s/{DEPLOYMENT}/exec"),
        },
        &mut noop(),
    )
    .unwrap()
}

#[test]
fn remove_clears_the_script_then_forgets_the_key() {
    let f = fx();
    let op = provisioned(&f);
    let seen = happy_helper(&f);
    let row = ready_channel(&f, op);
    let r = addons::remove(&f.ctx, row.id, &mut noop()).unwrap();
    assert!(r.removed, "{r:?}");
    assert_eq!(r.by_hand, vec!["delete_google_project".to_string()]);
    assert!(row_for(&f.ctx, op).unwrap().is_none());
    assert!(
        f.ctx.custody.get(&row.secret_alias).is_err(),
        "the write key is forgotten"
    );
    assert!(f.ctx.db.list_freshness_endpoints(op).unwrap().is_empty());
    let last = seen.lock().unwrap().last().cloned().unwrap();
    assert_eq!(last.0[0], "appsscript-check");
    assert!(
        arg_after(&last.0, "--seq").is_some(),
        "the empty container went out"
    );
    assert!(arg_after(&last.0, "--freshness-file").is_none());
}

#[test]
fn a_remove_that_cannot_clear_keeps_the_key_for_the_retry() {
    let f = fx();
    let op = provisioned(&f);
    happy_helper(&f);
    let row = ready_channel(&f, op);
    helper(&f, |_, _, _| {
        Ok(r#"{"ok":false,"reason":"unreachable"}"#.into())
    });
    let r = addons::remove(&f.ctx, row.id, &mut noop()).unwrap();
    assert!(!r.removed);
    assert!(
        r.warnings.iter().any(|w| w == "clear_failed:unreachable"),
        "{r:?}"
    );
    let kept = google_row(&f, op);
    assert_eq!(kept.state, AddonState::Removing);
    assert!(f.ctx.custody.get(&kept.secret_alias).is_ok());

    happy_helper(&f);
    assert!(addons::remove(&f.ctx, row.id, &mut noop()).unwrap().removed);
}

#[test]
fn relay_delete_never_waits_on_the_channel() {
    let f = fx();
    let op = provisioned(&f);
    happy_helper(&f);
    let row = ready_channel(&f, op);
    helper(&f, |_, _, _| {
        Ok(r#"{"ok":false,"reason":"unreachable"}"#.into())
    });
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
