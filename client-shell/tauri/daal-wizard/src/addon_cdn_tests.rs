//! The Cloudflare add-on driven through its command functions against
//! `MockRunner`. The helper's `cdn-*` verbs are answered by a closure;
//! nothing reaches Cloudflare, Hetzner or a relay.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use super::*;
use crate::addons::{get, list};
use crate::cli_bridge::{CliRunner, MockRunner, Pricing};
use crate::commands::{
    provision_run, publisher_keygen, select_profile, set_helper_ip, store_cloud_token, WizardCtx,
};
use crate::device_custody::{DeviceCustody, FileCustody};
use crate::keystore::Keystore;
use crate::operator_db::OperatorDb;

const FP: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const HZ_TOKEN: &str = "hcloud-cdn-test-token-0001";
const CF_TOKEN: &str = "cf-test-token-five-permissions-0001";
const HOST: &str = "k3j9.example.com";

fn base_record() -> Value {
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
}

fn front() -> Value {
    serde_json::json!({
        "hostname": HOST, "zone": "example.com", "zone_id": "zone-1",
        "public_path": "/p", "origin_path": "/p", "origin_port": 8443,
        "worker_route_id": "", "firewall_id": "fw-9",
        "origin_ca_fingerprint": "ab", "origin_cert_id": "cert-1",
        "origin_ca_cert_path": "/x/origin_ca.pem", "origin_ca_priv_path": "/x/origin_ca.key",
        "aop_ca_cert_path": "/x/aop_ca.pem", "aop_cert_id": "aop-1",
        "aop_client_cert_path": "", "aop_enabled": true,
        "dns_record_ids": ["dns-1"], "origin_rule_ref": "daal-k3j9",
        "ech": {"zone_setting":"on","published":true,"config_list_b64":"AAA="}
    })
}

/// How each verb answers. `None`: the default good answer.
#[derive(Default)]
struct Helper {
    /// (verb, argv, stdin non-empty)
    calls: Vec<(String, Vec<String>, bool)>,
    token_check: Option<std::result::Result<Value, (i32, String)>>,
    provision_fail: Option<(i32, String)>,
    door_fail: Option<(i32, String)>,
    /// Answers of cdn-test in order; the last one repeats.
    tests: Vec<Value>,
    remove_incomplete: bool,
}

struct Fx {
    ctx: WizardCtx,
    mock: Arc<MockRunner>,
    helper: Arc<Mutex<Helper>>,
    _dir: tempfile::TempDir,
}

fn ok_test() -> Value {
    serde_json::json!({"ok":true,"edge":"","ech_offered":true,"ech_accepted":true,"elapsed_ms":120})
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
        .with_provision_record(base_record().to_string()),
    );
    let helper = Arc::new(Mutex::new(Helper::default()));
    let h = helper.clone();
    *mock.addon_reply.lock().unwrap() = Some(Box::new(move |args: &[String], stdin: &[u8]| {
        for a in args {
            assert!(!a.contains(CF_TOKEN) && !a.contains(HZ_TOKEN), "a token is never an argument");
        }
        let verb = args[0].clone();
        let mut h = h.lock().unwrap();
        h.calls.push((verb.clone(), args.to_vec(), !stdin.is_empty()));
        let fail = |f: &Option<(i32, String)>| -> std::result::Result<(), BridgeError> {
            match f {
                Some((rc, stderr)) => Err(BridgeError::SubprocessFailed { rc: *rc, stderr: stderr.clone() }),
                None => Ok(()),
            }
        };
        let has_record = |want: &str| {
            let at = args.iter().position(|a| a == "--record-file").expect("--record-file");
            let rec: Value = serde_json::from_str(&std::fs::read_to_string(&args[at + 1]).unwrap()).unwrap();
            assert_eq!(rec["hostname"], want);
        };
        let out = match verb.as_str() {
            "cdn-token-check" => match h.token_check.clone() {
                None => serde_json::json!({"verdict":"ok","token_id":"t1","zones":[{"id":"zone-1","name":"example.com","status":"active"}]}),
                Some(Ok(v)) => v,
                Some(Err((rc, stderr))) => return Err(BridgeError::SubprocessFailed { rc, stderr }),
            },
            "cdn-provision" => {
                fail(&h.provision_fail)?;
                assert!(args.windows(2).any(|w| w[0] == "--zone" && w[1] == "example.com"));
                assert!(args.windows(2).any(|w| w[0] == "--origin-ip" && w[1] == "203.0.113.7"));
                assert!(args.windows(2).any(|w| w[0] == "--firewall-id" && w[1] == "daal-relay-123"));
                front()
            }
            "cdn-door" => {
                has_record(HOST);
                assert!(args.windows(2).any(|w| w[0] == "--priv-key" && w[1] == "-"));
                assert!(!stdin.is_empty(), "the signing key travels on stdin");
                fail(&h.door_fail)?;
                serde_json::json!({"ok":true})
            }
            "cdn-test" => {
                has_record(HOST);
                let n = h.calls.iter().filter(|c| c.0 == "cdn-test").count();
                let v = if h.tests.is_empty() {
                    ok_test()
                } else {
                    h.tests[(n - 1).min(h.tests.len() - 1)].clone()
                };
                if v["ok"] != true {
                    // Exit 4 with the answer on stdout; the bridge of
                    // the future appends it to the failure text.
                    return Err(BridgeError::SubprocessFailed { rc: 4, stderr: v.to_string() });
                }
                v
            }
            "cdn-posture" => {
                has_record(HOST);
                serde_json::json!({"ssl_strict":true,"websockets":true,"origin_rule":true,"aop_enabled":true,
                    "name_hidden":true,"firewall_checked":true,"only_cloudflare":true,
                    "ech":{"zone_setting":"on","published":true}})
            }
            "cdn-remove" => {
                has_record(HOST);
                if h.remove_incomplete {
                    let v = serde_json::json!({"steps":[{"name":"dns_records","state":"done"},
                        {"name":"origin_certificate","state":"failed","detail":"cloudflare: 500"}],
                        "complete":false,"tell":[]});
                    return Err(BridgeError::SubprocessFailed { rc: 4, stderr: v.to_string() });
                }
                serde_json::json!({"steps":[{"name":"dns_records","state":"done"}],"complete":true,"tell":[]})
            }
            other => panic!("unexpected verb {other}"),
        };
        Ok(serde_json::to_vec(&out).unwrap())
    }));
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
    Fx { ctx, mock, helper, _dir: dir }
}

fn provisioned(f: &Fx) -> i64 {
    let id = store_cloud_token(&f.ctx, "hetzner", HZ_TOKEN, None).unwrap();
    select_profile(&f.ctx, id, "fsn1", "cx22", "iran-default", vec!["vless-reality".into()]).unwrap();
    publisher_keygen(&f.ctx, id).unwrap();
    set_helper_ip(&f.ctx, id, "198.51.100.1", "manual").unwrap();
    provision_run(&f.ctx, id, "", &mut |_| {}).unwrap();
    id
}

fn noop() -> impl FnMut(AddonProgress) {
    |_| {}
}

fn verbs(f: &Fx) -> Vec<String> {
    f.helper.lock().unwrap().calls.iter().map(|c| c.0.clone()).collect()
}

fn args_of(f: &Fx, verb: &str) -> Vec<Vec<String>> {
    f.helper
        .lock()
        .unwrap()
        .calls
        .iter()
        .filter(|c| c.0 == verb)
        .map(|c| c.1.clone())
        .collect()
}

fn rec_of(f: &Fx, op: i64) -> Value {
    serde_json::from_str(&f.ctx.db.get(op).unwrap().operator_record_json).unwrap()
}

fn binds(f: &Fx) -> usize {
    f.mock.bind_calls.lock().unwrap().len()
}

fn last_signed_record(f: &Fx) -> Value {
    let calls = f.mock.bind_calls.lock().unwrap();
    serde_json::from_str(&calls.last().unwrap().record_json).unwrap()
}

fn token_of(f: &Fx, op: i64) -> Option<String> {
    f.ctx
        .custody
        .get(&cloudflare_alias(op))
        .ok()
        .map(|b| String::from_utf8(b).unwrap())
}

fn with_token(f: &Fx) -> i64 {
    let op = provisioned(f);
    let c = set_token(
        &f.ctx,
        CdnTokenInput { operator_id: op, token: format!("  {CF_TOKEN}\n"), zone: String::new() },
        &mut noop(),
    )
    .unwrap();
    assert!(c.stored);
    f.helper.lock().unwrap().calls.clear();
    op
}

fn built(f: &Fx, op: i64) -> AddonRow {
    build(&f.ctx, CdnBuildInput { operator_id: op, zone: "example.com".into() }, &mut noop()).unwrap()
}

fn code_of(e: &WizardError) -> String {
    e.to_string().split(':').next().unwrap_or("").to_string()
}

#[test]
fn a_token_with_exactly_the_five_permissions_is_kept_trimmed() {
    let f = fx();
    let op = provisioned(&f);
    let mut steps = Vec::new();
    let c = set_token(
        &f.ctx,
        CdnTokenInput { operator_id: op, token: format!(" {CF_TOKEN} "), zone: String::new() },
        &mut |p| steps.push(format!("{}:{}", p.step, p.state)),
    )
    .unwrap();
    assert_eq!(c.verdict, "ok");
    assert_eq!(c.zones, vec!["example.com".to_string()]);
    assert!(c.stored);
    assert_eq!(token_of(&f, op).as_deref(), Some(CF_TOKEN));
    assert_eq!(steps, ["token:running", "token:ok"]);
    assert_eq!(verbs(&f), ["cdn-token-check"]);
}

#[test]
fn a_token_that_can_do_more_is_refused_and_not_stored() {
    let f = fx();
    let op = with_token(&f);
    let refusal = serde_json::json!({"verdict":"too_broad","zones":[{"name":"example.com"},{"name":"other.org"}],
        "extra":["Account — Workers Scripts — Edit"]});
    f.helper.lock().unwrap().token_check = Some(Err((4, format!("{}\n", serde_json::to_string_pretty(&refusal).unwrap()))));
    let c = set_token(
        &f.ctx,
        CdnTokenInput { operator_id: op, token: "cf-broad-token".into(), zone: String::new() },
        &mut noop(),
    )
    .unwrap();
    assert_eq!(c.verdict, "too_broad");
    assert!(!c.stored);
    assert_eq!(c.extra, vec!["Account — Workers Scripts — Edit".to_string()]);
    assert_eq!(c.zones.len(), 2);
    // The good one from before is untouched.
    assert_eq!(token_of(&f, op).as_deref(), Some(CF_TOKEN));
}

#[test]
fn a_refusal_without_an_answer_is_refused_and_a_missing_permission_is_named() {
    let f = fx();
    let op = provisioned(&f);
    f.helper.lock().unwrap().token_check = Some(Err((4, "cdn-token-check: refused\n".into())));
    let c = set_token(&f.ctx, CdnTokenInput { operator_id: op, token: "x".into(), zone: String::new() }, &mut noop()).unwrap();
    assert_eq!((c.verdict.as_str(), c.stored), ("refused", false));
    f.helper.lock().unwrap().token_check = Some(Ok(serde_json::json!({"verdict":"missing_permission",
        "zones":[{"name":"example.com"}],"missing":["Zone — Origin Rules — Edit"]})));
    let c = set_token(&f.ctx, CdnTokenInput { operator_id: op, token: "x".into(), zone: "example.com".into() }, &mut noop()).unwrap();
    assert_eq!(c.verdict, "missing_permission");
    assert_eq!(c.missing, vec!["Zone — Origin Rules — Edit".to_string()]);
    assert!(token_of(&f, op).is_none());
    assert!(args_of(&f, "cdn-token-check")[1].windows(2).any(|w| w[0] == "--zone" && w[1] == "example.com"));
    let e = set_token(&f.ctx, CdnTokenInput { operator_id: op, token: "  ".into(), zone: String::new() }, &mut noop()).unwrap_err();
    assert!(matches!(e, WizardError::EmptyToken));
}

#[test]
fn build_makes_tests_and_signs_the_way_in() {
    let f = fx();
    let op = with_token(&f);
    let before = binds(&f);
    let mut steps = Vec::new();
    let row = build(
        &f.ctx,
        CdnBuildInput { operator_id: op, zone: "Example.com.".into() },
        &mut |p| steps.push(format!("{}:{}", p.step, p.state)),
    )
    .unwrap();
    assert_eq!(row.kind, AddonKind::Cdn);
    assert_eq!(row.state, AddonState::Ready);
    assert!(!row.has_secret, "the token keeps its FRP-8 home");
    assert_eq!((row.monthly_cost_cents, row.cost_currency.as_str()), (0, ""));
    assert_eq!(row.provider_ids.get("zone_id").map(String::as_str), Some("zone-1"));
    assert_eq!(row.provider_ids.get("dns_record_ids").map(String::as_str), Some("dns-1"));
    assert_eq!(row.detail["hostname"], HOST);
    assert_eq!(row.detail["name_hidden"], true);
    assert_eq!(row.detail["plain_fallback"], false);
    assert_eq!(verbs(&f), ["cdn-provision", "cdn-door", "cdn-test"]);
    assert!(args_of(&f, "cdn-door")[0].windows(2).any(|w| w[0] == "--action" && w[1] == "enable"));
    assert!(!args_of(&f, "cdn-test")[0].iter().any(|a| a.starts_with("--require-ech")));
    // Signed once, with the route's record member.
    assert_eq!(binds(&f), before + 1);
    assert_eq!(last_signed_record(&f)[RECORD_MEMBER]["hostname"], HOST);
    assert_eq!(rec_of(&f, op)[RECORD_MEMBER]["plain_fallback"], false);
    assert_eq!(
        steps,
        [
            "cloudflare:running", "cloudflare:ok", "firewall:ok", "door:running", "door:ok",
            "testing:running", "testing:ok", "signing:running", "signing:ok"
        ]
    );
    // Again: nothing to do.
    let again = built(&f, op);
    assert_eq!(again.id, row.id);
    assert_eq!(verbs(&f).len(), 3);
    // The staged front records are gone.
    assert!(!f.ctx.staging_dir.join(format!("{op}.cdn.front.json")).exists());
}

#[test]
fn a_zone_without_ech_still_works_and_says_the_name_shows() {
    let f = fx();
    let op = with_token(&f);
    f.helper.lock().unwrap().tests = vec![
        serde_json::json!({"ok":false,"ech_offered":false,"detail":"no ECH config for this hostname"}),
        serde_json::json!({"ok":true,"ech_offered":false,"ech_accepted":false}),
    ];
    let row = built(&f, op);
    assert_eq!(row.detail["name_hidden"], false);
    let t = args_of(&f, "cdn-test");
    assert_eq!(t.len(), 2);
    assert!(t[1].iter().any(|a| a == "--require-ech=false"));
}

#[test]
fn a_failed_test_takes_everything_down_and_signs_nothing() {
    let f = fx();
    let op = with_token(&f);
    let rec_before = rec_of(&f, op);
    let before = binds(&f);
    f.helper.lock().unwrap().tests =
        vec![serde_json::json!({"ok":false,"ech_offered":true,"detail":"HTTP 502 from the edge"})];
    let e = build(&f.ctx, CdnBuildInput { operator_id: op, zone: "example.com".into() }, &mut noop()).unwrap_err();
    assert_eq!(code_of(&e), E_CDN_TEST_FAILED);
    assert!(e.to_string().contains("HTTP 502"));
    assert_eq!(verbs(&f), ["cdn-provision", "cdn-door", "cdn-test", "cdn-door", "cdn-remove"]);
    assert!(args_of(&f, "cdn-door")[1].windows(2).any(|w| w[0] == "--action" && w[1] == "disable"));
    assert!(list(&f.ctx, op).unwrap().is_empty(), "nothing is left, so no row");
    assert_eq!(rec_of(&f, op), rec_before);
    assert_eq!(binds(&f), before);
}

#[test]
fn a_relay_without_the_door_needs_a_rebuild() {
    let f = fx();
    let op = with_token(&f);
    f.helper.lock().unwrap().door_fail = Some((3, "relay management has no /cdn\n".into()));
    let e = build(&f.ctx, CdnBuildInput { operator_id: op, zone: "example.com".into() }, &mut noop()).unwrap_err();
    assert_eq!(code_of(&e), E_CDN_NEEDS_REBUILD);
    assert_eq!(verbs(&f), ["cdn-provision", "cdn-door", "cdn-remove"]);
    assert!(list(&f.ctx, op).unwrap().is_empty());
}

#[test]
fn a_helper_without_the_door_verb_is_too_old() {
    let f = fx();
    let op = with_token(&f);
    f.helper.lock().unwrap().door_fail = Some((2, "unknown subcommand \"cdn-door\"\n".into()));
    let e = build(&f.ctx, CdnBuildInput { operator_id: op, zone: "example.com".into() }, &mut noop()).unwrap_err();
    assert_eq!(code_of(&e), E_DEPLOY_TOO_OLD);
    assert!(list(&f.ctx, op).unwrap().is_empty());
}

#[test]
fn a_provision_failure_leaves_no_row() {
    let f = fx();
    let op = with_token(&f);
    f.helper.lock().unwrap().provision_fail =
        Some((1, "cdn-provision: cloudflare: hostname already has a proxied record pointing elsewhere\n".into()));
    let e = build(&f.ctx, CdnBuildInput { operator_id: op, zone: "example.com".into() }, &mut noop()).unwrap_err();
    assert_eq!(code_of(&e), E_CDN_PROVISION);
    assert_eq!(verbs(&f), ["cdn-provision"]);
    assert!(list(&f.ctx, op).unwrap().is_empty());
}

#[test]
fn a_rollback_that_cannot_finish_keeps_the_row_and_remove_is_the_retry() {
    let f = fx();
    let op = with_token(&f);
    {
        let mut h = f.helper.lock().unwrap();
        h.tests = vec![serde_json::json!({"ok":false,"ech_offered":true,"detail":"timeout"})];
        h.remove_incomplete = true;
    }
    let e = build(&f.ctx, CdnBuildInput { operator_id: op, zone: "example.com".into() }, &mut noop()).unwrap_err();
    assert_eq!(code_of(&e), E_CDN_LEFT_BEHIND);
    assert!(e.to_string().contains("origin_certificate"));
    let rows = list(&f.ctx, op).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].state, AddonState::Building);
    assert_eq!(rows[0].detail["front"]["hostname"], HOST);

    // Remove, still incomplete: the row stays, the key stays.
    let rep = crate::addons::remove(&f.ctx, rows[0].id, &mut noop()).unwrap();
    assert!(!rep.removed);
    assert!(rep.warnings.iter().any(|w| w.contains("origin_certificate")));
    assert_eq!(get(&f.ctx, rows[0].id).unwrap().state, AddonState::Removing);
    assert!(token_of(&f, op).is_some());

    // Then it works.
    f.helper.lock().unwrap().remove_incomplete = false;
    let rep = crate::addons::remove(&f.ctx, rows[0].id, &mut noop()).unwrap();
    assert!(rep.removed);
    assert!(list(&f.ctx, op).unwrap().is_empty());
}

#[test]
fn build_without_a_key_creates_nothing() {
    let f = fx();
    let op = provisioned(&f);
    let e = build(&f.ctx, CdnBuildInput { operator_id: op, zone: "example.com".into() }, &mut noop()).unwrap_err();
    assert_eq!(code_of(&e), E_CDN_NO_TOKEN);
    assert!(verbs(&f).is_empty());
    assert!(list(&f.ctx, op).unwrap().is_empty());
    let e = build(&f.ctx, CdnBuildInput { operator_id: op, zone: "nozone".into() }, &mut noop()).unwrap_err();
    assert!(matches!(e, WizardError::Validation(_)));
}

#[test]
fn posture_reads_the_zone_and_tests_through_the_front() {
    let f = fx();
    let op = with_token(&f);
    built(&f, op);
    f.helper.lock().unwrap().calls.clear();
    let p = posture(&f.ctx, CdnPostureInput { operator_id: op, test: true }, &mut noop()).unwrap();
    assert_eq!(p.name_hidden, Some(true));
    assert_eq!(p.door_closed_to_others, Some(true));
    assert_eq!(p.last_test_ok, Some(true));
    assert!(p.last_test_at_unix > 0);
    assert_eq!(p.hostname, HOST);
    assert_eq!(p.zone, "example.com");
    assert!(!p.plain_fallback);
    assert!(!p.needs_rebuild);
    assert_eq!(verbs(&f), ["cdn-posture", "cdn-test"]);

    // Without a test: one read only, and the last test is remembered.
    f.helper.lock().unwrap().calls.clear();
    let q = posture(&f.ctx, CdnPostureInput { operator_id: op, test: false }, &mut noop()).unwrap();
    assert_eq!(verbs(&f), ["cdn-posture"]);
    assert_eq!(q.last_test_at_unix, p.last_test_at_unix);

    // A test that fails says so, and the name is not called hidden.
    f.helper.lock().unwrap().tests = vec![serde_json::json!({"ok":false,"ech_offered":true,"detail":"reset"})];
    let r = posture(&f.ctx, CdnPostureInput { operator_id: op, test: true }, &mut noop()).unwrap();
    assert_eq!(r.last_test_ok, Some(false));
    assert_eq!(r.name_hidden, Some(false));
    assert!(r.notes.contains("reset"));
}

#[test]
fn the_plain_fallback_flag_is_signed() {
    let f = fx();
    let op = with_token(&f);
    built(&f, op);
    let before = binds(&f);
    let row = set_plain_fallback(&f.ctx, CdnPlainFallbackInput { operator_id: op, allow: true }, &mut noop()).unwrap();
    assert_eq!(row.detail["plain_fallback"], true);
    assert_eq!(binds(&f), before + 1);
    assert_eq!(last_signed_record(&f)[RECORD_MEMBER]["plain_fallback"], true);
    // The same value again signs nothing.
    set_plain_fallback(&f.ctx, CdnPlainFallbackInput { operator_id: op, allow: true }, &mut noop()).unwrap();
    assert_eq!(binds(&f), before + 1);
    let p = posture(&f.ctx, CdnPostureInput { operator_id: op, test: false }, &mut noop()).unwrap();
    assert!(p.plain_fallback);
}

#[test]
fn remove_signs_without_the_route_first_then_takes_it_down_and_forgets_the_key() {
    let f = fx();
    let op = with_token(&f);
    let row = built(&f, op);
    f.helper.lock().unwrap().calls.clear();
    let before = binds(&f);
    let rep = crate::addons::remove(&f.ctx, row.id, &mut noop()).unwrap();
    assert!(rep.removed);
    assert_eq!(rep.by_hand, ["delete_cloudflare_token", "cancel_domain"]);
    assert_eq!(binds(&f), before + 1);
    assert!(last_signed_record(&f).get(RECORD_MEMBER).is_none(), "signed without the route");
    assert!(rec_of(&f, op).get(RECORD_MEMBER).is_none());
    assert_eq!(verbs(&f), ["cdn-door", "cdn-remove"]);
    assert!(args_of(&f, "cdn-door")[0].windows(2).any(|w| w[0] == "--action" && w[1] == "disable"));
    assert!(token_of(&f, op).is_none(), "the token is forgotten");
    assert!(list(&f.ctx, op).unwrap().is_empty());
}

#[test]
fn relay_delete_takes_the_cloudflare_side_down_or_keeps_the_relay() {
    let f = fx();
    let op = with_token(&f);
    let row = built(&f, op);
    f.helper.lock().unwrap().remove_incomplete = true;
    let o = on_relay_delete(&f.ctx, &row);
    assert_eq!((o.removed, o.keeps_relay, o.code.as_str()), (false, true, "failed"));
    assert!(o.error.contains("origin_certificate"));
    f.helper.lock().unwrap().remove_incomplete = false;
    let o = on_relay_delete(&f.ctx, &row);
    assert_eq!((o.removed, o.keeps_relay, o.code.as_str()), (true, false, "removed"));
    // No key on this phone: nothing could take it down, so it is left.
    let _ = f.ctx.custody.forget(&cloudflare_alias(op));
    let o = on_relay_delete(&f.ctx, &row);
    assert_eq!((o.removed, o.keeps_relay, o.code.as_str()), (false, false, "left"));
    // A row that never got a front record is simply removed.
    let mut bare = row.clone();
    bare.detail = serde_json::json!({});
    assert!(on_relay_delete(&f.ctx, &bare).removed);
}

#[test]
fn the_json_of_a_refusal_is_found_inside_the_failure_text() {
    assert_eq!(json_in("x\n{\n \"a\": 1\n}\n").unwrap()["a"], 1);
    assert!(json_in("no json").is_none());
    assert!(json_in("} {").is_none());
}
