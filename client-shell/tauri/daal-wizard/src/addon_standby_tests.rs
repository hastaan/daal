//! The standby add-on driven through its command functions against
//! `MockRunner`. The helper's `standby` verbs are answered by a closure;
//! nothing reaches Hetzner or a relay.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use super::*;
use crate::addons::{get, list};
use crate::cli_bridge::{CliRunner, MockRunner, Pricing};
use crate::commands::{
    provision_run, publisher_keygen, relay_destroy, select_profile, set_helper_ip,
    store_cloud_token, WizardCtx,
};
use crate::device_custody::{DeviceCustody, FileCustody};
use crate::keystore::Keystore;
use crate::operator_db::OperatorDb;

const FP: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const TOKEN: &str = "hcloud-standby-test-token-0001";
const SALT: &str = "AAECAwQFBgcICQoL";
const SB_IP: &str = "203.0.113.20";
/// The vector publisher/deploy/relaypack pins (computed outside Go).
const KEY: &str = "000G40 R40M3 0E209 185WP 03H2G";

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

fn with_standby(mut rec: Value) -> Value {
    rec["standby"] =
        serde_json::json!({"floating_ip_id":"fip-sb","ip":SB_IP,"mode":"sealed","salt":SALT});
    rec
}

/// What the helper was asked, and how it answers.
#[derive(Default)]
struct Helper {
    calls: Vec<(String, Value, bool)>, // (verb, record sent, key on stdin)
    fail_add: Option<(i32, String)>,
    fail_remove: Option<(i32, String)>,
}

struct Fx {
    ctx: WizardCtx,
    mock: Arc<MockRunner>,
    helper: Arc<Mutex<Helper>>,
    _dir: tempfile::TempDir,
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
        assert_eq!(args[0], "standby");
        assert!(
            !args.iter().any(|a| a.contains(TOKEN)),
            "the token is never an argument"
        );
        let verb = args[1].clone();
        let at = args.iter().position(|a| a == "--record-file").unwrap();
        let rec: Value =
            serde_json::from_str(&std::fs::read_to_string(&args[at + 1]).unwrap()).unwrap();
        let mut h = h.lock().unwrap();
        h.calls.push((verb.clone(), rec.clone(), !stdin.is_empty()));
        let fail = match verb.as_str() {
            "add" => h.fail_add.clone(),
            "remove" => h.fail_remove.clone(),
            _ => None,
        };
        if let Some((rc, stderr)) = fail {
            return Err(BridgeError::SubprocessFailed { rc, stderr });
        }
        let out = match verb.as_str() {
            "price" => {
                serde_json::json!({"currency":"EUR","monthly_net":"3.0000000000","monthly_net_cents":300,"monthly_gross_cents":357})
            }
            "add" => {
                assert!(args.windows(2).any(|w| w[0] == "--priv-key" && w[1] == "-"));
                let mode = args[args.iter().position(|a| a == "--mode").unwrap() + 1].clone();
                let mut r = with_standby(rec);
                r["standby"]["mode"] = Value::String(mode.clone());
                serde_json::json!({"record": r, "floating_ip_id":"fip-sb","mode":mode,"created":true,"key":KEY,
                                   "released":[],"still_billing":[],"warnings":[]})
            }
            "promote" => {
                let mut r = rec.clone();
                r.as_object_mut().unwrap().remove("standby");
                r["public_ip"] = Value::String(SB_IP.into());
                r["floating_ip_id"] = Value::String("fip-sb".into());
                serde_json::json!({"record": r, "key": KEY, "floating_ip_id":"fip-sb",
                                   "prior_address":"203.0.113.7","released":[],"still_billing":[],"warnings":[]})
            }
            "remove" => {
                let mut r = rec.clone();
                if let Some(m) = r.as_object_mut() {
                    m.remove("standby");
                }
                serde_json::json!({"record": r, "released":["fip-sb"],"still_billing":[],"warnings":[]})
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
    Fx {
        ctx,
        mock,
        helper,
        _dir: dir,
    }
}

fn provisioned(f: &Fx) -> i64 {
    let id = store_cloud_token(&f.ctx, "hetzner", TOKEN, None).unwrap();
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

fn rec_of(f: &Fx, op: i64) -> Value {
    serde_json::from_str(&f.ctx.db.get(op).unwrap().operator_record_json).unwrap()
}

fn verbs(f: &Fx) -> Vec<String> {
    f.helper
        .lock()
        .unwrap()
        .calls
        .iter()
        .map(|c| c.0.clone())
        .collect()
}

fn last_signed_record(f: &Fx) -> Value {
    let calls = f.mock.bind_calls.lock().unwrap();
    serde_json::from_str(&calls.last().unwrap().record_json).unwrap()
}

fn added(f: &Fx, op: i64) -> AddonRow {
    add(
        &f.ctx,
        StandbyAddInput {
            operator_id: op,
            mode: String::new(),
        },
        &mut noop(),
    )
    .unwrap()
}

#[test]
fn the_key_text_matches_the_shared_vector() {
    assert_eq!(key_text(SALT, SB_IP).as_deref(), Some(KEY));
    assert_eq!(key_text("AAEC", SB_IP), None, "short salt");
    assert_eq!(key_text(SALT, "2001:db8::1"), None, "not IPv4");
}

#[test]
fn price_reads_the_live_monthly_price_before_tax() {
    let f = fx();
    let op = provisioned(&f);
    let p = price(&f.ctx, StandbyPriceInput { operator_id: op }, &mut noop()).unwrap();
    assert_eq!(
        p,
        StandbyPrice {
            monthly_cents: 300,
            currency: "EUR".into(),
            vat_included: false
        }
    );
}

#[test]
fn add_rents_signs_with_the_standby_and_records_the_bill() {
    let f = fx();
    let op = provisioned(&f);
    let mut steps = Vec::new();
    let row = add(
        &f.ctx,
        StandbyAddInput {
            operator_id: op,
            mode: String::new(),
        },
        &mut |p| steps.push(format!("{}:{}", p.step, p.state)),
    )
    .unwrap();
    assert_eq!(row.state, AddonState::Ready);
    assert_eq!(
        row.provider_ids.get("floating_ip_id").map(String::as_str),
        Some("fip-sb")
    );
    assert_eq!(
        (row.monthly_cost_cents, row.cost_currency.as_str()),
        (300, "EUR")
    );
    assert!(!row.has_secret);
    assert_eq!(row.detail["mode"], "sealed");
    assert_eq!(verbs(&f), ["price", "add"]);
    let (_, sent, key_on_stdin) = f.helper.lock().unwrap().calls[1].clone();
    assert!(key_on_stdin, "the signing key travels on stdin");
    assert!(sent.get("standby").is_none());
    // The record now names the standby, and the pack was signed from it.
    assert_eq!(rec_of(&f, op)["standby"]["floating_ip_id"], "fip-sb");
    assert_eq!(last_signed_record(&f)["standby"]["ip"], SB_IP);
    assert_eq!(rec_of(&f, op)["public_ip"], "203.0.113.7", "not adopted");
    assert!(steps.contains(&"signing:ok".to_string()));
    // Again: nothing to do.
    let again = added(&f, op);
    assert_eq!(again.id, row.id);
    assert_eq!(verbs(&f).len(), 2);
}

#[test]
fn open_is_refused_while_an_everyone_file_exists() {
    let f = fx();
    let op = provisioned(&f);
    std::fs::write(f.ctx.staging_dir.join(format!("{op}.shared.sbp")), b"x").unwrap();
    let e = add(
        &f.ctx,
        StandbyAddInput {
            operator_id: op,
            mode: "open".into(),
        },
        &mut noop(),
    )
    .unwrap_err();
    assert!(e.to_string().starts_with(E_STANDBY_OPEN_REFUSED), "{e}");
    assert!(verbs(&f).is_empty() && list(&f.ctx, op).unwrap().is_empty());
    // Sealed is fine.
    added(&f, op);
}

#[test]
fn a_failed_add_that_gave_the_address_back_leaves_nothing() {
    let f = fx();
    let op = provisioned(&f);
    f.helper.lock().unwrap().fail_add = Some((
        1,
        "standby add: bind: permission denied — the standby address was given back; nothing is billing\n".into(),
    ));
    let before = rec_of(&f, op);
    assert!(add(
        &f.ctx,
        StandbyAddInput {
            operator_id: op,
            mode: String::new()
        },
        &mut noop()
    )
    .is_err());
    assert!(
        list(&f.ctx, op).unwrap().is_empty(),
        "no row: nothing bills"
    );
    assert_eq!(rec_of(&f, op), before);
}

#[test]
fn a_failed_add_that_could_not_give_it_back_keeps_the_row_for_the_retry() {
    let f = fx();
    let op = provisioned(&f);
    f.helper.lock().unwrap().fail_add = Some((
        1,
        "standby add: bind: timeout — and floating IP fip-sb could NOT be given back: it is still reserved and billing\n".into(),
    ));
    assert!(add(
        &f.ctx,
        StandbyAddInput {
            operator_id: op,
            mode: String::new()
        },
        &mut noop()
    )
    .is_err());
    let rows = list(&f.ctx, op).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].state, AddonState::Building);
    // The retry resumes the same row (the helper adopts what is there).
    f.helper.lock().unwrap().fail_add = None;
    let row = added(&f, op);
    assert_eq!((row.id, row.state), (rows[0].id, AddonState::Ready));
}

#[test]
fn the_limit_is_its_own_code() {
    let f = fx();
    let op = provisioned(&f);
    f.helper.lock().unwrap().fail_add = Some((
        9,
        "E_STANDBY_LIMIT: Hetzner has not allowed this account a second address yet\n".into(),
    ));
    let e = add(
        &f.ctx,
        StandbyAddInput {
            operator_id: op,
            mode: String::new(),
        },
        &mut noop(),
    )
    .unwrap_err();
    assert!(e.to_string().starts_with(E_STANDBY_LIMIT), "{e}");
    assert!(list(&f.ctx, op).unwrap().is_empty());
}

#[test]
fn a_relay_that_binds_the_standby_unsafely_is_its_own_code() {
    // relay-v1.5.1 binds a second address as a global one: the helper
    // refuses before renting (exit 10), and the wizard says so in its own
    // words — not "too old for this" in general, not a retry.
    let f = fx();
    let op = provisioned(&f);
    let before = rec_of(&f, op);
    f.helper.lock().unwrap().fail_add = Some((
        10,
        "E_STANDBY_NEEDS_REBUILD: this relay's software binds a second address where the relay's own traffic could leave from it, which would reveal a standby address; a relay set up with a newer Daal binds it safely. Nothing was rented (the relay advertises: bind-address,rotate-credentials-scoped)\n".into(),
    ));
    let e = add(
        &f.ctx,
        StandbyAddInput {
            operator_id: op,
            mode: String::new(),
        },
        &mut noop(),
    )
    .unwrap_err();
    assert!(
        e.to_string()
            .starts_with(&format!("{E_STANDBY_NEEDS_REBUILD}:")),
        "{e}"
    );
    // Nothing rented, so nothing to give back and no row that bills.
    assert!(list(&f.ctx, op).unwrap().is_empty());
    assert_eq!(verbs(&f), ["price", "add"]);
    assert_eq!(rec_of(&f, op), before);
}

#[test]
fn a_signature_that_fails_gives_the_address_back() {
    let f = fx();
    let op = provisioned(&f);
    let before = rec_of(&f, op);
    *f.mock.bind_error.lock().unwrap() = Some("relay unreachable".into());
    let e = add(
        &f.ctx,
        StandbyAddInput {
            operator_id: op,
            mode: String::new(),
        },
        &mut noop(),
    )
    .unwrap_err();
    assert!(e.to_string().contains("nothing is billing"), "{e}");
    assert_eq!(verbs(&f), ["price", "add", "remove"]);
    // The release was asked for with the standby the helper made.
    assert_eq!(
        f.helper.lock().unwrap().calls[2].1["standby"]["floating_ip_id"],
        "fip-sb"
    );
    assert_eq!(rec_of(&f, op), before);
    assert!(list(&f.ctx, op).unwrap().is_empty());
}

#[test]
fn key_and_promote() {
    let f = fx();
    let op = provisioned(&f);
    added(&f, op);
    assert_eq!(
        key(&f.ctx, StandbyKeyInput { operator_id: op }, &mut noop())
            .unwrap()
            .key,
        KEY
    );

    let res = promote(&f.ctx, StandbyPromoteInput { operator_id: op }, &mut noop()).unwrap();
    assert_eq!(res.key, KEY);
    assert_eq!(res.addon.state, AddonState::Promoted);
    assert_eq!(res.addon.detail["key"], KEY);
    let rec = rec_of(&f, op);
    assert_eq!(rec["public_ip"], SB_IP);
    assert!(rec.get("standby").is_none());
    assert_eq!(last_signed_record(&f)["public_ip"], SB_IP);
    // The key is still there to send after the sheet is closed.
    assert_eq!(
        key(&f.ctx, StandbyKeyInput { operator_id: op }, &mut noop())
            .unwrap()
            .key,
        KEY
    );
    // A promoted standby is the relay's address: not removable, and a
    // new standby may be rented beside it.
    assert!(addons::remove(&f.ctx, res.addon.id, &mut noop()).is_err());
    let fresh = added(&f, op);
    assert_ne!(fresh.id, res.addon.id);
}

#[test]
fn a_failed_promote_signature_puts_the_record_back() {
    let f = fx();
    let op = provisioned(&f);
    let row = added(&f, op);
    let before = rec_of(&f, op);
    *f.mock.bind_error.lock().unwrap() = Some("relay unreachable".into());
    assert!(promote(&f.ctx, StandbyPromoteInput { operator_id: op }, &mut noop()).is_err());
    assert_eq!(rec_of(&f, op), before);
    assert_eq!(get(&f.ctx, row.id).unwrap().state, AddonState::Ready);
}

#[test]
fn remove_signs_without_it_first_then_releases_then_forgets() {
    let f = fx();
    let op = provisioned(&f);
    let row = added(&f, op);
    let signs_before = f.mock.bind_calls.lock().unwrap().len();
    let rep = addons::remove(&f.ctx, row.id, &mut noop()).unwrap();
    assert!(rep.removed && rep.still_billing.is_empty());
    assert_eq!(f.mock.bind_calls.lock().unwrap().len(), signs_before + 1);
    assert!(
        last_signed_record(&f).get("standby").is_none(),
        "signed without it"
    );
    assert_eq!(verbs(&f).last().unwrap(), "remove");
    assert!(
        f.helper.lock().unwrap().calls.last().unwrap().2,
        "the relay is told to drop it"
    );
    assert!(rec_of(&f, op).get("standby").is_none());
    assert!(list(&f.ctx, op).unwrap().is_empty());
}

#[test]
fn remove_that_cannot_release_keeps_the_row_and_says_what_bills() {
    let f = fx();
    let op = provisioned(&f);
    let row = added(&f, op);
    f.helper.lock().unwrap().fail_remove =
        Some((6, "standby remove: at least one standby address could not be given back and is still billing\n".into()));
    let rep = addons::remove(&f.ctx, row.id, &mut noop()).unwrap();
    assert!(!rep.removed);
    assert_eq!(rep.still_billing, vec!["fip-sb".to_string()]);
    assert_eq!(get(&f.ctx, row.id).unwrap().state, AddonState::Removing);
    // The retry skips the signature (already done) and releases.
    f.helper.lock().unwrap().fail_remove = None;
    let signs = f.mock.bind_calls.lock().unwrap().len();
    let rep = addons::remove(&f.ctx, row.id, &mut noop()).unwrap();
    assert!(rep.removed);
    assert_eq!(f.mock.bind_calls.lock().unwrap().len(), signs);
}

#[test]
fn a_killed_add_is_removable_from_its_row() {
    let f = fx();
    let op = provisioned(&f);
    // What a run killed after the row was written leaves.
    let id = addons::insert(
        &f.ctx,
        &NewAddon {
            operator_id: op,
            kind: Some(AddonKind::Standby),
            ..Default::default()
        },
    )
    .unwrap();
    let rep = addons::remove(&f.ctx, id, &mut noop()).unwrap();
    assert!(rep.removed);
    assert_eq!(
        verbs(&f),
        ["remove"],
        "the helper sweeps what the killed run rented"
    );
}

#[test]
fn relay_delete_releases_it_with_the_relays_addresses() {
    let f = fx();
    let op = provisioned(&f);
    let row = added(&f, op);
    let rep = relay_destroy(&f.ctx, op, true).unwrap();
    assert!(rep.server_deleted && rep.local_removed && !rep.retry_needed);
    assert_eq!(rep.addons.len(), 1);
    let o = &rep.addons[0];
    assert_eq!(
        (o.addon_id, o.removed, o.keeps_relay, o.code.as_str()),
        (row.id, false, false, "with_relay")
    );
    // Decommission was asked to release the relay's addresses: that is
    // what gives the standby back.
    assert!(f.ctx.db.get(op).is_err());
    assert!(
        addons::get(&f.ctx, row.id).is_err(),
        "the row went with the relay"
    );
}

#[test]
fn the_account_check_lists_the_standby_as_a_billed_addon() {
    use crate::setup_recovery::{mark_addon_items, AccountItem};
    let f = fx();
    let op = provisioned(&f);
    added(&f, op);
    let item = |id: &str, name: &str, kind: &str| AccountItem {
        kind: kind.into(),
        id: id.into(),
        name: name.into(),
        verdict: "in-use".into(),
        finding: "yours_in_use".into(),
        belongs_to_relay_id: Some(op),
        ..Default::default()
    };
    let mut items = vec![
        item(
            "fip-sb",
            "daal-fsn1-0011223344556677-standby-ab12cd34",
            "floating-ip",
        ),
        item(
            "fip-l3",
            "daal-fsn1-0011223344556677-fip-0000",
            "floating-ip",
        ),
        item("123", "daal-fsn1-0011223344556677", "server"),
    ];
    mark_addon_items(&f.ctx, &mut items);
    assert_eq!(
        (
            items[0].addon.as_str(),
            items[0].billing,
            items[0].monthly_cost_cents
        ),
        ("standby", true, 300)
    );
    assert_eq!(items[0].cost_currency, "EUR");
    assert!(items[1].addon.is_empty() && items[2].addon.is_empty());
    assert!(!items[0].can_delete, "display only");
}

// ---------------------------------------------------------------------
// The wrapped code (specs/update-ladder-v2.md §3)
// ---------------------------------------------------------------------

/// The vectors bundle/go/bundle/standby_wrap_test.go pins (computed in
/// Python, outside Go and Rust).
#[test]
fn the_wrapped_code_matches_the_shared_vector() {
    let root: Vec<u8> = (0u8..32).collect();
    let pack = "rp-0123456789abcdef0123456789abcdef";
    let u = derive_update_secret(&root, pack, "people");
    assert_eq!(
        hex::encode(&u[..]),
        "92b41abddf99cd530b5f2603f924f47059d1614d763b9aa012b71e39870ca072"
    );
    assert_eq!(
        hex::encode(&derive_update_secret(&root, pack, "everyone")[..]),
        "0021e1088f401278348c56d9c449d97557de9106dd9ad0d2b0986655abdf34e2"
    );
    assert_eq!(
        hex::encode(&derive_update_secret(&root, pack, &people_audience(2))[..]),
        "042011ad414559d3ba0b4d4c60725a0d261de2161222d8f800f64529f0ab9659"
    );
    let k = bytes_of_text(KEY).unwrap();
    assert_eq!(text_of(&k), KEY);
    assert_eq!(text_of(&wrap_key(&k, &u)), "DW08XN Z6SE1 KJD95 57SAY MT9M8");
    // Typed the way people type.
    assert_eq!(bytes_of_text("000g40-r40m3-0e2o9 185wp 03h2g"), Some(k));
    assert_eq!(bytes_of_text("000G40"), None);
    assert_eq!(
        bytes_of_text("ZZZZZZ ZZZZZ ZZZZZ ZZZZZ ZZZZZ"),
        None,
        "trailing bits"
    );
}

fn person(f: &Fx, op: i64, n: u8) -> String {
    let fp = format!("{:064x}", n);
    f.ctx
        .db
        .insert_recipient(crate::operator_db::NewRecipientRow {
            operator_id: op,
            name: format!("r{n}"),
            display_name: format!("Person {n}"),
            address_str: String::new(),
            pubkey_x25519_hex: fp.clone(),
            fingerprint_hex: fp.clone(),
            vless_uuid: String::new(),
            reality_short_id: String::new(),
            hy2_password: String::new(),
            naive_password: String::new(),
            ws_path: String::new(),
            provisioned_at_unix: 1_800_000_000 + n as i64,
        })
        .unwrap();
    fp
}

fn code(f: &Fx, op: i64) -> StandbyKey {
    key(&f.ctx, StandbyKeyInput { operator_id: op }, &mut noop()).unwrap()
}

fn wrapped_under(f: &Fx, op: i64, audience: &str) -> String {
    let root = f.ctx.custody.get(UPDATE_ROOT_ALIAS).unwrap();
    let pack = f.ctx.db.get(op).unwrap().signed_sbp_relay_pack_id.unwrap();
    let u = derive_update_secret(&root, &pack, audience);
    text_of(&wrap_key(&bytes_of_text(KEY).unwrap(), &u))
}

#[test]
fn the_code_is_wrapped_only_when_every_person_holds_the_secret() {
    let f = fx();
    let op = provisioned(&f);
    f.ctx
        .db
        .record_signed_sbp(op, "00", "rp-wrap-test", 1)
        .unwrap();
    added(&f, op);
    let a = person(&f, op, 1);
    let b = person(&f, op, 2);

    // Nobody's file carries a secret yet: the plain key, as before.
    assert_eq!(
        code(&f, op),
        StandbyKey {
            key: KEY.into(),
            form: KEY_FORM_PLAIN.into(),
            plain_key: None,
        }
    );
    assert!(
        !crate::commands::custody_has(&f.ctx, UPDATE_ROOT_ALIAS),
        "asking for the code makes no root"
    );

    let sa = people_secret_for_file(&f.ctx, op, &a).unwrap().unwrap();
    assert_eq!(sa.audience, "people");
    assert_eq!(code(&f, op).form, KEY_FORM_PLAIN, "a's file is not made yet");
    record_holder(&f.ctx, op, &a, sa.gen).unwrap();
    assert_eq!(
        code(&f, op).form,
        KEY_FORM_PLAIN,
        "b's file has no secret yet"
    );
    let sb = people_secret_for_file(&f.ctx, op, &b).unwrap().unwrap();
    assert_eq!(*sa.secret_b64, *sb.secret_b64, "one secret for the family");
    record_holder(&f.ctx, op, &b, sb.gen).unwrap();
    let c = code(&f, op);
    assert_eq!(c.form, KEY_FORM_WRAPPED);
    assert_eq!(c.plain_key.as_deref(), Some(KEY), "a wrapped code always carries the plain one");
    assert_eq!(c.key, wrapped_under(&f, op, "people"));
    assert_ne!(c.key, KEY);

    // The Everyone file's secret is another one, and an Everyone file
    // means the plain form.
    let e = everyone_secret_for_file(&f.ctx, op).unwrap().unwrap();
    assert_eq!(e.audience, "everyone");
    assert_ne!(*e.secret_b64, *sa.secret_b64);
    std::fs::write(f.ctx.staging_dir.join(format!("{op}.shared.sbp")), b"x").unwrap();
    assert_eq!(code(&f, op).form, KEY_FORM_PLAIN);
    std::fs::remove_file(f.ctx.staging_dir.join(format!("{op}.shared.sbp"))).unwrap();
    assert_eq!(code(&f, op).form, KEY_FORM_WRAPPED);

    // Removing b: b could unwrap every later code, so the relay moves to
    // a new generation and the code is plain until a has a new file.
    let b_row = f
        .ctx
        .db
        .list_recipients(op)
        .unwrap()
        .into_iter()
        .find(|r| r.fingerprint_hex == b)
        .unwrap();
    f.ctx
        .db
        .mark_recipient_revoked(b_row.id, 1_800_000_100)
        .unwrap();
    assert_eq!(code(&f, op).form, KEY_FORM_PLAIN);
    let sa2 = people_secret_for_file(&f.ctx, op, &a).unwrap().unwrap();
    assert_eq!(sa2.audience, "people/2");
    assert_ne!(*sa2.secret_b64, *sa.secret_b64);
    record_holder(&f.ctx, op, &a, sa2.gen).unwrap();
    let c = code(&f, op);
    assert_eq!(c.form, KEY_FORM_WRAPPED);
    assert_eq!(c.key, wrapped_under(&f, op, "people/2"));
    assert_ne!(
        c.key,
        wrapped_under(&f, op, "people"),
        "b's secret opens nothing new"
    );

    // A switch shows the code to send; the row keeps the plain key.
    let res = promote(&f.ctx, StandbyPromoteInput { operator_id: op }, &mut noop()).unwrap();
    assert_eq!(res.key_form, KEY_FORM_WRAPPED);
    assert_eq!(res.plain_key.as_deref(), Some(KEY));
    assert_eq!(res.key, wrapped_under(&f, op, "people/2"));
    assert_eq!(res.addon.detail["key"], KEY);
    assert_eq!(code(&f, op).key, res.key);
}

/// A file the helper did not confirm (a failed pack, or a helper too old
/// to read `update_secret`) records no holder, so the code stays plain.
#[test]
fn a_file_without_a_confirmed_secret_records_no_holder() {
    let f = fx();
    let op = provisioned(&f);
    f.ctx
        .db
        .record_signed_sbp(op, "00", "rp-wrap-test", 1)
        .unwrap();
    added(&f, op);
    let a = person(&f, op, 1);
    for _ in 0..3 {
        assert!(people_secret_for_file(&f.ctx, op, &a).unwrap().is_some());
    }
    let c = code(&f, op);
    assert_eq!(c.form, KEY_FORM_PLAIN);
    assert_eq!(c.key, KEY);
    assert_eq!(c.plain_key, None);
}

/// A damaged relay state is an error, not a fresh generation 1: the
/// code goes plain and no file is given a generation-1 secret.
#[test]
fn a_damaged_update_state_means_the_plain_code_and_no_secret() {
    let f = fx();
    let op = provisioned(&f);
    f.ctx
        .db
        .record_signed_sbp(op, "00", "rp-wrap-test", 1)
        .unwrap();
    added(&f, op);
    let a = person(&f, op, 1);
    let s = people_secret_for_file(&f.ctx, op, &a).unwrap().unwrap();
    record_holder(&f.ctx, op, &a, s.gen).unwrap();
    assert_eq!(code(&f, op).form, KEY_FORM_WRAPPED);
    crate::commands::custody_put(&f.ctx, &format!("update_people_{op}"), b"{not json").unwrap();
    let c = code(&f, op);
    assert_eq!((c.form.as_str(), c.key.as_str()), (KEY_FORM_PLAIN, KEY));
    assert!(people_secret_for_file(&f.ctx, op, &a).is_err());
    assert!(everyone_secret_for_file(&f.ctx, op).is_err());
}

/// The database's stamp of an Everyone file counts even when the staged
/// copy is gone (a restore or a cleanup).
#[test]
fn an_everyone_file_stamped_in_the_database_keeps_the_code_plain() {
    let f = fx();
    let op = provisioned(&f);
    f.ctx
        .db
        .record_signed_sbp(op, "00", "rp-wrap-test", 1)
        .unwrap();
    added(&f, op);
    let a = person(&f, op, 1);
    let s = people_secret_for_file(&f.ctx, op, &a).unwrap().unwrap();
    record_holder(&f.ctx, op, &a, s.gen).unwrap();
    assert_eq!(code(&f, op).form, KEY_FORM_WRAPPED);
    f.ctx.db.stamp_shared_box_fp(op).unwrap();
    if !f.ctx.db.shared_box_fp(op).unwrap().is_empty() {
        assert_eq!(code(&f, op).form, KEY_FORM_PLAIN);
    }
}
