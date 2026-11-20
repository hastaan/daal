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
