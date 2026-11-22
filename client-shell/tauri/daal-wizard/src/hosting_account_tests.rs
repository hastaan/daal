//! The hosting account driven through its command functions against
//! `MockRunner`. Nothing reaches a hosting company.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use super::*;
use crate::cli_bridge::{CliRunner, MockRunner, Pricing};
use crate::commands::{
    cloud_alias, custody_get_string, reuse_cloud_token, saved_cloud_token, store_cloud_token,
};
use crate::device_custody::{DeviceCustody, FileCustody};
use crate::keystore::Keystore;
use crate::operator_db::OperatorDb;

const ACCOUNT_TOKEN: &str = "hcloud_ACCOUNT_do_not_leak_0001";
const RELAY_TOKEN: &str = "hcloud_RELAY_do_not_leak_0002";

struct Fx {
    ctx: WizardCtx,
    mock: Arc<MockRunner>,
    _dir: tempfile::TempDir,
}

fn fx_with(mock: MockRunner) -> Fx {
    let dir = tempfile::tempdir().unwrap();
    let staging_dir = dir.path().join("staging");
    std::fs::create_dir_all(&staging_dir).unwrap();
    let mock = Arc::new(mock);
    let cli: Arc<dyn CliRunner> = mock.clone();
    let clock = Arc::new(AtomicI64::new(1_800_000_000));
    let custody: Arc<dyn DeviceCustody> = Arc::new(FileCustody::static_test(dir.path()).unwrap());
    let ctx = WizardCtx {
        db: Arc::new(OperatorDb::open_in_memory().unwrap()),
        keystore: Arc::new(Keystore::new_in_memory(dir.path())),
        journal_dir: dir.path().join("journal"),
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

fn pricing() -> Pricing {
    Pricing {
        provider: "hetzner".into(),
        region: "fsn1".into(),
        server_type: "cx22".into(),
        hourly_eur: 0.005,
        monthly_eur: 3.85,
        included_traffic_tb_per_month: None,
        overage_eur_per_gb: None,
    }
}

fn fx() -> Fx {
    fx_with(MockRunner::new(pricing()))
}

fn hetzner(ctx: &WizardCtx) -> HostingAccountState {
    status(ctx).unwrap().get("hetzner").cloned().unwrap()
}

#[test]
fn connect_checks_the_key_with_the_hosting_company_then_keeps_it() {
    let f = fx();
    assert_eq!(hetzner(&f.ctx), HostingAccountState::default());

    let st = connect(&f.ctx, "hetzner", &format!("  {ACCOUNT_TOKEN}\n")).unwrap();
    assert_eq!(st, HostingAccountState { connected: true, account: true });

    // One read-only lookup, in the wizard's region, with the trimmed key.
    let calls = f.mock.list_server_type_calls.lock().unwrap().clone();
    assert_eq!(
        calls,
        vec![("hetzner".to_string(), "fsn1".to_string(), ACCOUNT_TOKEN.to_string())]
    );
    let kept = custody_get_string(&f.ctx, &account_alias("hetzner")).unwrap();
    assert_eq!(kept.as_str(), ACCOUNT_TOKEN);
    assert_eq!(account_alias("hetzner"), "daal.hosting.hetzner.account.token");

    // Connected, with no relay at all.
    assert!(f.ctx.db.list().unwrap().is_empty());
    assert_eq!(hetzner(&f.ctx), HostingAccountState { connected: true, account: true });
    // Another company is not connected by it.
    assert!(!status(&f.ctx).unwrap()["vultr"].connected);
}

#[test]
fn an_empty_key_is_refused_without_asking_anyone() {
    let f = fx();
    for t in ["", "   ", "\n"] {
        assert!(matches!(connect(&f.ctx, "hetzner", t), Err(WizardError::EmptyToken)));
    }
    assert!(f.mock.list_server_type_calls.lock().unwrap().is_empty());
    assert!(!hetzner(&f.ctx).connected);
}

#[test]
fn a_key_the_hosting_company_refuses_is_not_kept_and_not_echoed() {
    let f = fx_with(
        MockRunner::new(pricing())
            .with_list_server_types_error(format!("401 unauthorized: token {ACCOUNT_TOKEN} is invalid")),
    );
    let e = connect(&f.ctx, "hetzner", ACCOUNT_TOKEN).unwrap_err();
    let text = e.to_string();
    assert!(matches!(e, WizardError::Pricing(_)), "{text}");
    assert!(text.contains("401"), "the company's words stay: {text}");
    assert!(!text.contains(ACCOUNT_TOKEN), "the key leaked into the error: {text}");
    assert!(f.ctx.custody.get(&account_alias("hetzner")).is_err());
    assert!(!hetzner(&f.ctx).connected);
}

#[test]
fn an_unknown_hosting_company_is_refused() {
    let f = fx();
    assert!(matches!(
        connect(&f.ctx, "../../etc", ACCOUNT_TOKEN),
        Err(WizardError::Validation(_))
    ));
    assert!(matches!(disconnect(&f.ctx, "nope"), Err(WizardError::Validation(_))));
    assert!(f.mock.list_server_type_calls.lock().unwrap().is_empty());
}

#[test]
fn a_relay_that_holds_a_key_counts_as_connected_for_older_phones() {
    let f = fx();
    let id = store_cloud_token(&f.ctx, "hetzner", RELAY_TOKEN, None).unwrap();
    assert_eq!(hetzner(&f.ctx), HostingAccountState { connected: true, account: false });
    // A key custody cannot read does not count.
    f.ctx.custody.forget(&cloud_alias(id)).unwrap();
    assert!(!hetzner(&f.ctx).connected);
}

#[test]
fn a_new_relay_takes_a_copy_of_the_account_key_before_another_relays() {
    let f = fx();
    let old = store_cloud_token(&f.ctx, "hetzner", RELAY_TOKEN, None).unwrap();
    assert_eq!(
        saved_cloud_token(&f.ctx, "hetzner").unwrap().map(|s| (s.operator_id, s.account)),
        Some((old, false))
    );

    connect(&f.ctx, "hetzner", ACCOUNT_TOKEN).unwrap();
    let saved = saved_cloud_token(&f.ctx, "hetzner").unwrap().unwrap();
    assert!(saved.account);
    assert_eq!(saved.operator_id, 0);

    let new = reuse_cloud_token(&f.ctx, "hetzner").unwrap();
    assert_ne!(new, old);
    let row = f.ctx.db.get(new).unwrap();
    assert_eq!(row.cloud_token_keystore_alias, cloud_alias(new), "its own alias");
    assert_eq!(
        custody_get_string(&f.ctx, &cloud_alias(new)).unwrap().as_str(),
        ACCOUNT_TOKEN
    );
    // The older relay's key is untouched.
    assert_eq!(
        custody_get_string(&f.ctx, &cloud_alias(old)).unwrap().as_str(),
        RELAY_TOKEN
    );
}

#[test]
fn a_relay_can_be_started_from_the_account_with_no_relay_before_it() {
    let f = fx();
    connect(&f.ctx, "hetzner", ACCOUNT_TOKEN).unwrap();
    let id = reuse_cloud_token(&f.ctx, "hetzner").unwrap();
    assert_eq!(
        custody_get_string(&f.ctx, &cloud_alias(id)).unwrap().as_str(),
        ACCOUNT_TOKEN
    );
    // Only for that company.
    assert!(matches!(reuse_cloud_token(&f.ctx, "vultr"), Err(WizardError::EmptyToken)));
}

#[test]
fn disconnect_forgets_the_account_key_and_leaves_every_relays_copy() {
    let f = fx();
    connect(&f.ctx, "hetzner", ACCOUNT_TOKEN).unwrap();
    let a = reuse_cloud_token(&f.ctx, "hetzner").unwrap();
    let b = store_cloud_token(&f.ctx, "hetzner", RELAY_TOKEN, None).unwrap();

    disconnect(&f.ctx, "hetzner").unwrap();
    assert!(f.ctx.custody.get(&account_alias("hetzner")).is_err());
    assert_eq!(
        custody_get_string(&f.ctx, &cloud_alias(a)).unwrap().as_str(),
        ACCOUNT_TOKEN
    );
    assert_eq!(
        custody_get_string(&f.ctx, &cloud_alias(b)).unwrap().as_str(),
        RELAY_TOKEN
    );
    // Still connected through the relays, but no account key to forget.
    assert_eq!(hetzner(&f.ctx), HostingAccountState { connected: true, account: false });
    // A new relay now reuses the newest relay's key, as before.
    assert_eq!(
        saved_cloud_token(&f.ctx, "hetzner").unwrap().map(|s| (s.operator_id, s.account)),
        Some((b, false))
    );
    // Twice is fine.
    disconnect(&f.ctx, "hetzner").unwrap();
}
