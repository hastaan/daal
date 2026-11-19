//! D1: a setup that stopped half way, and "is anything of Daal's still
//! running in my hosting account?".
//!
//! The person has only a phone. A setup killed after the server was
//! rented used to leave a billing server the app had no record of, and
//! the only way out was the provider's own dashboard. This module turns
//! what the setup journalled (`provision_journal`) and what the hosting
//! account says (`account-audit`, which recognises only things carrying
//! Daal's own labels and derived names) into one truthful card per
//! relay: finish on the server that exists, or delete it and everything
//! made with it — and whether anything is still costing money.
//!
//! THE RULE FOR "DAAL MADE THIS" lives in `daal-deploy` (provider
//! labels `managed-by=daal-deploy` + `daal-relay=<derived name>`, the
//! derived names themselves, Vultr's tags). This side never widens it:
//! an item is offered for deletion only when the audit classified it as
//! Daal's and no record on this phone claims it, and the delete itself
//! is done by `account-reclaim`, which re-checks every guard.
//!
//! Secrets: tokens are read from custody here, grouped by a hash that
//! never leaves this process, and handed to the child only through the
//! bridge's 0600 tempfile. Nothing returned by this module contains one.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::cli_bridge::{
    verb_unknown, AccountAuditReport, AccountReclaimArgs, AuditedResourceRow, BridgeError,
    ResourceRef,
};
use crate::commands::{
    coded, custody_get_string, destroy_cloud_resources, failed_addresses, looks_like_stale_allowlist,
    parse_rfc3339_unix, DestroyReport, Result, WizardCtx, WizardError, E_CUSTODY_LOCKED,
    E_DEPLOY_TOO_OLD, E_SETUP_RUNNING,
};
use crate::operator_db::OperatorRow;
use crate::provision_journal::{self, JournalSummary};
use crate::staging::PreProvisionRecord;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Leftover {
    pub kind: String,
    pub id: String,
    pub name: String,
    pub billing: bool,
}

/// What the setup-recovery card shows. Mirrors `SetupRecovery` in
/// wizardCommands.ts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SetupRecovery {
    /// `none` | `running` | `finished_unsaved` | `server_running` |
    /// `nothing_billing` | `unknown`.
    pub state: String,
    pub provider: String,
    /// `created` (Daal rented it) | `yours` (the person's own server) | "".
    pub server_origin: String,
    /// True only for Hetzner + created + server_running, or
    /// finished_unsaved: the setup can be finished on the server that
    /// exists without renting another.
    pub can_finish_here: bool,
    pub server_id: String,
    pub public_ip: String,
    /// `yes` | `no` | `unknown`.
    pub billing: String,
    pub leftovers: Vec<Leftover>,
    /// `""` | `no_token` | `offline` | `account_unreadable` |
    /// `custody_locked` | `failed`.
    pub check_error: String,
    pub started_at_unix: i64,
    /// Raw text, for a Details disclosure only.
    pub details: Vec<String>,
}

fn base(state: &str, provider: &str) -> SetupRecovery {
    SetupRecovery {
        state: state.into(),
        provider: provider.into(),
        billing: "unknown".into(),
        ..Default::default()
    }
}

fn parse_record(row: &OperatorRow) -> Option<PreProvisionRecord> {
    serde_json::from_str(&row.operator_record_json).ok()
}

/// The record handed to the audit for one row, with the server id the
/// journal knows filled in when the record has none.
fn record_for_audit(ctx: &WizardCtx, row: &OperatorRow) -> Option<String> {
    let mut v: serde_json::Value = serde_json::from_str(&row.operator_record_json).ok()?;
    let has = |k: &str, v: &serde_json::Value| {
        v.get(k).and_then(|x| x.as_str()).map(|s| !s.trim().is_empty()).unwrap_or(false)
    };
    // The audit derives the relay name from (region, publisher key); a
    // record without both names nothing and would make the run refuse.
    if !has("publisher_pub_key", &v) || !has("region", &v) {
        return None;
    }
    if !has("server_id", &v) {
        if let Some(sid) = provision_journal::read(&ctx.journal_dir, row.id)
            .and_then(|j| j.teardown_server_id(false).map(str::to_string))
        {
            v["server_id"] = serde_json::Value::String(sid);
        }
    }
    Some(v.to_string())
}

/// Classify a failed audit/reclaim run for the UI.
fn classify_failure(e: &BridgeError) -> &'static str {
    let t = e.to_string().to_ascii_lowercase();
    if t.contains("401") || t.contains("unauthorized") || t.contains("forbidden") || t.contains("403")
    {
        return "token_rejected";
    }
    if t.contains("unsupported provider") || t.contains("unknown provider") {
        return "unsupported_provider";
    }
    if looks_like_stale_allowlist(&t)
        || t.contains("no such host")
        || t.contains("temporary failure in name resolution")
    {
        return "offline";
    }
    "failed"
}

fn custody_failure(e: &WizardError) -> &'static str {
    if e.to_string().starts_with(E_CUSTODY_LOCKED) {
        "custody_locked"
    } else {
        "failed"
    }
}

/// Stage record files under `<staging>/audit/`; removed on drop.
struct StagedRecords {
    paths: Vec<PathBuf>,
}

impl StagedRecords {
    fn stage(ctx: &WizardCtx, tag: &str, bodies: &[String]) -> Result<Self> {
        let dir = ctx.staging_dir.join("audit");
        std::fs::create_dir_all(&dir)
            .map_err(|e| WizardError::Pricing(format!("mkdir audit staging: {e}")))?;
        let mut paths = Vec::with_capacity(bodies.len());
        for (i, b) in bodies.iter().enumerate() {
            let p = dir.join(format!("{tag}.{i}.record.json"));
            std::fs::write(&p, b.as_bytes())
                .map_err(|e| WizardError::Pricing(format!("stage record: {e}")))?;
            paths.push(p);
        }
        Ok(Self { paths })
    }
}

impl Drop for StagedRecords {
    fn drop(&mut self) {
        for p in &self.paths {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// `wizard_setup_recovery`: read-only. What happened to a setup that
/// did not finish, and what the person can do about it.
pub fn setup_recovery(ctx: &WizardCtx, operator_id: i64) -> Result<SetupRecovery> {
    let mut out = setup_recovery_inner(ctx, operator_id)?;
    if out.state == "unknown" {
        let journal = provision_journal::read(&ctx.journal_dir, operator_id);
        fill_from_journal(&mut out, journal.as_ref());
    }
    Ok(out)
}

/// When the account could not be asked, what this phone's own journal
/// says was made is still the best answer to "what will be deleted":
/// the cancel sheet lists it (billing stays "unknown" — nothing was
/// checked). Created-and-not-deleted only; the account is not touched.
pub(crate) fn fill_from_journal(out: &mut SetupRecovery, journal: Option<&JournalSummary>) {
    let Some(j) = journal else { return };
    if out.leftovers.is_empty() {
        // The person's own server is never "what will be deleted".
        for o in j.servers.iter().filter(|s| s.origin != "yours").chain(j.other_live.iter()) {
            if out.leftovers.iter().any(|l| l.kind == o.kind && l.id == o.id) {
                continue;
            }
            out.leftovers.push(Leftover {
                kind: o.kind.clone(),
                id: o.id.clone(),
                name: o.name.clone(),
                billing: matches!(o.kind.as_str(), "server" | "floating-ip"),
            });
        }
    }
    if let Some(srv) = j.servers.iter().find(|s| s.origin != "yours") {
        if out.server_id.is_empty() {
            out.server_id = srv.id.clone();
            out.public_ip = srv.public_ip.clone();
        }
        if out.server_origin.is_empty() {
            out.server_origin = "created".into();
        }
    }
}

fn setup_recovery_inner(ctx: &WizardCtx, operator_id: i64) -> Result<SetupRecovery> {
    let row = ctx.db.get(operator_id)?;
    let rec = parse_record(&row);
    let provider = rec
        .as_ref()
        .map(|r| r.provider.clone())
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| row.cloud_provider.clone());
    if row.status != "pre-provision" {
        return Ok(base("none", &provider));
    }
    let jpath = provision_journal::journal_path(&ctx.journal_dir, operator_id);
    let journal: Option<JournalSummary> = provision_journal::read(&ctx.journal_dir, operator_id);
    let started_at_unix = journal
        .as_ref()
        .and_then(|j| j.last_begin.as_ref())
        .and_then(|b| parse_rfc3339_unix(&b.ts).ok())
        .unwrap_or(0);
    let journal_server = journal
        .as_ref()
        .and_then(|j| j.servers.first().cloned());

    if provision_journal::is_locked(&jpath) {
        let mut out = base("running", &provider);
        out.started_at_unix = started_at_unix;
        out.billing = if journal_server.is_some() { "yes" } else { "unknown" }.into();
        if let Some(s) = &journal_server {
            out.server_id = s.id.clone();
            out.public_ip = s.public_ip.clone();
            out.server_origin = if s.origin == "yours" { "yours" } else { "created" }.into();
        }
        return Ok(out);
    }
    if journal.as_ref().and_then(|j| j.done_record.as_ref()).is_some() {
        let rec = journal.as_ref().and_then(|j| j.done_record.clone()).unwrap_or_default();
        let mut out = base("finished_unsaved", &provider);
        out.can_finish_here = true;
        out.server_origin = "created".into();
        out.billing = "yes".into();
        out.started_at_unix = started_at_unix;
        out.server_id = rec.get("server_id").and_then(|v| v.as_str()).unwrap_or("").into();
        out.public_ip = rec.get("public_ip").and_then(|v| v.as_str()).unwrap_or("").into();
        return Ok(out);
    }
    let mode = journal
        .as_ref()
        .and_then(|j| j.last_begin.as_ref())
        .map(|b| b.mode.clone())
        .unwrap_or_default();
    // The person's own server is in play when the last run was setting
    // it up, and ALSO when an earlier run was and nothing Daal rented
    // since is (or may be) live: switching to "rent a new one" after a
    // failed own-server run must not make that server vanish from the
    // card — it would then go unnamed, and is never Daal's to delete
    // without the person saying so.
    let own_live = journal.as_ref().and_then(|j| {
        let daal_live = j.unanswered_server_intent
            || j.servers.iter().any(|s| s.origin != "yours");
        if daal_live {
            None
        } else {
            j.own_server().cloned()
        }
    });
    if mode == "rebuild_yours" || own_live.is_some() {
        // The person's own server: unlabelled, so the account cannot be
        // asked about it, and it was billing before Daal ever touched it.
        let mut out = base("server_running", &provider);
        out.server_origin = "yours".into();
        out.billing = "yes".into();
        out.started_at_unix = started_at_unix;
        let begin_id = journal
            .as_ref()
            .and_then(|j| j.last_begin.as_ref())
            .map(|b| b.existing_server_id.clone())
            .unwrap_or_default();
        let own = own_live.or_else(|| journal.as_ref().and_then(|j| j.own_server().cloned()));
        out.public_ip = own.as_ref().map(|s| s.public_ip.clone()).unwrap_or_default();
        out.server_id = own
            .map(|s| s.id)
            .or_else(|| journal_server.map(|s| s.id))
            .filter(|s| !s.is_empty())
            .unwrap_or(begin_id);
        return Ok(out);
    }

    let has_token = !row.cloud_token_keystore_alias.is_empty();
    let has_pub = rec.as_ref().is_some_and(|r| !r.publisher_pub_key.trim().is_empty());
    if !has_token {
        if journal.is_none() {
            return Ok(base("none", &provider));
        }
        let mut out = base("unknown", &provider);
        out.check_error = "no_token".into();
        out.started_at_unix = started_at_unix;
        return Ok(out);
    }
    if !has_pub {
        // No publisher key, no derived name, no setup could have run.
        if journal.is_none() {
            return Ok(base("none", &provider));
        }
        let mut out = base("unknown", &provider);
        out.check_error = "failed".into();
        out.details.push("this relay has a setup journal but no publisher key".into());
        return Ok(out);
    }
    let token = match custody_get_string(ctx, &row.cloud_token_keystore_alias) {
        Ok(t) => t,
        Err(e) => {
            let mut out = base("unknown", &provider);
            out.check_error = custody_failure(&e).into();
            out.details.push(e.to_string());
            out.started_at_unix = started_at_unix;
            return Ok(out);
        }
    };
    let Some(body) = record_for_audit(ctx, &row) else {
        let mut out = base(if journal.is_some() { "unknown" } else { "none" }, &provider);
        if journal.is_some() {
            out.check_error = "failed".into();
        }
        return Ok(out);
    };
    let staged = StagedRecords::stage(ctx, &format!("recovery-{operator_id}"), &[body])?;
    let report = ctx.cli.run_account_audit(&provider, token.as_str(), &staged.paths);
    drop(staged);
    let report = match report {
        Ok(r) => r,
        Err(e) => {
            let mut out = base("unknown", &provider);
            out.check_error = match classify_failure(&e) {
                "offline" => "offline",
                "token_rejected" => "account_unreadable",
                _ => "failed",
            }
            .into();
            out.details.push(e.to_string());
            out.started_at_unix = started_at_unix;
            return Ok(out);
        }
    };
    Ok(recovery_from_audit(
        &provider,
        &report,
        journal.as_ref(),
        started_at_unix,
    ))
}

/// The pure half of [`setup_recovery`]: one row's audit, read.
pub(crate) fn recovery_from_audit(
    provider: &str,
    report: &AccountAuditReport,
    journal: Option<&JournalSummary>,
    started_at_unix: i64,
) -> SetupRecovery {
    let mut out = base("unknown", provider);
    out.started_at_unix = started_at_unix;
    out.details.extend(report.warnings.iter().cloned());
    let known = report
        .known
        .iter()
        .find(|k| k.record_index.unwrap_or(0) == 0)
        .cloned()
        .unwrap_or_default();
    let relay = if !known.relay.is_empty() {
        known.relay.clone()
    } else {
        journal
            .and_then(|j| j.last_begin.as_ref())
            .map(|b| b.relay_name.clone())
            .unwrap_or_default()
    };
    if !relay.is_empty() {
        out.leftovers = report
            .resources
            .iter()
            .filter(|r| r.relay == relay)
            .map(|r| Leftover {
                kind: r.kind.clone(),
                id: r.id.clone(),
                name: r.name.clone(),
                billing: r.billing,
            })
            .collect();
    }
    if !known.live_server_id.is_empty() {
        out.state = "server_running".into();
        out.server_origin = "created".into();
        out.billing = "yes".into();
        out.server_id = known.live_server_id.clone();
        out.can_finish_here = provider.eq_ignore_ascii_case("hetzner");
        out.public_ip = report
            .resources
            .iter()
            .find(|r| r.kind == "server" && r.id == known.live_server_id)
            .map(|r| r.address.clone())
            .filter(|a| !a.is_empty())
            .or_else(|| {
                journal
                    .and_then(|j| j.servers.iter().find(|s| s.id == known.live_server_id))
                    .map(|s| s.public_ip.clone())
            })
            .unwrap_or_default();
        return out;
    }
    if report.server_list_complete {
        out.state = "nothing_billing".into();
        out.billing = if out.leftovers.iter().any(|l| l.billing) { "yes" } else { "no" }.into();
        return out;
    }
    out.check_error = "account_unreadable".into();
    out
}

/// `wizard_setup_remove_server`: delete the cloud side of a setup that
/// did not finish, and KEEP the relay row so the setup can start again
/// without typing the token in again.
pub fn setup_remove_server(ctx: &WizardCtx, operator_id: i64) -> Result<DestroyReport> {
    let row = ctx.db.get(operator_id)?;
    if row.status != "pre-provision" {
        return Err(WizardError::Validation(
            "this relay's setup has finished; remove the relay instead".into(),
        ));
    }
    let jpath = provision_journal::journal_path(&ctx.journal_dir, operator_id);
    if provision_journal::is_locked(&jpath) {
        return Err(coded(
            E_SETUP_RUNNING,
            "a setup is still running for this relay; wait a minute, then check again",
        ));
    }
    let cloud = destroy_cloud_resources(ctx, operator_id, &row, true, false)?;
    let still_billing = failed_addresses(&cloud);
    let retry_needed = cloud.retry_needed || !still_billing.is_empty();
    if retry_needed {
        ctx.db.set_unreleased_addresses(operator_id, &still_billing)?;
    } else {
        ctx.db.set_unreleased_addresses(operator_id, &[])?;
        provision_journal::remove(&ctx.journal_dir, operator_id);
    }
    let mut warnings = cloud.warnings;
    warnings.extend(cloud.bridge_notes);
    Ok(DestroyReport {
        server_deleted: cloud.server_deleted,
        ssh_key_deleted: cloud.ssh_key_deleted,
        firewall_deleted: cloud.firewall_deleted,
        local_removed: false,
        warnings,
        addresses: cloud.addresses,
        retry_needed,
    })
}

// --------------------------------------------------------------------
// The account check
// --------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct AccountItem {
    pub kind: String,
    pub id: String,
    pub name: String,
    pub address: String,
    pub billing: bool,
    /// `in-use` | `unclaimed` | `orphan` | `unproven`.
    pub verdict: String,
    /// `yours_in_use` | `unfinished_setup` | `not_on_this_phone` |
    /// `second_server_for_relay` | `leftover` | `cannot_tell`.
    pub finding: String,
    pub belongs_to_relay_id: Option<i64>,
    pub can_delete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct AccountCheckAccount {
    pub account_key: String,
    pub provider: String,
    pub relay_ids: Vec<i64>,
    /// The server list could be read. False means nothing is deletable.
    pub complete: bool,
    /// `""` | `offline` | `token_rejected` | `unsupported_provider` |
    /// `custody_locked` | `failed`.
    pub error_code: String,
    pub items: Vec<AccountItem>,
    pub details: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct AccountCheck {
    pub accounts: Vec<AccountCheckAccount>,
    pub checked_at_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct CleanupOutcome {
    pub kind: String,
    pub id: String,
    pub name: String,
    pub deleted: bool,
    pub code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct AccountCleanupReport {
    pub outcomes: Vec<CleanupOutcome>,
    pub details: Vec<String>,
}

/// One hosting account this phone has a token for.
struct Account {
    key: String,
    provider: String,
    token: Zeroizing<String>,
    /// Smallest id first.
    relay_ids: Vec<i64>,
}

/// Every account, grouped by (provider, sha256(token)), plus the rows
/// whose token could not be read (each its own entry). The token hash
/// is only a grouping key and is never returned.
fn group_accounts(
    ctx: &WizardCtx,
    rows: &[OperatorRow],
) -> (Vec<Account>, Vec<AccountCheckAccount>) {
    let mut groups: BTreeMap<(String, String), Account> = BTreeMap::new();
    let mut unreadable = Vec::new();
    for row in rows {
        if row.cloud_token_keystore_alias.is_empty() {
            continue;
        }
        let provider = parse_record(row)
            .map(|r| r.provider)
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| row.cloud_provider.clone());
        match custody_get_string(ctx, &row.cloud_token_keystore_alias) {
            Ok(token) => {
                let digest = hex::encode(Sha256::digest(token.as_bytes()));
                let entry = groups
                    .entry((provider.clone(), digest))
                    .or_insert_with(|| Account {
                        key: String::new(),
                        provider: provider.clone(),
                        token,
                        relay_ids: Vec::new(),
                    });
                entry.relay_ids.push(row.id);
            }
            Err(e) => unreadable.push(AccountCheckAccount {
                account_key: format!("{provider}:{}", row.id),
                provider,
                relay_ids: vec![row.id],
                complete: false,
                error_code: custody_failure(&e).into(),
                items: vec![],
                details: vec![e.to_string()],
            }),
        }
    }
    let mut out: Vec<Account> = groups.into_values().collect();
    for a in &mut out {
        a.relay_ids.sort_unstable();
        a.key = format!("{}:{}", a.provider, a.relay_ids[0]);
    }
    out.sort_by(|a, b| a.key.cmp(&b.key));
    (out, unreadable)
}

/// Every row of this phone on `provider` that names a relay, staged as a
/// record — a record protects everything it names, so ALL of them go to
/// the audit and the reclaim, not just the ones sharing this token.
fn records_for_provider(
    ctx: &WizardCtx,
    rows: &[OperatorRow],
    provider: &str,
) -> (Vec<String>, Vec<i64>) {
    let mut bodies = Vec::new();
    let mut ids = Vec::new();
    for row in rows {
        let p = parse_record(row)
            .map(|r| r.provider)
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| row.cloud_provider.clone());
        if !p.eq_ignore_ascii_case(provider) {
            continue;
        }
        if let Some(b) = record_for_audit(ctx, row) {
            bodies.push(b);
            ids.push(row.id);
        }
    }
    (bodies, ids)
}

/// The pure half of the account check: one audit, read against the rows.
pub(crate) fn account_items(
    report: &AccountAuditReport,
    index_to_op: &[i64],
    status_of: &HashMap<i64, String>,
) -> Vec<AccountItem> {
    let complete = report.server_list_complete;
    let mut relay_to_op: HashMap<&str, i64> = HashMap::new();
    for k in &report.known {
        if let Some(op) = k.record_index.and_then(|i| index_to_op.get(i)) {
            relay_to_op.insert(k.relay.as_str(), *op);
        }
    }
    report
        .resources
        .iter()
        .map(|r: &AuditedResourceRow| {
            let belongs = relay_to_op.get(r.relay.as_str()).copied();
            let status = belongs.and_then(|id| status_of.get(&id)).map(String::as_str);
            let pre = status == Some("pre-provision");
            let finding = match r.verdict.as_str() {
                "in-use" => {
                    if pre && r.kind == "server" {
                        "unfinished_setup"
                    } else {
                        "yours_in_use"
                    }
                }
                "unclaimed" => match (belongs, r.kind.as_str()) {
                    (Some(_), "server") if pre => "unfinished_setup",
                    (Some(_), "server") => "second_server_for_relay",
                    (None, "server") => "not_on_this_phone",
                    _ => "leftover",
                },
                "orphan" => "leftover",
                _ => "cannot_tell",
            };
            let can_delete = complete
                && match (r.verdict.as_str(), r.kind.as_str()) {
                    ("orphan", _) => r.reclaimable,
                    // An unclaimed server is one the audit proved Daal
                    // labelled for one of its relays and that no record
                    // on this phone claims. The reclaim re-checks both
                    // labels and refuses otherwise.
                    ("unclaimed", "server") => {
                        matches!(finding, "not_on_this_phone" | "second_server_for_relay")
                    }
                    // An address is only ever `unclaimed` when a record
                    // on this phone still names it (its server gone), and
                    // the reclaim keeps every address a record names
                    // (`kept_claimed`): offering it here would be an
                    // action that cannot work. Its relay's own "Try
                    // again" (`belongs_to_relay_id`) is the way to give
                    // it back.
                    ("unclaimed", "floating-ip") => false,
                    _ => false,
                };
            AccountItem {
                kind: r.kind.clone(),
                id: r.id.clone(),
                name: r.name.clone(),
                address: r.address.clone(),
                billing: r.billing,
                verdict: r.verdict.clone(),
                finding: finding.into(),
                belongs_to_relay_id: belongs,
                can_delete,
            }
        })
        .collect()
}

/// `wizard_account_check`: read-only, every hosting account this phone
/// holds a token for.
pub fn account_check(ctx: &WizardCtx) -> Result<AccountCheck> {
    let rows = ctx.db.list()?;
    let status_of: HashMap<i64, String> = rows.iter().map(|r| (r.id, r.status.clone())).collect();
    let (accounts, mut out) = group_accounts(ctx, &rows);
    let mut checked = Vec::new();
    for acc in accounts {
        let (bodies, index_to_op) = records_for_provider(ctx, &rows, &acc.provider);
        let mut entry = AccountCheckAccount {
            account_key: acc.key.clone(),
            provider: acc.provider.clone(),
            relay_ids: acc.relay_ids.clone(),
            ..Default::default()
        };
        let staged = StagedRecords::stage(ctx, &format!("check-{}", acc.relay_ids[0]), &bodies)?;
        let res = ctx.cli.run_account_audit(&acc.provider, acc.token.as_str(), &staged.paths);
        drop(staged);
        match res {
            Ok(report) => {
                entry.complete = report.server_list_complete;
                entry.items = account_items(&report, &index_to_op, &status_of);
                entry.details = report.warnings.clone();
            }
            Err(e) => {
                entry.error_code = classify_failure(&e).into();
                entry.details.push(e.to_string());
            }
        }
        checked.push(entry);
    }
    checked.append(&mut out);
    Ok(AccountCheck {
        accounts: checked,
        checked_at_unix: (ctx.clock)(),
    })
}

/// `wizard_account_cleanup`: delete what the person ticked, in one
/// account. `account-reclaim` re-checks every guard; an item it will not
/// delete comes back with the code that says why.
pub fn account_cleanup(
    ctx: &WizardCtx,
    account_key: &str,
    items: &[ResourceRef],
) -> Result<AccountCleanupReport> {
    let rows = ctx.db.list()?;
    let (accounts, _) = group_accounts(ctx, &rows);
    let Some(acc) = accounts.into_iter().find(|a| a.key == account_key) else {
        return Err(WizardError::Validation(
            "that hosting account is no longer on this phone; check again".into(),
        ));
    };
    if items.is_empty() {
        return Ok(AccountCleanupReport::default());
    }
    for it in items {
        if !matches!(it.kind.as_str(), "server" | "floating-ip" | "ssh-key" | "firewall")
            || it.id.trim().is_empty()
        {
            return Err(WizardError::Validation(format!("not a cloud object: {}", it.kind)));
        }
    }
    let (bodies, _) = records_for_provider(ctx, &rows, &acc.provider);
    let staged = StagedRecords::stage(ctx, &format!("reclaim-{}", acc.relay_ids[0]), &bodies)?;
    let include_unclaimed_servers = items.iter().any(|i| i.kind == "server");
    let res = ctx.cli.run_account_reclaim(AccountReclaimArgs {
        provider: &acc.provider,
        token: acc.token.as_str(),
        record_files: &staged.paths,
        only: items,
        include_unclaimed_servers,
    });
    drop(staged);
    let report = match res {
        Ok(r) => r,
        Err(e) if verb_unknown(&e)
            || crate::cli_bridge::flag_not_defined(&e, "include-unclaimed-servers") =>
        {
            return Err(coded(
                E_DEPLOY_TOO_OLD,
                format!("the setup helper bundled with this app cannot clean up the account: {e}"),
            ))
        }
        Err(e) => return Err(WizardError::Subprocess(e.to_string())),
    };
    let mut details = report.warnings.clone();
    let outcomes = report
        .outcomes
        .iter()
        .map(|o| {
            if !o.reason.is_empty() {
                details.push(format!("{}:{} {}", o.kind, o.id, o.reason));
            }
            let code = if !o.code.is_empty() {
                o.code.clone()
            } else if o.deleted {
                if o.kind == "floating-ip" { "released" } else { "deleted" }.into()
            } else {
                "kept_unproven".into()
            };
            CleanupOutcome {
                kind: o.kind.clone(),
                id: o.id.clone(),
                name: o.name.clone(),
                deleted: o.deleted,
                code,
            }
        })
        .collect();
    Ok(AccountCleanupReport { outcomes, details })
}
