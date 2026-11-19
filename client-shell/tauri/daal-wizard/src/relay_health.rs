//! D3: "is my relay working?" — a health check the publisher can press.
//!
//! Before this nothing ran one: the relay list badge showed only the
//! recorded state, so a server switched off at the provider, a relay
//! whose management stopped answering or a relay rebuilt without the
//! people on it all looked exactly like a healthy one.
//!
//! `daal-deploy relay-health` asks three things, read-only, using the
//! signed management calls that already exist (`/identity`,
//! `/users/list`) over the existing per-call firewall window — no new
//! port on the relay: does the server exist and run at the provider (if
//! a token is stored), does the relay's management answer, and does
//! each way in answer from HERE. This module turns that into the plain
//! verdict the UI shows, compares what the relay says against what the
//! signed file commits to, counts the people the relay no longer knows,
//! and keeps the last answer so the check runs at most every ten
//! minutes unless the person presses "Check now".
//!
//! Honest limit, stated once in the UI: from outside the censored
//! country nobody can see whether the relay is blocked inside it.
//!
//! Read-only: never re-signs, publishes or heals.

use serde::{Deserialize, Serialize};

use crate::cli_bridge::{verb_unknown, RelayHealthArgs, RelayHealthReport};
use crate::commands::{
    coded, custody_get, custody_get_string, looks_like_stale_allowlist, record_served_families,
    require_helper_ip, Result, WizardCtx, WizardError, E_DEPLOY_TOO_OLD,
};
use crate::relay_identity::ReplyMaterial;
use crate::staging::PreProvisionRecord;

/// How long a check stays fresh.
pub const HEALTH_CACHE_SECS: i64 = 600;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct HealthWay {
    pub family: String,
    /// `answers` | `no_answer` | `wrong_server` | `not_testable_here`.
    pub state: String,
}

/// Mirrors `RelayHealth` in wizardCommands.ts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RelayHealth {
    pub operator_id: i64,
    pub checked_at_unix: i64,
    pub from_cache: bool,
    /// `working` | `partly` | `not_working` | `unknown`.
    pub overall: String,
    pub server: String,
    pub management: String,
    /// `""` | `address_may_have_changed` | `timeout` | `refused`.
    pub management_reason: String,
    pub keys_match: Option<bool>,
    pub people_missing: Option<i64>,
    pub everyone_missing: Option<bool>,
    pub ways: Vec<HealthWay>,
    /// Raw text, for a Details disclosure only.
    pub details: Vec<String>,
}

fn one_of(v: &str, allowed: &[&str], fallback: &str) -> String {
    if allowed.contains(&v) {
        v.to_string()
    } else {
        fallback.to_string()
    }
}

/// What the live roster holds that a users list would have to show.
pub(crate) struct Expectations<'a> {
    /// Names of people not removed.
    pub live_names: &'a [String],
    pub everyone_file_exists: bool,
    pub committed: Option<&'a crate::cli_bridge::CommittedIdentity>,
    pub record_families: &'a [String],
}

/// The pure half: read one report.
pub(crate) fn assess(
    operator_id: i64,
    now: i64,
    report: &RelayHealthReport,
    exp: &Expectations<'_>,
) -> RelayHealth {
    let server = one_of(
        &report.server.state,
        &["running", "stopped", "starting", "missing", "not_checked", "error"],
        "error",
    );
    let management = one_of(
        &report.management.state,
        &["answers", "no_answer", "refused", "too_old", "not_checked", "error"],
        "error",
    );
    let management_reason = if matches!(management.as_str(), "no_answer" | "error")
        && looks_like_stale_allowlist(&report.management.error)
    {
        "address_may_have_changed"
    } else if management == "no_answer" {
        "timeout"
    } else if management == "refused" {
        "refused"
    } else {
        ""
    }
    .to_string();

    let keys_match = match (report.management.identity.as_ref(), exp.committed) {
        (Some(id), Some(committed)) => {
            let f = |k: &str| id.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
            let (rk, tls, sni) = (f("reality_public_key"), f("tls_cert_sha256"), f("cover_sni"));
            let changed = crate::relay_identity::keys_changed_in_place(committed, &rk, &tls);
            let moved = crate::relay_identity::moved(
                committed,
                &ReplyMaterial {
                    reality_public_key: &rk,
                    tls_cert_sha256: &tls,
                    cover_sni: &sni,
                    ss_password: "",
                    ss_method: "",
                },
                exp.record_families,
            );
            Some(changed.is_empty() && moved.is_empty())
        }
        _ => None,
    };

    let users = report.management.users.as_ref();
    let people_missing = users.map(|u| {
        exp.live_names
            .iter()
            .filter(|n| !u.iter().any(|x| x == *n))
            .count() as i64
    });
    let everyone_missing =
        users.map(|u| exp.everyone_file_exists && !u.iter().any(|x| x == "r0"));

    let ways: Vec<HealthWay> = report
        .ways
        .iter()
        .map(|w| HealthWay {
            family: w.family.clone(),
            state: one_of(
                &w.state,
                &["answers", "no_answer", "wrong_server", "not_testable_here"],
                "no_answer",
            ),
        })
        .collect();
    let testable: Vec<&HealthWay> = ways.iter().filter(|w| w.state != "not_testable_here").collect();

    let server_checked = !matches!(server.as_str(), "not_checked" | "error");
    let mgmt_checked = !matches!(management.as_str(), "not_checked" | "error");
    let overall = if !server_checked && !mgmt_checked && testable.is_empty() {
        "unknown"
    } else if matches!(server.as_str(), "missing" | "stopped")
        || (management == "no_answer" && testable.iter().all(|w| w.state == "no_answer"))
    {
        "not_working"
    } else if matches!(server.as_str(), "running" | "not_checked")
        && management == "answers"
        && keys_match != Some(false)
        // A way in was actually seen to answer: all-UDP is not "working".
        && !testable.is_empty()
        && testable.iter().all(|w| w.state == "answers")
        // A relay that does not know the people (a rebuilt box nobody
        // was renewed on) answers every probe while every file handed
        // out is dead: that is not "working" either.
        && people_missing.unwrap_or(0) == 0
        && everyone_missing != Some(true)
    {
        "working"
    } else {
        "partly"
    }
    .to_string();

    let mut details = Vec::new();
    for (leg, e) in [("server", &report.server.error), ("management", &report.management.error)] {
        if !e.is_empty() {
            details.push(format!("{leg}: {e}"));
        }
    }
    for w in &report.ways {
        if !w.error.is_empty() {
            details.push(format!("{} ({}): {}", w.family, w.port, w.error));
        }
    }
    details.extend(report.limits.iter().map(|l| format!("limit: {l}")));

    RelayHealth {
        operator_id,
        checked_at_unix: now,
        from_cache: false,
        overall,
        server,
        management,
        management_reason,
        keys_match,
        people_missing,
        everyone_missing,
        ways,
        details,
    }
}

/// `wizard_relay_health`.
pub fn relay_health(ctx: &WizardCtx, operator_id: i64, force: bool) -> Result<RelayHealth> {
    let row = ctx.db.get(operator_id)?;
    if row.status != "provisioned" {
        return Err(WizardError::Validation(
            "only a relay whose setup finished can be checked".into(),
        ));
    }
    let now = (ctx.clock)();
    if !force {
        let (json, at) = ctx.db.last_health(operator_id)?;
        if at > 0 && now - at < HEALTH_CACHE_SECS {
            if let Ok(mut cached) = serde_json::from_str::<RelayHealth>(&json) {
                cached.from_cache = true;
                return Ok(cached);
            }
        }
    }
    let helper_ip = require_helper_ip(ctx, operator_id)?;
    let priv_buf = custody_get(ctx, &row.publisher_priv_keystore_alias)?;
    let mut notes = Vec::new();
    let token = if row.cloud_token_keystore_alias.is_empty() {
        None
    } else {
        match custody_get_string(ctx, &row.cloud_token_keystore_alias) {
            Ok(t) => Some(t),
            Err(e) => {
                notes.push(format!("cloud token not readable, server not checked: {e}"));
                None
            }
        }
    };
    let record_path =
        crate::recipient_book::write_record_staging(ctx, operator_id, &row.operator_record_json)?;
    let res = ctx.cli.run_relay_health(
        RelayHealthArgs {
            record_path: &record_path,
            helper_ip: &helper_ip,
            token: token.as_ref().map(|t| t.as_str()),
            timeout_secs: 8,
        },
        priv_buf.as_slice(),
    );
    let _ = std::fs::remove_file(&record_path);
    let report = match res {
        Ok(r) => r,
        Err(e) if verb_unknown(&e) => {
            return Err(coded(
                E_DEPLOY_TOO_OLD,
                "the setup helper bundled with this app cannot check a relay's health",
            ))
        }
        Err(e) => return Err(WizardError::Subprocess(e.to_string())),
    };

    let live_names: Vec<String> = ctx
        .db
        .list_recipients(operator_id)?
        .into_iter()
        .filter(|r| r.revoked_at_unix == 0)
        .map(|r| r.name)
        .collect();
    let committed = crate::relay_identity::committed(ctx, operator_id)?;
    let families = serde_json::from_str::<PreProvisionRecord>(&row.operator_record_json)
        .map(|r| record_served_families(&r))
        .unwrap_or_default();
    let everyone_file_exists = ctx
        .staging_dir
        .join(format!("{operator_id}.shared.sbp"))
        .exists();
    let mut health = assess(
        operator_id,
        now,
        &report,
        &Expectations {
            live_names: &live_names,
            everyone_file_exists,
            committed: committed.as_ref(),
            record_families: &families,
        },
    );
    health.details.extend(notes);
    let json = serde_json::to_string(&health).unwrap_or_default();
    ctx.db.set_last_health(operator_id, &json, now)?;
    Ok(health)
}
