//! Add-on 2: a way in through Cloudflare (docs/optional-addons-plan.md
//! §2, specs/optional-addons-v1.md §4).
//!
//! The relay reachable through the publisher's own Cloudflare zone,
//! with ECH; one more signed route, tried last (decision D-2: no plain
//! hello fallback unless the publisher turns it on). No Worker (D-5).
//!
//! The flow the card runs: paste the token ([`set_token`]: checked by
//! `cdn-token-check`, kept only when it is exactly the five zone
//! permissions on one zone) → pick the zone → [`build`] (certificate and
//! Cloudflare settings and the relay firewall by `cdn-provision`, the
//! relay door by `cdn-door`, a real handshake through the front by
//! `cdn-test`, then the signature) → [`posture`] on every open.
//!
//! # What is stored where
//!
//! * The **token** stays where FRP-8 put it, `commands::cloudflare_alias`
//!   (`daal.cloudflare.<relay id>.token`): backed up, wiped by panic wipe
//!   and forgotten with the relay already. The row's `secret_alias` is
//!   left empty so there is one owner of that secret; [`remove`] forgets
//!   it explicitly. It reaches `daal-deploy` only as a 0600 temp file.
//! * The **front record** (`cloudflare.FrontRecord`: hostname, zone and
//!   Cloudflare's ids, the origin certificate's fingerprint and the
//!   local paths of its files; no secret) is in the row's `detail.front`
//!   and, while the way in is live, in the operator record as
//!   `cdn_front` (with `plain_fallback`), which is what the next
//!   signature reads. `detail.front` outlives the record member so a
//!   removal that signs first can still take the Cloudflare side down.
//!
//! # Rollback
//!
//! The row is written (`building`) before anything is created. A build
//! that fails after `cdn-provision` gives back what it made (door off,
//! `cdn-remove`). Only when that removal is incomplete does the row stay,
//! `building` with its front record, so [`remove`] is the retry.
//!
//! # The Cloudflare account (Accounts page)
//!
//! [`connect`] checks a token the same way without a relay and keeps it
//! under [`ACCOUNT_ALIAS`], with the one zone it sees under
//! [`ACCOUNT_ZONE_ALIAS`]. A relay that has no key of its own takes a
//! copy of the account's the first time it needs one (`cf_token`), so
//! from then on it is that relay's key exactly as [`set_token`] would
//! have stored it: backed up, forgotten by [`remove`]. [`account`] says
//! whether one is kept; [`disconnect`] forgets it (relays keep theirs).
//!
//! The older FRP-8 commands (`wizard_store_cloudflare_token`,
//! `wizard_provision_cdn_front`, `wizard_list_cdn_fronts`,
//! `wizard_verify_cdn_posture`) are left in `commands.rs` until the
//! shared registration retires them.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::addons::{
    self, AddonKind, AddonOutcome, AddonProgress, AddonRemoveReport, AddonRow, AddonState, NewAddon,
};
use crate::cli_bridge::{verb_unknown, AddonCliRequest, BridgeError, ProgressEvent};
use crate::commands::{
    cloudflare_alias, coded, custody_get, custody_get_string, custody_put, require_helper_ip,
    Result, WizardCtx, WizardError, E_DEPLOY_TOO_OLD, E_NOT_SUPPORTED, E_RELAY_TOO_OLD,
};
use crate::relay_identity::{resign_and_republish, Freshness};

/// No Cloudflare key on this phone for this relay (or the one there was
/// refused): paste one first. Nothing was created.
pub const E_CDN_NO_TOKEN: &str = "E_CDN_NO_TOKEN";
/// The relay was built before the Cloudflare door existed; it needs a
/// rebuild to gain it (plan §2.3). What was made was taken down again.
pub const E_CDN_NEEDS_REBUILD: &str = "E_CDN_NEEDS_REBUILD";
/// The handshake through Cloudflare did not work, so nothing was signed
/// and what was made was taken down again. The tail is the test's words.
pub const E_CDN_TEST_FAILED: &str = "E_CDN_TEST_FAILED";
/// A failed build could not take everything down again. The row stays
/// with its front record; "Remove" is the retry. The tail names what is
/// left.
pub const E_CDN_LEFT_BEHIND: &str = "E_CDN_LEFT_BEHIND";
/// Cloudflare refused a setup step (zone not active, a record already
/// using the name, a permission short of Edit). Nothing is left.
pub const E_CDN_PROVISION: &str = "E_CDN_PROVISION";

/// The Cloudflare account's key, kept apart from any relay.
pub const ACCOUNT_ALIAS: &str = "daal.cloudflare.account.token";
/// The one zone the account's key sees (not a secret; kept beside it).
pub const ACCOUNT_ZONE_ALIAS: &str = "daal.cloudflare.account.zone";

/// The record member the binder reads for the CDN route.
pub const RECORD_MEMBER: &str = "cdn_front";

/// `wizard_addon_cdn_set_token`: check a pasted Cloudflare token and,
/// when it is exactly what Daal needs, keep it in custody.
///
/// No `Debug`: the token must never reach a log line.
#[derive(Clone, Deserialize)]
pub struct CdnTokenInput {
    pub operator_id: i64,
    pub token: String,
    /// The zone the publisher means, when they already know it.
    #[serde(default)]
    pub zone: String,
}

/// `wizard_addon_cdn_connect`: check a pasted Cloudflare token without a
/// relay (the Accounts page) and keep it for every relay.
///
/// No `Debug`: the token must never reach a log line.
#[derive(Clone, Deserialize)]
pub struct CdnConnectInput {
    pub token: String,
}

/// `wizard_addon_cdn_account`: whether this phone keeps a Cloudflare
/// account key, and the zone it sees.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct CdnAccount {
    pub connected: bool,
    /// The zone's name; empty when not connected.
    pub zone: String,
}

/// What the token can see and do.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct CdnTokenCheck {
    /// Zones the token can see (name only).
    pub zones: Vec<String>,
    /// `ok` | `invalid` (not a working token) | `no_zone` (sees no
    /// active zone) | `zone_not_visible` (not the zone asked for) |
    /// `too_broad` (more than one zone, or more than the five
    /// permissions; refused, not stored) | `missing_permission` |
    /// `refused` (the helper refused it without saying why).
    pub verdict: String,
    /// Stored in custody (only when `ok`).
    pub stored: bool,
    /// Permission names missing (`missing_permission`) or extra
    /// (`too_broad`), in Cloudflare's words.
    #[serde(default)]
    pub missing: Vec<String>,
    #[serde(default)]
    pub extra: Vec<String>,
}

/// `wizard_addon_cdn_build`: certificate, Cloudflare settings, firewall,
/// relay door, test from this phone, signature. Rolls back on failure.
#[derive(Debug, Clone, Deserialize)]
pub struct CdnBuildInput {
    pub operator_id: i64,
    /// The zone to use, from `CdnTokenCheck::zones`.
    pub zone: String,
}

/// `wizard_addon_cdn_posture`: the card's posture line, refreshed.
#[derive(Debug, Clone, Deserialize)]
pub struct CdnPostureInput {
    pub operator_id: i64,
    /// Also run a real handshake through the front now (default yes).
    #[serde(default = "yes")]
    pub test: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct CdnPosture {
    /// "Name hidden": ECH is on for the zone and the last test used it.
    /// `None` when it could not be read.
    pub name_hidden: Option<bool>,
    /// "Only Cloudflare can reach the door": origin pull on and the
    /// firewall open to Cloudflare's ranges only. `None`: not checked.
    pub door_closed_to_others: Option<bool>,
    /// The last real handshake through the front from this device.
    pub last_test_at_unix: i64,
    pub last_test_ok: Option<bool>,
    /// Domain renewal date when the token can read it, else 0.
    pub renews_at_unix: i64,
    /// The relay was built before the CDN door existed: it needs a
    /// rebuild to gain it (plan §2.3).
    pub needs_rebuild: bool,
    /// The proxied name, e.g. `k3j9.example.com`. Public.
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub zone: String,
    /// The signed flag that lets the route fall back to a plain hello.
    #[serde(default)]
    pub plain_fallback: bool,
    /// Provider words for anything that could not be read. Details only.
    #[serde(default)]
    pub notes: String,
}

/// `wizard_addon_cdn_set_plain_fallback`: the signed per-pack flag that
/// lets the CDN route fall back to a plain hello (the zone name then
/// shows on the wire). Off by default (D-2).
#[derive(Debug, Clone, Deserialize)]
pub struct CdnPlainFallbackInput {
    pub operator_id: i64,
    pub allow: bool,
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

fn progress(op: i64, step: &str, state: &str, detail: impl Into<String>) -> AddonProgress {
    AddonProgress {
        operator_id: op,
        kind: AddonKind::Cdn,
        step: step.into(),
        state: state.into(),
        detail: detail.into(),
    }
}

/// `cdn-provision --progress-json` lines: `cloudflare` and `firewall`,
/// each with `state` running | ok | failed. The message can carry
/// provider words (already scrubbed of the token by the helper).
fn translate(op: i64, ev: &ProgressEvent, out: &mut dyn FnMut(AddonProgress)) {
    let state = ev.extra.get("state").and_then(Value::as_str).unwrap_or("running");
    let step = match ev.step.as_str() {
        "cloudflare" => "cloudflare",
        "firewall" => "firewall",
        "door" | "cdn_door" => "door",
        _ => return,
    };
    let detail = if state == "failed" { ev.message.clone() } else { String::new() };
    out(progress(op, step, state, detail));
}

/// The first JSON object inside a text, for a helper refusal (exit 4)
/// whose answer is on stdout: the bridge puts that stdout at the head of
/// the failure text (`cli_bridge::ADDON_REFUSED_RC`), and whatever the
/// helper wrote on stderr follows it.
fn json_in(text: &str) -> Option<Value> {
    let start = text.find('{')?;
    serde_json::Deserializer::from_str(&text[start..])
        .into_iter::<Value>()
        .next()?
        .ok()
        .filter(Value::is_object)
}

fn str_list(v: &Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

/// A helper failure in this add-on's error contract.
fn cli_err(what: &str, e: BridgeError) -> WizardError {
    if verb_unknown(&e) {
        return coded(
            E_DEPLOY_TOO_OLD,
            format!("the setup helper bundled with this app has no {what}"),
        );
    }
    match e {
        BridgeError::SubprocessFailed { rc: 3, stderr } => coded(E_RELAY_TOO_OLD, stderr.trim()),
        BridgeError::SubprocessFailed { stderr, .. } => {
            coded(E_CDN_PROVISION, crate::freshness::redact_detail(stderr.trim()))
        }
        other => WizardError::Subprocess(crate::freshness::redact_detail(&other.to_string())),
    }
}

/// The front record staged for one helper run, removed when dropped. It
/// holds no secret (ids, the hostname and paths), but it does not need
/// to outlive the run.
struct Staged(PathBuf);

impl Staged {
    fn write(ctx: &WizardCtx, op: i64, front: &Value) -> Result<Self> {
        Self::write_named(ctx, op, "cdn.front", front)
    }
    fn write_named(ctx: &WizardCtx, op: i64, what: &str, v: &Value) -> Result<Self> {
        std::fs::create_dir_all(&ctx.staging_dir)
            .map_err(|e| WizardError::Cdn(format!("mkdir staging: {e}")))?;
        let p = ctx.staging_dir.join(format!("{op}.{what}.json"));
        std::fs::write(&p, v.to_string().as_bytes())
            .map_err(|e| WizardError::Cdn(format!("write {what} record: {e}")))?;
        Ok(Self(p))
    }
    fn arg(&self) -> String {
        self.0.to_string_lossy().to_string()
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn record(ctx: &WizardCtx, op: i64) -> Result<(String, Value)> {
    let row = ctx.db.get(op)?;
    let v: Value = serde_json::from_str(&row.operator_record_json)
        .map_err(|e| WizardError::Validation(format!("this relay's record is unreadable: {e}")))?;
    Ok((row.operator_record_json, v))
}

fn with_member(rec: &Value, member: Option<Value>) -> String {
    let mut v = rec.clone();
    if let Some(m) = v.as_object_mut() {
        match member {
            Some(x) => {
                m.insert(RECORD_MEMBER.into(), x);
            }
            None => {
                m.remove(RECORD_MEMBER);
            }
        }
    }
    v.to_string()
}

/// The relay's live CDN row, if any.
fn live_row(ctx: &WizardCtx, op: i64) -> Result<Option<AddonRow>> {
    Ok(addons::list(ctx, op)?
        .into_iter()
        .find(|r| r.kind == AddonKind::Cdn && r.state != AddonState::Promoted))
}

fn front_of(row: &AddonRow) -> Option<Value> {
    row.detail.get("front").filter(|f| f.is_object()).cloned()
}

fn set_detail_field(ctx: &WizardCtx, row_id: i64, key: &str, v: Value) -> Result<()> {
    let mut d = addons::get(ctx, row_id)?.detail;
    if !d.is_object() {
        d = Value::Object(Default::default());
    }
    d.as_object_mut().unwrap().insert(key.into(), v);
    addons::set_detail(ctx, row_id, &d)
}

/// A kept token, or `None` when there is none under `alias`.
fn kept(ctx: &WizardCtx, alias: &str) -> Result<Option<Zeroizing<String>>> {
    match custody_get_string(ctx, alias) {
        Ok(t) if !t.trim().is_empty() => Ok(Some(t)),
        Ok(_) => Ok(None),
        Err(WizardError::Coded(c)) if c.starts_with(crate::commands::E_SECRET_MISSING) => Ok(None),
        Err(e) => Err(e),
    }
}

/// The relay's key; when it has none, a copy of the account's, kept as
/// the relay's own from now on.
fn cf_token(ctx: &WizardCtx, op: i64) -> Result<Zeroizing<String>> {
    if let Some(t) = kept(ctx, &cloudflare_alias(op))? {
        return Ok(t);
    }
    if let Some(t) = kept(ctx, ACCOUNT_ALIAS)? {
        custody_put(ctx, &cloudflare_alias(op), t.as_bytes())?;
        return Ok(t);
    }
    Err(coded(E_CDN_NO_TOKEN, "no Cloudflare key is kept for this relay"))
}

/// The hosting token, when this phone holds one: it closes the firewall
/// rule. Its absence skips that step, it does not stop a removal.
fn hz_token(ctx: &WizardCtx, op: i64) -> Option<Zeroizing<String>> {
    let row = ctx.db.get(op).ok()?;
    if row.cloud_token_keystore_alias.is_empty() {
        return None;
    }
    custody_get_string(ctx, &row.cloud_token_keystore_alias).ok()
}

fn provider_ids(front: &Value) -> BTreeMap<String, String> {
    let mut ids = BTreeMap::new();
    for k in ["zone_id", "hostname", "origin_cert_id", "aop_cert_id", "firewall_id", "origin_rule_ref"] {
        if let Some(s) = front.get(k).and_then(Value::as_str).filter(|s| !s.is_empty()) {
            ids.insert(k.to_string(), s.to_string());
        }
    }
    let dns = str_list(front, "dns_record_ids");
    if !dns.is_empty() {
        ids.insert("dns_record_ids".into(), dns.join(","));
    }
    ids
}

/// The relay's Hetzner firewall: `firewall_id` when the record has one,
/// else the name provisioning gave it (`daal-relay-<server id>`), which
/// `cdn-provision` looks up on the account. The front record it prints
/// carries the numeric id from then on.
fn firewall_of(rec: &Value) -> String {
    if let Some(s) = rec.get("firewall_id").and_then(Value::as_str).filter(|s| !s.is_empty()) {
        return s.to_string();
    }
    let sid = rec.get("server_id").and_then(Value::as_str).unwrap_or("");
    format!("daal-relay-{sid}")
}

// ---------------------------------------------------------------------
// The helper verbs
// ---------------------------------------------------------------------

/// What `cdn-test` said. `no_ech` is a refusal before dialling: the
/// hostname publishes no ECH config.
#[derive(Debug, Clone, Default)]
struct TestOut {
    ok: bool,
    ech_offered: bool,
    ech_accepted: bool,
    detail: String,
}

fn run_test(ctx: &WizardCtx, op: i64, front: &Value, require_ech: bool) -> Result<TestOut> {
    let staged = Staged::write(ctx, op, front)?;
    let mut args = vec!["cdn-test".to_string(), "--record-file".into(), staged.arg()];
    if !require_ech {
        args.push("--require-ech=false".into());
    }
    let v = match ctx.cli.run_addon(AddonCliRequest::args(args), &mut |_| {}) {
        Ok(out) => serde_json::from_slice::<Value>(&out).unwrap_or(Value::Null),
        Err(BridgeError::SubprocessFailed { rc: 4, stderr }) => {
            json_in(&stderr).unwrap_or_else(|| serde_json::json!({"ok": false, "detail": stderr.trim()}))
        }
        Err(e) => return Err(cli_err("Cloudflare test", e)),
    };
    Ok(TestOut {
        ok: v.get("ok").and_then(Value::as_bool).unwrap_or(false),
        ech_offered: v.get("ech_offered").and_then(Value::as_bool).unwrap_or(false),
        ech_accepted: v.get("ech_accepted").and_then(Value::as_bool).unwrap_or(false),
        detail: crate::freshness::redact_detail(v.get("detail").and_then(Value::as_str).unwrap_or("")),
    })
}

/// ECH first. A hostname that publishes no ECH config is tested once
/// more without it: the way in then works but shows its name, which the
/// card says ("Name hidden: no").
fn test_front(ctx: &WizardCtx, op: i64, front: &Value, on_progress: &mut dyn FnMut(AddonProgress)) -> Result<TestOut> {
    on_progress(progress(op, "testing", "running", ""));
    let mut t = run_test(ctx, op, front, true)?;
    if !t.ok && !t.ech_offered {
        t = run_test(ctx, op, front, false)?;
    }
    on_progress(progress(
        op,
        "testing",
        if t.ok { "ok" } else { "failed" },
        if t.ok { String::new() } else { t.detail.clone() },
    ));
    Ok(t)
}

/// `cdn-door --action enable|disable`: the relay's `ws-cdn-in` inbound
/// and its box-firewall rules for Cloudflare's ranges, through the
/// relay's management (signing key on stdin; the hosting token opens
/// the management window).
fn run_door(ctx: &WizardCtx, op: i64, front: &Value, action: &str) -> Result<()> {
    let row = ctx.db.get(op)?;
    let helper_ip = require_helper_ip(ctx, op)?;
    let hz = hz_token(ctx, op).ok_or(WizardError::EmptyToken)?;
    let key = custody_get(ctx, &row.publisher_priv_keystore_alias)?;
    let staged = Staged::write(ctx, op, front)?;
    let rec: Value = serde_json::from_str(&row.operator_record_json)
        .map_err(|e| WizardError::Validation(format!("this relay's record is unreadable: {e}")))?;
    let staged_rec = Staged::write_named(ctx, op, "cdn.operator", &rec)?;
    let req = AddonCliRequest {
        args: vec![
            "cdn-door".into(),
            "--record-file".into(),
            staged.arg(),
            "--operator-record".into(),
            staged_rec.arg(),
            "--action".into(),
            action.into(),
            "--priv-key".into(),
            "-".into(),
            "--helper-ip".into(),
            helper_ip,
        ],
        secret_files: vec![("--token-file", hz.as_str())],
        stdin: key.as_slice(),
        progress: false,
    };
    ctx.cli
        .run_addon(req, &mut |_| {})
        .map(|_| ())
        .map_err(|e| cli_err("Cloudflare door on the relay", e))
}

/// `cdn-remove`. Returns the failed steps (empty = complete) and what
/// the publisher must still do by hand.
fn run_remove(ctx: &WizardCtx, op: i64, front: &Value, token: &str) -> Result<Vec<String>> {
    let hz = hz_token(ctx, op);
    let staged = Staged::write(ctx, op, front)?;
    let mut secret_files = vec![("--token-file", token)];
    if let Some(h) = hz.as_ref() {
        secret_files.push(("--hetzner-token-file", h.as_str()));
    }
    let req = AddonCliRequest {
        args: vec!["cdn-remove".into(), "--record-file".into(), staged.arg()],
        secret_files,
        stdin: &[],
        progress: false,
    };
    let v = match ctx.cli.run_addon(req, &mut |_| {}) {
        Ok(out) => serde_json::from_slice::<Value>(&out).unwrap_or(Value::Null),
        Err(BridgeError::SubprocessFailed { rc: 4, stderr }) => match json_in(&stderr) {
            Some(v) => v,
            None => return Ok(vec![crate::freshness::redact_detail(stderr.trim())]),
        },
        Err(e) => return Err(cli_err("Cloudflare removal", e)),
    };
    let failed = v
        .get("steps")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter(|s| s.get("state").and_then(Value::as_str) == Some("failed"))
                .map(|s| {
                    let name = s.get("name").and_then(Value::as_str).unwrap_or("");
                    let detail = s.get("detail").and_then(Value::as_str).unwrap_or("");
                    crate::freshness::redact_detail(&format!("{name}: {detail}"))
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(failed)
}

/// Give back what a failed build made. Ok: nothing is left and the row
/// is forgotten. Err(E_CDN_LEFT_BEHIND): the row stays for [`remove`].
fn roll_back(
    ctx: &WizardCtx,
    op: i64,
    row_id: i64,
    front: &Value,
    door_on: bool,
    token: &str,
    cause: WizardError,
    on_progress: &mut dyn FnMut(AddonProgress),
) -> WizardError {
    on_progress(progress(op, "rolling_back", "running", ""));
    if door_on {
        let _ = run_door(ctx, op, front, "disable");
    }
    match run_remove(ctx, op, front, token) {
        Ok(left) if left.is_empty() => {
            let _ = addons::forget(ctx, row_id);
            on_progress(progress(op, "rolling_back", "ok", ""));
            cause
        }
        Ok(left) => {
            on_progress(progress(op, "rolling_back", "failed", left.join("; ")));
            coded(
                E_CDN_LEFT_BEHIND,
                format!("{cause} — and some of it could not be taken down ({}); remove it to try again", left.join("; ")),
            )
        }
        Err(e) => {
            on_progress(progress(op, "rolling_back", "failed", ""));
            coded(
                E_CDN_LEFT_BEHIND,
                format!("{cause} — and it could not be taken down ({e}); remove it to try again"),
            )
        }
    }
}

// ---------------------------------------------------------------------
// The commands
// ---------------------------------------------------------------------

pub fn set_token(
    ctx: &WizardCtx,
    mut input: CdnTokenInput,
    on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<CdnTokenCheck> {
    let op = input.operator_id;
    let token = Zeroizing::new(std::mem::take(&mut input.token).trim().to_string());
    if token.is_empty() {
        return Err(WizardError::EmptyToken);
    }
    let _ = ctx.db.get(op)?;
    let mut check = check_token(ctx, op, &token, input.zone.trim(), on_progress)?;
    if check.verdict == "ok" {
        custody_put(ctx, &cloudflare_alias(op), token.as_bytes())?;
        check.stored = true;
        on_progress(progress(op, "token", "ok", ""));
    } else {
        on_progress(progress(op, "token", "failed", check.verdict.clone()));
    }
    Ok(check)
}

/// The Accounts page: the same check, no relay. Kept only when the key
/// sees exactly one zone (`too_broad` otherwise), so every relay knows
/// which zone to use without asking. Progress is on relay id 0.
pub fn connect(
    ctx: &WizardCtx,
    mut input: CdnConnectInput,
    on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<CdnTokenCheck> {
    let token = Zeroizing::new(std::mem::take(&mut input.token).trim().to_string());
    if token.is_empty() {
        return Err(WizardError::EmptyToken);
    }
    let mut check = check_token(ctx, 0, &token, "", on_progress)?;
    if check.verdict == "ok" && check.zones.len() > 1 {
        check.verdict = "too_broad".into();
    }
    if check.verdict == "ok" {
        custody_put(ctx, ACCOUNT_ALIAS, token.as_bytes())?;
        custody_put(ctx, ACCOUNT_ZONE_ALIAS, check.zones[0].as_bytes())?;
        check.stored = true;
        on_progress(progress(0, "token", "ok", ""));
    } else {
        on_progress(progress(0, "token", "failed", check.verdict.clone()));
    }
    Ok(check)
}

/// Whether an account key is kept, and its zone. Local, no network.
pub fn account(ctx: &WizardCtx) -> Result<CdnAccount> {
    if kept(ctx, ACCOUNT_ALIAS)?.is_none() {
        return Ok(CdnAccount::default());
    }
    let zone = kept(ctx, ACCOUNT_ZONE_ALIAS)?.map(|z| z.trim().to_string()).unwrap_or_default();
    Ok(CdnAccount { connected: true, zone })
}

/// Forget the account key. Relays that took a copy keep theirs, so a
/// way in that is on stays removable.
pub fn disconnect(ctx: &WizardCtx) -> Result<()> {
    for a in [ACCOUNT_ALIAS, ACCOUNT_ZONE_ALIAS] {
        let _ = ctx.custody.forget(a);
    }
    Ok(())
}

/// `cdn-token-check` on a token: what it sees and whether it is exactly
/// what Daal needs. Stores nothing.
fn check_token(
    ctx: &WizardCtx,
    op: i64,
    token: &str,
    zone: &str,
    on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<CdnTokenCheck> {
    on_progress(progress(op, "token", "running", ""));
    let mut args = vec!["cdn-token-check".to_string()];
    if !zone.is_empty() {
        args.extend(["--zone".to_string(), zone.to_string()]);
    }
    let req = AddonCliRequest {
        args,
        secret_files: vec![("--token-file", token)],
        stdin: &[],
        progress: false,
    };
    let v = match ctx.cli.run_addon(req, &mut |_| {}) {
        Ok(out) => serde_json::from_slice::<Value>(&out).map_err(|e| {
            WizardError::Subprocess(format!("cdn-token-check: unreadable answer: {e}"))
        })?,
        Err(BridgeError::SubprocessFailed { rc: 4, stderr }) => {
            json_in(&stderr).unwrap_or_else(|| serde_json::json!({"verdict": "refused"}))
        }
        Err(e) => {
            on_progress(progress(op, "token", "failed", ""));
            return Err(cli_err("Cloudflare key check", e));
        }
    };
    let zones: Vec<String> = v
        .get("zones")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|z| z.get("name").and_then(Value::as_str).or_else(|| z.as_str()))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let mut check = CdnTokenCheck {
        verdict: v
            .get("verdict")
            .and_then(Value::as_str)
            .unwrap_or("refused")
            .to_string(),
        zones,
        stored: false,
        missing: str_list(&v, "missing"),
        extra: str_list(&v, "extra"),
    };
    if check.verdict == "ok" && check.zones.is_empty() {
        check.verdict = "no_zone".into();
    }
    Ok(check)
}

pub fn build(
    ctx: &WizardCtx,
    input: CdnBuildInput,
    on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<AddonRow> {
    let op = input.operator_id;
    let zone = input.zone.trim().trim_end_matches('.').to_ascii_lowercase();
    if zone.is_empty() || !zone.contains('.') {
        return Err(WizardError::Validation("pick the Cloudflare zone to use".into()));
    }
    let (prior_json, rec) = record(ctx, op)?;
    match rec.get("provider").and_then(Value::as_str).unwrap_or("") {
        "hetzner" => {}
        other => {
            return Err(coded(
                E_NOT_SUPPORTED,
                format!("a way in through Cloudflare is only available on Hetzner (this relay is on {other:?})"),
            ))
        }
    }
    let origin_ip = rec.get("public_ip").and_then(Value::as_str).unwrap_or("").to_string();
    if origin_ip.is_empty() {
        return Err(WizardError::Validation("this relay has no address yet".into()));
    }
    let token = cf_token(ctx, op)?;
    let hz = hz_token(ctx, op).ok_or(WizardError::EmptyToken)?;

    // A ready one is done; one being removed must finish first; a
    // `building` row from a run that stopped is cleaned and redone.
    if let Some(r) = live_row(ctx, op)? {
        match r.state {
            AddonState::Ready if rec.get(RECORD_MEMBER).is_some() => return Ok(r),
            AddonState::Removing => {
                return Err(WizardError::Validation(
                    "this way in is being removed; finish removing it first".into(),
                ))
            }
            _ => {
                if let Some(front) = front_of(&r) {
                    let left = run_remove(ctx, op, &front, token.as_str())?;
                    if !left.is_empty() {
                        return Err(coded(
                            E_CDN_LEFT_BEHIND,
                            format!("an earlier setup could not be taken down ({})", left.join("; ")),
                        ));
                    }
                }
                addons::forget(ctx, r.id)?;
            }
        }
    }
    let row_id = addons::insert(
        ctx,
        &NewAddon {
            operator_id: op,
            kind: Some(AddonKind::Cdn),
            state: Some(AddonState::Building),
            detail: Some(serde_json::json!({ "zone": zone })),
            ..Default::default()
        },
    )?;

    // 1. Cloudflare (certificate, origin pull, zone settings, DNS
    //    record, origin rule) and the relay firewall. The helper takes
    //    its own half-made Cloudflare side down when the firewall fails.
    let out_dir = ctx.staging_dir.join("cdn").join(op.to_string());
    if let Err(e) = std::fs::create_dir_all(&out_dir) {
        let _ = addons::forget(ctx, row_id);
        return Err(WizardError::Cdn(format!("create CDN staging dir: {e}")));
    }
    let mut args = vec![
        "cdn-provision".to_string(),
        "--zone".into(),
        zone.clone(),
        "--origin-ip".into(),
        origin_ip,
        "--out-dir".into(),
        out_dir.to_string_lossy().to_string(),
        "--firewall-id".into(),
        firewall_of(&rec),
    ];
    if let Some(v6) = rec.get("public_ipv6").and_then(Value::as_str).filter(|s| !s.is_empty()) {
        args.extend(["--origin-ipv6".to_string(), v6.to_string()]);
    }
    let req = AddonCliRequest {
        args,
        secret_files: vec![("--cf-token-file", token.as_str()), ("--token-file", hz.as_str())],
        stdin: &[],
        progress: true,
    };
    on_progress(progress(op, "cloudflare", "running", ""));
    let front: Value = match ctx
        .cli
        .run_addon(req, &mut |ev| translate(op, &ev, on_progress))
        .map_err(|e| cli_err("way in through Cloudflare", e))
        .and_then(|out| {
            serde_json::from_slice::<Value>(&out)
                .map_err(|e| WizardError::Subprocess(format!("cdn-provision: unreadable answer: {e}")))
        }) {
        Ok(f) if f.get("hostname").and_then(Value::as_str).is_some() => f,
        Ok(_) => {
            let _ = addons::forget(ctx, row_id);
            return Err(WizardError::Subprocess("cdn-provision: the answer names no hostname".into()));
        }
        Err(e) => {
            on_progress(progress(op, "cloudflare", "failed", ""));
            let _ = addons::forget(ctx, row_id);
            return Err(e);
        }
    };
    on_progress(progress(op, "cloudflare", "ok", ""));
    on_progress(progress(op, "firewall", "ok", ""));
    set_detail_field(ctx, row_id, "front", front.clone())?;
    addons::set_provider_ids(ctx, row_id, &provider_ids(&front))?;

    // 2. The door on the relay.
    on_progress(progress(op, "door", "running", ""));
    if let Err(e) = run_door(ctx, op, &front, "enable") {
        on_progress(progress(op, "door", "failed", ""));
        let cause = match &e {
            WizardError::Coded(c) if c.starts_with(E_RELAY_TOO_OLD) => coded(
                E_CDN_NEEDS_REBUILD,
                "this relay was built before the Cloudflare door existed; rebuild it to add this way in",
            ),
            _ => e,
        };
        return Err(roll_back(ctx, op, row_id, &front, false, token.as_str(), cause, on_progress));
    }
    on_progress(progress(op, "door", "ok", ""));

    // 3. A real handshake through the front, from this phone.
    let t = match test_front(ctx, op, &front, on_progress) {
        Ok(t) => t,
        Err(e) => return Err(roll_back(ctx, op, row_id, &front, true, token.as_str(), e, on_progress)),
    };
    if !t.ok {
        let cause = coded(E_CDN_TEST_FAILED, if t.detail.is_empty() { "no answer".into() } else { t.detail });
        return Err(roll_back(ctx, op, row_id, &front, true, token.as_str(), cause, on_progress));
    }

    // 4. The signature, with the route in it.
    let mut member = front.clone();
    member["plain_fallback"] = Value::Bool(false);
    ctx.db.update_record_json(op, &with_member(&rec, Some(member)))?;
    on_progress(progress(op, "signing", "running", ""));
    let resigned = match resign_and_republish(ctx, op, Freshness::AllowCached, &mut |_| {}) {
        Ok(r) => r,
        Err(e) => {
            on_progress(progress(op, "signing", "failed", ""));
            ctx.db.update_record_json(op, &prior_json)?;
            return Err(roll_back(ctx, op, row_id, &front, true, token.as_str(), e, on_progress));
        }
    };
    on_progress(progress(op, "signing", "ok", ""));
    let now = (ctx.clock)();
    let name_hidden = t.ech_accepted;
    addons::set_detail(
        ctx,
        row_id,
        &serde_json::json!({
            "zone": zone,
            "hostname": front.get("hostname").cloned().unwrap_or(Value::Null),
            "front": front,
            "plain_fallback": false,
            "name_hidden": name_hidden,
            "last_test_at_unix": now,
            "last_test_ok": true,
            "refresh_note_published": resigned.refresh_note_published,
            "refresh_note_problem": resigned.refresh_note_problem,
        }),
    )?;
    addons::set_state(ctx, row_id, AddonState::Ready)?;
    addons::get(ctx, row_id)
}

pub fn posture(
    ctx: &WizardCtx,
    input: CdnPostureInput,
    on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<CdnPosture> {
    let op = input.operator_id;
    let row = live_row(ctx, op)?
        .ok_or_else(|| WizardError::Validation("this relay has no way in through Cloudflare".into()))?;
    let d = row.detail.clone();
    let front = front_of(&row)
        .ok_or_else(|| WizardError::Validation("this way in was never finished".into()))?;
    let plain = d.get("plain_fallback").and_then(Value::as_bool).unwrap_or(false);
    let mut out = CdnPosture {
        name_hidden: d.get("name_hidden").and_then(Value::as_bool),
        door_closed_to_others: None,
        last_test_at_unix: d.get("last_test_at_unix").and_then(Value::as_i64).unwrap_or(0),
        last_test_ok: d.get("last_test_ok").and_then(Value::as_bool),
        renews_at_unix: 0,
        needs_rebuild: d.get("needs_rebuild").and_then(Value::as_bool).unwrap_or(false),
        hostname: front.get("hostname").and_then(Value::as_str).unwrap_or("").to_string(),
        zone: d.get("zone").and_then(Value::as_str).unwrap_or("").to_string(),
        plain_fallback: plain,
        notes: String::new(),
    };

    on_progress(progress(op, "posture", "running", ""));
    let token = cf_token(ctx, op)?;
    let hz = hz_token(ctx, op);
    let staged = Staged::write(ctx, op, &front)?;
    let mut secret_files = vec![("--token-file", token.as_str())];
    if let Some(h) = hz.as_ref() {
        secret_files.push(("--hetzner-token-file", h.as_str()));
    }
    let req = AddonCliRequest {
        args: vec!["cdn-posture".into(), "--record-file".into(), staged.arg()],
        secret_files,
        stdin: &[],
        progress: false,
    };
    let rep: Value = match ctx.cli.run_addon(req, &mut |_| {}) {
        Ok(b) => serde_json::from_slice(&b).unwrap_or(Value::Null),
        Err(e) => {
            on_progress(progress(op, "posture", "failed", ""));
            return Err(cli_err("Cloudflare check", e));
        }
    };
    drop(staged);
    let b = |k: &str| rep.get(k).and_then(Value::as_bool).unwrap_or(false);
    if rep.get("firewall_checked").and_then(Value::as_bool) == Some(true) {
        out.door_closed_to_others = Some(b("only_cloudflare"));
    }
    let zone_ech = b("name_hidden");
    out.notes = crate::freshness::redact_detail(rep.get("notes").and_then(Value::as_str).unwrap_or(""));
    on_progress(progress(op, "posture", "ok", ""));

    if input.test {
        let t = test_front(ctx, op, &front, on_progress)?;
        out.last_test_at_unix = (ctx.clock)();
        out.last_test_ok = Some(t.ok);
        out.name_hidden = Some(zone_ech && t.ok && t.ech_accepted);
        if !t.ok && !t.detail.is_empty() {
            out.notes = if out.notes.is_empty() { t.detail } else { format!("{}; {}", out.notes, t.detail) };
        }
    } else if !zone_ech {
        out.name_hidden = Some(false);
    }

    let mut nd = row.detail.clone();
    if let Some(m) = nd.as_object_mut() {
        m.insert("last_test_at_unix".into(), out.last_test_at_unix.into());
        m.insert("last_test_ok".into(), out.last_test_ok.map(Value::Bool).unwrap_or(Value::Null));
        m.insert("name_hidden".into(), out.name_hidden.map(Value::Bool).unwrap_or(Value::Null));
        m.insert(
            "door_closed_to_others".into(),
            out.door_closed_to_others.map(Value::Bool).unwrap_or(Value::Null),
        );
    }
    addons::set_detail(ctx, row.id, &nd)?;
    Ok(out)
}

pub fn set_plain_fallback(
    ctx: &WizardCtx,
    input: CdnPlainFallbackInput,
    on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<AddonRow> {
    let op = input.operator_id;
    let row = match live_row(ctx, op)? {
        Some(r) if r.state == AddonState::Ready => r,
        _ => {
            return Err(WizardError::Validation(
                "this relay has no way in through Cloudflare that is on".into(),
            ))
        }
    };
    let (prior_json, rec) = record(ctx, op)?;
    let mut member = match rec.get(RECORD_MEMBER) {
        Some(m) if m.is_object() => m.clone(),
        _ => {
            return Err(WizardError::Validation(
                "this relay's record no longer names its way in through Cloudflare".into(),
            ))
        }
    };
    if member.get("plain_fallback").and_then(Value::as_bool).unwrap_or(false) == input.allow {
        return Ok(row);
    }
    member["plain_fallback"] = Value::Bool(input.allow);
    ctx.db.update_record_json(op, &with_member(&rec, Some(member)))?;
    on_progress(progress(op, "signing", "running", ""));
    if let Err(e) = resign_and_republish(ctx, op, Freshness::AllowCached, &mut |_| {}) {
        on_progress(progress(op, "signing", "failed", ""));
        ctx.db.update_record_json(op, &prior_json)?;
        return Err(e);
    }
    on_progress(progress(op, "signing", "ok", ""));
    set_detail_field(ctx, row.id, "plain_fallback", Value::Bool(input.allow))?;
    addons::get(ctx, row.id)
}

/// Called by `addons::remove`. Order (plan §2.6): sign again without the
/// route and publish; turn the door off; delete the DNS record and origin
/// rule, revoke the origin certificate, close the firewall rule
/// (`cdn-remove`); forget the token; tell the publisher to delete the
/// token in Cloudflare and that the domain keeps billing until cancelled.
pub fn remove(
    ctx: &WizardCtx,
    row: &AddonRow,
    on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<AddonRemoveReport> {
    let op = row.operator_id;
    let mut report = AddonRemoveReport {
        addon_id: row.id,
        ..Default::default()
    };
    let front = match front_of(row) {
        Some(f) => f,
        None => {
            // Nothing was ever created.
            addons::forget(ctx, row.id)?;
            report.removed = true;
            return Ok(report);
        }
    };

    // 1. A pack without the route, signed first.
    let (json, rec) = record(ctx, op)?;
    if rec.get(RECORD_MEMBER).is_some() {
        let prior_state = row.state;
        ctx.db.update_record_json(op, &with_member(&rec, None))?;
        addons::set_state(ctx, row.id, AddonState::Removing)?;
        on_progress(progress(op, "signing", "running", ""));
        match resign_and_republish(ctx, op, Freshness::AllowCached, &mut |_| {}) {
            Err(e) => {
                on_progress(progress(op, "signing", "failed", ""));
                ctx.db.update_record_json(op, &json)?;
                addons::set_state(ctx, row.id, prior_state)?;
                return Err(e);
            }
            Ok(r) => {
                on_progress(progress(op, "signing", "ok", ""));
                if r.prior_pack_had_refresh_addresses && !r.refresh_note_published {
                    // Not a reason to keep it: once the name is gone the
                    // route simply stops answering for anyone still
                    // holding it. Said, not hidden.
                    report.warnings.push("republish_failed".into());
                }
            }
        }
    } else {
        addons::set_state(ctx, row.id, AddonState::Removing)?;
    }

    // 2. The door on the relay.
    on_progress(progress(op, "door", "running", ""));
    match run_door(ctx, op, &front, "disable") {
        Ok(()) => on_progress(progress(op, "door", "ok", "")),
        Err(_) => {
            on_progress(progress(op, "door", "failed", ""));
            report.warnings.push("relay_door_left_on".into());
        }
    }

    // 3. Cloudflare and the firewall.
    on_progress(progress(op, "cloudflare", "running", ""));
    let token = match cf_token(ctx, op) {
        Ok(t) => t,
        Err(_) => {
            on_progress(progress(op, "cloudflare", "failed", ""));
            report.warnings.push("no_cloudflare_key".into());
            report.still_billing.push("domain".into());
            return Ok(report);
        }
    };
    let left = run_remove(ctx, op, &front, token.as_str())?;
    if !left.is_empty() {
        on_progress(progress(op, "cloudflare", "failed", left.join("; ")));
        report.warnings.extend(left);
        return Ok(report);
    }
    on_progress(progress(op, "cloudflare", "ok", ""));

    // 4. Forget the key and the row.
    let alias = cloudflare_alias(op);
    let _ = ctx.custody.forget(&alias);
    let _ = ctx.keystore.forget(&alias);
    addons::forget(ctx, row.id)?;
    report.removed = true;
    report.by_hand = vec!["delete_cloudflare_token".into(), "cancel_domain".into()];
    Ok(report)
}

/// Called by `addons::before_relay_destroy`: the Cloudflare cleanup goes
/// before the server. The door and the firewall go with the server.
pub fn on_relay_delete(ctx: &WizardCtx, row: &AddonRow) -> AddonOutcome {
    let front = match front_of(row) {
        Some(f) => f,
        None => return AddonOutcome::removed(row),
    };
    let failed = |keeps_relay: bool, code: &str, error: String| AddonOutcome {
        addon_id: row.id,
        kind: row.kind,
        removed: false,
        keeps_relay,
        code: code.into(),
        error,
    };
    let token = match cf_token(ctx, row.operator_id) {
        Ok(t) => t,
        // Nothing on this phone can take it down: keeping the relay
        // would not change that. Left, and said.
        Err(_) => return failed(false, "left", "no Cloudflare key on this phone".into()),
    };
    match run_remove(ctx, row.operator_id, &front, token.as_str()) {
        Ok(left) if left.is_empty() => AddonOutcome::removed(row),
        Ok(left) => failed(true, "failed", left.join("; ")),
        Err(e) => failed(true, "failed", e.to_string()),
    }
}

#[cfg(test)]
#[path = "addon_cdn_tests.rs"]
mod tests;
