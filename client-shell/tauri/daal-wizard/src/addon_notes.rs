//! The update notes (docs/update-ladder-v2.md §3, §4.1, §4.3;
//! specs/update-ladder-v2.md §4): the GitHub account, and the two
//! per-relay switches that write sealed notes where a person's phone
//! looks when every ordinary refresh address is blocked.
//!
//! # The GitHub account (Accounts page)
//!
//! [`github_connect`] checks a pasted key with `note-gittag check` (one
//! call to GitHub: who the key is, and whether it can make a public
//! repository and write to it) and keeps it under
//! [`GITHUB_ACCOUNT_ALIAS`], with the account's name (not a secret)
//! under [`GITHUB_LOGIN_ALIAS`] and what the page says about the key
//! (its kind, what it can do beyond what Daal needs, when it stops
//! working; no secret) under [`GITHUB_INFO_ALIAS`]. The publisher backup
//! carries the three; panic wipe erases them. [`github_disconnect`]
//! forgets them; relays that turned the switch on keep their own copy.
//!
//! # The switches
//!
//! * **Updates through GitHub** ([`gittag_on`], kind `gittag`): one
//!   public repository per relay under the account, named with random
//!   letters (nothing of the relay in it). Every write is one
//!   `note-gittag publish`: the repository's two files carry the full
//!   note (the signed freshness document and pack, sealed) or filler of
//!   the same size, and a new tag carries the micro note (the revealed
//!   standby key, sealed) or filler.
//! * **Updates through DNS** ([`dnsnote_on`], kind `dnsnote`): six A
//!   records in the Cloudflare account's zone, written by `note-dns
//!   publish`. They carry only the micro note, and only for named people
//!   (the helper refuses the Everyone audience).
//!
//! A switch's row is written `building` before anything is created and
//! becomes `ready` once the first write went through; a failed first
//! write leaves it `building`, and turning it on again is the retry.
//! Once a switch is `ready`, every person's file made from then on
//! carries the carriers member ([`carriers_member`], through
//! `addon_standby::people_secret_for_file`), so the phone knows where to
//! look. Files made before do not: those people need a new file.
//!
//! # When notes are written
//!
//! [`write_relay`] writes every switch of a relay. It runs
//!
//! * after every freshness publish that signed a document
//!   (`freshness::publish`): the full note carries that document;
//! * after a switch to the standby (`addon_standby::promote`): the micro
//!   note reveals the key, the full note carries the new document;
//! * from [`tick`], when the app opens: a switch whose last write is
//!   from an earlier epoch (or failed) is written again, so filler moves
//!   with the epoch and a reveal stays readable (a reader tries this
//!   epoch and the one before).
//!
//! A failed write never fails what called it. It is kept on the row
//! (`detail.last_error`, `last_try_at_unix`) and the switch says so.
//!
//! # Secrets
//!
//! The GitHub key, the Cloudflare key and the update secret reach the
//! helper on stdin only (`--creds-file -`), never argv, a file name, a
//! log line or a progress event. Nothing here logs the repository, the
//! zone, a note name or an address; the helpers print none of them.
//! Only the current people generation is ever written: a person removed
//! while holding an older one cannot read what is written after.

use std::path::PathBuf;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::addons::{
    self, AddonKind, AddonOutcome, AddonProgress, AddonRemoveReport, AddonRow, AddonState, NewAddon,
};
use crate::cli_bridge::{verb_unknown, AddonCliRequest, BridgeError};
use crate::commands::{
    coded, custody_get_string, custody_has, custody_put, Result, WizardCtx, WizardError,
    E_DEPLOY_TOO_OLD,
};

/// The GitHub account's key, kept apart from any relay.
pub const GITHUB_ACCOUNT_ALIAS: &str = "daal.github.account.token";
/// The account's name on GitHub (not a secret; kept beside the key).
pub const GITHUB_LOGIN_ALIAS: &str = "daal.github.account.login";
/// What the page says about the key: `{"token_kind","extra","expires_at"}`
/// (not a secret).
pub const GITHUB_INFO_ALIAS: &str = "daal.github.account.info";
/// What the publisher backup carries and panic wipe erases.
pub const GITHUB_ACCOUNT_ALIASES: [&str; 3] =
    [GITHUB_ACCOUNT_ALIAS, GITHUB_LOGIN_ALIAS, GITHUB_INFO_ALIAS];

/// A relay's GitHub switch was turned on with no GitHub account. Nothing
/// was changed; the UI opens Accounts → GitHub.
pub const E_GITHUB_NO_ACCOUNT: &str = "E_GITHUB_NO_ACCOUNT";
/// GitHub refused a write: a permission the key lacks, a repository
/// that is not Daal's, another account. The tail starts with the
/// helper's code word (`missing_permission`, `repo_not_ours`, …).
pub const E_GITTAG_REFUSED: &str = "E_GITTAG_REFUSED";
/// GitHub could not be reached, answered with an error, or asked Daal to
/// wait (`rate_limited`). Trying again later is the fix.
pub const E_GITTAG_UNREACHABLE: &str = "E_GITTAG_UNREACHABLE";
/// Cloudflare refused the DNS write (`name_taken`, `zone_not_found`,
/// `not_authorised`).
pub const E_DNSNOTE_REFUSED: &str = "E_DNSNOTE_REFUSED";
/// Cloudflare could not be reached or answered with an error.
pub const E_DNSNOTE_UNREACHABLE: &str = "E_DNSNOTE_UNREACHABLE";
/// The relay has no signed pack yet, so it has no update secret to seal
/// notes with. The switch can be turned on once the relay is built.
pub const E_NOTES_NO_PACK: &str = "E_NOTES_NO_PACK";

/// Seconds in one note epoch (bundle.NoteEpochWeek): both labels are
/// weekly.
pub const EPOCH_SECONDS: i64 = 7 * 24 * 3600;

/// A failed write is tried again by [`tick`] once this much has passed.
pub const RETRY_AFTER_SECONDS: i64 = 10 * 60;

/// The slot a container is built with here. The gittag helper replaces
/// it with the note's own name (16 symbols, so the size does not move).
const SLOT_PLACEHOLDER: &str = "aaaaaaaaaaaaaaaa";
/// bundle.MaxFullNoteContainer.
const MAX_CONTAINER: usize = 65532;

// ---------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------

/// `wizard_github_connect`. No `Debug`: the token must never reach a
/// log line.
#[derive(Clone, Deserialize)]
pub struct GithubConnectInput {
    pub token: String,
}

/// What `note-gittag check` said about a key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct GithubCheck {
    /// `ok` | `ok_broad` (works and can do more than Daal needs; kept) |
    /// `invalid` | `missing_permission` (`missing` names what) |
    /// `owner_mismatch` | `rate_limited` (GitHub asked to wait; try
    /// again later). Only `ok` and `ok_broad` are kept.
    pub verdict: String,
    pub stored: bool,
    /// The account the key belongs to.
    #[serde(default)]
    pub login: String,
    /// `classic` | `fine_grained` | `other`.
    #[serde(default)]
    pub token_kind: String,
    #[serde(default)]
    pub missing: Vec<String>,
    #[serde(default)]
    pub extra: Vec<String>,
    /// What one read cannot show (a fine-grained key's permissions); the
    /// first write names the one GitHub refuses.
    #[serde(default)]
    pub unproven: Vec<String>,
    /// RFC 3339, when GitHub says the key stops working; '' when never.
    #[serde(default)]
    pub expires_at: String,
    /// Seconds GitHub asked to wait (`rate_limited`).
    #[serde(default)]
    pub retry_after_s: i64,
}

impl GithubCheck {
    pub fn usable(&self) -> bool {
        matches!(self.verdict.as_str(), "ok" | "ok_broad")
    }
}

/// `wizard_github_account`: local, no network, no secret.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct GithubAccount {
    pub connected: bool,
    #[serde(default)]
    pub login: String,
    #[serde(default)]
    pub token_kind: String,
    /// What the kept key can do beyond what Daal needs.
    #[serde(default)]
    pub extra: Vec<String>,
    #[serde(default)]
    pub expires_at: String,
}

/// `wizard_addon_gittag_on` / `wizard_addon_dnsnote_on`.
#[derive(Debug, Clone, Deserialize)]
pub struct NotesOnInput {
    pub operator_id: i64,
}

/// `wizard_notes_tick`: what the app-open pass did.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct NotesTickReport {
    /// Switches written now.
    pub written: i64,
    /// Of those, how many failed (kept on the row; tried again later).
    pub failed: i64,
}

/// A switch's row detail. Public: nothing secret, nothing a censor would
/// not learn from the person's file. The UI reads `last_ok_at_unix`,
/// `last_try_at_unix`, `last_error` and `people_before`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct NotesDetail {
    /// gittag: the repository `github.com/<owner>/<repo>`.
    pub owner: String,
    pub repo: String,
    /// gittag: the highest tag sequence this repository holds.
    pub seq: u64,
    /// dnsnote: the zone the records are written in.
    pub zone: String,
    /// The epoch of the last write that went through.
    pub epoch: u64,
    pub last_ok_at_unix: i64,
    pub last_try_at_unix: i64,
    /// '' after a write that went through; else the helper's code word.
    pub last_error: String,
    /// The last write revealed the standby key (else filler).
    pub revealed: bool,
    /// The last gittag write carried a freshness document.
    pub carried_document: bool,
    /// Audiences written under (dnsnote: what removal takes down).
    pub audiences: Vec<String>,
    /// People on the relay when the switch was turned on: they need a
    /// new file to use it.
    pub people_before: i64,
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

fn progress(op: i64, kind: AddonKind, step: &str, state: &str, detail: &str) -> AddonProgress {
    AddonProgress {
        operator_id: op,
        kind,
        step: step.into(),
        state: state.into(),
        detail: detail.into(),
    }
}

fn kept(ctx: &WizardCtx, alias: &str) -> Result<Option<Zeroizing<String>>> {
    match custody_get_string(ctx, alias) {
        Ok(t) if !t.trim().is_empty() => Ok(Some(t)),
        Ok(_) => Ok(None),
        Err(WizardError::Coded(c)) if c.starts_with(crate::commands::E_SECRET_MISSING) => Ok(None),
        Err(e) => Err(e),
    }
}

fn str_list(v: &Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

fn s(v: &Value, key: &str) -> String {
    v.get(key).and_then(Value::as_str).unwrap_or("").to_string()
}

/// The first JSON object in a helper's failure text: the note verbs put
/// their `{"ok":false,"code":…}` there (`cli_bridge` keeps a note verb's
/// stdout on every failing exit).
fn json_in(text: &str) -> Option<Value> {
    let start = text.find('{')?;
    serde_json::Deserializer::from_str(&text[start..])
        .into_iter::<Value>()
        .next()?
        .ok()
        .filter(Value::is_object)
}

/// One note verb, its creds JSON on stdin. Ok: the success JSON. Err:
/// (exit status, the failure JSON or `{}`), or a bridge failure that is
/// not the verb's own answer.
fn run_note(
    ctx: &WizardCtx,
    verb: &str,
    sub: &str,
    creds: &Value,
) -> std::result::Result<Value, NoteFail> {
    let body = Zeroizing::new(serde_json::to_vec(creds).unwrap_or_default());
    let req = AddonCliRequest {
        args: vec![verb.to_string(), sub.to_string(), "--creds-file".into(), "-".into()],
        secret_files: Vec::new(),
        stdin: &body,
        progress: false,
    };
    match ctx.cli.run_addon(req, &mut |_| {}) {
        Ok(out) => serde_json::from_slice::<Value>(&out)
            .map_err(|_| NoteFail::Bridge(WizardError::Subprocess(format!("{verb}: unreadable answer")))),
        Err(e) if verb_unknown(&e) => Err(NoteFail::Bridge(coded(
            E_DEPLOY_TOO_OLD,
            format!("the setup helper bundled with this app has no {verb}"),
        ))),
        Err(BridgeError::SubprocessFailed { rc, stderr }) => {
            Err(NoteFail::Verb { rc, answer: json_in(&stderr).unwrap_or_else(|| json!({})) })
        }
        Err(e) => Err(NoteFail::Bridge(WizardError::Subprocess(crate::freshness::redact_detail(
            &e.to_string(),
        )))),
    }
}

enum NoteFail {
    /// The verb answered with a failure (its JSON, or `{}`).
    Verb { rc: i32, answer: Value },
    Bridge(WizardError),
}

impl NoteFail {
    /// The stable code word kept on the row.
    fn word(&self) -> String {
        match self {
            NoteFail::Verb { answer, rc } => {
                let c = s(answer, "code");
                if c.is_empty() {
                    format!("exit_{rc}")
                } else {
                    c
                }
            }
            NoteFail::Bridge(WizardError::Coded(c)) if c.starts_with(E_DEPLOY_TOO_OLD) => {
                "helper_too_old".into()
            }
            NoteFail::Bridge(_) => "helper".into(),
        }
    }
}

fn gittag_err(f: NoteFail) -> WizardError {
    match f {
        NoteFail::Bridge(e) => e,
        NoteFail::Verb { answer, .. } => {
            let code = s(&answer, "code");
            let missing = str_list(&answer, "missing").join(", ");
            let tail = if missing.is_empty() { code.clone() } else { format!("{code}: {missing}") };
            match code.as_str() {
                "invalid_token" | "missing_permission" | "repo_private" | "repo_archived"
                | "repo_not_ours" | "repo_unseen" | "other_account" | "bad_input" => {
                    coded(E_GITTAG_REFUSED, tail)
                }
                _ => coded(E_GITTAG_UNREACHABLE, if tail.is_empty() { "github".into() } else { tail }),
            }
        }
    }
}

fn dns_err(f: NoteFail) -> WizardError {
    match f {
        NoteFail::Bridge(e) => e,
        NoteFail::Verb { rc, answer } => {
            let code = s(&answer, "code");
            if rc == 4 || !code.is_empty() {
                coded(E_DNSNOTE_REFUSED, if code.is_empty() { "refused".into() } else { code })
            } else {
                coded(E_DNSNOTE_UNREACHABLE, format!("exit {rc}"))
            }
        }
    }
}

fn detail_of(row: &AddonRow) -> NotesDetail {
    serde_json::from_value(row.detail.clone()).unwrap_or_default()
}

fn save_detail(ctx: &WizardCtx, id: i64, d: &NotesDetail) -> Result<()> {
    addons::set_detail(ctx, id, &serde_json::to_value(d).unwrap_or_else(|_| json!({})))
}

fn row_for(ctx: &WizardCtx, op: i64, kind: AddonKind) -> Result<Option<AddonRow>> {
    Ok(addons::list(ctx, op)?.into_iter().find(|r| r.kind == kind))
}

fn people_now(ctx: &WizardCtx, op: i64) -> i64 {
    ctx.db
        .list_recipients(op)
        .map(|v| v.into_iter().filter(|r| r.revoked_at_unix == 0).count() as i64)
        .unwrap_or(0)
}

/// Twelve lowercase letters and digits: a repository name with nothing
/// of the relay, the publisher or Daal in it.
fn random_repo() -> String {
    const A: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut b = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut b);
    // The first symbol is a letter, so the name never reads as a number.
    b.iter()
        .enumerate()
        .map(|(i, x)| {
            let v = (*x as usize) % if i == 0 { 26 } else { 32 };
            A[v] as char
        })
        .collect()
}

fn epoch_at(now: i64) -> u64 {
    if now <= 0 {
        0
    } else {
        (now / EPOCH_SECONDS) as u64
    }
}

/// The people secret every write seals under, or `E_NOTES_NO_PACK`.
fn secret(ctx: &WizardCtx, op: i64) -> Result<(Zeroizing<String>, String)> {
    match crate::addon_standby::current_people_secret(ctx, op)? {
        Some((u, audience)) => Ok((Zeroizing::new(B64.encode(&u[..])), audience)),
        None => Err(coded(E_NOTES_NO_PACK, "this relay has no signed pack yet")),
    }
}

/// The revealed standby key, with its commitment: `(26 symbols, commit)`.
fn reveal(ctx: &WizardCtx, op: i64) -> Option<(String, String)> {
    let k = crate::addon_standby::revealed_key(ctx, op)?;
    Some((
        crate::addon_standby::key_symbols(&k),
        crate::addon_standby::standby_commit(&k),
    ))
}

// ---------------------------------------------------------------------
// The carriers member
// ---------------------------------------------------------------------

/// Kept once a relay's note switch has been on (not a secret; erased by
/// panic wipe): with every switch off again, the next file carries
/// `{"v":1}` so the phone forgets the repository and the zone.
pub fn notes_ever_on_alias(op: i64) -> String {
    format!("daal.notes.ever_on.{op}")
}

fn mark_ever_on(ctx: &WizardCtx, op: i64) {
    if !custody_has(ctx, &notes_ever_on_alias(op)) {
        let _ = custody_put(ctx, &notes_ever_on_alias(op), b"1");
    }
}

/// The carriers member a person's file made now carries: one entry per
/// switch that is on (`ready`). With none on: `{"v":1}` when a switch was
/// ever on for this relay (it clears what the phone holds; absent would
/// keep it), else None, so a relay that never had one makes exactly the
/// files it made before.
pub fn carriers_member(ctx: &WizardCtx, op: i64) -> Option<Value> {
    let rows = addons::list(ctx, op).ok()?;
    let mut m = serde_json::Map::new();
    m.insert("v".into(), json!(1));
    for r in rows.iter().filter(|r| r.state == AddonState::Ready) {
        let d = detail_of(r);
        match r.kind {
            AddonKind::Gittag if !d.owner.is_empty() && !d.repo.is_empty() => {
                m.insert("gittag".into(), json!({"owner": d.owner, "repo": d.repo}));
            }
            AddonKind::Dnsnote if !d.zone.is_empty() => {
                m.insert("dns".into(), json!({"zone": d.zone}));
            }
            _ => {}
        }
    }
    if m.len() == 1 && !custody_has(ctx, &notes_ever_on_alias(op)) {
        None
    } else {
        Some(Value::Object(m))
    }
}

/// Everyone on the relay holds a new file (refile said all done): no
/// switch's "people need a new file" line stands any more.
pub fn clear_people_before(ctx: &WizardCtx, op: i64) {
    let Ok(rows) = addons::list(ctx, op) else { return };
    for r in rows
        .iter()
        .filter(|r| matches!(r.kind, AddonKind::Gittag | AddonKind::Dnsnote))
    {
        let mut d = detail_of(r);
        if d.people_before != 0 {
            d.people_before = 0;
            let _ = save_detail(ctx, r.id, &d);
        }
    }
}

// ---------------------------------------------------------------------
// The GitHub account
// ---------------------------------------------------------------------

pub fn github_connect(
    ctx: &WizardCtx,
    mut input: GithubConnectInput,
    on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<GithubCheck> {
    let token = Zeroizing::new(std::mem::take(&mut input.token).trim().to_string());
    if token.is_empty() {
        return Err(WizardError::EmptyToken);
    }
    on_progress(progress(0, AddonKind::Gittag, "token", "running", ""));
    let creds = json!({ "token": token.as_str() });
    let v = match run_note(ctx, "note-gittag", "check", &creds) {
        Ok(v) => v,
        Err(NoteFail::Verb { answer, rc }) => {
            let code = s(&answer, "code");
            match code.as_str() {
                "invalid_token" | "bad_input" => json!({"verdict": "invalid"}),
                "missing_permission" => {
                    json!({"verdict": "missing_permission", "missing": answer.get("missing").cloned().unwrap_or(json!([]))})
                }
                "rate_limited" => json!({
                    "verdict": "rate_limited",
                    "retry_after_s": answer.get("retry_after_s").cloned().unwrap_or(json!(0))
                }),
                _ => {
                    on_progress(progress(0, AddonKind::Gittag, "token", "failed", ""));
                    return Err(coded(
                        E_GITTAG_UNREACHABLE,
                        if code.is_empty() { format!("exit {rc}") } else { code },
                    ));
                }
            }
        }
        Err(NoteFail::Bridge(e)) => {
            on_progress(progress(0, AddonKind::Gittag, "token", "failed", ""));
            return Err(e);
        }
    };
    let mut check = GithubCheck {
        verdict: {
            let v = s(&v, "verdict");
            if v.is_empty() {
                "invalid".into()
            } else {
                v
            }
        },
        stored: false,
        login: s(&v, "login"),
        token_kind: s(&v, "token_kind"),
        missing: str_list(&v, "missing"),
        extra: str_list(&v, "extra"),
        unproven: str_list(&v, "unproven"),
        expires_at: s(&v, "expires_at"),
        retry_after_s: v.get("retry_after_s").and_then(Value::as_i64).unwrap_or(0),
    };
    if check.usable() && !owner_ok(&check.login) {
        // A key GitHub accepted for a name Daal cannot write a carriers
        // member with (an organisation, a bot): refused, never kept.
        check.verdict = "invalid".into();
    }
    if check.usable() {
        custody_put(ctx, GITHUB_ACCOUNT_ALIAS, token.as_bytes())?;
        custody_put(ctx, GITHUB_LOGIN_ALIAS, check.login.as_bytes())?;
        let info = json!({
            "token_kind": check.token_kind,
            "extra": check.extra,
            "expires_at": check.expires_at,
        });
        custody_put(ctx, GITHUB_INFO_ALIAS, info.to_string().as_bytes())?;
        check.stored = true;
        on_progress(progress(0, AddonKind::Gittag, "token", "ok", ""));
    } else {
        on_progress(progress(0, AddonKind::Gittag, "token", "failed", &check.verdict));
    }
    Ok(check)
}

/// bundle.GitOwnerOK: 1–39 of letters, digits and single inner hyphens.
pub(crate) fn owner_ok(o: &str) -> bool {
    let b = o.as_bytes();
    !b.is_empty()
        && b.len() <= 39
        && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
        && b[0] != b'-'
        && b[b.len() - 1] != b'-'
        && !o.contains("--")
}

pub fn github_account(ctx: &WizardCtx) -> Result<GithubAccount> {
    if !custody_has(ctx, GITHUB_ACCOUNT_ALIAS) {
        return Ok(GithubAccount::default());
    }
    let login = kept(ctx, GITHUB_LOGIN_ALIAS)?.map(|l| l.trim().to_string()).unwrap_or_default();
    let info: Value = kept(ctx, GITHUB_INFO_ALIAS)?
        .and_then(|i| serde_json::from_str(&i).ok())
        .unwrap_or_else(|| json!({}));
    Ok(GithubAccount {
        connected: true,
        login,
        token_kind: s(&info, "token_kind"),
        extra: str_list(&info, "extra"),
        expires_at: s(&info, "expires_at"),
    })
}

/// Forget the account key. Relays keep their own copy, so a switch that
/// is on keeps writing until it is turned off.
pub fn github_disconnect(ctx: &WizardCtx) -> Result<()> {
    for a in GITHUB_ACCOUNT_ALIASES {
        let _ = ctx.custody.forget(a);
    }
    Ok(())
}

/// The key a relay's GitHub switch writes with: the account's when one
/// is kept (and the relay's copy follows it), else the relay's copy.
fn github_token(ctx: &WizardCtx, row: &AddonRow) -> Result<Option<Zeroizing<String>>> {
    if let Some(t) = kept(ctx, GITHUB_ACCOUNT_ALIAS)? {
        let alias = addons::secret_alias(row.id, AddonKind::Gittag);
        let same = kept(ctx, &alias)?.map(|c| c.as_str() == t.as_str()).unwrap_or(false);
        if !same {
            custody_put(ctx, &alias, t.as_bytes())?;
            if row.secret_alias != alias {
                addons::set_secret_alias(ctx, row.id, &alias)?;
            }
        }
        return Ok(Some(t));
    }
    if row.secret_alias.is_empty() {
        return Ok(None);
    }
    kept(ctx, &row.secret_alias)
}

// ---------------------------------------------------------------------
// The full note's container
// ---------------------------------------------------------------------

/// The container staged for one write, removed when dropped.
struct Staged(PathBuf);

impl Drop for Staged {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// A daal-refresh-v2 container of the relay's current freshness document
/// (the one `freshness::publish` signed last), with the signed pack it
/// names when that fits, and the revealed standby key. None when there
/// is no document, it names another pack, or it has expired: the full
/// note is then filler.
fn container(ctx: &WizardCtx, op: i64, key: Option<&str>) -> Option<Vec<u8>> {
    let row = ctx.db.get(op).ok()?;
    let want = row.signed_sbp_sha256.clone().filter(|s| !s.is_empty())?;
    let doc = std::fs::read(ctx.staging_dir.join(format!("freshness.{op}.json"))).ok()?;
    let dv: Value = serde_json::from_slice(&doc).ok()?;
    let named = s(&dv, "current_bundle_sha256");
    if !named.eq_ignore_ascii_case(&want) {
        return None;
    }
    let not_after = s(&dv, "not_after");
    if !not_after.is_empty() {
        let t = time::OffsetDateTime::parse(&not_after, &time::format_description::well_known::Rfc3339)
            .ok()?;
        if t.unix_timestamp() <= (ctx.clock)() {
            return None;
        }
    }
    let mut c = serde_json::Map::new();
    c.insert("kind".into(), json!("daal-refresh-v2"));
    c.insert("slot".into(), json!(SLOT_PLACEHOLDER));
    c.insert("freshness".into(), json!(B64.encode(&doc)));
    let pack = std::fs::read(crate::freshness::default_signed_pack_path(ctx, op)).ok();
    if let Some(p) = pack.filter(|p| {
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(p)).eq_ignore_ascii_case(&want)
    }) {
        c.insert("pack".into(), json!(B64.encode(&p)));
    }
    if let Some(k) = key {
        c.insert("standby_key".into(), json!(k));
    }
    let mut out = serde_json::to_vec(&Value::Object(c.clone())).ok()?;
    if out.len() > MAX_CONTAINER {
        // Without the pack the phone fetches it from the pack's address.
        c.remove("pack");
        out = serde_json::to_vec(&Value::Object(c)).ok()?;
    }
    (out.len() <= MAX_CONTAINER).then_some(out)
}

fn stage_container(ctx: &WizardCtx, op: i64, bytes: &[u8]) -> Result<Staged> {
    std::fs::create_dir_all(&ctx.staging_dir)
        .map_err(|e| WizardError::Validation(format!("mkdir staging: {e}")))?;
    let p = ctx.staging_dir.join(format!("{op}.note.container.json"));
    // It holds the plain standby key: made 0600 from the first byte, never
    // written into a file of the default mode.
    let _ = std::fs::remove_file(&p);
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let staged = {
        use std::io::Write;
        let mut file = o
            .open(&p)
            .map_err(|e| WizardError::Validation(format!("write the note container: {e}")))?;
        let staged = Staged(p);
        file.write_all(bytes)
            .map_err(|e| WizardError::Validation(format!("write the note container: {e}")))?;
        staged
    };
    Ok(staged)
}

// ---------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------

/// One gittag write. Ok: the row's detail after it.
fn write_gittag(ctx: &WizardCtx, row: &AddonRow) -> Result<NotesDetail> {
    let op = row.operator_id;
    let mut d = detail_of(row);
    // Each attempt's word is its own: the row still carries the last
    // attempt's, and one that fails before the helper runs would
    // otherwise log (and keep) that older word.
    d.last_error.clear();
    let now = (ctx.clock)();
    let res = (|| -> Result<Value> {
        let token = github_token(ctx, row)?
            .ok_or_else(|| coded(E_GITHUB_NO_ACCOUNT, "no GitHub key is kept for this relay"))?;
        let (u, audience) = secret(ctx, op)?;
        let reveal = reveal(ctx, op);
        let staged = match container(ctx, op, reveal.as_ref().map(|(k, _)| k.as_str())) {
            Some(b) => Some(stage_container(ctx, op, &b)?),
            None => None,
        };
        let mut seq = d.seq.saturating_add(1).max(1);
        for _ in 0..2 {
            let mut creds = json!({
                "token": token.as_str(),
                "owner": d.owner,
                "repo": d.repo,
                "update_secret": u.as_str(),
                "update_audience": audience,
                "seq": seq,
            });
            if let Some((k, commit)) = &reveal {
                creds["standby_key"] = json!(k);
                creds["standby_commit"] = json!(commit);
            }
            if let Some(st) = &staged {
                creds["container_path"] = json!(st.0.to_string_lossy());
            }
            match run_note(ctx, "note-gittag", "publish", &creds) {
                Ok(v) => {
                    d.carried_document = staged.is_some();
                    d.revealed = reveal.is_some();
                    if !d.audiences.contains(&audience) {
                        d.audiences.push(audience.clone());
                    }
                    return Ok(v);
                }
                Err(NoteFail::Verb { answer, .. }) if s(&answer, "code") == "seq_behind" => {
                    let high = answer.get("highest_seq").and_then(Value::as_u64).unwrap_or(seq);
                    seq = high.saturating_add(1);
                }
                Err(f) => {
                    d.last_error = f.word();
                    return Err(gittag_err(f));
                }
            }
        }
        d.last_error = "seq_behind".into();
        Err(coded(E_GITTAG_UNREACHABLE, "seq_behind"))
    })();
    d.last_try_at_unix = now;
    match &res {
        Ok(v) => {
            let reason = s(v, "reason");
            let word = if reason.is_empty() { "ok".to_string() } else { reason };
            log_write(op, AddonKind::Gittag, &word, write_changed(AddonKind::Gittag, v));
        }
        Err(e) => {
            let word = if d.last_error.is_empty() { error_word(e) } else { d.last_error.clone() };
            log_write(op, AddonKind::Gittag, &word, false);
        }
    }
    match res {
        Ok(v) => {
            let got = v.get("seq").and_then(Value::as_u64).unwrap_or(0);
            let high = v.get("highest_seq").and_then(Value::as_u64).unwrap_or(0);
            d.seq = d.seq.max(got).max(high);
            d.epoch = v.get("epoch").and_then(Value::as_u64).unwrap_or_else(|| epoch_at(now));
            d.last_ok_at_unix = now;
            d.last_error.clear();
            save_detail(ctx, row.id, &d)?;
            Ok(d)
        }
        Err(e) => {
            if d.last_error.is_empty() {
                d.last_error = error_word(&e);
            }
            let _ = save_detail(ctx, row.id, &d);
            Err(e)
        }
    }
}

fn error_word(e: &WizardError) -> String {
    match e {
        WizardError::Coded(c) => c.split(':').next().unwrap_or("error").to_ascii_lowercase(),
        _ => "error".into(),
    }
}

/// The zone the DNS switch writes in: the relay's way in through
/// Cloudflare's zone when it has one, else the account's.
fn dns_zone(ctx: &WizardCtx, op: i64) -> Result<String> {
    if let Ok(rows) = addons::list(ctx, op) {
        if let Some(z) = rows
            .iter()
            .filter(|r| r.kind == AddonKind::Cdn && r.state != AddonState::Promoted)
            .find_map(|r| r.detail.get("front").and_then(|f| f.get("zone")).and_then(Value::as_str))
            .filter(|z| !z.is_empty())
        {
            return Ok(z.to_ascii_lowercase());
        }
    }
    let acc = crate::addon_cdn::account(ctx)?;
    if acc.zone.is_empty() {
        return Err(coded(crate::addon_cdn::E_CDN_NO_TOKEN, "Cloudflare is not connected"));
    }
    Ok(acc.zone.to_ascii_lowercase())
}

/// One dnsnote write, then the removal of what older audiences left.
fn write_dns(ctx: &WizardCtx, row: &AddonRow) -> Result<NotesDetail> {
    let op = row.operator_id;
    let mut d = detail_of(row);
    // Each attempt's word is its own: the row still carries the last
    // attempt's, and one that fails before the helper runs would
    // otherwise log (and keep) that older word.
    d.last_error.clear();
    let now = (ctx.clock)();
    let res = (|| -> Result<Value> {
        let token = crate::addon_cdn::cf_token(ctx, op)?;
        let (u, audience) = secret(ctx, op)?;
        let mut creds = json!({
            "cf_token": token.as_str(),
            "update_secret": u.as_str(),
            "update_audience": audience,
            "zone": d.zone,
        });
        let reveal = reveal(ctx, op);
        if let Some((k, _)) = &reveal {
            creds["standby_key"] = json!(k);
        }
        match run_note(ctx, "note-dns", "publish", &creds) {
            Ok(v) => {
                d.revealed = reveal.is_some();
                // Older audiences: what they hold stays as it was, and
                // goes. Best effort; kept in the list until it went.
                let mut left = Vec::new();
                for a in d.audiences.iter().filter(|a| **a != audience) {
                    let gone = match crate::addon_standby::people_secret_of(ctx, op, a) {
                        Ok(Some(old)) => run_note(
                            ctx,
                            "note-dns",
                            "remove",
                            &json!({
                                "cf_token": token.as_str(),
                                "update_secret": B64.encode(&old[..]),
                                "update_audience": a,
                                "zone": d.zone,
                            }),
                        )
                        .is_ok(),
                        _ => true,
                    };
                    if !gone {
                        left.push(a.clone());
                    }
                }
                left.push(audience);
                d.audiences = left;
                Ok(v)
            }
            Err(f) => {
                d.last_error = f.word();
                Err(dns_err(f))
            }
        }
    })();
    d.last_try_at_unix = now;
    match &res {
        Ok(v) => log_write(op, AddonKind::Dnsnote, "ok", write_changed(AddonKind::Dnsnote, v)),
        Err(e) => {
            let word = if d.last_error.is_empty() { error_word(e) } else { d.last_error.clone() };
            log_write(op, AddonKind::Dnsnote, &word, false);
        }
    }
    match res {
        Ok(v) => {
            d.epoch = v.get("epoch").and_then(Value::as_u64).unwrap_or_else(|| epoch_at(now));
            d.last_ok_at_unix = now;
            d.last_error.clear();
            save_detail(ctx, row.id, &d)?;
            Ok(d)
        }
        Err(e) => {
            if d.last_error.is_empty() {
                d.last_error = error_word(&e);
            }
            let _ = save_detail(ctx, row.id, &d);
            Err(e)
        }
    }
}

fn write_row(ctx: &WizardCtx, row: &AddonRow) -> Result<NotesDetail> {
    match row.kind {
        AddonKind::Gittag => write_gittag(ctx, row),
        AddonKind::Dnsnote => write_dns(ctx, row),
        _ => Err(WizardError::Validation("not a note switch".into())),
    }
}

// ---------------------------------------------------------------------
// The log line
// ---------------------------------------------------------------------

/// The one line a write attempt leaves in the app's log (the same
/// `eprintln!` the `[recipient_provision]` and `[rotate_credentials]`
/// lines use, so it reaches the phone's log too):
///
/// `[notes_write] op=<relay id> kind=gittag|dnsnote outcome=<word> changed=yes|no`
///
/// `outcome` is `ok` (or the helper's own word for a write that went
/// through, such as `already_published`) or the code word kept on the
/// row (`missing_permission`, `network`, `helper_too_old`…). Nothing
/// else: never a token, a repository or owner, a zone, a note name, a
/// tag or an address. A word that is not the closed shape of a code
/// word is written `error`, so even a helper that answered something
/// odd cannot put a name in the line.
fn write_line(op: i64, kind: AddonKind, outcome: &str, changed: bool) -> String {
    let kind = match kind {
        AddonKind::Gittag => "gittag",
        AddonKind::Dnsnote => "dnsnote",
        _ => "other",
    };
    let closed = !outcome.is_empty()
        && outcome.len() <= 40
        && outcome.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    let word = if closed { outcome } else { "error" };
    format!(
        "[notes_write] op={op} kind={kind} outcome={word} changed={}",
        if changed { "yes" } else { "no" }
    )
}

#[cfg(test)]
thread_local! {
    /// The lines this test thread printed (tests read them back).
    pub(crate) static WRITE_LINES: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}

fn log_write(op: i64, kind: AddonKind, outcome: &str, changed: bool) {
    let line = write_line(op, kind, outcome, changed);
    #[cfg(test)]
    WRITE_LINES.with(|l| l.borrow_mut().push(line.clone()));
    eprintln!("{line}");
}

/// Whether a write that went through changed anything: gittag says so
/// (`changed`); dnsnote counts the records it created, replaced or
/// removed.
fn write_changed(kind: AddonKind, v: &Value) -> bool {
    match kind {
        AddonKind::Gittag => v.get("changed").and_then(Value::as_bool).unwrap_or(false),
        _ => ["created", "replaced", "removed"]
            .iter()
            .any(|k| v.get(*k).and_then(Value::as_u64).unwrap_or(0) > 0),
    }
}

/// Write every note switch that is on for relay `op`. Never fails: each
/// switch keeps its own result on its row. Returns (written, failed).
pub fn write_relay(ctx: &WizardCtx, op: i64) -> (i64, i64) {
    let Ok(rows) = addons::list(ctx, op) else {
        return (0, 0);
    };
    let mut n = (0, 0);
    for r in rows
        .iter()
        .filter(|r| matches!(r.kind, AddonKind::Gittag | AddonKind::Dnsnote) && r.state == AddonState::Ready)
    {
        n.0 += 1;
        if write_row(ctx, r).is_err() {
            n.1 += 1;
        }
    }
    n
}

/// Whether a switch is due a write when the app opens: its last write
/// that went through is from an earlier epoch, or the last try failed
/// and a while has passed since.
fn due(d: &NotesDetail, now: i64) -> bool {
    if !d.last_error.is_empty() {
        // Not on every open in a row: a while after the last try.
        return now - d.last_try_at_unix >= RETRY_AFTER_SECONDS;
    }
    d.last_ok_at_unix == 0 || d.epoch < epoch_at(now)
}

/// `wizard_notes_tick`: on app open, write every switch that is due.
pub fn tick(ctx: &WizardCtx) -> Result<NotesTickReport> {
    let now = (ctx.clock)();
    let mut rep = NotesTickReport::default();
    for op in ctx.db.list()?.into_iter().filter(|o| o.status != "decommissioned") {
        let Ok(rows) = addons::list(ctx, op.id) else { continue };
        for r in rows.iter().filter(|r| {
            matches!(r.kind, AddonKind::Gittag | AddonKind::Dnsnote) && r.state == AddonState::Ready
        }) {
            if !due(&detail_of(r), now) {
                continue;
            }
            rep.written += 1;
            if write_row(ctx, r).is_err() {
                rep.failed += 1;
            }
        }
    }
    Ok(rep)
}

// ---------------------------------------------------------------------
// The switches
// ---------------------------------------------------------------------

/// Start or adopt the relay's row of `kind`. A `ready` row is returned
/// as is; a `removing` one refuses.
fn ensure_row(
    ctx: &WizardCtx,
    op: i64,
    kind: AddonKind,
    fill: impl FnOnce(&mut NotesDetail),
) -> Result<std::result::Result<AddonRow, AddonRow>> {
    if let Some(r) = row_for(ctx, op, kind)? {
        return match r.state {
            AddonState::Ready => Ok(Ok(r)),
            AddonState::Removing => Err(WizardError::Validation(
                "turning this off has not finished; finish it first".into(),
            )),
            _ => Ok(Err(r)),
        };
    }
    let mut d = NotesDetail {
        people_before: people_now(ctx, op),
        ..Default::default()
    };
    fill(&mut d);
    let id = addons::insert(
        ctx,
        &NewAddon {
            operator_id: op,
            kind: Some(kind),
            state: Some(AddonState::Building),
            detail: Some(serde_json::to_value(&d).unwrap_or_else(|_| json!({}))),
            ..Default::default()
        },
    )?;
    Ok(Err(addons::get(ctx, id)?))
}

/// `wizard_addon_gittag_on`: «Updates through GitHub», on. Needs the
/// GitHub account. Makes the repository and writes the first note; only
/// then is the switch `ready` and do new files name it.
pub fn gittag_on(
    ctx: &WizardCtx,
    input: NotesOnInput,
    on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<AddonRow> {
    let op = input.operator_id;
    let _ = ctx.db.get(op)?;
    let account = github_account(ctx)?;
    if let Some(r) = row_for(ctx, op, AddonKind::Gittag)? {
        if r.state == AddonState::Ready {
            return Ok(r);
        }
    }
    if !account.connected || !owner_ok(&account.login) {
        return Err(coded(E_GITHUB_NO_ACCOUNT, "GitHub is not connected"));
    }
    // The update secret first: no row for a relay that cannot seal.
    let _ = secret(ctx, op)?;
    let row = match ensure_row(ctx, op, AddonKind::Gittag, |d| {
        d.owner = account.login.clone();
        d.repo = random_repo();
    })? {
        Ok(ready) => return Ok(ready),
        Err(r) => r,
    };
    // A retry after the account changed writes under the new account.
    let mut d = detail_of(&row);
    if d.owner != account.login {
        d.owner = account.login.clone();
        d.repo = random_repo();
        d.seq = 0;
        save_detail(ctx, row.id, &d)?;
    }
    let row = addons::get(ctx, row.id)?;
    on_progress(progress(op, AddonKind::Gittag, "github", "running", ""));
    match write_gittag(ctx, &row) {
        Ok(d) => {
            let ids = std::collections::BTreeMap::from([(
                "repository".to_string(),
                format!("{}/{}", d.owner, d.repo),
            )]);
            addons::set_provider_ids(ctx, row.id, &ids)?;
            addons::set_state(ctx, row.id, AddonState::Ready)?;
            mark_ever_on(ctx, op);
            on_progress(progress(op, AddonKind::Gittag, "github", "ok", ""));
            addons::get(ctx, row.id)
        }
        Err(e) => {
            on_progress(progress(op, AddonKind::Gittag, "github", "failed", &error_word(&e)));
            Err(e)
        }
    }
}

/// `wizard_addon_dnsnote_on`: «Updates through DNS», on. Needs the
/// Cloudflare account and its zone.
pub fn dnsnote_on(
    ctx: &WizardCtx,
    input: NotesOnInput,
    on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<AddonRow> {
    let op = input.operator_id;
    let _ = ctx.db.get(op)?;
    if let Some(r) = row_for(ctx, op, AddonKind::Dnsnote)? {
        if r.state == AddonState::Ready {
            return Ok(r);
        }
    }
    let zone = dns_zone(ctx, op)?;
    // The key before anything is made.
    let _ = crate::addon_cdn::cf_token(ctx, op)?;
    let _ = secret(ctx, op)?;
    let row = match ensure_row(ctx, op, AddonKind::Dnsnote, |d| d.zone = zone.clone())? {
        Ok(ready) => return Ok(ready),
        Err(r) => r,
    };
    let mut d = detail_of(&row);
    if d.zone.is_empty() {
        d.zone = zone;
        save_detail(ctx, row.id, &d)?;
    }
    let row = addons::get(ctx, row.id)?;
    on_progress(progress(op, AddonKind::Dnsnote, "dns", "running", ""));
    match write_dns(ctx, &row) {
        Ok(_) => {
            addons::set_state(ctx, row.id, AddonState::Ready)?;
            mark_ever_on(ctx, op);
            on_progress(progress(op, AddonKind::Dnsnote, "dns", "ok", ""));
            addons::get(ctx, row.id)
        }
        Err(e) => {
            on_progress(progress(op, AddonKind::Dnsnote, "dns", "failed", &error_word(&e)));
            Err(e)
        }
    }
}

/// Take the DNS records of every audience written down. Ok(true): all
/// gone (or nothing to take down).
fn dns_take_down(ctx: &WizardCtx, row: &AddonRow) -> bool {
    let op = row.operator_id;
    let d = detail_of(row);
    if d.audiences.is_empty() || d.zone.is_empty() {
        return true;
    }
    let Ok(token) = crate::addon_cdn::cf_token(ctx, op) else {
        return false;
    };
    let mut all = true;
    for a in &d.audiences {
        let Ok(Some(u)) = crate::addon_standby::people_secret_of(ctx, op, a) else {
            continue;
        };
        let creds = json!({
            "cf_token": token.as_str(),
            "update_secret": B64.encode(&u[..]),
            "update_audience": a,
            "zone": d.zone,
        });
        if run_note(ctx, "note-dns", "remove", &creds).is_err() {
            all = false;
        }
    }
    all
}

/// Called by `addons::remove` (a switch, off). GitHub: the repository
/// stays (Daal never deletes one; the publisher may); the row and the
/// relay's key copy go. DNS: the records go first; if Cloudflare cannot
/// take them down the row stays `removing`, and the same call is the
/// retry. Files already made keep naming the carrier; with nothing new
/// written there, their phones find nothing new.
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
    on_progress(progress(op, row.kind, "removing", "running", ""));
    if row.kind == AddonKind::Dnsnote {
        addons::set_state(ctx, row.id, AddonState::Removing)?;
        if !dns_take_down(ctx, row) {
            on_progress(progress(op, row.kind, "removing", "failed", ""));
            report.warnings.push("dns_records_left".into());
            return Ok(report);
        }
    } else if !detail_of(row).repo.is_empty() {
        report.by_hand.push("github_repository".into());
    }
    addons::forget(ctx, row.id)?;
    report.removed = true;
    on_progress(progress(op, row.kind, "removing", "ok", ""));
    Ok(report)
}

/// Called by `addons::before_relay_destroy`. Nothing bills and nothing
/// needs the relay's row, so it never keeps the relay: DNS records are
/// taken down when they can be (best effort), the repository stays.
pub fn on_relay_delete(ctx: &WizardCtx, row: &AddonRow) -> AddonOutcome {
    let mut out = AddonOutcome::removed(row);
    if row.kind == AddonKind::Dnsnote && !dns_take_down(ctx, row) {
        out.error = "the DNS records were not taken down".into();
    }
    out
}

#[cfg(test)]
#[path = "addon_notes_tests.rs"]
mod tests;
