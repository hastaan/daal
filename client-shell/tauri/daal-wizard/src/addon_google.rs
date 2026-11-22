//! Add-on 3: an update channel through Google (docs/optional-addons-plan.md
//! §3, specs/optional-addons-v1.md §5).
//!
//! Google is an account, like Cloudflare: one tiny Apps Script web app
//! per Google account serves every relay of this publisher, each relay
//! in its own "slot". The script is added once, from Accounts → Google:
//! the publisher copies it (the account's write key is already in it),
//! deploys it by hand as a web app and pastes the address back
//! ([`account_attach`]); "Sign in with Google" ([`account_sign_in`],
//! Path A) is the same step done through the Apps Script API, offered
//! only by a build that has the OAuth clients. Either way Daal then
//! writes a test container to the test slot and reads it back the way a
//! recipient does, and only then is the account connected.
//!
//! A relay's switch ([`turn_on`]) needs the account connected. It gives
//! the relay a random slot, puts the slot's address in the relay's
//! freshness table (kind `appsscript`), sends the relay's first update
//! and reads it back. Turning it off ([`remove`]) takes the address out
//! and clears the slot (the slot's empty container). Nothing per relay
//! happens in Google.
//!
//! # What is stored where
//!
//! * The account's **write key** (32 random bytes) is in device custody
//!   under [`ACCOUNT_KEY_ALIAS`], and the script's address (not a secret)
//!   beside it under [`ACCOUNT_URL_ALIAS`], like the Cloudflare account
//!   key and its zone. The publisher backup carries both
//!   (`publisher_backup::account_aliases`). [`account_disconnect`]
//!   forgets them; the script stays in Google until the publisher deletes
//!   it.
//! * A relay that turns the channel on takes a **copy** of the key under
//!   its add-on row's `secret_alias` (`daal.addon.<id>.google`), as a
//!   relay takes a copy of the Cloudflare account key. So the relay's
//!   freshness publish and its removal read the relay's own key, a
//!   disconnected account leaves the relays that use it working and
//!   removable, and the backup carries it through the row's alias column.
//!   It reaches `daal-deploy` only as a 0600 temp file
//!   (`--write-key-file`), never argv, a log line or a progress event.
//! * The **slot** and the relay's mirror URL
//!   (`…/exec?s=<slot>&k=<read token>`) are public: every pack of that
//!   relay carries them. They are in `detail_json`. The read token is
//!   derived from the key and the slot ([`read_token`]), so the script
//!   keeps no list.
//! * **No Google token is stored.** On Android the shell gets a one-shot
//!   access token from Play services (`PlatformHandle::google_authorize`)
//!   and hands it to [`account_sign_in`]; on desktop it runs the loopback
//!   + PKCE sign-in in the system browser and hands the code and verifier
//!   over. Either goes to `appsscript-deploy` on stdin, which makes the
//!   four Apps Script API calls, revokes the token and zeroes it.
//!
//! # OAuth clients (owner prerequisite, plan §3.5)
//!
//! The client ids are build-time configuration:
//! `DAAL_GOOGLE_DESKTOP_CLIENT_ID` and `DAAL_GOOGLE_DESKTOP_CLIENT_SECRET`
//! (a "Desktop app" client; Google says its secret is not confidential)
//! for desktop, and `DAAL_GOOGLE_ANDROID_CLIENT_ID` for Android (read by
//! the platform plugin). A build without them hides "Sign in with
//! Google" altogether ([`GoogleAccount::sign_in`]) and answers
//! `E_GOOGLE_NOT_CONFIGURED` if asked anyway; adding the script by hand
//! always works.
//!
//! Publishing an update is not a verb of its own: it runs inside the
//! freshness publish as one more mirror. `freshness::publish` hands
//! `publish-freshness` the relay's mirror URL and its copy of the key
//! (`--appsscript-url`, `--appsscript-write-key-file`, and the signed
//! pack as `--appsscript-pack-file`), and the helper's `appsscript`
//! backend POSTs the container to the relay's slot.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::addons::{
    self, AddonKind, AddonOutcome, AddonProgress, AddonRemoveReport, AddonRow, AddonState, NewAddon,
};
use crate::cli_bridge::{verb_unknown, AddonCliRequest, BridgeError};
use crate::commands::{
    coded, custody_get, custody_put, Result, WizardCtx, WizardError, E_DEPLOY_TOO_OLD,
};

/// The two OAuth scopes Path A asks for (plan §3.5), and nothing else.
pub const SCOPES: [&str; 2] = [
    "https://www.googleapis.com/auth/script.projects",
    "https://www.googleapis.com/auth/script.deployments",
];

/// This build has no OAuth client for this platform (the owner has not
/// created the Google Cloud project yet). The UI does not offer sign-in
/// then; adding the script by hand still works.
pub const E_GOOGLE_NOT_CONFIGURED: &str = "E_GOOGLE_NOT_CONFIGURED";
/// The account has not turned on the Apps Script API
/// (script.google.com/home/usersettings).
pub const E_GOOGLE_API_NOT_ENABLED: &str = "E_GOOGLE_API_NOT_ENABLED";
/// Google refused the sign-in or the token.
pub const E_GOOGLE_UNAUTHORIZED: &str = "E_GOOGLE_UNAUTHORIZED";
/// The publisher closed or refused the Google sign-in.
pub const E_GOOGLE_SIGN_IN_CANCELLED: &str = "E_GOOGLE_SIGN_IN_CANCELLED";
/// A project was created but not deployed; trying again resumes into
/// it. The tail names it.
pub const E_GOOGLE_PARTIAL: &str = "E_GOOGLE_PARTIAL";
/// Another Apps Script API failure.
pub const E_GOOGLE_API: &str = "E_GOOGLE_API";
/// The pasted address is not a deployed web app's /exec address.
pub const E_GOOGLE_BAD_ADDRESS: &str = "E_GOOGLE_BAD_ADDRESS";
/// The script did not take the update or did not give it back. The tail
/// starts with the reason word ([`GoogleCheck::reason`]).
pub const E_GOOGLE_CHECK_FAILED: &str = "E_GOOGLE_CHECK_FAILED";
/// A relay's switch was turned on with no Google account connected.
/// Nothing was changed; the UI opens Accounts → Google.
pub const E_GOOGLE_NO_ACCOUNT: &str = "E_GOOGLE_NO_ACCOUNT";

/// The account's write key (32 bytes), kept apart from any relay.
pub const ACCOUNT_KEY_ALIAS: &str = "daal.google.account.write_key";
/// The account script's address, `https://script.google.com/macros/s/<id>/exec`
/// (not a secret; kept beside the key). Present only once the connect
/// check passed.
pub const ACCOUNT_URL_ALIAS: &str = "daal.google.account.url";
/// A project a failed sign-in created; the next sign-in resumes into it.
const ACCOUNT_PARTIAL_ALIAS: &str = "daal.google.account.partial_script";
/// What the publisher backup carries of the account (when present).
pub const ACCOUNT_ALIASES: [&str; 2] = [ACCOUNT_KEY_ALIAS, ACCOUNT_URL_ALIAS];

/// The slot the connect check writes to (`appsscript.TestSlot` in Go).
/// No relay is given it.
pub const TEST_SLOT: &str = "connectTest";

/// Desktop OAuth client, from the build.
const DESKTOP_CLIENT_ID: Option<&str> = option_env!("DAAL_GOOGLE_DESKTOP_CLIENT_ID");
const DESKTOP_CLIENT_SECRET: Option<&str> = option_env!("DAAL_GOOGLE_DESKTOP_CLIENT_SECRET");

/// The project title shown in the publisher's Google Drive. Neutral on
/// purpose.
const PROJECT_TITLE: &str = "Notes";

/// How long the desktop sign-in waits for the browser.
const SIGN_IN_WAIT: Duration = Duration::from_secs(300);

// ---------------------------------------------------------------------
// Types the UI sees
// ---------------------------------------------------------------------

/// `wizard_google_account`: the Google account on this phone. Local, no
/// network, no secret.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GoogleAccount {
    /// The script is added and its check passed: relays can use it.
    pub connected: bool,
    /// A write key was made (the script was copied) and no address is
    /// connected yet: the sheet goes on at "paste the address".
    pub script_made: bool,
    /// The script's address, '' when not connected.
    pub url: String,
    /// This build can sign in with Google (OAuth clients configured).
    /// Filled by the shell, which knows the platform's answer.
    pub sign_in: bool,
}

/// `wizard_google_account_script`: the script to paste, with the
/// account's write key already in it.
///
/// `code_gs` carries the write key: `Debug` leaves it out.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct GoogleScript {
    pub code_gs: String,
    pub manifest_json: String,
}

impl std::fmt::Debug for GoogleScript {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GoogleScript")
            .field("code_gs", &format_args!("<{} bytes>", self.code_gs.len()))
            .field("manifest_json", &self.manifest_json)
            .finish()
    }
}

impl Drop for GoogleScript {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.code_gs.zeroize();
    }
}

/// `wizard_google_account_attach`: the web-app address pasted back.
/// Checked for shape, written to (test slot), read back.
#[derive(Debug, Clone, Deserialize)]
pub struct GoogleAccountAttachInput {
    pub url: String,
}

/// `wizard_addon_google_on`: turn a relay's switch on.
#[derive(Debug, Clone, Deserialize)]
pub struct GoogleOnInput {
    pub operator_id: i64,
}

/// `wizard_addon_google_check`: fetch the relay's container back again.
#[derive(Debug, Clone, Deserialize)]
pub struct GoogleCheckInput {
    pub operator_id: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GoogleCheck {
    /// The fetch-back returned the container just published.
    pub ok: bool,
    /// Through the Google front (SNI www.google.com), as recipients
    /// fetch; false when only the plain attempt worked.
    pub via_front: bool,
    pub checked_at_unix: i64,
    /// `not_deployed` (no web app open to anyone at this address) |
    /// `refused` (a script with another write key) | `stale` (it holds
    /// a newer update) | `wrong_content` (it answered with something
    /// else) | `unreachable` | `full` (the account's script has no room
    /// left) | `bad_address` | `no_address` (the channel has no address
    /// yet) | "" when ok.
    #[serde(default)]
    pub reason: String,
    /// The helper's words for a failure (Details only); never a secret.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

/// Kind-specific state of a relay's row (`detail_json`). Nothing secret.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct GoogleDetail {
    /// The relay's place in the account's script.
    #[serde(default)]
    pub slot: String,
    /// The relay's mirror URL, `?s=<slot>&k=<read token>`.
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub deployment_id: String,
    /// The last update the script accepted, and its hash.
    #[serde(default)]
    pub posted_seq: u64,
    #[serde(default)]
    pub posted_sha256: String,
    #[serde(default)]
    pub last_check_at_unix: i64,
    #[serde(default)]
    pub last_check_ok: bool,
    #[serde(default)]
    pub last_check_via_front: bool,
    #[serde(default)]
    pub last_check_reason: String,
}

/// What `appsscript-check` / `appsscript-account-check` print.
#[derive(Debug, Clone, Default, Deserialize)]
struct CliCheck {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    via_front: bool,
    #[serde(default)]
    seq: u64,
    #[serde(default)]
    sha256: String,
    #[serde(default)]
    reason: String,
    #[serde(default)]
    detail: String,
}

// ---------------------------------------------------------------------
// The slot's read token (specs/relaypack-v1.md, "Mirror provider
// appsscript"; `appsscript.ReadToken` in Go, `readToken_` in Code.gs)
// ---------------------------------------------------------------------

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = Zeroizing::new([0u8; 64]);
    if key.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = Zeroizing::new([0x36u8; 64]);
    let mut opad = Zeroizing::new([0x5cu8; 64]);
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let inner = Sha256::new()
        .chain_update(ipad.as_ref())
        .chain_update(msg)
        .finalize();
    Sha256::new()
        .chain_update(opad.as_ref())
        .chain_update(inner)
        .finalize()
        .into()
}

/// A slot's read token: the first 16 bytes of
/// HMAC-SHA256(write key, "daal-read-v2\n" + slot), base64url, no
/// padding (22 characters).
pub fn read_token(write_key: &[u8], slot: &str) -> String {
    let mac = hmac_sha256(write_key, format!("daal-read-v2\n{slot}").as_bytes());
    URL_SAFE_NO_PAD.encode(&mac[..16])
}

fn valid_slot(s: &str) -> bool {
    s.len() == 11
        && s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// A fresh slot: 8 random bytes as 11 base64url characters.
fn new_slot() -> String {
    let mut b = [0u8; 8];
    loop {
        OsRng.fill_bytes(&mut b);
        let s = URL_SAFE_NO_PAD.encode(b);
        if s != TEST_SLOT {
            return s;
        }
    }
}

/// A relay's mirror URL in the script at `base`.
pub fn slot_url(base: &str, write_key: &[u8], slot: &str) -> String {
    format!("{base}?s={slot}&k={}", read_token(write_key, slot))
}

// ---------------------------------------------------------------------
// Row, key and progress helpers
// ---------------------------------------------------------------------

fn progress(op: i64, step: &str, state: &str, detail: &str) -> AddonProgress {
    AddonProgress {
        operator_id: op,
        kind: AddonKind::Google,
        step: step.into(),
        state: state.into(),
        detail: detail.into(),
    }
}

fn detail_of(row: &AddonRow) -> GoogleDetail {
    serde_json::from_value(row.detail.clone()).unwrap_or_default()
}

fn save_detail(ctx: &WizardCtx, id: i64, d: &GoogleDetail) -> Result<()> {
    addons::set_detail(ctx, id, &serde_json::to_value(d).unwrap_or_default())
}

/// The relay's Google row, if any.
fn row_for(ctx: &WizardCtx, op: i64) -> Result<Option<AddonRow>> {
    Ok(addons::list(ctx, op)?
        .into_iter()
        .find(|r| r.kind == AddonKind::Google && r.state != AddonState::Promoted))
}

fn random_b64(n: usize) -> String {
    let mut b = vec![0u8; n];
    OsRng.fill_bytes(&mut b);
    URL_SAFE_NO_PAD.encode(&b)
}

/// A kept value under `alias`, or `None` when there is none.
fn kept(ctx: &WizardCtx, alias: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
    match custody_get(ctx, alias) {
        Ok(v) if !v.is_empty() => Ok(Some(v)),
        Ok(_) => Ok(None),
        Err(WizardError::Coded(c)) if c.starts_with(crate::commands::E_SECRET_MISSING) => Ok(None),
        Err(e) => Err(e),
    }
}

fn kept_string(ctx: &WizardCtx, alias: &str) -> Result<Option<String>> {
    Ok(kept(ctx, alias)?
        .and_then(|v| String::from_utf8(v.to_vec()).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty()))
}

/// The account's write key, when one is kept.
fn account_key(ctx: &WizardCtx) -> Result<Option<Zeroizing<Vec<u8>>>> {
    Ok(kept(ctx, ACCOUNT_KEY_ALIAS)?.filter(|k| k.len() == 32))
}

/// The account's key, made on first use (the script is being copied).
fn ensure_account_key(ctx: &WizardCtx) -> Result<Zeroizing<Vec<u8>>> {
    if let Some(k) = account_key(ctx)? {
        return Ok(k);
    }
    let mut key = Zeroizing::new(vec![0u8; 32]);
    OsRng.fill_bytes(key.as_mut_slice());
    custody_put(ctx, ACCOUNT_KEY_ALIAS, &key)?;
    Ok(key)
}

/// The connected account: its address and key. `E_GOOGLE_NO_ACCOUNT`
/// when either is missing.
fn connected_account(ctx: &WizardCtx) -> Result<(String, Zeroizing<Vec<u8>>)> {
    match (kept_string(ctx, ACCOUNT_URL_ALIAS)?, account_key(ctx)?) {
        (Some(url), Some(key)) => Ok((url, key)),
        _ => Err(coded(
            E_GOOGLE_NO_ACCOUNT,
            "connect Google on the Accounts page first",
        )),
    }
}

/// The relay's copy of the write key as the 64 hex characters
/// `--write-key-file` takes.
fn write_key_hex(ctx: &WizardCtx, row: &AddonRow) -> Result<Zeroizing<String>> {
    if row.secret_alias.is_empty() {
        return Err(coded(
            crate::commands::E_SECRET_MISSING,
            "the Google update channel has no write key",
        ));
    }
    let k = custody_get(ctx, &row.secret_alias)?;
    if k.len() != 32 {
        return Err(coded(
            crate::commands::E_CUSTODY_BACKEND,
            "the stored write key has the wrong length",
        ));
    }
    Ok(Zeroizing::new(hex::encode(k.as_slice())))
}

/// Whether the relay's channel has its write key (the freshness panel's
/// `has_credential` for the `appsscript` endpoint). A probe; the key is
/// dropped zeroed.
pub(crate) fn has_write_key(ctx: &WizardCtx, op: i64) -> bool {
    match row_for(ctx, op) {
        Ok(Some(r)) if r.has_secret => ctx
            .custody
            .get(&r.secret_alias)
            .map(Zeroizing::new)
            .map(|k| k.len() == 32)
            .unwrap_or(false),
        _ => false,
    }
}

/// A `daal-deploy` failure in this add-on's words: the helper's own
/// `E_GOOGLE_*` / `E_NOT_BUILT` first line is passed through as the
/// code; an older helper is `E_DEPLOY_TOO_OLD`.
fn cli_err(e: BridgeError) -> WizardError {
    if verb_unknown(&e) {
        return coded(
            E_DEPLOY_TOO_OLD,
            "the setup helper in this app has no Google update channel",
        );
    }
    if let BridgeError::SubprocessFailed { stderr, .. } = &e {
        if let Some(line) = stderr
            .lines()
            .find(|l| l.starts_with("E_GOOGLE_") || l.starts_with("E_NOT_BUILT:"))
        {
            return WizardError::Coded(crate::freshness::redact_detail(line));
        }
    }
    WizardError::Subprocess(crate::freshness::redact_detail(&e.to_string()))
}

fn run_json<T: for<'de> Deserialize<'de>>(
    ctx: &WizardCtx,
    req: AddonCliRequest<'_>,
    on_progress: &mut dyn FnMut(AddonProgress),
    op: i64,
) -> Result<T> {
    let out = ctx
        .cli
        .run_addon(req, &mut |ev| {
            on_progress(progress(op, &ev.step, "running", ""));
        })
        .map_err(cli_err)?;
    serde_json::from_slice(&out).map_err(|e| {
        WizardError::Subprocess(format!(
            "the setup helper printed something unexpected: {e}"
        ))
    })
}

fn check_failed(reason: &str, detail: &str) -> WizardError {
    let detail = crate::freshness::redact_detail(detail);
    if detail.is_empty() {
        coded(
            E_GOOGLE_CHECK_FAILED,
            format!("{reason}: the script did not answer as it should"),
        )
    } else {
        coded(E_GOOGLE_CHECK_FAILED, format!("{reason}: {detail}"))
    }
}

/// The next update number nobody has used: past the freshness
/// counter, the clock and the last update the script took. Recorded in
/// the freshness counter at once, so the next signed document is
/// numbered past it (the script refuses an older number in the slot).
fn next_seq(ctx: &WizardCtx, op: i64, d: &GoogleDetail) -> Result<u64> {
    let row = ctx.db.get(op)?;
    let now = (ctx.clock)().max(0) as u64;
    let last = row.freshness_last_sequence.max(0) as u64;
    let seq = now
        .max(last.saturating_add(1))
        .max(d.posted_seq.saturating_add(1));
    ctx.db
        .record_freshness_sequence(op, seq.min(i64::MAX as u64) as i64)?;
    Ok(seq)
}

/// The last signed document `publish-freshness` wrote for this relay,
/// with its sequence, and the signed pack when it is the one the
/// document names.
fn last_document(ctx: &WizardCtx, op: i64) -> Option<(PathBuf, u64, Option<PathBuf>)> {
    let doc = ctx.staging_dir.join(format!("freshness.{op}.json"));
    let body = std::fs::read(&doc).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&body).ok()?;
    let seq = v.get("sequence")?.as_u64()?;
    let named = v
        .get("current_bundle_sha256")?
        .as_str()?
        .to_ascii_lowercase();
    let pack = crate::freshness::default_signed_pack_path(ctx, op);
    let pack = match std::fs::read(&pack) {
        Ok(b) if hex::encode(Sha256::digest(&b)) == named => Some(pack),
        _ => None,
    };
    Some((doc, seq, pack))
}

/// What to send: the document (and pack), or the slot's empty container
/// under a fresh number.
enum Payload {
    Document { doc: PathBuf, pack: Option<PathBuf> },
    Empty { seq: u64 },
}

/// POST one update to the relay's slot and fetch it back. Records what
/// the script now holds in the row.
fn send(
    ctx: &WizardCtx,
    row: &AddonRow,
    url: &str,
    payload: Payload,
    on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<GoogleCheck> {
    let op = row.operator_id;
    let key = write_key_hex(ctx, row)?;
    let mut args = vec![
        "appsscript-check".to_string(),
        "--url".into(),
        url.to_string(),
    ];
    match &payload {
        Payload::Document { doc, pack } => {
            args.push("--freshness-file".into());
            args.push(doc.to_string_lossy().into_owned());
            if let Some(p) = pack {
                args.push("--pack-file".into());
                args.push(p.to_string_lossy().into_owned());
            }
        }
        Payload::Empty { seq } => {
            args.push("--seq".into());
            args.push(seq.to_string());
        }
    }
    on_progress(progress(op, "checking", "running", ""));
    let r: CliCheck = run_json(
        ctx,
        AddonCliRequest {
            args,
            secret_files: vec![("--write-key-file", key.as_str())],
            stdin: &[],
            progress: false,
        },
        on_progress,
        op,
    )?;
    let now = (ctx.clock)();
    let mut d = detail_of(&addons::get(ctx, row.id)?);
    if r.ok {
        d.posted_seq = d.posted_seq.max(r.seq);
        d.posted_sha256 = r.sha256.clone();
    }
    d.last_check_at_unix = now;
    d.last_check_ok = r.ok;
    d.last_check_via_front = r.via_front;
    d.last_check_reason = r.reason.clone();
    save_detail(ctx, row.id, &d)?;
    on_progress(progress(
        op,
        "checking",
        if r.ok { "ok" } else { "failed" },
        &crate::freshness::redact_detail(&r.detail),
    ));
    Ok(GoogleCheck {
        ok: r.ok,
        via_front: r.via_front,
        checked_at_unix: now,
        reason: r.reason,
        detail: crate::freshness::redact_detail(&r.detail),
    })
}

/// The update that goes first into a new slot: the last signed
/// document when there is one, the empty container otherwise.
fn first_payload(ctx: &WizardCtx, row: &AddonRow) -> Result<Payload> {
    let d = detail_of(row);
    match last_document(ctx, row.operator_id) {
        Some((doc, seq, pack)) if seq >= d.posted_seq => Ok(Payload::Document { doc, pack }),
        _ => Ok(Payload::Empty {
            seq: next_seq(ctx, row.operator_id, &d)?,
        }),
    }
}

// ---------------------------------------------------------------------
// The account (Accounts → Google)
// ---------------------------------------------------------------------

/// Whether this build can sign in with Google on a desktop. The shell
/// adds the Android plugin's answer to make [`GoogleAccount::sign_in`].
pub fn desktop_sign_in_configured() -> bool {
    !cfg!(any(target_os = "android", target_os = "ios")) && desktop_client().is_some()
}

/// The account on this phone. Local: no network, no secret in the
/// answer. `sign_in` is left false for the shell to fill.
pub fn account(ctx: &WizardCtx) -> Result<GoogleAccount> {
    let key = account_key(ctx)?.is_some();
    let url = kept_string(ctx, ACCOUNT_URL_ALIAS)?.unwrap_or_default();
    Ok(GoogleAccount {
        connected: key && !url.is_empty(),
        script_made: key && url.is_empty(),
        url: if key { url } else { String::new() },
        sign_in: false,
    })
}

/// Copy the script: Code.gs with the account's write key in it. The
/// first call makes the key; later calls give the same script, so a
/// script already pasted stays good.
pub fn account_script(
    ctx: &WizardCtx,
    on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<GoogleScript> {
    let key = ensure_account_key(ctx)?;
    let key_hex = Zeroizing::new(hex::encode(key.as_slice()));
    on_progress(progress(0, "script", "running", ""));
    let s: GoogleScript = run_json(
        ctx,
        AddonCliRequest {
            args: vec!["appsscript-script".into()],
            secret_files: vec![("--write-key-file", key_hex.as_str())],
            stdin: &[],
            progress: false,
        },
        on_progress,
        0,
    )?;
    on_progress(progress(0, "script", "ok", ""));
    Ok(s)
}

/// The script's own address for what a publisher pasted (or the Apps
/// Script API answered): `https://script.google.com/macros/s/<id>/exec`,
/// the shape `freshness.ValidateAppsScriptBase` accepts. A trailing
/// slash, a query or a fragment are dropped.
pub(crate) fn normalize_base(pasted: &str) -> std::result::Result<String, String> {
    let s = pasted.trim();
    const HOST: &str = "https://script.google.com/";
    // `get`, not indexing: pasted text may start with anything,
    // including a character that does not end on byte 26.
    if !s.get(..HOST.len()).is_some_and(|p| p.eq_ignore_ascii_case(HOST)) {
        return Err("that is not a script.google.com web-app address".into());
    }
    let rest = &s[HOST.len() - 1..];
    let rest = rest.split('#').next().unwrap_or("");
    let path = rest.split('?').next().unwrap_or("");
    let path = path.trim_end_matches('/');
    if path.ends_with("/dev") {
        return Err(
            "that is the test address (/dev); copy the web app address that ends in /exec".into(),
        );
    }
    let id = path
        .strip_prefix("/macros/s/")
        .and_then(|p| p.strip_suffix("/exec"))
        .ok_or_else(|| "the address must look like script.google.com/macros/s/…/exec".to_string())?;
    if !(20..=120).contains(&id.len())
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("the address must look like script.google.com/macros/s/…/exec".into());
    }
    Ok(format!("https://script.google.com/macros/s/{id}/exec"))
}

fn deployment_id_of(url: &str) -> Option<String> {
    let rest = url.strip_prefix("https://script.google.com/macros/s/")?;
    Some(rest.split('/').next()?.to_string())
}

/// The connect check: an update with a fresh nonce to the test slot,
/// read back through the Google front. Only when it worked is the
/// address kept, and the account connected.
fn connect_with(
    ctx: &WizardCtx,
    base: &str,
    key: &[u8],
    on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<GoogleAccount> {
    let key_hex = Zeroizing::new(hex::encode(key));
    on_progress(progress(0, "checking", "running", ""));
    // The test slot's update is numbered by the helper's clock in
    // milliseconds, so two checks in one second still go up.
    let r: CliCheck = run_json(
        ctx,
        AddonCliRequest {
            args: vec![
                "appsscript-account-check".into(),
                "--url".into(),
                base.to_string(),
            ],
            secret_files: vec![("--write-key-file", key_hex.as_str())],
            stdin: &[],
            progress: false,
        },
        on_progress,
        0,
    )?;
    if !r.ok {
        on_progress(progress(0, "checking", "failed", &r.reason));
        return Err(check_failed(&r.reason, &r.detail));
    }
    custody_put(ctx, ACCOUNT_URL_ALIAS, base.as_bytes())?;
    let _ = ctx.custody.forget(ACCOUNT_PARTIAL_ALIAS);
    on_progress(progress(0, "checking", "ok", ""));
    account(ctx)
}

/// Accounts → Google, by hand: the web-app address pasted back after
/// the script was copied and deployed.
pub fn account_attach(
    ctx: &WizardCtx,
    input: GoogleAccountAttachInput,
    on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<GoogleAccount> {
    let key = account_key(ctx)?.ok_or_else(|| {
        WizardError::Validation("copy the script first: it carries this account's write key".into())
    })?;
    let base = normalize_base(&input.url).map_err(|e| coded(E_GOOGLE_BAD_ADDRESS, e))?;
    connect_with(ctx, &base, &key, on_progress)
}

/// Forget the account: its key and address. Relays that turned the
/// channel on keep their own copies, so their channels keep working and
/// stay removable. The script stays in Google until the publisher
/// deletes it there.
pub fn account_disconnect(ctx: &WizardCtx) -> Result<()> {
    for a in [ACCOUNT_KEY_ALIAS, ACCOUNT_URL_ALIAS, ACCOUNT_PARTIAL_ALIAS] {
        let _ = ctx.custody.forget(a);
    }
    Ok(())
}

/// `mobile_token`: on Android the shell obtains a one-shot access token
/// from the platform plugin (`PlatformHandle::google_authorize`) and
/// hands it here; on desktop it is `None` and this module signs in
/// through the system browser (loopback + PKCE). Either way the token
/// is used for the four Apps Script API calls and dropped; nothing is
/// stored. The UI offers this only when [`GoogleAccount::sign_in`].
pub fn account_sign_in(
    ctx: &WizardCtx,
    mobile_token: Option<Zeroizing<String>>,
    on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<GoogleAccount> {
    let auth = match mobile_token {
        Some(t) => SignIn::Token(t),
        None => {
            if cfg!(any(target_os = "android", target_os = "ios")) {
                return Err(coded(
                    E_GOOGLE_NOT_CONFIGURED,
                    "signing in with Google is not set up in this build; add the script by hand",
                ));
            }
            match desktop_client() {
                Some(c) => SignIn::Desktop(c),
                None => return Err(coded(
                    E_GOOGLE_NOT_CONFIGURED,
                    "signing in with Google is not set up in this build; add the script by hand",
                )),
            }
        }
    };
    account_sign_in_with(ctx, auth, &mut open_system_browser, SIGN_IN_WAIT, on_progress)
}

/// Where Path A's access comes from.
pub(crate) enum SignIn {
    /// Android: from Play services.
    Token(Zeroizing<String>),
    /// Desktop: loopback + PKCE with this client.
    Desktop(DesktopClient),
}

#[derive(Clone)]
pub(crate) struct DesktopClient {
    pub id: String,
    pub secret: String,
    /// Google's authorization endpoint (tests: anything; the browser
    /// is simulated).
    pub auth_endpoint: String,
}

fn desktop_client() -> Option<DesktopClient> {
    match (DESKTOP_CLIENT_ID, DESKTOP_CLIENT_SECRET) {
        (Some(id), Some(secret)) if !id.trim().is_empty() => Some(DesktopClient {
            id: id.trim().into(),
            secret: secret.trim().into(),
            auth_endpoint: "https://accounts.google.com/o/oauth2/v2/auth".into(),
        }),
        _ => None,
    }
}

/// The sign-in JSON `appsscript-deploy` reads on stdin.
#[derive(Serialize)]
struct DeployStdin<'a> {
    #[serde(skip_serializing_if = "str::is_empty")]
    access_token: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    code: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    code_verifier: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    redirect_uri: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    client_id: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    client_secret: &'a str,
}

#[derive(Deserialize)]
struct Deployed {
    url: String,
}

/// Path A at account level: the same script deployed through the API,
/// then the same connect check as by hand.
pub(crate) fn account_sign_in_with(
    ctx: &WizardCtx,
    auth: SignIn,
    open: &mut dyn FnMut(&str) -> std::io::Result<()>,
    wait: Duration,
    on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<GoogleAccount> {
    let key = ensure_account_key(ctx)?;
    let key_hex = Zeroizing::new(hex::encode(key.as_slice()));

    on_progress(progress(0, "signing_in", "running", ""));
    let stdin: Zeroizing<Vec<u8>> = match &auth {
        SignIn::Token(t) => Zeroizing::new(
            serde_json::to_vec(&DeployStdin {
                access_token: t.as_str(),
                code: "",
                code_verifier: "",
                redirect_uri: "",
                client_id: "",
                client_secret: "",
            })
            .unwrap_or_default(),
        ),
        SignIn::Desktop(c) => {
            let got = match loopback_sign_in(c, open, wait) {
                Ok(g) => g,
                Err(e) => {
                    on_progress(progress(0, "signing_in", "failed", ""));
                    return Err(e);
                }
            };
            Zeroizing::new(
                serde_json::to_vec(&DeployStdin {
                    access_token: "",
                    code: got.code.as_str(),
                    code_verifier: got.verifier.as_str(),
                    redirect_uri: &got.redirect_uri,
                    client_id: &c.id,
                    client_secret: &c.secret,
                })
                .unwrap_or_default(),
            )
        }
    };
    drop(auth);
    on_progress(progress(0, "signing_in", "ok", ""));

    let mut args = vec![
        "appsscript-deploy".to_string(),
        "--title".into(),
        PROJECT_TITLE.into(),
    ];
    if let Some(id) = kept_string(ctx, ACCOUNT_PARTIAL_ALIAS)? {
        args.push("--script-id".into());
        args.push(id);
    }
    on_progress(progress(0, "deploying", "running", ""));
    let deployed: Result<Deployed> = run_json(
        ctx,
        AddonCliRequest {
            args,
            secret_files: vec![("--write-key-file", key_hex.as_str())],
            stdin: &stdin,
            progress: true,
        },
        on_progress,
        0,
    );
    drop(stdin);
    let deployed = match deployed {
        Ok(v) => v,
        Err(e) => {
            // A project that exists but is not deployed: keep its id
            // so the next attempt goes into it.
            let text = e.to_string();
            if let Some(rest) = text.strip_prefix(&format!("{E_GOOGLE_PARTIAL}: script_id=")) {
                let id: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                    .collect();
                if !id.is_empty() {
                    custody_put(ctx, ACCOUNT_PARTIAL_ALIAS, id.as_bytes())?;
                }
            }
            on_progress(progress(0, "deploying", "failed", ""));
            return Err(e);
        }
    };
    on_progress(progress(0, "deploying", "ok", ""));
    let base = normalize_base(&deployed.url).map_err(|e| coded(E_GOOGLE_API, e))?;
    connect_with(ctx, &base, &key, on_progress)
}

// ---------------------------------------------------------------------
// A relay's switch
// ---------------------------------------------------------------------

/// The relay's row, with a slot and the account's key copied under the
/// row's own alias. A row left `building` by an earlier attempt keeps
/// its slot and takes the account's current key and address.
fn ensure_row(ctx: &WizardCtx, op: i64, base: &str, key: &[u8]) -> Result<AddonRow> {
    let row = match row_for(ctx, op)? {
        Some(r) => r,
        None => {
            let d = GoogleDetail {
                slot: new_slot(),
                ..Default::default()
            };
            let id = addons::insert(
                ctx,
                &NewAddon {
                    operator_id: op,
                    kind: Some(AddonKind::Google),
                    state: Some(AddonState::Building),
                    detail: Some(serde_json::to_value(&d).unwrap_or_default()),
                    ..Default::default()
                },
            )?;
            addons::get(ctx, id)?
        }
    };
    let mut d = detail_of(&row);
    if !valid_slot(&d.slot) {
        d.slot = new_slot();
    }
    let alias = addons::secret_alias(row.id, AddonKind::Google);
    // The key goes into custody before the row points at it; a custody
    // failure on a new row leaves no row behind.
    if let Err(e) = custody_put(ctx, &alias, key) {
        if row.state == AddonState::Building && detail_of(&row).url.is_empty() {
            let _ = addons::forget(ctx, row.id);
        }
        return Err(e);
    }
    addons::set_secret_alias(ctx, row.id, &alias)?;
    d.url = slot_url(base, key, &d.slot);
    d.deployment_id = deployment_id_of(base).unwrap_or_default();
    save_detail(ctx, row.id, &d)?;
    addons::get(ctx, row.id)
}

/// The relay's switch, on: a slot in the account's script, the slot's
/// address in the relay's mirror table, the first update sent and read
/// back the way a recipient fetches. Only then is the row `ready` («On»).
/// A failed send or read-back takes the address out of the table again
/// and leaves the row `building`: turning it on again is the retry.
pub fn turn_on(
    ctx: &WizardCtx,
    input: GoogleOnInput,
    on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<AddonRow> {
    let op = input.operator_id;
    let _ = ctx.db.get(op)?;
    if let Some(r) = row_for(ctx, op)? {
        if r.state == AddonState::Ready {
            return Ok(r);
        }
        if r.state == AddonState::Removing {
            return Err(WizardError::Validation(
                "turning this off has not finished; finish it first".into(),
            ));
        }
    }
    let (base, key) = connected_account(ctx)?;
    on_progress(progress(op, "slot", "running", ""));
    let row = ensure_row(ctx, op, &base, &key)?;
    drop(key);
    let url = detail_of(&row).url;
    let had_mirror = crate::freshness::has_appsscript_endpoint(ctx, op, &url);
    crate::freshness::set_appsscript_endpoint(ctx, op, &url)?;
    on_progress(progress(op, "slot", "ok", ""));
    let sent = first_payload(ctx, &row).and_then(|p| send(ctx, &row, &url, p, on_progress));
    match sent {
        Ok(c) if c.ok => {
            make_ready(ctx, &row)?;
            addons::get(ctx, row.id)
        }
        Ok(c) => {
            if !had_mirror {
                let _ = crate::freshness::remove_appsscript_endpoint(ctx, op);
            }
            Err(check_failed(&c.reason, &c.detail))
        }
        Err(e) => {
            if !had_mirror {
                let _ = crate::freshness::remove_appsscript_endpoint(ctx, op);
            }
            Err(e)
        }
    }
}

fn make_ready(ctx: &WizardCtx, row: &AddonRow) -> Result<()> {
    let d = detail_of(&addons::get(ctx, row.id)?);
    let mut ids = std::collections::BTreeMap::new();
    if !d.deployment_id.is_empty() {
        ids.insert("deployment_id".to_string(), d.deployment_id.clone());
    }
    if !d.slot.is_empty() {
        ids.insert("slot".to_string(), d.slot.clone());
    }
    addons::set_provider_ids(ctx, row.id, &ids)?;
    addons::set_state(ctx, row.id, AddonState::Ready)
}

pub fn check(
    ctx: &WizardCtx,
    input: GoogleCheckInput,
    on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<GoogleCheck> {
    let op = input.operator_id;
    let row = row_for(ctx, op)?
        .ok_or_else(|| WizardError::Validation("this relay has no Google update channel".into()))?;
    let d = detail_of(&row);
    let now = (ctx.clock)();
    if d.url.is_empty() || row.state != AddonState::Ready || d.posted_sha256.is_empty() {
        return Ok(GoogleCheck {
            ok: false,
            via_front: false,
            checked_at_unix: now,
            reason: "no_address".into(),
            detail: String::new(),
        });
    }
    on_progress(progress(op, "checking", "running", ""));
    let r: CliCheck = run_json(
        ctx,
        AddonCliRequest::args([
            "appsscript-check".to_string(),
            "--url".into(),
            d.url.clone(),
            "--expect-sha256".into(),
            d.posted_sha256.clone(),
        ]),
        on_progress,
        op,
    )?;
    let mut d = detail_of(&addons::get(ctx, row.id)?);
    d.last_check_at_unix = now;
    d.last_check_ok = r.ok;
    d.last_check_via_front = r.via_front;
    d.last_check_reason = r.reason.clone();
    save_detail(ctx, row.id, &d)?;
    on_progress(progress(
        op,
        "checking",
        if r.ok { "ok" } else { "failed" },
        &r.reason,
    ));
    Ok(GoogleCheck {
        ok: r.ok,
        via_front: r.via_front,
        checked_at_unix: now,
        reason: r.reason,
        detail: crate::freshness::redact_detail(&r.detail),
    })
}

/// Called by `addons::remove` (the relay's switch, off). Order (plan
/// §3.6): take the mirror out of the table and publish without it;
/// clear the relay's slot (its empty container); forget the row and the
/// relay's copy of the key. The account and its script stay.
///
/// If the slot cannot be cleared, the row stays (state `removing`) with
/// its key, so the same call is the retry: a forgotten key would leave a
/// slot nobody can clear.
pub fn remove(
    ctx: &WizardCtx,
    row: &AddonRow,
    on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<AddonRemoveReport> {
    let op = row.operator_id;
    let d = detail_of(row);
    let mut report = AddonRemoveReport {
        addon_id: row.id,
        ..Default::default()
    };
    on_progress(progress(op, "removing", "running", ""));
    addons::set_state(ctx, row.id, AddonState::Removing)?;

    let in_table = crate::freshness::remove_appsscript_endpoint(ctx, op)?;
    if in_table {
        // The document stops naming the channel. A publish that cannot
        // run (no pack URL yet, too few other mirrors) is not a reason
        // to keep a channel the publisher asked to remove.
        match crate::freshness::publish(ctx, op, &mut |_| {}) {
            Ok(r) if r.blocked_reason.is_empty() && r.succeeded >= r.min_mirrors => {}
            Ok(r) => report.warnings.push(if r.blocked_reason.is_empty() {
                "republish_failed".into()
            } else {
                format!("republish_blocked:{}", r.blocked_reason)
            }),
            Err(_) => report.warnings.push("republish_failed".into()),
        }
    }
    if crate::freshness::pack_names_appsscript(ctx, op) {
        // Files already handed out still list the channel until the
        // next signed pack; the empty container keeps that harmless.
        report.warnings.push("pack_still_names_channel".into());
    }

    if !d.url.is_empty() && row.has_secret {
        let seq = next_seq(ctx, op, &d)?;
        match send(ctx, row, &d.url, Payload::Empty { seq }, on_progress) {
            Ok(c) if c.ok || c.reason == "not_deployed" => {
                // not_deployed: the publisher already deleted the script.
            }
            Ok(c) => {
                on_progress(progress(op, "removing", "failed", &c.reason));
                report.warnings.push(format!("clear_failed:{}", c.reason));
                return Ok(report);
            }
            Err(e) => {
                on_progress(progress(op, "removing", "failed", ""));
                report.warnings.push("clear_failed".into());
                report
                    .warnings
                    .push(crate::freshness::redact_detail(&e.to_string()));
                return Ok(report);
            }
        }
    }
    addons::forget(ctx, row.id)?;
    report.removed = true;
    on_progress(progress(op, "removing", "ok", ""));
    Ok(report)
}

/// Called by `addons::before_relay_destroy`. The channel is free and
/// needs nothing of the relay's row, so it never keeps the relay: the
/// slot is cleared if it can be (best effort), and the row and key go
/// with the relay either way. Documents the script still holds are
/// signed and expire on their own.
pub fn on_relay_delete(ctx: &WizardCtx, row: &AddonRow) -> AddonOutcome {
    let d = detail_of(row);
    let mut out = AddonOutcome::removed(row);
    if d.url.is_empty() || !row.has_secret {
        return out;
    }
    let sent = next_seq(ctx, row.operator_id, &d)
        .and_then(|seq| send(ctx, row, &d.url, Payload::Empty { seq }, &mut |_| {}));
    match sent {
        Ok(c) if c.ok => {}
        Ok(c) => out.error = format!("the update channel was not cleared: {}", c.reason),
        Err(e) => {
            out.error = format!(
                "the update channel was not cleared: {}",
                crate::freshness::redact_detail(&e.to_string())
            )
        }
    }
    out
}

// ---------------------------------------------------------------------
// Desktop sign-in: loopback + PKCE in the system browser
// ---------------------------------------------------------------------

struct GotCode {
    code: Zeroizing<String>,
    verifier: Zeroizing<String>,
    redirect_uri: String,
}

/// Open the system browser on `url`. The URL is one this module built.
fn open_system_browser(url: &str) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    let mut cmd = {
        let mut c = std::process::Command::new("open");
        c.arg(url);
        c
    };
    #[cfg(target_os = "windows")]
    let mut cmd = {
        let mut c = std::process::Command::new("rundll32");
        c.arg("url.dll,FileProtocolHandler").arg(url);
        c
    };
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let mut cmd = {
        let mut c = std::process::Command::new("xdg-open");
        c.arg(url);
        c
    };
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map(|_| ())
}

fn pct(s: &str) -> String {
    let mut o = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

fn unpct(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let h = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
                out.push(u8::from_str_radix(h, 16).ok()?);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// The authorization URL for one attempt.
fn auth_url(c: &DesktopClient, redirect_uri: &str, challenge: &str, state: &str) -> String {
    format!(
        "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&code_challenge={}&code_challenge_method=S256&state={}&access_type=online&include_granted_scopes=false",
        c.auth_endpoint,
        pct(&c.id),
        pct(redirect_uri),
        pct(&SCOPES.join(" ")),
        challenge,
        state
    )
}

const PAGE_DONE: &str = "<!doctype html><meta charset=utf-8><title>Daal</title>\
<body style=\"font-family:sans-serif;max-width:32em;margin:3em auto;line-height:1.6\">\
<p>Signed in. You can go back to Daal now.</p>\
<p dir=\"rtl\" lang=\"fa\">وارد حساب شدید. به برنامهٔ دال برگردید.</p></body>";
const PAGE_CANCELLED: &str = "<!doctype html><meta charset=utf-8><title>Daal</title>\
<body style=\"font-family:sans-serif;max-width:32em;margin:3em auto;line-height:1.6\">\
<p>Sign-in was cancelled. You can close this tab.</p>\
<p dir=\"rtl\" lang=\"fa\">ورود لغو شد. این صفحه را ببندید.</p></body>";

fn respond(mut s: &TcpStream, status: &str, body: &str) {
    let _ = write!(
        s,
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = s.flush();
}

/// Run the desktop sign-in: a one-shot listener on 127.0.0.1, the
/// system browser on Google's consent page, and the code that comes
/// back, checked against the state this attempt made.
fn loopback_sign_in(
    c: &DesktopClient,
    open: &mut dyn FnMut(&str) -> std::io::Result<()>,
    wait: Duration,
) -> Result<GotCode> {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .map_err(|e| WizardError::Validation(format!("could not start the sign-in: {e}")))?;
    let port = listener
        .local_addr()
        .map_err(|e| WizardError::Validation(format!("could not start the sign-in: {e}")))?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{port}");
    let verifier = Zeroizing::new(random_b64(32)); // 43 characters
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let state = random_b64(16);
    open(&auth_url(c, &redirect_uri, &challenge, &state))
        .map_err(|e| WizardError::Validation(format!("could not open the browser: {e}")))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| WizardError::Validation(format!("sign-in: {e}")))?;
    let deadline = Instant::now() + wait;
    loop {
        if Instant::now() > deadline {
            return Err(coded(
                E_GOOGLE_SIGN_IN_CANCELLED,
                "the sign-in was not finished in time",
            ));
        }
        let (stream, _) = match listener.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(e) => return Err(WizardError::Validation(format!("sign-in: {e}"))),
        };
        let _ = stream.set_nonblocking(false);
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let mut buf = Zeroizing::new(vec![0u8; 8192]);
        let mut n = 0;
        let mut s = &stream;
        while n < buf.len() {
            match s.read(&mut buf[n..]) {
                Ok(0) => break,
                Ok(k) => {
                    n += k;
                    if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let head = String::from_utf8_lossy(&buf[..n]).into_owned();
        let head = Zeroizing::new(head);
        let target = head
            .lines()
            .next()
            .and_then(|l| l.strip_prefix("GET "))
            .and_then(|l| l.split(' ').next())
            .unwrap_or("");
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        if path != "/" {
            respond(&stream, "404 Not Found", "");
            continue;
        }
        let mut code = None;
        let mut got_state = None;
        let mut error = None;
        for kv in query.split('&') {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            match k {
                "code" => code = unpct(v).map(Zeroizing::new),
                "state" => got_state = unpct(v),
                "error" => error = unpct(v),
                _ => {}
            }
        }
        let state_ok = got_state
            .as_deref()
            .map(|g| bool::from(g.as_bytes().ct_eq(state.as_bytes())))
            .unwrap_or(false);
        if !state_ok {
            // Not this attempt's answer: ignore it and keep waiting.
            respond(&stream, "400 Bad Request", "");
            continue;
        }
        if let Some(e) = error {
            respond(&stream, "200 OK", PAGE_CANCELLED);
            return Err(coded(
                E_GOOGLE_SIGN_IN_CANCELLED,
                format!("Google answered {e}"),
            ));
        }
        match code {
            Some(code) if !code.is_empty() => {
                respond(&stream, "200 OK", PAGE_DONE);
                return Ok(GotCode {
                    code,
                    verifier,
                    redirect_uri,
                });
            }
            _ => {
                respond(&stream, "400 Bad Request", "");
                continue;
            }
        }
    }
}

#[cfg(test)]
#[path = "addon_google_tests.rs"]
mod tests;
