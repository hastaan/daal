//! Add-on 3: an update channel through Google (docs/optional-addons-plan.md
//! §3, specs/optional-addons-v1.md §5).
//!
//! A tiny Apps Script web app that serves the `daal-refresh-v1`
//! container, updated by a plain HTTPS POST with a write key (never by
//! OAuth after setup). "Sign in with Google" (Path A) is used once, to
//! create and deploy the script, and its token is thrown away; the
//! by-hand path (Path B) ends in the same state: the same script, a URL
//! in the freshness endpoint table (kind `appsscript`) and the write key
//! in device custody.
//!
//! # What is stored where
//!
//! * The **write key** (32 random bytes) is this add-on's one secret. It
//!   lives in device custody under the row's `secret_alias`
//!   (`daal.addon.<id>.google`), like every other publisher secret, and
//!   is carried by the backup through that column. It reaches
//!   `daal-deploy` only as a 0600 temp file (`--write-key-file`), never
//!   argv, a log line or a progress event. The freshness endpoint row
//!   for the channel holds no alias of its own: one secret, one owner.
//! * The **path token** (`k`, 16 random bytes) and the URL are public:
//!   every pack carries them. They are in `detail_json`.
//! * **No Google token is stored.** On Android the shell gets a one-shot
//!   access token from Play services (`PlatformHandle::google_authorize`)
//!   and hands it to [`sign_in`]; on desktop [`sign_in`] runs the
//!   loopback + PKCE sign-in in the system browser and hands the code
//!   and verifier over. Either goes to `appsscript-deploy` on stdin,
//!   which makes the four Apps Script API calls, revokes the token and
//!   zeroes it. This side holds the token in a `Zeroizing` buffer for
//!   the length of that one call.
//!
//! # OAuth clients (owner prerequisite, plan §3.5)
//!
//! The client ids are build-time configuration:
//! `DAAL_GOOGLE_DESKTOP_CLIENT_ID` and `DAAL_GOOGLE_DESKTOP_CLIENT_SECRET`
//! (a "Desktop app" client; Google says its secret is not confidential)
//! for desktop, and `DAAL_GOOGLE_ANDROID_CLIENT_ID` for Android (the
//! Play services client is matched by package name and signing SHA-1;
//! the id only proves the owner registered one, and gates the button).
//! A build without them answers `E_GOOGLE_NOT_CONFIGURED`; Path B always
//! works.
//!
//! Publishing an update is not a verb of its own: it runs inside the
//! freshness publish as one more mirror. `freshness::publish` hands
//! `publish-freshness` the channel's address and write key
//! (`--appsscript-url`, `--appsscript-write-key-file`, and the signed
//! pack as `--appsscript-pack-file`), and the helper's `appsscript`
//! backend POSTs the container and fetches it back like any other
//! mirror.

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
/// created the Google Cloud project yet). Path B still works.
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
/// The channel was set up but the POST or fetch-back did not work. The
/// tail starts with the reason word ([`GoogleCheck::reason`]).
pub const E_GOOGLE_CHECK_FAILED: &str = "E_GOOGLE_CHECK_FAILED";

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

/// `wizard_addon_google_script` (Path B): the script to paste, with
/// this relay's write key already in it.
#[derive(Debug, Clone, Deserialize)]
pub struct GoogleScriptInput {
    pub operator_id: i64,
}

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

/// `wizard_addon_google_sign_in` (Path A): sign in once, create and
/// deploy the script, throw the token away, POST the current container
/// and fetch it back the way a recipient would.
#[derive(Debug, Clone, Deserialize)]
pub struct GoogleSignInInput {
    pub operator_id: i64,
}

/// `wizard_addon_google_attach` (Path B): the web-app address pasted
/// back. Checked for shape, POSTed to, fetched back.
#[derive(Debug, Clone, Deserialize)]
pub struct GoogleAttachInput {
    pub operator_id: i64,
    pub url: String,
}

/// `wizard_addon_google_check`: fetch the container back again.
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
    /// else) | `unreachable` | `no_address` (the channel has no address
    /// yet) | "" when ok. `api_not_enabled` is an error of sign-in
    /// ([`E_GOOGLE_API_NOT_ENABLED`]), not of a check.
    #[serde(default)]
    pub reason: String,
}

/// Kind-specific state of the row (`detail_json`). Nothing secret.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct GoogleDetail {
    /// The `k` of the /exec URL.
    #[serde(default)]
    pub path_token: String,
    /// "A" (signed in) | "B" (by hand) | "" (not set up yet).
    #[serde(default)]
    pub path: String,
    /// The mirror URL, `?k=` included; "" until set up.
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub script_id: String,
    #[serde(default)]
    pub deployment_id: String,
    /// A project a failed Path A attempt created; the next attempt
    /// resumes into it, and removal names it.
    #[serde(default)]
    pub partial_script_id: String,
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

/// What `appsscript-check` / `appsscript-clear` print.
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

/// The relay's row, made on first use with a fresh write key in
/// custody and a fresh path token. The key goes into custody before the
/// row points at it; a custody failure leaves no row behind.
fn ensure_row(ctx: &WizardCtx, op: i64) -> Result<AddonRow> {
    if let Some(r) = row_for(ctx, op)? {
        if r.has_secret {
            return Ok(r);
        }
    }
    let row = match row_for(ctx, op)? {
        Some(r) => r,
        None => {
            let d = GoogleDetail {
                path_token: random_b64(16),
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
    let alias = addons::secret_alias(row.id, AddonKind::Google);
    let mut key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(key.as_mut());
    if let Err(e) = custody_put(ctx, &alias, key.as_ref()) {
        let _ = addons::forget(ctx, row.id);
        return Err(e);
    }
    addons::set_secret_alias(ctx, row.id, &alias)?;
    addons::get(ctx, row.id)
}

/// The write key as the 64 hex characters `--write-key-file` takes.
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

/// The next update number nobody has used: past the freshness
/// counter, the clock and the last update the script took. Recorded in
/// the freshness counter at once, so the next signed document is
/// numbered past it (the script refuses an older number).
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

/// What to send: the document (and pack), or the empty container under
/// a fresh number.
enum Payload {
    Document { doc: PathBuf, pack: Option<PathBuf> },
    Empty { seq: u64 },
}

/// POST one update and fetch it back. Records what the script now
/// holds in the row.
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
    })
}

/// The update that goes first on a new channel: the last signed
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
// Commands
// ---------------------------------------------------------------------

pub fn script(
    ctx: &WizardCtx,
    input: GoogleScriptInput,
    on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<GoogleScript> {
    let op = input.operator_id;
    let row = ensure_row(ctx, op)?;
    let d = detail_of(&row);
    let key = write_key_hex(ctx, &row)?;
    on_progress(progress(op, "script", "running", ""));
    let s: GoogleScript = run_json(
        ctx,
        AddonCliRequest {
            args: vec![
                "appsscript-script".into(),
                "--path-token".into(),
                d.path_token,
            ],
            secret_files: vec![("--write-key-file", key.as_str())],
            stdin: &[],
            progress: false,
        },
        on_progress,
        op,
    )?;
    on_progress(progress(op, "script", "ok", ""));
    Ok(s)
}

/// `mobile_token`: on Android the shell obtains a one-shot access token
/// from the platform plugin (`PlatformHandle::google_authorize`) and
/// hands it here; on desktop it is `None` and this module signs in
/// through the system browser (loopback + PKCE). Either way the token
/// is used for the four Apps Script API calls and dropped; nothing is
/// stored.
pub fn sign_in(
    ctx: &WizardCtx,
    input: GoogleSignInInput,
    mobile_token: Option<Zeroizing<String>>,
    on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<AddonRow> {
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
    sign_in_with(
        ctx,
        input,
        auth,
        &mut open_system_browser,
        SIGN_IN_WAIT,
        on_progress,
    )
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
    script_id: String,
    deployment_id: String,
    url: String,
}

pub(crate) fn sign_in_with(
    ctx: &WizardCtx,
    input: GoogleSignInInput,
    auth: SignIn,
    open: &mut dyn FnMut(&str) -> std::io::Result<()>,
    wait: Duration,
    on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<AddonRow> {
    let op = input.operator_id;
    let row = ensure_row(ctx, op)?;
    let mut d = detail_of(&row);
    let key = write_key_hex(ctx, &row)?;

    on_progress(progress(op, "signing_in", "running", ""));
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
                    on_progress(progress(op, "signing_in", "failed", ""));
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
    on_progress(progress(op, "signing_in", "ok", ""));

    let mut args = vec![
        "appsscript-deploy".to_string(),
        "--path-token".into(),
        d.path_token.clone(),
        "--title".into(),
        PROJECT_TITLE.into(),
    ];
    if !d.partial_script_id.is_empty() {
        args.push("--script-id".into());
        args.push(d.partial_script_id.clone());
    }
    on_progress(progress(op, "deploying", "running", ""));
    let deployed: Result<Deployed> = run_json(
        ctx,
        AddonCliRequest {
            args,
            secret_files: vec![("--write-key-file", key.as_str())],
            stdin: &stdin,
            progress: true,
        },
        on_progress,
        op,
    );
    drop(stdin);
    let deployed = match deployed {
        Ok(v) => v,
        Err(e) => {
            // A project that exists but is not deployed: keep its id
            // so the next attempt goes into it, and removal names it.
            let text = e.to_string();
            if let Some(rest) = text.strip_prefix(&format!("{E_GOOGLE_PARTIAL}: script_id=")) {
                let id: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                    .collect();
                if !id.is_empty() {
                    d.partial_script_id = id;
                    save_detail(ctx, row.id, &d)?;
                }
            }
            on_progress(progress(op, "deploying", "failed", ""));
            return Err(e);
        }
    };
    on_progress(progress(op, "deploying", "ok", ""));
    let url = crate::freshness::normalize_appsscript_url(&deployed.url, &d.path_token)
        .map_err(|e| coded(E_GOOGLE_API, e))?;
    d.path = "A".into();
    d.script_id = deployed.script_id;
    d.deployment_id = deployed.deployment_id;
    d.partial_script_id.clear();
    d.url = url.clone();
    save_detail(ctx, row.id, &d)?;
    finish_setup(ctx, &addons::get(ctx, row.id)?, &url, on_progress)
}

pub fn attach(
    ctx: &WizardCtx,
    input: GoogleAttachInput,
    on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<AddonRow> {
    let op = input.operator_id;
    let row = match row_for(ctx, op)? {
        Some(r) if r.has_secret => r,
        _ => {
            return Err(WizardError::Validation(
                "copy the script first: it carries this relay's write key".into(),
            ))
        }
    };
    let mut d = detail_of(&row);
    let url = crate::freshness::normalize_appsscript_url(&input.url, &d.path_token)
        .map_err(|e| coded(E_GOOGLE_BAD_ADDRESS, e))?;
    if d.path.is_empty() {
        d.path = "B".into();
    }
    d.url = url.clone();
    if let Some(id) = deployment_id_of(&url) {
        d.deployment_id = id;
    }
    save_detail(ctx, row.id, &d)?;
    finish_setup(ctx, &addons::get(ctx, row.id)?, &url, on_progress)
}

fn deployment_id_of(url: &str) -> Option<String> {
    let rest = url.strip_prefix("https://script.google.com/macros/s/")?;
    Some(rest.split('/').next()?.to_string())
}

/// Both paths end here: POST the first update, fetch it back, and only
/// when that worked put the URL in the mirror table and call the
/// channel ready. A failed check leaves the row building with its URL,
/// so `check` can finish it later without a second setup.
fn finish_setup(
    ctx: &WizardCtx,
    row: &AddonRow,
    url: &str,
    on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<AddonRow> {
    let payload = first_payload(ctx, row)?;
    let c = send(ctx, row, url, payload, on_progress)?;
    if !c.ok {
        return Err(coded(
            E_GOOGLE_CHECK_FAILED,
            format!("{}: the script did not answer as it should", c.reason),
        ));
    }
    make_ready(ctx, row, url)?;
    addons::get(ctx, row.id)
}

fn make_ready(ctx: &WizardCtx, row: &AddonRow, url: &str) -> Result<()> {
    crate::freshness::set_appsscript_endpoint(ctx, row.operator_id, url)?;
    let d = detail_of(&addons::get(ctx, row.id)?);
    let mut ids = std::collections::BTreeMap::new();
    if !d.script_id.is_empty() {
        ids.insert("script_id".to_string(), d.script_id.clone());
    }
    if !d.deployment_id.is_empty() {
        ids.insert("deployment_id".to_string(), d.deployment_id.clone());
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
    if d.url.is_empty() {
        return Ok(GoogleCheck {
            ok: false,
            via_front: false,
            checked_at_unix: now,
            reason: "no_address".into(),
        });
    }
    if row.state == AddonState::Building || d.posted_sha256.is_empty() {
        // Set up but never confirmed: this is the retry of the setup.
        let c = send(ctx, &row, &d.url, first_payload(ctx, &row)?, on_progress)?;
        if c.ok && row.state == AddonState::Building {
            make_ready(ctx, &row, &d.url)?;
        }
        return Ok(c);
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
    })
}

/// Called by `addons::remove`. Order (plan §3.6): take the mirror out of
/// the table and publish without it; POST the empty container; forget
/// the row and the write key; tell the publisher to delete the project
/// at script.google.com (Daal holds no token to do it).
///
/// If the empty container cannot be sent, the row stays (state
/// `removing`) with its key, so the same call is the retry: a forgotten
/// key would leave a channel nobody can clear.
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
                // not_deployed: the publisher already deleted it.
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
    if !d.script_id.is_empty() || !d.partial_script_id.is_empty() || !d.url.is_empty() {
        report.by_hand.push("delete_google_project".into());
    }
    report.removed = true;
    on_progress(progress(op, "removing", "ok", ""));
    Ok(report)
}

/// Called by `addons::before_relay_destroy`. The channel is free and
/// needs nothing of the relay's row, so it never keeps the relay: the
/// empty container is sent if it can be (best effort), and the row and
/// key go with the relay either way. Documents the script still holds
/// are signed and expire on their own.
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
