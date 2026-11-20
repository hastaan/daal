//! Add-on 3: an update channel through Google (docs/optional-addons-plan.md
//! §3, specs/optional-addons-v1.md §5).
//!
//! A tiny Apps Script web app that serves the `daal-refresh-v1`
//! container, updated by a plain HTTPS POST with a write key (never by
//! OAuth after setup). "Sign in with Google" (Path A) is used once, to
//! create and deploy the script, and its token is thrown away; the
//! by-hand path (Path B) ends in the same state.
//!
//! NOT BUILT YET. Owned by lane L-google-pub (item G3). Every function
//! here answers `E_NOT_BUILT`; the signatures, the Tauri commands that
//! call them (`src-tauri/src/lib.rs`, "optional add-ons") and their
//! TypeScript wrappers (`wizardCommands.ts`, `Addons`) are fixed, so
//! the lane fills in this file (and, for Android, the platform plugin's
//! `google_authorize`). The input and output types are this lane's to
//! change.
//!
//! Publishing an update is not a verb of its own: it runs inside the
//! existing freshness publish as one more backend (G2,
//! `publisher/deploy/freshness/backends/appsscript`). The `daal-deploy`
//! verbs this module will drive are `appsscript-script`,
//! `appsscript-deploy`, `appsscript-check` and `appsscript-clear`
//! (`publisher/deploy/cli/cli_addon_google.go`), through
//! `CliRunner::run_addon`.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::addons::{not_built, AddonOutcome, AddonProgress, AddonRemoveReport, AddonRow};
use crate::commands::{Result, WizardCtx};

/// The two OAuth scopes Path A asks for (plan §3.5), and nothing else.
pub const SCOPES: [&str; 2] = [
    "https://www.googleapis.com/auth/script.projects",
    "https://www.googleapis.com/auth/script.deployments",
];

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
    /// `api_not_enabled` | `not_deployed` | `wrong_content` |
    /// `unreachable` | "" when ok.
    #[serde(default)]
    pub reason: String,
}

pub fn script(
    _ctx: &WizardCtx,
    _input: GoogleScriptInput,
    _on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<GoogleScript> {
    Err(not_built("the Google update script"))
}

/// `mobile_token`: on Android the shell obtains a one-shot access token
/// from the platform plugin (`PlatformHandle::google_authorize`) and
/// hands it here; on desktop it is `None` and this module signs in
/// through the system browser (loopback + PKCE). Either way the token
/// is used for the four Apps Script API calls and dropped; nothing is
/// stored.
pub fn sign_in(
    _ctx: &WizardCtx,
    _input: GoogleSignInInput,
    _mobile_token: Option<Zeroizing<String>>,
    _on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<AddonRow> {
    Err(not_built("signing in with Google"))
}

pub fn attach(
    _ctx: &WizardCtx,
    _input: GoogleAttachInput,
    _on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<AddonRow> {
    Err(not_built("the Google update channel"))
}

pub fn check(
    _ctx: &WizardCtx,
    _input: GoogleCheckInput,
    _on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<GoogleCheck> {
    Err(not_built("the Google update channel check"))
}

/// Called by `addons::remove`. Order (plan §3.6): sign the mirror set
/// again without it and publish; POST an empty container; forget the
/// write key; tell the publisher to delete the project at
/// script.google.com.
pub fn remove(
    _ctx: &WizardCtx,
    _row: &AddonRow,
    _on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<AddonRemoveReport> {
    Err(not_built("removing the Google update channel"))
}

/// Called by `addons::before_relay_destroy`.
pub fn on_relay_delete(_ctx: &WizardCtx, row: &AddonRow) -> AddonOutcome {
    AddonOutcome::not_built(row)
}
