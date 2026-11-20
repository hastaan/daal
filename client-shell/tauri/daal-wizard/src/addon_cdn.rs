//! Add-on 2: a way in through Cloudflare (docs/optional-addons-plan.md
//! §2, specs/optional-addons-v1.md §4).
//!
//! The relay reachable through the publisher's own Cloudflare zone,
//! with ECH; one more signed route, tried last (decision D-2: no plain
//! hello fallback unless the publisher turns it on). No Worker (D-5).
//!
//! NOT BUILT YET. Owned by lane L-ui (item B-7, the shell half; it also
//! moves the older `provision_cdn_front` family out of `commands.rs`).
//! Every function here answers `E_NOT_BUILT`; the signatures, the Tauri
//! commands that call them (`src-tauri/src/lib.rs`, "optional
//! add-ons") and their TypeScript wrappers (`wizardCommands.ts`,
//! `Addons`) are fixed, so the lane fills in this file only. The input
//! and output types are this lane's to change.
//!
//! The older FRP-8 commands (`wizard_store_cloudflare_token`,
//! `wizard_provision_cdn_front`, `wizard_list_cdn_fronts`,
//! `wizard_verify_cdn_posture`) are left as they are until B-7 retires
//! them. The token stays under `commands::cloudflare_alias(id)`.
//!
//! The `daal-deploy` verbs it will drive are `cdn-token-check`,
//! `cdn-provision` (rewritten by B-3), `cdn-test`, `cdn-posture` and
//! `cdn-remove` (`publisher/deploy/cli/cli_addon_cdn.go`), through
//! `CliRunner::run_addon`.

use serde::{Deserialize, Serialize};

use crate::addons::{not_built, AddonOutcome, AddonProgress, AddonRemoveReport, AddonRow};
use crate::commands::{Result, WizardCtx};

/// `wizard_addon_cdn_set_token`: check a pasted Cloudflare token and,
/// when it is exactly what Daal needs, keep it in custody.
///
/// No `Debug`: the token must never reach a log line.
#[derive(Clone, Deserialize)]
pub struct CdnTokenInput {
    pub operator_id: i64,
    pub token: String,
}

/// What the token can see and do.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CdnTokenCheck {
    /// Zones the token can see (name only).
    pub zones: Vec<String>,
    /// `ok` | `too_broad` (can do more than the five permissions; refused,
    /// not stored) | `too_narrow` (a permission is missing) | `no_zone`.
    pub verdict: String,
    /// Stored in custody (only when `ok`).
    pub stored: bool,
}

/// `wizard_addon_cdn_build`: certificate, relay door, Cloudflare
/// settings, firewall, test from this phone. Rolls back on failure.
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
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CdnPosture {
    /// "Name hidden": ECH is on for the zone and the last test used it.
    pub name_hidden: Option<bool>,
    /// "Only Cloudflare can reach the door": AOP on and the firewall
    /// open to Cloudflare's ranges only.
    pub door_closed_to_others: Option<bool>,
    /// The last real handshake through the front from this device.
    pub last_test_at_unix: i64,
    pub last_test_ok: Option<bool>,
    /// Domain renewal date when the token can read it, else 0.
    pub renews_at_unix: i64,
    /// The relay was built before the CDN door existed: it needs a
    /// rebuild to gain it (plan §2.3).
    pub needs_rebuild: bool,
}

/// `wizard_addon_cdn_set_plain_fallback`: the signed per-pack flag that
/// lets the CDN route fall back to a plain hello (the zone name then
/// shows on the wire). Off by default (D-2).
#[derive(Debug, Clone, Deserialize)]
pub struct CdnPlainFallbackInput {
    pub operator_id: i64,
    pub allow: bool,
}

pub fn set_token(
    _ctx: &WizardCtx,
    _input: CdnTokenInput,
    _on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<CdnTokenCheck> {
    Err(not_built("the Cloudflare key check"))
}

pub fn build(
    _ctx: &WizardCtx,
    _input: CdnBuildInput,
    _on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<AddonRow> {
    Err(not_built("the way in through Cloudflare"))
}

pub fn posture(
    _ctx: &WizardCtx,
    _input: CdnPostureInput,
    _on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<CdnPosture> {
    Err(not_built("the Cloudflare check"))
}

pub fn set_plain_fallback(
    _ctx: &WizardCtx,
    _input: CdnPlainFallbackInput,
    _on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<AddonRow> {
    Err(not_built("the Cloudflare fallback setting"))
}

/// Called by `addons::remove`. Order (plan §2.6): sign again without the
/// route and publish; delete the DNS record and origin rule; revoke the
/// origin certificate; close the firewall rule; disable the inbound;
/// forget the token; tell the publisher to delete the token in
/// Cloudflare and that the domain keeps billing until cancelled.
pub fn remove(
    _ctx: &WizardCtx,
    _row: &AddonRow,
    _on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<AddonRemoveReport> {
    Err(not_built("removing the way in through Cloudflare"))
}

/// Called by `addons::before_relay_destroy`: the Cloudflare cleanup goes
/// before the server.
pub fn on_relay_delete(_ctx: &WizardCtx, row: &AddonRow) -> AddonOutcome {
    AddonOutcome::not_built(row)
}
