//! Add-on 1: a standby address (docs/optional-addons-plan.md §1,
//! specs/optional-addons-v1.md §3).
//!
//! A second Hetzner Floating IPv4, attached to the relay from the start
//! and kept back; the signed pack carries only a commitment to it
//! (sealed, the default) or the address itself (open, only when no
//! Everyone file exists — decision D-1).
//!
//! NOT BUILT YET. Owned by lane L-standby-pub (item S6). Every function
//! here answers `E_NOT_BUILT`; the signatures, the Tauri commands that
//! call them (`src-tauri/src/lib.rs`, "optional add-ons") and their
//! TypeScript wrappers (`wizardCommands.ts`, `Addons`) are fixed, so
//! the lane fills in this file only. The input and output types are
//! this lane's to change: the shell passes them through whole.
//!
//! The `daal-deploy` verbs it will drive are `standby price | add |
//! promote | remove` (`publisher/deploy/cli/cli_addon_standby.go`),
//! through `CliRunner::run_addon`.

use serde::{Deserialize, Serialize};

use crate::addons::{not_built, AddonOutcome, AddonProgress, AddonRemoveReport, AddonRow};
use crate::commands::{Result, WizardCtx};

/// `wizard_addon_standby_price`.
#[derive(Debug, Clone, Deserialize)]
pub struct StandbyPriceInput {
    pub operator_id: i64,
}

/// The monthly price of one Floating IPv4 in the relay's location, read
/// live from the hosting company (the confirm sheet shows it).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StandbyPrice {
    pub monthly_cents: i64,
    /// ISO 4217, e.g. "EUR".
    pub currency: String,
    /// Whether `monthly_cents` includes VAT. Hetzner quotes both; the
    /// card says "plus tax" when false.
    pub vat_included: bool,
}

/// `wizard_addon_standby_add`: rent, attach, check over the new
/// address, sign. Rolls back what it created on any failure.
#[derive(Debug, Clone, Deserialize)]
pub struct StandbyAddInput {
    pub operator_id: i64,
    /// "sealed" (default) | "open". Open is refused while the relay has
    /// an Everyone file (D-1).
    #[serde(default)]
    pub mode: String,
}

/// `wizard_addon_standby_promote`: "Switch to standby".
#[derive(Debug, Clone, Deserialize)]
pub struct StandbyPromoteInput {
    pub operator_id: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StandbyPromoteResult {
    pub addon: AddonRow,
    /// The 26-character standby key, grouped for reading aloud
    /// (specs/relaypack-v1.md `_standby`). Not a secret once sent.
    pub key: String,
    /// The pack signed with the standby as its address reached enough
    /// refresh addresses.
    pub refresh_note_published: bool,
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// `wizard_addon_standby_key`: show the key again after the sheet that
/// first showed it was closed.
#[derive(Debug, Clone, Deserialize)]
pub struct StandbyKeyInput {
    pub operator_id: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StandbyKey {
    pub key: String,
}

pub fn price(
    _ctx: &WizardCtx,
    _input: StandbyPriceInput,
    _on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<StandbyPrice> {
    Err(not_built("the standby address price"))
}

pub fn add(
    _ctx: &WizardCtx,
    _input: StandbyAddInput,
    _on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<AddonRow> {
    Err(not_built("renting a standby address"))
}

pub fn promote(
    _ctx: &WizardCtx,
    _input: StandbyPromoteInput,
    _on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<StandbyPromoteResult> {
    Err(not_built("switching to the standby address"))
}

pub fn key(
    _ctx: &WizardCtx,
    _input: StandbyKeyInput,
    _on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<StandbyKey> {
    Err(not_built("the standby key"))
}

/// Called by `addons::remove`. Order (plan §1.6): sign again without
/// `_standby` and publish, then unbind on the box, then delete the
/// Floating IP, then `addons::forget`.
pub fn remove(
    _ctx: &WizardCtx,
    _row: &AddonRow,
    _on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<AddonRemoveReport> {
    Err(not_built("removing the standby address"))
}

/// Called by `addons::before_relay_destroy`. The Floating IP is also
/// released by `decommission --release-addresses` once the record names
/// it (S3); this answers for the row.
pub fn on_relay_delete(_ctx: &WizardCtx, row: &AddonRow) -> AddonOutcome {
    AddonOutcome::not_built(row)
}
