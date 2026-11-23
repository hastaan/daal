//! The add-on ledger: optional, per-relay extras a publisher turns on
//! after the relay exists (docs/optional-addons-plan.md, X1;
//! specs/optional-addons-v1.md §2).
//!
//! Five kinds: a standby address (`addon_standby`), a way in through
//! Cloudflare (`addon_cdn`), an update channel through Google
//! (`addon_google`), and the two update-note carriers, through GitHub
//! and through DNS (`addon_notes`). Each kind's module does the work; this one owns
//! the table (`relay_addons`, V019) and the plumbing every kind shares:
//!
//! * listing a relay's add-ons, for the Add-ons section;
//! * removing one, which hands the row to its kind;
//! * relay delete: each kind's teardown runs before the cloud leg, and
//!   an add-on that could not be taken down keeps the relay row (and
//!   so the credentials) for the retry, the way an address that could
//!   not be released does;
//! * forgetting: a row and its custody secret go together.
//!
//! The table holds no secret. An add-on's own secret (a Cloudflare
//! token, a script's write key) lives in device custody under
//! `secret_alias`; the publisher backup carries it through that column
//! (`publisher_backup::ALIAS_COLUMNS`) and `panic_wipe` finds it through
//! `OperatorDb::list_all_keystore_aliases`.
//!
//! Wave 0 builds only this ledger and the command surface. Every kind's
//! operation answers `E_NOT_BUILT` until its lane lands; nothing here
//! creates a row on its own.

use std::collections::BTreeMap;

use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::commands::{coded, Result, WizardCtx, WizardError, E_NOT_BUILT};
use crate::operator_db::DbError;

/// The Tauri event every add-on operation reports its steps on.
pub const PROGRESS_EVENT: &str = "wizard://addon-progress";

/// Which add-on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AddonKind {
    Standby,
    Cdn,
    Google,
    /// Updates through GitHub (`addon_notes`, V021).
    Gittag,
    /// Updates through DNS (`addon_notes`, V021).
    Dnsnote,
}

impl AddonKind {
    pub const ALL: [AddonKind; 5] = [
        AddonKind::Standby,
        AddonKind::Cdn,
        AddonKind::Google,
        AddonKind::Gittag,
        AddonKind::Dnsnote,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            AddonKind::Standby => "standby",
            AddonKind::Cdn => "cdn",
            AddonKind::Google => "google",
            AddonKind::Gittag => "gittag",
            AddonKind::Dnsnote => "dnsnote",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

/// Where an add-on is in its life. See V019 for what each means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AddonState {
    Building,
    Ready,
    Promoted,
    Removing,
}

impl AddonState {
    pub fn as_str(self) -> &'static str {
        match self {
            AddonState::Building => "building",
            AddonState::Ready => "ready",
            AddonState::Promoted => "promoted",
            AddonState::Removing => "removing",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        [
            AddonState::Building,
            AddonState::Ready,
            AddonState::Promoted,
            AddonState::Removing,
        ]
        .into_iter()
        .find(|k| k.as_str() == s)
    }
}

/// One row of `relay_addons`, as the UI sees it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AddonRow {
    pub id: i64,
    pub operator_id: i64,
    pub kind: AddonKind,
    pub state: AddonState,
    /// The provider's ids of what Daal created. Never a secret.
    pub provider_ids: BTreeMap<String, String>,
    /// What the provider bills each month, as read when it was made.
    /// 0 with an empty currency: nothing Daal knows of.
    pub monthly_cost_cents: i64,
    pub cost_currency: String,
    /// The add-on holds a secret in custody. The alias itself stays on
    /// this side.
    pub has_secret: bool,
    #[serde(skip)]
    pub secret_alias: String,
    /// Kind-specific, non-secret state; owned by the kind's module.
    pub detail: Value,
    pub created_at_unix: i64,
    pub updated_at_unix: i64,
}

/// What a kind's module writes when it starts building an add-on.
#[derive(Debug, Clone, Default)]
pub struct NewAddon {
    pub operator_id: i64,
    pub kind: Option<AddonKind>,
    pub state: Option<AddonState>,
    pub provider_ids: BTreeMap<String, String>,
    pub monthly_cost_cents: i64,
    pub cost_currency: String,
    pub secret_alias: String,
    pub detail: Option<Value>,
}

/// One step of an add-on operation, for the progress list.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AddonProgress {
    pub operator_id: i64,
    pub kind: AddonKind,
    /// A stable step word the UI translates (`renting`, `attaching`,
    /// `checking`, `signing`, `certificate`, `firewall`, `testing`, …).
    pub step: String,
    /// `running` | `ok` | `failed`.
    pub state: String,
    /// Provider or relay text, Details only. Never a token.
    #[serde(default)]
    pub detail: String,
}

/// What "Remove" did with one add-on.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct AddonRemoveReport {
    pub addon_id: i64,
    pub removed: bool,
    /// Things that may still bill, in the provider's words.
    #[serde(default)]
    pub still_billing: Vec<String>,
    /// What the publisher must still do by hand (delete the token in
    /// Cloudflare, delete the script project, cancel the domain), as
    /// stable words the UI translates.
    #[serde(default)]
    pub by_hand: Vec<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// What relay delete did with one add-on (`DestroyReport::addons`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AddonOutcome {
    pub addon_id: i64,
    pub kind: AddonKind,
    /// Taken down, and its row and secret are gone.
    pub removed: bool,
    /// Something of it is still there and only this relay's row holds
    /// what removes it: the relay must not be forgotten yet.
    pub keeps_relay: bool,
    /// `removed` | `not_built` | `failed` | `left` (a local-only removal
    /// that never asked the provider: it keeps running and billing).
    pub code: String,
    /// Provider text, Details only.
    #[serde(default)]
    pub error: String,
}

impl AddonOutcome {
    pub fn removed(row: &AddonRow) -> Self {
        Self {
            addon_id: row.id,
            kind: row.kind,
            removed: true,
            keeps_relay: false,
            code: "removed".into(),
            error: String::new(),
        }
    }

    /// The kind's teardown is not built: keep the relay, and with it
    /// what would remove the add-on later.
    pub fn not_built(row: &AddonRow) -> Self {
        Self {
            addon_id: row.id,
            kind: row.kind,
            removed: false,
            keeps_relay: true,
            code: "not_built".into(),
            error: String::new(),
        }
    }
}

/// The stable refusal of an add-on operation whose lane has not landed.
pub fn not_built(what: &str) -> WizardError {
    coded(E_NOT_BUILT, format!("{what} is not built yet"))
}

/// The conventional custody alias for an add-on's secret.
pub fn secret_alias(addon_id: i64, kind: AddonKind) -> String {
    format!("daal.addon.{addon_id}.{}", kind.as_str())
}

// ---------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------

const COLUMNS: &str = "id, operator_id, kind, state, provider_ids_json, monthly_cost_cents, \
                       cost_currency, secret_alias, detail_json, created_at_unix, updated_at_unix";

fn row_from(r: &rusqlite::Row<'_>) -> rusqlite::Result<AddonRow> {
    let kind: String = r.get(2)?;
    let state: String = r.get(3)?;
    let ids: String = r.get(4)?;
    let alias: String = r.get(7)?;
    let detail: String = r.get(8)?;
    let bad = |what: &str, v: &str| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            format!("relay_addons: unknown {what} {v:?}").into(),
        )
    };
    Ok(AddonRow {
        id: r.get(0)?,
        operator_id: r.get(1)?,
        kind: AddonKind::parse(&kind).ok_or_else(|| bad("kind", &kind))?,
        state: AddonState::parse(&state).ok_or_else(|| bad("state", &state))?,
        provider_ids: serde_json::from_str(&ids).unwrap_or_default(),
        monthly_cost_cents: r.get(5)?,
        cost_currency: r.get(6)?,
        has_secret: !alias.is_empty(),
        secret_alias: alias,
        detail: serde_json::from_str(&detail).unwrap_or_else(|_| Value::Object(Default::default())),
        created_at_unix: r.get(9)?,
        updated_at_unix: r.get(10)?,
    })
}

fn db_err(e: rusqlite::Error) -> WizardError {
    WizardError::Db(DbError::Sqlite(e))
}

/// Start a row. Refuses a second live add-on of the same kind on one
/// relay (a promoted standby does not count) and a relay that does not
/// exist.
pub fn insert(ctx: &WizardCtx, new: &NewAddon) -> Result<i64> {
    let kind = new
        .kind
        .ok_or_else(|| WizardError::Validation("add-on: kind required".into()))?;
    let state = new.state.unwrap_or(AddonState::Building);
    let _ = ctx.db.get(new.operator_id)?;
    let ids = serde_json::to_string(&new.provider_ids).unwrap_or_else(|_| "{}".into());
    let detail = new
        .detail
        .as_ref()
        .map(|d| d.to_string())
        .unwrap_or_else(|| "{}".into());
    let now = (ctx.clock)();
    ctx.db.with_conn(|c| {
        let live: Option<i64> = c
            .query_row(
                "SELECT id FROM relay_addons
                  WHERE operator_id = ?1 AND kind = ?2 AND state <> 'promoted'",
                params![new.operator_id, kind.as_str()],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_err)?;
        if live.is_some() {
            return Err(WizardError::Validation(format!(
                "add-on: this relay already has a {} add-on",
                kind.as_str()
            )));
        }
        c.execute(
            "INSERT INTO relay_addons (operator_id, kind, state, provider_ids_json,
                 monthly_cost_cents, cost_currency, secret_alias, detail_json,
                 created_at_unix, updated_at_unix)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)",
            params![
                new.operator_id,
                kind.as_str(),
                state.as_str(),
                ids,
                new.monthly_cost_cents.max(0),
                new.cost_currency,
                new.secret_alias,
                detail,
                now
            ],
        )
        .map_err(db_err)?;
        Ok(c.last_insert_rowid())
    })
}

/// One row, or `Validation` when there is none.
pub fn get(ctx: &WizardCtx, addon_id: i64) -> Result<AddonRow> {
    ctx.db
        .with_conn(|c| {
            c.query_row(
                &format!("SELECT {COLUMNS} FROM relay_addons WHERE id = ?1"),
                params![addon_id],
                row_from,
            )
            .optional()
        })
        .map_err(db_err)?
        .ok_or_else(|| WizardError::Validation(format!("add-on {addon_id} does not exist")))
}

fn rows_for(ctx: &WizardCtx, operator_id: i64) -> Result<Vec<AddonRow>> {
    ctx.db
        .with_conn(|c| -> rusqlite::Result<Vec<AddonRow>> {
            let mut s = c.prepare(&format!(
                "SELECT {COLUMNS} FROM relay_addons WHERE operator_id = ?1 ORDER BY id"
            ))?;
            let rows = s.query_map(params![operator_id], row_from)?;
            rows.collect()
        })
        .map_err(db_err)
}

/// `wizard_addons_list`: a relay's add-ons, oldest first. Read-only;
/// touches no secret and no network.
pub fn list(ctx: &WizardCtx, operator_id: i64) -> Result<Vec<AddonRow>> {
    let _ = ctx.db.get(operator_id)?;
    rows_for(ctx, operator_id)
}

fn update(ctx: &WizardCtx, addon_id: i64, sql: &str, value: &dyn rusqlite::ToSql) -> Result<()> {
    let now = (ctx.clock)();
    let n = ctx
        .db
        .with_conn(|c| c.execute(sql, params![addon_id, value, now]))
        .map_err(db_err)?;
    if n == 0 {
        return Err(WizardError::Validation(format!("add-on {addon_id} does not exist")));
    }
    Ok(())
}

pub fn set_state(ctx: &WizardCtx, addon_id: i64, state: AddonState) -> Result<()> {
    update(
        ctx,
        addon_id,
        "UPDATE relay_addons SET state = ?2, updated_at_unix = ?3 WHERE id = ?1",
        &state.as_str(),
    )
}

pub fn set_provider_ids(ctx: &WizardCtx, addon_id: i64, ids: &BTreeMap<String, String>) -> Result<()> {
    let j = serde_json::to_string(ids).unwrap_or_else(|_| "{}".into());
    update(
        ctx,
        addon_id,
        "UPDATE relay_addons SET provider_ids_json = ?2, updated_at_unix = ?3 WHERE id = ?1",
        &j,
    )
}

pub fn set_detail(ctx: &WizardCtx, addon_id: i64, detail: &Value) -> Result<()> {
    update(
        ctx,
        addon_id,
        "UPDATE relay_addons SET detail_json = ?2, updated_at_unix = ?3 WHERE id = ?1",
        &detail.to_string(),
    )
}

pub fn set_secret_alias(ctx: &WizardCtx, addon_id: i64, alias: &str) -> Result<()> {
    update(
        ctx,
        addon_id,
        "UPDATE relay_addons SET secret_alias = ?2, updated_at_unix = ?3 WHERE id = ?1",
        &alias,
    )
}

/// Drop a row and forget its secret. The row goes first: a failed
/// delete leaves the secret in place for the retry, a forgotten secret
/// with its row still there would be an add-on nothing can remove.
/// Idempotent.
pub fn forget(ctx: &WizardCtx, addon_id: i64) -> Result<()> {
    let row = match get(ctx, addon_id) {
        Ok(r) => r,
        Err(WizardError::Validation(_)) => return Ok(()),
        Err(e) => return Err(e),
    };
    ctx.db
        .with_conn(|c| c.execute("DELETE FROM relay_addons WHERE id = ?1", params![addon_id]))
        .map_err(db_err)?;
    if !row.secret_alias.is_empty() {
        let _ = ctx.custody.forget(&row.secret_alias);
        let _ = ctx.keystore.forget(&row.secret_alias);
    }
    Ok(())
}

/// The custody aliases a relay's add-ons hold. Read before the relay row
/// goes (the rows go with it, by cascade).
pub fn secret_aliases(ctx: &WizardCtx, operator_id: i64) -> Vec<String> {
    rows_for(ctx, operator_id)
        .unwrap_or_default()
        .into_iter()
        .filter(|r| !r.secret_alias.is_empty())
        .map(|r| r.secret_alias)
        .collect()
}

// ---------------------------------------------------------------------
// Plumbing shared by every kind
// ---------------------------------------------------------------------

/// `wizard_addon_remove`: take one add-on down. The kind's module does
/// it in its own order (sign the pack again without it and publish
/// first, then the provider, then [`forget`]).
pub fn remove(
    ctx: &WizardCtx,
    addon_id: i64,
    on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<AddonRemoveReport> {
    let row = get(ctx, addon_id)?;
    match row.kind {
        AddonKind::Standby => crate::addon_standby::remove(ctx, &row, on_progress),
        AddonKind::Cdn => crate::addon_cdn::remove(ctx, &row, on_progress),
        AddonKind::Google => crate::addon_google::remove(ctx, &row, on_progress),
        AddonKind::Gittag | AddonKind::Dnsnote => crate::addon_notes::remove(ctx, &row, on_progress),
    }
}

/// Relay delete, cloud path: take every add-on down before the server
/// goes. Each kind answers for its own; one that is taken down has its
/// row and secret forgotten here. Never fails as a whole: an outcome per
/// add-on, and the caller keeps the relay when any says `keeps_relay`.
pub fn before_relay_destroy(ctx: &WizardCtx, operator_id: i64) -> Result<Vec<AddonOutcome>> {
    let mut out = Vec::new();
    for row in rows_for(ctx, operator_id)? {
        let o = match row.kind {
            AddonKind::Standby => crate::addon_standby::on_relay_delete(ctx, &row),
            AddonKind::Cdn => crate::addon_cdn::on_relay_delete(ctx, &row),
            AddonKind::Google => crate::addon_google::on_relay_delete(ctx, &row),
            AddonKind::Gittag | AddonKind::Dnsnote => crate::addon_notes::on_relay_delete(ctx, &row),
        };
        if o.removed {
            if let Err(e) = forget(ctx, row.id) {
                out.push(AddonOutcome {
                    keeps_relay: false,
                    error: e.to_string(),
                    ..o
                });
                continue;
            }
        }
        out.push(o);
    }
    Ok(out)
}

/// Relay delete, local-only path ("forget it here, leave the server"):
/// nothing is asked of any provider, so every add-on is `left` running.
/// The caller forgets the rows with the relay.
pub fn left_by_local_removal(ctx: &WizardCtx, operator_id: i64) -> Vec<AddonOutcome> {
    rows_for(ctx, operator_id)
        .unwrap_or_default()
        .into_iter()
        .map(|r| AddonOutcome {
            addon_id: r.id,
            kind: r.kind,
            removed: false,
            keeps_relay: false,
            code: "left".into(),
            error: String::new(),
        })
        .collect()
}

#[cfg(test)]
#[path = "addons_tests.rs"]
mod tests;
