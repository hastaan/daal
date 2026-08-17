//! High-level wizard command surface.
//!
//! These functions are the operations the Tauri command bindings
//! call (FRP-5 commit 4 wires the `#[tauri::command]` shims). Each
//! function takes a [`WizardCtx`] holding the dependencies — DB,
//! keystore, CLI runner — so unit tests can substitute mocks.
//!
//! ## Custody
//!
//! Publisher secrets — the Ed25519 signing key, the cloud-provider
//! token, the Cloudflare token — live under [`DeviceCustody`]. **No
//! function in this module takes a PIN.** `ctx.keystore` survives
//! only as the reader for the one-time PIN→custody migration
//! ([`migrate_from_pin`]) and for `forget()` on teardown; see the
//! header of `keystore.rs`.
//!
//! At FRP-5 ship the LIVE operations are:
//!
//!   - `store_cloud_token`
//!   - `pricing_lookup`
//!   - `select_profile`
//!   - `publisher_keygen`
//!   - `publisher_keyimport`
//!   - `finalize_pre_provision`
//!   - `list_operators`
//!   - `cancel_and_cleanup`
//!
//! FRP-4b adds the live cloud-mutating + signing operations:
//!
//!   - `provision_run`     — call daal-deploy provision; flip status.
//!   - `sign_relaypack`    — call daal-deploy bind-and-sign.
//!   - `qr_render`         — call daal-deploy qr-fountain; stream frames.
//!
//! The Tauri shims forward each ProgressEvent emitted by the CLI
//! to the wizard frontend via `app.emit()` (commit 5/6).

use std::path::PathBuf;
use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::cli_bridge::{
    AssignFipArgs, BindAndSignArgs, BindResult, CdnProvisionArgs, CdnRotateHostnameArgs,
    CdnRotateOriginArgs, CdnRotatePathArgs, CdnRotateResult, CliRunner, DecommissionArgs,
    DecommissionResult, FountainFrame, Pricing, ProgressEvent, ProvisionArgs,
    PublishFreshnessArgs, ReprovisionArgs,
};
use crate::device_custody::{CustodyError, DeviceCustody};
use crate::keystore::{Keystore, KeystoreError};
use crate::operator_db::{CdnFrontRow, DbError, OperatorDb, OperatorRow, SubkeyRow};
use crate::publisher_key::{self, Fingerprint, KeyError};
use crate::staging::{self, PreProvisionRecord, StagingError};

#[derive(Debug, Error)]
pub enum WizardError {
    #[error(transparent)]
    Db(#[from] DbError),
    #[error(transparent)]
    Keystore(#[from] KeystoreError),
    #[error(transparent)]
    Key(#[from] KeyError),
    #[error(transparent)]
    Staging(#[from] StagingError),
    #[error("cloud token must not be empty")]
    EmptyToken,
    #[error("pricing: {0}")]
    Pricing(String),
    #[error("cdn: {0}")]
    Cdn(String),
    /// Anything coming back from the `daal-deploy` subprocess or
    /// other on-box round-trips. Surfaces the actual stderr from
    /// the failing subcommand instead of being lumped under
    /// "pricing:" (the historical catch-all). Used by the
    /// per-recipient provision/revoke/list flow and by the .sbpx
    /// envelope wrap path so the React layer can render the real
    /// box-side error to the operator.
    #[error("subprocess: {0}")]
    Subprocess(String),
    /// Generic precondition / validation failure surfaced to the
    /// React layer (e.g. "recipient identity not yet created").
    /// Distinct from `EmptyToken`, which carries dedicated copy for
    /// that specific user-facing prompt.
    #[error("{0}")]
    Validation(String),
    /// Device Custody v1 is locked — UI should prompt for session
    /// passphrase (or trigger an OS-keystore unlock) before retry.
    #[error("custody locked: {0}")]
    CustodyLocked(String),
    /// A publisher-custody or helper-IP failure whose message is a
    /// **stable machine-readable code** followed by `": "` and human
    /// text — one of `E_CUSTODY_LOCKED`, `E_CUSTODY_WRONG_PASS`,
    /// `E_CUSTODY_BACKEND`, `E_LEGACY_PIN_REQUIRED`,
    /// `E_SECRET_MISSING`, `E_HELPER_IP_MISSING`, `E_HELPER_IP_STALE`.
    ///
    /// The React layer branches on that prefix
    /// (`classifyPublisherError` in `wizardCommands.ts`) to choose
    /// between "unlock", "run the migration", "re-detect your IP" and
    /// "this is broken, here's why". Display is `{0}` **verbatim**:
    /// prefixing anything — even "wizard: " — silently breaks every
    /// consumer, because Tauri hands the React side `e.to_string()`.
    #[error("{0}")]
    Coded(String),
}

// ---- Stable error codes (contract with the React layer) ----------
//
// These tokens are load-bearing UI state, not log text. Changing one
// changes which recovery affordance the user is offered.

/// Session-passphrase custody exists but has not been unlocked.
pub const E_CUSTODY_LOCKED: &str = "E_CUSTODY_LOCKED";
/// An AEAD failure attributable to a just-typed session passphrase.
pub const E_CUSTODY_WRONG_PASS: &str = "E_CUSTODY_WRONG_PASS";
/// The OS/Android keystore itself is unreachable or broken.
pub const E_CUSTODY_BACKEND: &str = "E_CUSTODY_BACKEND";
/// The secret exists only as a legacy PIN-sealed blob — run the
/// one-time migration.
pub const E_LEGACY_PIN_REQUIRED: &str = "E_LEGACY_PIN_REQUIRED";
/// Neither a custody blob nor a legacy blob: the key is gone.
pub const E_SECRET_MISSING: &str = "E_SECRET_MISSING";
/// `operators.helper_ip` is empty; the UI must detect + set, then retry.
pub const E_HELPER_IP_MISSING: &str = "E_HELPER_IP_MISSING";
/// The box was unreachable in a way consistent with a stale
/// firewall allowlist entry for the publisher's IP.
pub const E_HELPER_IP_STALE: &str = "E_HELPER_IP_STALE";

/// Build a [`WizardError::Coded`] from a code constant and a tail.
fn coded(code: &str, tail: impl std::fmt::Display) -> WizardError {
    WizardError::Coded(format!("{code}: {tail}"))
}

/// Does this `daal-deploy` stderr look like the box refusing us at
/// the network layer?
///
/// The publisher's IP is allowlisted on the cloud firewall for the
/// duration of one call. When the publisher moves between Wi-Fi and
/// cellular, or a CGNAT re-NATs them, the stored IP no longer matches
/// and the box becomes unreachable — not "down", *unreachable from
/// here*. The two look identical from a subprocess exit code, and the
/// difference decides whether the UI says "your relay is broken" or
/// "your network address changed, updating it" and silently retries.
///
/// We only claim staleness on transport-shaped failures. An
/// application-level error from a box we clearly reached (a 4xx from
/// the mgmt API itself, a JSON parse failure) is not an allowlist
/// problem and must not be papered over with a retry.
pub(crate) fn looks_like_stale_allowlist(stderr: &str) -> bool {
    let s = stderr.to_ascii_lowercase();
    const TRANSPORT_MARKERS: &[&str] = &[
        "connection refused",
        "connection reset",
        "no route to host",
        "network is unreachable",
        "host is unreachable",
        "i/o timeout",
        "timeout awaiting",
        "deadline exceeded",
        "dial tcp",
        "tls handshake",
        "handshake failure",
        "eof",
        "403 forbidden",
        "status 403",
        "401 unauthorized",
        "status 401",
    ];
    TRANSPORT_MARKERS.iter().any(|m| s.contains(m))
}

/// Map a `daal-deploy` subprocess failure onto the error contract,
/// promoting transport-shaped failures to `E_HELPER_IP_STALE` so the
/// UI can re-detect the publisher's IP and retry once instead of
/// showing a dead end.
pub(crate) fn map_deploy_err(e: crate::cli_bridge::BridgeError) -> WizardError {
    let text = e.to_string();
    if looks_like_stale_allowlist(&text) {
        return coded(E_HELPER_IP_STALE, text);
    }
    WizardError::Subprocess(text)
}

pub type Result<T> = std::result::Result<T, WizardError>;

/// `WizardCtx` carries the dependencies the command surface uses.
/// The Tauri shell builds one of these on app startup and passes
/// it into each `#[tauri::command]` shim via Tauri's State<>.
pub struct WizardCtx {
    pub db: Arc<OperatorDb>,
    /// **Legacy.** The PIN-sealed store. Read only by the one-time
    /// migration ([`migrate_from_pin`]) and probed by
    /// [`Keystore::has`]; erased by `cancel_and_cleanup` /
    /// `panic_wipe`. No live operation opens a secret from here.
    pub keystore: Arc<Keystore>,
    pub staging_dir: PathBuf,
    pub cli: Arc<dyn CliRunner>,
    pub clock: Arc<dyn Fn() -> i64 + Send + Sync>,
    /// Device Custody v1 — the custody surface for **every** secret
    /// this app holds: the recipient X25519 priv, the publisher
    /// Ed25519 signing key, and the cloud/Cloudflare API tokens.
    ///
    /// This reverses the FRP-5 design, which kept publisher secrets
    /// behind a typed PIN and called that friction deliberate. It
    /// wasn't buying what it claimed. On Android the `keyring` crate
    /// has no backend, so the PIN path degraded to app-private files
    /// whose only protection was Argon2id over a 6-digit secret,
    /// while the DWK reached through `DaalKeystore.kt` is a
    /// non-exportable AndroidKeyStore key that never leaves the TEE.
    /// Dropping the PIN on Android is a security *upgrade*, and on
    /// desktop the OS keyring is at least as strong as the PIN was.
    /// What the PIN did buy was a wizard the user could not resume:
    /// it was collected on one step, never persisted, and every
    /// later step's button was disabled for invisible reasons after
    /// a relaunch.
    pub custody: Arc<dyn DeviceCustody>,
}

/// Read a publisher secret out of custody, translating custody
/// failures into the stable `E_*` codes the UI branches on.
///
/// The `NotFound` case is the interesting one: it means either "this
/// install has not run the PIN→custody migration yet" (recoverable —
/// prompt for the old PIN once) or "the key is genuinely gone"
/// (unrecoverable). `Keystore::has` is what separates them, and
/// getting that distinction wrong would either hide a recoverable
/// state behind a dead end or demand a PIN that no longer exists.
pub(crate) fn custody_get(ctx: &WizardCtx, alias: &str) -> Result<Zeroizing<Vec<u8>>> {
    match ctx.custody.get(alias) {
        Ok(b) => Ok(Zeroizing::new(b)),
        Err(e) => Err(map_custody_err(ctx, alias, e)),
    }
}

/// Presence probe: is `alias` readable from custody right now?
///
/// The plaintext is dropped through `Zeroizing` rather than as a bare
/// `Vec<u8>`. This matters more than it looks: the migration gate and
/// the relay-detail header both call `custody_status`, which walks
/// every alias — so a naive `custody.get(a).is_ok()` would copy every
/// relay's Ed25519 signing key into freed heap on each mount of the
/// publisher surface, in a crate that otherwise zeroizes carefully.
fn custody_has(ctx: &WizardCtx, alias: &str) -> bool {
    ctx.custody.get(alias).map(Zeroizing::new).is_ok()
}

/// Same, decoding the secret as UTF-8 (cloud + Cloudflare tokens).
pub(crate) fn custody_get_string(ctx: &WizardCtx, alias: &str) -> Result<Zeroizing<String>> {
    let bytes = custody_get(ctx, alias)?;
    let s = String::from_utf8(bytes.to_vec())
        .map_err(|e| coded(E_CUSTODY_BACKEND, format!("token is not UTF-8: {e}")))?;
    Ok(Zeroizing::new(s))
}

fn map_custody_err(ctx: &WizardCtx, alias: &str, e: CustodyError) -> WizardError {
    match e {
        CustodyError::Locked => coded(
            E_CUSTODY_LOCKED,
            "unlock this device's key store to continue",
        ),
        CustodyError::WrongPassphrase => {
            coded(E_CUSTODY_WRONG_PASS, "that passphrase does not match")
        }
        CustodyError::NotFound(_) => {
            if ctx.keystore.has(alias) {
                coded(
                    E_LEGACY_PIN_REQUIRED,
                    format!("{alias} is still sealed under your old PIN"),
                )
            } else {
                coded(E_SECRET_MISSING, format!("no key stored for {alias}"))
            }
        }
        // BindingMismatch outside the passphrase-attribution window,
        // Backend (Android JNI / keyring), and every crypto-layer
        // failure are all "the key store is not answering correctly".
        // There is nothing the user can type to fix any of them.
        other => coded(E_CUSTODY_BACKEND, other),
    }
}

/// Write a publisher secret into custody under the same code mapping.
fn custody_put(ctx: &WizardCtx, alias: &str, secret: &[u8]) -> Result<()> {
    ctx.custody
        .put(alias, secret)
        .map_err(|e| map_custody_err(ctx, alias, e))
}

/// Read the persisted helper IP for an operator, or fail with
/// `E_HELPER_IP_MISSING` **before** spawning any subprocess.
///
/// Every mgmt-plane call needs this: `daal-deploy` punches an
/// ephemeral cloud-firewall rule for the publisher's own public IP
/// immediately before talking to the box. Failing here — cheaply,
/// with a code the UI can act on — beats a 30-second subprocess
/// timeout that surfaces as "connection refused".
pub(crate) fn require_helper_ip(ctx: &WizardCtx, operator_id: i64) -> Result<String> {
    let row = ctx.db.get(operator_id)?;
    if row.helper_ip.trim().is_empty() {
        return Err(coded(
            E_HELPER_IP_MISSING,
            "this device's public IP is not known yet",
        ));
    }
    Ok(row.helper_ip)
}

/// Accept an IPv4 dotted-quad or an IPv6 textual address. Rejecting
/// anything else is what stops a captive-portal HTML page from being
/// stored as a helper IP by the auto-detect path.
pub fn is_valid_ip(s: &str) -> bool {
    s.trim().parse::<std::net::IpAddr>().is_ok()
}

/// `OperatorSummary` is the shape returned by `list_operators` —
/// everything the relay list needs to render one card, in one call.
///
/// It is deliberately fat. The previous shape carried id / status /
/// provider / region / server_type only, so two relays on the same
/// provider and region were literally indistinguishable in the
/// picker, and the recipient counts had to come from an N+1 of
/// `recipient_list(id)` per row. Every field below is already in
/// hand when we walk the rows; returning them costs one extra
/// COUNT per operator and removes a whole class of "which one is
/// this?" from the UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorSummary {
    pub id: i64,
    pub status: String,
    pub provider: String,
    pub region: String,
    pub server_type: String,
    pub publisher_pub_hex: String,
    pub created_at_unix: i64,
    /// V012 nickname; "" when the user never named it.
    pub nickname: String,
    /// From the OperatorRecord; "" until provisioned.
    pub public_ip: String,
    pub public_ipv6: String,
    pub server_id: String,
    /// V012 helper IP; "" when never detected.
    pub helper_ip: String,
    pub last_provisioned_at_unix: i64,
    pub decommissioned_at_unix: i64,
    /// True once a RelayPack has been bound and signed for this relay.
    pub has_signed_sbp: bool,
    pub signed_sbp_at_unix: i64,
    pub live_recipient_count: i64,
    pub total_recipient_count: i64,
}

/// `OperatorState` is the full resumable state returned by
/// `get_operator_state`. The React wizard uses this to jump to
/// the correct step on mount and to populate all fields without
/// re-entering data the user already provided.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorState {
    pub id: i64,
    pub status: String,
    pub provider: String,
    pub region: String,
    pub server_type: String,
    pub publisher_pub_hex: String,
    pub has_cloud_token: bool,
    pub has_publisher_key: bool,
    pub is_provisioned: bool,
    pub has_signed_sbp: bool,
    /// The wizard step the user should resume from. One of:
    /// "provider", "pricing", "keys", "provision", "sign", "distribute", "done".
    ///
    /// These strings are the **stable** resume vocabulary. The React
    /// wizard collapsed 7 screens into 3 and maps these onto screen
    /// indices in one place (`stepIdToIdx`); do not rename them here
    /// to match the new screen names or every resume breaks.
    pub wizard_step: String,
    pub created_at_unix: i64,
    /// V012 nickname, so a resume can rehydrate the name field
    /// without a second round-trip.
    pub nickname: String,
    /// From the OperatorRecord; "" until provisioned.
    pub public_ip: String,
    /// V012 helper IP; "" when never detected.
    pub helper_ip: String,
}

/// Derive the wizard step from the operator's DB state.
fn derive_wizard_step(row: &crate::operator_db::OperatorRow) -> &'static str {
    if row.cloud_token_keystore_alias.is_empty() {
        return "provider";
    }
    // A provisioned operator resumes at the share/distribute step.
    // Check this BEFORE the region/server_type probe below: Hetzner's
    // create response can omit those fields, and without the shortcut
    // a fully-provisioned server would regress to "pricing" and
    // re-run a size choice it can no longer act on.
    if row.status == "provisioned" {
        if row.signed_sbp_sha256.is_some() {
            return "distribute";
        }
        return "sign";
    }
    // Parse the record to check for region/server_type
    if let Ok(rec) = serde_json::from_str::<serde_json::Value>(&row.operator_record_json) {
        let region = rec
            .get("region")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let server_type = rec
            .get("server_type")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if region.is_empty() || server_type.is_empty() {
            return "pricing";
        }
    }
    if row.publisher_pub_hex.is_empty() {
        return "keys";
    }
    if row.status == "pre-provision" {
        return "provision";
    }
    if row.signed_sbp_sha256.is_none() {
        return "sign";
    }
    "distribute"
}

/// Return the full resumable state for an operator. Reads only
/// non-secret metadata from the DB — it never touches custody, so it
/// is always safe to call on mount.
pub fn get_operator_state(ctx: &WizardCtx, operator_id: i64) -> Result<OperatorState> {
    let row = ctx.db.get(operator_id)?;
    let rec: serde_json::Value =
        serde_json::from_str(&row.operator_record_json).unwrap_or_default();
    let field = |k: &str| -> String {
        rec.get(k)
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string()
    };
    let region = field("region");
    let server_type = field("server_type");
    let step = derive_wizard_step(&row);
    Ok(OperatorState {
        id: row.id,
        status: row.status.clone(),
        provider: row.cloud_provider.clone(),
        region,
        server_type,
        publisher_pub_hex: row.publisher_pub_hex.clone(),
        has_cloud_token: !row.cloud_token_keystore_alias.is_empty(),
        has_publisher_key: !row.publisher_pub_hex.is_empty(),
        is_provisioned: row.status == "provisioned",
        has_signed_sbp: row.signed_sbp_sha256.is_some(),
        wizard_step: step.to_string(),
        created_at_unix: row.created_at_unix,
        nickname: row.nickname.clone(),
        public_ip: field("public_ip"),
        helper_ip: row.helper_ip.clone(),
    })
}

/// Step 1a: store the cloud-provider token under device custody.
///
/// `operator_id` selects between INSERT and UPDATE. Passing `None`
/// creates a new relay; passing `Some(id)` re-points an existing
/// pre-provision row at a (possibly new) token. The UPDATE branch is
/// not a nicety: without it, walking Back then Next on the wizard's
/// first screen INSERTed a second operator row every time, quietly
/// littering the relay list with half-built duplicates that each
/// held their own keystore aliases.
pub fn store_cloud_token(
    ctx: &WizardCtx,
    provider: &str,
    token: &str,
    operator_id: Option<i64>,
) -> Result<i64> {
    if token.trim().is_empty() {
        return Err(WizardError::EmptyToken);
    }
    let now = (ctx.clock)();

    if let Some(id) = operator_id {
        // UPDATE: the row exists; re-seal the token under its
        // canonical alias and re-point the provider if it changed.
        let row = ctx.db.get(id)?;
        let token_alias = cloud_alias(id);
        custody_put(ctx, &token_alias, token.as_bytes())?;
        ctx.db.update_token_alias(id, &token_alias)?;
        if row.cloud_provider != provider {
            ctx.db.set_cloud_provider(id, provider)?;
            let mut rec: PreProvisionRecord =
                serde_json::from_str(&row.operator_record_json).map_err(StagingError::from)?;
            rec.provider = provider.to_string();
            let body = serde_json::to_string(&rec).map_err(StagingError::from)?;
            ctx.db.update_record_json(id, &body)?;
        }
        return Ok(id);
    }

    // INSERT: placeholder row first so we have an id to bind the
    // custody alias to.
    let initial_record = PreProvisionRecord::new(provider, "", "", "iran-default", vec![], "");
    let initial_json = serde_json::to_string(&initial_record).map_err(StagingError::from)?;
    let id = ctx.db.insert_pre_provision(
        &initial_json,
        "", // no pubkey yet (keygen not run)
        "", // no priv alias yet
        provider,
        &cloud_alias(0), // overwrite below after id is known
        now,
    )?;
    let token_alias = cloud_alias(id);
    custody_put(ctx, &token_alias, token.as_bytes())?;
    // Update the row with the now-known token alias.
    ctx.db.update_record_json(id, &initial_json)?;
    ctx.db.update_token_alias(id, &token_alias)?;
    Ok(id)
}

/// Seal the operator's Cloudflare API token under device custody.
///
/// This lives here rather than inline in the Tauri shim so it goes
/// through [`custody_put`] like every other secret-touching command.
/// Calling `ctx.custody.put` directly loses the stable `E_CUSTODY_*`
/// prefix, and the React layer branches on that prefix to decide
/// whether to offer the unlock sheet, the migration sheet, or a plain
/// retry — a bare "custody is locked; call unlock() with a passphrase
/// first" string gets none of them.
pub fn store_cloudflare_token(ctx: &WizardCtx, operator_id: i64, token: &str) -> Result<()> {
    if token.trim().is_empty() {
        return Err(WizardError::EmptyToken);
    }
    // Confirm the operator exists before minting an alias bound to it.
    let _ = ctx.db.get(operator_id)?;
    custody_put(ctx, &cloudflare_alias(operator_id), token.as_bytes())
}

/// List existing servers on the operator's cloud account.
/// Reads the stored token and calls `daal-deploy list-servers`.
pub fn list_existing_servers(
    ctx: &WizardCtx,
    operator_id: i64,
) -> Result<Vec<crate::cli_bridge::ExistingServer>> {
    let row = ctx.db.get(operator_id)?;
    let token = custody_get_string(ctx, &row.cloud_token_keystore_alias)?;
    let servers = ctx
        .cli
        .run_list_servers(&row.cloud_provider, token.as_str())
        .map_err(|e| WizardError::Pricing(e.to_string()))?;
    Ok(servers)
}

/// List available server types for the operator's cloud provider.
/// Reads the stored token and calls `daal-deploy list-server-types`.
pub fn list_server_types(
    ctx: &WizardCtx,
    operator_id: i64,
    region: &str,
) -> Result<Vec<crate::cli_bridge::ServerTypeOption>> {
    let row = ctx.db.get(operator_id)?;
    let token = custody_get_string(ctx, &row.cloud_token_keystore_alias)?;
    let types = ctx
        .cli
        .run_list_server_types(&row.cloud_provider, region, token.as_str())
        .map_err(|e| WizardError::Pricing(e.to_string()))?;
    Ok(types)
}

/// Step 1b: live read-only pricing lookup. Reads the cloud token,
/// hands it to the FRP-4a CLI, returns the Pricing JSON.
pub fn pricing_lookup(
    ctx: &WizardCtx,
    operator_id: i64,
    region: &str,
    server_type: &str,
) -> Result<Pricing> {
    let row = ctx.db.get(operator_id)?;
    let token = custody_get_string(ctx, &row.cloud_token_keystore_alias)?;
    let pricing = ctx
        .cli
        .run_pricing(&row.cloud_provider, region, server_type, token.as_str())
        .map_err(|e| WizardError::Pricing(e.to_string()))?;
    Ok(pricing)
}

/// Step 2: persist the user's region/server-type/toolbox-profile +
/// enabled-families selection into the operator's record JSON.
///
/// # Why this patches a `Value` instead of a typed round-trip
///
/// Before provisioning, `operator_record_json` holds a
/// [`PreProvisionRecord`]. **After** provisioning it holds the full
/// FRP-4b `OperatorRecord` daal-deploy emitted, which carries the
/// mgmt plane (`mgmt_port`, `mgmt_tls_fingerprint`) and the box's
/// connection material (`reality_public_key`, `tls_cert_sha256`) —
/// none of which exist on `PreProvisionRecord`. Deserialising into
/// that struct and re-serialising therefore *silently deletes* them,
/// and nothing ever writes them back: `write_record_staging` would
/// hand daal-deploy a record with no mgmt port and no TLS pin, so
/// every users-* call would fail for good and every `.sbp`/`.sbpx`
/// built afterwards would be non-connectable. The relay would be
/// unmanageable with no way back short of a reprovision.
///
/// That is not hypothetical: the build screen re-runs this stage from
/// the top on every "Try again", including retries after the box is
/// already up. Patching the parsed JSON in place keeps every key the
/// struct does not model.
pub fn select_profile(
    ctx: &WizardCtx,
    operator_id: i64,
    region: &str,
    server_type: &str,
    toolbox_profile: &str,
    enabled_families: Vec<String>,
) -> Result<()> {
    let row = ctx.db.get(operator_id)?;
    // A provisioned box's region and server type are facts about a
    // machine that already exists, not a preference the plan screen
    // still owns. Rewriting them would make the record disagree with
    // the running server. Idempotent no-op rather than an error so a
    // retry higher up the chain can never be turned into a failure.
    if row.status == "provisioned" {
        return Ok(());
    }
    let mut rec: serde_json::Value =
        serde_json::from_str(&row.operator_record_json).map_err(StagingError::from)?;
    let obj = rec.as_object_mut().ok_or_else(|| {
        WizardError::Pricing("operator record JSON is not an object".into())
    })?;
    obj.insert("region".into(), region.into());
    obj.insert("server_type".into(), server_type.into());
    obj.insert("toolbox_profile".into(), toolbox_profile.into());
    obj.insert(
        "enabled_families".into(),
        serde_json::Value::from(enabled_families),
    );
    let body = serde_json::to_string(&rec).map_err(StagingError::from)?;
    ctx.db.update_record_json(operator_id, &body)?;
    Ok(())
}

/// Step 3a: generate a fresh publisher keypair, wrap it under device
/// custody, store the alias on the operator row, return the
/// fingerprint to render.
pub fn publisher_keygen(ctx: &WizardCtx, operator_id: i64) -> Result<Fingerprint> {
    let key = publisher_key::generate();
    seal_and_store_publisher(ctx, operator_id, &key.priv_bytes, &key.pub_bytes)?;
    Ok(key.fingerprint)
}

/// Step 3b: import an existing publisher key. `priv_bytes_b64` is
/// base64 of the 32- or 64-byte raw form. This is also the restore
/// path for a recovery blob written by [`export_recovery_key`].
pub fn publisher_keyimport(
    ctx: &WizardCtx,
    operator_id: i64,
    priv_bytes_b64: &str,
) -> Result<Fingerprint> {
    let raw = B64
        .decode(priv_bytes_b64.trim().as_bytes())
        .map_err(|e| WizardError::Pricing(format!("base64: {e}")))?;
    let key = publisher_key::import(&raw)?;
    seal_and_store_publisher(ctx, operator_id, &key.priv_bytes, &key.pub_bytes)?;
    Ok(key.fingerprint)
}

fn seal_and_store_publisher(
    ctx: &WizardCtx,
    operator_id: i64,
    priv_bytes: &[u8],
    pub_bytes: &[u8; 32],
) -> Result<()> {
    let alias = pub_alias(operator_id);
    custody_put(ctx, &alias, priv_bytes)?;
    let pub_hex = hex_of(pub_bytes);
    let pub_b64 = B64.encode(pub_bytes);
    // Update record JSON with the pubkey, and update the row's
    // pub_hex + alias columns.
    let row = ctx.db.get(operator_id)?;
    let mut rec: PreProvisionRecord =
        serde_json::from_str(&row.operator_record_json).map_err(StagingError::from)?;
    rec.publisher_pub_key = pub_b64;
    let body = serde_json::to_string(&rec).map_err(StagingError::from)?;
    ctx.db.update_record_json(operator_id, &body)?;
    ctx.db
        .update_publisher_columns(operator_id, &pub_hex, &alias)?;
    Ok(())
}

/// `SubkeyRotateResult` mirrors the JSON line emitted by
/// `daal-publish subkey rotate --json` plus the wizard-side
/// metadata derived from it (rotation timestamp, parsed cert
/// validity in unix seconds for easier 75%/95% lifetime maths).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubkeyRotateResult {
    pub subkey_dir: String,
    pub subkey_pub_path: String,
    pub subkey_priv_path: String,
    pub subkey_cert_path: String,
    pub subkey_meta_path: String,
    pub valid_from: String,
    pub valid_until: String,
    pub label: String,
    pub root_fingerprint_hex: String,
    pub subkey_fingerprint_hex: String,
    /// Wizard-side fields (not in the CLI JSON):
    pub rotated_at_unix: i64,
    pub valid_from_unix: i64,
    pub valid_until_unix: i64,
}

/// Per-CLI shape directly read from `daal-publish subkey
/// rotate --json` stdout.
#[derive(Debug, Clone, Deserialize)]
struct CliSubkeyRotateLine {
    pub subkey_dir: String,
    pub subkey_pub_path: String,
    pub subkey_priv_path: String,
    pub subkey_cert_path: String,
    pub subkey_meta_path: String,
    pub valid_from: String,
    pub valid_until: String,
    pub label: String,
    pub root_fingerprint_hex: String,
    pub subkey_fingerprint_hex: String,
}

/// FRP-7.5: rotate the operator's publisher sub-key. Steps:
///
///   1. Read the root publisher.priv out of device custody.
///   2. (was: PIN validation — gone with the PIN.)
///   3. Write the root priv to a 0o600 tempfile.
///   4. Spawn `daal-publish subkey rotate --json`. The subprocess
///      mints a fresh sub-key, signs a 90-day cert with the root,
///      and writes subkey.{pub,priv,cert,meta.json} into the
///      sub-keys tree alongside the operator's keystore.
///   5. Delete the root-priv tempfile (drop runs unlink + zeroize).
///   6. Parse the JSON output line; load the cert bytes from disk
///      to store inline in the V004 row (lets the wizard compute
///      lifetime % without re-reading disk on every banner tick).
///   7. Insert a fresh V004 `subkeys` row with active=1; the prior
///      row (if any) flips to active=0 in the same transaction.
///
/// Returns the structured result so the caller (Tauri shim) can
/// hand the keystore paths and validity window to the UI.
///
/// Position B preserved: the function spawns ONLY `daal-publish`
/// (no network IO). The root priv lives in a tempfile only for
/// the duration of the subprocess call; tempfile is mode 0o600
/// and is unlinked + zeroed on drop.
pub fn subkey_rotate(
    ctx: &WizardCtx,
    operator_id: i64,
    validity: &str,
    label: &str,
) -> Result<SubkeyRotateResult> {
    use std::io::Write as _;
    use std::process::Command;

    // Read root priv out of custody. `custody_get` returns
    // Zeroizing<Vec<u8>> so the bytes are wiped when this scope exits.
    let row = ctx.db.get(operator_id)?;
    let mut root_priv = custody_get(ctx, &row.publisher_priv_keystore_alias)?;

    // Write root priv to a 0o600 tempfile.
    let tmp_dir = ctx.staging_dir.join("tmp-subkey-rotate");
    std::fs::create_dir_all(&tmp_dir).map_err(|e| WizardError::Pricing(e.to_string()))?;
    let priv_path = tmp_dir.join(format!("root-{}.priv", operator_id));
    {
        // Open with mode 0o600 (POSIX). On non-POSIX targets
        // we fall back to a regular create + (best-effort) chmod
        // that the OS may ignore.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .mode(0o600)
                .open(&priv_path)
                .map_err(|e| WizardError::Pricing(e.to_string()))?;
            f.write_all(&root_priv)
                .map_err(|e| WizardError::Pricing(e.to_string()))?;
        }
        #[cfg(not(unix))]
        {
            let mut f = std::fs::File::create(&priv_path)
                .map_err(|e| WizardError::Pricing(e.to_string()))?;
            f.write_all(&root_priv)
                .map_err(|e| WizardError::Pricing(e.to_string()))?;
        }
    }
    // Zeroize the in-memory copy as soon as the tempfile is written.
    root_priv.zeroize();

    // Out-dir for the new sub-key — co-located with the wizard's
    // staging area, namespaced by operator id.
    //
    // TODO(custody): `daal-publish subkey rotate` writes
    // subkey.priv here in PLAINTEXT (mode 0o600, but plaintext) and
    // we persist only its path in the V004 row; `sign_relaypack` and
    // `publish_freshness_after_rotate` then read it straight off
    // disk. The PIN never protected this file — it gated the command
    // that produced it and nothing more — so removing the PIN loses
    // nothing here, but the gap is real and predates this change: a
    // rotated operator's active signing key sits unwrapped in the
    // staging dir. The fix is to wrap the sub-key priv under
    // `DeviceCustody` (alias `daal.subkey.<operator_id>.priv`) and
    // materialise a 0o600 tempfile only for the subprocess call, the
    // same shape `publish_freshness_after_rotate` already uses for
    // the root key. Out of scope for this phase because it needs a
    // V013 column swap plus a migration for existing rows.
    let out_dir = ctx
        .staging_dir
        .join("subkeys")
        .join(operator_id.to_string());
    std::fs::create_dir_all(&out_dir).map_err(|e| WizardError::Pricing(e.to_string()))?;

    // Spawn daal-publish.
    let bin = std::env::var("DAAL_PUBLISH_BIN").unwrap_or_else(|_| "daal-publish".to_string());
    let output = Command::new(&bin)
        .arg("subkey")
        .arg("rotate")
        .arg("--root-priv")
        .arg(&priv_path)
        .arg("--out-dir")
        .arg(&out_dir)
        .arg("--validity")
        .arg(validity)
        .arg("--label")
        .arg(label)
        .arg("--json")
        .output();

    // Always best-effort delete the priv tempfile.
    let _ = std::fs::remove_file(&priv_path);

    let output = output.map_err(|e| {
        WizardError::Pricing(format!("daal-publish subkey rotate spawn failed: {e}"))
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        return Err(WizardError::Pricing(format!(
            "daal-publish subkey rotate failed (rc={}): {}",
            output.status.code().unwrap_or(-1),
            stderr
        )));
    }
    let line: CliSubkeyRotateLine = serde_json::from_slice(&output.stdout)
        .map_err(|e| WizardError::Pricing(format!("parse subkey rotate JSON: {e}")))?;

    // Parse the cert validity window into unix seconds for fast
    // lifetime maths in the wizard (75%/95% banner thresholds).
    let valid_from_unix = parse_rfc3339_unix(&line.valid_from)
        .map_err(|e| WizardError::Pricing(format!("parse valid_from: {e}")))?;
    let valid_until_unix = parse_rfc3339_unix(&line.valid_until)
        .map_err(|e| WizardError::Pricing(format!("parse valid_until: {e}")))?;
    let rotated_at_unix = (ctx.clock)();

    // Read the cert JSON bytes off disk — small, but needed by
    // the wizard to render the cert summary without re-reading
    // every time.
    let cert_json = std::fs::read_to_string(&line.subkey_cert_path)
        .map_err(|e| WizardError::Pricing(format!("read cert: {e}")))?;

    // Persist the rotation in V004.
    ctx.db.insert_subkey_rotation(
        operator_id,
        &line.subkey_fingerprint_hex,
        &line.subkey_pub_path,
        &line.subkey_priv_path,
        &line.subkey_cert_path,
        &cert_json,
        &line.label,
        valid_from_unix,
        valid_until_unix,
        rotated_at_unix,
    )?;

    Ok(SubkeyRotateResult {
        subkey_dir: line.subkey_dir,
        subkey_pub_path: line.subkey_pub_path,
        subkey_priv_path: line.subkey_priv_path,
        subkey_cert_path: line.subkey_cert_path,
        subkey_meta_path: line.subkey_meta_path,
        valid_from: line.valid_from,
        valid_until: line.valid_until,
        label: line.label,
        root_fingerprint_hex: line.root_fingerprint_hex,
        subkey_fingerprint_hex: line.subkey_fingerprint_hex,
        rotated_at_unix,
        valid_from_unix,
        valid_until_unix,
    })
}

/// FRP-7.5: read the currently-active sub-key for an operator,
/// or `None` if none has been rotated yet.
pub fn active_subkey(ctx: &WizardCtx, operator_id: i64) -> Result<Option<SubkeyRow>> {
    Ok(ctx.db.active_subkey(operator_id)?)
}

/// FRP-7.5: list the sub-key rotation history for an operator,
/// most recent first.
pub fn list_subkey_history(ctx: &WizardCtx, operator_id: i64) -> Result<Vec<SubkeyRow>> {
    Ok(ctx.db.list_subkey_history(operator_id)?)
}

// ---------------------------------------------------------------
// FRP-8: CDN screen 2.5 — Cloudflare front provisioning
// ---------------------------------------------------------------

/// `ProvisionCdnFrontInput` is the payload the wizard's CDN
/// screen 2.5 hands to `provision_cdn_front`. Mirrors the public
/// fields of `publisher/deploy/cloudflare.CloudflareOpts` plus
/// the operator id the row binds to.
///
/// Position B: the Cloudflare API token comes from device custody
/// (alias `daal.cloudflare.<operator_id>.token`); it is NOT in this
/// struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionCdnFrontInput {
    pub operator_id: i64,
    pub hostname: String,
    pub origin_ip: String,
    #[serde(default)]
    pub origin_ipv6: String,
    pub origin_path: String,
    /// Optional. When empty the provider generates a random
    /// `/r/<hex>` path.
    #[serde(default)]
    pub public_path: String,
}

/// `provision_cdn_front` is the wizard CDN screen 2.5 entry
/// point. It validates the input, reads the operator's Cloudflare
/// token from device custody, hands everything to the Go-side
/// `publisher/deploy/cloudflare` provider, and on success records
/// the resulting front in V005's `cdn_fronts`.
///
/// Returns the freshly-inserted CDN front row id.
pub fn provision_cdn_front(ctx: &WizardCtx, input: &ProvisionCdnFrontInput) -> Result<i64> {
    if input.hostname.is_empty() || input.origin_ip.is_empty() || input.origin_path.is_empty() {
        return Err(WizardError::Cdn(
            "hostname, origin_ip, origin_path required".into(),
        ));
    }
    let op = ctx.db.get(input.operator_id)?;
    // Read the Cloudflare token (alias =
    // daal.cloudflare.<operator_id>.token) and the cloud-provider
    // token. The Go CLI uses the latter to lock the origin firewall
    // to Cloudflare edge ranges before returning a validator-ready
    // `firewall_id`.
    let token_alias = cloudflare_alias(input.operator_id);
    let token = custody_get_string(ctx, &token_alias)?;
    let token_str = token.as_str();
    let cloud_token = custody_get_string(ctx, &op.cloud_token_keystore_alias)?;
    let cloud_token_str = cloud_token.as_str();
    let out_dir = ctx
        .staging_dir
        .join("cdn")
        .join(input.operator_id.to_string());
    std::fs::create_dir_all(&out_dir)
        .map_err(|e| WizardError::Cdn(format!("create CDN staging dir: {e}")))?;
    let front = ctx
        .cli
        .run_cdn_provision(CdnProvisionArgs {
            hostname: &input.hostname,
            origin_ip: &input.origin_ip,
            origin_ipv6: &input.origin_ipv6,
            origin_path: &input.origin_path,
            public_path: &input.public_path,
            out_dir: &out_dir,
            cf_token: token_str,
            cloud_token: cloud_token_str,
        })
        .map_err(|e| WizardError::Cdn(e.to_string()))?;
    let now = (ctx.clock)();
    let row = CdnFrontRow {
        id: 0,
        operator_id: input.operator_id,
        hostname: front.hostname,
        zone_id: front.zone_id,
        public_path: front.public_path,
        origin_path: front.origin_path,
        worker_route_id: front.worker_route_id,
        origin_ca_fingerprint: front.origin_ca_fingerprint,
        origin_ca_cert_path: front.origin_ca_cert_path,
        origin_ca_priv_path: front.origin_ca_priv_path,
        aop_client_cert_path: front.aop_client_cert_path,
        aop_enabled: front.aop_enabled,
        firewall_id: front.firewall_id,
        dns_only_present: false,
        edge_ranges_fetched_unix: now,
        last_verified_unix: now,
        created_unix: now,
    };
    Ok(ctx.db.upsert_cdn_front(&row)?)
}

/// `record_cdn_front_attestation` is the offline path for tests
/// + diagnostic tooling: insert a CDN front row from a known-good
/// attestation without going through the live provider. Used by
/// the FRP-4b CLI integration tests.
///
/// Production wizard does NOT call this; it always goes through
/// `provision_cdn_front` so the §11.7 hardening is exercised
/// end-to-end.
pub fn record_cdn_front_attestation(ctx: &WizardCtx, row: &CdnFrontRow) -> Result<i64> {
    let id = ctx.db.upsert_cdn_front(row)?;
    Ok(id)
}

/// `list_cdn_fronts` returns all CDN front rows for an operator,
/// most recent first.
pub fn list_cdn_fronts(ctx: &WizardCtx, operator_id: i64) -> Result<Vec<CdnFrontRow>> {
    Ok(ctx.db.list_cdn_fronts(operator_id)?)
}

/// `verify_cdn_posture` is the wizard's "Verify CDN posture"
/// button. The FRP-8 CLI bridge owns the live Cloudflare API; at
/// this layer we record the operator-visible timestamp after the
/// live check path succeeds.
///
/// It opens no secret and never did — the PIN it used to demand was
/// pure theatre, validated and then discarded.
pub fn verify_cdn_posture(ctx: &WizardCtx, front_id: i64) -> Result<()> {
    let now = (ctx.clock)();
    ctx.db.touch_cdn_front_verification(front_id, now, now)?;
    Ok(())
}

/// `RotateCdnPathInput` is the payload for `rotate_cdn_path`. The
/// caller may leave `new_public_path` empty to let the
/// `daal-deploy cdn-rotate-path` invocation pick a fresh
/// `/r/<hex>` path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateCdnPathInput {
    pub front_id: i64,
    pub account_id: String,
    #[serde(default)]
    pub new_public_path: String,
}

/// `rotate_cdn_path` is the supplement §14.4 public-path
/// rotation. The visible random path changes; hostname unchanged;
/// origin path unchanged. **The wizard MUST re-sign the RelayPack
/// after this call returns** because a `public_risk_tag` value
/// (the path) changed; that step is owned by the rotation
/// executor (`rotate_execute`'s mode-aware branch lands at FRP-9
/// commit 4/8). This layer only drives the CDN-side rebind and
/// updates the V005 row.
pub fn rotate_cdn_path(ctx: &WizardCtx, input: &RotateCdnPathInput) -> Result<CdnRotateResult> {
    let row = ctx.db.get_cdn_front(input.front_id)?;
    let token = custody_get_string(ctx, &cloudflare_alias(row.operator_id))?;
    let token_str = token.as_str();
    let res = ctx
        .cli
        .run_cdn_rotate_path(CdnRotatePathArgs {
            front_id: row.id,
            hostname: &row.hostname,
            zone_id: &row.zone_id,
            account_id: &input.account_id,
            old_route_id: &row.worker_route_id,
            origin_path: &row.origin_path,
            new_public_path: &input.new_public_path,
            cf_token: token_str,
        })
        .map_err(|e| WizardError::Cdn(e.to_string()))?;
    ctx.db.update_cdn_front_rotation(
        row.id,
        &res.hostname,
        &res.zone_id,
        &res.public_path,
        &res.worker_route_id,
    )?;
    Ok(res)
}

/// `RotateCdnHostnameInput` is the payload for
/// `rotate_cdn_hostname`. The new hostname's apex must be a zone
/// the FRP's Cloudflare token controls; the deploy CLI surfaces
/// `ErrCFNotImplemented` if the token doesn't authorize that zone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateCdnHostnameInput {
    pub front_id: i64,
    pub new_hostname: String,
    pub origin_ipv4: String,
    #[serde(default)]
    pub origin_ipv6: String,
}

/// `rotate_cdn_hostname` is the supplement §14.4 hostname
/// rotation. The hostname changes; public path + origin IP are
/// unchanged from the operator's vantage. As with public-path
/// rotation, the wizard MUST re-sign the RelayPack afterwards
/// because `host:`, `sni:`, and `public_domain:` tags all change.
pub fn rotate_cdn_hostname(
    ctx: &WizardCtx,
    input: &RotateCdnHostnameInput,
) -> Result<CdnRotateResult> {
    if input.new_hostname.is_empty() || input.origin_ipv4.is_empty() {
        return Err(WizardError::Cdn(
            "new_hostname and origin_ipv4 required".into(),
        ));
    }
    let row = ctx.db.get_cdn_front(input.front_id)?;
    let token = custody_get_string(ctx, &cloudflare_alias(row.operator_id))?;
    let token_str = token.as_str();
    let res = ctx
        .cli
        .run_cdn_rotate_hostname(CdnRotateHostnameArgs {
            front_id: row.id,
            old_hostname: &row.hostname,
            old_zone_id: &row.zone_id,
            public_path: &row.public_path,
            origin_path: &row.origin_path,
            new_hostname: &input.new_hostname,
            origin_ipv4: &input.origin_ipv4,
            origin_ipv6: &input.origin_ipv6,
            cf_token: token_str,
        })
        .map_err(|e| WizardError::Cdn(e.to_string()))?;
    ctx.db.update_cdn_front_rotation(
        row.id,
        &res.hostname,
        &res.zone_id,
        &row.public_path,
        &res.worker_route_id,
    )?;
    Ok(res)
}

/// `RotateCdnOriginInput` is the payload for `rotate_cdn_origin`.
/// **Origin-only path**: the wizard does NOT re-sign the
/// RelayPack and does NOT re-publish the freshness JSON document
/// — the candidate is byte-identical because no `public_risk_tag`
/// changed. From the censor's vantage the public surface is
/// untouched.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateCdnOriginInput {
    pub front_id: i64,
    pub new_origin_ipv4: String,
    #[serde(default)]
    pub new_origin_ipv6: String,
}

/// `rotate_cdn_origin` is the supplement §14.4 origin-only
/// rotation. The Cloudflare A / AAAA records are re-pointed at
/// the new origin IP; hostname, public path, and worker route
/// binding are unchanged. The wizard MUST NOT re-sign the
/// RelayPack — the family sees nothing.
pub fn rotate_cdn_origin(ctx: &WizardCtx, input: &RotateCdnOriginInput) -> Result<CdnRotateResult> {
    if input.new_origin_ipv4.is_empty() {
        return Err(WizardError::Cdn("new_origin_ipv4 required".into()));
    }
    let row = ctx.db.get_cdn_front(input.front_id)?;
    let token = custody_get_string(ctx, &cloudflare_alias(row.operator_id))?;
    let token_str = token.as_str();
    let res = ctx
        .cli
        .run_cdn_rotate_origin(CdnRotateOriginArgs {
            front_id: row.id,
            hostname: &row.hostname,
            zone_id: &row.zone_id,
            new_origin_ipv4: &input.new_origin_ipv4,
            new_origin_ipv6: &input.new_origin_ipv6,
            cf_token: token_str,
        })
        .map_err(|e| WizardError::Cdn(e.to_string()))?;
    // Origin-only does NOT mutate hostname / zone_id / public_path
    // / worker_route_id, and it MUST NOT update posture timestamps:
    // re-pointing DNS is not the same as verifying §11.7 hardening
    // or refreshing the provider firewall. rotate_execute records
    // the audit-only signed_sbps history row.
    Ok(res)
}

/// Minimal RFC3339 → unix seconds helper. The wizard already
/// pulls `chrono` indirectly via tauri but we keep this local to
/// avoid a runtime dep on chrono just for this one call.
fn parse_rfc3339_unix(s: &str) -> std::result::Result<i64, String> {
    // Format expected: YYYY-MM-DDThh:mm:ssZ (UTC, no fractional).
    // We split into year-month-day and hour-min-sec.
    let s = s.trim_end_matches('Z');
    let (date, time) = s
        .split_once('T')
        .ok_or_else(|| format!("missing T in {s:?}"))?;
    let mut date_parts = date.split('-');
    let y: i64 = date_parts
        .next()
        .and_then(|p| p.parse().ok())
        .ok_or("year")?;
    let mo: i64 = date_parts
        .next()
        .and_then(|p| p.parse().ok())
        .ok_or("month")?;
    let d: i64 = date_parts
        .next()
        .and_then(|p| p.parse().ok())
        .ok_or("day")?;
    let mut time_parts = time.split(':');
    let hh: i64 = time_parts
        .next()
        .and_then(|p| p.parse().ok())
        .ok_or("hour")?;
    let mm: i64 = time_parts
        .next()
        .and_then(|p| p.parse().ok())
        .ok_or("min")?;
    let ss: i64 = time_parts
        .next()
        .and_then(|p| p.parse().ok())
        .ok_or("sec")?;

    // Days since unix epoch using a Howard Hinnant date algorithm.
    // (Civil-from-days inverse — handles all dates 1970..9999.)
    let yy = if mo <= 2 { y - 1 } else { y };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let doy = (153 * (if mo > 2 { mo - 3 } else { mo + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;

    Ok(days * 86400 + hh * 3600 + mm * 60 + ss)
}

/// Step 3c: write the pre-provision JSON staging file FRP-4b reads.
/// Returns the file path written.
pub fn finalize_pre_provision(ctx: &WizardCtx, operator_id: i64) -> Result<PathBuf> {
    let row = ctx.db.get(operator_id)?;
    let rec: PreProvisionRecord =
        serde_json::from_str(&row.operator_record_json).map_err(StagingError::from)?;
    let path = staging::write_record(&ctx.staging_dir, operator_id, &rec)?;
    Ok(path)
}

/// List all operators (any status), fully populated for the relay
/// list. Touches no secrets, so it is always safe to call on boot.
pub fn list_operators(ctx: &WizardCtx) -> Result<Vec<OperatorSummary>> {
    let rows = ctx.db.list()?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        // The record JSON is the authority for provisioned facts
        // (public IP, server id): `daal-deploy provision` writes the
        // whole OperatorRecord back and we store it verbatim.
        let rec: PreProvisionRecord =
            serde_json::from_str(&row.operator_record_json).map_err(StagingError::from)?;
        out.push(OperatorSummary {
            id: row.id,
            status: row.status,
            provider: rec.provider,
            region: rec.region,
            server_type: rec.server_type,
            publisher_pub_hex: row.publisher_pub_hex,
            created_at_unix: row.created_at_unix,
            nickname: row.nickname,
            public_ip: rec.public_ip,
            public_ipv6: rec.public_ipv6,
            server_id: rec.server_id,
            helper_ip: row.helper_ip,
            last_provisioned_at_unix: row.last_provisioned_at_unix.unwrap_or(0),
            decommissioned_at_unix: row.decommissioned_at_unix.unwrap_or(0),
            has_signed_sbp: row.signed_sbp_sha256.is_some(),
            signed_sbp_at_unix: row.signed_sbp_at_unix.unwrap_or(0),
            live_recipient_count: ctx.db.count_live_recipients(row.id)?,
            total_recipient_count: ctx.db.count_total_recipients(row.id)?,
        });
    }
    Ok(out)
}

/// V012: set (or clear, with "") the human nickname for a relay.
pub fn set_operator_nickname(ctx: &WizardCtx, operator_id: i64, nickname: &str) -> Result<()> {
    ctx.db.set_nickname(operator_id, nickname.trim())?;
    Ok(())
}

/// Cancel-and-cleanup: delete the DB row, then erase every secret
/// bound to this operator and its staged files. Idempotent.
///
/// Both stores are swept. Custody holds the live secrets; the legacy
/// keystore may still hold PIN-sealed copies on an install that never
/// ran the migration, and leaving those behind would keep a signing
/// key on disk for a relay the user just deleted.
///
/// # Why the row goes first
///
/// The DB delete is the only fallible step here — everything after it
/// is `let _ =` best-effort — and it can genuinely fail (a locked or
/// full sqlite file, a FK constraint). The old order erased the
/// custody aliases first, so a failed delete left a live operator row
/// whose Ed25519 signing key had already been destroyed: unusable,
/// unrecoverable, and every retry failed the same way. Deleting the
/// row first means a failure returns `Err` with the keys still there
/// and the retry able to succeed. The reverse risk — row gone,
/// secrets briefly stranded — is recoverable: `panic_wipe` and the
/// next `cancel_and_cleanup` of the same id both re-sweep the same
/// conventional aliases, which are pure functions of the operator id.
pub fn cancel_and_cleanup(ctx: &WizardCtx, operator_id: i64) -> Result<()> {
    let row = match ctx.db.get(operator_id) {
        Ok(r) => r,
        Err(DbError::NotFound(_)) => return Ok(()),
        Err(e) => return Err(WizardError::Db(e)),
    };
    let mut aliases: Vec<String> = Vec::new();
    if !row.publisher_priv_keystore_alias.is_empty() {
        aliases.push(row.publisher_priv_keystore_alias.clone());
    }
    if !row.cloud_token_keystore_alias.is_empty() {
        aliases.push(row.cloud_token_keystore_alias.clone());
    }
    // Conventional aliases with no column of their own.
    aliases.push(pub_alias(operator_id));
    aliases.push(cloud_alias(operator_id));
    aliases.push(cloudflare_alias(operator_id));
    aliases.sort();
    aliases.dedup();

    // Fallible step first; see the doc comment above.
    match ctx.db.delete(operator_id) {
        Ok(()) | Err(DbError::NotFound(_)) => {}
        Err(e) => return Err(WizardError::Db(e)),
    }

    for alias in &aliases {
        // Both forget()s are idempotent on a missing alias, and a
        // failure to erase one store must not stop us erasing the
        // other — teardown is best-effort by design.
        let _ = ctx.custody.forget(alias);
        let _ = ctx.keystore.forget(alias);
    }
    let staging_path = ctx
        .staging_dir
        .join(format!("{operator_id}.pre-provision.json"));
    if staging_path.exists() {
        let _ = std::fs::remove_file(&staging_path);
    }
    // The rotated sub-key lives here, unwrapped: `subkey_rotate`
    // writes `subkey.priv` as a plaintext 0o600 file under
    // `<staging>/subkeys/<id>/` and `sign_relaypack` reads it straight
    // back, so for any operator that has rotated, this directory holds
    // the *active* signing key. Nothing else removes it per-operator
    // (`panic_wipe` only catches it because it drops the whole staging
    // dir), so without this a "removed" relay left its signing key in
    // the clear on disk forever.
    let _ = std::fs::remove_dir_all(ctx.staging_dir.join("subkeys").join(operator_id.to_string()));
    Ok(())
}

// ---- Real teardown --------------------------------------------------

/// What a "Remove relay" actually accomplished, resource by resource.
///
/// Deleting a relay used to be a purely local act — the app forgot the
/// keys and dropped the row while the VPS stayed up and kept billing.
/// Now that the cloud legs are real, "it worked" is no longer one bit
/// of information: a run that killed the server but could not delete
/// the ephemeral SSH key leaves the user's *next* provision in the same
/// region permanently broken on a name collision, and they can only act
/// on that if we say so. Every leg is reported, and `warnings` carries
/// the provider's own text verbatim rather than a rewritten summary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct DestroyReport {
    pub server_deleted: bool,
    pub ssh_key_deleted: bool,
    pub firewall_deleted: bool,
    pub local_removed: bool,
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// `relay_destroy`: remove a relay, optionally destroying the cloud
/// resources behind it first.
///
/// `delete_server == false` is byte-for-byte today's behaviour — forget
/// the secrets, drop the row, leave the box running. That stays the
/// default for the escape hatches (a stuck custody migration has no
/// readable token, so it *cannot* authenticate a cloud delete).
///
/// `delete_server == true` destroys the cloud side **first**, and the
/// order is a correctness property rather than a preference:
/// [`cancel_and_cleanup`] erases the cloud API token and then the row
/// holding `server_id`, `region` and the publisher pubkey. Those five
/// values are the *only* way to name the resources to be destroyed.
/// Run the local sweep first and a failed cloud call is unrecoverable —
/// a billing server with no credential left to delete it. So a cloud
/// failure returns `Err` with the local state fully intact, and the
/// user can retry. Nothing local is touched until the cloud says the
/// server is gone.
pub fn relay_destroy(
    ctx: &WizardCtx,
    operator_id: i64,
    delete_server: bool,
) -> Result<DestroyReport> {
    if !delete_server {
        cancel_and_cleanup(ctx, operator_id)?;
        return Ok(DestroyReport {
            local_removed: true,
            ..Default::default()
        });
    }

    let row = match ctx.db.get(operator_id) {
        Ok(r) => r,
        // Already gone: idempotent, same as cancel_and_cleanup. There
        // is no record left to name a cloud resource with, so there is
        // nothing truthful to claim about the server either.
        Err(DbError::NotFound(_)) => {
            return Ok(DestroyReport {
                local_removed: true,
                ..Default::default()
            })
        }
        Err(e) => return Err(WizardError::Db(e)),
    };

    // Cloud first. A failure here propagates and the local state — row,
    // token, staged record — survives untouched for the retry.
    let cloud = destroy_cloud_resources(ctx, operator_id, &row)?;

    // The local sweep is reported, never propagated. Past this point the
    // VPS is already gone, and `?` here would throw that fact away: the
    // sheet would render "the server was NOT deleted, it is still
    // billing" — the exact opposite of the truth — for what is really a
    // local sqlite problem. `local_removed: false` plus the error text
    // in `warnings` is what the report shape (and
    // `pub.relays.destroy.report.local_kept`) exists for.
    let mut warnings = cloud.warnings;
    let local_removed = match cancel_and_cleanup(ctx, operator_id) {
        Ok(()) => true,
        Err(e) => {
            warnings.push(format!(
                "the cloud resources are gone, but this relay could not be removed from \
                 the app: {e}"
            ));
            false
        }
    };

    Ok(DestroyReport {
        server_deleted: cloud.server_deleted,
        ssh_key_deleted: cloud.ssh_key_deleted,
        firewall_deleted: cloud.firewall_deleted,
        local_removed,
        warnings,
    })
}

/// Stage the OperatorRecord and hand it to `daal-deploy decommission`.
///
/// Returns `Ok` with everything false and a warning when the relay
/// never reached the cloud at all — a draft that only ever held a token
/// has no server id, no region and no publisher key, so there is no
/// name to derive and nothing to sweep. Failing that case would block
/// the user from deleting a row that costs nothing.
fn destroy_cloud_resources(
    ctx: &WizardCtx,
    operator_id: i64,
    row: &OperatorRow,
) -> Result<DecommissionResult> {
    let record_json = row.operator_record_json.trim();
    let rec: Option<PreProvisionRecord> = if record_json.is_empty() {
        None
    } else {
        serde_json::from_str(record_json).ok()
    };
    // `server_id` alone is not the test. A provision that failed
    // partway leaves `server_id` empty while an ephemeral SSH key
    // named from (publisher pubkey, region) is already orphaned in the
    // account — and that orphan is what makes every later attempt in
    // that region fail on a name collision. So a record carrying a
    // publisher key is worth sweeping even with no server to delete.
    let has_cloud_footprint = rec.as_ref().is_some_and(|r| {
        !r.provider.trim().is_empty()
            && (!r.server_id.trim().is_empty() || !r.publisher_pub_key.trim().is_empty())
    });
    if !has_cloud_footprint {
        // Every flag true, because each one answers "is it gone now?",
        // not "did this run delete it" — and nothing was ever created.
        // Reporting false here made the teardown sheet raise its red
        // "the server is still running and still billing" alarm over a
        // VPS that never existed, and send the user hunting through a
        // cloud console for it. The warning below still says plainly
        // that there was nothing to delete.
        return Ok(DecommissionResult {
            server_deleted: true,
            ssh_key_deleted: true,
            firewall_deleted: true,
            warnings: vec![
                "this relay was never provisioned — nothing exists in your cloud account to \
                 delete"
                    .to_string(),
            ],
        });
    }

    if row.cloud_token_keystore_alias.is_empty() {
        // No credential means no way to authenticate the delete. Say so
        // rather than silently downgrading to a local-only removal that
        // strands a billing server.
        return Err(WizardError::EmptyToken);
    }
    let token = custody_get_string(ctx, &row.cloud_token_keystore_alias)?;

    let record_path = ctx.staging_dir.join(format!("{operator_id}.record.json"));
    std::fs::create_dir_all(&ctx.staging_dir)
        .map_err(|e| WizardError::Pricing(format!("mkdir staging: {e}")))?;
    std::fs::write(&record_path, record_json.as_bytes())
        .map_err(|e| WizardError::Pricing(format!("write record: {e}")))?;

    let res = ctx.cli.run_decommission(DecommissionArgs {
        record_path: &record_path,
        token: token.as_str(),
    });
    // Erase the staged record on both paths; it carries no secret but
    // leaving it behind after a failure would desync the next retry.
    let _ = std::fs::remove_file(&record_path);

    res.map_err(map_deploy_err)
}

// ---- FRP-4b live operations ----------------------------------------

/// `provision_run`: call `daal-deploy provision` for the operator
/// with the wizard's stored cloud token + pubkey. On success, the
/// returned OperatorRecord JSON is written back into the operator
/// row and `status` flips to `provisioned`.
///
/// Progress events are forwarded via `on_progress` so the Tauri
/// shim can emit them to the wizard frontend.
///
/// The helper IP is read from `operators.helper_ip` (V012) rather
/// than passed in: it used to be a parameter with no storage
/// anywhere, so it evaporated on every relaunch.
pub fn provision_run(
    ctx: &WizardCtx,
    operator_id: i64,
    existing_server_id: &str,
    on_progress: &mut dyn FnMut(ProgressEvent),
) -> Result<()> {
    let helper_ip = require_helper_ip(ctx, operator_id)?;
    let row = ctx.db.get(operator_id)?;
    let token = custody_get_string(ctx, &row.cloud_token_keystore_alias)?;
    let rec: PreProvisionRecord =
        serde_json::from_str(&row.operator_record_json).map_err(StagingError::from)?;

    // Pubkey was base64-encoded into the record at FRP-5.
    let pub_bytes = B64
        .decode(rec.publisher_pub_key.as_bytes())
        .map_err(|e| WizardError::Pricing(format!("pubkey base64: {e}")))?;
    let pubkey_path = ctx.staging_dir.join(format!("{operator_id}.pub"));
    std::fs::create_dir_all(&ctx.staging_dir)
        .map_err(|e| WizardError::Pricing(format!("mkdir staging: {e}")))?;
    std::fs::write(&pubkey_path, &pub_bytes)
        .map_err(|e| WizardError::Pricing(format!("write pubkey: {e}")))?;

    let families: Vec<&str> = rec.enabled_families.iter().map(|s| s.as_str()).collect();
    let stdout_json = ctx
        .cli
        .run_provision(
            ProvisionArgs {
                provider: &row.cloud_provider,
                region: &rec.region,
                server_type: &rec.server_type,
                toolbox_profile: &rec.toolbox_profile,
                families,
                helper_ip: &helper_ip,
                pubkey_file: &pubkey_path,
                token: token.as_str(),
                dry_run: false,
                existing_server_id,
                // Empty: a relay being built for the first time takes
                // whatever the pool seeds for it. The rotation path is
                // the one that must forward a value — see rotate_execute.
                cover_sni: "",
                // A failure past ServerCreate must not leave a billing
                // box behind: this function only persists the
                // OperatorRecord on success, so a kept box has no server
                // id anywhere in the app and no reusable mgmt port. See
                // ProvisionArgs::rollback_on_failure.
                rollback_on_failure: true,
            },
            on_progress,
        )
        .map_err(map_deploy_err)?;

    // Wipe pubkey file on disk; the OperatorRecord we get back
    // already carries the pub bytes inside its JSON.
    let _ = std::fs::remove_file(&pubkey_path);

    ctx.db.update_record_json(operator_id, &stdout_json)?;
    persist_mgmt_plane_if_present(ctx, operator_id, &stdout_json)?;
    let now = (ctx.clock)();
    ctx.db.mark_provisioned(operator_id, now)?;
    Ok(())
}

fn persist_mgmt_plane_if_present(
    ctx: &WizardCtx,
    operator_id: i64,
    operator_json: &str,
) -> Result<()> {
    let parsed: serde_json::Value =
        serde_json::from_str(operator_json).map_err(StagingError::from)?;
    let port = parsed
        .get("mgmt_port")
        .and_then(|v| v.as_i64())
        .unwrap_or_default();
    let fp = parsed
        .get("mgmt_tls_fingerprint")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if port == 0 && fp.is_empty() {
        return Ok(());
    }
    if port == 0 || fp.is_empty() {
        return Err(WizardError::Pricing(
            "daal-deploy returned partial mgmt-plane fields".into(),
        ));
    }
    ctx.db.record_mgmt_plane(operator_id, port, fp)?;
    Ok(())
}

/// `sign_relaypack`: call `daal-deploy bind-and-sign` for an
/// operator whose status is `provisioned`. By default the root
/// publisher key is read from device custody and piped via stdin.
/// After FRP-7.5, if the operator has an active sub-key row, the
/// active sub-key private key is read from its 0o600 artefact path
/// and paired with its cert path so the emitted bundle is
/// spec_version=4 / sub-key-signed. In both cases the signing bytes
/// are zeroized immediately after the subprocess exits.
///
/// On success the wizard records the .sbp's sha256 + relay_pack_id
/// on the operator row (V002 columns) and returns the BindResult
/// summary so the Tauri shim can populate Screen 5/6.
pub fn sign_relaypack(
    ctx: &WizardCtx,
    operator_id: i64,
    phase: &str,
    output_dir: &std::path::Path,
    publisher_name: &str,
    on_progress: &mut dyn FnMut(ProgressEvent),
) -> Result<BindResult> {
    let row = ctx.db.get(operator_id)?;

    let active_subkey = ctx.db.active_subkey(operator_id)?;
    let subkey_cert_path = active_subkey
        .as_ref()
        .map(|row| PathBuf::from(row.subkey_cert_path.clone()));

    let mut priv_buf = if let Some(subkey) = active_subkey {
        // See the TODO(custody) in subkey_rotate: the sub-key priv is
        // a plaintext 0o600 file whose path we stored. Reading it back
        // is all the "custody" this branch has.
        let bytes = std::fs::read(&subkey.subkey_priv_path).map_err(|e| {
            WizardError::Pricing(format!(
                "read active sub-key priv {}: {e}",
                subkey.subkey_priv_path
            ))
        })?;
        Zeroizing::new(bytes)
    } else {
        custody_get(ctx, &row.publisher_priv_keystore_alias)?
    };

    // Stage the OperatorRecord JSON for the subprocess.
    let record_path = ctx.staging_dir.join(format!("{operator_id}.record.json"));
    std::fs::create_dir_all(&ctx.staging_dir)
        .map_err(|e| WizardError::Pricing(format!("mkdir staging: {e}")))?;
    std::fs::write(&record_path, row.operator_record_json.as_bytes())
        .map_err(|e| WizardError::Pricing(format!("write record: {e}")))?;
    std::fs::create_dir_all(output_dir)
        .map_err(|e| WizardError::Pricing(format!("mkdir output: {e}")))?;
    let output_path = output_dir.join(format!("{operator_id}.sbp"));

    let now = (ctx.clock)();
    let res = ctx
        .cli
        .run_bind_and_sign(
            BindAndSignArgs {
                operator_record_path: &record_path,
                output_path: &output_path,
                phase,
                now_unix: now,
                expiry_days: 30,
                publisher_name,
                subkey_cert_path: subkey_cert_path.as_deref(),
            },
            priv_buf.as_slice(),
            on_progress,
        )
        .map_err(|e| WizardError::Pricing(e.to_string()))?;
    // Wipe priv-buf and the staged record JSON immediately.
    priv_buf.zeroize();
    let _ = std::fs::remove_file(&record_path);

    ctx.db
        .record_signed_sbp(operator_id, &res.sbp_sha256, &res.relay_pack_id, now)?;
    Ok(res)
}

/// `qr_render`: call `daal-deploy qr-fountain` and stream frames
/// to `on_frame`. The stream stops when `on_frame` returns false
/// or `max_frames` frames have been emitted.
///
/// The wizard frontend drives the FPS by buffering frames and
/// pulling them from the buffer on its render tick.
pub fn qr_render(
    ctx: &WizardCtx,
    operator_id: i64,
    block_size: u32,
    max_frames: u32,
    seed: i64,
    on_frame: &mut dyn FnMut(FountainFrame) -> bool,
) -> Result<()> {
    let row = ctx.db.get(operator_id)?;
    if row.signed_sbp_sha256.is_none() {
        return Err(WizardError::Pricing(
            "no signed SBP for this operator (run sign_relaypack first)".into(),
        ));
    }
    // Convention: sign_relaypack writes the .sbp to staging_dir.
    let sbp_path = ctx.staging_dir.join(format!("{operator_id}.sbp"));
    if !sbp_path.exists() {
        return Err(WizardError::Pricing(format!(
            "missing SBP file: {}",
            sbp_path.display()
        )));
    }
    ctx.cli
        .run_qr_fountain(&sbp_path, block_size, max_frames, seed, on_frame)
        .map_err(|e| WizardError::Pricing(e.to_string()))?;
    Ok(())
}

// ---- FRP-7 rotation surface --------------------------------------

/// `RotateRecommendInput` selects between the Explanation-driven
/// path (the recipient pasted their diagnostics JSON) and the
/// FRP-only context path. Exactly one variant is honoured per call.
#[derive(Debug, Clone)]
pub enum RotateRecommendInput {
    /// Recipient supplied a parsed FRP-3 Explanation as JSON.
    Explanation(String),
    /// FRP supplied failure classifications + signals + a leak hint.
    Context(crate::cli_bridge::RotateContext),
}

/// `rotate_recommend` calls the Go rotation recommender via the
/// daal-deploy CLI and returns the resulting recommendation.
pub fn rotate_recommend(
    ctx: &WizardCtx,
    operator_id: i64,
    input: RotateRecommendInput,
) -> Result<crate::cli_bridge::RotationRecommendation> {
    let row = ctx.db.get(operator_id)?;
    // Stage the OperatorRecord JSON so the CLI subprocess can read it.
    let record_path = ctx.staging_dir.join(format!("{operator_id}.record.json"));
    std::fs::create_dir_all(&ctx.staging_dir)
        .map_err(|e| WizardError::Pricing(format!("mkdir staging: {e}")))?;
    std::fs::write(&record_path, row.operator_record_json.as_bytes())
        .map_err(|e| WizardError::Pricing(format!("write record: {e}")))?;

    let res = match &input {
        RotateRecommendInput::Explanation(json) => {
            ctx.cli
                .run_rotate_recommend(crate::cli_bridge::RotateRecommendArgs {
                    record_path: &record_path,
                    explanation_json: Some(json),
                    context: None,
                })
        }
        RotateRecommendInput::Context(c) => {
            ctx.cli
                .run_rotate_recommend(crate::cli_bridge::RotateRecommendArgs {
                    record_path: &record_path,
                    explanation_json: None,
                    context: Some(c.clone()),
                })
        }
    }
    .map_err(|e| WizardError::Pricing(e.to_string()))?;

    // Erase the staged record JSON; it contains no secrets but
    // we keep the staging dir minimal between operations.
    let _ = std::fs::remove_file(&record_path);
    Ok(res)
}

/// `RotateExecuteInput` carries the level-specific parameters the
/// wizard collects in the RotateModal confirmation step.
#[derive(Debug, Clone, Default)]
pub struct RotateExecuteInput {
    pub level: String,
    pub reason: String,
    /// Helper machine public IP. Required when the selected
    /// rotation level recreates the VPS and therefore re-runs
    /// cloud-init firewall allowlisting.
    pub helper_ip: Option<String>,
    /// L3 only: floating-IP id to attach.
    pub new_floating_ip_id: Option<String>,
    /// L1 only.
    pub regen_credentials: bool,
    /// L2 only.
    pub new_sni: Option<String>,
    /// L2 only.
    pub new_ws_path: Option<String>,
    /// L4/L5/L6: new toolbox profile slug.
    pub new_toolbox_profile: Option<String>,
    /// FRP-9 L7/L8/L9 (cdn_fronted modes): the cdn_fronts row to
    /// rotate. The wizard CDN screen surfaces this via
    /// list_cdn_fronts; one row per front.
    pub cdn_front_id: Option<i64>,
    /// FRP-9 L7 only: Cloudflare account ID hosting the rewrite
    /// worker. (Zone ID is read off the cdn_fronts row.)
    pub cdn_account_id: Option<String>,
    /// FRP-9 L7 only: optional new public path; empty lets the
    /// CLI generate `/r/<hex>`.
    pub cdn_new_public_path: Option<String>,
    /// FRP-9 L8 only: new hostname (apex must be a zone the FRP's
    /// Cloudflare token controls).
    pub cdn_new_hostname: Option<String>,
    /// FRP-9 L8/L9: new origin IPv4 (L8 attaches to the new
    /// hostname; L9 re-points the existing one).
    pub cdn_new_origin_ipv4: Option<String>,
    /// FRP-9 L8/L9: optional new origin IPv6.
    pub cdn_new_origin_ipv6: Option<String>,
    /// FRP-9 L7/L8 only: publisher-controlled HTTPS URL where the
    /// re-signed SBP will be hosted. Required for publish-
    /// freshness; the freshness JSON document points recipients
    /// at this URL. Empty on L9 (no re-publish).
    pub freshness_signed_sbp_url: Option<String>,
}

/// `RotateExecuteOutput` is returned to the wizard once the
/// rotation transaction commits. The wizard renders the fresh
/// fingerprint + SBP path on the modal's success state.
#[derive(Debug, Clone, Serialize)]
pub struct RotateExecuteOutput {
    pub level: String,
    pub signed_sbp_id: i64,
    pub bind_result: crate::cli_bridge::BindResult,
    pub signed_at_unix: i64,
}

#[derive(Debug, Deserialize)]
struct RotateRecordForProvision {
    #[serde(default)]
    provider: String,
    #[serde(default)]
    region: String,
    #[serde(default)]
    server_type: String,
    #[serde(default)]
    toolbox_profile: String,
    #[serde(default)]
    enabled_families: Vec<String>,
    #[serde(default)]
    publisher_pub_key: String,
    #[serde(default)]
    candidates: Vec<RotateCandidateForProvision>,
    /// The cover host `reprovision` just rotated onto this relay.
    /// Forwarded to `provision` below; without it the rebuild
    /// re-derives the ORIGINAL host and the rotation is undone.
    #[serde(default)]
    cover_sni: String,
}

#[derive(Debug, Deserialize)]
struct RotateCandidateForProvision {
    #[serde(default)]
    family: String,
}

fn trimmed_opt(value: Option<&String>) -> Option<&str> {
    value.map(|s| s.trim()).filter(|s| !s.is_empty())
}

fn require_rotate_param(value: Option<&String>, label: &str) -> Result<String> {
    trimmed_opt(value)
        .map(|s| s.to_string())
        .ok_or_else(|| WizardError::Pricing(format!("rotation requires {label}")))
}

fn rotation_families(rec: &RotateRecordForProvision) -> Vec<String> {
    if !rec.enabled_families.is_empty() {
        return rec.enabled_families.clone();
    }
    let mut out = Vec::new();
    for c in &rec.candidates {
        if c.family.is_empty() || out.iter().any(|v| v == &c.family) {
            continue;
        }
        out.push(c.family.clone());
    }
    out
}

fn ws_path_fingerprint(path: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(path.as_bytes());
    let digest = hasher.finalize();
    format!("ws_path_fp:{}", hex::encode(&digest[..8]))
}

fn push_unique_json_string(arr: &mut Vec<serde_json::Value>, value: String) {
    if arr.iter().any(|v| v.as_str() == Some(value.as_str())) {
        return;
    }
    arr.push(serde_json::Value::String(value));
}

fn apply_l2_route_param_overrides(
    record_json: &str,
    new_sni: Option<&String>,
    new_ws_path: Option<&String>,
) -> Result<String> {
    let sni = trimmed_opt(new_sni);
    let ws_path = trimmed_opt(new_ws_path);
    if sni.is_none() && ws_path.is_none() {
        return Ok(record_json.to_string());
    }

    let mut root: serde_json::Value =
        serde_json::from_str(record_json).map_err(StagingError::from)?;
    let candidates = root
        .get_mut("candidates")
        .and_then(|v| v.as_array_mut())
        .ok_or_else(|| WizardError::Pricing("rotation record missing candidates[]".into()))?;
    for cand in candidates {
        let Some(obj) = cand.as_object_mut() else {
            continue;
        };
        let family = obj
            .get("family")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        if !obj.get("params").is_some_and(|v| v.is_object()) {
            obj.insert("params".into(), serde_json::json!({}));
        }
        if let Some(params) = obj.get_mut("params").and_then(|v| v.as_object_mut()) {
            if let Some(sni) = sni {
                params.insert("sni".into(), serde_json::Value::String(sni.to_string()));
                if family == "vless-reality" {
                    params.insert(
                        "reality_dest".into(),
                        serde_json::Value::String(sni.to_string()),
                    );
                }
            }
            if let Some(ws_path) = ws_path {
                params.insert(
                    "ws_path".into(),
                    serde_json::Value::String(ws_path.to_string()),
                );
            }
        }
        if !obj.get("public_risk_tags").is_some_and(|v| v.is_array()) {
            obj.insert("public_risk_tags".into(), serde_json::json!([]));
        }
        if let Some(tags) = obj
            .get_mut("public_risk_tags")
            .and_then(|v| v.as_array_mut())
        {
            if let Some(sni) = sni {
                push_unique_json_string(tags, format!("sni:{sni}"));
            }
            if let Some(ws_path) = ws_path {
                push_unique_json_string(tags, ws_path_fingerprint(ws_path));
            }
        }
    }

    serde_json::to_string(&root).map_err(|e| WizardError::Staging(StagingError::from(e)))
}

/// `rotate_execute` runs the two-stage rotation: (1) Provider
/// mutation via the CLI (`reprovision` for L1/L2/L4/L5/L6,
/// `assign-fip` for L3), then (2) re-sign the RelayPack and
/// commit the V003 history transaction.
pub fn rotate_execute(
    ctx: &WizardCtx,
    operator_id: i64,
    input: RotateExecuteInput,
    on_progress: &mut dyn FnMut(ProgressEvent),
) -> Result<RotateExecuteOutput> {
    let row = ctx.db.get(operator_id)?;
    let token = custody_get_string(ctx, &row.cloud_token_keystore_alias)?;

    std::fs::create_dir_all(&ctx.staging_dir)
        .map_err(|e| WizardError::Pricing(format!("mkdir staging: {e}")))?;
    let record_path = ctx
        .staging_dir
        .join(format!("{operator_id}.rotate.record.json"));
    std::fs::write(&record_path, row.operator_record_json.as_bytes())
        .map_err(|e| WizardError::Pricing(format!("write rotation record: {e}")))?;

    on_progress(ProgressEvent {
        step: "rotate_provider_start".into(),
        message: format!("level={}", input.level),
        ts: String::new(),
        extra: Default::default(),
    });

    match input.level.as_str() {
        "L3" => {
            let fip_id = require_rotate_param(input.new_floating_ip_id.as_ref(), "floating IP id")?;
            let updated = ctx
                .cli
                .run_assign_fip(AssignFipArgs {
                    record_path: &record_path,
                    token: token.as_str(),
                    fip_id: &fip_id,
                })
                .map_err(|e| WizardError::Pricing(e.to_string()))?;
            ctx.db.update_record_json(operator_id, &updated)?;
        }
        "L1" | "L2" | "L4" | "L5" | "L6" => {
            let updated = ctx
                .cli
                .run_reprovision(ReprovisionArgs {
                    record_path: &record_path,
                    token: token.as_str(),
                    regen_credentials: input.regen_credentials || input.level == "L1",
                    new_sni: trimmed_opt(input.new_sni.as_ref()),
                    new_ws_path: trimmed_opt(input.new_ws_path.as_ref()),
                    new_toolbox_profile: trimmed_opt(input.new_toolbox_profile.as_ref()),
                })
                .map_err(|e| WizardError::Pricing(e.to_string()))?;

            let rec: RotateRecordForProvision =
                serde_json::from_str(&updated).map_err(StagingError::from)?;
            // An explicit override still wins; otherwise take the
            // persisted V012 value. Before V012 this was a required
            // parameter the UI had no way to supply on a resumed
            // session, so a rotation could fail on "rotation requires
            // helper IP" with no field on screen to satisfy it.
            let helper_ip = match trimmed_opt(input.helper_ip.as_ref()) {
                Some(s) => s.to_string(),
                None => require_helper_ip(ctx, operator_id)?,
            };
            let pub_bytes = B64
                .decode(rec.publisher_pub_key.as_bytes())
                .map_err(|e| WizardError::Pricing(format!("pubkey base64: {e}")))?;
            let pubkey_path = ctx.staging_dir.join(format!("{operator_id}.rotate.pub"));
            std::fs::write(&pubkey_path, &pub_bytes)
                .map_err(|e| WizardError::Pricing(format!("write rotation pubkey: {e}")))?;

            let families_owned = rotation_families(&rec);
            let families: Vec<&str> = families_owned.iter().map(|s| s.as_str()).collect();
            let provider = if rec.provider.is_empty() {
                row.cloud_provider.as_str()
            } else {
                rec.provider.as_str()
            };
            if rec.region.is_empty() || rec.server_type.is_empty() {
                let _ = std::fs::remove_file(&pubkey_path);
                return Err(WizardError::Pricing(
                    "rotation record missing region/server_type".into(),
                ));
            }
            let toolbox_profile = trimmed_opt(input.new_toolbox_profile.as_ref())
                .or_else(|| {
                    if rec.toolbox_profile.is_empty() {
                        None
                    } else {
                        Some(rec.toolbox_profile.as_str())
                    }
                })
                .unwrap_or("iran-default");
            let mut provisioned = ctx
                .cli
                .run_provision(
                    ProvisionArgs {
                        provider,
                        region: &rec.region,
                        server_type: &rec.server_type,
                        toolbox_profile,
                        families,
                        helper_ip: &helper_ip,
                        pubkey_file: &pubkey_path,
                        token: token.as_str(),
                        dry_run: false,
                        existing_server_id: "",
                        // THE ROTATION'S ACTUAL PAYLOAD, for L2.
                        //
                        // `reprovision` computed a fresh cover host
                        // (provider.NextCoverSNI, excluding the one this
                        // relay is advertising today) and wrote it into
                        // the record we just deserialized. `provision`
                        // seeds its own pick on the derived server name,
                        // which is a pure function of (publisher key,
                        // region) and is unchanged by a rebuild — so
                        // omitting this hands the relay back the exact
                        // host it was rotated off, and then rewrites the
                        // record to agree, making the reversion
                        // invisible. An operator would burn a relay,
                        // pay for a full rebuild, and get the blocked
                        // SNI back.
                        cover_sni: &rec.cover_sni,
                        // Same reasoning as provision_run: the rotation
                        // only writes the record back on success, so a
                        // kept half-built box would be invisible to the
                        // app and still billing.
                        rollback_on_failure: true,
                    },
                    on_progress,
                )
                .map_err(|e| WizardError::Pricing(e.to_string()))?;
            if input.level == "L2" {
                provisioned = apply_l2_route_param_overrides(
                    &provisioned,
                    input.new_sni.as_ref(),
                    input.new_ws_path.as_ref(),
                )?;
            }
            let _ = std::fs::remove_file(&pubkey_path);
            ctx.db.update_record_json(operator_id, &provisioned)?;
            ctx.db.mark_provisioned(operator_id, (ctx.clock)())?;
        }
        // FRP-9 L7: cdn_fronted public-path rotation. The visible
        // /r/<hex> path changes; hostname + origin path unchanged.
        // Requires re-sign because public_path → ws_path_fp tag
        // changes.
        "L7_CDN_PATH" => {
            let front_id = input
                .cdn_front_id
                .ok_or_else(|| WizardError::Cdn("L7_CDN_PATH requires cdn_front_id".into()))?;
            let account_id = require_rotate_param(input.cdn_account_id.as_ref(), "cdn_account_id")?;
            let new_path = input.cdn_new_public_path.clone().unwrap_or_default();
            let _res = rotate_cdn_path(
                ctx,
                &RotateCdnPathInput {
                    front_id,
                    account_id,
                    new_public_path: new_path,
                },
            )?;
        }
        // FRP-9 L8: cdn_fronted hostname rotation. The hostname
        // changes; public path unchanged. Requires re-sign because
        // host:/sni:/public_domain: tags change.
        "L8_CDN_HOSTNAME" => {
            let front_id = input
                .cdn_front_id
                .ok_or_else(|| WizardError::Cdn("L8_CDN_HOSTNAME requires cdn_front_id".into()))?;
            let new_hostname =
                require_rotate_param(input.cdn_new_hostname.as_ref(), "cdn_new_hostname")?;
            let origin_ipv4 =
                require_rotate_param(input.cdn_new_origin_ipv4.as_ref(), "cdn_new_origin_ipv4")?;
            let origin_ipv6 = input.cdn_new_origin_ipv6.clone().unwrap_or_default();
            let _res = rotate_cdn_hostname(
                ctx,
                &RotateCdnHostnameInput {
                    front_id,
                    new_hostname,
                    origin_ipv4,
                    origin_ipv6,
                },
            )?;
        }
        // FRP-9 L9: cdn_fronted origin-only rotation. Per
        // supplement §14.4 this MUST NOT re-sign the RelayPack —
        // every public-surface field is byte-identical, the
        // censor sees nothing. We commit a history row with a
        // dedicated reason tag so the audit view distinguishes
        // it from L1–L8.
        "L9_CDN_ORIGIN" => {
            let front_id = input
                .cdn_front_id
                .ok_or_else(|| WizardError::Cdn("L9_CDN_ORIGIN requires cdn_front_id".into()))?;
            let origin_ipv4 =
                require_rotate_param(input.cdn_new_origin_ipv4.as_ref(), "cdn_new_origin_ipv4")?;
            let origin_ipv6 = input.cdn_new_origin_ipv6.clone().unwrap_or_default();
            let _res = rotate_cdn_origin(
                ctx,
                &RotateCdnOriginInput {
                    front_id,
                    new_origin_ipv4: origin_ipv4,
                    new_origin_ipv6: origin_ipv6,
                },
            )?;
            let _ = std::fs::remove_file(&record_path);
            on_progress(ProgressEvent {
                step: "rotate_provider_done".into(),
                message: "level=L9_CDN_ORIGIN (origin-only, no re-sign)".into(),
                ts: String::new(),
                extra: Default::default(),
            });
            // Record a history row WITHOUT re-signing. The
            // signed_sbp_id slot is zero so downstream readers
            // can distinguish L9 from re-signed rotations.
            let now = (ctx.clock)();
            let _ = ctx.db.record_origin_only_rotation(
                operator_id,
                now,
                &format!("{} | {}", input.level, input.reason),
            );
            on_progress(ProgressEvent {
                step: "rotate_done".into(),
                message: "L9_CDN_ORIGIN: origin re-pointed; RelayPack unchanged".into(),
                ts: String::new(),
                extra: Default::default(),
            });
            return Ok(RotateExecuteOutput {
                level: input.level,
                signed_sbp_id: 0,
                bind_result: crate::cli_bridge::BindResult::default(),
                signed_at_unix: now,
            });
        }
        other => {
            let _ = std::fs::remove_file(&record_path);
            return Err(WizardError::Pricing(format!(
                "unsupported rotation level {other}"
            )));
        }
    }
    let _ = std::fs::remove_file(&record_path);

    on_progress(ProgressEvent {
        step: "rotate_provider_done".into(),
        message: format!("level={}", input.level),
        ts: String::new(),
        extra: Default::default(),
    });

    on_progress(ProgressEvent {
        step: "rotate_bind_start".into(),
        message: "re-signing RelayPack".into(),
        ts: String::new(),
        extra: Default::default(),
    });

    // Re-sign the RelayPack using the same flow as FRP-4b's
    // sign_relaypack — it reads the publisher key from custody.
    //
    // The phase MUST be the same constant the initial sign used. It
    // was literal "V1.5" here while the wizard's first sign was
    // "V1.6", so every rotation silently downgraded the pack's phase
    // and re-closed RP004 / RP021 on the recipient.
    let bind = sign_relaypack(
        ctx,
        operator_id,
        crate::phase::RELAYPACK_PHASE,
        &ctx.staging_dir,
        "Family Relay Publisher",
        on_progress,
    )?;

    // FRP-9 commit 4/8: on L7 (path) and L8 (hostname) rotations
    // we MUST re-publish the freshness JSON document so recipients
    // can re-walk the sub-key chain on the new bundle. L1–L6 keep
    // the existing freshness document because the public-domain /
    // path / SNI / WS path that the recipient connects to is
    // unchanged from the freshness fetcher's vantage at V1.5
    // (freshness URL itself is FRP-controlled and stable).
    //
    // Per supplement §14.4 the L9 origin-only path early-returns
    // before this point; freshness is intentionally NOT touched.
    if matches!(input.level.as_str(), "L7_CDN_PATH" | "L8_CDN_HOSTNAME") {
        let signed_url = require_rotate_param(
            input.freshness_signed_sbp_url.as_ref(),
            "freshness_signed_sbp_url",
        )?;
        publish_freshness_after_rotate(ctx, operator_id, &bind, &signed_url, on_progress)?;
    }

    let now = (ctx.clock)();
    // Persist the rotation in the V003 history table.
    let new_sbp_id = ctx.db.record_rotated_sbp(
        operator_id,
        now,
        &bind.sbp_path,
        &bind.sbp_sha256,
        &bind.relay_pack_id,
        bind.shared_risk_edges.max(0),
        &format!("{} | {}", input.level, input.reason),
    )?;

    on_progress(ProgressEvent {
        step: "rotate_done".into(),
        message: format!("signed_sbps id={new_sbp_id}"),
        ts: String::new(),
        extra: Default::default(),
    });

    Ok(RotateExecuteOutput {
        level: input.level,
        signed_sbp_id: new_sbp_id,
        bind_result: bind,
        signed_at_unix: now,
    })
}

/// FRP-9 commit 4/8: build + sign + (eventually) publish a fresh
/// freshness JSON document after an L7 / L8 rotation. The current
/// signed-SBP URL is the FRP's published bundle URL; the
/// recipient's freshness fetcher (core/refresh/relaypack.go)
/// reads this document and redirects to the new bundle.
///
/// This commit ships the wizard ↔ CLI plumbing and the in-memory
/// build + sign flow (covered by publisher/deploy/freshness
/// tests). Live backend Put (R2 / GH Pages) lands in a follow-up
/// patch alongside the SDK wiring; the wizard stages the signed
/// bytes in `<staging_dir>/freshness.<operator_id>.json` so a
/// manual upload (or the CI bridge planned for FRP-9 commit 8/8)
/// can publish them.
fn publish_freshness_after_rotate(
    ctx: &WizardCtx,
    operator_id: i64,
    bind: &BindResult,
    signed_sbp_url: &str,
    on_progress: &mut dyn FnMut(ProgressEvent),
) -> Result<()> {
    let row = ctx.db.get(operator_id)?;
    // publisher_pub_hex is already stored as hex in V002.
    let publisher_pub_hex = row.publisher_pub_hex.clone();

    // Stash the priv key (or active sub-key) in a mode-0600
    // tempfile inside the staging dir; delete on exit. The
    // daal-deploy publish-freshness CLI reads from a path
    // (rather than stdin) so this temp-file step is unavoidable
    // — we keep its lifetime as short as possible.
    let active_subkey = ctx.db.active_subkey(operator_id)?;
    let priv_dir = ctx.staging_dir.join(format!("freshness.{operator_id}"));
    std::fs::create_dir_all(&priv_dir)
        .map_err(|e| WizardError::Pricing(format!("mkdir freshness staging: {e}")))?;
    let priv_path = priv_dir.join("priv.bin");
    let mut subkey_cert_path: Option<PathBuf> = None;

    let mut priv_buf = if let Some(subkey) = active_subkey {
        subkey_cert_path = Some(PathBuf::from(subkey.subkey_cert_path.clone()));
        let bytes = std::fs::read(&subkey.subkey_priv_path).map_err(|e| {
            WizardError::Pricing(format!(
                "read sub-key priv {}: {e}",
                subkey.subkey_priv_path
            ))
        })?;
        Zeroizing::new(bytes)
    } else {
        custody_get(ctx, &row.publisher_priv_keystore_alias)?
    };
    std::fs::write(&priv_path, priv_buf.as_slice())
        .map_err(|e| WizardError::Pricing(format!("write priv tempfile: {e}")))?;
    // mode-0600 on POSIX. tempfile crate's NamedTempFile would
    // also work; we open + chmod by hand to stay on the same
    // path-based contract used by cf_token elsewhere.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&priv_path, std::fs::Permissions::from_mode(0o600));
    }
    priv_buf.zeroize();

    let out_file = ctx
        .staging_dir
        .join(format!("freshness.{operator_id}.json"));

    on_progress(ProgressEvent {
        step: "publish_freshness_start".into(),
        message: format!("relay_pack_id={}", bind.relay_pack_id),
        ts: String::new(),
        extra: Default::default(),
    });

    let res = if subkey_cert_path.is_some() {
        ctx.cli.run_publish_freshness(PublishFreshnessArgs {
            relay_pack_id: &bind.relay_pack_id,
            current_bundle_sha256: &bind.sbp_sha256,
            current_signed_url: signed_sbp_url,
            publisher_pub_hex: &publisher_pub_hex,
            root_priv_path: None,
            subkey_priv_path: Some(&priv_path),
            subkey_cert_path: subkey_cert_path.as_deref(),
            out_file: Some(&out_file),
            now_unix: (ctx.clock)(),
        })
    } else {
        ctx.cli.run_publish_freshness(PublishFreshnessArgs {
            relay_pack_id: &bind.relay_pack_id,
            current_bundle_sha256: &bind.sbp_sha256,
            current_signed_url: signed_sbp_url,
            publisher_pub_hex: &publisher_pub_hex,
            root_priv_path: Some(&priv_path),
            subkey_priv_path: None,
            subkey_cert_path: None,
            out_file: Some(&out_file),
            now_unix: (ctx.clock)(),
        })
    };
    // Always best-effort wipe + delete the priv tempfile.
    if let Ok(mut fbytes) = std::fs::read(&priv_path) {
        for b in fbytes.iter_mut() {
            *b = 0;
        }
        let _ = std::fs::write(&priv_path, &fbytes);
    }
    let _ = std::fs::remove_file(&priv_path);
    let _ = std::fs::remove_dir(&priv_dir);

    let res = res.map_err(|e| WizardError::Pricing(format!("publish-freshness: {e}")))?;

    on_progress(ProgressEvent {
        step: "publish_freshness_done".into(),
        message: format!("doc={}", res.signed_doc_path),
        ts: String::new(),
        extra: Default::default(),
    });
    Ok(())
}

/// `rotate_revert` flips the most-recent inactive history row back
/// to active and updates the operators projection. No CLI
/// subprocess; pure DB op.
pub fn rotate_revert(
    ctx: &WizardCtx,
    operator_id: i64,
) -> Result<crate::operator_db::SignedSbpRow> {
    let restored = ctx.db.revert_to_previous_sbp(operator_id)?;
    Ok(restored)
}

/// `list_rotation_history` returns the V003 history rows for the
/// wizard's audit view.
pub fn list_rotation_history(
    ctx: &WizardCtx,
    operator_id: i64,
) -> Result<Vec<crate::operator_db::SignedSbpRow>> {
    Ok(ctx.db.list_signed_sbps_history(operator_id)?)
}

fn cloud_alias(id: i64) -> String {
    format!("daal.cloud.{id}.token")
}

fn pub_alias(id: i64) -> String {
    format!("daal.publisher.{id}.priv")
}

fn cloudflare_alias(id: i64) -> String {
    format!("daal.cloudflare.{id}.token")
}

/// True for aliases holding an irreplaceable Ed25519 signing key.
/// Everything else this app stores (cloud tokens, Cloudflare tokens)
/// can be re-pasted from the provider's dashboard; a lost signing key
/// orphans the relay permanently. The migration orders and reports on
/// these separately for exactly that reason.
fn is_signing_key_alias(alias: &str) -> bool {
    alias.starts_with("daal.publisher.") && alias.ends_with(".priv")
}

// ---------------------------------------------------------------
// Device custody: status, one-time PIN migration, recovery export
// ---------------------------------------------------------------

/// Rate-limit window for the one surviving PIN entry point,
/// [`migrate_from_pin`]. The migration is a once-per-device event, so
/// a ceiling costs a legitimate user nothing.
const PIN_ATTEMPT_WINDOW_SECS: i64 = 15 * 60;

/// Failed PINs tolerated inside `PIN_ATTEMPT_WINDOW_SECS`.
const MAX_PIN_ATTEMPTS_PER_WINDOW: i64 = 10;

/// Honest custody report for the publisher surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublisherCustodyStatus {
    /// "hardware" | "os_keystore" | "session_passphrase".
    pub level: String,
    /// `DeviceCustody::is_unlocked()`.
    pub unlocked: bool,
    /// True only if a live put→get→forget probe succeeded.
    ///
    /// Never gate "can I sign?" on `unlocked` alone: both
    /// `AndroidKeystoreDwk::is_ready()` and `KeyringDwk::is_ready()`
    /// return `true` unconditionally, so a completely broken keystore
    /// reports itself as unlocked right up until the first real
    /// operation fails.
    pub ok: bool,
    /// Non-empty when `ok == false`. Carries the same stable
    /// `E_CUSTODY_*` prefix as a thrown command error, so the UI can
    /// run it through `classifyPublisherError` and tell "just needs a
    /// passphrase" apart from "this keystore is broken" — which decide
    /// between an unlock sheet and a dead-end error card.
    pub error: String,
    /// True when at least one legacy PIN-sealed blob still exists and
    /// its custody counterpart does not.
    pub legacy_pending: bool,
    /// The aliases awaiting migration. Empty when `legacy_pending`.
    pub legacy_aliases: Vec<String>,
    /// True when at least one custody blob is already on disk — i.e.
    /// a session passphrase has been chosen on this device before.
    ///
    /// The unlock sheet is *both* "create a passphrase" and "enter
    /// your passphrase", and [`custody_unlock`] deliberately accepts
    /// anything on a first run (there is no stored blob to be wrong
    /// about). Without this flag the UI cannot tell the two apart, so
    /// a brand-new install is asked to "enter" a passphrase that does
    /// not exist yet — and whatever the user types, including a typo,
    /// silently becomes the wrap key for a signing key generated
    /// minutes later. There is no escrow for that mistake.
    ///
    /// Detected without decrypting anything: `FileCustody::get` reads
    /// the blob file *before* it touches the DWK, so a locked custody
    /// still answers `NotFound` for an absent alias and something else
    /// for a present one.
    pub passphrase_set: bool,
}

/// Outcome of one [`migrate_from_pin`] run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyMigrationReport {
    /// Moved, verified by read-back, legacy blob then forgotten.
    pub migrated: Vec<String>,
    /// Already readable from custody; nothing to do.
    pub skipped: Vec<String>,
    /// "alias: reason". The legacy blob is left **intact** for these.
    pub failed: Vec<String>,
    /// True iff every publisher signing key is now readable from
    /// custody. The UI may not dismiss the migration gate while this
    /// is false.
    pub signing_keys_safe: bool,
}

/// The alias inventory the custody surface cares about, de-duplicated
/// and ordered signing-keys-first.
fn publisher_aliases(ctx: &WizardCtx) -> Result<Vec<String>> {
    let mut aliases = ctx.db.list_all_keystore_aliases()?;
    aliases.sort();
    aliases.dedup();
    // Signing keys first: if the process dies mid-run, the thing that
    // got moved is the thing that cannot be replaced.
    aliases.sort_by_key(|a| !is_signing_key_alias(a));
    Ok(aliases)
}

/// Probe custody for real rather than asking it whether it feels ready.
/// Returns `Ok(())` only if a value round-trips through the backend.
fn probe_custody(ctx: &WizardCtx) -> std::result::Result<(), CustodyError> {
    // unlock(None) forces the DWK to materialise, which is what
    // surfaces an Android JNI / libsecret failure eagerly.
    ctx.custody.unlock(None)?;
    const PROBE: &str = "daal.custody.probe";
    ctx.custody.put(PROBE, b"1")?;
    let got = ctx.custody.get(PROBE);
    let _ = ctx.custody.forget(PROBE);
    let got = got?;
    if got != b"1" {
        return Err(CustodyError::Backend(
            "custody probe returned different bytes than were written".into(),
        ));
    }
    Ok(())
}

/// Unlock session-passphrase custody and verify the passphrase was
/// actually right.
///
/// `unlock` alone cannot tell: it only derives a key from whatever the
/// user typed and caches it. Neither can the round-trip probe in
/// [`custody_status`] — it writes and reads with the *same* derived
/// key, so a wrong passphrase round-trips perfectly. The only real
/// test is opening a blob that was written under the correct key, so
/// that is what this does.
///
/// If no existing blob is found there is nothing to be wrong about:
/// this is a first unlock, and the passphrase the user just chose
/// becomes the passphrase. Reporting "wrong" there would lock a user
/// out of their own fresh install.
pub fn custody_unlock(ctx: &WizardCtx, passphrase: &str) -> Result<PublisherCustodyStatus> {
    ctx.custody
        .unlock(Some(passphrase))
        .map_err(|e| coded(E_CUSTODY_BACKEND, e))?;

    // Candidates: every publisher secret, plus the recipient identity
    // (read-only — we never write it here; it shares the same custody
    // and is often the only blob present on a recipient-first install).
    let mut candidates = publisher_aliases(ctx)?;
    candidates.push("recipient_priv_x25519".to_string());

    for alias in &candidates {
        // Zeroizing: on the success path this is a decrypted signing
        // key, and we only wanted to know that it opened.
        match ctx.custody.get(alias).map(Zeroizing::new) {
            // Opened a real blob — the passphrase is right.
            Ok(_) => break,
            // No blob under this alias: says nothing about the
            // passphrase, keep looking.
            Err(CustodyError::NotFound(_)) => continue,
            // A blob exists and will not open. Within the attribution
            // window FileCustody has already called this a passphrase
            // problem; either way the user's answer did not work.
            Err(CustodyError::WrongPassphrase) | Err(CustodyError::BindingMismatch) => {
                return Err(coded(
                    E_CUSTODY_WRONG_PASS,
                    "that passphrase does not open this device's stored keys",
                ));
            }
            Err(e) => return Err(coded(E_CUSTODY_BACKEND, e)),
        }
    }

    let now = (ctx.clock)();
    let level = ctx.custody.level().as_str().to_string();
    let _ = ctx.db.insert_custody_event(now, "unlocked", &level, "{}");
    custody_status(ctx)
}

/// Report the custody level, whether it actually works, and whether a
/// one-time PIN migration is still outstanding.
///
/// On a device that never ran the PIN build this must be completely
/// silent: every alias is absent, so `legacy_pending` is false and the
/// UI shows no banner, no sheet and no prompt. That silence is the
/// entire point of removing the PIN.
pub fn custody_status(ctx: &WizardCtx) -> Result<PublisherCustodyStatus> {
    let (ok, error) = match probe_custody(ctx) {
        Ok(()) => (true, String::new()),
        // The probe alias is a scratch value, never a stored secret,
        // so NotFound here can only mean the backend swallowed the
        // write — which is a backend fault, not a missing key.
        Err(CustodyError::Locked) => (
            false,
            format!("{E_CUSTODY_LOCKED}: unlock this device's key store to continue"),
        ),
        Err(CustodyError::WrongPassphrase) => (
            false,
            format!("{E_CUSTODY_WRONG_PASS}: that passphrase does not match"),
        ),
        Err(e) => (false, format!("{E_CUSTODY_BACKEND}: {e}")),
    };

    let mut legacy_aliases = Vec::new();
    // A blob that is present but unreadable (locked custody, wrong
    // wrap key) still proves a passphrase was chosen on this device
    // once. `NotFound` is the only answer that means "nothing stored".
    // The recipient identity shares the same custody, and on a
    // recipient-first install it is often the only blob there is.
    let mut passphrase_set = !matches!(
        ctx.custody.get(crate::recipient_identity::RECIPIENT_PRIV_ALIAS),
        Err(CustodyError::NotFound(_))
    );
    for alias in publisher_aliases(ctx)? {
        if !matches!(ctx.custody.get(&alias), Err(CustodyError::NotFound(_))) {
            passphrase_set = true;
        }
        // Already migrated → nothing to do. Note this is a real read:
        // presence of the blob is not enough, it must open.
        if custody_has(ctx, &alias) {
            continue;
        }
        // PIN-free probe. Never open the legacy blob to test it — on
        // desktop that is the OS keyring and a read can raise a
        // platform unlock prompt the user did not ask for.
        if ctx.keystore.has(&alias) {
            legacy_aliases.push(alias);
        }
    }

    Ok(PublisherCustodyStatus {
        level: ctx.custody.level().as_str().to_string(),
        unlocked: ctx.custody.is_unlocked(),
        ok,
        error,
        legacy_pending: !legacy_aliases.is_empty(),
        legacy_aliases,
        passphrase_set,
    })
}

/// One-time upgrade: move every legacy PIN-sealed secret into device
/// custody. Idempotent and resumable.
///
/// # The safety property
///
/// **A legacy blob is deleted only after the same plaintext has been
/// written under custody AND read back byte-identical.** Losing
/// `daal.publisher.<id>.priv` permanently orphans a relay: signing,
/// adding a recipient, revoking a recipient and rotating all die, and
/// there is no escrow anywhere. Already-distributed packs keep working
/// and the box keeps running, so the user does not even find out until
/// the next time they try to add someone. Every failure path below
/// therefore leaves the legacy blob exactly where it was.
///
/// A crash between the write and the delete leaves both copies, which
/// the next run classifies as `skipped`. That is the intended failure
/// mode: duplicated, never absent.
pub fn migrate_from_pin(ctx: &WizardCtx, pin: &str) -> Result<CustodyMigrationReport> {
    // A locked session-passphrase custody cannot accept a single
    // `put`, so every alias would be unsealed with the PIN (briefly
    // materialising every signing key in memory) only to fail at the
    // write. Worse, the gate that shows this sheet has no unlock
    // control on it, so the run could never start succeeding. Refuse
    // up front with the code that routes the user to the unlock sheet.
    if !ctx.custody.is_unlocked() {
        return Err(coded(
            E_CUSTODY_LOCKED,
            "unlock this device's key store before upgrading the old PIN store",
        ));
    }
    // The PIN is on its way out, but this is still a 6-digit secret
    // behind a tap-and-retry loop: without a ceiling, anyone holding
    // the unlocked device could walk the whole space one guess at a
    // time. The old build rate-limited exactly this path; the dormant
    // V001 `pin_attempts` table is reused rather than reintroducing a
    // module for it.
    let now = (ctx.clock)();
    let recent_failures = ctx
        .db
        .count_recent_failed_pins(now - PIN_ATTEMPT_WINDOW_SECS)
        .unwrap_or(0);
    if recent_failures >= MAX_PIN_ATTEMPTS_PER_WINDOW {
        return Err(WizardError::Validation(format!(
            "too many incorrect PINs — wait {} minutes and try again",
            PIN_ATTEMPT_WINDOW_SECS / 60
        )));
    }

    let mut report = CustodyMigrationReport {
        migrated: Vec::new(),
        skipped: Vec::new(),
        failed: Vec::new(),
        signing_keys_safe: false,
    };
    let aliases = publisher_aliases(ctx)?;
    let level = ctx.custody.level().as_str().to_string();
    // How many legacy blobs we have actually tried to open. Only the
    // FIRST one carries information about the PIN itself — see below.
    let mut opens_attempted = 0usize;

    for alias in &aliases {
        if custody_has(ctx, alias) {
            report.skipped.push(alias.clone());
            continue;
        }
        if !ctx.keystore.has(alias) {
            // Absent from both stores — e.g. a Cloudflare alias for an
            // operator that never provisioned a CDN front.
            continue;
        }

        // 1. Unseal with the legacy PIN. Zeroizing so the plaintext
        //    does not outlive this iteration.
        opens_attempted += 1;
        let plain: Zeroizing<Vec<u8>> = match ctx.keystore.open(alias, pin) {
            Ok(b) => Zeroizing::new(b),
            Err(KeystoreError::WrongPin) => {
                // `Keystore::open` collapses *every* AEAD failure into
                // WrongPin, so a single truncated blob (the legacy
                // writer used a non-atomic fs::write) is
                // indistinguishable from a bad PIN. Aborting the run on
                // any of them would strand every other relay's
                // recoverable signing key behind a gate with no exit.
                //
                // Only the first blob we try says anything about the
                // PIN: if that one opens, the PIN is right and a later
                // failure is that blob's problem, not the user's.
                if opens_attempted == 1 {
                    ctx.db.record_pin_attempt(now, false).ok();
                    return Err(WizardError::Keystore(KeystoreError::WrongPin));
                }
                report
                    .failed
                    .push(format!("{alias}: will not decrypt (blob damaged?)"));
                continue;
            }
            Err(e) => {
                report.failed.push(format!("{alias}: {e}"));
                continue;
            }
        };

        // 2. Write under custody.
        if let Err(e) = ctx.custody.put(alias, &plain) {
            report.failed.push(format!("{alias}: put: {e}"));
            continue; // legacy blob INTACT
        }

        // 3. Verify by read-back. This is the safety property; without
        //    it, a keystore that silently swallows writes would eat the
        //    signing key at step 4.
        match ctx.custody.get(alias).map(Zeroizing::new) {
            Ok(rb) if rb.as_slice() == plain.as_slice() => {}
            Ok(_) => {
                report.failed.push(format!("{alias}: read-back mismatch"));
                continue; // legacy blob INTACT
            }
            Err(e) => {
                report.failed.push(format!("{alias}: read-back: {e}"));
                continue; // legacy blob INTACT
            }
        }

        // 4. ONLY NOW erase the legacy copy. forget() is idempotent;
        //    a failure here is non-fatal because both copies exist and
        //    the next run's step-0 check turns this alias into a skip.
        //
        //    `put` above is durable before it returns (FileCustody
        //    fsyncs the blob and its directory), so this unlink cannot
        //    outrun the data it is replacing.
        if let Err(e) = ctx.keystore.forget(alias) {
            eprintln!("[custody-migrate] forget({alias}) failed: {e}");
        }
        report.migrated.push(alias.clone());
        let _ = ctx.db.insert_custody_event(
            now,
            "migrated",
            &level,
            &serde_json::json!({ "alias": alias }).to_string(),
        );
    }

    if opens_attempted > 0 {
        ctx.db.record_pin_attempt(now, true).ok();
    }

    // The verdict the UI gates on: not "did the run finish" but "is
    // every irreplaceable key readable from its new home".
    report.signing_keys_safe = aliases
        .iter()
        .filter(|a| is_signing_key_alias(a))
        .all(|a| custody_has(ctx, a));
    Ok(report)
}

/// Write a base64 recovery blob of the operator's Ed25519 signing key
/// to a 0o600 file in the staging dir and return its path.
///
/// This exists because device custody has one failure mode the PIN did
/// not: the Device Wrap Key lives in the AndroidKeyStore / OS keyring
/// and is **not** exportable, so a factory reset, an OS reinstall, or a
/// keystore invalidation destroys it — and with it every relay this
/// device publishes. There is no escrow. A file the user chooses to
/// keep is the only recovery path, and [`publisher_keyimport`] is the
/// restore.
///
/// The secret never crosses the IPC boundary: the caller (the Tauri
/// shim) receives a path, copies the file to Downloads, and unlinks
/// the staged copy.
pub fn export_recovery_key(ctx: &WizardCtx, operator_id: i64) -> Result<PathBuf> {
    let row = ctx.db.get(operator_id)?;
    if row.publisher_priv_keystore_alias.is_empty() {
        return Err(coded(
            E_SECRET_MISSING,
            "this relay has no publisher key yet",
        ));
    }
    let priv_bytes = custody_get(ctx, &row.publisher_priv_keystore_alias)?;
    let body = Zeroizing::new(B64.encode(priv_bytes.as_slice()));

    std::fs::create_dir_all(&ctx.staging_dir)
        .map_err(|e| WizardError::Pricing(format!("mkdir staging: {e}")))?;
    let path = ctx
        .staging_dir
        .join(format!("{operator_id}.recovery.daalkey"));
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| WizardError::Pricing(format!("write recovery key: {e}")))?;
        f.write_all(body.as_bytes())
            .map_err(|e| WizardError::Pricing(format!("write recovery key: {e}")))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&path, body.as_bytes())
            .map_err(|e| WizardError::Pricing(format!("write recovery key: {e}")))?;
    }
    let _ = ctx.db.insert_custody_event(
        (ctx.clock)(),
        "recovery_exported",
        ctx.custody.level().as_str(),
        &serde_json::json!({ "operator_id": operator_id }).to_string(),
    );
    Ok(path)
}

// ---------------------------------------------------------------
// Artifacts + helper IP
// ---------------------------------------------------------------

/// One distributable file belonging to a relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactInfo {
    /// "shared_sbp" | "raw_sbp" | "sbpx".
    pub kind: String,
    pub path: String,
    pub exists: bool,
    pub size_bytes: u64,
    pub modified_at_unix: i64,
    /// Only for `kind == "sbpx"`.
    pub recipient_id: Option<i64>,
    /// Display name (falling back to the on-box name); "" otherwise.
    pub recipient_label: String,
}

/// Enumerate a relay's artifacts: the shared `.sbp`, the raw signed
/// `.sbp`, and one `.sbpx` per recipient row.
///
/// Pure `std::fs::metadata` over conventional staging names — it
/// mutates nothing and is safe to call on every render. Missing files
/// come back with `exists: false` rather than being filtered out, so
/// the UI can explain the gap ("this recipient's pack failed to
/// build — rebuild it") instead of silently hiding a row the user is
/// looking for.
///
/// Ordering is a contract: index 0 is always `shared_sbp`, index 1 is
/// always `raw_sbp`, then `sbpx` entries by ascending recipient id.
pub fn list_artifacts(ctx: &WizardCtx, operator_id: i64) -> Result<Vec<ArtifactInfo>> {
    let mut out = Vec::new();
    let describe = |kind: &str,
                    path: PathBuf,
                    recipient_id: Option<i64>,
                    recipient_label: String|
     -> ArtifactInfo {
        let meta = std::fs::metadata(&path).ok();
        let modified_at_unix = meta
            .as_ref()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        ArtifactInfo {
            kind: kind.to_string(),
            path: path.to_string_lossy().to_string(),
            exists: meta.is_some(),
            size_bytes: meta.as_ref().map(|m| m.len()).unwrap_or(0),
            modified_at_unix,
            recipient_id,
            recipient_label,
        }
    };

    out.push(describe(
        "shared_sbp",
        ctx.staging_dir.join(format!("{operator_id}.shared.sbp")),
        None,
        String::new(),
    ));
    out.push(describe(
        "raw_sbp",
        ctx.staging_dir.join(format!("{operator_id}.sbp")),
        None,
        String::new(),
    ));

    let mut recipients = ctx.db.list_recipients(operator_id)?;
    recipients.sort_by_key(|r| r.id);
    for r in recipients {
        let label = if r.display_name.trim().is_empty() {
            r.name.clone()
        } else {
            r.display_name.clone()
        };
        out.push(describe(
            "sbpx",
            ctx.staging_dir
                .join(format!("{operator_id}.{}.sbpx", r.name)),
            Some(r.id),
            label,
        ));
    }
    Ok(out)
}

/// Read the persisted helper IP, or "" when never detected.
pub fn get_helper_ip(ctx: &WizardCtx, operator_id: i64) -> Result<String> {
    Ok(ctx.db.get(operator_id)?.helper_ip)
}

/// Persist the helper IP. Rejects anything that is not a textual IPv4
/// or IPv6 address — the auto-detect path races third-party echo
/// services, and a captive portal answering with an HTML login page
/// must never be stored as an address.
///
/// `source` is "auto" | "manual" | "whoami", recorded for diagnosis
/// only; nothing branches on it.
pub fn set_helper_ip(
    ctx: &WizardCtx,
    operator_id: i64,
    helper_ip: &str,
    source: &str,
) -> Result<()> {
    let trimmed = helper_ip.trim();
    if !is_valid_ip(trimmed) {
        // Deliberately un-prefixed: this is a bad argument from the
        // caller, not a helper-IP state the UI should try to self-heal.
        return Err(WizardError::Validation(format!(
            "not a valid IP address: {trimmed:?}"
        )));
    }
    let source = match source {
        "auto" | "manual" | "whoami" => source,
        _ => "auto",
    };
    ctx.db
        .set_helper_ip(operator_id, trimmed, source, (ctx.clock)())?;
    Ok(())
}

fn hex_of(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli_bridge::MockRunner;
    use std::sync::atomic::{AtomicI64, Ordering};
    use tempfile::tempdir;

    /// The canned pricing fixture every mock runner is built on.
    fn test_pricing() -> Pricing {
        Pricing {
            provider: "hetzner".into(),
            region: "fsn1".into(),
            server_type: "cx22".into(),
            hourly_eur: 0.005,
            monthly_eur: 3.85,
            included_traffic_tb_per_month: None,
            overage_eur_per_gb: None,
        }
    }

    fn ctx(now: i64) -> (WizardCtx, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let db = Arc::new(OperatorDb::open_in_memory().unwrap());
        let ks = Arc::new(Keystore::new_in_memory(dir.path()));
        let staging_dir = dir.path().join("staging");
        let cli = Arc::new(MockRunner::new(test_pricing()));
        let clock_tick = AtomicI64::new(now);
        let clock_arc: Arc<dyn Fn() -> i64 + Send + Sync> = Arc::new(move || {
            // Deterministic clock: ticks 1 s per call.
            clock_tick.fetch_add(1, Ordering::Relaxed)
        });
        let custody: Arc<dyn DeviceCustody> = Arc::new(
            crate::device_custody::FileCustody::static_test(dir.path()).unwrap(),
        );
        (
            WizardCtx {
                db,
                keystore: ks,
                staging_dir,
                cli,
                clock: clock_arc,
                custody,
            },
            dir,
        )
    }

    fn ctx_with_mock(
        now: i64,
        cli: Arc<MockRunner>,
    ) -> (WizardCtx, tempfile::TempDir, Arc<MockRunner>) {
        let dir = tempdir().unwrap();
        let db = Arc::new(OperatorDb::open_in_memory().unwrap());
        let ks = Arc::new(Keystore::new_in_memory(dir.path()));
        let staging_dir = dir.path().join("staging");
        let clock_arc: Arc<dyn Fn() -> i64 + Send + Sync> = Arc::new(move || now);
        let custody: Arc<dyn DeviceCustody> = Arc::new(
            crate::device_custody::FileCustody::static_test(dir.path()).unwrap(),
        );
        (
            WizardCtx {
                db,
                keystore: ks,
                staging_dir,
                cli: cli.clone(),
                clock: clock_arc,
                custody,
            },
            dir,
            cli,
        )
    }

    #[test]
    fn wizard_ctx_is_send_sync_for_tauri_state() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<WizardCtx>();
    }

    fn wizard_step_row(
        status: &str,
        token_alias: &str,
        record_json: &str,
        pub_hex: &str,
        signed: Option<&str>,
    ) -> crate::operator_db::OperatorRow {
        crate::operator_db::OperatorRow {
            id: 1,
            status: status.into(),
            operator_record_json: record_json.into(),
            publisher_pub_hex: pub_hex.into(),
            publisher_priv_keystore_alias: String::new(),
            cloud_provider: "hetzner".into(),
            cloud_token_keystore_alias: token_alias.into(),
            created_at_unix: 0,
            last_provisioned_at_unix: None,
            decommissioned_at_unix: None,
            signed_sbp_sha256: signed.map(|s| s.to_string()),
            signed_sbp_relay_pack_id: None,
            signed_sbp_at_unix: None,
            mgmt_port: 0,
            mgmt_tls_fingerprint: String::new(),
            nickname: String::new(),
            helper_ip: String::new(),
            helper_ip_source: String::new(),
            helper_ip_at_unix: 0,
        }
    }

    #[test]
    fn derive_wizard_step_resumes_provisioned_operator_at_distribute() {
        // Regression: a fully-provisioned operator whose record lost its
        // region/server_type (Hetzner create response can omit them) must
        // resume at "distribute", NOT regress to "pricing" — a dead end
        // that re-asks a size question the user can no longer act on.
        let row = wizard_step_row(
            "provisioned",
            "alias",
            r#"{"region":"","server_type":""}"#,
            "abcd",
            Some("deadbeef"),
        );
        assert_eq!(derive_wizard_step(&row), "distribute");

        // Provisioned but not yet signed → the sign step (also PIN-free).
        let row = wizard_step_row("provisioned", "alias", r#"{"region":"","server_type":""}"#, "abcd", None);
        assert_eq!(derive_wizard_step(&row), "sign");

        // Pre-provision with empty profile still routes to pricing.
        let row = wizard_step_row("pre-provision", "alias", r#"{"region":"","server_type":""}"#, "", None);
        assert_eq!(derive_wizard_step(&row), "pricing");

        // No token at all → provider step.
        let row = wizard_step_row("draft", "", "{}", "", None);
        assert_eq!(derive_wizard_step(&row), "provider");
    }

    #[test]
    fn full_happy_path_screens_0_to_finalize() {
        let (ctx, _dir) = ctx(1_700_000_000);
        let id = store_cloud_token(&ctx, "hetzner", "tok-abc", None).unwrap();
        select_profile(
            &ctx,
            id,
            "fsn1",
            "cpx12",
            "iran-default",
            vec!["vless-reality".into(), "hysteria2".into()],
        )
        .unwrap();
        let pricing = pricing_lookup(&ctx, id, "fsn1", "cpx12").unwrap();
        assert_eq!(pricing.hourly_eur, 0.005);
        let fp = publisher_keygen(&ctx, id).unwrap();
        assert_eq!(fp.en_words.split(' ').count(), 4);
        let path = finalize_pre_provision(&ctx, id).unwrap();
        assert!(path.exists());
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(
            body.contains("\"provider\""),
            "missing provider key: {body}"
        );
        assert!(
            body.contains("\"hetzner\""),
            "missing provider value: {body}"
        );
        assert!(body.contains("\"fsn1\""), "missing region value: {body}");
        assert!(
            body.contains("\"freshness_url\""),
            "missing freshness_url key: {body}"
        );
        assert!(
            body.contains("\"vless-reality\""),
            "missing enabled-family value"
        );

        let summaries = list_operators(&ctx).unwrap();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].status, "pre-provision");
    }

    #[test]
    fn store_token_rejects_empty_token() {
        let (ctx, _dir) = ctx(1_700_000_000);
        match store_cloud_token(&ctx, "hetzner", "   ", None) {
            Err(WizardError::EmptyToken) => (),
            other => panic!("wanted EmptyToken, got {other:?}"),
        }
    }

    #[test]
    fn store_token_with_operator_id_updates_instead_of_inserting() {
        // Regression: Back→Next on the wizard's first screen used to
        // INSERT a second operator row every time, littering the relay
        // list with half-built duplicates that each held their own
        // keystore aliases. Passing the known id must UPDATE.
        let (ctx, _dir) = ctx(1_700_000_000);
        let id = store_cloud_token(&ctx, "hetzner", "tok-one", None).unwrap();
        let again = store_cloud_token(&ctx, "hetzner", "tok-two", Some(id)).unwrap();
        assert_eq!(again, id, "update must reuse the row id");
        assert_eq!(list_operators(&ctx).unwrap().len(), 1, "no duplicate row");

        // And the row now holds the second token, not the first.
        let row = ctx.db.get(id).unwrap();
        let tok = ctx.custody.get(&row.cloud_token_keystore_alias).unwrap();
        assert_eq!(tok, b"tok-two");
    }

    #[test]
    fn cancel_and_cleanup_is_idempotent_and_deletes() {
        let (ctx, _dir) = ctx(1_700_000_000);
        let id = store_cloud_token(&ctx, "hetzner", "tok", None).unwrap();
        publisher_keygen(&ctx, id).unwrap();
        finalize_pre_provision(&ctx, id).unwrap();
        cancel_and_cleanup(&ctx, id).unwrap();
        // second call -> Ok (idempotent on missing).
        cancel_and_cleanup(&ctx, id).unwrap();
        assert!(list_operators(&ctx).unwrap().is_empty());
    }

    #[test]
    fn cancel_and_cleanup_removes_the_plaintext_subkey_directory() {
        // `subkey_rotate` writes the rotated sub-key private key as a
        // plaintext 0o600 file under `<staging>/subkeys/<id>/` and
        // `sign_relaypack` reads it straight back — for any operator
        // that has rotated, that IS the active signing key, and it is
        // not under DeviceCustody. Removing the relay while leaving it
        // there means the key outlives the relay in the clear.
        let (ctx, _dir) = ctx(1_700_000_000);
        let id = store_cloud_token(&ctx, "hetzner", "tok", None).unwrap();
        let subkeys = ctx.staging_dir.join("subkeys").join(id.to_string());
        std::fs::create_dir_all(&subkeys).unwrap();
        std::fs::write(subkeys.join("subkey.priv"), b"-----BEGIN PRIVATE KEY-----").unwrap();

        cancel_and_cleanup(&ctx, id).unwrap();

        assert!(
            !subkeys.exists(),
            "the operator's unwrapped signing key survived its own removal"
        );
    }

    #[test]
    fn cancel_and_cleanup_keeps_the_signing_key_when_the_row_cannot_go() {
        // Ordering property: the DB delete is the only fallible step,
        // so it runs FIRST. A relay that has rotated used to fail the
        // delete on a FOREIGN KEY violation *after* its custody aliases
        // were already forgotten — key gone, row still there, every
        // retry identical. The child sweep in OperatorDb::delete is the
        // primary fix; this pins the ordering that made the failure
        // unrecoverable rather than merely annoying.
        let (ctx, _dir) = ctx(1_700_000_000);
        let id = store_cloud_token(&ctx, "hetzner", "tok", None).unwrap();
        publisher_keygen(&ctx, id).unwrap();
        ctx.db
            .record_rotated_sbp(id, 1_000, "/staging/a.sbp", "sha-a", "rp-a", 3, "L1")
            .unwrap();

        cancel_and_cleanup(&ctx, id).unwrap();

        assert!(list_operators(&ctx).unwrap().is_empty());
        assert!(ctx.custody.get(&pub_alias(id)).is_err());
    }

    #[test]
    fn cancel_and_cleanup_erases_custody_and_legacy_secrets() {
        // Deleting a relay must leave nothing behind in EITHER store —
        // a signing key surviving a deletion is a signing key on disk
        // for a relay the user believes is gone.
        let (ctx, _dir) = ctx(1_700_000_000);
        let id = store_cloud_token(&ctx, "hetzner", "tok", None).unwrap();
        publisher_keygen(&ctx, id).unwrap();
        // Plant a legacy PIN-sealed blob as if this install predates
        // the migration and never ran it.
        ctx.keystore
            .seal(&pub_alias(id), "123456", b"legacy-priv")
            .unwrap();
        assert!(ctx.keystore.has(&pub_alias(id)));

        cancel_and_cleanup(&ctx, id).unwrap();

        assert!(ctx.custody.get(&pub_alias(id)).is_err(), "custody priv");
        assert!(ctx.custody.get(&cloud_alias(id)).is_err(), "custody token");
        assert!(!ctx.keystore.has(&pub_alias(id)), "legacy priv");
    }

    // ---- Real teardown (relay_destroy) ---------------------------

    /// Drive a relay to a state that looks provisioned: a record with a
    /// server id, a region and a publisher key, i.e. one that genuinely
    /// owns cloud resources.
    fn provisioned_relay(ctx: &WizardCtx) -> i64 {
        let id = store_cloud_token(ctx, "hetzner", "tok-live", None).unwrap();
        select_profile(
            ctx,
            id,
            "fsn1",
            "cpx12",
            "iran-default",
            vec!["vless-reality".into()],
        )
        .unwrap();
        publisher_keygen(ctx, id).unwrap();
        let mut rec: PreProvisionRecord =
            serde_json::from_str(&ctx.db.get(id).unwrap().operator_record_json).unwrap();
        rec.server_id = "12345678".into();
        rec.public_ip = "203.0.113.9".into();
        ctx.db
            .update_record_json(id, &serde_json::to_string(&rec).unwrap())
            .unwrap();
        id
    }

    #[test]
    fn relay_destroy_local_only_matches_cancel_and_cleanup() {
        // delete_server=false must not touch the cloud at all — this is
        // the path CustodyGate's "forget relay" escape uses, where there
        // is no readable token to authenticate a delete with.
        let (ctx, _dir, mock) = ctx_with_mock(
            1_700_000_000,
            Arc::new(MockRunner::new(test_pricing())),
        );
        let id = provisioned_relay(&ctx);

        let rep = relay_destroy(&ctx, id, false).unwrap();
        assert!(rep.local_removed);
        assert!(!rep.server_deleted, "must not claim a cloud delete");
        assert!(!rep.ssh_key_deleted);
        assert!(!rep.firewall_deleted);
        assert!(rep.warnings.is_empty());
        assert!(
            mock.decommission_calls.lock().unwrap().is_empty(),
            "local-only removal must never reach the provider"
        );

        // Same observable end state as today's cancel_and_cleanup.
        assert!(list_operators(&ctx).unwrap().is_empty());
        assert!(ctx.custody.get(&pub_alias(id)).is_err(), "custody priv");
        assert!(ctx.custody.get(&cloud_alias(id)).is_err(), "custody token");
        // And it stays idempotent on a row that is already gone.
        assert!(relay_destroy(&ctx, id, false).unwrap().local_removed);
    }

    #[test]
    fn relay_destroy_with_server_sweeps_cloud_then_local() {
        let (ctx, _dir, mock) = ctx_with_mock(
            1_700_000_000,
            Arc::new(MockRunner::new(test_pricing())),
        );
        let id = provisioned_relay(&ctx);

        let rep = relay_destroy(&ctx, id, true).unwrap();
        assert_eq!(
            rep,
            DestroyReport {
                server_deleted: true,
                ssh_key_deleted: true,
                firewall_deleted: true,
                local_removed: true,
                warnings: vec![],
            }
        );

        // The CLI was handed the real record + the real token.
        let calls = mock.decommission_calls.lock().unwrap().clone();
        assert_eq!(calls.len(), 1, "exactly one decommission");
        assert_eq!(calls[0].token, "tok-live");
        assert!(
            calls[0].record_json.contains("12345678"),
            "record must carry the server id: {}",
            calls[0].record_json
        );

        // Local state is gone afterwards, staged record included.
        assert!(list_operators(&ctx).unwrap().is_empty());
        assert!(ctx.custody.get(&cloud_alias(id)).is_err());
        assert!(!calls[0].record_path.exists(), "staged record swept");
    }

    #[test]
    fn relay_destroy_cloud_failure_leaves_local_state_intact() {
        // THE ordering property. cancel_and_cleanup destroys the cloud
        // token and then the row holding server_id/region/pubkey — the
        // only handles on the resources. If it ran before a failed
        // cloud call, the user would be left with a billing server and
        // no credential to delete it. A cloud failure must therefore
        // surface as an error with everything local still in place.
        let (ctx, _dir, mock) = ctx_with_mock(
            1_700_000_000,
            Arc::new(
                MockRunner::new(test_pricing())
                    .with_decommission_error("hetzner: server delete: 503 service unavailable\n"),
            ),
        );
        let id = provisioned_relay(&ctx);

        let err = relay_destroy(&ctx, id, true).unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("503 service unavailable"),
            "provider error must reach the user verbatim: {text}"
        );

        assert_eq!(mock.decommission_calls.lock().unwrap().len(), 1);
        // Everything needed for the retry survived.
        assert_eq!(list_operators(&ctx).unwrap().len(), 1, "row survives");
        assert_eq!(
            ctx.custody.get(&cloud_alias(id)).unwrap(),
            b"tok-live",
            "cloud token survives"
        );
        assert!(ctx.custody.get(&pub_alias(id)).is_ok(), "signing key survives");
        assert!(ctx
            .db
            .get(id)
            .unwrap()
            .operator_record_json
            .contains("12345678"));

        // And the retry works once the provider recovers.
        *mock.decommission_error.lock().unwrap() = None;
        assert!(relay_destroy(&ctx, id, true).unwrap().server_deleted);
        assert!(list_operators(&ctx).unwrap().is_empty());
    }

    #[test]
    fn relay_destroy_propagates_partial_sweep_warnings() {
        // A run that killed the box but could not delete the ephemeral
        // SSH key is not a success to round up: that orphan key is what
        // makes the next provision in this region fail forever on a
        // name collision. The warning has to reach the user intact.
        let (ctx, _dir, _mock) = ctx_with_mock(
            1_700_000_000,
            Arc::new(MockRunner::new(test_pricing()).with_decommission_result(
                DecommissionResult {
                    server_deleted: true,
                    ssh_key_deleted: false,
                    firewall_deleted: true,
                    warnings: vec!["hetzner: delete ssh key: 409 conflict".into()],
                },
            )),
        );
        let id = provisioned_relay(&ctx);

        let rep = relay_destroy(&ctx, id, true).unwrap();
        assert!(rep.server_deleted);
        assert!(!rep.ssh_key_deleted);
        assert!(rep.firewall_deleted);
        assert!(rep.local_removed, "a live box is gone — finish locally too");
        assert_eq!(rep.warnings, vec!["hetzner: delete ssh key: 409 conflict"]);
    }

    #[test]
    fn relay_destroy_skips_cloud_for_a_never_provisioned_draft() {
        // A row that only ever held a token has no server id, no region
        // and no publisher key, so there is no resource name to derive.
        // Calling the provider would fail on an empty record and block
        // the user from deleting a relay that costs nothing.
        let (ctx, _dir, mock) = ctx_with_mock(
            1_700_000_000,
            Arc::new(MockRunner::new(test_pricing())),
        );
        let id = store_cloud_token(&ctx, "hetzner", "tok-draft", None).unwrap();

        let rep = relay_destroy(&ctx, id, true).unwrap();
        assert!(rep.local_removed);
        // Every flag true because each answers "is it gone now?" — and
        // nothing was ever created. Reporting false made the teardown
        // sheet raise its red "the server is still running and still
        // billing" alarm over a VPS that never existed.
        assert!(rep.server_deleted);
        assert!(rep.ssh_key_deleted);
        assert!(rep.firewall_deleted);
        assert_eq!(rep.warnings.len(), 1, "the skip is stated, not silent");
        assert!(rep.warnings[0].contains("never provisioned"));
        assert!(mock.decommission_calls.lock().unwrap().is_empty());
        assert!(list_operators(&ctx).unwrap().is_empty());
    }

    #[test]
    fn relay_destroy_sweeps_a_failed_provision_with_no_server_id() {
        // The orphaned-SSH-key case: provision died after creating the
        // key, so server_id is empty but `daal-<region>-<hex8>-ephemeral`
        // exists and poisons every retry. Skipping the cloud call here
        // would leave the user permanently unable to provision.
        let (ctx, _dir, mock) = ctx_with_mock(
            1_700_000_000,
            Arc::new(MockRunner::new(test_pricing()).with_decommission_result(
                DecommissionResult {
                    server_deleted: false,
                    ssh_key_deleted: true,
                    firewall_deleted: false,
                    warnings: vec![],
                },
            )),
        );
        let id = store_cloud_token(&ctx, "hetzner", "tok-failed", None).unwrap();
        select_profile(&ctx, id, "fsn1", "cpx12", "iran-default", vec![]).unwrap();
        publisher_keygen(&ctx, id).unwrap();
        assert!(
            ctx.db
                .get(id)
                .unwrap()
                .operator_record_json
                .contains("\"server_id\":\"\""),
            "precondition: no server was ever created"
        );

        let rep = relay_destroy(&ctx, id, true).unwrap();
        assert_eq!(mock.decommission_calls.lock().unwrap().len(), 1);
        assert!(rep.ssh_key_deleted, "the orphan key is the whole point");
        assert!(!rep.server_deleted);
        assert!(rep.local_removed);
    }

    #[test]
    fn publisher_keygen_stores_priv_under_custody_not_keystore() {
        let (ctx, _dir) = ctx(1_700_000_000);
        let id = store_cloud_token(&ctx, "hetzner", "tok", None).unwrap();
        publisher_keygen(&ctx, id).unwrap();

        let row = ctx.db.get(id).unwrap();
        assert_eq!(row.publisher_priv_keystore_alias, pub_alias(id));
        let from_custody = ctx.custody.get(&pub_alias(id)).unwrap();
        assert!(!from_custody.is_empty());
        // Nothing was written to the legacy PIN store.
        assert!(!ctx.keystore.has(&pub_alias(id)));
    }

    #[test]
    fn import_publisher_key_round_trip() {
        let (ctx, _dir) = ctx(1_700_000_000);
        let id = store_cloud_token(&ctx, "hetzner", "tok", None).unwrap();
        // Seed = 32 zero bytes (allowed by ed25519-dalek)
        let seed = vec![0u8; 32];
        let b64 = B64.encode(&seed);
        let fp = publisher_keyimport(&ctx, id, &b64).unwrap();
        assert_eq!(fp.en_words.split(' ').count(), 4);
        // Re-import yields identical fingerprint.
        let fp2 = publisher_keyimport(&ctx, id, &b64).unwrap();
        assert_eq!(fp, fp2);
    }

    #[test]
    fn recovery_key_export_round_trips_through_keyimport() {
        // The DWK is not exportable, so a factory reset destroys every
        // relay this device publishes unless the user kept a recovery
        // blob. Export → import must reproduce the same key exactly,
        // or the recovery path is a lie.
        let (ctx, _dir) = ctx(1_700_000_000);
        let id = store_cloud_token(&ctx, "hetzner", "tok", None).unwrap();
        let fp = publisher_keygen(&ctx, id).unwrap();

        let path = export_recovery_key(&ctx, id).unwrap();
        let blob = std::fs::read_to_string(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "recovery blob must be 0600");
        }

        // Wipe custody entirely, as a reinstall would.
        ctx.custody.forget(&pub_alias(id)).unwrap();
        assert!(ctx.custody.get(&pub_alias(id)).is_err());

        let restored = publisher_keyimport(&ctx, id, &blob).unwrap();
        assert_eq!(restored, fp, "restored key must have the same fingerprint");
    }

    // ---- Custody status + the one-time PIN migration ----------------

    #[test]
    fn fresh_install_reports_no_legacy_migration() {
        // The whole point of removing the PIN: a device that never ran
        // the PIN build must see zero prompts. legacy_pending false,
        // legacy_aliases empty, custody working.
        let (ctx, _dir) = ctx(1_700_000_000);
        let id = store_cloud_token(&ctx, "hetzner", "tok", None).unwrap();
        publisher_keygen(&ctx, id).unwrap();

        let st = custody_status(&ctx).unwrap();
        assert!(st.ok, "probe failed: {}", st.error);
        assert!(!st.legacy_pending);
        assert!(st.legacy_aliases.is_empty());
        assert_eq!(st.error, "");
    }

    /// Build a context whose secrets are ONLY in the legacy PIN store,
    /// exactly as an install from before this refactor would look.
    fn ctx_with_legacy_pin_secrets(pin: &str) -> (WizardCtx, tempfile::TempDir, i64) {
        let (ctx, dir) = ctx(1_700_000_000);
        let id = ctx
            .db
            .insert_pre_provision(
                r#"{"provider":"hetzner","region":"fsn1","server_type":"cpx12"}"#,
                "abcd",
                &pub_alias(1),
                "hetzner",
                &cloud_alias(1),
                1_700_000_000,
            )
            .unwrap();
        // Aliases are id-derived; the insert above hard-codes 1 because
        // it is the first row in a fresh in-memory DB.
        assert_eq!(id, 1);
        ctx.keystore.seal(&pub_alias(id), pin, b"root-priv-bytes").unwrap();
        ctx.keystore.seal(&cloud_alias(id), pin, b"cloud-token").unwrap();
        (ctx, dir, id)
    }

    #[test]
    fn custody_status_flags_legacy_blobs_without_asking_for_a_pin() {
        let (ctx, _dir, id) = ctx_with_legacy_pin_secrets("123456");
        let st = custody_status(&ctx).unwrap();
        assert!(st.legacy_pending);
        assert!(st.legacy_aliases.contains(&pub_alias(id)), "{st:?}");
        assert!(st.legacy_aliases.contains(&cloud_alias(id)), "{st:?}");
    }

    #[test]
    fn migration_moves_secrets_to_custody_and_forgets_legacy() {
        let (ctx, _dir, id) = ctx_with_legacy_pin_secrets("123456");

        let report = migrate_from_pin(&ctx, "123456").unwrap();
        assert!(report.signing_keys_safe, "{report:?}");
        assert!(report.failed.is_empty(), "{report:?}");
        assert!(report.migrated.contains(&pub_alias(id)), "{report:?}");
        assert!(report.migrated.contains(&cloud_alias(id)), "{report:?}");

        // Plaintext preserved byte-for-byte, and now readable without
        // any PIN at all.
        assert_eq!(ctx.custody.get(&pub_alias(id)).unwrap(), b"root-priv-bytes");
        assert_eq!(ctx.custody.get(&cloud_alias(id)).unwrap(), b"cloud-token");
        // Legacy copies erased only after that read-back succeeded.
        assert!(!ctx.keystore.has(&pub_alias(id)));
        assert!(!ctx.keystore.has(&cloud_alias(id)));

        // And the gate closes: nothing left to migrate.
        let st = custody_status(&ctx).unwrap();
        assert!(!st.legacy_pending, "{st:?}");
    }

    #[test]
    fn migration_is_idempotent_and_resumable() {
        let (ctx, _dir, id) = ctx_with_legacy_pin_secrets("123456");
        migrate_from_pin(&ctx, "123456").unwrap();

        // Second run: everything already in custody → all skipped,
        // nothing failed, verdict still safe. This is also the
        // crash-recovery path (a crash between put and forget leaves
        // both copies; the rerun classifies them as skipped).
        let again = migrate_from_pin(&ctx, "123456").unwrap();
        assert!(again.migrated.is_empty(), "{again:?}");
        assert!(again.failed.is_empty(), "{again:?}");
        assert!(again.skipped.contains(&pub_alias(id)), "{again:?}");
        assert!(again.signing_keys_safe);
    }

    #[test]
    fn migration_with_wrong_pin_aborts_and_touches_nothing() {
        let (ctx, _dir, id) = ctx_with_legacy_pin_secrets("123456");

        let err = migrate_from_pin(&ctx, "999999").unwrap_err();
        assert!(
            matches!(err, WizardError::Keystore(KeystoreError::WrongPin)),
            "got {err:?}"
        );
        // NOTHING moved and NOTHING was deleted. A wrong PIN that ate
        // the signing key would be unrecoverable.
        assert!(ctx.keystore.has(&pub_alias(id)));
        assert!(ctx.keystore.has(&cloud_alias(id)));
        assert!(ctx.custody.get(&pub_alias(id)).is_err());
    }

    #[test]
    fn migration_never_deletes_a_legacy_blob_it_could_not_verify() {
        // THE safety property, exercised against a custody backend
        // that accepts writes and then returns nothing. Without the
        // read-back check the legacy blob would be erased here and the
        // relay would be orphaned with no escrow and no recovery.
        use crate::device_custody::{CustodyLevel, Result as CResult};

        struct BlackHoleCustody;
        impl DeviceCustody for BlackHoleCustody {
            fn level(&self) -> CustodyLevel {
                CustodyLevel::OsKeystore
            }
            fn is_unlocked(&self) -> bool {
                true
            }
            fn unlock(&self, _p: Option<&str>) -> CResult<()> {
                Ok(())
            }
            fn lock(&self) {}
            /// Reports success and stores nothing — the shape of a
            /// keystore whose writes silently no-op.
            fn put(&self, _alias: &str, _secret: &[u8]) -> CResult<()> {
                Ok(())
            }
            fn get(&self, alias: &str) -> CResult<Vec<u8>> {
                Err(CustodyError::NotFound(alias.to_string()))
            }
            fn forget(&self, _alias: &str) -> CResult<()> {
                Ok(())
            }
            fn forget_prefix(&self, _prefix: &str) -> CResult<usize> {
                Ok(0)
            }
        }

        let (mut ctx, _dir, id) = ctx_with_legacy_pin_secrets("123456");
        ctx.custody = Arc::new(BlackHoleCustody);

        let report = migrate_from_pin(&ctx, "123456").unwrap();
        assert!(
            !report.signing_keys_safe,
            "a custody that stores nothing must not be declared safe: {report:?}"
        );
        assert!(report.migrated.is_empty(), "{report:?}");
        assert!(
            report.failed.iter().any(|f| f.contains(&pub_alias(id))),
            "{report:?}"
        );
        // The irreplaceable key is still exactly where it was.
        assert!(
            ctx.keystore.has(&pub_alias(id)),
            "legacy signing key MUST survive an unverifiable migration"
        );
        assert_eq!(
            ctx.keystore.open(&pub_alias(id), "123456").unwrap(),
            b"root-priv-bytes"
        );
    }

    #[test]
    fn migration_survives_one_undecryptable_blob() {
        // `Keystore::open` collapses every AEAD failure into WrongPin,
        // so a truncated blob is indistinguishable from a bad PIN.
        // Aborting the run on it would strand every OTHER relay's
        // recoverable signing key behind a gate with no exit — the
        // regression this pins. Signing keys sort first, so relay 1's
        // damaged blob is attempted before relay 2's good one.
        let (ctx, _dir, _id1) = ctx_with_legacy_pin_secrets("123456");
        let id2 = ctx
            .db
            .insert_pre_provision(
                r#"{"provider":"hetzner","region":"fsn1","server_type":"cpx12"}"#,
                "beef",
                &pub_alias(2),
                "hetzner",
                &cloud_alias(2),
                1_700_000_000,
            )
            .unwrap();
        assert_eq!(id2, 2);
        ctx.keystore
            .seal(&pub_alias(id2), "123456", b"second-relay-priv")
            .unwrap();

        // Relay 2's blob will not open under this PIN — the exact
        // signal a truncated/damaged blob produces, since `open` maps
        // every AEAD failure to WrongPin.
        ctx.keystore
            .seal(&pub_alias(id2), "999999", b"second-relay-priv")
            .unwrap();

        let report = migrate_from_pin(&ctx, "123456").unwrap();
        assert!(
            report.migrated.contains(&pub_alias(1)),
            "relay 1's perfectly good signing key must still migrate: {report:?}"
        );
        assert!(
            custody_has(&ctx, &pub_alias(1)),
            "relay 1's key must be readable from custody: {report:?}"
        );
        assert!(
            report.failed.iter().any(|f| f.contains(&pub_alias(id2))),
            "the unopenable blob must be reported, not thrown away: {report:?}"
        );
        assert!(
            !report.signing_keys_safe,
            "a key that did not move is not safe: {report:?}"
        );
        // And the unopenable legacy blob is left exactly where it was.
        assert!(ctx.keystore.has(&pub_alias(id2)));
    }

    #[test]
    fn custody_status_reports_whether_a_passphrase_was_ever_chosen() {
        // The unlock sheet is BOTH "choose a passphrase" and "enter
        // yours", and `custody_unlock` accepts anything on a first run
        // because there is no stored blob to be wrong about. Without
        // this flag the UI tells a brand-new install to "enter" a
        // passphrase that does not exist, and a typo there silently
        // becomes the wrap key for a signing key with no escrow.
        let dir = tempdir().unwrap();
        let mk = || -> WizardCtx {
            let custody = crate::device_custody::FileCustody::session_passphrase(dir.path())
                .unwrap();
            WizardCtx {
                db: Arc::new(OperatorDb::open_in_memory().unwrap()),
                keystore: Arc::new(Keystore::new_in_memory(dir.path())),
                staging_dir: dir.path().join("staging"),
                cli: Arc::new(MockRunner::new(Pricing {
                    provider: "hetzner".into(),
                    region: "fsn1".into(),
                    server_type: "cpx12".into(),
                    hourly_eur: 0.0,
                    monthly_eur: 0.0,
                    included_traffic_tb_per_month: None,
                    overage_eur_per_gb: None,
                })),
                clock: Arc::new(|| 1_700_000_000),
                custody: Arc::new(custody),
            }
        };

        // Nothing stored yet → this is a first run.
        let fresh = mk();
        assert!(!custody_status(&fresh).unwrap().passphrase_set);

        // Store one blob under a passphrase, then start over with a
        // LOCKED custody over the same directory: the flag must survive,
        // because "there is a blob here" is exactly what distinguishes
        // "enter yours" from "choose one".
        fresh.custody.unlock(Some("correct horse")).unwrap();
        fresh
            .custody
            .put(crate::recipient_identity::RECIPIENT_PRIV_ALIAS, b"secret")
            .unwrap();

        let relaunched = mk();
        assert!(!relaunched.custody.is_unlocked());
        let st = custody_status(&relaunched).unwrap();
        assert!(st.passphrase_set, "{st:?}");
        assert_eq!(st.level, "session_passphrase");
    }

    #[test]
    fn migration_refuses_to_start_on_locked_custody() {
        // Regression: on a session-passphrase device the migration card
        // used to render in front of the unlock sheet. Every alias
        // would be unsealed with the PIN and then fail at `put`, so
        // `signing_keys_safe` never flipped and the gate never cleared.
        // Fail fast with the code that routes to the unlock sheet.
        let (mut ctx, _dir, _id) = ctx_with_legacy_pin_secrets("123456");
        let locked = crate::device_custody::FileCustody::session_passphrase(_dir.path()).unwrap();
        assert!(!locked.is_unlocked());
        ctx.custody = Arc::new(locked);

        let err = migrate_from_pin(&ctx, "123456").unwrap_err().to_string();
        assert!(err.starts_with(E_CUSTODY_LOCKED), "{err}");
        // Nothing was touched.
        assert!(ctx.keystore.has(&pub_alias(1)));
    }

    #[test]
    fn select_profile_preserves_post_provision_record_fields() {
        // Regression, and a bad one: `select_profile` used to round-trip
        // `operator_record_json` through `PreProvisionRecord`, which has
        // no mgmt_port / mgmt_tls_fingerprint / reality_public_key /
        // tls_cert_sha256. After provisioning, that record IS the full
        // FRP-4b OperatorRecord, so a single re-run — which the build
        // screen does on every "Try again" — silently deleted the mgmt
        // plane and the box's connection material. Nothing writes them
        // back, so every users-* call and every pack built afterwards
        // was dead, permanently.
        let (ctx, _dir) = ctx(1_700_000_000);
        let full = r#"{"provider":"hetzner","region":"fsn1","server_type":"cpx12",
            "public_ip":"1.2.3.4","mgmt_port":17847,
            "mgmt_tls_fingerprint":"aabb","reality_public_key":"rk","tls_cert_sha256":"tp",
            "toolbox_profile":"iran-default","enabled_families":["vless-reality"]}"#;
        let id = ctx
            .db
            .insert_pre_provision(full, "abcd", "", "hetzner", &cloud_alias(1), 1_700_000_000)
            .unwrap();

        select_profile(&ctx, id, "nbg1", "cpx22", "iran-default", vec!["hysteria2".into()])
            .unwrap();

        let after: serde_json::Value =
            serde_json::from_str(&ctx.db.get(id).unwrap().operator_record_json).unwrap();
        assert_eq!(after["region"], "nbg1");
        assert_eq!(after["server_type"], "cpx22");
        assert_eq!(after["enabled_families"][0], "hysteria2");
        for key in [
            "mgmt_port",
            "mgmt_tls_fingerprint",
            "reality_public_key",
            "tls_cert_sha256",
            "public_ip",
        ] {
            assert!(
                after.get(key).is_some(),
                "select_profile dropped {key}: {after}"
            );
        }
    }

    #[test]
    fn select_profile_is_a_no_op_once_provisioned() {
        // A provisioned box's region and size are facts about a machine
        // that exists. Rewriting them from the plan screen's leftover
        // React state would make the record disagree with the server.
        let (ctx, _dir) = ctx(1_700_000_000);
        let full = r#"{"provider":"hetzner","region":"fsn1","server_type":"cpx12","mgmt_port":17847}"#;
        let id = ctx
            .db
            .insert_pre_provision(full, "abcd", "", "hetzner", &cloud_alias(1), 1_700_000_000)
            .unwrap();
        ctx.db.mark_provisioned(id, 1_700_000_100).unwrap();

        select_profile(&ctx, id, "nbg1", "cax11", "iran-default", vec![]).unwrap();

        let after: serde_json::Value =
            serde_json::from_str(&ctx.db.get(id).unwrap().operator_record_json).unwrap();
        assert_eq!(after["region"], "fsn1");
        assert_eq!(after["server_type"], "cpx12");
    }

    #[test]
    fn custody_unlock_rejects_a_passphrase_that_opens_nothing() {
        // A round-trip probe cannot catch this: it writes and reads
        // with the same derived key, so a wrong passphrase round-trips
        // perfectly. The only real test is opening a blob written
        // under the right key — which is what custody_unlock does, and
        // why a wrong passphrase surfaces here instead of eight
        // screens later in the middle of signing.
        let dir = tempdir().unwrap();
        let mk = |pass: Option<&str>| -> WizardCtx {
            let custody = crate::device_custody::FileCustody::session_passphrase(dir.path())
                .unwrap();
            if let Some(p) = pass {
                custody.unlock(Some(p)).unwrap();
            }
            WizardCtx {
                db: Arc::new(OperatorDb::open_in_memory().unwrap()),
                keystore: Arc::new(Keystore::new_in_memory(dir.path())),
                staging_dir: dir.path().join("staging"),
                cli: Arc::new(MockRunner::new(Pricing {
                    provider: "hetzner".into(),
                    region: "fsn1".into(),
                    server_type: "cpx12".into(),
                    hourly_eur: 0.0,
                    monthly_eur: 0.0,
                    included_traffic_tb_per_month: None,
                    overage_eur_per_gb: None,
                })),
                clock: Arc::new(|| 1_700_000_000),
                custody: Arc::new(custody),
            }
        };

        // Seed a real secret under the correct passphrase.
        let seeded = mk(Some("correct horse battery staple"));
        let id = store_cloud_token(&seeded, "hetzner", "tok", None).unwrap();
        publisher_keygen(&seeded, id).unwrap();

        // A fresh context over the same blob dir. Right passphrase
        // opens it; the DB is fresh so we probe the alias directly.
        let good = mk(Some("correct horse battery staple"));
        assert!(good.custody.get(&pub_alias(id)).is_ok());

        // Wrong passphrase: unlock() itself succeeds (it just derives
        // *a* key), so the rejection has to come from the read-back.
        let bad = mk(None);
        // Give the fresh DB the same alias inventory to probe against.
        bad.db
            .insert_pre_provision(
                r#"{"provider":"hetzner"}"#,
                "abcd",
                &pub_alias(id),
                "hetzner",
                &cloud_alias(id),
                1_700_000_000,
            )
            .unwrap();
        let err = custody_unlock(&bad, "not the same passphrase").unwrap_err();
        assert!(
            err.to_string().starts_with(E_CUSTODY_WRONG_PASS),
            "want E_CUSTODY_WRONG_PASS, got: {err}"
        );
    }

    #[test]
    fn custody_unlock_accepts_any_passphrase_on_a_first_run() {
        // Nothing stored yet means nothing to be wrong about: the
        // passphrase the user picks IS the passphrase. Rejecting here
        // would lock someone out of their own empty install.
        let dir = tempdir().unwrap();
        let custody =
            crate::device_custody::FileCustody::session_passphrase(dir.path()).unwrap();
        let ctx = WizardCtx {
            db: Arc::new(OperatorDb::open_in_memory().unwrap()),
            keystore: Arc::new(Keystore::new_in_memory(dir.path())),
            staging_dir: dir.path().join("staging"),
            cli: Arc::new(MockRunner::new(Pricing {
                provider: "hetzner".into(),
                region: "fsn1".into(),
                server_type: "cpx12".into(),
                hourly_eur: 0.0,
                monthly_eur: 0.0,
                included_traffic_tb_per_month: None,
                overage_eur_per_gb: None,
            })),
            clock: Arc::new(|| 1_700_000_000),
            custody: Arc::new(custody),
        };
        let st = custody_unlock(&ctx, "brand new passphrase").unwrap();
        assert!(st.ok, "{st:?}");
        assert!(st.unlocked);
        assert_eq!(st.level, "session_passphrase");
    }

    // ---- Helper IP + artifacts -------------------------------------

    #[test]
    fn helper_ip_round_trips_and_rejects_non_addresses() {
        let (ctx, _dir) = ctx(1_700_000_000);
        let id = store_cloud_token(&ctx, "hetzner", "tok", None).unwrap();
        assert_eq!(get_helper_ip(&ctx, id).unwrap(), "");

        set_helper_ip(&ctx, id, " 203.0.113.9 ", "auto").unwrap();
        assert_eq!(get_helper_ip(&ctx, id).unwrap(), "203.0.113.9");

        // IPv6 must be accepted: the old dotted-quad-only regex
        // silently failed on IPv6-only mobile networks.
        set_helper_ip(&ctx, id, "2001:db8::1", "manual").unwrap();
        assert_eq!(get_helper_ip(&ctx, id).unwrap(), "2001:db8::1");

        // A captive-portal HTML body must never become a helper IP.
        let err = set_helper_ip(&ctx, id, "<html>Sign in to WiFi", "auto").unwrap_err();
        assert!(matches!(err, WizardError::Validation(_)), "{err:?}");
        assert_eq!(get_helper_ip(&ctx, id).unwrap(), "2001:db8::1", "unchanged");
    }

    #[test]
    fn mgmt_calls_fail_fast_with_helper_ip_missing_code() {
        let (ctx, _dir) = ctx(1_700_000_000);
        let id = store_cloud_token(&ctx, "hetzner", "tok", None).unwrap();
        publisher_keygen(&ctx, id).unwrap();

        let mut sink = |_ev: ProgressEvent| {};
        let err = provision_run(&ctx, id, "", &mut sink).unwrap_err();
        assert!(
            err.to_string().starts_with(E_HELPER_IP_MISSING),
            "error must lead with the code the UI branches on, got: {err}"
        );
    }

    #[test]
    fn transport_failures_classify_as_stale_allowlist() {
        // The publisher moving from Wi-Fi to cellular looks exactly
        // like the box being down. Only transport-shaped failures may
        // claim staleness; an application error from a box we clearly
        // reached must not be papered over with a retry.
        assert!(looks_like_stale_allowlist(
            // RFC 5737 documentation address on purpose: this fixture
            // only has to *look* like a transport failure, and a real
            // relay's IP + its randomised mgmt port is exactly the pair
            // this project exists to keep off a public git remote.
            "daal-deploy failed: rc=1 stderr=dial tcp 203.0.113.7:17847: i/o timeout"
        ));
        assert!(looks_like_stale_allowlist("connection refused"));
        assert!(looks_like_stale_allowlist(
            "remote error: tls handshake failure"
        ));
        assert!(looks_like_stale_allowlist("mgmt returned status 403"));
        assert!(!looks_like_stale_allowlist(
            "user r7 already exists on this box"
        ));
        assert!(!looks_like_stale_allowlist("invalid recipient address"));
    }

    #[test]
    fn list_artifacts_orders_shared_then_raw_then_recipients() {
        let (ctx, _dir) = ctx(1_700_000_000);
        let id = store_cloud_token(&ctx, "hetzner", "tok", None).unwrap();
        std::fs::create_dir_all(&ctx.staging_dir).unwrap();
        std::fs::write(
            ctx.staging_dir.join(format!("{id}.shared.sbp")),
            b"shared-bytes",
        )
        .unwrap();
        // The raw bundle is deliberately absent: a missing artifact
        // must come back with exists=false so the UI can explain the
        // gap instead of hiding a row the user is looking for.
        for (i, (n, display)) in [("r1", "Bahar"), ("r2", "")].into_iter().enumerate() {
            ctx.db
                .insert_recipient(crate::operator_db::NewRecipientRow {
                    operator_id: id,
                    name: n.into(),
                    display_name: display.into(),
                    address_str: format!("daal1{n}"),
                    // Unique per row: (operator_id, pubkey) is a UNIQUE key.
                    pubkey_x25519_hex: format!("{:02x}", i).repeat(32),
                    fingerprint_hex: format!("{:02x}", i + 0x80).repeat(32),
                    vless_uuid: "u".into(),
                    reality_short_id: "s".into(),
                    hy2_password: "h".into(),
                    naive_password: "n".into(),
                    ws_path: "/w".into(),
                    provisioned_at_unix: 1,
                })
                .unwrap();
        }

        let arts = list_artifacts(&ctx, id).unwrap();
        assert_eq!(arts.len(), 4);
        assert_eq!(arts[0].kind, "shared_sbp");
        assert!(arts[0].exists);
        assert_eq!(arts[0].size_bytes, b"shared-bytes".len() as u64);
        assert_eq!(arts[1].kind, "raw_sbp");
        assert!(!arts[1].exists, "missing files are reported, not hidden");
        assert_eq!(arts[2].kind, "sbpx");
        assert_eq!(arts[2].recipient_label, "Bahar");
        // No display name → fall back to the on-box name rather than
        // rendering a blank row.
        assert_eq!(arts[3].recipient_label, "r2");
    }

    #[test]
    fn list_operators_carries_enough_to_tell_two_relays_apart() {
        let (ctx, _dir) = ctx(1_700_000_000);
        let a = store_cloud_token(&ctx, "hetzner", "tok-a", None).unwrap();
        let b = store_cloud_token(&ctx, "hetzner", "tok-b", None).unwrap();
        set_operator_nickname(&ctx, a, "  Mum's relay  ").unwrap();
        set_helper_ip(&ctx, b, "203.0.113.4", "manual").unwrap();

        let ops = list_operators(&ctx).unwrap();
        let get = |id: i64| ops.iter().find(|o| o.id == id).unwrap();
        assert_eq!(get(a).nickname, "Mum's relay", "nickname is trimmed");
        assert_eq!(get(b).nickname, "");
        assert_eq!(get(b).helper_ip, "203.0.113.4");
        assert!(!get(a).has_signed_sbp);
        assert_eq!(get(a).live_recipient_count, 0);
        assert_eq!(get(a).total_recipient_count, 0);
    }

    // ---- FRP-4b commands -------------------------------------------

    /// Helper: stand up a context whose CLI mock is pre-loaded with
    /// canned record JSON + bind result. Tests can mutate via the
    /// returned MockRunner reference (Arc downcasts not pretty;
    /// instead we own the runner via .with_provision_record /
    /// .with_bind_result before constructing the ctx).
    fn ctx_with_canned(
        now: i64,
        record_json: &str,
        bind: BindResult,
    ) -> (WizardCtx, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let db = Arc::new(OperatorDb::open_in_memory().unwrap());
        let ks = Arc::new(Keystore::new_in_memory(dir.path()));
        let staging_dir = dir.path().join("staging");
        let pricing = Pricing {
            provider: "hetzner".into(),
            region: "fsn1".into(),
            server_type: "cx22".into(),
            hourly_eur: 0.005,
            monthly_eur: 3.85,
            included_traffic_tb_per_month: None,
            overage_eur_per_gb: None,
        };
        let cli = MockRunner::new(pricing)
            .with_provision_record(record_json)
            .with_bind_result(bind);
        let cli = Arc::new(cli);
        let clock_arc: Arc<dyn Fn() -> i64 + Send + Sync> = Arc::new(move || now);
        let custody: Arc<dyn DeviceCustody> = Arc::new(
            crate::device_custody::FileCustody::static_test(dir.path()).unwrap(),
        );
        (
            WizardCtx {
                db,
                keystore: ks,
                staging_dir,
                cli,
                clock: clock_arc,
                custody,
            },
            dir,
        )
    }

    fn full_record_json() -> String {
        // OperatorRecord with two candidates so BindAndSign would
        // pass RP014 if it ran live; the mock ignores it but the
        // shape lets us drive the JSON parse path.
        r#"{
            "provider":"hetzner","server_id":"mock-1","region":"fsn1",
            "server_type":"cx22","public_ip":"5.75.0.1",
            "toolbox_profile":"iran-default",
            "enabled_families":["vless-reality"],
            "publisher_pub_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "mgmt_port":42424,
            "mgmt_tls_fingerprint":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "candidates":[{"family":"vless-reality"}],
            "provisioned_at":"2026-05-03T00:00:00Z",
            "freshness_url":""
        }"#
        .to_string()
    }

    #[test]
    fn provision_run_flips_status_to_provisioned() {
        let bind = BindResult {
            sbp_path: "/tmp/ignored".into(),
            sbp_sha256: "0".repeat(64),
            relay_pack_id: "rp-x".into(),
            fingerprint_hex: "f".repeat(64),
            fingerprint_en: "alpha bravo charlie delta".into(),
            fingerprint_fa: "یک دو سه چهار".into(),
            lint_warnings: vec![],
            shared_risk_edges: 0,
        };
        let (ctx, _dir) = ctx_with_canned(1_700_000_000, &full_record_json(), bind);
        let id = store_cloud_token(&ctx, "hetzner", "tok", None).unwrap();
        select_profile(
            &ctx,
            id,
            "fsn1",
            "cx22",
            "iran-default",
            vec!["vless-reality".into()],
        )
        .unwrap();
        publisher_keygen(&ctx, id).unwrap();
        set_helper_ip(&ctx, id, "1.2.3.4", "manual").unwrap();

        let mut events: Vec<ProgressEvent> = vec![];
        let mut on_prog = |ev: ProgressEvent| events.push(ev);
        provision_run(&ctx, id, "", &mut on_prog).unwrap();
        let row = ctx.db.get(id).unwrap();
        assert_eq!(row.status, "provisioned");
        assert_eq!(row.mgmt_port, 42424);
        assert_eq!(
            row.mgmt_tls_fingerprint,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        assert!(row.last_provisioned_at_unix.is_some());
        assert!(events.iter().any(|e| e.step == "provision_start"));
        assert!(events.iter().any(|e| e.step == "provision_done"));
    }

    #[test]
    fn provision_run_reports_a_missing_publisher_key_as_such() {
        // Replaces the old `provision_run_rejects_wrong_pin`: there is
        // no PIN to get wrong any more. What remains worth asserting is
        // that a genuinely absent secret is named honestly, so the UI
        // can tell "run the migration" apart from "the key is gone".
        let bind = BindResult {
            sbp_path: String::new(),
            sbp_sha256: "0".repeat(64),
            relay_pack_id: "rp-x".into(),
            fingerprint_hex: "f".repeat(64),
            fingerprint_en: "a b c d".into(),
            fingerprint_fa: "a b c d".into(),
            lint_warnings: vec![],
            shared_risk_edges: 0,
        };
        let (ctx, _dir) = ctx_with_canned(1_700_000_000, &full_record_json(), bind);
        let id = store_cloud_token(&ctx, "hetzner", "tok", None).unwrap();
        publisher_keygen(&ctx, id).unwrap();
        set_helper_ip(&ctx, id, "1.2.3.4", "manual").unwrap();
        // Lose the cloud token from both stores.
        ctx.custody.forget(&cloud_alias(id)).unwrap();

        let mut on_prog = |_ev: ProgressEvent| {};
        let err = provision_run(&ctx, id, "", &mut on_prog).unwrap_err();
        assert!(
            err.to_string().starts_with(E_SECRET_MISSING),
            "want E_SECRET_MISSING, got: {err}"
        );

        // Now plant a legacy PIN-sealed copy: the same absence must be
        // reported as recoverable instead.
        ctx.keystore
            .seal(&cloud_alias(id), "123456", b"tok")
            .unwrap();
        let err = provision_run(&ctx, id, "", &mut on_prog).unwrap_err();
        assert!(
            err.to_string().starts_with(E_LEGACY_PIN_REQUIRED),
            "want E_LEGACY_PIN_REQUIRED, got: {err}"
        );
    }

    #[test]
    fn sign_relaypack_records_sbp_metadata() {
        let bind = BindResult {
            sbp_path: "/tmp/0.sbp".into(),
            sbp_sha256: "a".repeat(64),
            relay_pack_id: "rp-abcdefabcdefabcdef".into(),
            fingerprint_hex: "f".repeat(64),
            fingerprint_en: "alpha bravo charlie delta".into(),
            fingerprint_fa: "یک دو سه چهار".into(),
            lint_warnings: vec![],
            shared_risk_edges: 1,
        };
        let (ctx, dir) = ctx_with_canned(1_700_000_000, &full_record_json(), bind.clone());
        let id = store_cloud_token(&ctx, "hetzner", "tok", None).unwrap();
        select_profile(
            &ctx,
            id,
            "fsn1",
            "cx22",
            "iran-default",
            vec!["vless-reality".into()],
        )
        .unwrap();
        publisher_keygen(&ctx, id).unwrap();
        set_helper_ip(&ctx, id, "1.2.3.4", "manual").unwrap();

        let mut on_prog = |_ev: ProgressEvent| {};
        provision_run(&ctx, id, "", &mut on_prog).unwrap();

        let out_dir = dir.path().join("out");
        std::fs::create_dir_all(&out_dir).unwrap();
        let res = sign_relaypack(
            &ctx,
            id,
            crate::phase::RELAYPACK_PHASE,
            &out_dir,
            "Family Relay",
            &mut on_prog,
        )
        .unwrap();
        assert_eq!(res.sbp_sha256, bind.sbp_sha256);
        let row = ctx.db.get(id).unwrap();
        assert_eq!(
            row.signed_sbp_sha256.as_deref(),
            Some(bind.sbp_sha256.as_str())
        );
        assert_eq!(
            row.signed_sbp_relay_pack_id.as_deref(),
            Some(bind.relay_pack_id.as_str())
        );
        assert_eq!(row.signed_sbp_at_unix, Some(1_700_000_000));
    }

    #[test]
    fn sign_relaypack_pipes_priv_key_through_stdin() {
        // The mock records the priv-key bytes it received; this
        // proves the wizard never wrote them to disk.
        use crate::cli_bridge::MockRunner;
        let bind = BindResult {
            sbp_path: String::new(),
            sbp_sha256: "a".repeat(64),
            relay_pack_id: "rp-mockmockmockmock".into(),
            fingerprint_hex: "f".repeat(64),
            fingerprint_en: "a b c d".into(),
            fingerprint_fa: "a b c d".into(),
            lint_warnings: vec![],
            shared_risk_edges: 0,
        };
        let dir = tempdir().unwrap();
        let db = Arc::new(OperatorDb::open_in_memory().unwrap());
        let ks = Arc::new(Keystore::new_in_memory(dir.path()));
        let pricing = Pricing {
            provider: "hetzner".into(),
            region: "fsn1".into(),
            server_type: "cx22".into(),
            hourly_eur: 0.005,
            monthly_eur: 3.85,
            included_traffic_tb_per_month: None,
            overage_eur_per_gb: None,
        };
        let mock = Arc::new(
            MockRunner::new(pricing)
                .with_provision_record(full_record_json())
                .with_bind_result(bind),
        );
        let mock_ref = mock.clone();
        let ctx_ = WizardCtx {
            db,
            keystore: ks,
            staging_dir: dir.path().join("staging"),
            cli: mock,
            clock: Arc::new(|| 1_700_000_000),
            custody: Arc::new(
                crate::device_custody::FileCustody::static_test(dir.path()).unwrap(),
            ),
        };
        let id = store_cloud_token(&ctx_, "hetzner", "tok", None).unwrap();
        select_profile(
            &ctx_,
            id,
            "fsn1",
            "cx22",
            "iran-default",
            vec!["vless-reality".into()],
        )
        .unwrap();
        publisher_keygen(&ctx_, id).unwrap();
        set_helper_ip(&ctx_, id, "1.2.3.4", "manual").unwrap();
        let mut on_prog = |_e: ProgressEvent| {};
        provision_run(&ctx_, id, "", &mut on_prog).unwrap();
        let out_dir = dir.path().join("out");
        std::fs::create_dir_all(&out_dir).unwrap();
        let _ = sign_relaypack(&ctx_, id, crate::phase::RELAYPACK_PHASE, &out_dir, "", &mut on_prog).unwrap();

        let captured = mock_ref.last_priv_key.lock().unwrap().clone();
        assert!(captured.is_some(), "mock did not receive priv-key");
        let bytes = captured.unwrap();
        // ed25519 signing key is 64 bytes (seed + pub).
        assert_eq!(bytes.len(), 64, "priv-key length wrong");
    }

    #[test]
    fn sign_relaypack_uses_active_subkey_when_present() {
        use crate::cli_bridge::MockRunner;
        let bind = BindResult {
            sbp_path: String::new(),
            sbp_sha256: "b".repeat(64),
            relay_pack_id: "rp-subkeysubkeysubkey".into(),
            fingerprint_hex: "f".repeat(64),
            fingerprint_en: "a b c d".into(),
            fingerprint_fa: "a b c d".into(),
            lint_warnings: vec![],
            shared_risk_edges: 0,
        };
        let pricing = Pricing {
            provider: "hetzner".into(),
            region: "fsn1".into(),
            server_type: "cx22".into(),
            hourly_eur: 0.005,
            monthly_eur: 3.85,
            included_traffic_tb_per_month: None,
            overage_eur_per_gb: None,
        };
        let mock = Arc::new(
            MockRunner::new(pricing)
                .with_provision_record(full_record_json())
                .with_bind_result(bind),
        );
        let mock_ref = mock.clone();
        let (ctx, dir, _) = ctx_with_mock(1_700_000_000, mock);
        let id = store_cloud_token(&ctx, "hetzner", "tok", None).unwrap();
        select_profile(
            &ctx,
            id,
            "fsn1",
            "cx22",
            "iran-default",
            vec!["vless-reality".into()],
        )
        .unwrap();
        publisher_keygen(&ctx, id).unwrap();
        set_helper_ip(&ctx, id, "1.2.3.4", "manual").unwrap();
        let mut on_prog = |_e: ProgressEvent| {};
        provision_run(&ctx, id, "", &mut on_prog).unwrap();

        let sub_dir = dir.path().join("subkey-active");
        std::fs::create_dir_all(&sub_dir).unwrap();
        let sub_priv_path = sub_dir.join("subkey.priv");
        let sub_cert_path = sub_dir.join("subkey.cert");
        let sub_pub_path = sub_dir.join("subkey.pub");
        let sub_priv = vec![7u8; 64];
        std::fs::write(&sub_priv_path, &sub_priv).unwrap();
        std::fs::write(&sub_cert_path, r#"{"kind":"subkey_cert"}"#).unwrap();
        std::fs::write(&sub_pub_path, &[8u8; 32]).unwrap();
        ctx.db
            .insert_subkey_rotation(
                id,
                "ab".repeat(32).as_str(),
                sub_pub_path.to_str().unwrap(),
                sub_priv_path.to_str().unwrap(),
                sub_cert_path.to_str().unwrap(),
                r#"{"kind":"subkey_cert"}"#,
                "active-test",
                1_700_000_000,
                1_707_776_000,
                1_700_000_000,
            )
            .unwrap();

        let out_dir = dir.path().join("out");
        std::fs::create_dir_all(&out_dir).unwrap();
        let _ = sign_relaypack(&ctx, id, crate::phase::RELAYPACK_PHASE, &out_dir, "", &mut on_prog).unwrap();

        let captured = mock_ref.last_priv_key.lock().unwrap().clone().unwrap();
        assert_eq!(captured, sub_priv, "active sub-key must be sent to signer");
        let cert_path = mock_ref
            .last_subkey_cert_path
            .lock()
            .unwrap()
            .clone()
            .expect("subkey cert path should be passed");
        assert_eq!(cert_path, sub_cert_path);
    }

    #[test]
    fn qr_render_streams_until_callback_returns_false() {
        let bind = BindResult {
            sbp_path: String::new(),
            sbp_sha256: "a".repeat(64),
            relay_pack_id: "rp-x".into(),
            fingerprint_hex: "f".repeat(64),
            fingerprint_en: "a b c d".into(),
            fingerprint_fa: "a b c d".into(),
            lint_warnings: vec![],
            shared_risk_edges: 0,
        };
        let (ctx, dir) = ctx_with_canned(1_700_000_000, &full_record_json(), bind);
        let id = store_cloud_token(&ctx, "hetzner", "tok", None).unwrap();
        select_profile(
            &ctx,
            id,
            "fsn1",
            "cx22",
            "iran-default",
            vec!["vless-reality".into()],
        )
        .unwrap();
        publisher_keygen(&ctx, id).unwrap();
        set_helper_ip(&ctx, id, "1.2.3.4", "manual").unwrap();
        let mut on_prog = |_e: ProgressEvent| {};
        provision_run(&ctx, id, "", &mut on_prog).unwrap();
        let out_dir = dir.path().join("out");
        std::fs::create_dir_all(&out_dir).unwrap();
        let _ = sign_relaypack(&ctx, id, crate::phase::RELAYPACK_PHASE, &out_dir, "", &mut on_prog).unwrap();

        // qr_render reads from staging_dir/<id>.sbp; create a
        // synthetic file so the existence check passes.
        std::fs::create_dir_all(&ctx.staging_dir).unwrap();
        std::fs::write(ctx.staging_dir.join(format!("{id}.sbp")), &[1, 2, 3, 4]).unwrap();

        let mut got = 0usize;
        let mut on_frame = |_f: FountainFrame| -> bool {
            got += 1;
            got < 3 // stop after 3 frames
        };
        qr_render(&ctx, id, 256, 10, 7, &mut on_frame).unwrap();
        assert!(got >= 3, "expected at least 3 frames, got {got}");
    }

    // ---- FRP-7 rotation surface ----------------------------------

    fn make_provisioned_op(ctx: &WizardCtx) -> i64 {
        let id = store_cloud_token(ctx, "hetzner", "tok-abc", None).unwrap();
        select_profile(
            ctx,
            id,
            "fsn1",
            "cx22",
            "iran-default",
            vec!["vless-reality".into()],
        )
        .unwrap();
        let _ = publisher_keygen(ctx, id).unwrap();
        let _ = finalize_pre_provision(ctx, id).unwrap();
        // Mark provisioned so rotate_execute's sign_relaypack succeeds.
        ctx.db.mark_provisioned(id, 1_700_000_000).unwrap();
        id
    }

    #[test]
    fn rotate_recommend_explanation_path() {
        let (ctx, _dir) = ctx(1_700_000_000);
        let id = make_provisioned_op(&ctx);
        // Replace MockRunner with a canned recommendation
        let mock = Arc::new(
            MockRunner::new(Pricing {
                provider: "hetzner".into(),
                region: "fsn1".into(),
                server_type: "cx22".into(),
                hourly_eur: 0.0,
                monthly_eur: 0.0,
                included_traffic_tb_per_month: None,
                overage_eur_per_gb: None,
            })
            .with_rotation_recommendation(crate::cli_bridge::RotationRecommendation {
                level: "L3".into(),
                confidence: "high".into(),
                reason: "tcp_reset on burned IP".into(),
                est_wallclock: "~10s".into(),
                override_levels: vec!["L4".into(), "L2".into()],
            }),
        );
        let ctx2 = WizardCtx {
            db: ctx.db.clone(),
            keystore: ctx.keystore.clone(),
            staging_dir: ctx.staging_dir.clone(),
            cli: mock,
            clock: ctx.clock.clone(),
            custody: ctx.custody.clone(),
        };
        // A selector Explanation as the shipped phase emits it.
        let exp = format!(
            r#"{{"pick":{{"exposure_mode":"direct_vps"}},"failures":[],"phase":"{}"}}"#,
            crate::phase::RELAYPACK_PHASE
        );
        let r = rotate_recommend(&ctx2, id, RotateRecommendInput::Explanation(exp)).unwrap();
        assert_eq!(r.level, "L3");
        assert_eq!(r.confidence, "high");
        assert_eq!(r.est_wallclock, "~10s");
    }

    #[test]
    fn rotate_recommend_context_path() {
        let (ctx, _dir) = ctx(1_700_000_000);
        let id = make_provisioned_op(&ctx);
        let r = rotate_recommend(
            &ctx,
            id,
            RotateRecommendInput::Context(crate::cli_bridge::RotateContext {
                failure_classifications: vec!["sni_rst".into()],
                network_signals: vec![],
                exposure_mode: "direct_vps".into(),
                credential_leak_suspected: false,
            }),
        )
        .unwrap();
        // MockRunner returns the L1 default for an empty
        // recommendation slot — that's the smoke we're after; live
        // wiring goes through the Go binary covered by
        // publisher/deploy/cli/cli_test.go.
        assert!(!r.level.is_empty());
        assert!(!r.confidence.is_empty());
    }

    #[test]
    fn rotate_revert_with_no_history_errors() {
        let (ctx, _dir) = ctx(1_700_000_000);
        let id = make_provisioned_op(&ctx);
        let err = rotate_revert(&ctx, id).unwrap_err();
        match err {
            WizardError::Db(DbError::NotFound(x)) if x == id => (),
            e => panic!("unexpected error: {e:?}"),
        }
    }

    #[test]
    fn list_rotation_history_empty_returns_empty_vec() {
        let (ctx, _dir) = ctx(1_700_000_000);
        let id = make_provisioned_op(&ctx);
        let history = list_rotation_history(&ctx, id).unwrap();
        assert!(history.is_empty());
    }

    #[test]
    fn rotate_execute_l3_assigns_fip_before_signing_and_records_history() {
        let bind = BindResult {
            sbp_path: "/tmp/rotated.sbp".into(),
            sbp_sha256: "b".repeat(64),
            relay_pack_id: "rp-rotated".into(),
            fingerprint_hex: "e".repeat(64),
            fingerprint_en: "alpha bravo charlie delta".into(),
            fingerprint_fa: "یک دو سه چهار".into(),
            lint_warnings: vec![],
            shared_risk_edges: 2,
        };
        let pricing = Pricing {
            provider: "hetzner".into(),
            region: "fsn1".into(),
            server_type: "cx22".into(),
            hourly_eur: 0.005,
            monthly_eur: 3.85,
            included_traffic_tb_per_month: None,
            overage_eur_per_gb: None,
        };
        let mock = Arc::new(
            MockRunner::new(pricing)
                .with_provision_record(full_record_json())
                .with_bind_result(bind.clone()),
        );
        let (ctx, _dir, mock) = ctx_with_mock(1_700_000_000, mock);
        let id = make_provisioned_op(&ctx);
        let mut events = Vec::new();
        let mut on_prog = |e: ProgressEvent| events.push(e);

        let out = rotate_execute(
            &ctx,
            id,
            RotateExecuteInput {
                level: "L3".into(),
                reason: "ip burned".into(),
                new_floating_ip_id: Some("fip-new".into()),
                ..Default::default()
            },
            &mut on_prog,
        )
        .unwrap();

        assert_eq!(out.bind_result, bind);
        assert_eq!(mock.assign_fip_calls.lock().unwrap().len(), 1);
        assert_eq!(mock.assign_fip_calls.lock().unwrap()[0].fip_id, "fip-new");
        assert_eq!(*mock.provision_calls.lock().unwrap(), 0);
        assert!(ctx
            .db
            .get(id)
            .unwrap()
            .operator_record_json
            .contains("\"floating_ip_id\":\"fip-new\""));
        let history = ctx.db.list_signed_sbps_history(id).unwrap();
        assert_eq!(history.len(), 1);
        assert!(history[0].active);
        assert!(events.iter().any(|e| e.step == "rotate_provider_done"));
    }

    /// The gate this whole step exists to close, on the Rust side.
    ///
    /// `sign_relaypack` is called from two places: the wizard's build
    /// flow (initial sign) and `rotate_execute` (re-sign). They used
    /// to pass different literals — "V1.6" from the TS wizard, "V1.5"
    /// hard-coded here — so rotating a relay silently downgraded the
    /// pack's phase and re-shut RP004 / RP021 on every recipient. Both
    /// calls succeed either way, so only the recorded `--phase`
    /// transcript can catch it.
    #[test]
    fn rotate_resign_uses_the_same_phase_as_the_initial_sign() {
        let pricing = Pricing {
            provider: "hetzner".into(),
            region: "fsn1".into(),
            server_type: "cx22".into(),
            hourly_eur: 0.005,
            monthly_eur: 3.85,
            included_traffic_tb_per_month: None,
            overage_eur_per_gb: None,
        };
        let mock = Arc::new(MockRunner::new(pricing).with_provision_record(full_record_json()));
        let (ctx, dir, mock) = ctx_with_mock(1_700_000_000, mock);
        let id = make_provisioned_op(&ctx);
        let mut on_prog = |_e: ProgressEvent| {};

        // 1. Initial sign, exactly as the wizard's build flow does it.
        let out_dir = dir.path().join("out");
        sign_relaypack(
            &ctx,
            id,
            crate::phase::RELAYPACK_PHASE,
            &out_dir,
            "Family Relay Publisher",
            &mut on_prog,
        )
        .unwrap();

        // 2. Rotate, which re-signs through its own call site.
        rotate_execute(
            &ctx,
            id,
            RotateExecuteInput {
                level: "L3".into(),
                reason: "ip burned".into(),
                new_floating_ip_id: Some("fip-new".into()),
                ..Default::default()
            },
            &mut on_prog,
        )
        .unwrap();

        let phases = mock.bind_phases.lock().unwrap().clone();
        assert_eq!(phases.len(), 2, "expected an initial sign and a re-sign");
        assert_eq!(
            phases[0], phases[1],
            "rotation re-signed at a different phase than the initial sign"
        );
        // And both are the one canonical value, not merely equal to
        // each other at some third phase.
        assert_eq!(phases[1], crate::phase::RELAYPACK_PHASE);
    }

    #[test]
    fn rotate_execute_l4_reprovisions_then_provisions_replacement() {
        let bind = BindResult {
            sbp_path: "/tmp/rotated-l4.sbp".into(),
            sbp_sha256: "c".repeat(64),
            relay_pack_id: "rp-rotated-l4".into(),
            fingerprint_hex: "d".repeat(64),
            fingerprint_en: "alpha bravo charlie delta".into(),
            fingerprint_fa: "یک دو سه چهار".into(),
            lint_warnings: vec![],
            shared_risk_edges: 3,
        };
        let pricing = Pricing {
            provider: "hetzner".into(),
            region: "fsn1".into(),
            server_type: "cx22".into(),
            hourly_eur: 0.005,
            monthly_eur: 3.85,
            included_traffic_tb_per_month: None,
            overage_eur_per_gb: None,
        };
        let mock = Arc::new(
            MockRunner::new(pricing)
                .with_provision_record(full_record_json())
                .with_bind_result(bind),
        );
        let (ctx, _dir, mock) = ctx_with_mock(1_700_000_000, mock);
        let id = make_provisioned_op(&ctx);
        let mut on_prog = |_e: ProgressEvent| {};

        rotate_execute(
            &ctx,
            id,
            RotateExecuteInput {
                level: "L4".into(),
                reason: "datacenter prefix burned".into(),
                helper_ip: Some("1.2.3.4".into()),
                new_toolbox_profile: Some("tcp-only-vps-native".into()),
                ..Default::default()
            },
            &mut on_prog,
        )
        .unwrap();

        let reprovision_calls = mock.reprovision_calls.lock().unwrap();
        assert_eq!(reprovision_calls.len(), 1);
        assert_eq!(
            reprovision_calls[0].new_toolbox_profile.as_deref(),
            Some("tcp-only-vps-native")
        );
        drop(reprovision_calls);
        assert_eq!(*mock.provision_calls.lock().unwrap(), 1);
        assert_eq!(ctx.db.list_signed_sbps_history(id).unwrap().len(), 1);
    }

    #[test]
    fn rotate_execute_l2_applies_route_params_before_signing() {
        let bind = BindResult {
            sbp_path: "/tmp/rotated-l2.sbp".into(),
            sbp_sha256: "d".repeat(64),
            relay_pack_id: "rp-rotated-l2".into(),
            fingerprint_hex: "c".repeat(64),
            fingerprint_en: "alpha bravo charlie delta".into(),
            fingerprint_fa: "یک دو سه چهار".into(),
            lint_warnings: vec![],
            shared_risk_edges: 3,
        };
        let pricing = Pricing {
            provider: "hetzner".into(),
            region: "fsn1".into(),
            server_type: "cx22".into(),
            hourly_eur: 0.005,
            monthly_eur: 3.85,
            included_traffic_tb_per_month: None,
            overage_eur_per_gb: None,
        };
        let mock = Arc::new(
            MockRunner::new(pricing)
                .with_provision_record(full_record_json())
                .with_bind_result(bind),
        );
        let (ctx, _dir, mock) = ctx_with_mock(1_700_000_000, mock);
        let id = make_provisioned_op(&ctx);
        let mut on_prog = |_e: ProgressEvent| {};

        rotate_execute(
            &ctx,
            id,
            RotateExecuteInput {
                level: "L2".into(),
                reason: "sni blocked".into(),
                helper_ip: Some("1.2.3.4".into()),
                new_sni: Some("front.example.com".into()),
                new_ws_path: Some("/front/ws".into()),
                ..Default::default()
            },
            &mut on_prog,
        )
        .unwrap();

        let reprovision_calls = mock.reprovision_calls.lock().unwrap();
        assert_eq!(reprovision_calls.len(), 1);
        assert_eq!(
            reprovision_calls[0].new_sni.as_deref(),
            Some("front.example.com")
        );
        assert_eq!(
            reprovision_calls[0].new_ws_path.as_deref(),
            Some("/front/ws")
        );
        drop(reprovision_calls);
        let record = ctx.db.get(id).unwrap().operator_record_json;
        assert!(record.contains("\"sni\":\"front.example.com\""), "{record}");
        assert!(
            record.contains("\"reality_dest\":\"front.example.com\""),
            "{record}"
        );
        assert!(record.contains("\"ws_path\":\"/front/ws\""), "{record}");
        assert!(record.contains("\"sni:front.example.com\""), "{record}");
        assert!(record.contains("\"ws_path_fp:"), "{record}");
        assert_eq!(ctx.db.list_signed_sbps_history(id).unwrap().len(), 1);
    }

    /// Wave 2, Step 4: an L2 rotation must actually MOVE the relay's
    /// cover host.
    ///
    /// The failure this pins is silent and expensive. `reprovision`
    /// picks a fresh cover host and writes it into the record;
    /// `provision` then rebuilds the box, and its own pick is seeded on
    /// the derived server name — `daal-<region>-<hex8 of publisher
    /// key>` — which a rebuild does not change. So if the rotated value
    /// is not forwarded, `provision` re-derives the ORIGINAL host, the
    /// record is overwritten to agree, and the operator has paid for a
    /// full rebuild to land back on the exact SNI that was blocked.
    #[test]
    fn rotate_execute_l2_forwards_the_rotated_cover_host_to_provision() {
        let bind = BindResult {
            sbp_path: "/tmp/rotated-l2-sni.sbp".into(),
            sbp_sha256: "d".repeat(64),
            relay_pack_id: "rp-rotated-l2-sni".into(),
            fingerprint_hex: "c".repeat(64),
            fingerprint_en: "alpha bravo charlie delta".into(),
            fingerprint_fa: "یک دو سه چهار".into(),
            lint_warnings: vec![],
            shared_risk_edges: 3,
        };
        let pricing = Pricing {
            provider: "hetzner".into(),
            region: "fsn1".into(),
            server_type: "cx22".into(),
            hourly_eur: 0.005,
            monthly_eur: 3.85,
            included_traffic_tb_per_month: None,
            overage_eur_per_gb: None,
        };
        let mock = Arc::new(
            MockRunner::new(pricing)
                .with_provision_record(full_record_json())
                .with_bind_result(bind),
        );
        let (ctx, _dir, mock) = ctx_with_mock(1_700_000_000, mock);
        let id = make_provisioned_op(&ctx);
        let mut on_prog = |_e: ProgressEvent| {};

        // No explicit --new-sni: the pool picks, which is the normal
        // "this host was blocked, move me" case and the one where an
        // unforwarded value is undetectable by eye.
        rotate_execute(
            &ctx,
            id,
            RotateExecuteInput {
                level: "L2".into(),
                reason: "cover host blocked".into(),
                helper_ip: Some("1.2.3.4".into()),
                ..Default::default()
            },
            &mut on_prog,
        )
        .unwrap();

        let snis = mock.provision_cover_snis.lock().unwrap();
        assert_eq!(snis.len(), 1, "expected exactly one provision call");
        assert_eq!(
            snis[0], "mirror.rotated.test",
            "the rebuild must be told the cover host reprovision just rotated onto \
             this relay; an empty value re-derives the burned one"
        );
    }

    // ----- FRP-8 CDN command tests -----

    fn cdn_row_fixture(operator_id: i64, hostname: &str) -> CdnFrontRow {
        CdnFrontRow {
            id: 0,
            operator_id,
            hostname: hostname.into(),
            zone_id: "zone-test".into(),
            public_path: "/r/abcdefab".into(),
            origin_path: "/ws".into(),
            worker_route_id: "route-1".into(),
            origin_ca_fingerprint: "ababababababababababababababababababababababababababababababab"
                .into(),
            origin_ca_cert_path: "/tmp/origin_ca.pem".into(),
            origin_ca_priv_path: "/tmp/origin_ca.key".into(),
            aop_client_cert_path: "/tmp/aop_client.pem".into(),
            aop_enabled: true,
            firewall_id: "fw-test".into(),
            dns_only_present: false,
            edge_ranges_fetched_unix: 0,
            last_verified_unix: 0,
            created_unix: 1_700_000_000,
        }
    }

    #[test]
    fn record_cdn_front_attestation_and_list() {
        let (ctx, _dir) = ctx(1_700_000_000);
        let op_id = store_cloud_token(&ctx, "hetzner", "tok", None).unwrap();
        let row = cdn_row_fixture(op_id, "front.example.com");
        let id = record_cdn_front_attestation(&ctx, &row).unwrap();
        assert!(id > 0);
        let rows = list_cdn_fronts(&ctx, op_id).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].hostname, "front.example.com");
        assert!(rows[0].aop_enabled);
        assert!(!rows[0].dns_only_present);
    }

    #[test]
    fn record_cdn_front_attestation_upserts_on_conflict() {
        let (ctx, _dir) = ctx(1_700_000_000);
        let op_id = store_cloud_token(&ctx, "hetzner", "tok", None).unwrap();
        let mut row = cdn_row_fixture(op_id, "front.example.com");
        record_cdn_front_attestation(&ctx, &row).unwrap();
        // Re-insert with a different public_path; the unique
        // (operator_id, hostname) index drives ON CONFLICT
        // DO UPDATE.
        row.public_path = "/r/newpath".into();
        record_cdn_front_attestation(&ctx, &row).unwrap();
        let rows = list_cdn_fronts(&ctx, op_id).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].public_path, "/r/newpath");
    }

    #[test]
    fn provision_cdn_front_inserts_live_front_record() {
        let (ctx, _dir) = ctx(1_700_000_000);
        let op_id = store_cloud_token(&ctx, "hetzner", "tok", None).unwrap();
        // Stash the CF token under the alias the command reads.
        ctx.custody
            .put(&cloudflare_alias(op_id), b"cf-token")
            .unwrap();
        let input = ProvisionCdnFrontInput {
            operator_id: op_id,
            hostname: "front.example.com".into(),
            origin_ip: "5.75.0.1".into(),
            origin_ipv6: String::new(),
            origin_path: "/ws".into(),
            public_path: String::new(),
        };
        let front_id = provision_cdn_front(&ctx, &input).unwrap();
        let rows = list_cdn_fronts(&ctx, op_id).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, front_id);
        assert_eq!(rows[0].hostname, "momsroute.example.com");
        assert_eq!(rows[0].firewall_id, "fw-example");
        assert!(rows[0].aop_enabled);
    }

    #[test]
    fn provision_cdn_front_validates_input() {
        let (ctx, _dir) = ctx(1_700_000_000);
        let op_id = store_cloud_token(&ctx, "hetzner", "tok", None).unwrap();
        let input = ProvisionCdnFrontInput {
            operator_id: op_id,
            hostname: String::new(),
            origin_ip: "5.75.0.1".into(),
            origin_ipv6: String::new(),
            origin_path: "/ws".into(),
            public_path: String::new(),
        };
        let err = provision_cdn_front(&ctx, &input).unwrap_err();
        assert!(matches!(err, WizardError::Cdn(_)));
    }

    #[test]
    fn verify_cdn_posture_updates_timestamp() {
        let (ctx, _dir) = ctx(1_700_000_000);
        let op_id = store_cloud_token(&ctx, "hetzner", "tok", None).unwrap();
        let mut row = cdn_row_fixture(op_id, "front.example.com");
        row.edge_ranges_fetched_unix = 1;
        row.last_verified_unix = 1;
        let front_id = record_cdn_front_attestation(&ctx, &row).unwrap();
        verify_cdn_posture(&ctx, front_id).unwrap();
        let rows = list_cdn_fronts(&ctx, op_id).unwrap();
        assert!(rows[0].edge_ranges_fetched_unix > 1);
        assert!(rows[0].last_verified_unix > 1);
    }

    /// FRP-9 commit 1/8: rotate_cdn_path drives the rotate-path
    /// CLI surface, mutates the V005 row to the new public path
    /// + worker_route_id, and leaves hostname/zone_id/origin_path
    /// untouched.
    #[test]
    fn rotate_cdn_path_mutates_only_public_surface() {
        let (ctx, _dir) = ctx(1_700_000_000);
        let op_id = store_cloud_token(&ctx, "hetzner", "tok", None).unwrap();
        ctx.custody
            .put(&cloudflare_alias(op_id), b"cf-token")
            .unwrap();
        let row = cdn_row_fixture(op_id, "front.example.com");
        let front_id = record_cdn_front_attestation(&ctx, &row).unwrap();
        let res = rotate_cdn_path(
            &ctx,
            &RotateCdnPathInput {
                front_id,
                account_id: "account-example.com".into(),
                new_public_path: "/r/newAB12".into(),
            },
        )
        .unwrap();
        assert_eq!(res.public_path, "/r/newAB12");
        let rows = list_cdn_fronts(&ctx, op_id).unwrap();
        assert_eq!(rows[0].public_path, "/r/newAB12");
        // §14.4 invariant: hostname must NOT change in a path
        // rotation.
        assert_eq!(rows[0].hostname, row.hostname);
        assert_eq!(rows[0].origin_path, row.origin_path);
    }

    /// FRP-9 commit 1/8: rotate_cdn_hostname mutates hostname,
    /// zone_id, and worker_route_id; public_path + origin_path
    /// stay put. The wizard re-signs the RelayPack at a later
    /// step (commit 4/8); this layer's job is just the CDN-side
    /// rebind.
    #[test]
    fn rotate_cdn_hostname_mutates_hostname_and_zone() {
        let (ctx, _dir) = ctx(1_700_000_000);
        let op_id = store_cloud_token(&ctx, "hetzner", "tok", None).unwrap();
        ctx.custody
            .put(&cloudflare_alias(op_id), b"cf-token")
            .unwrap();
        let row = cdn_row_fixture(op_id, "front.example.com");
        let front_id = record_cdn_front_attestation(&ctx, &row).unwrap();
        let res = rotate_cdn_hostname(
            &ctx,
            &RotateCdnHostnameInput {
                front_id,
                new_hostname: "frontB.newdomain.com".into(),
                origin_ipv4: "5.75.9.9".into(),
                origin_ipv6: String::new(),
            },
        )
        .unwrap();
        assert_eq!(res.hostname, "frontB.newdomain.com");
        let rows = list_cdn_fronts(&ctx, op_id).unwrap();
        assert_eq!(rows[0].hostname, "frontB.newdomain.com");
        assert_eq!(rows[0].zone_id, "zone-frontB.newdomain.com");
        // §14.4: public path is unchanged.
        assert_eq!(rows[0].public_path, row.public_path);
    }

    /// FRP-9 commit 1/8 + supplement §14.4: rotate_cdn_origin
    /// MUST NOT mutate any public-surface field. The censor sees
    /// nothing; the wizard MUST NOT re-sign the RelayPack.
    #[test]
    fn rotate_cdn_origin_origin_only_invisible() {
        let (ctx, _dir) = ctx(1_700_000_000);
        let op_id = store_cloud_token(&ctx, "hetzner", "tok", None).unwrap();
        ctx.custody
            .put(&cloudflare_alias(op_id), b"cf-token")
            .unwrap();
        let row = cdn_row_fixture(op_id, "front.example.com");
        let front_id = record_cdn_front_attestation(&ctx, &row).unwrap();
        rotate_cdn_origin(
            &ctx,
            &RotateCdnOriginInput {
                front_id,
                new_origin_ipv4: "5.75.99.99".into(),
                new_origin_ipv6: String::new(),
            },
        )
        .unwrap();
        let rows = list_cdn_fronts(&ctx, op_id).unwrap();
        // EVERY public-surface field must be byte-identical.
        assert_eq!(rows[0].hostname, row.hostname);
        assert_eq!(rows[0].zone_id, row.zone_id);
        assert_eq!(rows[0].public_path, row.public_path);
        assert_eq!(rows[0].origin_path, row.origin_path);
        assert_eq!(rows[0].worker_route_id, row.worker_route_id);
        assert_eq!(rows[0].origin_ca_fingerprint, row.origin_ca_fingerprint);
        assert_eq!(rows[0].aop_enabled, row.aop_enabled);
        // Re-pointing the origin is not a posture verification; the
        // operator must run Verify CDN posture separately after any
        // firewall/cert repair. Do not stamp the row as verified.
        assert_eq!(
            rows[0].edge_ranges_fetched_unix,
            row.edge_ranges_fetched_unix
        );
        assert_eq!(rows[0].last_verified_unix, row.last_verified_unix);
    }

    /// FRP-9 commit 1/8 belt-and-braces: empty IPv4 must be
    /// rejected so a wizard bug doesn't silently bring the front
    /// down by writing an empty A record.
    #[test]
    fn rotate_cdn_origin_rejects_empty_ipv4() {
        let (ctx, _dir) = ctx(1_700_000_000);
        let op_id = store_cloud_token(&ctx, "hetzner", "tok", None).unwrap();
        ctx.custody
            .put(&cloudflare_alias(op_id), b"cf-token")
            .unwrap();
        let row = cdn_row_fixture(op_id, "front.example.com");
        let front_id = record_cdn_front_attestation(&ctx, &row).unwrap();
        let err = rotate_cdn_origin(
            &ctx,
            &RotateCdnOriginInput {
                front_id,
                new_origin_ipv4: String::new(),
                new_origin_ipv6: String::new(),
            },
        )
        .unwrap_err();
        assert!(matches!(err, WizardError::Cdn(_)));
    }

    /// FRP-9 commit 3/8: rotate_execute(L7_CDN_PATH) drives the
    /// path-rotation CLI shape AND re-signs the RelayPack. The
    /// resulting RotateExecuteOutput carries a non-zero
    /// signed_sbp_id and the new bind_result.
    #[test]
    fn rotate_execute_l7_cdn_path_rotates_path_and_resigns() {
        let bind = BindResult {
            sbp_path: "/tmp/rotated-l7.sbp".into(),
            sbp_sha256: "7".repeat(64),
            relay_pack_id: "rp-l7".into(),
            fingerprint_hex: "7".repeat(64),
            fingerprint_en: "lima mike november oscar".into(),
            fingerprint_fa: "ل م ن س".into(),
            lint_warnings: vec![],
            shared_risk_edges: 0,
        };
        let pricing = Pricing {
            provider: "hetzner".into(),
            region: "fsn1".into(),
            server_type: "cx22".into(),
            hourly_eur: 0.005,
            monthly_eur: 3.85,
            included_traffic_tb_per_month: None,
            overage_eur_per_gb: None,
        };
        let mock = Arc::new(
            MockRunner::new(pricing)
                .with_provision_record(full_record_json())
                .with_bind_result(bind.clone()),
        );
        let (ctx, _dir, mock) = ctx_with_mock(1_700_000_000, mock);
        let id = make_provisioned_op(&ctx);
        // Stage CF token + CDN front row.
        ctx.custody
            .put(&cloudflare_alias(id), b"cf-token")
            .unwrap();
        let row = cdn_row_fixture(id, "front.example.com");
        let front_id = record_cdn_front_attestation(&ctx, &row).unwrap();

        let out = rotate_execute(
            &ctx,
            id,
            RotateExecuteInput {
                level: "L7_CDN_PATH".into(),
                reason: "public path burned".into(),
                cdn_front_id: Some(front_id),
                cdn_account_id: Some("account-example.com".into()),
                cdn_new_public_path: Some("/r/newAB12".into()),
                freshness_signed_sbp_url: Some(
                    "https://freshness.example.com/operator-1.sbp".into(),
                ),
                ..Default::default()
            },
            &mut |_e| {},
        )
        .unwrap();

        // Re-sign happened: signed_sbp_id != 0 and bind_result is
        // the mocked new bind.
        assert_ne!(out.signed_sbp_id, 0);
        assert_eq!(out.bind_result.relay_pack_id, "rp-l7");
        assert_eq!(out.level, "L7_CDN_PATH");
        // CDN row was mutated to the new public path.
        let rows = list_cdn_fronts(&ctx, id).unwrap();
        assert_eq!(rows[0].public_path, "/r/newAB12");
        // L7 must NOT call assign-fip or reprovision.
        assert_eq!(mock.assign_fip_calls.lock().unwrap().len(), 0);
        assert_eq!(mock.reprovision_calls.lock().unwrap().len(), 0);
        // L7 MUST call cdn-rotate-path.
        assert_eq!(mock.cdn_rotate_path_calls.lock().unwrap().len(), 1);
        // §14.4: L7 MUST publish freshness.
        let pf = mock.publish_freshness_calls.lock().unwrap();
        assert_eq!(pf.len(), 1, "expected publish-freshness call on L7");
        assert_eq!(pf[0].relay_pack_id, "rp-l7");
        assert_eq!(
            pf[0].current_signed_url,
            "https://freshness.example.com/operator-1.sbp"
        );
    }

    /// FRP-9 commit 3/8: rotate_execute(L8_CDN_HOSTNAME) drives
    /// the hostname-rotation CLI shape AND re-signs the
    /// RelayPack.
    #[test]
    fn rotate_execute_l8_cdn_hostname_rotates_hostname_and_resigns() {
        let bind = BindResult {
            sbp_path: "/tmp/rotated-l8.sbp".into(),
            sbp_sha256: "8".repeat(64),
            relay_pack_id: "rp-l8".into(),
            fingerprint_hex: "8".repeat(64),
            fingerprint_en: "papa quebec romeo sierra".into(),
            fingerprint_fa: "پ ق ر س".into(),
            lint_warnings: vec![],
            shared_risk_edges: 0,
        };
        let pricing = Pricing {
            provider: "hetzner".into(),
            region: "fsn1".into(),
            server_type: "cx22".into(),
            hourly_eur: 0.005,
            monthly_eur: 3.85,
            included_traffic_tb_per_month: None,
            overage_eur_per_gb: None,
        };
        let mock = Arc::new(
            MockRunner::new(pricing)
                .with_provision_record(full_record_json())
                .with_bind_result(bind.clone()),
        );
        let (ctx, _dir, mock) = ctx_with_mock(1_700_000_000, mock);
        let id = make_provisioned_op(&ctx);
        ctx.custody
            .put(&cloudflare_alias(id), b"cf-token")
            .unwrap();
        let row = cdn_row_fixture(id, "front.example.com");
        let front_id = record_cdn_front_attestation(&ctx, &row).unwrap();

        let out = rotate_execute(
            &ctx,
            id,
            RotateExecuteInput {
                level: "L8_CDN_HOSTNAME".into(),
                reason: "hostname domain-blocked".into(),
                cdn_front_id: Some(front_id),
                cdn_new_hostname: Some("frontB.newdomain.com".into()),
                cdn_new_origin_ipv4: Some("5.75.9.9".into()),
                freshness_signed_sbp_url: Some(
                    "https://freshness.example.com/operator-1.sbp".into(),
                ),
                ..Default::default()
            },
            &mut |_e| {},
        )
        .unwrap();

        assert_ne!(out.signed_sbp_id, 0);
        assert_eq!(out.bind_result.relay_pack_id, "rp-l8");
        let rows = list_cdn_fronts(&ctx, id).unwrap();
        assert_eq!(rows[0].hostname, "frontB.newdomain.com");
        assert_eq!(rows[0].public_path, row.public_path);
        assert_eq!(mock.cdn_rotate_hostname_calls.lock().unwrap().len(), 1);
        // §14.4: L8 MUST publish freshness.
        let pf = mock.publish_freshness_calls.lock().unwrap();
        assert_eq!(pf.len(), 1, "expected publish-freshness call on L8");
    }

    /// FRP-9 commit 3/8 + supplement §14.4: rotate_execute(
    /// L9_CDN_ORIGIN) MUST NOT re-sign the RelayPack and MUST NOT
    /// re-publish freshness. The output's signed_sbp_id is 0 and
    /// the bind_result is the Default. The CDN row's public-
    /// surface fields are byte-identical before and after.
    #[test]
    fn rotate_execute_l9_cdn_origin_does_not_resign() {
        let pricing = Pricing {
            provider: "hetzner".into(),
            region: "fsn1".into(),
            server_type: "cx22".into(),
            hourly_eur: 0.005,
            monthly_eur: 3.85,
            included_traffic_tb_per_month: None,
            overage_eur_per_gb: None,
        };
        let mock = Arc::new(MockRunner::new(pricing).with_provision_record(full_record_json()));
        let (ctx, _dir, mock) = ctx_with_mock(1_700_000_000, mock);
        let id = make_provisioned_op(&ctx);
        ctx.custody
            .put(&cloudflare_alias(id), b"cf-token")
            .unwrap();
        let row = cdn_row_fixture(id, "front.example.com");
        let front_id = record_cdn_front_attestation(&ctx, &row).unwrap();
        let before = list_cdn_fronts(&ctx, id).unwrap()[0].clone();

        let out = rotate_execute(
            &ctx,
            id,
            RotateExecuteInput {
                level: "L9_CDN_ORIGIN".into(),
                reason: "origin VPS rebuilt".into(),
                cdn_front_id: Some(front_id),
                cdn_new_origin_ipv4: Some("5.75.99.99".into()),
                ..Default::default()
            },
            &mut |_e| {},
        )
        .unwrap();

        // §14.4 invariant: NO re-sign.
        assert_eq!(out.signed_sbp_id, 0);
        assert_eq!(out.bind_result, BindResult::default());
        assert_eq!(out.level, "L9_CDN_ORIGIN");
        // §14.4 invariant: every public-surface field
        // byte-identical.
        let after = list_cdn_fronts(&ctx, id).unwrap()[0].clone();
        assert_eq!(before.hostname, after.hostname);
        assert_eq!(before.zone_id, after.zone_id);
        assert_eq!(before.public_path, after.public_path);
        assert_eq!(before.origin_path, after.origin_path);
        assert_eq!(before.worker_route_id, after.worker_route_id);
        // CFClient was driven via the rotate-origin path only —
        // not assign-fip, not reprovision.
        assert_eq!(mock.cdn_rotate_origin_calls.lock().unwrap().len(), 1);
        assert_eq!(mock.assign_fip_calls.lock().unwrap().len(), 0);
        assert_eq!(mock.reprovision_calls.lock().unwrap().len(), 0);
        // History got an audit-only row tagged L9_CDN_ORIGIN.
        let history = list_rotation_history(&ctx, id).unwrap();
        assert!(
            history
                .iter()
                .any(|h| h.rotation_reason.contains("L9_CDN_ORIGIN")),
            "expected L9_CDN_ORIGIN history row, got: {history:?}"
        );
        // §14.4: L9 origin-only MUST NOT publish freshness.
        assert_eq!(
            mock.publish_freshness_calls.lock().unwrap().len(),
            0,
            "L9 must NOT publish freshness"
        );
    }

    /// FRP-9 commit 3/8: missing required L7 input surfaces a
    /// clean WizardError::Cdn instead of corrupting the row.
    #[test]
    fn rotate_execute_l7_requires_cdn_front_id() {
        let pricing = Pricing {
            provider: "hetzner".into(),
            region: "fsn1".into(),
            server_type: "cx22".into(),
            hourly_eur: 0.005,
            monthly_eur: 3.85,
            included_traffic_tb_per_month: None,
            overage_eur_per_gb: None,
        };
        let mock = Arc::new(MockRunner::new(pricing).with_provision_record(full_record_json()));
        let (ctx, _dir, _mock) = ctx_with_mock(1_700_000_000, mock);
        let id = make_provisioned_op(&ctx);
        let err = rotate_execute(
            &ctx,
            id,
            RotateExecuteInput {
                level: "L7_CDN_PATH".into(),
                reason: "missing-front-id".into(),
                ..Default::default()
            },
            &mut |_e| {},
        )
        .unwrap_err();
        assert!(matches!(err, WizardError::Cdn(_)));
    }
}
