//! High-level wizard command surface.
//!
//! These functions are the operations the Tauri command bindings
//! call (FRP-5 commit 4 wires the `#[tauri::command]` shims). Each
//! function takes a [`WizardCtx`] holding the dependencies — DB,
//! keystore, CLI runner — so unit tests can substitute mocks.
//!
//! At FRP-5 ship the LIVE operations are:
//!
//!   - `set_pin` / `unlock_pin`
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
    CdnRotateOriginArgs, CdnRotatePathArgs, CdnRotateResult, CliRunner, FountainFrame, Pricing,
    ProgressEvent, ProvisionArgs, PublishFreshnessArgs, ReprovisionArgs,
};
use crate::keystore::{Keystore, KeystoreError};
use crate::operator_db::{CdnFrontRow, DbError, OperatorDb, SubkeyRow};
use crate::pin_lockout::{self, LockoutStatus};
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
    #[error("PIN lockout active until unix={0}")]
    Locked(i64),
    #[error("invalid PIN: must be 6-12 ASCII digits")]
    InvalidPin,
    #[error("cloud token must not be empty")]
    EmptyToken,
    #[error("pricing: {0}")]
    Pricing(String),
    #[error("cdn: {0}")]
    Cdn(String),
}

pub type Result<T> = std::result::Result<T, WizardError>;

/// `WizardCtx` carries the dependencies the command surface uses.
/// The Tauri shell builds one of these on app startup and passes
/// it into each `#[tauri::command]` shim via Tauri's State<>.
pub struct WizardCtx {
    pub db: Arc<OperatorDb>,
    pub keystore: Arc<Keystore>,
    pub staging_dir: PathBuf,
    pub cli: Arc<dyn CliRunner>,
    pub clock: Arc<dyn Fn() -> i64 + Send + Sync>,
}

/// `OperatorSummary` is the lightweight shape returned by
/// `list_operators` — enough to render a "your relays" list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorSummary {
    pub id: i64,
    pub status: String,
    pub provider: String,
    pub region: String,
    pub server_type: String,
    pub publisher_pub_hex: String,
    pub created_at_unix: i64,
}

/// PIN format: 6-12 ASCII digits.
fn validate_pin(pin: &str) -> Result<()> {
    if pin.len() < 6 || pin.len() > 12 || !pin.chars().all(|c| c.is_ascii_digit()) {
        return Err(WizardError::InvalidPin);
    }
    Ok(())
}

/// Validate a PIN before any operation that uses it. Returns
/// `Locked` if the rate limiter is engaged.
pub fn check_pin_allowed(ctx: &WizardCtx) -> Result<()> {
    let now = (ctx.clock)();
    match pin_lockout::check(&ctx.db, now)? {
        LockoutStatus::Allowed => Ok(()),
        LockoutStatus::Locked { unlock_at_unix } => Err(WizardError::Locked(unlock_at_unix)),
    }
}

/// Record a PIN attempt outcome. Wizard calls this from any path
/// that consults the PIN.
pub fn record_pin_attempt(ctx: &WizardCtx, success: bool) -> Result<()> {
    let now = (ctx.clock)();
    ctx.db.record_pin_attempt(now, success)?;
    Ok(())
}

/// Step 1a: store the cloud-provider token under the PIN.
/// Returns the new operator row id (status=pre-provision).
pub fn store_cloud_token(ctx: &WizardCtx, provider: &str, token: &str, pin: &str) -> Result<i64> {
    validate_pin(pin)?;
    if token.trim().is_empty() {
        return Err(WizardError::EmptyToken);
    }
    check_pin_allowed(ctx)?;
    let now = (ctx.clock)();

    // Insert a placeholder row so we have an id to bind to keystore aliases.
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
    ctx.keystore.seal(&token_alias, pin, token.as_bytes())?;
    // Update the row with the now-known token alias.
    ctx.db.update_record_json(id, &initial_json)?;
    let conn = &ctx.db; // borrow for the next call
    conn.update_token_alias(id, &token_alias)?;
    record_pin_attempt(ctx, true)?;
    Ok(id)
}

/// Step 1b: live read-only pricing lookup. Decrypts the cloud
/// token, hands it to the FRP-4a CLI, returns the Pricing JSON.
pub fn pricing_lookup(
    ctx: &WizardCtx,
    operator_id: i64,
    region: &str,
    server_type: &str,
    pin: &str,
) -> Result<Pricing> {
    validate_pin(pin)?;
    check_pin_allowed(ctx)?;
    let row = ctx.db.get(operator_id)?;
    let token_bytes = match ctx.keystore.open(&row.cloud_token_keystore_alias, pin) {
        Ok(b) => b,
        Err(KeystoreError::WrongPin) => {
            record_pin_attempt(ctx, false)?;
            return Err(WizardError::Keystore(KeystoreError::WrongPin));
        }
        Err(e) => return Err(WizardError::Keystore(e)),
    };
    record_pin_attempt(ctx, true)?;
    let token = Zeroizing::new(
        String::from_utf8(token_bytes)
            .map_err(|e| WizardError::Pricing(format!("token utf8: {e}")))?,
    );
    let pricing = ctx
        .cli
        .run_pricing(&row.cloud_provider, region, server_type, token.as_str())
        .map_err(|e| WizardError::Pricing(e.to_string()))?;
    Ok(pricing)
}

/// Step 2: persist the user's region/server-type/toolbox-profile +
/// enabled-families selection into the operator's record JSON.
pub fn select_profile(
    ctx: &WizardCtx,
    operator_id: i64,
    region: &str,
    server_type: &str,
    toolbox_profile: &str,
    enabled_families: Vec<String>,
) -> Result<()> {
    let row = ctx.db.get(operator_id)?;
    let mut rec: PreProvisionRecord =
        serde_json::from_str(&row.operator_record_json).map_err(StagingError::from)?;
    rec.region = region.to_string();
    rec.server_type = server_type.to_string();
    rec.toolbox_profile = toolbox_profile.to_string();
    rec.enabled_families = enabled_families;
    let body = serde_json::to_string(&rec).map_err(StagingError::from)?;
    ctx.db.update_record_json(operator_id, &body)?;
    Ok(())
}

/// Step 3a: generate a fresh publisher keypair, seal under PIN,
/// store keystore alias on the operator row, return the
/// fingerprint to render on screen 3.
pub fn publisher_keygen(ctx: &WizardCtx, operator_id: i64, pin: &str) -> Result<Fingerprint> {
    validate_pin(pin)?;
    check_pin_allowed(ctx)?;
    verify_operator_pin(ctx, operator_id, pin)?;
    let key = publisher_key::generate();
    seal_and_store_publisher(ctx, operator_id, pin, &key.priv_bytes, &key.pub_bytes)?;
    Ok(key.fingerprint)
}

/// Step 3b: import an existing publisher key. `priv_bytes_b64` is
/// base64 of the 32- or 64-byte raw form.
pub fn publisher_keyimport(
    ctx: &WizardCtx,
    operator_id: i64,
    pin: &str,
    priv_bytes_b64: &str,
) -> Result<Fingerprint> {
    validate_pin(pin)?;
    check_pin_allowed(ctx)?;
    verify_operator_pin(ctx, operator_id, pin)?;
    let raw = B64
        .decode(priv_bytes_b64.as_bytes())
        .map_err(|e| WizardError::Pricing(format!("base64: {e}")))?;
    let key = publisher_key::import(&raw)?;
    seal_and_store_publisher(ctx, operator_id, pin, &key.priv_bytes, &key.pub_bytes)?;
    Ok(key.fingerprint)
}

fn seal_and_store_publisher(
    ctx: &WizardCtx,
    operator_id: i64,
    pin: &str,
    priv_bytes: &[u8],
    pub_bytes: &[u8; 32],
) -> Result<()> {
    let alias = pub_alias(operator_id);
    ctx.keystore.seal(&alias, pin, priv_bytes)?;
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
///   1. Validate PIN, verify it against the operator row.
///   2. Open the root publisher.priv from the keystore (the PIN
///      gates this; on wrong PIN the lockout counter ticks).
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
    pin: &str,
    validity: &str,
    label: &str,
) -> Result<SubkeyRotateResult> {
    use std::io::Write as _;
    use std::process::Command;

    validate_pin(pin)?;
    check_pin_allowed(ctx)?;
    verify_operator_pin(ctx, operator_id, pin)?;

    // Open root priv. The keystore's open() returns Zeroizing<Vec<u8>>
    // so the bytes are wiped when this scope exits.
    let row = ctx.db.get(operator_id)?;
    let mut root_priv = ctx
        .keystore
        .open(&row.publisher_priv_keystore_alias, pin)
        .map_err(WizardError::Keystore)?;

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
/// Position B: the Cloudflare API token comes from the OS
/// keystore (alias `daal.cloudflare.<operator_id>.token`); it
/// is NOT in this struct.
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
/// point. It validates the input, decrypts the operator's
/// Cloudflare token from the keystore, hands everything to the
/// Go-side `publisher/deploy/cloudflare` provider, and on
/// success records the resulting front in V005's `cdn_fronts`.
///
/// Returns the freshly-inserted CDN front row id.
pub fn provision_cdn_front(
    ctx: &WizardCtx,
    input: &ProvisionCdnFrontInput,
    pin: &str,
) -> Result<i64> {
    validate_pin(pin)?;
    check_pin_allowed(ctx)?;
    if input.hostname.is_empty() || input.origin_ip.is_empty() || input.origin_path.is_empty() {
        return Err(WizardError::Cdn(
            "hostname, origin_ip, origin_path required".into(),
        ));
    }
    let op = ctx.db.get(input.operator_id)?;
    // Decrypt the Cloudflare token (alias =
    // daal.cloudflare.<operator_id>.token) and the cloud-provider
    // token. The Go CLI uses the latter to lock the origin firewall
    // to Cloudflare edge ranges before returning a validator-ready
    // `firewall_id`.
    let token_alias = format!("daal.cloudflare.{}.token", input.operator_id);
    let token = ctx
        .keystore
        .open(&token_alias, pin)
        .map_err(WizardError::Keystore)?;
    let token = Zeroizing::new(token);
    let token_str = std::str::from_utf8(token.as_slice())
        .map_err(|_| WizardError::Cdn("Cloudflare token must be UTF-8".into()))?;
    let cloud_token = ctx
        .keystore
        .open(&op.cloud_token_keystore_alias, pin)
        .map_err(WizardError::Keystore)?;
    let cloud_token = Zeroizing::new(cloud_token);
    let cloud_token_str = std::str::from_utf8(cloud_token.as_slice())
        .map_err(|_| WizardError::Cdn("Cloud provider token must be UTF-8".into()))?;
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
pub fn verify_cdn_posture(ctx: &WizardCtx, front_id: i64, pin: &str) -> Result<()> {
    validate_pin(pin)?;
    check_pin_allowed(ctx)?;
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
pub fn rotate_cdn_path(
    ctx: &WizardCtx,
    input: &RotateCdnPathInput,
    pin: &str,
) -> Result<CdnRotateResult> {
    validate_pin(pin)?;
    check_pin_allowed(ctx)?;
    let row = ctx.db.get_cdn_front(input.front_id)?;
    let token_alias = format!("daal.cloudflare.{}.token", row.operator_id);
    let token = ctx
        .keystore
        .open(&token_alias, pin)
        .map_err(WizardError::Keystore)?;
    let token = Zeroizing::new(token);
    let token_str = std::str::from_utf8(token.as_slice())
        .map_err(|_| WizardError::Cdn("Cloudflare token must be UTF-8".into()))?;
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
    pin: &str,
) -> Result<CdnRotateResult> {
    validate_pin(pin)?;
    check_pin_allowed(ctx)?;
    if input.new_hostname.is_empty() || input.origin_ipv4.is_empty() {
        return Err(WizardError::Cdn(
            "new_hostname and origin_ipv4 required".into(),
        ));
    }
    let row = ctx.db.get_cdn_front(input.front_id)?;
    let token_alias = format!("daal.cloudflare.{}.token", row.operator_id);
    let token = ctx
        .keystore
        .open(&token_alias, pin)
        .map_err(WizardError::Keystore)?;
    let token = Zeroizing::new(token);
    let token_str = std::str::from_utf8(token.as_slice())
        .map_err(|_| WizardError::Cdn("Cloudflare token must be UTF-8".into()))?;
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
pub fn rotate_cdn_origin(
    ctx: &WizardCtx,
    input: &RotateCdnOriginInput,
    pin: &str,
) -> Result<CdnRotateResult> {
    validate_pin(pin)?;
    check_pin_allowed(ctx)?;
    if input.new_origin_ipv4.is_empty() {
        return Err(WizardError::Cdn("new_origin_ipv4 required".into()));
    }
    let row = ctx.db.get_cdn_front(input.front_id)?;
    let token_alias = format!("daal.cloudflare.{}.token", row.operator_id);
    let token = ctx
        .keystore
        .open(&token_alias, pin)
        .map_err(WizardError::Keystore)?;
    let token = Zeroizing::new(token);
    let token_str = std::str::from_utf8(token.as_slice())
        .map_err(|_| WizardError::Cdn("Cloudflare token must be UTF-8".into()))?;
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

fn verify_operator_pin(ctx: &WizardCtx, operator_id: i64, pin: &str) -> Result<()> {
    let row = ctx.db.get(operator_id)?;
    let mut token_bytes = match ctx.keystore.open(&row.cloud_token_keystore_alias, pin) {
        Ok(b) => b,
        Err(KeystoreError::WrongPin) => {
            record_pin_attempt(ctx, false)?;
            return Err(WizardError::Keystore(KeystoreError::WrongPin));
        }
        Err(e) => return Err(WizardError::Keystore(e)),
    };
    token_bytes.zeroize();
    record_pin_attempt(ctx, true)?;
    Ok(())
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

/// List all operators (any status).
pub fn list_operators(ctx: &WizardCtx) -> Result<Vec<OperatorSummary>> {
    let rows = ctx.db.list()?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
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
        });
    }
    Ok(out)
}

/// Cancel-and-cleanup: erase keystore aliases, delete DB row,
/// remove staging file. Idempotent.
pub fn cancel_and_cleanup(ctx: &WizardCtx, operator_id: i64) -> Result<()> {
    let row = match ctx.db.get(operator_id) {
        Ok(r) => r,
        Err(DbError::NotFound(_)) => return Ok(()),
        Err(e) => return Err(WizardError::Db(e)),
    };
    if !row.publisher_priv_keystore_alias.is_empty() {
        ctx.keystore.forget(&row.publisher_priv_keystore_alias)?;
    }
    if !row.cloud_token_keystore_alias.is_empty() {
        ctx.keystore.forget(&row.cloud_token_keystore_alias)?;
    }
    let staging_path = ctx
        .staging_dir
        .join(format!("{operator_id}.pre-provision.json"));
    if staging_path.exists() {
        let _ = std::fs::remove_file(&staging_path);
    }
    match ctx.db.delete(operator_id) {
        Ok(()) | Err(DbError::NotFound(_)) => Ok(()),
        Err(e) => Err(WizardError::Db(e)),
    }
}

// ---- FRP-4b live operations ----------------------------------------

/// `provision_run`: call `daal-deploy provision` for the operator
/// with the wizard's stored cloud token + pubkey. On success, the
/// returned OperatorRecord JSON is written back into the operator
/// row and `status` flips to `provisioned`.
///
/// Progress events are forwarded via `on_progress` so the Tauri
/// shim can emit them to the wizard frontend.
pub fn provision_run(
    ctx: &WizardCtx,
    operator_id: i64,
    pin: &str,
    helper_ip: &str,
    on_progress: &mut dyn FnMut(ProgressEvent),
) -> Result<()> {
    validate_pin(pin)?;
    check_pin_allowed(ctx)?;
    let row = ctx.db.get(operator_id)?;
    let token_bytes = match ctx.keystore.open(&row.cloud_token_keystore_alias, pin) {
        Ok(b) => b,
        Err(KeystoreError::WrongPin) => {
            record_pin_attempt(ctx, false)?;
            return Err(WizardError::Keystore(KeystoreError::WrongPin));
        }
        Err(e) => return Err(WizardError::Keystore(e)),
    };
    record_pin_attempt(ctx, true)?;
    let token = Zeroizing::new(
        String::from_utf8(token_bytes).map_err(|e| WizardError::Pricing(format!("token: {e}")))?,
    );
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
                helper_ip,
                pubkey_file: &pubkey_path,
                token: token.as_str(),
                dry_run: false,
            },
            on_progress,
        )
        .map_err(|e| WizardError::Pricing(e.to_string()))?;

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
/// publisher key is decrypted from the keystore and piped via stdin.
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
    pin: &str,
    phase: &str,
    output_dir: &std::path::Path,
    publisher_name: &str,
    on_progress: &mut dyn FnMut(ProgressEvent),
) -> Result<BindResult> {
    validate_pin(pin)?;
    check_pin_allowed(ctx)?;
    let row = ctx.db.get(operator_id)?;

    let active_subkey = ctx.db.active_subkey(operator_id)?;
    let subkey_cert_path = active_subkey
        .as_ref()
        .map(|row| PathBuf::from(row.subkey_cert_path.clone()));

    let mut priv_buf = if let Some(subkey) = active_subkey {
        // The sub-key path is still PIN-gated at the wizard command
        // boundary. We verify the PIN against the operator before
        // reading the sub-key artefact, then pass the certified
        // sub-key to daal-deploy.
        verify_operator_pin(ctx, operator_id, pin)?;
        let bytes = std::fs::read(&subkey.subkey_priv_path).map_err(|e| {
            WizardError::Pricing(format!(
                "read active sub-key priv {}: {e}",
                subkey.subkey_priv_path
            ))
        })?;
        Zeroizing::new(bytes)
    } else {
        let priv_bytes = match ctx.keystore.open(&row.publisher_priv_keystore_alias, pin) {
            Ok(b) => b,
            Err(KeystoreError::WrongPin) => {
                record_pin_attempt(ctx, false)?;
                return Err(WizardError::Keystore(KeystoreError::WrongPin));
            }
            Err(e) => return Err(WizardError::Keystore(e)),
        };
        record_pin_attempt(ctx, true)?;
        Zeroizing::new(priv_bytes)
    };

    // Stage the OperatorRecord JSON for the subprocess.
    let record_path = ctx.staging_dir.join(format!("{operator_id}.record.json"));
    std::fs::create_dir_all(&ctx.staging_dir)
        .map_err(|e| WizardError::Pricing(format!("mkdir staging: {e}")))?;
    std::fs::write(&record_path, row.operator_record_json.as_bytes())
        .map_err(|e| WizardError::Pricing(format!("write record: {e}")))?;
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
    pin: &str,
    input: RotateExecuteInput,
    on_progress: &mut dyn FnMut(ProgressEvent),
) -> Result<RotateExecuteOutput> {
    validate_pin(pin)?;
    check_pin_allowed(ctx)?;
    let row = ctx.db.get(operator_id)?;
    let token_bytes = match ctx.keystore.open(&row.cloud_token_keystore_alias, pin) {
        Ok(b) => b,
        Err(KeystoreError::WrongPin) => {
            record_pin_attempt(ctx, false)?;
            return Err(WizardError::Keystore(KeystoreError::WrongPin));
        }
        Err(e) => return Err(WizardError::Keystore(e)),
    };
    record_pin_attempt(ctx, true)?;
    let token = Zeroizing::new(
        String::from_utf8(token_bytes).map_err(|e| WizardError::Pricing(format!("token: {e}")))?,
    );

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
            let helper_ip = require_rotate_param(input.helper_ip.as_ref(), "helper IP")?;
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
                pin,
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
                pin,
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
                pin,
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
    // sign_relaypack. The PIN unlocks the publisher private key.
    let bind = sign_relaypack(
        ctx,
        operator_id,
        pin,
        "V1.5",
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
        publish_freshness_after_rotate(ctx, operator_id, pin, &bind, &signed_url, on_progress)?;
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
    pin: &str,
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
        verify_operator_pin(ctx, operator_id, pin)?;
        subkey_cert_path = Some(PathBuf::from(subkey.subkey_cert_path.clone()));
        let bytes = std::fs::read(&subkey.subkey_priv_path).map_err(|e| {
            WizardError::Pricing(format!(
                "read sub-key priv {}: {e}",
                subkey.subkey_priv_path
            ))
        })?;
        Zeroizing::new(bytes)
    } else {
        let priv_bytes = match ctx.keystore.open(&row.publisher_priv_keystore_alias, pin) {
            Ok(b) => b,
            Err(KeystoreError::WrongPin) => {
                record_pin_attempt(ctx, false)?;
                return Err(WizardError::Keystore(KeystoreError::WrongPin));
            }
            Err(e) => return Err(WizardError::Keystore(e)),
        };
        record_pin_attempt(ctx, true)?;
        Zeroizing::new(priv_bytes)
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

    fn ctx(now: i64) -> (WizardCtx, tempfile::TempDir) {
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
        let cli = Arc::new(MockRunner::new(pricing));
        let clock_tick = AtomicI64::new(now);
        let clock_arc: Arc<dyn Fn() -> i64 + Send + Sync> = Arc::new(move || {
            // Deterministic clock: ticks 1 s per call.
            clock_tick.fetch_add(1, Ordering::Relaxed)
        });
        (
            WizardCtx {
                db,
                keystore: ks,
                staging_dir,
                cli,
                clock: clock_arc,
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
        (
            WizardCtx {
                db,
                keystore: ks,
                staging_dir,
                cli: cli.clone(),
                clock: clock_arc,
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

    #[test]
    fn full_happy_path_screens_0_to_finalize() {
        let (ctx, _dir) = ctx(1_700_000_000);
        let id = store_cloud_token(&ctx, "hetzner", "tok-abc", "123456").unwrap();
        select_profile(
            &ctx,
            id,
            "fsn1",
            "cx22",
            "iran-default",
            vec!["vless-reality".into(), "hysteria2".into()],
        )
        .unwrap();
        let pricing = pricing_lookup(&ctx, id, "fsn1", "cx22", "123456").unwrap();
        assert_eq!(pricing.hourly_eur, 0.005);
        let fp = publisher_keygen(&ctx, id, "123456").unwrap();
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
    fn store_token_rejects_short_pin() {
        let (ctx, _dir) = ctx(1_700_000_000);
        match store_cloud_token(&ctx, "hetzner", "tok", "12") {
            Err(WizardError::InvalidPin) => (),
            other => panic!("wanted InvalidPin, got {other:?}"),
        }
    }

    #[test]
    fn store_token_rejects_four_digit_pin() {
        let (ctx, _dir) = ctx(1_700_000_000);
        match store_cloud_token(&ctx, "hetzner", "tok", "1234") {
            Err(WizardError::InvalidPin) => (),
            other => panic!("wanted InvalidPin, got {other:?}"),
        }
    }

    #[test]
    fn store_token_rejects_empty_token() {
        let (ctx, _dir) = ctx(1_700_000_000);
        match store_cloud_token(&ctx, "hetzner", "   ", "123456") {
            Err(WizardError::EmptyToken) => (),
            other => panic!("wanted EmptyToken, got {other:?}"),
        }
    }

    #[test]
    fn cancel_and_cleanup_is_idempotent_and_deletes() {
        let (ctx, _dir) = ctx(1_700_000_000);
        let id = store_cloud_token(&ctx, "hetzner", "tok", "123456").unwrap();
        publisher_keygen(&ctx, id, "123456").unwrap();
        finalize_pre_provision(&ctx, id).unwrap();
        cancel_and_cleanup(&ctx, id).unwrap();
        // second call -> Ok (idempotent on missing).
        cancel_and_cleanup(&ctx, id).unwrap();
        assert!(list_operators(&ctx).unwrap().is_empty());
    }

    #[test]
    fn wrong_pin_records_failure() {
        let (ctx, _dir) = ctx(1_700_000_000);
        let id = store_cloud_token(&ctx, "hetzner", "tok", "123456").unwrap();
        let err = pricing_lookup(&ctx, id, "fsn1", "cx22", "999999").unwrap_err();
        match err {
            WizardError::Keystore(KeystoreError::WrongPin) => (),
            e => panic!("wanted WrongPin, got {e:?}"),
        }
    }

    #[test]
    fn publisher_keygen_rejects_wrong_operator_pin() {
        let (ctx, _dir) = ctx(1_700_000_000);
        let id = store_cloud_token(&ctx, "hetzner", "tok", "123456").unwrap();
        let err = publisher_keygen(&ctx, id, "999999").unwrap_err();
        match err {
            WizardError::Keystore(KeystoreError::WrongPin) => (),
            e => panic!("wanted WrongPin, got {e:?}"),
        }
        let row = ctx.db.get(id).unwrap();
        assert_eq!(row.publisher_pub_hex, "");
        assert_eq!(row.publisher_priv_keystore_alias, "");
        assert_eq!(ctx.db.count_recent_failed_pins(1_699_999_900).unwrap(), 1);
    }

    #[test]
    fn publisher_keyimport_rejects_wrong_operator_pin() {
        let (ctx, _dir) = ctx(1_700_000_000);
        let id = store_cloud_token(&ctx, "hetzner", "tok", "123456").unwrap();
        let seed = vec![0u8; 32];
        let b64 = B64.encode(&seed);
        let err = publisher_keyimport(&ctx, id, "999999", &b64).unwrap_err();
        match err {
            WizardError::Keystore(KeystoreError::WrongPin) => (),
            e => panic!("wanted WrongPin, got {e:?}"),
        }
        let row = ctx.db.get(id).unwrap();
        assert_eq!(row.publisher_pub_hex, "");
        assert_eq!(row.publisher_priv_keystore_alias, "");
    }

    #[test]
    fn import_publisher_key_round_trip() {
        let (ctx, _dir) = ctx(1_700_000_000);
        let id = store_cloud_token(&ctx, "hetzner", "tok", "123456").unwrap();
        // Seed = 32 zero bytes (allowed by ed25519-dalek)
        let seed = vec![0u8; 32];
        let b64 = B64.encode(&seed);
        let fp = publisher_keyimport(&ctx, id, "123456", &b64).unwrap();
        assert_eq!(fp.en_words.split(' ').count(), 4);
        // Re-import yields identical fingerprint.
        let fp2 = publisher_keyimport(&ctx, id, "123456", &b64).unwrap();
        assert_eq!(fp, fp2);
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
        (
            WizardCtx {
                db,
                keystore: ks,
                staging_dir,
                cli,
                clock: clock_arc,
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
        let id = store_cloud_token(&ctx, "hetzner", "tok", "123456").unwrap();
        select_profile(
            &ctx,
            id,
            "fsn1",
            "cx22",
            "iran-default",
            vec!["vless-reality".into()],
        )
        .unwrap();
        publisher_keygen(&ctx, id, "123456").unwrap();

        let mut events: Vec<ProgressEvent> = vec![];
        let mut on_prog = |ev: ProgressEvent| events.push(ev);
        provision_run(&ctx, id, "123456", "1.2.3.4", &mut on_prog).unwrap();
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
    fn provision_run_rejects_wrong_pin() {
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
        let id = store_cloud_token(&ctx, "hetzner", "tok", "123456").unwrap();
        publisher_keygen(&ctx, id, "123456").unwrap();
        let mut on_prog = |_ev: ProgressEvent| {};
        let err = provision_run(&ctx, id, "999999", "1.2.3.4", &mut on_prog).unwrap_err();
        match err {
            WizardError::Keystore(KeystoreError::WrongPin) => (),
            e => panic!("want WrongPin, got {e:?}"),
        }
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
        let id = store_cloud_token(&ctx, "hetzner", "tok", "123456").unwrap();
        select_profile(
            &ctx,
            id,
            "fsn1",
            "cx22",
            "iran-default",
            vec!["vless-reality".into()],
        )
        .unwrap();
        publisher_keygen(&ctx, id, "123456").unwrap();

        let mut on_prog = |_ev: ProgressEvent| {};
        provision_run(&ctx, id, "123456", "1.2.3.4", &mut on_prog).unwrap();

        let out_dir = dir.path().join("out");
        std::fs::create_dir_all(&out_dir).unwrap();
        let res = sign_relaypack(
            &ctx,
            id,
            "123456",
            "V1.5",
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
        };
        let id = store_cloud_token(&ctx_, "hetzner", "tok", "123456").unwrap();
        select_profile(
            &ctx_,
            id,
            "fsn1",
            "cx22",
            "iran-default",
            vec!["vless-reality".into()],
        )
        .unwrap();
        publisher_keygen(&ctx_, id, "123456").unwrap();
        let mut on_prog = |_e: ProgressEvent| {};
        provision_run(&ctx_, id, "123456", "1.2.3.4", &mut on_prog).unwrap();
        let out_dir = dir.path().join("out");
        std::fs::create_dir_all(&out_dir).unwrap();
        let _ = sign_relaypack(&ctx_, id, "123456", "V1.5", &out_dir, "", &mut on_prog).unwrap();

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
        let id = store_cloud_token(&ctx, "hetzner", "tok", "123456").unwrap();
        select_profile(
            &ctx,
            id,
            "fsn1",
            "cx22",
            "iran-default",
            vec!["vless-reality".into()],
        )
        .unwrap();
        publisher_keygen(&ctx, id, "123456").unwrap();
        let mut on_prog = |_e: ProgressEvent| {};
        provision_run(&ctx, id, "123456", "1.2.3.4", &mut on_prog).unwrap();

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
        let _ = sign_relaypack(&ctx, id, "123456", "V1.5", &out_dir, "", &mut on_prog).unwrap();

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
        let id = store_cloud_token(&ctx, "hetzner", "tok", "123456").unwrap();
        select_profile(
            &ctx,
            id,
            "fsn1",
            "cx22",
            "iran-default",
            vec!["vless-reality".into()],
        )
        .unwrap();
        publisher_keygen(&ctx, id, "123456").unwrap();
        let mut on_prog = |_e: ProgressEvent| {};
        provision_run(&ctx, id, "123456", "1.2.3.4", &mut on_prog).unwrap();
        let out_dir = dir.path().join("out");
        std::fs::create_dir_all(&out_dir).unwrap();
        let _ = sign_relaypack(&ctx, id, "123456", "V1.5", &out_dir, "", &mut on_prog).unwrap();

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
        let id = store_cloud_token(ctx, "hetzner", "tok-abc", "123456").unwrap();
        select_profile(
            ctx,
            id,
            "fsn1",
            "cx22",
            "iran-default",
            vec!["vless-reality".into()],
        )
        .unwrap();
        let _ = publisher_keygen(ctx, id, "123456").unwrap();
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
        };
        let exp = r#"{"pick":{"exposure_mode":"direct_vps"},"failures":[],"phase":"V1.5"}"#;
        let r = rotate_recommend(&ctx2, id, RotateRecommendInput::Explanation(exp.into())).unwrap();
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
            "123456",
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
            "123456",
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
            "123456",
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
        let op_id = store_cloud_token(&ctx, "hetzner", "tok", "123456").unwrap();
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
        let op_id = store_cloud_token(&ctx, "hetzner", "tok", "123456").unwrap();
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
        let op_id = store_cloud_token(&ctx, "hetzner", "tok", "123456").unwrap();
        // Stash the CF token under the alias the command reads.
        ctx.keystore
            .seal(
                &format!("daal.cloudflare.{}.token", op_id),
                "123456",
                b"cf-token",
            )
            .unwrap();
        let input = ProvisionCdnFrontInput {
            operator_id: op_id,
            hostname: "front.example.com".into(),
            origin_ip: "5.75.0.1".into(),
            origin_ipv6: String::new(),
            origin_path: "/ws".into(),
            public_path: String::new(),
        };
        let front_id = provision_cdn_front(&ctx, &input, "123456").unwrap();
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
        let op_id = store_cloud_token(&ctx, "hetzner", "tok", "123456").unwrap();
        let input = ProvisionCdnFrontInput {
            operator_id: op_id,
            hostname: String::new(),
            origin_ip: "5.75.0.1".into(),
            origin_ipv6: String::new(),
            origin_path: "/ws".into(),
            public_path: String::new(),
        };
        let err = provision_cdn_front(&ctx, &input, "123456").unwrap_err();
        assert!(matches!(err, WizardError::Cdn(_)));
    }

    #[test]
    fn verify_cdn_posture_updates_timestamp() {
        let (ctx, _dir) = ctx(1_700_000_000);
        let op_id = store_cloud_token(&ctx, "hetzner", "tok", "123456").unwrap();
        let mut row = cdn_row_fixture(op_id, "front.example.com");
        row.edge_ranges_fetched_unix = 1;
        row.last_verified_unix = 1;
        let front_id = record_cdn_front_attestation(&ctx, &row).unwrap();
        verify_cdn_posture(&ctx, front_id, "123456").unwrap();
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
        let op_id = store_cloud_token(&ctx, "hetzner", "tok", "123456").unwrap();
        ctx.keystore
            .seal(
                &format!("daal.cloudflare.{}.token", op_id),
                "123456",
                b"cf-token",
            )
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
            "123456",
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
        let op_id = store_cloud_token(&ctx, "hetzner", "tok", "123456").unwrap();
        ctx.keystore
            .seal(
                &format!("daal.cloudflare.{}.token", op_id),
                "123456",
                b"cf-token",
            )
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
            "123456",
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
        let op_id = store_cloud_token(&ctx, "hetzner", "tok", "123456").unwrap();
        ctx.keystore
            .seal(
                &format!("daal.cloudflare.{}.token", op_id),
                "123456",
                b"cf-token",
            )
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
            "123456",
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
        let op_id = store_cloud_token(&ctx, "hetzner", "tok", "123456").unwrap();
        ctx.keystore
            .seal(
                &format!("daal.cloudflare.{}.token", op_id),
                "123456",
                b"cf-token",
            )
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
            "123456",
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
        ctx.keystore
            .seal(
                &format!("daal.cloudflare.{}.token", id),
                "123456",
                b"cf-token",
            )
            .unwrap();
        let row = cdn_row_fixture(id, "front.example.com");
        let front_id = record_cdn_front_attestation(&ctx, &row).unwrap();

        let out = rotate_execute(
            &ctx,
            id,
            "123456",
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
        ctx.keystore
            .seal(
                &format!("daal.cloudflare.{}.token", id),
                "123456",
                b"cf-token",
            )
            .unwrap();
        let row = cdn_row_fixture(id, "front.example.com");
        let front_id = record_cdn_front_attestation(&ctx, &row).unwrap();

        let out = rotate_execute(
            &ctx,
            id,
            "123456",
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
        ctx.keystore
            .seal(
                &format!("daal.cloudflare.{}.token", id),
                "123456",
                b"cf-token",
            )
            .unwrap();
        let row = cdn_row_fixture(id, "front.example.com");
        let front_id = record_cdn_front_attestation(&ctx, &row).unwrap();
        let before = list_cdn_fronts(&ctx, id).unwrap()[0].clone();

        let out = rotate_execute(
            &ctx,
            id,
            "123456",
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
            "123456",
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
