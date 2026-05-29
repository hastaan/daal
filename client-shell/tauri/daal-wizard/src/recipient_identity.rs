//! FRP-14 Layer 3c — recipient-side X25519 identity.
//!
//! See `specs/recipient-identity-v1.md` for the locked design.
//!
//! Summary:
//!
//! * One row, ever (`recipient_identity.id = 1`, CHECK-pinned).
//! * Private key wrapped by Device Custody v1 (alias
//!   `recipient_priv_x25519`) — **no per-operation PIN**. On
//!   platforms with a hardware/OS keystore the wrap key lives
//!   there; on bare platforms the user sets a session passphrase
//!   once. See `device_custody.rs`.
//! * Public key + derived `daal1…` address + fingerprint cached
//!   in the DB; they are not secret.
//! * Lazy create: the row is materialised only when the user
//!   enters the “My Daal address” screen and taps Create. We do
//!   not silently mint keys on first launch.
//!
//! Out of scope here: rotation/history (Device Custody B4),
//! multi-device sync, encrypting the cached pub at rest.

use rand::rngs::OsRng;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::commands::{WizardCtx, WizardError};
use crate::device_custody::CustodyError;
use crate::operator_db::DbError;

/// Keystore alias under which the recipient private X25519 key
/// is sealed. Pinned by `recipient-identity-v1.md` §4.1.
pub const RECIPIENT_PRIV_ALIAS: &str = "recipient_priv_x25519";

/// Summary returned to the UI. Never contains the priv-key.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RecipientIdentitySummary {
    pub address: String,
    pub fingerprint_hex: String,
    pub created_at_unix: i64,
}

#[derive(Debug, Error)]
pub enum RecipientIdentityError {
    #[error("identity not yet created")]
    NotYetCreated,
    #[error("device custody is locked; unlock with your session passphrase first")]
    Locked,
    #[error(transparent)]
    Db(#[from] DbError),
    #[error(transparent)]
    Custody(#[from] CustodyError),
}

/// Map a custody error, promoting the locked state to our own
/// `Locked` variant so the UI can prompt for a session passphrase.
fn map_custody(e: CustodyError) -> RecipientIdentityError {
    match e {
        CustodyError::Locked => RecipientIdentityError::Locked,
        other => RecipientIdentityError::Custody(other),
    }
}

impl From<RecipientIdentityError> for WizardError {
    fn from(e: RecipientIdentityError) -> Self {
        match e {
            RecipientIdentityError::NotYetCreated => {
                WizardError::Validation("recipient identity not yet created".into())
            }
            RecipientIdentityError::Locked => {
                WizardError::CustodyLocked("device custody is locked".into())
            }
            RecipientIdentityError::Db(d) => WizardError::Db(d),
            RecipientIdentityError::Custody(c) => WizardError::CustodyLocked(c.to_string()),
        }
    }
}

/// Read the cached summary without touching the keystore.
/// Returns `Ok(None)` if no identity row exists yet — the UI uses
/// this to decide whether to render the “Create my Daal address”
/// CTA or the address card.
pub fn get_summary(
    ctx: &WizardCtx,
) -> Result<Option<RecipientIdentitySummary>, RecipientIdentityError> {
    let row = ctx.db.get_recipient_identity()?;
    Ok(row.map(|r| RecipientIdentitySummary {
        address: r.address_str,
        fingerprint_hex: r.fingerprint_hex,
        created_at_unix: r.created_at_unix,
    }))
}

/// First call: generate a fresh X25519 keypair via OS RNG, wrap
/// the private key via Device Custody, persist (pub, address,
/// fingerprint, timestamp) to the DB, and return the summary.
/// Subsequent calls: confirm the custody entry opens, then return
/// the cached summary.
///
/// No PIN. On a session-passphrase device the caller must have
/// called `custody.unlock(Some(passphrase))` first; otherwise this
/// returns `Locked`.
pub fn get_or_create(
    ctx: &WizardCtx,
) -> Result<RecipientIdentitySummary, RecipientIdentityError> {
    // Fast path: row already present. Confirm the custody entry is
    // openable so we surface a locked/missing-key state instead of
    // lying about availability.
    if let Some(row) = ctx.db.get_recipient_identity()? {
        match ctx.custody.get(&row.keystore_alias) {
            Ok(bytes) => {
                let _z = Zeroizing::new(bytes);
            }
            Err(e) => return Err(map_custody(e)),
        }
        return Ok(RecipientIdentitySummary {
            address: row.address_str,
            fingerprint_hex: row.fingerprint_hex,
            created_at_unix: row.created_at_unix,
        });
    }

    // Fresh-create path. Generate keypair, wrap priv, insert row.
    let secret = StaticSecret::random_from_rng(&mut OsRng);
    let public = PublicKey::from(&secret);
    let pub_bytes: [u8; 32] = public.to_bytes();
    let priv_bytes: [u8; 32] = secret.to_bytes();
    let priv_z = Zeroizing::new(priv_bytes);

    let address = daal_recipient_addr::encode(&pub_bytes);
    let fingerprint_hex = daal_recipient_addr::fingerprint(&pub_bytes);
    let created_at_unix = (ctx.clock)();

    // Wrap first, persist second. If the wrap fails (e.g. custody
    // locked), we never wrote the row, so a later call cleanly
    // retries once the user unlocks.
    ctx.custody
        .put(RECIPIENT_PRIV_ALIAS, priv_z.as_slice())
        .map_err(map_custody)?;

    let inserted =
        ctx.db
            .upsert_recipient_identity(&pub_bytes, &address, &fingerprint_hex, created_at_unix)?;

    if !inserted {
        // Lost a race with another thread that created the row
        // between our `get_recipient_identity` check and the
        // upsert. Return whatever the canonical row says — the
        // priv we just wrote is now an unreachable orphan in
        // custody, but the alias is shared so re-wrapping on top
        // of it just overwrites; benign.
        let row = ctx
            .db
            .get_recipient_identity()?
            .ok_or(RecipientIdentityError::NotYetCreated)?;
        return Ok(RecipientIdentitySummary {
            address: row.address_str,
            fingerprint_hex: row.fingerprint_hex,
            created_at_unix: row.created_at_unix,
        });
    }

    // Audit event — fresh identity created.
    let detail = serde_json::json!({"address": &address});
    let _ = ctx.db.insert_custody_event(
        created_at_unix,
        "created",
        ctx.custody.level().as_str(),
        &detail.to_string(),
    );

    Ok(RecipientIdentitySummary {
        address,
        fingerprint_hex,
        created_at_unix,
    })
}

/// Open the priv-key. Used by `.sbpx` import (Layer 3d). Caller
/// is responsible for zeroizing the returned buffer; we hand back
/// a plain `[u8; 32]` rather than a `StaticSecret` so the call
/// site can shape the type to match `envelope.Decrypt`'s API.
///
/// No PIN — pulls the priv through Device Custody. Returns `Locked`
/// when a session-passphrase device hasn't been unlocked yet.
pub fn open_priv(ctx: &WizardCtx) -> Result<[u8; 32], RecipientIdentityError> {
    let row = ctx
        .db
        .get_recipient_identity()?
        .ok_or(RecipientIdentityError::NotYetCreated)?;

    let bytes = ctx.custody.get(&row.keystore_alias).map_err(map_custody)?;
    if bytes.len() != 32 {
        return Err(RecipientIdentityError::Custody(CustodyError::Backend(
            format!("priv key is {} bytes, want 32", bytes.len()),
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    // bytes drops here; out is the caller's to zeroize.
    Ok(out)
}

/// Device Custody B4: open every priv-key the user has ever held,
/// newest first (current identity, then history.v_n descending).
/// Used by `.sbpx` import to grace-decrypt envelopes sealed to a
/// pre-rotation address — `users-unpack-sbpx` is invoked once per
/// candidate priv, stopping at the first that decrypts.
///
/// Each entry is `(alias, priv_bytes)`. Caller MUST zeroize each
/// priv before dropping. Skips history aliases whose keystore
/// entry was lost (best-effort), but surfaces a `Locked` error
/// from the *current* alias since that means the session
/// passphrase hasn't been entered yet.
pub fn open_all_privs(
    ctx: &WizardCtx,
) -> Result<Vec<(String, [u8; 32])>, RecipientIdentityError> {
    let cur = ctx
        .db
        .get_recipient_identity()?
        .ok_or(RecipientIdentityError::NotYetCreated)?;
    let history = ctx.db.list_recipient_identity_history()?;

    let mut out: Vec<(String, [u8; 32])> = Vec::new();
    // Current priv: any custody error here is fatal (Locked or
    // backend missing). NotFound on the current alias is treated
    // as Locked too — on session-passphrase devices the row may
    // exist but the AEAD blob is unreadable until unlock; on
    // hardware/OS-keystore devices the row+blob are co-created.
    let bytes = match ctx.custody.get(&cur.keystore_alias) {
        Ok(b) => b,
        Err(CustodyError::Locked) => return Err(RecipientIdentityError::Locked),
        Err(CustodyError::NotFound(_))
            if ctx.custody.level()
                == crate::device_custody::CustodyLevel::SessionPassphrase
                && !ctx.custody.is_unlocked() =>
        {
            return Err(RecipientIdentityError::Locked);
        }
        Err(other) => return Err(map_custody(other)),
    };
    if bytes.len() == 32 {
        let mut k = [0u8; 32];
        k.copy_from_slice(&bytes);
        out.push((cur.keystore_alias.clone(), k));
    }
    // history is already DESC by retired_at_unix.
    for h in history {
        match ctx.custody.get(&h.keystore_alias) {
            Ok(b) if b.len() == 32 => {
                let mut k = [0u8; 32];
                k.copy_from_slice(&b);
                out.push((h.keystore_alias.clone(), k));
            }
            _ => continue,
        }
    }
    Ok(out)
}

/// Device Custody B4: rotate the singleton identity.
///
/// Steps (all-or-nothing as far as user-visible state):
///   1. Pull the OLD priv from custody under
///      `recipient_priv_x25519`.
///   2. Re-wrap that OLD priv under a versioned alias
///      `recipient_priv_x25519.v<n>` (the version is the index
///      it will receive in `recipient_identity_history`).
///   3. Generate a fresh X25519 keypair via OS RNG.
///   4. Wrap the NEW priv under `recipient_priv_x25519`,
///      overwriting the old payload (custody.put is overwrite-
///      always).
///   5. Run `OperatorDb::rotate_recipient_identity` to demote the
///      current `recipient_identity` row into history and write
///      the new row in one transaction.
///   6. Append a `kind="rotated"` event to `custody_events`.
///
/// Returns the new summary.
pub fn rotate(ctx: &WizardCtx) -> Result<RecipientIdentitySummary, RecipientIdentityError> {
    use rand::rngs::OsRng;
    use zeroize::Zeroize;

    // 1. Pull the current priv (failures cleanly bail before any
    //    DB mutation).
    let current_row = ctx
        .db
        .get_recipient_identity()?
        .ok_or(RecipientIdentityError::NotYetCreated)?;
    let mut old_priv = ctx
        .custody
        .get(&current_row.keystore_alias)
        .map_err(map_custody)?;
    if old_priv.len() != 32 {
        old_priv.zeroize();
        return Err(RecipientIdentityError::Custody(CustodyError::Backend(
            format!("old priv key is {} bytes, want 32", old_priv.len()),
        )));
    }

    // 2. Compute next version + the retire alias. Use the same
    //    formula as `rotate_recipient_identity`'s transaction so
    //    they agree.
    let history = ctx.db.list_recipient_identity_history()?;
    let next_version = history.iter().map(|h| h.version).max().unwrap_or(0) + 1;
    let retire_alias = format!("{}.v{}", RECIPIENT_PRIV_ALIAS, next_version);
    ctx.custody
        .put(&retire_alias, &old_priv)
        .map_err(|e| {
            // Best-effort: if the put failed, the original priv is
            // still under its original alias — nothing to undo.
            old_priv.zeroize();
            map_custody(e)
        })?;
    old_priv.zeroize();

    // 3. Mint fresh keypair.
    let secret = StaticSecret::random_from_rng(&mut OsRng);
    let public = PublicKey::from(&secret);
    let pub_bytes: [u8; 32] = public.to_bytes();
    let priv_bytes: [u8; 32] = secret.to_bytes();
    let priv_z = Zeroizing::new(priv_bytes);
    let address = daal_recipient_addr::encode(&pub_bytes);
    let fingerprint_hex = daal_recipient_addr::fingerprint(&pub_bytes);
    let now = (ctx.clock)();

    // 4. Overwrite the canonical alias with the new priv.
    ctx.custody
        .put(RECIPIENT_PRIV_ALIAS, priv_z.as_slice())
        .map_err(|e| {
            // Try to wind the partial change back: forget the
            // versioned alias we just created (best-effort).
            let _ = ctx.custody.forget(&retire_alias);
            map_custody(e)
        })?;

    // 5. Atomic DB swap (demote current → history, write new).
    let version = ctx.db.rotate_recipient_identity(
        &retire_alias,
        &pub_bytes,
        &address,
        &fingerprint_hex,
        now,
        now,
    )?;
    // Sanity: the version the DB picked must match what we
    // assumed. If it disagrees (a concurrent rotation), we'd have
    // a misaligned alias — extremely unlikely on a single-user
    // device, but rename if needed.
    if version != next_version {
        let canonical_alias = format!("{}.v{}", RECIPIENT_PRIV_ALIAS, version);
        if canonical_alias != retire_alias {
            // Best-effort: copy under the correct alias, drop the
            // misaligned one. We pull the bytes back through
            // custody rather than holding them in memory across
            // the DB tx to keep the lock-free codepath simple.
            if let Ok(bytes) = ctx.custody.get(&retire_alias) {
                let _ = ctx.custody.put(&canonical_alias, &bytes);
                let _ = ctx.custody.forget(&retire_alias);
            }
        }
    }

    // 6. Audit event.
    let detail = serde_json::json!({
        "version": version,
        "new_address": address,
        "retire_alias": retire_alias,
    });
    let _ = ctx.db.insert_custody_event(
        now,
        "rotated",
        ctx.custody.level().as_str(),
        &detail.to_string(),
    );

    Ok(RecipientIdentitySummary {
        address,
        fingerprint_hex,
        created_at_unix: now,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli_bridge::{MockRunner, Pricing};
    use crate::commands::WizardCtx;
    use crate::device_custody::FileCustody;
    use crate::keystore::Keystore;
    use crate::operator_db::OperatorDb;
    use std::sync::Arc;

    fn fixed_clock(t: i64) -> Arc<dyn Fn() -> i64 + Send + Sync> {
        Arc::new(move || t)
    }

    fn make_ctx() -> WizardCtx {
        let db = OperatorDb::open_in_memory().expect("open_in_memory");
        let tmp = tempfile::tempdir().expect("tempdir");
        // Use the memory backend so tests don't hit the OS keychain.
        let ks = Keystore::new_in_memory(tmp.path());
        let custody = FileCustody::static_test(tmp.path()).expect("custody");
        let staging_dir = tmp.path().to_path_buf();
        // Tempdir's lifetime must outlive the ctx; leak it for the
        // test (cheap, runs once per test).
        let _ = Box::leak(Box::new(tmp));
        WizardCtx {
            db: Arc::new(db),
            keystore: Arc::new(ks),
            staging_dir,
            cli: Arc::new(MockRunner::new(Pricing {
                provider: "hetzner".into(),
                region: "fsn1".into(),
                server_type: "cx22".into(),
                hourly_eur: 0.0,
                monthly_eur: 0.0,
                included_traffic_tb_per_month: None,
                overage_eur_per_gb: None,
            })),
            clock: fixed_clock(1_700_000_000),
            custody: Arc::new(custody),
        }
    }

    #[test]
    fn get_summary_empty() {
        let ctx = make_ctx();
        assert!(get_summary(&ctx).unwrap().is_none());
    }

    #[test]
    fn get_or_create_first_call_creates_row() {
        let ctx = make_ctx();
        let s = get_or_create(&ctx).expect("first create");
        assert!(s.address.starts_with("daal1"), "addr={}", s.address);
        // `daal_recipient_addr::fingerprint` returns hex(SHA-256(pub)),
        // i.e. 64 lowercase hex chars (32 bytes). The truncation
        // policy is the caller's; we cache the full thing.
        assert_eq!(s.fingerprint_hex.len(), 64);
        assert_eq!(s.created_at_unix, 1_700_000_000);

        let s2 = get_summary(&ctx).unwrap().expect("row now exists");
        assert_eq!(s2, s);
    }

    #[test]
    fn get_or_create_is_idempotent() {
        let ctx = make_ctx();
        let s1 = get_or_create(&ctx).unwrap();
        let s2 = get_or_create(&ctx).unwrap();
        assert_eq!(s1, s2, "second call must return the same summary");
    }

    #[test]
    fn get_or_create_locked_session_custody_errors() {
        // A session-passphrase device that hasn't been unlocked
        // cannot wrap a fresh priv → Locked.
        let db = OperatorDb::open_in_memory().expect("open_in_memory");
        let tmp = tempfile::tempdir().expect("tempdir");
        let ks = Keystore::new_in_memory(tmp.path());
        let custody = FileCustody::session_passphrase(tmp.path()).expect("custody");
        let staging_dir = tmp.path().to_path_buf();
        let _ = Box::leak(Box::new(tmp));
        let ctx = WizardCtx {
            db: Arc::new(db),
            keystore: Arc::new(ks),
            staging_dir,
            cli: Arc::new(MockRunner::new(Pricing {
                provider: "hetzner".into(),
                region: "fsn1".into(),
                server_type: "cx22".into(),
                hourly_eur: 0.0,
                monthly_eur: 0.0,
                included_traffic_tb_per_month: None,
                overage_eur_per_gb: None,
            })),
            clock: fixed_clock(1_700_000_000),
            custody: Arc::new(custody),
        };
        let err = get_or_create(&ctx).unwrap_err();
        assert!(matches!(err, RecipientIdentityError::Locked), "got: {err:?}");
    }

    #[test]
    fn open_priv_round_trips_after_create() {
        let ctx = make_ctx();
        let s = get_or_create(&ctx).unwrap();
        let priv_bytes = open_priv(&ctx).unwrap();
        // Derive pub from priv via X25519 base-point multiplication
        // (StaticSecret::from -> PublicKey::from).
        let secret = x25519_dalek::StaticSecret::from(priv_bytes);
        let public = x25519_dalek::PublicKey::from(&secret);
        let derived_addr = daal_recipient_addr::encode(&public.to_bytes());
        assert_eq!(derived_addr, s.address);
    }

    #[test]
    fn open_priv_not_yet_created_errors() {
        let ctx = make_ctx();
        let err = open_priv(&ctx).unwrap_err();
        assert!(matches!(err, RecipientIdentityError::NotYetCreated));
    }

    // --- Device Custody B4 -----------------------------------------

    #[test]
    fn rotate_creates_new_identity_and_demotes_old_to_history() {
        let ctx = make_ctx();
        let first = get_or_create(&ctx).unwrap();
        let rotated = rotate(&ctx).unwrap();
        // New address differs from the original.
        assert_ne!(first.address, rotated.address);
        // New row is the current identity.
        let cur = get_summary(&ctx).unwrap().unwrap();
        assert_eq!(cur.address, rotated.address);
        // History now has exactly one row, version 1.
        let hist = ctx.db.list_recipient_identity_history().unwrap();
        assert_eq!(hist.len(), 1);
        assert_eq!(hist[0].version, 1);
        assert_eq!(hist[0].address_str, first.address);
        assert_eq!(hist[0].keystore_alias, "recipient_priv_x25519.v1");
        // The retired priv is still openable through custody.
        assert!(ctx.custody.get(&hist[0].keystore_alias).is_ok());
        // open_all_privs returns current then v1 (in that order).
        let privs = open_all_privs(&ctx).unwrap();
        assert_eq!(privs.len(), 2);
        assert_eq!(privs[0].0, "recipient_priv_x25519");
        assert_eq!(privs[1].0, "recipient_priv_x25519.v1");
        // The retired priv resolves to the original public key.
        let secret = x25519_dalek::StaticSecret::from(privs[1].1);
        let pub_from_retired = x25519_dalek::PublicKey::from(&secret);
        assert_eq!(daal_recipient_addr::encode(&pub_from_retired.to_bytes()), first.address);
    }

    #[test]
    fn rotate_twice_indexes_versions_monotonically() {
        let ctx = make_ctx();
        let _ = get_or_create(&ctx).unwrap();
        let _ = rotate(&ctx).unwrap();
        let _ = rotate(&ctx).unwrap();
        let hist = ctx.db.list_recipient_identity_history().unwrap();
        assert_eq!(hist.len(), 2);
        // Newest retirement first.
        assert_eq!(hist[0].version, 2);
        assert_eq!(hist[1].version, 1);
    }

    #[test]
    fn rotate_emits_audit_event() {
        let ctx = make_ctx();
        let _ = get_or_create(&ctx).unwrap();
        let _ = rotate(&ctx).unwrap();
        let events = ctx.db.list_custody_events(50).unwrap();
        // created + rotated, newest first.
        assert_eq!(events.first().unwrap().kind, "rotated");
        assert!(events.iter().any(|e| e.kind == "created"));
    }

    #[test]
    fn rotate_without_identity_errors() {
        let ctx = make_ctx();
        let err = rotate(&ctx).unwrap_err();
        assert!(matches!(err, RecipientIdentityError::NotYetCreated));
    }
}
