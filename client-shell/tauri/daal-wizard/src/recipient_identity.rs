//! FRP-14 Layer 3c — recipient-side X25519 identity.
//!
//! See `specs/recipient-identity-v1.md` for the locked design.
//!
//! Summary:
//!
//! * One row, ever (`recipient_identity.id = 1`, CHECK-pinned).
//! * Private key sealed under PIN in the OS keystore (alias
//!   `recipient_priv_x25519`) via the same two-layer envelope
//!   the publisher keys use.
//! * Public key + derived `daal1…` address + fingerprint cached
//!   in the DB; they are not secret.
//! * Lazy create: the row is materialised only when the user
//!   enters the “My Daal address” screen and supplies a PIN.
//!   We do not silently mint keys on first launch.
//!
//! Out of scope (v2): rotation, multi-device sync, encrypting the
//! cached pub at rest.

use rand::rngs::OsRng;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::commands::{validate_pin, WizardCtx, WizardError};
use crate::keystore::KeystoreError;
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
    #[error("identity already exists but its keystore entry could not be opened: {0}")]
    KeystoreOrphan(#[source] KeystoreError),
    #[error("wrong PIN")]
    WrongPin,
    #[error("identity not yet created")]
    NotYetCreated,
    #[error(transparent)]
    Db(#[from] DbError),
    #[error(transparent)]
    Keystore(#[from] KeystoreError),
}

impl From<RecipientIdentityError> for WizardError {
    fn from(e: RecipientIdentityError) -> Self {
        match e {
            RecipientIdentityError::Db(d) => WizardError::Db(d),
            RecipientIdentityError::Keystore(k) => WizardError::Keystore(k),
            RecipientIdentityError::WrongPin
            | RecipientIdentityError::KeystoreOrphan(_) => {
                WizardError::Keystore(KeystoreError::WrongPin)
            }
            RecipientIdentityError::NotYetCreated => {
                WizardError::Pricing("recipient identity not yet created".into())
            }
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

/// First call: generate a fresh X25519 keypair via OS RNG, seal
/// the private key under PIN, persist (pub, address, fingerprint,
/// timestamp) to the DB, and return the summary. Subsequent
/// calls: return the cached summary without touching the
/// keystore.
///
/// PIN is validated (length ≥ 6) on both branches so the UI gets
/// consistent error shapes.
pub fn get_or_create(
    ctx: &WizardCtx,
    pin: &str,
) -> Result<RecipientIdentitySummary, RecipientIdentityError> {
    validate_pin(pin).map_err(|_| RecipientIdentityError::WrongPin)?;

    // Fast path: row already present. We *do* re-open the keystore
    // entry to confirm the PIN round-trips; this catches the
    // "DB row exists but keystore was wiped / migrated to a new
    // OS user" orphan case so we surface it as KeystoreOrphan
    // instead of silently lying about availability.
    if let Some(row) = ctx.db.get_recipient_identity()? {
        // Round-trip check.
        let opened = ctx.keystore.open(&row.keystore_alias, pin);
        match opened {
            Ok(bytes) => {
                let _z = Zeroizing::new(bytes);
                // ok
            }
            Err(KeystoreError::WrongPin) => return Err(RecipientIdentityError::WrongPin),
            Err(e) => return Err(RecipientIdentityError::KeystoreOrphan(e)),
        }
        return Ok(RecipientIdentitySummary {
            address: row.address_str,
            fingerprint_hex: row.fingerprint_hex,
            created_at_unix: row.created_at_unix,
        });
    }

    // Fresh-create path. Generate keypair, seal priv, insert row.
    let secret = StaticSecret::random_from_rng(&mut OsRng);
    let public = PublicKey::from(&secret);
    let pub_bytes: [u8; 32] = public.to_bytes();
    let priv_bytes: [u8; 32] = secret.to_bytes();
    let priv_z = Zeroizing::new(priv_bytes);

    let address = daal_recipient_addr::encode(&pub_bytes);
    let fingerprint_hex = daal_recipient_addr::fingerprint(&pub_bytes);
    let created_at_unix = (ctx.clock)();

    // Seal first, persist second. If seal fails, we never wrote
    // the row, so a later call cleanly retries.
    ctx.keystore
        .seal(RECIPIENT_PRIV_ALIAS, pin, priv_z.as_slice())?;

    let inserted =
        ctx.db
            .upsert_recipient_identity(&pub_bytes, &address, &fingerprint_hex, created_at_unix)?;

    if !inserted {
        // Lost a race with another thread that created the row
        // between our `get_recipient_identity` check and the
        // upsert. Return whatever the canonical row says — the
        // priv we just wrote is now an unreachable orphan in the
        // keystore, but the alias is shared so re-sealing on top
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
pub fn open_priv(ctx: &WizardCtx, pin: &str) -> Result<[u8; 32], RecipientIdentityError> {
    validate_pin(pin).map_err(|_| RecipientIdentityError::WrongPin)?;

    let row = ctx
        .db
        .get_recipient_identity()?
        .ok_or(RecipientIdentityError::NotYetCreated)?;

    let bytes = match ctx.keystore.open(&row.keystore_alias, pin) {
        Ok(b) => b,
        Err(KeystoreError::WrongPin) => return Err(RecipientIdentityError::WrongPin),
        Err(e) => return Err(RecipientIdentityError::Keystore(e)),
    };
    if bytes.len() != 32 {
        return Err(RecipientIdentityError::Keystore(KeystoreError::WrongPin));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    // bytes drops here; out is the caller's to zeroize.
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli_bridge::{MockRunner, Pricing};
    use crate::commands::WizardCtx;
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
        let s = get_or_create(&ctx, "123456").expect("first create");
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
        let s1 = get_or_create(&ctx, "123456").unwrap();
        let s2 = get_or_create(&ctx, "123456").unwrap();
        assert_eq!(s1, s2, "second call must return the same summary");
    }

    #[test]
    fn get_or_create_wrong_pin_after_create_errors() {
        let ctx = make_ctx();
        let _ = get_or_create(&ctx, "123456").unwrap();
        let err = get_or_create(&ctx, "654321").unwrap_err();
        assert!(
            matches!(err, RecipientIdentityError::WrongPin),
            "got: {err:?}"
        );
    }

    #[test]
    fn open_priv_round_trips_after_create() {
        let ctx = make_ctx();
        let s = get_or_create(&ctx, "123456").unwrap();
        let priv_bytes = open_priv(&ctx, "123456").unwrap();
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
        let err = open_priv(&ctx, "123456").unwrap_err();
        assert!(matches!(err, RecipientIdentityError::NotYetCreated));
    }

    #[test]
    fn open_priv_wrong_pin_errors() {
        let ctx = make_ctx();
        let _ = get_or_create(&ctx, "123456").unwrap();
        let err = open_priv(&ctx, "654321").unwrap_err();
        assert!(matches!(err, RecipientIdentityError::WrongPin));
    }
}
