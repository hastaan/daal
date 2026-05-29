//! FRP-14 Layer 3d — recipient-side `.sbpx` import.
//!
//! Pipeline:
//!
//! 1. Read the first 6 bytes of the input file. If they aren't
//!    `DSBP\x00\x01`, return [`SbpxImportError::NotEnvelope`] so
//!    the caller can fall through to the legacy `.sbp` lane.
//! 2. Open the recipient's X25519 priv via
//!    [`recipient_identity::open_priv`].
//! 3. Subprocess into `daal-deploy users-unpack-sbpx`, piping the
//!    priv-key hex through stdin. The subprocess writes the
//!    plaintext `.sbp` to a mode-0600 tempfile under the wizard
//!    staging dir.
//! 4. Return the tempfile path. The caller (Tauri command) hands
//!    it to the existing `importSbp(path)` contract.
//!
//! The plaintext tempfile lives in `<staging>/sbpx/<rand>.sbp`
//! and is unlinked on import or after 10 minutes by the next
//! launch's sweep.
//!
//! See `specs/sbpx-import-v1.md` for the locked surface.

use std::path::PathBuf;

use rand::RngCore;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::cli_bridge::{BridgeError, UsersUnpackSbpxArgs};
use crate::commands::WizardCtx;
use crate::recipient_identity::{self, RecipientIdentityError};

/// 6-byte sbpx magic prefix (mirrors `bundle/go/envelope/Magic`).
pub const SBPX_MAGIC: [u8; 6] = [b'D', b'S', b'B', b'P', 0x00, 0x01];

#[derive(Debug, Error)]
pub enum SbpxImportError {
    #[error("not an .sbpx file (bad magic)")]
    NotEnvelope,
    #[error("identity not yet created")]
    IdentityMissing,
    #[error("device custody is locked; unlock with your session passphrase first")]
    Locked,
    #[error("envelope corrupt or not addressed to this phone: {0}")]
    EnvelopeCorrupt(String),
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("bridge: {0}")]
    Bridge(String),
}

/// Returns true iff `head` starts with the 6-byte sbpx magic.
/// Safe to call on shorter inputs (returns false without panic).
pub fn is_sbpx(head: &[u8]) -> bool {
    head.len() >= SBPX_MAGIC.len() && head[..SBPX_MAGIC.len()] == SBPX_MAGIC
}

/// Quickly sniff the file without reading its entire body. Returns
/// `Ok(true)` on `.sbpx`, `Ok(false)` on anything else.
pub fn sniff_file(path: &std::path::Path) -> std::io::Result<bool> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut head = [0u8; 6];
    let n = f.read(&mut head)?;
    Ok(n >= 6 && is_sbpx(&head))
}

/// Decrypt a `.sbpx` file at `in_sbpx_path` using the recipient's
/// identity. On success returns the path of the plaintext `.sbp`
/// tempfile the caller can hand to the importer.
pub fn import_sbpx(
    ctx: &WizardCtx,
    in_sbpx_path: &std::path::Path,
) -> Result<PathBuf, SbpxImportError> {
    if !sniff_file(in_sbpx_path)? {
        return Err(SbpxImportError::NotEnvelope);
    }

    // Device Custody B4 grace decrypt: try the current priv, then
    // each historical priv (newest retirement first). The first
    // priv that decrypts cleanly wins; we stop iterating.
    let privs = recipient_identity::open_all_privs(ctx).map_err(|e| match e {
        RecipientIdentityError::Locked => SbpxImportError::Locked,
        RecipientIdentityError::NotYetCreated => SbpxImportError::IdentityMissing,
        other => SbpxImportError::Bridge(other.to_string()),
    })?;
    if privs.is_empty() {
        return Err(SbpxImportError::IdentityMissing);
    }

    let sbpx_dir = ctx.staging_dir.join("sbpx");
    std::fs::create_dir_all(&sbpx_dir)?;

    let mut last_stderr = String::new();
    for (alias, mut priv_bytes) in privs {
        // Hand to subprocess as hex; never write the priv to disk.
        let priv_hex = Zeroizing::new(hex::encode(priv_bytes));
        for b in priv_bytes.iter_mut() {
            *b = 0;
        }

        // Each attempt gets its own out path; on failure we unlink.
        let mut tag = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut tag);
        let out_path = sbpx_dir.join(format!("{}.sbp", hex::encode(tag)));

        match ctx.cli.run_users_unpack_sbpx(
            UsersUnpackSbpxArgs {
                in_sbpx_path,
                out_sbp_path: &out_path,
            },
            priv_hex.as_str(),
        ) {
            Ok(_res) => return Ok(out_path),
            Err(BridgeError::SubprocessFailed { rc: _, stderr }) => {
                let _ = std::fs::remove_file(&out_path);
                last_stderr = format!("[{alias}] {stderr}");
                continue;
            }
            Err(e) => return Err(SbpxImportError::Bridge(e.to_string())),
        }
    }
    Err(SbpxImportError::EnvelopeCorrupt(last_stderr))
}

/// Sweep stale plaintext tempfiles older than `older_than_secs`
/// from `<staging>/sbpx/`. Called at app launch to reap crash
/// leftovers.
pub fn sweep_stale(ctx: &WizardCtx, older_than_secs: i64) -> std::io::Result<usize> {
    let sbpx_dir = ctx.staging_dir.join("sbpx");
    if !sbpx_dir.exists() {
        return Ok(0);
    }
    let cutoff = (ctx.clock)() - older_than_secs;
    let mut removed = 0usize;
    for entry in std::fs::read_dir(&sbpx_dir)? {
        let entry = entry?;
        let meta = entry.metadata()?;
        if let Ok(mtime) = meta.modified() {
            if let Ok(d) = mtime.duration_since(std::time::UNIX_EPOCH) {
                if (d.as_secs() as i64) < cutoff {
                    let _ = std::fs::remove_file(entry.path());
                    removed += 1;
                }
            }
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli_bridge::{MockRunner, Pricing};
    use crate::device_custody::FileCustody;
    use crate::keystore::Keystore;
    use crate::operator_db::OperatorDb;
    use std::sync::Arc;

    fn make_ctx() -> WizardCtx {
        let db = OperatorDb::open_in_memory().expect("open_in_memory");
        let tmp = tempfile::tempdir().expect("tempdir");
        let ks = Keystore::new_in_memory(tmp.path());
        let custody = FileCustody::static_test(tmp.path()).expect("custody");
        let staging_dir = tmp.path().to_path_buf();
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
            clock: Arc::new(|| 1_700_000_000),
            custody: Arc::new(custody),
        }
    }

    #[test]
    fn is_sbpx_magic_check() {
        assert!(is_sbpx(b"DSBP\x00\x01extra"));
        assert!(!is_sbpx(b"DSBP\x00\x02"));
        assert!(!is_sbpx(b"DSBP"));
        assert!(!is_sbpx(b""));
        assert!(!is_sbpx(b"plain sbp"));
    }

    #[test]
    fn import_sbpx_round_trips_via_mock_runner() {
        let ctx = make_ctx();
        // Stand up the identity row.
        let _ = recipient_identity::get_or_create(&ctx).unwrap();

        // Build a fake .sbpx file: magic + plaintext (matches the
        // MockRunner unpack logic that strips the prefix).
        let plaintext = b"---DAAL SBP v1---\nfake body bytes here\n";
        let mut sbpx = Vec::new();
        sbpx.extend_from_slice(&SBPX_MAGIC);
        sbpx.extend_from_slice(plaintext);
        let in_path = ctx.staging_dir.join("incoming.sbpx");
        std::fs::write(&in_path, &sbpx).unwrap();

        let out = import_sbpx(&ctx, &in_path).expect("import_sbpx");
        let got = std::fs::read(&out).unwrap();
        assert_eq!(got, plaintext);
    }

    #[test]
    fn import_sbpx_rejects_non_envelope() {
        let ctx = make_ctx();
        let _ = recipient_identity::get_or_create(&ctx).unwrap();
        let in_path = ctx.staging_dir.join("plain.sbp");
        std::fs::write(&in_path, b"PLAINSBPHEADER").unwrap();
        let err = import_sbpx(&ctx, &in_path).unwrap_err();
        assert!(matches!(err, SbpxImportError::NotEnvelope), "got: {err:?}");
    }

    #[test]
    fn import_sbpx_without_identity_errors() {
        let ctx = make_ctx();
        let mut sbpx = Vec::new();
        sbpx.extend_from_slice(&SBPX_MAGIC);
        sbpx.extend_from_slice(b"body");
        let in_path = ctx.staging_dir.join("incoming.sbpx");
        std::fs::write(&in_path, &sbpx).unwrap();
        let err = import_sbpx(&ctx, &in_path).unwrap_err();
        assert!(matches!(err, SbpxImportError::IdentityMissing), "got: {err:?}");
    }

    #[test]
    fn import_sbpx_grace_decrypts_after_rotation() {
        // After rotation, `.sbpx` import still succeeds. The mock
        // unpack ignores the priv (so we can't tell which key
        // "won"), but the wiring exercises open_all_privs +
        // try-each-priv loop end-to-end.
        let ctx = make_ctx();
        let _ = recipient_identity::get_or_create(&ctx).unwrap();
        let _ = recipient_identity::rotate(&ctx).unwrap();

        let plaintext = b"---DAAL SBP v1---\npost-rotation body\n";
        let mut sbpx = Vec::new();
        sbpx.extend_from_slice(&SBPX_MAGIC);
        sbpx.extend_from_slice(plaintext);
        let in_path = ctx.staging_dir.join("post_rotation.sbpx");
        std::fs::write(&in_path, &sbpx).unwrap();

        let out = import_sbpx(&ctx, &in_path).expect("import_sbpx after rotate");
        let got = std::fs::read(&out).unwrap();
        assert_eq!(got, plaintext);
    }

    #[test]
    fn import_sbpx_locked_session_custody_errors() {
        // Session-passphrase custody, never unlocked → Locked.
        let db = OperatorDb::open_in_memory().expect("open_in_memory");
        let tmp = tempfile::tempdir().expect("tempdir");
        let ks = Keystore::new_in_memory(tmp.path());
        let custody = FileCustody::session_passphrase(tmp.path()).expect("custody");
        // Seed an identity row directly so we reach the open_priv path.
        db.upsert_recipient_identity(&[7u8; 32], "daal1seed", "fp", 1_700_000_000)
            .unwrap();
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
            clock: Arc::new(|| 1_700_000_000),
            custody: Arc::new(custody),
        };
        let mut sbpx = Vec::new();
        sbpx.extend_from_slice(&SBPX_MAGIC);
        sbpx.extend_from_slice(b"body");
        let in_path = ctx.staging_dir.join("incoming.sbpx");
        std::fs::write(&in_path, &sbpx).unwrap();
        let err = import_sbpx(&ctx, &in_path).unwrap_err();
        assert!(matches!(err, SbpxImportError::Locked), "got: {err:?}");
    }
}
