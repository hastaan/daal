//! LEGACY two-layer key custody. **Read-only except `forget()`.**
//!
//! This module was the FRP-5 publisher custody: every publisher
//! secret (Ed25519 signing key, cloud-provider token, Cloudflare
//! token) was sealed under a user-typed PIN. That is over. Publisher
//! secrets now live under [`crate::device_custody`] — hardware-backed
//! on Android via the AndroidKeyStore DWK, OS keyring on desktop,
//! session passphrase only where neither exists — and **no command
//! takes a PIN any more**.
//!
//! The module is deliberately kept, not deleted, for exactly three
//! live jobs:
//!
//!   1. [`Keystore::open`] is the *reader* for the one-time
//!      PIN→custody migration (`commands::migrate_from_pin`). Until a
//!      given install has run that migration, this is the only thing
//!      that can decrypt its publisher signing key. Deleting it would
//!      orphan every relay provisioned before the migration landed.
//!   2. [`Keystore::has`] answers "is there still a legacy blob?"
//!      without a PIN, so the UI can decide whether to prompt at all.
//!   3. [`Keystore::forget`] is live in `cancel_and_cleanup` and
//!      `panic_wipe`, which must erase legacy blobs whether or not
//!      the migration ever ran.
//!
//! [`Keystore::seal`] survives only because `open`'s round-trip tests
//! need it. **Do not add new callers of `seal`.** New secrets go
//! through `DeviceCustody::put`.
//!
//! Outer layer: OS-keystore (`keyring` crate v3 — macOS Keychain,
//! Windows Credential Manager via DPAPI, Linux libsecret).
//! Inner layer: AES-GCM with a 32-byte key derived from a 6-12
//! digit PIN + per-install salt via Argon2id.
//!
//! ## Wire format (in keystore)
//!
//! Each value stored under `service="daal"`, `user=<alias>` is the
//! base64-encoded concatenation:
//!
//! ```text
//!   nonce[12] || ciphertext || tag[16]   (AES-256-GCM)
//! ```
//!
//! Note the Android caveat this design carried and `device_custody`
//! removes: on Android the `keyring` crate has no backend, so the
//! outer layer degraded to plain app-private files and the *only*
//! protection was the PIN-derived inner layer. The AndroidKeyStore
//! DWK the publisher path now uses is strictly stronger.
//!
//! The Argon2id salt is read from `~/.config/daal/keystore_salt`
//! (16 random bytes, generated on first call). Its parameters are
//! pinned: m=65_536 KiB, t=3, p=4 (OWASP 2024 desktop interactive
//! recommendation).
//!
//! ## Production guard
//!
//! Feature `dev-no-keystore` lets developers bypass the OS-keystore
//! outer layer (PIN-AES-GCM still runs over an in-memory test backend).
//! The feature is `compile_error!`-rejected in release builds (see
//! the `cfg` block at the bottom of this file).

use std::path::{Path, PathBuf};

use aes_gcm::{
    aead::{rand_core::RngCore, Aead, KeyInit, OsRng as AeadRng},
    Aes256Gcm, Key, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use thiserror::Error;
use zeroize::Zeroize;

const SERVICE: &str = "daal";
const SALT_FILENAME: &str = "keystore_salt";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

/// Argon2id parameters. Tuned for desktop interactive use per OWASP
/// 2024 (m=65_536 KiB, t=3, p=4). Changing these breaks every
/// previously-stored ciphertext, so they are version-pinned here.
const ARGON_M_KIB: u32 = 65_536;
const ARGON_T: u32 = 3;
const ARGON_P: u32 = 4;

#[derive(Debug, Error)]
pub enum KeystoreError {
    #[error("keystore i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("keyring: {0}")]
    Keyring(String),
    #[error("argon2: {0}")]
    Argon2(String),
    #[error("aes-gcm: {0}")]
    Aead(String),
    #[error("base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("ciphertext too short ({0} bytes; need >= {NONCE_LEN})")]
    CiphertextTooShort(usize),
    #[error("wrong PIN")]
    WrongPin,
}

pub type Result<T> = std::result::Result<T, KeystoreError>;

/// `Keystore` owns the salt file location and provides
/// PIN-derived AES-GCM seal/open against the OS-keystore.
pub struct Keystore {
    salt_path: PathBuf,
    backend: Backend,
    /// Process-lifetime memo for [`Keystore::has`]. See that method:
    /// on the OS-keyring backend the only existence check the crate
    /// offers is a real credential read, which can raise a platform
    /// unlock dialog. `custody_status` walks every alias on each mount
    /// of the publisher surface, so without this memo a user with a
    /// locked login keyring would get one dialog per pending alias,
    /// every time they open the page.
    has_memo: std::sync::Mutex<std::collections::HashMap<String, bool>>,
}

/// `Backend` selects the outer storage layer. The OS-keystore path
/// is the production default; `Memory` is for unit tests; `File`
/// is for platforms without a native keyring (Android).
pub enum Backend {
    /// Production desktop: `keyring` crate v3 against the OS keystore.
    Os,
    /// Test: in-memory map keyed by alias. NOT for production use.
    Memory(std::sync::Mutex<std::collections::HashMap<String, String>>),
    /// File-based blob store. Each alias maps to a file under
    /// `<dir>/keyblobs/<sanitized-alias>.blob`. The ciphertext is
    /// already AES-GCM encrypted before storage, so the file
    /// contains base64 of `nonce || ct || tag` — same wire format
    /// as the OS-keystore path.
    ///
    /// Used on Android, where the `keyring` crate has no backend.
    /// This is precisely why the PIN had to go: with no OS-keystore
    /// outer layer, an Android install's entire protection was
    /// Argon2id over a short PIN, guarding a file that any process
    /// with the app's uid could read. `device_custody` replaces it
    /// with a non-exportable AndroidKeyStore key.
    File(PathBuf),
}

impl Keystore {
    /// Construct a production keystore. On desktop this uses the
    /// OS keyring; on Android it falls back to file-based blobs.
    pub fn new_os(config_dir: impl AsRef<Path>) -> Self {
        let config = config_dir.as_ref().to_path_buf();
        #[cfg(target_os = "android")]
        let backend = Backend::File(config.join("keyblobs"));
        #[cfg(not(target_os = "android"))]
        let backend = Backend::Os;
        Self {
            salt_path: config.join(SALT_FILENAME),
            backend,
            has_memo: Default::default(),
        }
    }

    /// Construct a file-based keystore explicitly. Useful for
    /// testing the file backend on any platform.
    pub fn new_file(config_dir: impl AsRef<Path>) -> Self {
        Self {
            salt_path: config_dir.as_ref().join(SALT_FILENAME),
            backend: Backend::File(config_dir.as_ref().join("keyblobs")),
            has_memo: Default::default(),
        }
    }

    /// Construct an in-memory keystore for unit tests.
    pub fn new_in_memory(config_dir: impl AsRef<Path>) -> Self {
        Self {
            salt_path: config_dir.as_ref().join(SALT_FILENAME),
            backend: Backend::Memory(std::sync::Mutex::new(Default::default())),
            has_memo: Default::default(),
        }
    }

    /// Encrypt `secret` under the PIN and store the ciphertext at
    /// `alias`. Overwrites any prior value at that alias. The
    /// secret is zeroized before return.
    pub fn seal(&self, alias: &str, pin: &str, secret: &[u8]) -> Result<()> {
        let mut key_bytes = self.derive_key(pin)?;
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);

        let mut nonce_bytes = [0u8; NONCE_LEN];
        AeadRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ct = cipher
            .encrypt(nonce, secret)
            .map_err(|e| KeystoreError::Aead(e.to_string()))?;

        let mut blob = Vec::with_capacity(NONCE_LEN + ct.len());
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ct);
        let encoded = B64.encode(&blob);

        key_bytes.zeroize();
        let r = self.put_blob(alias, &encoded);
        self.invalidate_has(alias);
        r
    }

    /// Decrypt the ciphertext at `alias` under the PIN. Returns
    /// `WrongPin` for AEAD failure.
    pub fn open(&self, alias: &str, pin: &str) -> Result<Vec<u8>> {
        let encoded = self.get_blob(alias)?;
        let blob = B64.decode(encoded.as_bytes())?;
        if blob.len() < NONCE_LEN {
            return Err(KeystoreError::CiphertextTooShort(blob.len()));
        }
        let (nonce_bytes, ct) = blob.split_at(NONCE_LEN);
        let nonce = Nonce::from_slice(nonce_bytes);

        let mut key_bytes = self.derive_key(pin)?;
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);

        let pt = cipher
            .decrypt(nonce, ct)
            .map_err(|_| KeystoreError::WrongPin)?;
        key_bytes.zeroize();
        Ok(pt)
    }

    /// Legacy probe: does a PIN-sealed blob still exist for this
    /// alias? PIN-free on purpose — the migration gate must be able
    /// to decide whether to prompt at all *without* first asking for
    /// a PIN, and a fresh install must reach "nothing to migrate"
    /// silently.
    ///
    /// It does **not** decrypt the secret — the PIN never enters this
    /// path, so the AES-GCM layer is never opened. It is not a free
    /// stat either, and it is worth being precise about that: on the
    /// File backend this reads the opaque base64 blob off disk, and on
    /// the OS-keyring backend it *retrieves the credential*
    /// (`Entry::get_password`), because `keyring` v3 exposes no
    /// existence check that stops short of a read. On a platform where
    /// the item carries an ACL — a locked gnome-keyring, a macOS
    /// Keychain per-item prompt — that retrieval can raise a system
    /// dialog.
    ///
    /// Hence the process-lifetime memo. `custody_status` walks every
    /// alias on each mount of the publisher surface, so an uncached
    /// probe would mean one dialog per pending alias, every visit.
    /// The memo is invalidated by the two methods that can change the
    /// answer (`seal`, `forget`), and nothing outside this process
    /// writes the legacy store any more.
    ///
    /// Any error (no entry, keyring locked, backend missing) reads as
    /// `false`. That is the safe direction: a false negative merely
    /// means the migration skips an alias and the legacy blob stays
    /// on disk, which loses nothing. A false *positive* would make
    /// the UI demand a PIN for a secret that isn't there.
    pub fn has(&self, alias: &str) -> bool {
        if let Some(v) = self.has_memo.lock().unwrap().get(alias) {
            return *v;
        }
        let present = self.get_blob(alias).is_ok();
        self.has_memo
            .lock()
            .unwrap()
            .insert(alias.to_string(), present);
        present
    }

    /// Drop the [`Keystore::has`] memo for one alias. Called by every
    /// method that can change whether a blob exists.
    fn invalidate_has(&self, alias: &str) {
        self.has_memo.lock().unwrap().remove(alias);
    }

    /// Erase any stored value at `alias`. Returns Ok even if the
    /// alias was never set (idempotent).
    pub fn forget(&self, alias: &str) -> Result<()> {
        self.invalidate_has(alias);
        match &self.backend {
            Backend::Os => {
                let entry = keyring::Entry::new(SERVICE, alias)
                    .map_err(|e| KeystoreError::Keyring(e.to_string()))?;
                match entry.delete_credential() {
                    Ok(()) => Ok(()),
                    Err(keyring::Error::NoEntry) => Ok(()),
                    Err(e) => Err(KeystoreError::Keyring(e.to_string())),
                }
            }
            Backend::Memory(m) => {
                m.lock().unwrap().remove(alias);
                Ok(())
            }
            Backend::File(dir) => {
                let path = blob_path(dir, alias);
                match std::fs::remove_file(&path) {
                    Ok(()) => Ok(()),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    Err(e) => Err(KeystoreError::Io(e)),
                }
            }
        }
    }

    fn put_blob(&self, alias: &str, encoded: &str) -> Result<()> {
        match &self.backend {
            Backend::Os => {
                let entry = keyring::Entry::new(SERVICE, alias)
                    .map_err(|e| KeystoreError::Keyring(e.to_string()))?;
                entry
                    .set_password(encoded)
                    .map_err(|e| KeystoreError::Keyring(e.to_string()))
            }
            Backend::Memory(m) => {
                m.lock()
                    .unwrap()
                    .insert(alias.to_string(), encoded.to_string());
                Ok(())
            }
            Backend::File(dir) => {
                std::fs::create_dir_all(dir)?;
                let path = blob_path(dir, alias);
                std::fs::write(&path, encoded.as_bytes())?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
                }
                Ok(())
            }
        }
    }

    fn get_blob(&self, alias: &str) -> Result<String> {
        match &self.backend {
            Backend::Os => {
                let entry = keyring::Entry::new(SERVICE, alias)
                    .map_err(|e| KeystoreError::Keyring(e.to_string()))?;
                entry
                    .get_password()
                    .map_err(|e| KeystoreError::Keyring(e.to_string()))
            }
            Backend::Memory(m) => m
                .lock()
                .unwrap()
                .get(alias)
                .cloned()
                .ok_or_else(|| KeystoreError::Keyring(format!("no entry for {alias}"))),
            Backend::File(dir) => {
                let path = blob_path(dir, alias);
                std::fs::read_to_string(&path).map_err(|e| {
                    if e.kind() == std::io::ErrorKind::NotFound {
                        KeystoreError::Keyring(format!("no entry for {alias}"))
                    } else {
                        KeystoreError::Io(e)
                    }
                })
            }
        }
    }

    fn derive_key(&self, pin: &str) -> Result<[u8; KEY_LEN]> {
        let salt = self.read_or_create_salt()?;
        let params = Params::new(ARGON_M_KIB, ARGON_T, ARGON_P, Some(KEY_LEN))
            .map_err(|e| KeystoreError::Argon2(e.to_string()))?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = [0u8; KEY_LEN];
        argon
            .hash_password_into(pin.as_bytes(), &salt, &mut out)
            .map_err(|e| KeystoreError::Argon2(e.to_string()))?;
        Ok(out)
    }

    fn read_or_create_salt(&self) -> Result<[u8; SALT_LEN]> {
        if self.salt_path.exists() {
            let bytes = std::fs::read(&self.salt_path)?;
            if bytes.len() != SALT_LEN {
                return Err(KeystoreError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("salt length {} != {}", bytes.len(), SALT_LEN),
                )));
            }
            let mut out = [0u8; SALT_LEN];
            out.copy_from_slice(&bytes);
            return Ok(out);
        }
        if let Some(parent) = self.salt_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut salt = [0u8; SALT_LEN];
        AeadRng.fill_bytes(&mut salt);
        std::fs::write(&self.salt_path, salt)?;
        // tighten file mode on unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perm = std::fs::Permissions::from_mode(0o600);
            let _ = std::fs::set_permissions(&self.salt_path, perm);
        }
        Ok(salt)
    }
}

/// Sanitize an alias into a safe filename. Replaces characters
/// that are problematic on any filesystem with underscores.
fn blob_path(dir: &Path, alias: &str) -> PathBuf {
    let safe: String = alias
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    dir.join(format!("{safe}.blob"))
}

// Production-build guard: `dev-no-keystore` only allowed in debug.
#[cfg(all(feature = "dev-no-keystore", not(debug_assertions)))]
compile_error!(
    "feature `dev-no-keystore` is not allowed in release builds; \
     remove it from the cargo invocation or build with debug_assertions"
);

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn round_trip_seal_open() {
        let dir = tempdir().unwrap();
        let ks = Keystore::new_in_memory(dir.path());
        let secret = b"this-is-a-private-key-stand-in";
        ks.seal("daal.publisher.1.priv", "123456", secret).unwrap();
        let got = ks.open("daal.publisher.1.priv", "123456").unwrap();
        assert_eq!(got, secret);
    }

    #[test]
    fn wrong_pin_returns_wrong_pin_error() {
        let dir = tempdir().unwrap();
        let ks = Keystore::new_in_memory(dir.path());
        ks.seal("alias", "123456", b"secret").unwrap();
        let err = ks.open("alias", "654321").unwrap_err();
        match err {
            KeystoreError::WrongPin => (),
            e => panic!("wanted WrongPin, got {e:?}"),
        }
    }

    #[test]
    fn salt_persists_across_keystore_instances() {
        let dir = tempdir().unwrap();
        let ks_a = Keystore::new_in_memory(dir.path());
        ks_a.seal("k", "111111", b"hello").unwrap();
        // New instance pointing at same salt + ciphertext source
        // would only succeed if the salt is read from disk. We copy
        // the keystore blob across by going through OS-keystore in
        // production; here we re-use the in-memory backend by
        // moving the entry.
        //
        // To check the salt-stability property, we instead derive a
        // key with two distinct Keystore instances over the same
        // salt path and confirm the derived bytes match.
        let ks_b = Keystore::new_in_memory(dir.path());
        let a = ks_a.derive_key("111111").unwrap();
        let b = ks_b.derive_key("111111").unwrap();
        assert_eq!(
            a, b,
            "derived key must match across instances reading the same salt"
        );
    }

    #[test]
    fn forget_is_idempotent() {
        let dir = tempdir().unwrap();
        let ks = Keystore::new_in_memory(dir.path());
        ks.forget("never-set").unwrap(); // must not error
        ks.seal("a", "111111", b"x").unwrap();
        ks.forget("a").unwrap();
        let err = ks.open("a", "111111").unwrap_err();
        match err {
            KeystoreError::Keyring(_) => (), // entry-not-found path
            e => panic!("unexpected error after forget: {e:?}"),
        }
    }

    #[test]
    fn ciphertext_changes_per_seal() {
        let dir = tempdir().unwrap();
        let ks = Keystore::new_in_memory(dir.path());
        ks.seal("a", "111111", b"hello").unwrap();
        let c1 = ks.get_blob("a").unwrap();
        ks.seal("a", "111111", b"hello").unwrap();
        let c2 = ks.get_blob("a").unwrap();
        assert_ne!(c1, c2, "nonce must be fresh per seal -> ciphertext differs");
    }

    // ---- File backend tests ----

    #[test]
    fn file_backend_round_trip() {
        let dir = tempdir().unwrap();
        let ks = Keystore::new_file(dir.path());
        let secret = b"cloud-api-token-xyz";
        ks.seal("daal.cloud.1.token", "123456", secret).unwrap();
        let got = ks.open("daal.cloud.1.token", "123456").unwrap();
        assert_eq!(got, secret);
    }

    #[test]
    fn file_backend_wrong_pin() {
        let dir = tempdir().unwrap();
        let ks = Keystore::new_file(dir.path());
        ks.seal("alias", "123456", b"secret").unwrap();
        let err = ks.open("alias", "654321").unwrap_err();
        match err {
            KeystoreError::WrongPin => (),
            e => panic!("wanted WrongPin, got {e:?}"),
        }
    }

    #[test]
    fn file_backend_forget() {
        let dir = tempdir().unwrap();
        let ks = Keystore::new_file(dir.path());
        ks.forget("never-set").unwrap();
        ks.seal("a", "111111", b"x").unwrap();
        ks.forget("a").unwrap();
        let err = ks.open("a", "111111").unwrap_err();
        match err {
            KeystoreError::Keyring(_) => (),
            e => panic!("unexpected error after forget: {e:?}"),
        }
    }

    #[test]
    fn file_backend_blob_path_sanitizes() {
        let dir = tempdir().unwrap();
        let p = blob_path(dir.path(), "daal.cloud.1.token");
        assert_eq!(
            p.file_name().unwrap().to_str().unwrap(),
            "daal_cloud_1_token.blob"
        );
    }
}
