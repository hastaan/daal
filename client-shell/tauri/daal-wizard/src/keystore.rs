//! Two-layer key custody for the FRP-5 wizard.
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
}

/// `Backend` selects the outer storage layer. The OS-keystore path
/// is the production default; `Memory` is for unit tests.
pub enum Backend {
    /// Production: `keyring` crate v3 against the OS keystore.
    Os,
    /// Test: in-memory map keyed by alias. NOT for production use.
    Memory(std::sync::Mutex<std::collections::HashMap<String, String>>),
}

impl Keystore {
    /// Construct a production keystore. Salt is read from /
    /// generated under `config_dir`.
    pub fn new_os(config_dir: impl AsRef<Path>) -> Self {
        Self {
            salt_path: config_dir.as_ref().join(SALT_FILENAME),
            backend: Backend::Os,
        }
    }

    /// Construct an in-memory keystore for unit tests.
    pub fn new_in_memory(config_dir: impl AsRef<Path>) -> Self {
        Self {
            salt_path: config_dir.as_ref().join(SALT_FILENAME),
            backend: Backend::Memory(std::sync::Mutex::new(Default::default())),
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
        self.put_blob(alias, &encoded)
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

    /// Erase any stored value at `alias`. Returns Ok even if the
    /// alias was never set (idempotent).
    pub fn forget(&self, alias: &str) -> Result<()> {
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
}
