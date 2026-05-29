//! Device Custody v1 — cross-platform private-key wrapping with
//! honest security labelling.
//!
//! Replaces "always ask PIN per operation" with a hybrid model:
//!
//! - On platforms with hardware/OS keystore (Android Keystore,
//!   iOS Keychain, macOS Keychain, Windows DPAPI, Linux libsecret)
//!   the priv key is wrapped by a per-app **Device Wrap Key (DWK)**
//!   that lives inside that keystore. No PIN. UI shows the custody
//!   level honestly ("Hardware" / "OS Keystore").
//!
//! - On platforms without one (headless Linux, broken Android
//!   emulator), we fall back to a **session passphrase** the user
//!   sets once per session. The passphrase derives an in-memory
//!   key via Argon2id; the priv-on-disk is AES-GCM under
//!   `HKDF(DWK_or_passphrase_key, machine_id)`. The "Session
//!   passphrase" level is shown explicitly in the UI.
//!
//! Critically, the **machine-id binding is mixed into the wrap
//! key**, never used as the wrap key alone. This means:
//!   - lift the on-disk blob without the DWK → cannot open;
//!   - lift the blob + the DWK alias but move to another machine
//!     → cannot open (binding mismatch).
//!
//! ## Architecture
//!
//! `DeviceCustody` is the object-safe surface the rest of
//! `daal-wizard` holds (`Arc<dyn DeviceCustody>`). `FileCustody`
//! is the one concrete implementation: it owns the per-alias
//! AES-GCM blob store + the machine-binding salt, and delegates
//! the *source of the Device Wrap Key* to a pluggable
//! [`DwkProvider`].
//!
//! Providers:
//!   - [`PassphraseDwk`]   — in-memory, Argon2id over a session
//!                           passphrase. `SessionPassphrase` level.
//!   - [`StaticTestDwk`]   — deterministic; tests + dev only.
//!   - (shell) `KeystoreDwk` — Android Keystore / libsecret /
//!                           DPAPI. Lives in `src-tauri` because it
//!                           needs `unsafe` JNI; this crate stays
//!                           `forbid(unsafe_code)`.
//!
//! ## Storage layout
//!
//! `<config_dir>/custody/binding.salt`        — 32 random bytes, persisted on first use
//! `<config_dir>/custody/aliases/<safe>.blob` — per-alias AES-GCM blob, base64 of (nonce ‖ ct ‖ tag)
//!
//! The blob wire-format is **identical** across backends so the
//! file shape is the only persistent invariant; backend swaps
//! never migrate ciphertext on disk.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use aes_gcm::{
    aead::{rand_core::RngCore, Aead, KeyInit, OsRng as AeadRng},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const BINDING_SALT_LEN: usize = 32;

/// Honest label of the custody backend currently in force. Shown
/// in the UI verbatim; the strings carry the security promise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyLevel {
    /// Hardware-backed keystore (Android StrongBox/TEE, Apple
    /// Secure Enclave, Windows Hello + TPM, …). Strongest.
    Hardware,
    /// OS-managed keystore without hardware backing (libsecret,
    /// DPAPI user-scope, plain Android Keystore on a device whose
    /// TEE is unavailable). Strong, software-only.
    OsKeystore,
    /// No keystore — the user must enter a passphrase once per
    /// session. The wrap key lives in memory only; lock() clears
    /// it. Weakest of the three because cold-storage attacks
    /// against the on-disk blob can be brute-forced under
    /// (passphrase × Argon2id).
    SessionPassphrase,
}

impl CustodyLevel {
    /// Stable snake_case token for i18n key lookup.
    pub fn as_str(self) -> &'static str {
        match self {
            CustodyLevel::Hardware => "hardware",
            CustodyLevel::OsKeystore => "os_keystore",
            CustodyLevel::SessionPassphrase => "session_passphrase",
        }
    }
}

#[derive(Debug, Error)]
pub enum CustodyError {
    #[error("custody i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("aes-gcm: {0}")]
    Aead(String),
    #[error("base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("ciphertext too short ({0} bytes; need >= {NONCE_LEN})")]
    CiphertextTooShort(usize),
    #[error("alias not found: {0}")]
    NotFound(String),
    #[error("custody is locked; call unlock() with a passphrase first")]
    Locked,
    #[error("wrong passphrase")]
    WrongPassphrase,
    #[error("machine binding mismatch — wrapped on a different device")]
    BindingMismatch,
    #[error("argon2: {0}")]
    Argon2(String),
    #[error("backend: {0}")]
    Backend(String),
}

pub type Result<T> = std::result::Result<T, CustodyError>;

/// Public trait implemented per platform via [`FileCustody`]. Stays
/// object-safe so the rest of `daal-wizard` can hold
/// `Arc<dyn DeviceCustody>` without caring which provider is live.
pub trait DeviceCustody: Send + Sync {
    fn level(&self) -> CustodyLevel;

    /// Returns true if subsequent `put`/`get` calls will succeed.
    /// Hardware and OsKeystore providers are always ready once the
    /// OS user is logged in; SessionPassphrase providers are locked
    /// until `unlock(Some(passphrase))` is called.
    fn is_unlocked(&self) -> bool;

    /// SessionPassphrase: provide the passphrase to derive the
    /// in-memory wrap key. Hardware/OsKeystore: `Some(_)` is
    /// ignored and `None` simply forces the DWK to load (surfacing
    /// any keystore error eagerly).
    fn unlock(&self, passphrase: Option<&str>) -> Result<()>;

    /// Drop any in-memory key material. Hardware/OsKeystore remain
    /// functional afterward (they re-fetch per call); only
    /// SessionPassphrase flips `is_unlocked()` to false.
    fn lock(&self);

    /// Encrypt `secret` and persist it under `alias`. Overwrites.
    fn put(&self, alias: &str, secret: &[u8]) -> Result<()>;

    /// Decrypt the value at `alias`. Returns `NotFound` if absent.
    fn get(&self, alias: &str) -> Result<Vec<u8>>;

    /// Erase the value at `alias`. Idempotent.
    fn forget(&self, alias: &str) -> Result<()>;

    /// Wipe **every** alias whose (sanitized) name starts with
    /// `prefix`. Used by panic_wipe to nuke `daal/*`. An empty
    /// prefix wipes everything. Returns the number of aliases
    /// removed (informational; used by tests).
    fn forget_prefix(&self, prefix: &str) -> Result<usize>;
}

// ---------------------------------------------------------------------
// DwkProvider — pluggable source of the Device Wrap Key.
// ---------------------------------------------------------------------

/// Source of the 32-byte Device Wrap Key. Implementations decide
/// where the DWK lives (in-memory passphrase derivation, OS
/// keystore, hardware element). `FileCustody` mixes the returned
/// DWK with the machine-binding salt before using it as an AEAD
/// key, so a provider that leaks its DWK still does not by itself
/// allow cross-device decryption.
pub trait DwkProvider: Send + Sync {
    /// Honest custody level for this provider.
    fn level(&self) -> CustodyLevel;

    /// True if `ensure_dwk()` will currently succeed without a
    /// passphrase prompt.
    fn is_ready(&self) -> bool;

    /// Return the DWK, loading or generating it as needed. Callers
    /// must zeroize the returned array.
    fn ensure_dwk(&self) -> Result<[u8; KEY_LEN]>;

    /// SessionPassphrase: derive the DWK from `passphrase`. Other
    /// providers treat this as a no-op (they ignore the passphrase).
    fn set_passphrase(&self, passphrase: &str) -> Result<()>;

    /// Drop in-memory key material. No-op for providers whose DWK
    /// is re-fetched from a keystore on each call.
    fn clear(&self);
}

/// In-memory passphrase-derived DWK. `SessionPassphrase` level.
/// The DWK is `Argon2id(passphrase, binding_salt)`; the binding
/// salt doubles as the Argon2 salt so the derived key is itself
/// machine-bound.
pub struct PassphraseDwk {
    binding_salt: [u8; BINDING_SALT_LEN],
    state: Mutex<Option<[u8; KEY_LEN]>>,
}

impl PassphraseDwk {
    /// Reads (or creates) the shared `custody/binding.salt` under
    /// `base_dir` so the Argon2 salt matches the one `FileCustody`
    /// mixes into the wrap key.
    pub fn new(base_dir: impl AsRef<Path>) -> Result<Self> {
        let base = base_dir.as_ref().join("custody");
        std::fs::create_dir_all(&base)?;
        let binding_salt = read_or_create_binding_salt(&base)?;
        Ok(Self {
            binding_salt,
            state: Mutex::new(None),
        })
    }
}

impl Drop for PassphraseDwk {
    fn drop(&mut self) {
        if let Ok(mut g) = self.state.lock() {
            if let Some(mut k) = g.take() {
                k.zeroize();
            }
        }
    }
}

impl DwkProvider for PassphraseDwk {
    fn level(&self) -> CustodyLevel {
        CustodyLevel::SessionPassphrase
    }

    fn is_ready(&self) -> bool {
        self.state.lock().unwrap().is_some()
    }

    fn ensure_dwk(&self) -> Result<[u8; KEY_LEN]> {
        self.state.lock().unwrap().ok_or(CustodyError::Locked)
    }

    fn set_passphrase(&self, passphrase: &str) -> Result<()> {
        if passphrase.is_empty() {
            return Err(CustodyError::WrongPassphrase);
        }
        let key = derive_passphrase_key(passphrase.as_bytes(), &self.binding_salt)?;
        let mut g = self.state.lock().unwrap();
        if let Some(mut old) = g.replace(key) {
            old.zeroize();
        }
        Ok(())
    }

    fn clear(&self) {
        let mut g = self.state.lock().unwrap();
        if let Some(mut k) = g.take() {
            k.zeroize();
        }
    }
}

/// Deterministic DWK derived from the binding salt alone. **Tests
/// and dev only.** Reports `SessionPassphrase` (never claims
/// hardware) so it cannot mislead the UI if it ever escapes a test
/// build. Always ready; `set_passphrase`/`clear` are no-ops.
pub struct StaticTestDwk {
    dwk: [u8; KEY_LEN],
}

impl StaticTestDwk {
    pub fn new(base_dir: impl AsRef<Path>) -> Result<Self> {
        let base = base_dir.as_ref().join("custody");
        std::fs::create_dir_all(&base)?;
        let salt = read_or_create_binding_salt(&base)?;
        Ok(Self {
            dwk: derive_test_key(&salt),
        })
    }
}

impl DwkProvider for StaticTestDwk {
    fn level(&self) -> CustodyLevel {
        CustodyLevel::SessionPassphrase
    }
    fn is_ready(&self) -> bool {
        true
    }
    fn ensure_dwk(&self) -> Result<[u8; KEY_LEN]> {
        Ok(self.dwk)
    }
    fn set_passphrase(&self, _passphrase: &str) -> Result<()> {
        Ok(())
    }
    fn clear(&self) {}
}

// ---------------------------------------------------------------------
// FileCustody — per-alias AES-GCM blob store + machine binding.
// ---------------------------------------------------------------------

/// The one concrete `DeviceCustody`. Owns the binding salt and the
/// per-alias blob directory; delegates the DWK to a [`DwkProvider`].
pub struct FileCustody {
    provider: Arc<dyn DwkProvider>,
    /// `<config_dir>/custody/`
    base_dir: PathBuf,
    binding_salt: [u8; BINDING_SALT_LEN],
}

impl FileCustody {
    /// Construct with an explicit provider. The shell uses this to
    /// inject `KeystoreDwk`; tests use the convenience constructors
    /// below.
    pub fn with_provider(
        base_dir: impl AsRef<Path>,
        provider: Arc<dyn DwkProvider>,
    ) -> Result<Self> {
        let base = base_dir.as_ref().join("custody");
        std::fs::create_dir_all(base.join("aliases"))?;
        let binding_salt = read_or_create_binding_salt(&base)?;
        Ok(Self {
            provider,
            base_dir: base,
            binding_salt,
        })
    }

    /// Session-passphrase custody (no OS keystore). The user must
    /// `unlock(Some(passphrase))` once per session.
    pub fn session_passphrase(base_dir: impl AsRef<Path>) -> Result<Self> {
        let p = Arc::new(PassphraseDwk::new(&base_dir)?);
        Self::with_provider(base_dir, p)
    }

    /// Deterministic test custody. **Tests/dev only.**
    pub fn static_test(base_dir: impl AsRef<Path>) -> Result<Self> {
        let p = Arc::new(StaticTestDwk::new(&base_dir)?);
        Self::with_provider(base_dir, p)
    }

    fn alias_path(&self, alias: &str) -> PathBuf {
        self.base_dir
            .join("aliases")
            .join(format!("{}.blob", sanitize(alias)))
    }
}

impl DeviceCustody for FileCustody {
    fn level(&self) -> CustodyLevel {
        self.provider.level()
    }

    fn is_unlocked(&self) -> bool {
        self.provider.is_ready()
    }

    fn unlock(&self, passphrase: Option<&str>) -> Result<()> {
        match passphrase {
            Some(p) => self.provider.set_passphrase(p),
            None => {
                // Force the DWK to materialise so keystore errors
                // surface here rather than on first put/get.
                let mut k = self.provider.ensure_dwk()?;
                k.zeroize();
                Ok(())
            }
        }
    }

    fn lock(&self) {
        self.provider.clear();
    }

    fn put(&self, alias: &str, secret: &[u8]) -> Result<()> {
        let mut dwk = self.provider.ensure_dwk()?;
        let mut wrap_key = mix_binding(&dwk, &self.binding_salt);
        dwk.zeroize();
        let sealed = aes_gcm_seal(&wrap_key, secret);
        wrap_key.zeroize();
        let blob = sealed?;
        let encoded = B64.encode(&blob);
        let path = self.alias_path(alias);
        std::fs::write(&path, encoded.as_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    fn get(&self, alias: &str) -> Result<Vec<u8>> {
        let path = self.alias_path(alias);
        let encoded = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(CustodyError::NotFound(alias.to_string()))
            }
            Err(e) => return Err(CustodyError::Io(e)),
        };
        let blob = B64.decode(encoded.as_bytes())?;
        let mut dwk = self.provider.ensure_dwk()?;
        let mut wrap_key = mix_binding(&dwk, &self.binding_salt);
        dwk.zeroize();
        let plain = aes_gcm_open(&wrap_key, &blob);
        wrap_key.zeroize();
        plain
    }

    fn forget(&self, alias: &str) -> Result<()> {
        let path = self.alias_path(alias);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(CustodyError::Io(e)),
        }
    }

    fn forget_prefix(&self, prefix: &str) -> Result<usize> {
        let dir = self.base_dir.join("aliases");
        if !dir.exists() {
            return Ok(0);
        }
        let safe_prefix = sanitize(prefix);
        let mut n = 0usize;
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if prefix.is_empty() || name.starts_with(&safe_prefix) {
                std::fs::remove_file(entry.path())?;
                n += 1;
            }
        }
        Ok(n)
    }
}

// ---------------------------------------------------------------------
// Crypto primitives — kept private so backends share one implementation.
// ---------------------------------------------------------------------

fn aes_gcm_seal(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    AeadRng.fill_bytes(&mut nonce_bytes);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|e| CustodyError::Aead(e.to_string()))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn aes_gcm_open(key: &[u8; KEY_LEN], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < NONCE_LEN {
        return Err(CustodyError::CiphertextTooShort(blob.len()));
    }
    let (nonce, ct) = blob.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce), ct)
        .map_err(|_| CustodyError::BindingMismatch)
}

/// Mix the binding salt into the DWK so that lifting only the DWK
/// (e.g. exporting an OS-keystore alias) still cannot decrypt blobs
/// from a different machine. `HKDF-SHA256(dwk, salt=binding,
/// info="daal.custody.v1.wrap")` produces a 32-byte AEAD key.
fn mix_binding(dwk: &[u8; KEY_LEN], binding: &[u8; BINDING_SALT_LEN]) -> [u8; KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(Some(binding), dwk);
    let mut out = [0u8; KEY_LEN];
    hk.expand(b"daal.custody.v1.wrap", &mut out)
        .expect("HKDF expand 32 bytes never fails");
    out
}

/// Argon2id over the passphrase, salted by the per-install binding.
/// Parameters mirror `keystore.rs` so users carrying both auth
/// surfaces (publisher PIN, recipient passphrase) see consistent
/// unlock latency.
fn derive_passphrase_key(
    passphrase: &[u8],
    binding: &[u8; BINDING_SALT_LEN],
) -> Result<[u8; KEY_LEN]> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(65_536, 3, 4, Some(KEY_LEN))
        .map_err(|e| CustodyError::Argon2(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; KEY_LEN];
    argon
        .hash_password_into(passphrase, binding, &mut out)
        .map_err(|e| CustodyError::Argon2(e.to_string()))?;
    Ok(out)
}

/// Test/dev helper: derive a deterministic DWK from the binding
/// salt alone. NEVER used in production paths.
fn derive_test_key(binding: &[u8; BINDING_SALT_LEN]) -> [u8; KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(Some(binding), b"daal.custody.test.dev-only");
    let mut out = [0u8; KEY_LEN];
    hk.expand(b"daal.custody.v1.dev", &mut out).unwrap();
    out
}

fn read_or_create_binding_salt(base: &Path) -> Result<[u8; BINDING_SALT_LEN]> {
    let path = base.join("binding.salt");
    if path.exists() {
        let bytes = std::fs::read(&path)?;
        if bytes.len() != BINDING_SALT_LEN {
            return Err(CustodyError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("binding salt length {} != {}", bytes.len(), BINDING_SALT_LEN),
            )));
        }
        let mut out = [0u8; BINDING_SALT_LEN];
        out.copy_from_slice(&bytes);
        return Ok(out);
    }
    let mut salt = [0u8; BINDING_SALT_LEN];
    AeadRng.fill_bytes(&mut salt);
    std::fs::write(&path, salt)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(salt)
}

/// Sanitize an alias into a safe filename. Replaces characters
/// that are problematic on any filesystem with underscores.
fn sanitize(alias: &str) -> String {
    alias
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Helper used by callers that want a `Zeroizing<Vec<u8>>` rather
/// than a raw `Vec<u8>`. Keeps `recipient_identity` succinct.
pub fn get_zeroizing(c: &dyn DeviceCustody, alias: &str) -> Result<Zeroizing<Vec<u8>>> {
    c.get(alias).map(Zeroizing::new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn static_test_round_trip() {
        let dir = tempdir().unwrap();
        let c = FileCustody::static_test(dir.path()).unwrap();
        c.put("daal/x", b"hello").unwrap();
        assert_eq!(c.get("daal/x").unwrap(), b"hello");
    }

    #[test]
    fn session_passphrase_round_trip() {
        let dir = tempdir().unwrap();
        let c = FileCustody::session_passphrase(dir.path()).unwrap();
        assert!(!c.is_unlocked());
        // Operations fail while locked.
        assert!(matches!(c.put("a", b"x").unwrap_err(), CustodyError::Locked));
        c.unlock(Some("correct horse battery staple")).unwrap();
        assert!(c.is_unlocked());
        c.put("a", b"super-secret").unwrap();
        assert_eq!(c.get("a").unwrap(), b"super-secret");
        c.lock();
        assert!(!c.is_unlocked());
        assert!(matches!(c.get("a").unwrap_err(), CustodyError::Locked));
    }

    #[test]
    fn session_passphrase_wrong_passphrase_fails_decrypt() {
        let dir = tempdir().unwrap();
        let c = FileCustody::session_passphrase(dir.path()).unwrap();
        c.unlock(Some("correct horse battery staple")).unwrap();
        c.put("a", b"super-secret").unwrap();
        c.lock();
        c.unlock(Some("not the same passphrase")).unwrap();
        // Now is_unlocked is true (we have *a* key in memory) but
        // the key doesn't decrypt prior ciphertext → BindingMismatch
        // from the AEAD tag failure.
        let err = c.get("a").unwrap_err();
        assert!(matches!(err, CustodyError::BindingMismatch), "got: {err:?}");
    }

    #[test]
    fn unlock_none_on_session_is_locked() {
        let dir = tempdir().unwrap();
        let c = FileCustody::session_passphrase(dir.path()).unwrap();
        // No passphrase → still locked; unlock(None) cannot conjure one.
        assert!(matches!(c.unlock(None).unwrap_err(), CustodyError::Locked));
    }

    #[test]
    fn unlock_none_on_static_is_ok() {
        let dir = tempdir().unwrap();
        let c = FileCustody::static_test(dir.path()).unwrap();
        // Hardware-style providers materialise the DWK on unlock(None).
        c.unlock(None).unwrap();
        assert!(c.is_unlocked());
    }

    #[test]
    fn forget_idempotent() {
        let dir = tempdir().unwrap();
        let c = FileCustody::static_test(dir.path()).unwrap();
        c.forget("never-set").unwrap();
        c.put("a", b"x").unwrap();
        c.forget("a").unwrap();
        assert!(matches!(c.get("a").unwrap_err(), CustodyError::NotFound(_)));
    }

    #[test]
    fn forget_prefix_wipes_matching_aliases() {
        let dir = tempdir().unwrap();
        let c = FileCustody::static_test(dir.path()).unwrap();
        c.put("daal/priv", b"a").unwrap();
        c.put("daal/old", b"b").unwrap();
        c.put("other/x", b"c").unwrap();
        let n = c.forget_prefix("daal/").unwrap();
        assert_eq!(n, 2);
        assert!(matches!(
            c.get("daal/priv").unwrap_err(),
            CustodyError::NotFound(_)
        ));
        assert_eq!(c.get("other/x").unwrap(), b"c");
    }

    #[test]
    fn forget_prefix_empty_wipes_all() {
        let dir = tempdir().unwrap();
        let c = FileCustody::static_test(dir.path()).unwrap();
        c.put("daal/priv", b"a").unwrap();
        c.put("other/x", b"c").unwrap();
        let n = c.forget_prefix("").unwrap();
        assert_eq!(n, 2);
        assert!(matches!(
            c.get("other/x").unwrap_err(),
            CustodyError::NotFound(_)
        ));
    }

    #[test]
    fn binding_salt_is_persisted_and_reused() {
        let dir = tempdir().unwrap();
        let c1 = FileCustody::static_test(dir.path()).unwrap();
        let salt1 = c1.binding_salt;
        drop(c1);
        let c2 = FileCustody::static_test(dir.path()).unwrap();
        assert_eq!(c2.binding_salt, salt1);
    }

    #[test]
    fn binding_mismatch_when_blob_copied_to_other_machine() {
        // Simulate: machine 1 has binding salt S1, blob B sealed
        // under DWK ⊕ HKDF(S1). Machine 2 has a different binding
        // salt S2. Copying B to machine 2 must fail to decrypt.
        let dir1 = tempdir().unwrap();
        let c1 = FileCustody::static_test(dir1.path()).unwrap();
        c1.put("priv", b"secret-key-material").unwrap();
        let blob = std::fs::read_to_string(c1.alias_path("priv")).unwrap();

        let dir2 = tempdir().unwrap();
        std::fs::create_dir_all(dir2.path().join("custody")).unwrap();
        std::fs::write(
            dir2.path().join("custody").join("binding.salt"),
            [0xAB; BINDING_SALT_LEN],
        )
        .unwrap();
        let c2 = FileCustody::static_test(dir2.path()).unwrap();
        std::fs::create_dir_all(c2.base_dir.join("aliases")).unwrap();
        std::fs::write(c2.alias_path("priv"), blob.as_bytes()).unwrap();

        let err = c2.get("priv").unwrap_err();
        assert!(matches!(err, CustodyError::BindingMismatch), "got: {err:?}");
    }

    #[test]
    fn level_for_filecustody_is_session_passphrase_for_test_providers() {
        let dir = tempdir().unwrap();
        let c = FileCustody::static_test(dir.path()).unwrap();
        // We never lie to the UI about hardware backing.
        assert_eq!(c.level(), CustodyLevel::SessionPassphrase);
    }

    #[test]
    fn get_zeroizing_helper_round_trips() {
        let dir = tempdir().unwrap();
        let c = FileCustody::static_test(dir.path()).unwrap();
        c.put("k", b"value").unwrap();
        let z = get_zeroizing(&c, "k").unwrap();
        assert_eq!(z.as_slice(), b"value");
    }
}
