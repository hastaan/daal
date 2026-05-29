//! Device Custody v1 — shell-side DWK providers.
//!
//! `daal-wizard` owns the custody *mechanism* (`FileCustody`: the
//! per-alias AES-GCM blob store + machine-binding mix) but stays
//! `forbid(unsafe_code)`, so the platform key sources that need
//! `unsafe` JNI live here in the Tauri shell.
//!
//! Providers:
//!   - desktop (`not(android)`): [`KeyringDwk`] — the 32-byte
//!     Device Wrap Key lives in the OS keyring (macOS Keychain,
//!     Windows Credential Manager/DPAPI, Linux libsecret).
//!     Level: `OsKeystore`.
//!   - Android: [`AndroidKeystoreDwk`] — the DWK is wrapped by an
//!     AES key held in the AndroidKeyStore (`DaalKeystore.kt`).
//!     Level: `Hardware` when the key is inside secure hardware,
//!     else `OsKeystore`.
//!
//! If the platform provider can't initialise (no libsecret on a
//! headless box, Keystore unavailable on a broken emulator) we
//! fall back to `FileCustody::session_passphrase` — the user sets
//! a passphrase once per session and the UI honestly shows the
//! `SessionPassphrase` level. We **never** silently downgrade to a
//! machine-id-only wrap.

use std::path::Path;
use std::sync::{Arc, Mutex};

use daal_wizard::device_custody::{
    CustodyError, CustodyLevel, DeviceCustody, DwkProvider, FileCustody,
};

/// Keyring identifiers for the desktop DWK.
#[cfg(not(target_os = "android"))]
const KEYRING_SERVICE: &str = "daal";
#[cfg(not(target_os = "android"))]
const KEYRING_DWK_USER: &str = "dwk-v1";

const DWK_LEN: usize = 32;

/// Build the live `DeviceCustody` for this platform, with a
/// session-passphrase fallback. Never panics on provider failure —
/// it degrades to passphrase custody instead.
///
/// On Android we *skip* the eager `ensure_dwk()` probe at startup
/// because `build_wizard_ctx()` runs on a Rust worker thread (the
/// Tauri/Wry setup) **before** `MainActivity.onCreate` has cached
/// the app classloader. A native `find_class("org/daal/desktop/...")`
/// from such a thread uses the bootstrap classloader and crashes
/// with `ClassNotFoundException: org.daal.desktop.DaalKeystore`
/// (FRP-14 Phase B2c regression observed on Samsung One UI 16).
///
/// Desktop probes eagerly (no classloader concern) so a broken
/// keyring degrades to session-passphrase up front.
pub fn build_device_custody(state_dir: &Path) -> Arc<dyn DeviceCustody> {
    if let Some(provider) = try_platform_provider() {
        if cfg!(target_os = "android") {
            // Skip the JNI probe: classloader isn't set up yet.
            // First real recipient-identity call (from a Tauri
            // command thread post-activity-init) will surface any
            // error and the UI can react then.
            match FileCustody::with_provider(state_dir, provider) {
                Ok(fc) => return Arc::new(fc),
                Err(e) => eprintln!("[custody] FileCustody init failed: {e}; falling back"),
            }
        } else {
            // Desktop: probe once so an unavailable keystore degrades
            // cleanly rather than failing on the first identity op.
            match provider.ensure_dwk() {
                Ok(mut dwk) => {
                    use zeroize::Zeroize;
                    dwk.zeroize();
                    match FileCustody::with_provider(state_dir, provider) {
                        Ok(fc) => return Arc::new(fc),
                        Err(e) => {
                            eprintln!("[custody] FileCustody init failed: {e}; falling back")
                        }
                    }
                }
                Err(e) => eprintln!(
                    "[custody] platform keystore unavailable: {e}; using session passphrase"
                ),
            }
        }
    }
    Arc::new(
        FileCustody::session_passphrase(state_dir)
            .expect("session-passphrase custody must initialise"),
    )
}

#[cfg(not(target_os = "android"))]
fn try_platform_provider() -> Option<Arc<dyn DwkProvider>> {
    Some(Arc::new(KeyringDwk::new()))
}

#[cfg(target_os = "android")]
fn try_platform_provider() -> Option<Arc<dyn DwkProvider>> {
    Some(Arc::new(AndroidKeystoreDwk::new()))
}

// ---------------------------------------------------------------------
// Desktop: OS keyring DWK.
// ---------------------------------------------------------------------

#[cfg(not(target_os = "android"))]
pub struct KeyringDwk {
    cached: Mutex<Option<[u8; DWK_LEN]>>,
}

#[cfg(not(target_os = "android"))]
impl KeyringDwk {
    pub fn new() -> Self {
        Self {
            cached: Mutex::new(None),
        }
    }

    fn load_or_create(&self) -> Result<[u8; DWK_LEN], CustodyError> {
        use base64::{engine::general_purpose::STANDARD as B64, Engine};
        let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_DWK_USER)
            .map_err(|e| CustodyError::Backend(format!("keyring entry: {e}")))?;
        match entry.get_password() {
            Ok(b64) => {
                let raw = B64
                    .decode(b64.as_bytes())
                    .map_err(|e| CustodyError::Backend(format!("dwk base64: {e}")))?;
                if raw.len() != DWK_LEN {
                    return Err(CustodyError::Backend(format!(
                        "stored dwk is {} bytes, want {DWK_LEN}",
                        raw.len()
                    )));
                }
                let mut out = [0u8; DWK_LEN];
                out.copy_from_slice(&raw);
                Ok(out)
            }
            Err(keyring::Error::NoEntry) => {
                use rand::RngCore;
                let mut dwk = [0u8; DWK_LEN];
                rand::rngs::OsRng.fill_bytes(&mut dwk);
                let b64 = B64.encode(dwk);
                entry
                    .set_password(&b64)
                    .map_err(|e| CustodyError::Backend(format!("keyring set: {e}")))?;
                Ok(dwk)
            }
            Err(e) => Err(CustodyError::Backend(format!("keyring get: {e}"))),
        }
    }
}

#[cfg(not(target_os = "android"))]
impl DwkProvider for KeyringDwk {
    fn level(&self) -> CustodyLevel {
        CustodyLevel::OsKeystore
    }
    fn is_ready(&self) -> bool {
        true
    }
    fn ensure_dwk(&self) -> Result<[u8; DWK_LEN], CustodyError> {
        if let Some(k) = *self.cached.lock().unwrap() {
            return Ok(k);
        }
        let dwk = self.load_or_create()?;
        *self.cached.lock().unwrap() = Some(dwk);
        Ok(dwk)
    }
    fn set_passphrase(&self, _passphrase: &str) -> Result<(), CustodyError> {
        Ok(())
    }
    fn clear(&self) {
        use zeroize::Zeroize;
        if let Some(mut k) = self.cached.lock().unwrap().take() {
            k.zeroize();
        }
    }
}

// ---------------------------------------------------------------------
// Android: AndroidKeyStore-wrapped DWK via JNI to DaalKeystore.kt.
// ---------------------------------------------------------------------

#[cfg(target_os = "android")]
pub struct AndroidKeystoreDwk {
    cached: Mutex<Option<[u8; DWK_LEN]>>,
    hardware: Mutex<Option<bool>>,
}

#[cfg(target_os = "android")]
impl AndroidKeystoreDwk {
    pub fn new() -> Self {
        Self {
            cached: Mutex::new(None),
            hardware: Mutex::new(None),
        }
    }

    /// Calls `DaalKeystore.getOrCreateDwk(): ByteArray` via JNI.
    ///
    /// Any JVM exception raised inside the Kotlin call (KeyStore
    /// unavailable, file I/O failure, etc.) is **described + cleared**
    /// before we return so the Tauri bridge doesn't propagate a
    /// half-raised exception to the WebView with the opaque
    /// "Java exception was raised during method invocation" toast.
    fn jni_get_or_create_dwk(&self) -> Result<[u8; DWK_LEN], CustodyError> {
        let ctx = ndk_context::android_context();
        let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) }
            .map_err(|e| CustodyError::Backend(format!("attach JavaVM: {e}")))?;
        let mut env = vm
            .attach_current_thread()
            .map_err(|e| CustodyError::Backend(format!("attach thread: {e}")))?;
        let class = env.find_class("org/daal/desktop/DaalKeystore").map_err(|e| {
            check_and_clear_exception(&mut env);
            CustodyError::Backend(format!("find DaalKeystore: {e}"))
        })?;
        let ret = env
            .call_static_method(&class, "getOrCreateDwk", "()[B", &[])
            .map_err(|e| {
                check_and_clear_exception(&mut env);
                CustodyError::Backend(format!("getOrCreateDwk: {e}"))
            })?;
        let obj = ret
            .l()
            .map_err(|e| CustodyError::Backend(format!("getOrCreateDwk ret: {e}")))?;
        let arr: jni::objects::JByteArray = obj.into();
        let bytes = env
            .convert_byte_array(&arr)
            .map_err(|e| CustodyError::Backend(format!("convert dwk: {e}")))?;
        check_and_clear_exception(&mut env);
        drop(env);
        std::mem::forget(vm);
        if bytes.len() != DWK_LEN {
            return Err(CustodyError::Backend(format!(
                "android dwk is {} bytes, want {DWK_LEN}",
                bytes.len()
            )));
        }
        let mut out = [0u8; DWK_LEN];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    /// Calls `DaalKeystore.isHardwareBacked(): Boolean` via JNI.
    /// Any pending JVM exception is cleared before return.
    fn jni_is_hardware_backed(&self) -> bool {
        let run = || -> Result<bool, CustodyError> {
            let ctx = ndk_context::android_context();
            let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) }
                .map_err(|e| CustodyError::Backend(format!("attach JavaVM: {e}")))?;
            let mut env = vm
                .attach_current_thread()
                .map_err(|e| CustodyError::Backend(format!("attach thread: {e}")))?;
            let class = env.find_class("org/daal/desktop/DaalKeystore").map_err(|e| {
                check_and_clear_exception(&mut env);
                CustodyError::Backend(format!("find DaalKeystore: {e}"))
            })?;
            let ret = env
                .call_static_method(&class, "isHardwareBacked", "()Z", &[])
                .and_then(|v| v.z())
                .map_err(|e| {
                    check_and_clear_exception(&mut env);
                    CustodyError::Backend(format!("isHardwareBacked: {e}"))
                })?;
            check_and_clear_exception(&mut env);
            drop(env);
            std::mem::forget(vm);
            Ok(ret)
        };
        run().unwrap_or(false)
    }
}

/// Best-effort: if the JVM has a pending exception, describe it to
/// logcat and clear it so the calling Tauri command can return its
/// own structured `String` error instead of the WebView seeing a
/// stale exception flag and rendering "Java exception was raised
/// during method invocation".
#[cfg(target_os = "android")]
fn check_and_clear_exception(env: &mut jni::JNIEnv) {
    if let Ok(true) = env.exception_check() {
        let _ = env.exception_describe();
        let _ = env.exception_clear();
    }
}

#[cfg(target_os = "android")]
impl DwkProvider for AndroidKeystoreDwk {
    fn level(&self) -> CustodyLevel {
        let mut g = self.hardware.lock().unwrap();
        let hw = match *g {
            Some(v) => v,
            None => {
                let v = self.jni_is_hardware_backed();
                *g = Some(v);
                v
            }
        };
        if hw {
            CustodyLevel::Hardware
        } else {
            CustodyLevel::OsKeystore
        }
    }
    fn is_ready(&self) -> bool {
        true
    }
    fn ensure_dwk(&self) -> Result<[u8; DWK_LEN], CustodyError> {
        if let Some(k) = *self.cached.lock().unwrap() {
            return Ok(k);
        }
        let dwk = self.jni_get_or_create_dwk()?;
        *self.cached.lock().unwrap() = Some(dwk);
        Ok(dwk)
    }
    fn set_passphrase(&self, _passphrase: &str) -> Result<(), CustodyError> {
        Ok(())
    }
    fn clear(&self) {
        use zeroize::Zeroize;
        if let Some(mut k) = self.cached.lock().unwrap().take() {
            k.zeroize();
        }
    }
}
