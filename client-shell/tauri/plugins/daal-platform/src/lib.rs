//! tauri-plugin-daal-platform
//!
//! Mobile-only platform glue. On Android the plugin owns the
//! `VpnService` lifecycle and the Kotlin → JNI → engine ABI bridge
//! that hands the TUN file descriptor to libdaalcore's in-process
//! sing-box driver. On desktop the plugin is a deliberate no-op:
//! desktop data-plane integration runs in the same process via the
//! `daal-tun-helper` SCM_RIGHTS path and reaches the engine without
//! going through a plugin command.
//!
//! Commands (declared in build.rs and exposed in `commands.rs`):
//!   - `vpn_start(route_id)` → on Android, prepares the VPN consent
//!     prompt if needed and starts `DaalVpnService` with the chosen
//!     route. An absent or empty `route_id` is an AUTOMATIC connect:
//!     the service asks the engine to pick a route, try it and move on. The Kotlin side `Builder.establish()`s the TUN, detaches
//!     the fd, and forwards it to the engine via
//!     `engine_set_tun_fd`. Desktop branch returns Ok with
//!     `{ "applied": true, "platform": "desktop" }`.
//!   - `vpn_stop()` → on Android, stops `DaalVpnService` (which calls
//!     `engine_clear_tun_fd`). Desktop is a no-op.
//!   - `vpn_status()` → returns a small JSON status (connected /
//!     idle / route_id).
//!
//! Also reached from the app's own commands (not invoked from the page
//! as plugin commands): `PlatformHandle::secure_screen(on)` (PB-20,
//! FLAG_SECURE while the recovery words are on screen; a no-op on
//! desktop), `PlatformHandle::field_probe_watch(on)` (the network
//! test's start facts and its watch; `None` on desktop) and
//! `PlatformHandle::clipboard_read()` / `clipboard_write(text)` (Paste
//! and Copy, which the Android web view's own clipboard refuses; `None`
//! / `false` on desktop, where the page's clipboard works).

use tauri::{
    plugin::{Builder, TauriPlugin},
    Manager, Runtime,
};

pub mod commands;
pub mod error;
pub mod models;

#[cfg(mobile)]
mod mobile;

#[cfg(mobile)]
use mobile::Platform;

pub use error::{Error, Result};

pub trait PlatformExt<R: Runtime> {
    fn platform(&self) -> PlatformHandle<R>;
}

/// `PlatformHandle` is the runtime accessor command handlers reach
/// through. On Android it wraps the registered Tauri-Mobile plugin
/// instance (from `mobile.rs`); on desktop it is a deterministic
/// no-op so the same command surface can be invoked from a frontend
/// build that doesn't distinguish targets.
pub struct PlatformHandle<R: Runtime> {
    #[cfg(mobile)]
    inner: Platform<R>,
    // PhantomData<fn() -> R> is Send + Sync regardless of R, which lets
    // the desktop branch call `app.manage(handle)` without forcing
    // every Runtime down the stack to be Sync.
    #[cfg(not(mobile))]
    _marker: std::marker::PhantomData<fn() -> R>,
}

impl<R: Runtime> Clone for PlatformHandle<R> {
    fn clone(&self) -> Self {
        Self {
            #[cfg(mobile)]
            inner: self.inner.clone(),
            #[cfg(not(mobile))]
            _marker: std::marker::PhantomData,
        }
    }
}

#[cfg(mobile)]
impl<R: Runtime> PlatformHandle<R> {
    /// `route_id` "" = connect automatically.
    pub fn vpn_start(&self, route_id: &str) -> Result<models::VpnStartResponse> {
        self.inner.vpn_start(route_id)
    }
    pub fn vpn_stop(&self) -> Result<models::VpnStopResponse> {
        self.inner.vpn_stop()
    }
    pub fn vpn_status(&self) -> Result<models::VpnStatusResponse> {
        self.inner.vpn_status()
    }
    /// PB-20: FLAG_SECURE on the activity window while `on`.
    pub fn secure_screen(&self, on: bool) -> Result<()> {
        self.inner.secure_screen(on).map(|_| ())
    }
    /// Paste: the clipboard's text, `Some("")` when there is none. The
    /// text may be a key: never logged.
    pub fn clipboard_read(&self) -> Result<Option<String>> {
        self.inner.clipboard_read().map(|r| Some(r.text))
    }
    /// Copy: `text` onto the clipboard; true once it is there.
    pub fn clipboard_write(&self, text: &str) -> Result<bool> {
        self.inner.clipboard_write(text).map(|r| r.written)
    }
    /// Network test: what the start needs from the phone, and the watch
    /// for the length of the run (`on`) or its end. `None` = nothing to
    /// tell (desktop).
    pub fn field_probe_watch(&self, on: bool) -> Result<Option<models::FieldProbeHost>> {
        self.inner.field_probe_watch(on).map(Some)
    }
    /// Optional add-ons, Google update channel, Path A
    /// (docs/optional-addons-plan.md §3.3, item G3): a one-shot OAuth
    /// access token for `scopes` from Play services' authorization
    /// client (`GoogleAuth.kt`). The caller uses it for the Apps Script
    /// API calls and drops it; nothing is stored. Errors start with an
    /// `E_GOOGLE_*` code (`E_GOOGLE_NOT_CONFIGURED` in a build without
    /// the Android OAuth client, `E_GOOGLE_SIGN_IN_CANCELLED`,
    /// `E_GOOGLE_NO_PLAY_SERVICES`, `E_GOOGLE_UNAUTHORIZED`).
    pub fn google_authorize(&self, scopes: &[&str]) -> Result<Option<String>> {
        self.inner.google_authorize(scopes)
    }
    /// Whether this build has the Android OAuth client, so "Sign in with
    /// Google" may be offered at all. False hides it.
    pub fn google_sign_in_configured(&self) -> bool {
        self.inner.google_sign_in_configured()
    }
}

#[cfg(not(mobile))]
impl<R: Runtime> PlatformHandle<R> {
    pub fn vpn_start(&self, _route_id: &str) -> Result<models::VpnStartResponse> {
        Ok(models::VpnStartResponse {
            applied: true,
            platform: "desktop".into(),
            requires_consent: false,
        })
    }
    pub fn vpn_stop(&self) -> Result<models::VpnStopResponse> {
        Ok(models::VpnStopResponse { applied: true, platform: "desktop".into() })
    }
    pub fn vpn_status(&self) -> Result<models::VpnStatusResponse> {
        Ok(models::VpnStatusResponse {
            connected: false,
            route_id: None,
            platform: "desktop".into(),
            last_switch: None,
            auto: false,
            holding: false,
            running: false,
        })
    }
    /// PB-20: the desktop window has no capture flag; nothing to do.
    pub fn secure_screen(&self, _on: bool) -> Result<()> {
        Ok(())
    }
    /// Desktop: the page's own clipboard works; `None` says so and the
    /// page reads it itself.
    pub fn clipboard_read(&self) -> Result<Option<String>> {
        Ok(None)
    }
    /// Desktop: nothing written here (`false`); the page writes it itself.
    pub fn clipboard_write(&self, _text: &str) -> Result<bool> {
        Ok(false)
    }
    /// Network test: the desktop shell has no network watch; the engine
    /// is told nothing extra.
    pub fn field_probe_watch(&self, _on: bool) -> Result<Option<models::FieldProbeHost>> {
        Ok(None)
    }
    /// Optional add-ons, Google Path A: desktop has no platform sign-in;
    /// `None` tells `daal_wizard::addon_google::account_sign_in` to sign
    /// in through the system browser (loopback + PKCE) itself.
    pub fn google_authorize(&self, _scopes: &[&str]) -> Result<Option<String>> {
        Ok(None)
    }
    /// Desktop has no platform sign-in; whether the desktop client is
    /// configured is `daal_wizard::addon_google::desktop_sign_in_configured`.
    pub fn google_sign_in_configured(&self) -> bool {
        false
    }
}

impl<R: Runtime, T: Manager<R>> PlatformExt<R> for T {
    fn platform(&self) -> PlatformHandle<R> {
        self.state::<PlatformHandle<R>>().inner().clone()
    }
}

/// Plugin init. Registered from `src-tauri/src/lib.rs`:
///
/// ```ignore
/// .plugin(tauri_plugin_daal_platform::init())
/// ```
pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("daal-platform")
        .invoke_handler(tauri::generate_handler![
            commands::vpn_start,
            commands::vpn_stop,
            commands::vpn_status,
        ])
        .setup(|app, _api| {
            #[cfg(mobile)]
            let handle = PlatformHandle {
                inner: mobile::init(app, _api)?,
            };
            #[cfg(not(mobile))]
            let handle = PlatformHandle::<R> {
                _marker: std::marker::PhantomData,
            };
            app.manage(handle);
            Ok(())
        })
        .build()
}
