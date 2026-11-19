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
//! desktop).

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
