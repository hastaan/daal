//! `#[tauri::command]` surface for the plugin. The frontend invokes
//! these as `plugin:daal-platform|vpn_start` etc.; on Android the
//! call routes into the Kotlin `DaalPlatformPlugin` via Tauri Mobile,
//! and the Kotlin side talks to `DaalVpnService` and the JNI bridge
//! into `libdaalcore.so`'s `engine_set_tun_fd` / `engine_clear_tun_fd`
//! / `engine_register_protect_callback` symbols. On desktop the
//! handlers short-circuit (the data plane is already in-process).

use tauri::{command, AppHandle, Runtime};

use crate::models::{VpnStartRequest, VpnStartResponse, VpnStatusResponse, VpnStopResponse};
use crate::{PlatformExt, Result};

/// One `warn` line for a platform command that fails (the reason goes
/// to the webview as before; this is the copy that reaches logcat).
/// The error is the plugin's own — a Tauri/JNI failure or the Kotlin
/// side's rejection text — and carries a route id at most.
fn logged<T>(command: &'static str, r: Result<T>) -> Result<T> {
    if let Err(e) = &r {
        log::warn!("command plugin:daal-platform|{command} failed: {e}");
    }
    r
}

#[command]
pub async fn vpn_start<R: Runtime>(
    app: AppHandle<R>,
    request: VpnStartRequest,
) -> Result<VpnStartResponse> {
    logged("vpn_start", app.platform().vpn_start(&request.route_id))
}

#[command]
pub async fn vpn_stop<R: Runtime>(app: AppHandle<R>) -> Result<VpnStopResponse> {
    logged("vpn_stop", app.platform().vpn_stop())
}

#[command]
pub async fn vpn_status<R: Runtime>(app: AppHandle<R>) -> Result<VpnStatusResponse> {
    logged("vpn_status", app.platform().vpn_status())
}
