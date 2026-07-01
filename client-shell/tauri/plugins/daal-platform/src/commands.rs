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

#[command]
pub async fn vpn_start<R: Runtime>(
    app: AppHandle<R>,
    request: VpnStartRequest,
) -> Result<VpnStartResponse> {
    app.platform().vpn_start(&request.route_id)
}

#[command]
pub async fn vpn_stop<R: Runtime>(app: AppHandle<R>) -> Result<VpnStopResponse> {
    app.platform().vpn_stop()
}

#[command]
pub async fn vpn_status<R: Runtime>(app: AppHandle<R>) -> Result<VpnStatusResponse> {
    app.platform().vpn_status()
}
