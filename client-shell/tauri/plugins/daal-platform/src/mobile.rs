//! Tauri Mobile registration. On Android we attach to the Kotlin
//! plugin class `DaalPlatformPlugin` (package `org.daal.desktop.platform`);
//! iOS support lands in a follow-up phase.
//!
//! The three `vpn_*` methods funnel into `PluginHandle::run_mobile_plugin`
//! with the matching command name; the Kotlin side declares the same
//! names via `@Command` annotations.

use serde::de::DeserializeOwned;
use tauri::{
    plugin::{PluginApi, PluginHandle},
    AppHandle, Runtime,
};

use crate::error::Result;
use crate::models::{VpnStartResponse, VpnStatusResponse, VpnStopResponse};

#[cfg(target_os = "android")]
const PLUGIN_IDENTIFIER: &str = "org.daal.desktop.platform";

#[cfg(target_os = "ios")]
tauri::ios_plugin_binding!(init_plugin_daal_platform);

pub fn init<R: Runtime, C: DeserializeOwned>(
    _app: &AppHandle<R>,
    api: PluginApi<R, C>,
) -> Result<Platform<R>> {
    #[cfg(target_os = "android")]
    let handle = api.register_android_plugin(PLUGIN_IDENTIFIER, "DaalPlatformPlugin")?;
    #[cfg(target_os = "ios")]
    let handle = api.register_ios_plugin(init_plugin_daal_platform)?;
    Ok(Platform(handle))
}

#[derive(Debug)]
pub struct Platform<R: Runtime>(PluginHandle<R>);

impl<R: Runtime> Clone for Platform<R> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

#[derive(Debug, serde::Serialize)]
struct StartArgs<'a> {
    route_id: &'a str,
}

impl<R: Runtime> Platform<R> {
    pub fn vpn_start(&self, route_id: &str) -> Result<VpnStartResponse> {
        Ok(self.0.run_mobile_plugin::<VpnStartResponse>(
            "vpnStart",
            StartArgs { route_id },
        )?)
    }
    pub fn vpn_stop(&self) -> Result<VpnStopResponse> {
        Ok(self.0.run_mobile_plugin::<VpnStopResponse>("vpnStop", ())?)
    }
    pub fn vpn_status(&self) -> Result<VpnStatusResponse> {
        Ok(self.0.run_mobile_plugin::<VpnStatusResponse>("vpnStatus", ())?)
    }
}
