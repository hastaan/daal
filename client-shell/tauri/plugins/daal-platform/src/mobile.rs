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

use crate::error::{Error, Result};
use crate::models::{
    ClipboardReadResponse, ClipboardWriteRequest, ClipboardWriteResponse, FieldProbeHost,
    FieldProbeWatchRequest, SecureScreenRequest, SecureScreenResponse, VpnStartResponse,
    VpnStatusResponse, VpnStopResponse,
};

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
    // Optional add-ons, Google update channel, Path A: Play services'
    // authorization client (GoogleAuth.kt), reached through the SAME
    // plugin. A second register_android_plugin under this identifier
    // replaces the first on the Kotlin side: every DaalPlatformPlugin
    // command (VPN, secure screen, insets) then failed on the phone.
    #[cfg(target_os = "android")]
    let google = None;
    #[cfg(target_os = "ios")]
    let handle = api.register_ios_plugin(init_plugin_daal_platform)?;
    #[cfg(target_os = "ios")]
    let google = None;
    Ok(Platform(handle, google))
}

/// The main plugin, and the Google sign-in plugin where there is one.
#[derive(Debug)]
pub struct Platform<R: Runtime>(PluginHandle<R>, Option<PluginHandle<R>>);

impl<R: Runtime> Clone for Platform<R> {
    fn clone(&self) -> Self {
        Self(self.0.clone(), self.1.clone())
    }
}

/// The Android OAuth client the owner registered (package name plus the
/// release signing SHA-1) is matched by Play services, not by this id;
/// the id's presence at build time says one exists, and gates Path A.
const ANDROID_CLIENT_ID: Option<&str> = option_env!("DAAL_GOOGLE_ANDROID_CLIENT_ID");

const NOT_CONFIGURED: &str =
    "E_GOOGLE_NOT_CONFIGURED: signing in with Google is not set up in this build; add the script by hand";

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct GoogleAuthorizeArgs<'a> {
    scopes: &'a [&'a str],
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct GoogleAuthorizeResponse {
    #[serde(default)]
    access_token: String,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct StartArgs<'a> {
    // Serialized as `routeId` to match the Kotlin plugin's
    // `@InvokeArg VpnStartArgs.routeId` (Tauri Mobile parses args as
    // camelCase). Without the rename the forwarded field is `route_id`
    // and the Kotlin lateinit `routeId` is never set, failing the
    // post-consent start with "lateinit property routeId has not been
    // initialized".
    //
    // "" = connect automatically (the Kotlin side treats an empty or
    // absent routeId as "let the engine pick").
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
    pub fn field_probe_watch(&self, on: bool) -> Result<FieldProbeHost> {
        Ok(self
            .0
            .run_mobile_plugin::<FieldProbeHost>("fieldProbeWatch", FieldProbeWatchRequest { on })?)
    }
    /// Path A: a one-shot access token for `scopes`. The Kotlin side
    /// rejects with a message that starts with an `E_GOOGLE_*` code;
    /// that code is what reaches the wizard. The token is handed back
    /// once and kept nowhere here.
    /// A build with the Android OAuth client may offer Path A.
    pub fn google_sign_in_configured(&self) -> bool {
        ANDROID_CLIENT_ID.is_some_and(|s| !s.trim().is_empty())
    }
    pub fn google_authorize(&self, scopes: &[&str]) -> Result<Option<String>> {
        if !self.google_sign_in_configured() {
            return Err(Error::Other(NOT_CONFIGURED.into()));
        }
        #[cfg(not(target_os = "android"))]
        if self.1.is_none() {
            return Err(Error::Other(NOT_CONFIGURED.into()));
        }
        let google = &self.0;
        match google.run_mobile_plugin::<GoogleAuthorizeResponse>(
            "googleAuthorize",
            GoogleAuthorizeArgs { scopes },
        ) {
            Ok(r) if !r.access_token.is_empty() => Ok(Some(r.access_token)),
            Ok(_) => Err(Error::Other(
                "E_GOOGLE_UNAUTHORIZED: Google gave no access".into(),
            )),
            Err(e) => {
                let s = e.to_string();
                Err(Error::Other(match s.find("E_GOOGLE_") {
                    Some(i) => s[i..].trim_end_matches(['"', '}', ' ']).to_string(),
                    None => format!("E_GOOGLE_UNAUTHORIZED: {s}"),
                }))
            }
        }
    }
    pub fn secure_screen(&self, on: bool) -> Result<SecureScreenResponse> {
        Ok(self
            .0
            .run_mobile_plugin::<SecureScreenResponse>("secureScreen", SecureScreenRequest { on })?)
    }
    pub fn clipboard_read(&self) -> Result<ClipboardReadResponse> {
        Ok(self
            .0
            .run_mobile_plugin::<ClipboardReadResponse>("clipboardRead", ())?)
    }
    pub fn clipboard_write(&self, text: &str) -> Result<ClipboardWriteResponse> {
        Ok(self.0.run_mobile_plugin::<ClipboardWriteResponse>(
            "clipboardWrite",
            ClipboardWriteRequest { text: text.to_string() },
        )?)
    }
}
