use serde::{Deserialize, Serialize};

/// Request payload for the `plugin:daal-platform|vpn_start` invoke.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnStartRequest {
    /// Route id chosen via `engine_set_route` semantics. The plugin
    /// forwards this string verbatim through to the Kotlin
    /// `DaalVpnService.onStartCommand` extra so the service can
    /// activate the right outbound block.
    pub route_id: String,
}

/// Response payload for `vpn_start`. `requires_consent` is set when
/// the host has not yet completed the system VPN consent dialog;
/// the UI must wait for the consent Activity to return before
/// retrying.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnStartResponse {
    pub applied: bool,
    pub platform: String,
    #[serde(default)]
    pub requires_consent: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnStopResponse {
    pub applied: bool,
    pub platform: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnStatusResponse {
    pub connected: bool,
    pub route_id: Option<String>,
    pub platform: String,
}
