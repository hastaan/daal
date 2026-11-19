use serde::{Deserialize, Serialize};

/// Request payload for the `plugin:daal-platform|vpn_start` invoke.
///
/// `rename_all = "camelCase"` is required: the JS side invokes with
/// `{ request: { routeId } }` (the Tauri convention), so without the
/// rename this struct rejects the payload with "missing field
/// `route_id`" and the Connect button fails.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
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
    /// The last route switch that did not take, if there is one to
    /// report: the person asked for `route_id`, it was refused or
    /// carried nothing, and the service stayed on (or went back to)
    /// `kept_route_id`. Cleared by the next connect that succeeds and
    /// by a disconnect. The engine's own diagnostics lose this when the
    /// old route is reconnected, which is why it is kept here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_switch: Option<SwitchNote>,
}

/// See `VpnStatusResponse::last_switch`. Ids and closed codes only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwitchNote {
    /// The route that was asked for and did not come up.
    pub route_id: String,
    /// The route still connected afterwards; `None` if none is.
    #[serde(default)]
    pub kept_route_id: Option<String>,
    /// `"refused"` (the engine would not try it) or `"failed"` (it was
    /// tried and carried nothing).
    pub outcome: String,
    /// The engine's refusal code (`cooldown`, `revoked`, `expired`,
    /// `needs_new_file`, `other`) or failure category; may be empty.
    #[serde(default)]
    pub reason: String,
}
