use serde::{Deserialize, Serialize};

/// Request payload for the `plugin:daal-platform|vpn_start` invoke.
///
/// `rename_all = "camelCase"` is required: the JS side invokes with
/// `{ request: { routeId } }` (the Tauri convention), so without the
/// rename this struct rejects the payload with "missing field
/// `route_id`" and the Connect button fails.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VpnStartRequest {
    /// Route id chosen via `engine_set_route` semantics. The plugin
    /// forwards this string verbatim through to the Kotlin
    /// `DaalVpnService.onStartCommand` extra so the service can
    /// activate the right outbound block.
    ///
    /// ABSENT OR EMPTY MEANS "CONNECT AUTOMATICALLY": the service asks
    /// the engine to pick a route, try it and move on
    /// (`engine_connect_auto`). That is the one rule — there is no
    /// separate flag — and it is the same on every layer: this field,
    /// the Kotlin `VpnStartArgs.routeId`, and the service's
    /// `EXTRA_ROUTE_ID`.
    #[serde(default)]
    pub route_id: Option<String>,
}

impl VpnStartRequest {
    /// The route asked for; "" when the request is an automatic connect.
    pub fn route(&self) -> &str {
        self.route_id.as_deref().unwrap_or("").trim()
    }
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
    /// The route actually running, or `None`.
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
    /// True while the engine's automatic connect is in charge of the
    /// connection (from an automatic start until a disconnect or a
    /// route picked by hand). `route_id` is then the route the engine
    /// is on NOW, which it may change by itself.
    #[serde(default)]
    pub auto: bool,
    /// Android only. True while the service keeps the VPN interface up
    /// with NOTHING behind it: the engine's automatic connect ran out of
    /// routes while the person was connected, and the service is asking
    /// it again on a timer. Every other app is cut off meanwhile (that
    /// is the point: nothing leaks), so the page must say so and offer
    /// a way to let go. False on desktop and from an older service.
    #[serde(default)]
    pub holding: bool,
    /// Android only. True while the VPN service is up and is itself
    /// telling the engine about the phone's network (from a start until
    /// the stop, whether or not a route is connected). The page must
    /// then keep its own `network_changed` call to itself: it knows
    /// neither the kind of network nor its identity, and its poorer
    /// fact would replace the service's. False on desktop and from an
    /// older service.
    #[serde(default)]
    pub running: bool,
}

/// Arguments of the Kotlin `secureScreen` command (PB-20): `on` while a
/// screen showing the recovery words is mounted.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecureScreenRequest {
    pub on: bool,
}

/// What the Kotlin side answers; `on` is the flag as now set.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecureScreenResponse {
    #[serde(default)]
    pub on: bool,
}

/// Arguments of the Kotlin `fieldProbeWatch` command (network test):
/// `on` when a test is starting, `false` when it has ended.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FieldProbeWatchRequest {
    pub on: bool,
}

/// What the phone knows that the network test's start needs and the
/// engine cannot see itself. `dns_servers` are addresses: they go into
/// the engine's start options in memory and are never logged or kept.
/// Every field defaults, so an older plugin's answer still parses (and
/// says nothing).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FieldProbeHost {
    #[serde(default)]
    pub watching: bool,
    #[serde(default)]
    pub dns_servers: Vec<String>,
    /// `off` | `auto` | `strict` | `unknown`; "" from an older plugin.
    #[serde(default)]
    pub private_dns: String,
    #[serde(default)]
    pub vpn_active: bool,
    #[serde(default)]
    pub ipv6_global: bool,
    /// The system blocks this app's traffic ("Block connections without
    /// VPN").
    #[serde(default)]
    pub blocked: bool,
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
    /// For an automatic connect (`auto`), the engine's verdict code
    /// (`network_down`, `all_cooling_down`, …).
    #[serde(default)]
    pub reason: String,
    /// True when this note is about an automatic connect that found no
    /// route that carries. `route_id` is then "" — no single route was
    /// asked for.
    #[serde(default)]
    pub auto: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_secure_screen_request_is_one_boolean_named_on() {
        // The Kotlin @InvokeArg SecureScreenArgs reads exactly `on`.
        assert_eq!(
            serde_json::to_string(&SecureScreenRequest { on: true }).unwrap(),
            r#"{"on":true}"#
        );
        let r: SecureScreenResponse = serde_json::from_str("{}").unwrap();
        assert!(!r.on);
    }

    #[test]
    fn the_field_probe_watch_speaks_the_kotlin_names() {
        assert_eq!(
            serde_json::to_string(&FieldProbeWatchRequest { on: true }).unwrap(),
            r#"{"on":true}"#
        );
        let h: FieldProbeHost = serde_json::from_str(
            r#"{"watching":true,"dns_servers":["192.0.2.53"],"private_dns":"auto",
                "vpn_active":false,"ipv6_global":true,"blocked":false}"#,
        )
        .unwrap();
        assert_eq!(h.dns_servers, vec!["192.0.2.53".to_string()]);
        assert_eq!(h.private_dns, "auto");
        assert!(h.ipv6_global && h.watching);
        // An answer with nothing in it says nothing.
        let h: FieldProbeHost = serde_json::from_str("{}").unwrap();
        assert_eq!(h, FieldProbeHost::default());
    }

    #[test]
    fn a_start_with_no_route_is_an_automatic_connect() {
        // What connectAuto() sends: no route id at all.
        let r: VpnStartRequest = serde_json::from_str("{}").unwrap();
        assert_eq!(r.route(), "");
        let r: VpnStartRequest = serde_json::from_str(r#"{"routeId":null}"#).unwrap();
        assert_eq!(r.route(), "");
        let r: VpnStartRequest = serde_json::from_str(r#"{"routeId":"  "}"#).unwrap();
        assert_eq!(r.route(), "");
        // What connect(routeId) has always sent.
        let r: VpnStartRequest = serde_json::from_str(r#"{"routeId":"r2"}"#).unwrap();
        assert_eq!(r.route(), "r2");
    }

    #[test]
    fn status_reads_a_note_about_an_automatic_connect() {
        let s: VpnStatusResponse = serde_json::from_str(
            r#"{"connected":false,"route_id":null,"platform":"android",
                "last_switch":{"route_id":"","kept_route_id":null,"outcome":"failed",
                               "reason":"network_down","auto":true}}"#,
        )
        .unwrap();
        let n = s.last_switch.unwrap();
        assert!(n.auto);
        assert_eq!(n.reason, "network_down");
        assert_eq!(n.route_id, "");
        // A note written before the field existed is a manual switch.
        let s: VpnStatusResponse = serde_json::from_str(
            r#"{"connected":true,"route_id":"r1","platform":"android",
                "last_switch":{"route_id":"r2","kept_route_id":"r1","outcome":"refused","reason":"cooldown"}}"#,
        )
        .unwrap();
        assert!(!s.last_switch.unwrap().auto);
    }

    #[test]
    fn status_carries_holding_through_to_the_page() {
        let s: VpnStatusResponse = serde_json::from_str(
            r#"{"connected":false,"route_id":null,"platform":"android","auto":true,"holding":true}"#,
        )
        .unwrap();
        assert!(s.holding);
        assert!(serde_json::to_string(&s).unwrap().contains(r#""holding":true"#));
        // A service that predates the field is not holding.
        let s: VpnStatusResponse =
            serde_json::from_str(r#"{"connected":false,"route_id":null,"platform":"android","auto":true}"#).unwrap();
        assert!(!s.holding);
    }

    #[test]
    fn status_says_when_the_service_reports_the_network_itself() {
        let s: VpnStatusResponse = serde_json::from_str(
            r#"{"connected":true,"route_id":"r1","platform":"android","auto":true,"running":true}"#,
        )
        .unwrap();
        assert!(s.running);
        assert!(serde_json::to_string(&s).unwrap().contains(r#""running":true"#));
        // A service that predates the field does not report the network.
        let s: VpnStatusResponse =
            serde_json::from_str(r#"{"connected":true,"route_id":"r1","platform":"android"}"#).unwrap();
        assert!(!s.running);
    }
}
