// Package engine wraps the platform engine (sing-box). For Phase 1B the
// real sing-box is gated behind a build tag (//go:build singbox). The
// default build ships a stub driver that satisfies the engine ABI for unit
// and integration tests, plus this config-builder which is real.
package engine

import (
	"daal/bundle-go/bundle"
	"daal/core/routestore"
	"encoding/json"
	"errors"
	"fmt"
)

// SingBoxConfig is the minimum subset of sing-box's config schema we care
// about for V1. Sing-box accepts additional fields silently; this struct
// is strict on what we *write*, not on what sing-box accepts.
type SingBoxConfig struct {
	Log map[string]any `json:"log,omitempty"`
	DNS map[string]any `json:"dns,omitempty"`

	// Endpoints is sing-box's top-level `endpoints[]` array
	// (option.Options.Endpoints), and its absence was the reason a
	// WireGuard route could not be expressed AT ALL by this build.
	//
	// sing-box 1.11 deprecated the WireGuard OUTBOUND and 1.13 removed
	// it: include/registry.go registers C.TypeWireGuard as a stub whose
	// only behaviour is to return "WireGuard outbound is deprecated in
	// sing-box 1.11.0 and removed in sing-box 1.13.0, use WireGuard
	// endpoint instead". An endpoint is a peer this process both dials
	// out through and can receive on, so it lives in its own array
	// rather than in outbounds[] — but it shares the outbound tag
	// namespace (option.checkOutbounds validates outbounds and
	// endpoints against one `seen` set), which is what lets
	// route.final name it exactly like an outbound.
	//
	// So a WireGuard route is: the profile object here, tagged
	// "active", with outbounds[] carrying only direct/block. Nothing
	// else about the config changes.
	Endpoints []map[string]any `json:"endpoints,omitempty"`

	Inbounds  []map[string]any `json:"inbounds,omitempty"`
	Outbounds []map[string]any `json:"outbounds"`
	Route     map[string]any   `json:"route,omitempty"`
}

// endpointTypes are the sing-box `type` values that belong in
// endpoints[] rather than outbounds[]. Both are registered by
// include.EndpointRegistry() in 1.13.12: wireguard (behind the
// with_wireguard tag, which tools/build-engine-android.sh sets) and
// tailscale.
//
// A type in this set placed in outbounds[] is not a soft error. For
// wireguard the strict parser resolves the stub and the route dies at
// dial with the deprecation message; the config still "parses", so
// nothing catches it earlier. That is precisely how this build shipped
// a WireGuard family it could not dial.
var endpointTypes = map[string]bool{
	"wireguard": true,
	"tailscale": true,
}

// BuildSingBoxConfig assembles a sing-box config that uses the supplied
// outbound profile bytes (already sing-box outbound JSON per
// specs/route-internal-v1.md) as the active outbound. UDP-gated routes are
// represented as-is; the path manager controls whether the route is
// activated based on the UDP probe.
func BuildSingBoxConfig(route routestore.RouteRow, profile []byte) (*SingBoxConfig, error) {
	if len(profile) == 0 {
		return nil, errors.New("engine: empty profile")
	}
	var outbound map[string]any
	if err := json.Unmarshal(profile, &outbound); err != nil {
		return nil, fmt.Errorf("engine: profile is not a sing-box outbound JSON object: %w", err)
	}
	if _, ok := outbound["tag"]; !ok {
		outbound["tag"] = "active"
	}
	// The `tor` family is the one outbound whose config is incomplete
	// until it meets a device: the tor executable lives in a directory
	// whose path contains an install-specific hash, and the data
	// directory must sit inside the app sandbox. materialiseTorOutbound
	// fills both in and resolves a pluggable-transport binary for every
	// bridge line, or returns an error naming exactly what is missing.
	//
	// The error is returned, not swallowed: a tor route whose plugin is
	// absent does not fail, it HANGS — tor retries a bridge it cannot
	// reach and the user watches a spinner. See torconfig.go.
	if outbound["type"] == "tor" {
		if err := materialiseTorOutbound(outbound); err != nil {
			return nil, err
		}
	}
	cfg := &SingBoxConfig{
		Log: map[string]any{
			"level":     "warn",
			"timestamp": false, // hour-bucketed elsewhere; sing-box stdout is debug-only
		},
		Outbounds: []map[string]any{
			{"tag": "direct", "type": "direct"},
			{"tag": "block", "type": "block"},
		},
		Route: map[string]any{
			"final": "active",
		},
	}
	// The active profile goes to endpoints[] or outbounds[] by TYPE,
	// not by family: what decides it is which sing-box registry owns
	// the type, and a pasted profile is the only thing that knows. It
	// keeps its "active" tag either way — endpoints share the outbound
	// tag namespace — so route.final needs no special case.
	if t, _ := outbound["type"].(string); endpointTypes[t] {
		cfg.Endpoints = []map[string]any{outbound}
	} else {
		cfg.Outbounds = append([]map[string]any{outbound}, cfg.Outbounds...)
	}
	// An outbound that cannot carry UDP leaves every app without names.
	// See outboundCarriesUDP.
	if !outboundCarriesUDP(outbound) {
		cfg.Route["rules"] = []any{dnsHijackRule()}
	}
	if isUDPFamily(bundle.TransportFamily(route.TransportFamily)) {
		// Mark the config so the engine driver knows to gate on UDP probe.
		cfg.Route["udp_gated"] = true
	}
	// The loopback SOCKS5 refresh inlet. route.final already sends
	// everything to "active", so a fetch dialled here leaves the device
	// over the relay — which is the only way the engine's own scheduled
	// fetches can happen at all while refresh.TunnelRequired() holds.
	// See inlet.go for the loopback-exposure analysis and why the inlet
	// is authenticated and ephemeral-ported.
	//
	// A nil plan is not an error: the tunnel must come up regardless,
	// and without an inlet refresh simply stays fail-closed.
	inlet := planRefreshInlet()
	stageRefreshInlet(inlet)
	if inlet != nil {
		cfg.Inbounds = append(cfg.Inbounds, inlet.inboundJSON())
	}
	return cfg, nil
}

// MarshalSingBox returns the canonical JSON the engine driver hands to
// sing-box.
func MarshalSingBox(cfg *SingBoxConfig) ([]byte, error) {
	return json.MarshalIndent(cfg, "", "  ")
}

// IsUDPFamily reports whether a route of this transport family reaches
// its relay over UDP. The automatic connect uses it to tell a silent
// UDP route from a silent address (core/abi/connect_auto.go).
func IsUDPFamily(family string) bool { return isUDPFamily(bundle.TransportFamily(family)) }

func isUDPFamily(f bundle.TransportFamily) bool {
	switch f {
	case bundle.TransportHysteria2, bundle.TransportTUIC, bundle.TransportMASQUE,
		bundle.TransportWireGuard, bundle.TransportAmneziaWG:
		return true
	}
	return false
}

// outboundCarriesUDP reports whether sing-box will accept a UDP packet
// for this outbound. Where it will not, an app's name lookup cannot work
// as sent:
//
// The VpnService hands Android two resolvers (1.1.1.1, 9.9.9.9), and the
// platform resolver queries them over plain UDP/53 — it turns to TCP only
// when an answer comes back truncated, not when none comes back. Inside
// the engine that datagram is routed to route.final like everything
// else, the outbound says "UDP is not supported", and the netstack
// answers the app with an ICMP port-unreachable. Every lookup fails, so
// no connection ever starts: the route is "connected" and nothing loads.
//
// (A device that upgrades those resolvers to DNS-over-TLS on its own —
// Android's "Private DNS: Automatic" — never sends the UDP query, which
// is how a naive route can look fine on one phone and dead on the next.)
//
// engine_singbox.go has always added a dns block with a DNS-over-TCP
// server detoured through the active outbound "so name lookups work over
// every transport" — but a dns block only answers queries the ROUTER
// hands it, and nothing did. dnsHijackRule is that missing half, applied
// only where UDP DNS is certain to be dead; outbounds that carry UDP keep
// forwarding the app's own queries untouched.
//
// The answer mirrors the network list each sing-box 1.13.12 outbound
// registers itself with (protocol/*/outbound.go, the NewAdapter call),
// which is what the router consults:
//
//   - tcpOnlyOutboundTypes register [tcp] unconditionally;
//   - naive registers [tcp] unless udp_over_tcp is enabled;
//   - every other type registers what its "network" option says, and both
//     when the option is absent — so a profile pinned to "network":"tcp"
//     is as UDP-less as naive is.
//
// A type this function does not know is assumed to carry UDP: the cost
// of being wrong that way is the defect as it stood, never a new one.
func outboundCarriesUDP(outbound map[string]any) bool {
	t, _ := outbound["type"].(string)
	if tcpOnlyOutboundTypes[t] {
		return false
	}
	if t == "naive" {
		return udpOverTCPEnabled(outbound["udp_over_tcp"])
	}
	switch n := outbound["network"].(type) {
	case string:
		return n == "" || n == "udp"
	case []any:
		if len(n) == 0 {
			return true
		}
		for _, v := range n {
			if v == "udp" {
				return true
			}
		}
		return false
	}
	return true
}

// tcpOnlyOutboundTypes are the outbound types sing-box 1.13.12 registers
// with networks [tcp] whatever their options say.
// TestTCPOnlyOutboundTypesMatchSingBox reads the list back out of the
// sing-box source this module is pinned to, so a version bump that adds
// or changes one fails a test instead of a phone.
var tcpOnlyOutboundTypes = map[string]bool{
	"http":      true,
	"tor":       true,
	"ssh":       true,
	"shadowtls": true,
}

// udpOverTCPEnabled reads sing-box's udp_over_tcp option, which is
// either a bare bool or an object with an "enabled" field.
func udpOverTCPEnabled(v any) bool {
	switch u := v.(type) {
	case bool:
		return u
	case map[string]any:
		on, _ := u["enabled"].(bool)
		return on
	}
	return false
}

// dnsHijackRule makes the engine answer UDP/53 itself, through its own
// dns servers (DNS-over-TCP via the active outbound), instead of
// forwarding a datagram the outbound cannot carry. TCP/53 is left alone:
// it is a stream and already reaches the resolver the app asked for.
func dnsHijackRule() map[string]any {
	return map[string]any{"network": "udp", "port": 53, "action": "hijack-dns"}
}
