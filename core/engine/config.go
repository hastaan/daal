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
	Log       map[string]any   `json:"log,omitempty"`
	DNS       map[string]any   `json:"dns,omitempty"`
	Inbounds  []map[string]any `json:"inbounds,omitempty"`
	Outbounds []map[string]any `json:"outbounds"`
	Route     map[string]any   `json:"route,omitempty"`
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
	cfg := &SingBoxConfig{
		Log: map[string]any{
			"level":     "warn",
			"timestamp": false, // hour-bucketed elsewhere; sing-box stdout is debug-only
		},
		Outbounds: []map[string]any{
			outbound,
			{"tag": "direct", "type": "direct"},
			{"tag": "block", "type": "block"},
		},
		Route: map[string]any{
			"final": "active",
		},
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

func isUDPFamily(f bundle.TransportFamily) bool {
	switch f {
	case bundle.TransportHysteria2, bundle.TransportTUIC, bundle.TransportMASQUE,
		bundle.TransportWireGuard, bundle.TransportAmneziaWG:
		return true
	}
	return false
}
