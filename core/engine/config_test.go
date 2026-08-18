package engine

import (
	"encoding/json"
	"strings"
	"testing"

	"daal/core/routestore"
)

func TestBuildSingBoxConfigPassesProfileThrough(t *testing.T) {
	route := routestore.RouteRow{
		RouteID:         "r1",
		TransportFamily: "vless-reality",
	}
	profile := []byte(`{"type":"vless","tag":"r1","server":"203.0.113.1"}`)
	cfg, err := BuildSingBoxConfig(route, profile)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Outbounds) != 3 {
		t.Fatalf("expected active+direct+block, got %d", len(cfg.Outbounds))
	}
	body, err := MarshalSingBox(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"server": "203.0.113.1"`) {
		t.Fatalf("config did not include server: %s", body)
	}
	if !strings.Contains(string(body), `"final": "active"`) {
		t.Fatalf("config did not set final outbound to 'active'")
	}
}

func TestBuildSingBoxConfigMarksUDPFamilies(t *testing.T) {
	for _, fam := range []string{"hysteria2", "tuic", "masque", "wireguard", "amneziawg"} {
		cfg, err := BuildSingBoxConfig(
			routestore.RouteRow{RouteID: "r", TransportFamily: fam},
			[]byte(`{"type":"x"}`),
		)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Route["udp_gated"] != true {
			t.Fatalf("%s should be udp_gated", fam)
		}
	}
}

func TestBuildSingBoxConfigRejectsEmptyProfile(t *testing.T) {
	_, err := BuildSingBoxConfig(routestore.RouteRow{}, nil)
	if err == nil {
		t.Fatal("empty profile should fail")
	}
}

// TestEndpointFamiliesGoToEndpointsArray pins the routing rule the
// Endpoints slot exists for, in the DEFAULT (untagged) build so it runs
// on every `go test ./...`.
//
// The rule is by sing-box TYPE, not by daal family: what decides the
// array is which sing-box registry owns the type, and only the profile
// knows that. A `wireguard` object in outbounds[] is not a config error
// — sing-box 1.13 still registers the type as a stub — it is a route
// that parses and then fails at dial with "WireGuard outbound is
// deprecated in sing-box 1.11.0 and removed in sing-box 1.13.0".
func TestEndpointFamiliesGoToEndpointsArray(t *testing.T) {
	profile := []byte(`{"type":"wireguard","address":["10.13.13.2/32"],
	  "private_key":"SLVvRuBMYzKPPFvQfE0nT4jGgpN0GfmwFCU6Rf1jZ2Y=",
	  "peers":[{"address":"198.51.100.7","port":51820,
	    "public_key":"xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
	    "allowed_ips":["0.0.0.0/0"]}]}`)
	cfg, err := BuildSingBoxConfig(routestore.RouteRow{RouteID: "r1", TransportFamily: "wireguard"}, profile)
	if err != nil {
		t.Fatalf("BuildSingBoxConfig: %v", err)
	}
	if len(cfg.Endpoints) != 1 {
		t.Fatalf("Endpoints = %v, want the wireguard profile", cfg.Endpoints)
	}
	if cfg.Endpoints[0]["tag"] != "active" {
		t.Errorf("endpoint tag = %v, want active", cfg.Endpoints[0]["tag"])
	}
	// outbounds[] keeps only direct/block. It must stay non-empty and
	// present in the JSON: SingBoxConfig.Outbounds has no omitempty,
	// and route.final resolves against the shared tag namespace.
	if len(cfg.Outbounds) != 2 {
		t.Fatalf("Outbounds = %v, want just direct+block", cfg.Outbounds)
	}
	for _, ob := range cfg.Outbounds {
		if ob["type"] == "wireguard" {
			t.Fatalf("wireguard leaked into outbounds[]: %v", ob)
		}
	}
	// Round-trip: the array survives marshalling under the key sing-box
	// reads (option.Options.Endpoints is `json:"endpoints,omitempty"`).
	body, err := MarshalSingBox(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var back struct {
		Endpoints []map[string]any `json:"endpoints"`
		Outbounds []map[string]any `json:"outbounds"`
		Route     map[string]any   `json:"route"`
	}
	if err := json.Unmarshal(body, &back); err != nil {
		t.Fatalf("marshalled config is not JSON: %v", err)
	}
	if len(back.Endpoints) != 1 || back.Endpoints[0]["type"] != "wireguard" {
		t.Fatalf("endpoints[] did not round-trip: %s", body)
	}
	if back.Route["final"] != "active" {
		t.Errorf("route.final = %v, want the endpoint's tag", back.Route["final"])
	}
	for _, ob := range back.Outbounds {
		if ob["tag"] == "active" {
			t.Fatalf("an endpoint route must not also be an outbound: %s", body)
		}
	}
}

// TestNonEndpointFamiliesStayInOutbounds is the other half: adding the
// Endpoints slot must not move anything that was already working, and
// the active outbound must stay FIRST (the order the pre-Wave-5 config
// had, and what every existing golden/shape assertion reads).
func TestNonEndpointFamiliesStayInOutbounds(t *testing.T) {
	profile := []byte(`{"type":"tuic","server":"198.51.100.7","server_port":8443,
	  "uuid":"11111111-2222-3333-4444-555555555555","password":"p",
	  "tls":{"enabled":true,"alpn":["h3"]}}`)
	cfg, err := BuildSingBoxConfig(routestore.RouteRow{RouteID: "r1", TransportFamily: "tuic"}, profile)
	if err != nil {
		t.Fatalf("BuildSingBoxConfig: %v", err)
	}
	if len(cfg.Endpoints) != 0 {
		t.Fatalf("Endpoints = %v, want none", cfg.Endpoints)
	}
	if len(cfg.Outbounds) != 3 || cfg.Outbounds[0]["type"] != "tuic" {
		t.Fatalf("Outbounds = %v, want the tuic profile first then direct+block", cfg.Outbounds)
	}
	if cfg.Outbounds[0]["tag"] != "active" {
		t.Errorf("active tag missing: %v", cfg.Outbounds[0])
	}
	// tuic is UDP-gated, like hysteria2: the path manager must be told.
	if cfg.Route["udp_gated"] != true {
		t.Errorf("tuic route must be udp_gated: %v", cfg.Route)
	}
}
