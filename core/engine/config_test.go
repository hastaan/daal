package engine

import (
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
