package selection

import (
	"strings"
	"testing"

	"daal/core/routestore"
)

func TestProjectFromRouteRow_RelayPackPopulatesEverything(t *testing.T) {
	r := routestore.RouteRow{
		RouteID:             "r1",
		TransportFamily:     "vless-reality",
		ScarcityClass:       "normal",
		ModesAllowed:        []string{"normal", "lifeline"},
		ExposureMode:        "direct_vps",
		FamilyClass:         "vps-native",
		ProbingRiskClass:    "low",
		PublicRiskTags:      []string{"public_ip:5.75.0.1", "public_port:tcp443"},
		OriginRiskTags:      []string{},
		RelayPackID:         "rp-frp3-test",
		FreshnessURL:        "",
		SharedRiskGraphJSON: `[{"tag":"public_ip:5.75.0.1","members":["r1","r2"]}]`,
	}
	c, err := ProjectFromRouteRow(r)
	if err != nil {
		t.Fatal(err)
	}
	if c.ExposureMode != "direct_vps" || c.FamilyClass != "vps-native" {
		t.Errorf("RelayPack fields not propagated: %+v", c)
	}
	if !c.IsRelayPack() {
		t.Error("IsRelayPack must be true when ExposureMode/RelayPackID set")
	}
	if len(c.SharedRiskGraph) != 1 || c.SharedRiskGraph[0].Tag != "public_ip:5.75.0.1" {
		t.Errorf("SharedRiskGraph parse failed: %+v", c.SharedRiskGraph)
	}
	siblings := c.SiblingsOnTag("public_ip:5.75.0.1")
	if len(siblings) != 1 || siblings[0] != "r2" {
		t.Errorf("SiblingsOnTag wrong: %v", siblings)
	}
}

func TestProjectFromRouteRow_LegacyRowYieldsEmptyGraph(t *testing.T) {
	r := routestore.RouteRow{
		RouteID:             "legacy-1",
		TransportFamily:     "vless-reality",
		ScarcityClass:       "normal",
		SharedRiskGraphJSON: "[]", // sentinel-empty
	}
	c, err := ProjectFromRouteRow(r)
	if err != nil {
		t.Fatal(err)
	}
	if c.IsRelayPack() {
		t.Error("legacy row must not be RelayPack")
	}
	if len(c.SharedRiskGraph) != 0 {
		t.Errorf("legacy SharedRiskGraph must be empty; got %v", c.SharedRiskGraph)
	}
	if c.SiblingsOnTag("anything") != nil {
		t.Error("SiblingsOnTag on empty graph must return nil")
	}
}

func TestProjectFromRouteRow_MalformedSharedRiskGraphReturnsError(t *testing.T) {
	r := routestore.RouteRow{
		RouteID:             "broken",
		SharedRiskGraphJSON: `{not json`,
	}
	_, err := ProjectFromRouteRow(r)
	if err == nil {
		t.Fatal("expected parse error")
	}
	if !strings.Contains(err.Error(), "shared_risk_graph parse") {
		t.Errorf("expected wrapped error; got %v", err)
	}
}

func TestProjectFromRouteRow_UDPGatedDetected(t *testing.T) {
	r := routestore.RouteRow{
		RouteID:        "rH",
		PublicRiskTags: []string{"public_ip:1.2.3.4", "udp_gated:true"},
	}
	c, _ := ProjectFromRouteRow(r)
	if !c.UDPGated {
		t.Fatal("UDPGated must be true when udp_gated:true tag present")
	}
}

func TestProjectFromRouteRow_AllNineRelayPackFieldsPreserved(t *testing.T) {
	r := routestore.RouteRow{
		RouteID:             "r-full",
		ExposureMode:        "cdn_fronted",
		FamilyClass:         "vps-native",
		ProbingRiskClass:    "moderate",
		PublicRiskTags:      []string{"cdn:cloudflare", "public_domain:test.example"},
		OriginRiskTags:      []string{"origin_ip:5.75.0.1"},
		ModifiersJSON:       `[]`,
		RelayPackID:         "rp-x",
		FreshnessURL:        "https://example.invalid/relaypack.json",
		SharedRiskGraphJSON: `[{"tag":"cdn:cloudflare","members":["r-full"]}]`,
	}
	c, err := ProjectFromRouteRow(r)
	if err != nil {
		t.Fatal(err)
	}
	if c.ExposureMode != "cdn_fronted" {
		t.Error("ExposureMode lost")
	}
	if c.FreshnessURL != "https://example.invalid/relaypack.json" {
		t.Error("FreshnessURL lost")
	}
	if c.RelayPackID != "rp-x" {
		t.Error("RelayPackID lost")
	}
	if len(c.OriginRiskTags) != 1 || c.OriginRiskTags[0] != "origin_ip:5.75.0.1" {
		t.Error("OriginRiskTags lost")
	}
	if c.ModifiersJSON != `[]` {
		t.Error("ModifiersJSON lost")
	}
}
