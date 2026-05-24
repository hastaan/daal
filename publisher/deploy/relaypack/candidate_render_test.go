package relaypack

import (
	"encoding/json"
	"net"
	"testing"

	"daal/bundle-go/bundle"
	"daal/publisher/deploy/provider"
)

func mkDirectVPSRec() *provider.OperatorRecord {
	return &provider.OperatorRecord{
		Provider:   "hetzner",
		ServerID:   "12345",
		Region:     "fsn1",
		ServerType: "cx22",
		PublicIP:   net.ParseIP("5.75.0.1"),
		Candidates: []provider.CandidateMeta{
			{
				Family:           "vless-reality",
				ExposureMode:     "direct_vps",
				FamilyClass:      "vps-native",
				ProbingRiskClass: "low",
				Port:             443,
				PublicRiskTags: []string{
					"public_ip:5.75.0.1",
					"public_port:tcp443",
					"public_provider:hetzner",
				},
				OriginRiskTags: []string{},
			},
			{
				Family:           "hysteria2",
				ExposureMode:     "direct_vps",
				FamilyClass:      "vps-native",
				ProbingRiskClass: "low",
				Port:             443,
				PublicRiskTags: []string{
					"public_ip:5.75.0.1",
					"public_port:udp443",
					"public_provider:hetzner",
				},
				OriginRiskTags: []string{},
			},
		},
	}
}

func TestRenderCandidates_DirectVPSFields(t *testing.T) {
	rec := mkDirectVPSRec()
	out, err := renderCandidates(rec, "2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z")
	if err != nil {
		t.Fatalf("renderCandidates: %v", err)
	}
	if len(out.routes) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(out.routes))
	}
	r := out.routes[0]
	if r.ID != "r1" {
		t.Fatalf("unexpected id %q", r.ID)
	}
	if r.TransportFamily != string(bundle.TransportVLESSReality) {
		t.Fatalf("unexpected transport %q", r.TransportFamily)
	}
	if r.ConfigPath != "profiles/r1.json" {
		t.Fatalf("unexpected config_path %q", r.ConfigPath)
	}
	if r.UDPGated {
		t.Fatalf("vless-reality should not be udp_gated")
	}
	// _relaypack must be inside FamilySpecificConfig.
	parsed, err := bundle.ParseRelayPackEntry(r.FamilySpecificConfig)
	if err != nil {
		t.Fatalf("ParseRelayPackEntry: %v", err)
	}
	if parsed.ExposureMode != "direct_vps" || parsed.FamilyClass != "vps-native" {
		t.Fatalf("relaypack entry mismatch: %+v", parsed)
	}
	if len(parsed.PublicRiskTags) != 3 {
		t.Fatalf("expected 3 public_risk_tags, got %d", len(parsed.PublicRiskTags))
	}
}

func TestRenderCandidates_OrderStable(t *testing.T) {
	rec := mkDirectVPSRec()
	a, _ := renderCandidates(rec, "2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z")
	b, _ := renderCandidates(rec, "2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z")
	if a.routes[0].ID != b.routes[0].ID || a.routes[1].ID != b.routes[1].ID {
		t.Fatalf("rendering not order-stable")
	}
}

func TestRenderCandidates_UDPFamilyMarkedGated(t *testing.T) {
	rec := &provider.OperatorRecord{
		Provider: "hetzner", ServerID: "1", Region: "fsn1",
		PublicIP: net.ParseIP("5.75.0.1"),
		Candidates: []provider.CandidateMeta{
			{Family: "hysteria2", ExposureMode: "direct_vps", FamilyClass: "vps-native",
				ProbingRiskClass: "low", Port: 443,
				PublicRiskTags: []string{"public_ip:5.75.0.1"}, OriginRiskTags: []string{}},
		},
	}
	out, err := renderCandidates(rec, "2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z")
	if err != nil {
		t.Fatalf("renderCandidates: %v", err)
	}
	if !out.routes[0].UDPGated {
		t.Fatalf("hysteria2 should be udp_gated")
	}
}

func TestRenderCandidates_AmneziaFamilyNormalised(t *testing.T) {
	rec := &provider.OperatorRecord{
		Provider: "hetzner", ServerID: "1", Region: "fsn1",
		PublicIP: net.ParseIP("5.75.0.1"),
		Candidates: []provider.CandidateMeta{
			{Family: "amnezia-wg", ExposureMode: "direct_vps", FamilyClass: "vps-native",
				ProbingRiskClass: "moderate", Port: 51820,
				PublicRiskTags: []string{"public_ip:5.75.0.1"}, OriginRiskTags: []string{}},
		},
	}
	out, err := renderCandidates(rec, "2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z")
	if err != nil {
		t.Fatalf("renderCandidates: %v", err)
	}
	if out.routes[0].TransportFamily != string(bundle.TransportAmneziaWG) {
		t.Fatalf("amnezia-wg should normalise to %q, got %q",
			bundle.TransportAmneziaWG, out.routes[0].TransportFamily)
	}
}

func TestRenderCandidates_PassThroughParams(t *testing.T) {
	rec := mkDirectVPSRec()
	rec.Candidates[0].Params = json.RawMessage(`{"reality_dest":"www.microsoft.com"}`)
	out, err := renderCandidates(rec, "2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z")
	if err != nil {
		t.Fatalf("renderCandidates: %v", err)
	}
	var fc map[string]any
	if err := json.Unmarshal(out.routes[0].FamilySpecificConfig, &fc); err != nil {
		t.Fatalf("unmarshal fc: %v", err)
	}
	if fc["reality_dest"] != "www.microsoft.com" {
		t.Fatalf("Params not passed through: %+v", fc)
	}
	if _, hasRP := fc["_relaypack"]; !hasRP {
		t.Fatalf("_relaypack not injected: %+v", fc)
	}
}

func TestRenderCandidates_RejectsUnknownFamily(t *testing.T) {
	rec := &provider.OperatorRecord{
		Provider: "hetzner", ServerID: "1", Region: "fsn1",
		PublicIP: net.ParseIP("5.75.0.1"),
		Candidates: []provider.CandidateMeta{
			{Family: "no-such-family", ExposureMode: "direct_vps", FamilyClass: "vps-native",
				ProbingRiskClass: "low", PublicRiskTags: []string{"public_ip:5.75.0.1"}, OriginRiskTags: []string{}},
		},
	}
	if _, err := renderCandidates(rec, "2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z"); err == nil {
		t.Fatalf("expected error for unknown family")
	}
}
