package relaypack

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"daal/bundle-go/bundle"
	"daal/bundle-go/relaypackvalidate"
	"daal/publisher/deploy/provider"
)

// TestBindAndSign_EmitsCDNAttestation locks that the binder
// renders the per-candidate `_cdn_attestation` sub-object into
// the FamilySpecificConfig blob for cdn_fronted candidates, and
// that the resulting bundle passes the V1.6 validator.
func TestBindAndSign_EmitsCDNAttestation(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	rec := &provider.OperatorRecord{
		Provider:        "hetzner",
		ServerID:        "12345",
		ServerType:      "cx22",
		Region:          "fsn1",
		ToolboxProfile:  "iran-default",
		PublisherPubKey: pub,
		Candidates: []provider.CandidateMeta{
			{
				Family:           "websocket-tls",
				ExposureMode:     "cdn_fronted",
				FamilyClass:      "vps-native",
				ProbingRiskClass: "low",
				Port:             443,
				PublicRiskTags:   []string{"cdn:cloudflare", "public_domain:e.example.com"},
				OriginRiskTags:   []string{"origin_ip:5.75.0.1"},
				CDNAttestation: &provider.CDNAttestation{
					OriginCAFingerprint: "ababababababababababababababababababababababababababababababab",
					AOPEnabled:          true,
					FirewallID:          "fw-1234",
					DNSOnlyPresent:      false,
				},
			},
			{
				Family:           "vless-reality",
				ExposureMode:     "direct_vps",
				FamilyClass:      "vps-native",
				ProbingRiskClass: "low",
				Port:             443,
				PublicRiskTags:   []string{"public_ip:5.75.0.1", "public_port:tcp443"},
				OriginRiskTags:   []string{},
			},
		},
	}
	res, err := BindAndSign(rec, priv, BindOpts{
		Now:          time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC),
		Phase:        relaypackvalidate.PhaseV16,
		FreshnessURL: "https://freshness.example.com/rp.json",
	})
	if err != nil {
		t.Fatalf("BindAndSign: %v", err)
	}

	// Re-parse and check the cdn_fronted candidate carries
	// _cdn_attestation.
	parsed, err := bundle.ParseSBP(strings.NewReader(string(res.SBPBytes)), int64(len(res.SBPBytes)))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Manifest.RelayPack == nil || parsed.Manifest.RelayPack.FreshnessURL != "https://freshness.example.com/rp.json" {
		t.Errorf("FreshnessURL not propagated: %+v", parsed.Manifest.RelayPack)
	}
	for _, r := range parsed.Manifest.Routes {
		if r.TransportFamily != "websocket-tls" {
			continue
		}
		var probe map[string]json.RawMessage
		if err := json.Unmarshal(r.FamilySpecificConfig, &probe); err != nil {
			t.Fatal(err)
		}
		raw, ok := probe["_cdn_attestation"]
		if !ok {
			t.Fatalf("websocket-tls route missing _cdn_attestation: %s", string(r.FamilySpecificConfig))
		}
		var att bundle.CDNAttestation
		if err := json.Unmarshal(raw, &att); err != nil {
			t.Fatal(err)
		}
		if !att.AOPEnabled || att.FirewallID != "fw-1234" || att.DNSOnlyPresent {
			t.Errorf("attestation lost data: %+v", att)
		}
	}
}

// TestBindAndSign_RejectsCDNWithoutAttestationAtV16 confirms
// the validator wired into the binder fires RP022 when a
// cdn_fronted candidate lacks an attestation.
func TestBindAndSign_RejectsCDNWithoutAttestationAtV16(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	rec := &provider.OperatorRecord{
		Provider:        "hetzner",
		ServerID:        "12345",
		ServerType:      "cx22",
		Region:          "fsn1",
		ToolboxProfile:  "iran-default",
		PublisherPubKey: pub,
		Candidates: []provider.CandidateMeta{
			{
				Family:           "websocket-tls",
				ExposureMode:     "cdn_fronted",
				FamilyClass:      "vps-native",
				ProbingRiskClass: "low",
				Port:             443,
				PublicRiskTags:   []string{"cdn:cloudflare", "public_domain:e.example.com"},
				OriginRiskTags:   []string{"origin_ip:5.75.0.1"},
				// CDNAttestation deliberately nil
			},
			{
				Family:           "vless-reality",
				ExposureMode:     "direct_vps",
				FamilyClass:      "vps-native",
				ProbingRiskClass: "low",
				Port:             443,
				PublicRiskTags:   []string{"public_ip:5.75.0.1", "public_port:tcp443"},
				OriginRiskTags:   []string{},
			},
		},
	}
	_, err := BindAndSign(rec, priv, BindOpts{
		Now:   time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC),
		Phase: relaypackvalidate.PhaseV16,
	})
	if err == nil || !strings.Contains(err.Error(), "RP022") {
		t.Fatalf("want RP022 error, got %v", err)
	}
}
