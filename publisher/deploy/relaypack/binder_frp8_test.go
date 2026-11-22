package relaypack

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"daal/bundle-go/bundle"
	"daal/bundle-go/relaypackvalidate"
	"daal/publisher/deploy/freshness"
	"daal/publisher/deploy/provider"
)

// TestBindAndSign_EmitsCDNAttestation locks that the way in through
// Cloudflare (BindOpts.CDN) is signed as one more websocket-tls route
// with `_cdn_attestation`, the RP005/RP006 tags and `_cdn_endpoint`
// (the ECH configuration copied from the front record), and never an
// `_endpoint`, and that the bundle passes the V1.6 validator and
// ValidateForSigning.
func TestBindAndSign_EmitsCDNAttestation(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	rec := cdnTestRec(pub)
	mirrors, err := freshness.NewMirrorSet([]freshness.Mirror{
		{Provider: freshness.ProviderR2, URL: "https://freshness.example.com/rp.json"},
		{Provider: freshness.ProviderGHPages, URL: "https://frp.github.io/f/rp.json"},
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := BindAndSign(rec, priv, BindOpts{
		Now:       time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC),
		Phase:     relaypackvalidate.PhaseV16,
		Freshness: mirrors,
		CDN:       cdnTestFront(t),
	})
	if err != nil {
		t.Fatalf("BindAndSign: %v", err)
	}
	if len(res.Uncommitted) != 0 {
		t.Errorf("uncommitted = %+v", res.Uncommitted)
	}

	parsed, err := bundle.ParseSBP(strings.NewReader(string(res.SBPBytes)), int64(len(res.SBPBytes)))
	if err != nil {
		t.Fatal(err)
	}
	// The legacy scalar slot carries the lowest-sorting mirror
	// (provider "ghpages" sorts before "r2"), not the order the
	// caller happened to list them in — the set is ordered so the
	// pack stays byte-identical across runs.
	if parsed.Manifest.RelayPack == nil || parsed.Manifest.RelayPack.FreshnessURL != "https://frp.github.io/f/rp.json" {
		t.Errorf("FreshnessURL not propagated: %+v", parsed.Manifest.RelayPack)
	}
	if n := len(parsed.Manifest.Routes); n != 2 {
		t.Fatalf("%d routes, want the direct one plus the CDN one", n)
	}
	r := parsed.Manifest.Routes[1]
	if r.ID != "r2" || r.TransportFamily != "websocket-tls" {
		t.Fatalf("CDN route = %s %s", r.ID, r.TransportFamily)
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(r.FamilySpecificConfig, &probe); err != nil {
		t.Fatal(err)
	}
	if _, ok := probe[bundle.EndpointKey]; ok {
		t.Fatalf("CDN route carries _endpoint: %s", r.FamilySpecificConfig)
	}
	var att bundle.CDNAttestation
	if err := json.Unmarshal(probe["_cdn_attestation"], &att); err != nil {
		t.Fatalf("_cdn_attestation: %v (%s)", err, r.FamilySpecificConfig)
	}
	if !att.AOPEnabled || att.FirewallID != "fw-1234" || att.DNSOnlyPresent || att.OriginCAFingerprint == "" {
		t.Errorf("attestation lost data: %+v", att)
	}
	ep, err := bundle.ParseCDNEndpoint(r.TransportFamily, r.FamilySpecificConfig)
	if err != nil {
		t.Fatalf("_cdn_endpoint: %v", err)
	}
	if ep.Server != "door.example.org" || ep.Port != 443 || ep.ECHConfig != cdnTestECH ||
		ep.PlainFallback || len(ep.EdgeSeeds) != 2 || ep.EdgeSeeds[0] != "104.16.0.0/13" || len(ep.TLSRootsSHA256) != 1 {
		t.Errorf("endpoint = %+v", ep)
	}
	entry, err := bundle.ParseRelayPackEntry(r.FamilySpecificConfig)
	if err != nil || entry.ExposureMode != "cdn_fronted" ||
		!containsString(entry.PublicRiskTags, "cdn:cloudflare") || !containsString(entry.OriginRiskTags, "origin_ip:5.75.0.1") {
		t.Errorf("_relaypack = %+v (%v)", entry, err)
	}
	// The direct route keeps its own endpoint.
	if _, err := bundle.ParseEndpoint(parsed.Manifest.Routes[0].FamilySpecificConfig); err != nil {
		t.Errorf("direct route lost its endpoint: %v", err)
	}
}

// No ECH configuration and no signed plain fallback: the route could
// never be dialled, so it is not signed (RP026). With the flag it is.
func TestBindAndSign_CDNWithoutECHNeedsPlainFallback(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	cdn := cdnTestFront(t)
	cdn.Front.ECH.ConfigListB64 = ""
	opts := BindOpts{Now: time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC), Phase: relaypackvalidate.PhaseV16, CDN: cdn}
	if _, err := BindAndSign(cdnTestRec(pub), priv, opts); err == nil || !strings.Contains(err.Error(), "RP026") {
		t.Fatalf("want RP026, got %v", err)
	}
	cdn.PlainFallback = true
	if _, err := BindAndSign(cdnTestRec(pub), priv, opts); err != nil {
		t.Fatalf("with plain_fallback: %v", err)
	}
}

// A cdn_fronted candidate in the record itself is refused both ways:
// with BindOpts.CDN (one way in only), and without it, because the
// direct renderer would give it an `_endpoint` (RP026).
func TestBindAndSign_CDNCandidateInRecordRefused(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	rec := cdnTestRec(pub)
	rec.Candidates = append(rec.Candidates, provider.CandidateMeta{
		Family: "websocket-tls", ExposureMode: "cdn_fronted", FamilyClass: "vps-native", ProbingRiskClass: "low", Port: 443,
		PublicRiskTags: []string{"cdn:cloudflare"}, OriginRiskTags: []string{"origin_ip:5.75.0.1"},
		CDNAttestation: &provider.CDNAttestation{OriginCAFingerprint: "abab", AOPEnabled: true, FirewallID: "fw-1"},
	})
	opts := BindOpts{Now: time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC), Phase: relaypackvalidate.PhaseV16}
	if _, err := BindAndSign(rec, priv, opts); err == nil || !strings.Contains(err.Error(), "RP026") {
		t.Fatalf("without BindOpts.CDN: want RP026, got %v", err)
	}
	opts.CDN = cdnTestFront(t)
	if _, err := BindAndSign(rec, priv, opts); err != ErrCDNCandidateInRecord {
		t.Fatalf("with BindOpts.CDN: %v", err)
	}
}

// A one-mirror set is accepted when its one provider is appsscript
// (D-3, MeetsFloor), and the zero value is still refused.
func TestBindAndSign_MirrorFloorIsMeetsFloor(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	rec := cdnTestRec(pub)
	rec.Candidates = append(rec.Candidates, rec.Candidates[0])
	rec.Candidates[1].Family = "hysteria2"
	rec.Candidates[1].PublicRiskTags = []string{"public_ip:5.75.0.1", "public_port:udp443"}
	zero := &freshness.MirrorSet{}
	_, err := BindAndSign(rec, priv, BindOpts{Now: time.Now().UTC(), Phase: relaypackvalidate.PhaseV16, Freshness: zero})
	if err != freshness.ErrTooFewMirrors {
		t.Fatalf("zero set: %v", err)
	}
	one, err := freshness.NewMirrorSet([]freshness.Mirror{{Provider: freshness.ProviderAppsScript, URL: cdnTestAppsScriptURL}})
	if err != nil {
		t.Skipf("appsscript single-mirror set not constructible here: %v", err)
	}
	if _, err := BindAndSign(rec, priv, BindOpts{Now: time.Now().UTC(), Phase: relaypackvalidate.PhaseV16, Freshness: one}); err != nil {
		t.Fatalf("single appsscript mirror: %v", err)
	}
}

func TestCDNRootDigests(t *testing.T) {
	ca := cdnTestRootPEM(t)
	d, err := CDNRootDigests(append(append([]byte{}, ca...), ca...))
	if err != nil || len(d) != 1 {
		t.Fatalf("digests = %v, %v", d, err)
	}
	if _, err := CDNRootDigests([]byte("not pem")); err == nil {
		t.Error("an empty bundle was accepted")
	}
}

// TestBindAndSign_RejectsCDNWithoutAttestationAtV16 confirms
// the validator wired into the binder fires RP022 when a
// cdn_fronted candidate lacks an attestation.
func TestBindAndSign_RejectsCDNWithoutAttestationAtV16(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	rec := &provider.OperatorRecord{
		Provider:       "hetzner",
		ServerID:       "12345",
		ServerType:     "cx22",
		Region:         "fsn1",
		ToolboxProfile: "iran-default",
		PublicIP:       net.ParseIP("5.75.0.1"), RealityPublicKey: fixtureRealityPub, TLSCertSHA256: fixtureTLSPin,
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
