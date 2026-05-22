package relaypackvalidate

import (
	"encoding/json"
	"testing"

	"daal/bundle-go/bundle"
)

// FRP-8 RP022/RP023/RP024 + RP007 per-family tests.

// passingAttestation returns a passing CDN attestation map.
func passingAttestation() bundle.CDNAttestation {
	return bundle.CDNAttestation{
		OriginCAFingerprint: "abababababababababababababababababababababababababababababababab",
		AOPEnabled:          true,
		FirewallID:          "fw-test",
		DNSOnlyPresent:      false,
	}
}

// TestRP022_MissingAttestation: cdn_fronted candidate without
// _cdn_attestation rejected at V16+.
func TestRP022_MissingAttestation(t *testing.T) {
	cdn := minimalCDN()
	// Pack manually omitting _cdn_attestation by signaling
	// extras with a sentinel that prevents auto-injection.
	cdnFSC := json.RawMessage(`{"_relaypack":{"exposure_mode":"cdn_fronted","family_class":"vps-native","probing_risk_class":"low","public_risk_tags":["cdn:cloudflare","public_domain:e.example.com"],"origin_risk_tags":["origin_ip:5.75.0.1"]}}`)
	_ = cdn
	b := bundleWith([]bundle.RouteManifestEntry{
		{ID: "r1", TransportFamily: "websocket-tls", FamilySpecificConfig: cdnFSC},
		{ID: "r2", TransportFamily: "vless-reality", FamilySpecificConfig: packEntry(t, minimalDirectVPS(), nil)},
	}, &bundle.RelayPack{RelayPackID: "rp-test"})
	expectError(t, b, ValidateOpts{Phase: PhaseV16}, CodeRP022)
}

// TestRP022_EmptyOriginCAFingerprint: attestation without
// origin_ca_fingerprint rejected.
func TestRP022_EmptyOriginCAFingerprint(t *testing.T) {
	att := passingAttestation()
	att.OriginCAFingerprint = ""
	b := twoRouteBundle(t,
		minimalDirectVPS(),
		minimalCDN(),
	)
	// Replace r2's config with the broken attestation.
	b.Manifest.Routes[1].FamilySpecificConfig = packEntry(t, minimalCDN(), map[string]any{"_cdn_attestation": att})
	expectError(t, b, ValidateOpts{Phase: PhaseV16}, CodeRP022)
}

// TestRP022_AOPDisabled: aop_enabled=false rejected.
func TestRP022_AOPDisabled(t *testing.T) {
	att := passingAttestation()
	att.AOPEnabled = false
	b := twoRouteBundle(t, minimalDirectVPS(), minimalCDN())
	b.Manifest.Routes[1].FamilySpecificConfig = packEntry(t, minimalCDN(), map[string]any{"_cdn_attestation": att})
	expectError(t, b, ValidateOpts{Phase: PhaseV16}, CodeRP022)
}

// TestRP022_EmptyFirewallID: firewall_id empty rejected.
func TestRP022_EmptyFirewallID(t *testing.T) {
	att := passingAttestation()
	att.FirewallID = ""
	b := twoRouteBundle(t, minimalDirectVPS(), minimalCDN())
	b.Manifest.Routes[1].FamilySpecificConfig = packEntry(t, minimalCDN(), map[string]any{"_cdn_attestation": att})
	expectError(t, b, ValidateOpts{Phase: PhaseV16}, CodeRP022)
}

// TestRP023_DNSOnlyPresent: dns_only_present=true rejected.
func TestRP023_DNSOnlyPresent(t *testing.T) {
	att := passingAttestation()
	att.DNSOnlyPresent = true
	b := twoRouteBundle(t, minimalDirectVPS(), minimalCDN())
	b.Manifest.Routes[1].FamilySpecificConfig = packEntry(t, minimalCDN(), map[string]any{"_cdn_attestation": att})
	expectError(t, b, ValidateOpts{Phase: PhaseV16}, CodeRP023)
}

// TestRP024_LintCDNWithoutDirect: cdn_fronted without direct_vps
// sibling surfaces RP024 warning (does NOT block import).
func TestRP024_LintCDNWithoutDirect(t *testing.T) {
	cdn := minimalCDN()
	// Two cdn_fronted siblings, no direct_vps.
	b := bundleWith([]bundle.RouteManifestEntry{
		{ID: "r1", TransportFamily: "websocket-tls", FamilySpecificConfig: packEntry(t, cdn, nil)},
		{ID: "r2", TransportFamily: "vless-reality", FamilySpecificConfig: packEntry(t, cdn, nil)},
	}, &bundle.RelayPack{RelayPackID: "rp-test"})
	rep, err := Validate(b, ValidateOpts{Phase: PhaseV16})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	found := false
	for _, w := range rep.Warnings {
		if w.Code == CodeRP024 {
			found = true
		}
	}
	if !found {
		t.Errorf("expected RP024 warning, got %v", rep.Warnings)
	}
}

// TestRP024_NotFiredWhenDirectSiblingPresent: rp024 silent when
// at least one direct_vps sibling exists.
func TestRP024_NotFiredWhenDirectSiblingPresent(t *testing.T) {
	b := twoRouteBundle(t, minimalDirectVPS(), minimalCDN())
	rep, err := Validate(b, ValidateOpts{Phase: PhaseV16})
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range rep.Warnings {
		if w.Code == CodeRP024 {
			t.Errorf("RP024 should not fire when direct_vps sibling exists; got %v", rep.Warnings)
		}
	}
}

// TestRP007_PerFamily covers the §11.1.1 cdn_fronted "no" rows
// for the four UDP-only families that motivated the per-family
// matrix in the FRP-8 codebook corrections.
func TestRP007_PerFamily(t *testing.T) {
	cases := []struct {
		family string
		want   bool // true = should pass
	}{
		{"vless-reality", true},
		{"naive", true},
		{"websocket-tls", true},
		{"hysteria2", false},
		{"tuic", false},
		{"wireguard", false},
		{"amneziawg", false},
	}
	for _, c := range cases {
		t.Run(c.family, func(t *testing.T) {
			cdn := minimalCDN()
			b := bundleWith([]bundle.RouteManifestEntry{
				{ID: "r1", TransportFamily: c.family, FamilySpecificConfig: packEntry(t, cdn, nil)},
				{ID: "r2", TransportFamily: "vless-reality", FamilySpecificConfig: packEntry(t, minimalDirectVPS(), nil)},
			}, &bundle.RelayPack{RelayPackID: "rp-test"})
			_, err := Validate(b, ValidateOpts{Phase: PhaseV16})
			if c.want && err != nil {
				t.Errorf("family %q should pass at V1.6, got %v", c.family, err)
			}
			if !c.want && err == nil {
				t.Errorf("family %q should fail RP007 at V1.6, got nil", c.family)
			}
		})
	}
}

// TestRP021_LiftAtV16: freshness_url accepted at V1.6 (FRP-8 lift).
func TestRP021_LiftAtV16(t *testing.T) {
	b := twoRouteBundle(t, minimalDirectVPS(), minimalDirectVPS())
	b.Manifest.RelayPack.FreshnessURL = "https://example.com/freshness/rp.json"
	if _, err := Validate(b, ValidateOpts{Phase: PhaseV16}); err != nil {
		t.Errorf("freshness_url should be accepted at V1.6, got %v", err)
	}
}

// TestRP021_RejectAtV15: freshness_url rejected at V1.5 (regression
// guard — the FRP-1 RP021 path still fires).
func TestRP021_RejectAtV15(t *testing.T) {
	b := twoRouteBundle(t, minimalDirectVPS(), minimalDirectVPS())
	b.Manifest.RelayPack.FreshnessURL = "https://example.com/freshness/rp.json"
	expectError(t, b, ValidateOpts{Phase: PhaseV15}, CodeRP021)
}

// TestParseCDNAttestation_RoundTrip: bundle.ParseCDNAttestation
// recovers a struct that round-trips through canonical JSON.
func TestParseCDNAttestation_RoundTrip(t *testing.T) {
	att := passingAttestation()
	wrapper := map[string]any{"_cdn_attestation": att, "x": 1}
	body, _ := json.Marshal(wrapper)
	got, err := bundle.ParseCDNAttestation(body)
	if err != nil {
		t.Fatal(err)
	}
	if got.OriginCAFingerprint != att.OriginCAFingerprint {
		t.Errorf("fp = %q", got.OriginCAFingerprint)
	}
	if !got.AOPEnabled || got.FirewallID != "fw-test" || got.DNSOnlyPresent {
		t.Errorf("round-trip lost data: %+v", got)
	}
}

// TestParseCDNAttestation_AbsentReturnsSentinel
func TestParseCDNAttestation_AbsentReturnsSentinel(t *testing.T) {
	body := json.RawMessage(`{"x":1}`)
	if _, err := bundle.ParseCDNAttestation(body); err == nil || err != bundle.ErrNoCDNAttestation {
		t.Errorf("want ErrNoCDNAttestation, got %v", err)
	}
}
