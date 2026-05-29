package relaypackvalidate

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"daal/bundle-go/bundle"
)

// helpers ---------------------------------------------------------

func packEntry(t *testing.T, entry bundle.RelayPackEntry, extras map[string]any) json.RawMessage {
	t.Helper()
	m := map[string]any{"_relaypack": entry}
	// FRP-8: cdn_fronted candidates require a passing
	// _cdn_attestation at V16+. Tests that exercise the
	// positive path get a default-passing attestation
	// auto-injected here unless the test supplied one in
	// `extras`. Tests that want to exercise RP022/RP023 set
	// the field explicitly via extras.
	if _, hasAtt := extras["_cdn_attestation"]; !hasAtt && entry.ExposureMode == "cdn_fronted" {
		m["_cdn_attestation"] = bundle.CDNAttestation{
			OriginCAFingerprint: "abababababababababababababababababababababababababababababababab",
			AOPEnabled:          true,
			FirewallID:          "fw-test",
			DNSOnlyPresent:      false,
		}
	}
	for k, v := range extras {
		m[k] = v
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("pack entry: %v", err)
	}
	return json.RawMessage(b)
}

func bundleWith(routes []bundle.RouteManifestEntry, rp *bundle.RelayPack) *bundle.Bundle {
	return &bundle.Bundle{
		Manifest: bundle.Manifest{
			SpecVersion: 3,
			Routes:      routes,
			RelayPack:   rp,
		},
	}
}

// minimalDirectVPS returns a valid V1.5 direct_vps RelayPack entry.
func minimalDirectVPS() bundle.RelayPackEntry {
	return bundle.RelayPackEntry{
		ExposureMode:     "direct_vps",
		FamilyClass:      "vps-native",
		ProbingRiskClass: "low",
		PublicRiskTags:   []string{"public_ip:5.75.0.1", "public_port:tcp443"},
		OriginRiskTags:   []string{},
	}
}

// minimalCDN returns a valid cdn_fronted entry (rejected at V15).
func minimalCDN() bundle.RelayPackEntry {
	return bundle.RelayPackEntry{
		ExposureMode:     "cdn_fronted",
		FamilyClass:      "vps-native",
		ProbingRiskClass: "low",
		PublicRiskTags:   []string{"cdn:cloudflare", "public_domain:e.example.com"},
		OriginRiskTags:   []string{"origin_ip:5.75.0.1", "origin_provider:hetzner"},
	}
}

// twoRouteBundle returns a 2-route bundle where each route carries
// a fresh _relaypack entry. Both default to vps-native so RP014
// passes.
func twoRouteBundle(t *testing.T, e1, e2 bundle.RelayPackEntry) *bundle.Bundle {
	t.Helper()
	return bundleWith([]bundle.RouteManifestEntry{
		{ID: "r1", TransportFamily: "vless-reality", FamilySpecificConfig: packEntry(t, e1, nil)},
		{ID: "r2", TransportFamily: "naive", FamilySpecificConfig: packEntry(t, e2, nil)},
	}, &bundle.RelayPack{
		RelayPackID:     "rp-test",
		SharedRiskGraph: []bundle.SharedRiskEdge{},
	})
}

// expectError asserts Validate returns *ValidationError with Code == want.
func expectError(t *testing.T, b *bundle.Bundle, opts ValidateOpts, want Code) {
	t.Helper()
	_, err := Validate(b, opts)
	if err == nil {
		t.Fatalf("expected error %s, got nil", want)
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("expected *ValidationError, got %T: %v", err, err)
	}
	if ve.Code != want {
		t.Fatalf("expected code %s, got %s: %s", want, ve.Code, ve.Message)
	}
}

func expectOK(t *testing.T, b *bundle.Bundle, opts ValidateOpts) LintReport {
	t.Helper()
	rep, err := Validate(b, opts)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	return rep
}

// ----------------------------------------------------------------
// POSITIVE PATH (1 test per phase)
// ----------------------------------------------------------------

func TestPositive_TwoDirectVPSAtV15(t *testing.T) {
	b := twoRouteBundle(t, minimalDirectVPS(), minimalDirectVPS())
	rep, err := Validate(b, ValidateOpts{Phase: PhaseV15})
	if err != nil {
		t.Fatalf("expected V1.5 direct_vps positive case to pass, got %v", err)
	}
	// Lint may surface RP019 (all candidates share public_ip) — that's fine.
	for _, w := range rep.Warnings {
		if w.Code != CodeRP019 && w.Code != CodeRP020 {
			t.Errorf("unexpected warning %s: %s", w.Code, w.Message)
		}
	}
}

func TestPositive_DirectAndCDNAtV16(t *testing.T) {
	cdn := minimalCDN()
	b := twoRouteBundle(t, minimalDirectVPS(), cdn)
	if _, err := Validate(b, ValidateOpts{Phase: PhaseV16}); err != nil {
		t.Fatalf("expected V1.6 direct+cdn positive case to pass, got %v", err)
	}
}

func TestPositive_DirectVPSWithSNI(t *testing.T) {
	e := minimalDirectVPS()
	e.PublicRiskTags = append(e.PublicRiskTags, "sni:www.microsoft.com", "public_domain:host.example.com", "host:host.example.com")
	b := twoRouteBundle(t, e, minimalDirectVPS())
	if _, err := Validate(b, ValidateOpts{Phase: PhaseV15}); err != nil {
		t.Fatalf("expected sni/host/public_domain on direct_vps to pass, got %v", err)
	}
}

// ----------------------------------------------------------------
// RP001: _relaypack present without Manifest.RelayPack
// ----------------------------------------------------------------

func TestRP001_RelayPackMissingFromManifest(t *testing.T) {
	routes := []bundle.RouteManifestEntry{
		{ID: "r1", TransportFamily: "vless-reality", FamilySpecificConfig: packEntry(t, minimalDirectVPS(), nil)},
		{ID: "r2", TransportFamily: "naive", FamilySpecificConfig: packEntry(t, minimalDirectVPS(), nil)},
	}
	b := bundleWith(routes, nil) // RelayPack nil
	expectError(t, b, ValidateOpts{Phase: PhaseV15}, CodeRP001)
}

// ----------------------------------------------------------------
// RP002: bad exposure_mode
// ----------------------------------------------------------------

func TestRP002_UnknownExposureMode(t *testing.T) {
	bad := minimalDirectVPS()
	bad.ExposureMode = "totally-bogus"
	b := twoRouteBundle(t, bad, minimalDirectVPS())
	expectError(t, b, ValidateOpts{Phase: PhaseV15}, CodeRP002)
}

func TestRP002_MalformedRelayPackBlob(t *testing.T) {
	routes := []bundle.RouteManifestEntry{
		{ID: "r1", TransportFamily: "vless-reality",
			FamilySpecificConfig: json.RawMessage(`{"_relaypack":"not-an-object"}`)},
		{ID: "r2", TransportFamily: "naive", FamilySpecificConfig: packEntry(t, minimalDirectVPS(), nil)},
	}
	b := bundleWith(routes, &bundle.RelayPack{RelayPackID: "rp", SharedRiskGraph: []bundle.SharedRiskEdge{}})
	expectError(t, b, ValidateOpts{Phase: PhaseV15}, CodeRP002)
}

// ----------------------------------------------------------------
// RP003: serverless_external rejected at V15 / V16
// ----------------------------------------------------------------

func TestRP003_ServerlessAtV15(t *testing.T) {
	bad := minimalDirectVPS()
	bad.ExposureMode = "serverless_external"
	bad.PublicRiskTags = []string{"public_func:aws-lambda"}
	bad.OriginRiskTags = []string{}
	b := twoRouteBundle(t, bad, minimalDirectVPS())
	expectError(t, b, ValidateOpts{Phase: PhaseV15}, CodeRP003)
}

func TestRP003_ServerlessAtV16(t *testing.T) {
	bad := minimalDirectVPS()
	bad.ExposureMode = "serverless_external"
	bad.PublicRiskTags = []string{"public_func:aws-lambda"}
	bad.OriginRiskTags = []string{}
	b := twoRouteBundle(t, bad, minimalDirectVPS())
	expectError(t, b, ValidateOpts{Phase: PhaseV16}, CodeRP003)
}

// ----------------------------------------------------------------
// RP004: cdn_fronted rejected at V15
// ----------------------------------------------------------------

func TestRP004_CDNAtV15(t *testing.T) {
	b := twoRouteBundle(t, minimalCDN(), minimalDirectVPS())
	expectError(t, b, ValidateOpts{Phase: PhaseV15}, CodeRP004)
}

// ----------------------------------------------------------------
// RP005: cdn_fronted requires >=1 cdn:* tag
// ----------------------------------------------------------------

func TestRP005_CDNMissingCDNTag(t *testing.T) {
	bad := minimalCDN()
	bad.PublicRiskTags = []string{"public_domain:e.example.com"} // no cdn:*
	b := twoRouteBundle(t, bad, minimalDirectVPS())
	expectError(t, b, ValidateOpts{Phase: PhaseV16}, CodeRP005)
}

// ----------------------------------------------------------------
// RP006: cdn_fronted requires >=1 origin_* tag
// ----------------------------------------------------------------

func TestRP006_CDNMissingOriginTag(t *testing.T) {
	bad := minimalCDN()
	bad.OriginRiskTags = []string{} // no origin_*
	b := twoRouteBundle(t, bad, minimalDirectVPS())
	expectError(t, b, ValidateOpts{Phase: PhaseV16}, CodeRP006)
}

// ----------------------------------------------------------------
// RP007: cdn_fronted family compat per §11.1.1
// ----------------------------------------------------------------

func TestRP007_HysteriaCDNRejected(t *testing.T) {
	cdn := minimalCDN()
	routes := []bundle.RouteManifestEntry{
		{ID: "r1", TransportFamily: "hysteria2", FamilySpecificConfig: packEntry(t, cdn, nil)},
		{ID: "r2", TransportFamily: "naive", FamilySpecificConfig: packEntry(t, minimalDirectVPS(), nil)},
	}
	b := bundleWith(routes, &bundle.RelayPack{RelayPackID: "rp", SharedRiskGraph: []bundle.SharedRiskEdge{}})
	expectError(t, b, ValidateOpts{Phase: PhaseV16}, CodeRP007)
}

// ----------------------------------------------------------------
// RP008: direct_vps requires public_ip:* tag
// ----------------------------------------------------------------

func TestRP008_DirectMissingPublicIP(t *testing.T) {
	bad := minimalDirectVPS()
	bad.PublicRiskTags = []string{"public_port:tcp443"} // no public_ip
	b := twoRouteBundle(t, bad, minimalDirectVPS())
	expectError(t, b, ValidateOpts{Phase: PhaseV15}, CodeRP008)
}

// ----------------------------------------------------------------
// RP009: direct_vps must NOT carry cdn:* tag
// ----------------------------------------------------------------

func TestRP009_DirectWithCDNTag(t *testing.T) {
	bad := minimalDirectVPS()
	bad.PublicRiskTags = append(bad.PublicRiskTags, "cdn:cloudflare")
	b := twoRouteBundle(t, bad, minimalDirectVPS())
	expectError(t, b, ValidateOpts{Phase: PhaseV15}, CodeRP009)
}

// ----------------------------------------------------------------
// RP010: direct_vps must NOT carry origin_* tag
// ----------------------------------------------------------------

func TestRP010_DirectWithOriginTag(t *testing.T) {
	bad := minimalDirectVPS()
	bad.OriginRiskTags = []string{"origin_ip:5.75.0.1"}
	b := twoRouteBundle(t, bad, minimalDirectVPS())
	expectError(t, b, ValidateOpts{Phase: PhaseV15}, CodeRP010)
}

// ----------------------------------------------------------------
// RP011: family_class enum
// ----------------------------------------------------------------

func TestRP011_BadFamilyClass(t *testing.T) {
	bad := minimalDirectVPS()
	bad.FamilyClass = "garbage"
	b := twoRouteBundle(t, bad, minimalDirectVPS())
	expectError(t, b, ValidateOpts{Phase: PhaseV15}, CodeRP011)
}

// ----------------------------------------------------------------
// RP012: probing_risk_class enum
// ----------------------------------------------------------------

func TestRP012_BadProbingRiskClass(t *testing.T) {
	bad := minimalDirectVPS()
	bad.ProbingRiskClass = "extreme"
	b := twoRouteBundle(t, bad, minimalDirectVPS())
	expectError(t, b, ValidateOpts{Phase: PhaseV15}, CodeRP012)
}

// ----------------------------------------------------------------
// RP013: non-empty modifiers[] rejected at V15 / V16
// ----------------------------------------------------------------

func TestRP013_ModifiersAtV15(t *testing.T) {
	bad := minimalDirectVPS()
	bad.Modifiers = []bundle.Modifier{{Kind: "client_desync", Platform: "linux_desktop_only", ProbingRiskClass: "high"}}
	b := twoRouteBundle(t, bad, minimalDirectVPS())
	expectError(t, b, ValidateOpts{Phase: PhaseV15}, CodeRP013)
}

func TestRP013_ModifiersAtV16(t *testing.T) {
	bad := minimalDirectVPS()
	bad.Modifiers = []bundle.Modifier{{Kind: "client_desync"}}
	b := twoRouteBundle(t, bad, minimalDirectVPS())
	expectError(t, b, ValidateOpts{Phase: PhaseV16}, CodeRP013)
}

func TestRP013_ModifiersAtPostV2NotInAllowList(t *testing.T) {
	bad := minimalDirectVPS()
	bad.Modifiers = []bundle.Modifier{{Kind: "tls_fragment"}}
	b := twoRouteBundle(t, bad, minimalDirectVPS())
	opts := ValidateOpts{Phase: PhasePostV2, AllowedModifierKinds: map[string]bool{"client_desync": true}}
	expectError(t, b, opts, CodeRP013)
}

func TestRP013_ModifiersAtPostV2Allowed(t *testing.T) {
	good := minimalDirectVPS()
	good.Modifiers = []bundle.Modifier{{Kind: "client_desync", Platform: "linux_desktop_only", ProbingRiskClass: "high"}}
	b := twoRouteBundle(t, good, minimalDirectVPS())
	opts := ValidateOpts{Phase: PhasePostV2, AllowedModifierKinds: map[string]bool{"client_desync": true}}
	if _, err := Validate(b, opts); err != nil {
		t.Fatalf("expected modifier in allow-list to pass, got %v", err)
	}
}

// ----------------------------------------------------------------
// RP014: bundle must contain >=2 vps-native candidates
// ----------------------------------------------------------------

func TestRP014_OneCandidate(t *testing.T) {
	routes := []bundle.RouteManifestEntry{
		{ID: "r1", TransportFamily: "vless-reality", FamilySpecificConfig: packEntry(t, minimalDirectVPS(), nil)},
	}
	b := bundleWith(routes, &bundle.RelayPack{RelayPackID: "rp", SharedRiskGraph: []bundle.SharedRiskEdge{}})
	expectError(t, b, ValidateOpts{Phase: PhaseV15}, CodeRP014)
}

func TestRP014_TwoButOneIsExternalEcosystem(t *testing.T) {
	e := minimalDirectVPS()
	e.FamilyClass = "external-ecosystem"
	b := twoRouteBundle(t, minimalDirectVPS(), e) // 1 vps-native
	expectError(t, b, ValidateOpts{Phase: PhaseV15}, CodeRP014)
}

// ----------------------------------------------------------------
// RP015: external-ecosystem rejected for FRP-self-hosted
// ----------------------------------------------------------------

func TestRP015_ExternalEcosystemSelfHosted(t *testing.T) {
	a := minimalDirectVPS() // r1 is vps-native
	bad := minimalDirectVPS()
	bad.FamilyClass = "external-ecosystem"
	c := minimalDirectVPS() // r3 is vps-native (so RP014 passes: 2 vps-native)
	routes := []bundle.RouteManifestEntry{
		{ID: "r1", TransportFamily: "vless-reality", FamilySpecificConfig: packEntry(t, a, nil)},
		{ID: "r2", TransportFamily: "naive", FamilySpecificConfig: packEntry(t, bad, nil)},
		{ID: "r3", TransportFamily: "websocket-tls", FamilySpecificConfig: packEntry(t, c, nil)},
	}
	b := bundleWith(routes, &bundle.RelayPack{RelayPackID: "rp", SharedRiskGraph: []bundle.SharedRiskEdge{}})
	opts := ValidateOpts{Phase: PhaseV15, FRPSelfHosted: map[string]bool{"r2": true}}
	expectError(t, b, opts, CodeRP015)
}

// ----------------------------------------------------------------
// RP016: cell_scope rejected at V15
// ----------------------------------------------------------------

func TestRP016_CellScopeAtV15(t *testing.T) {
	bad := minimalDirectVPS()
	bad.CellScope = &bundle.CellScope{CellID: "moms-may-2026", CellMaxDepth: 1}
	b := twoRouteBundle(t, bad, minimalDirectVPS())
	expectError(t, b, ValidateOpts{Phase: PhaseV15}, CodeRP016)
}

// ----------------------------------------------------------------
// RP017: legacy flat shared_risk_tags array
// ----------------------------------------------------------------

func TestRP017_LegacyFlatSharedRiskTags(t *testing.T) {
	blob := json.RawMessage(`{"_relaypack":{"exposure_mode":"direct_vps","family_class":"vps-native","probing_risk_class":"low","public_risk_tags":["public_ip:5.75.0.1"],"origin_risk_tags":[]},"shared_risk_tags":["legacy"]}`)
	routes := []bundle.RouteManifestEntry{
		{ID: "r1", TransportFamily: "vless-reality", FamilySpecificConfig: blob},
		{ID: "r2", TransportFamily: "naive", FamilySpecificConfig: packEntry(t, minimalDirectVPS(), nil)},
	}
	b := bundleWith(routes, &bundle.RelayPack{RelayPackID: "rp", SharedRiskGraph: []bundle.SharedRiskEdge{}})
	_, err := Validate(b, ValidateOpts{Phase: PhaseV15})
	if err == nil {
		t.Fatalf("expected RP017 error")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Code != CodeRP017 {
		t.Fatalf("expected RP017, got %v", err)
	}
	if !strings.Contains(ve.Message, "v2.3.5") || !strings.Contains(ve.Message, "specs/relaypack-v1.md") {
		t.Errorf("RP017 message must point at v2.3.5 + specs/relaypack-v1.md, got: %s", ve.Message)
	}
}

// ----------------------------------------------------------------
// RP018: shared_risk_graph members must be known candidate IDs
// ----------------------------------------------------------------

func TestRP018_DanglingSharedRiskGraphMember(t *testing.T) {
	b := twoRouteBundle(t, minimalDirectVPS(), minimalDirectVPS())
	b.Manifest.RelayPack.SharedRiskGraph = []bundle.SharedRiskEdge{
		{Tag: "public_ip:5.75.0.1", Members: []string{"r1", "r2", "ghost"}},
	}
	expectError(t, b, ValidateOpts{Phase: PhaseV15}, CodeRP018)
}

// ----------------------------------------------------------------
// RP021: freshness_url rejected at V15; FRP-8 lifts at V16
// ----------------------------------------------------------------

func TestRP021_FreshnessURLAtV15(t *testing.T) {
	b := twoRouteBundle(t, minimalDirectVPS(), minimalDirectVPS())
	b.Manifest.RelayPack.FreshnessURL = "https://frp.example.com/relaypack.json"
	expectError(t, b, ValidateOpts{Phase: PhaseV15}, CodeRP021)
}

func TestRP021_FreshnessURLAtV16(t *testing.T) {
	b := twoRouteBundle(t, minimalDirectVPS(), minimalDirectVPS())
	b.Manifest.RelayPack.FreshnessURL = "https://frp.example.com/relaypack.json"
	expectOK(t, b, ValidateOpts{Phase: PhaseV16})
}

// ----------------------------------------------------------------
// RP019: warning — all candidates share every public_risk_tag
// ----------------------------------------------------------------

func TestRP019_AllShareSameTags(t *testing.T) {
	// Both candidates have IDENTICAL PublicRiskTags.
	b := twoRouteBundle(t, minimalDirectVPS(), minimalDirectVPS())
	rep := expectOK(t, b, ValidateOpts{Phase: PhaseV15})
	found := false
	for _, w := range rep.Warnings {
		if w.Code == CodeRP019 {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected RP019 warning, got %+v", rep.Warnings)
	}
}

func TestRP019_DiverseTagsNoWarning(t *testing.T) {
	a := minimalDirectVPS()
	b := minimalDirectVPS()
	b.PublicRiskTags = []string{"public_ip:1.2.3.4", "public_port:tcp443"}
	bn := twoRouteBundle(t, a, b)
	rep := expectOK(t, bn, ValidateOpts{Phase: PhaseV15})
	for _, w := range rep.Warnings {
		if w.Code == CodeRP019 {
			t.Fatalf("RP019 should not fire when public tags differ, got %+v", rep.Warnings)
		}
	}
}

// ----------------------------------------------------------------
// RP020: warning — no UDP-shaped candidate AND no udp_gated:true
// ----------------------------------------------------------------

func TestRP020_NoUDPCoverage(t *testing.T) {
	b := twoRouteBundle(t, minimalDirectVPS(), minimalDirectVPS())
	rep := expectOK(t, b, ValidateOpts{Phase: PhaseV15})
	found := false
	for _, w := range rep.Warnings {
		if w.Code == CodeRP020 {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected RP020 warning, got %+v", rep.Warnings)
	}
}

func TestRP020_HysteriaSilencesWarning(t *testing.T) {
	a := minimalDirectVPS()
	c := minimalDirectVPS()
	routes := []bundle.RouteManifestEntry{
		{ID: "r1", TransportFamily: "vless-reality", FamilySpecificConfig: packEntry(t, a, nil)},
		{ID: "r2", TransportFamily: "hysteria2", FamilySpecificConfig: packEntry(t, c, nil)},
	}
	b := bundleWith(routes, &bundle.RelayPack{RelayPackID: "rp", SharedRiskGraph: []bundle.SharedRiskEdge{}})
	rep := expectOK(t, b, ValidateOpts{Phase: PhaseV15})
	for _, w := range rep.Warnings {
		if w.Code == CodeRP020 {
			t.Fatalf("RP020 should not fire when a UDP family is present, got %+v", rep.Warnings)
		}
	}
}

// ----------------------------------------------------------------
// Non-RelayPack bundles: validator inert (regression)
// ----------------------------------------------------------------

func TestNonRelayPackBundleInert(t *testing.T) {
	routes := []bundle.RouteManifestEntry{
		{ID: "r1", TransportFamily: "vless-reality"},
		{ID: "r2", TransportFamily: "naive"},
	}
	b := bundleWith(routes, nil)
	if _, err := Validate(b, ValidateOpts{Phase: PhaseV15}); err != nil {
		t.Fatalf("expected non-RelayPack bundle to pass through, got %v", err)
	}
}

// ----------------------------------------------------------------
// Phase progression: same bundle, different phase outcomes
// ----------------------------------------------------------------

func TestPhaseProgression_CDNV15RejectV16Accept(t *testing.T) {
	cdn := minimalCDN()
	b := twoRouteBundle(t, cdn, minimalDirectVPS())
	// V1.5 rejects.
	expectError(t, b, ValidateOpts{Phase: PhaseV15}, CodeRP004)
	// V1.6 accepts.
	if _, err := Validate(b, ValidateOpts{Phase: PhaseV16}); err != nil {
		t.Fatalf("V1.6 should accept cdn_fronted, got %v", err)
	}
}
