package importer_test

// FRP-2 (Phase 30) importer tests. Exercise the importer's
// RelayPack hook directly via in-memory fixtures (we synthesise
// signed bundles inline so this file does not depend on the
// FRP-2 corpus regeneration in commit 4).

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"daal/bundle-go/bundle"
	"daal/bundle-go/importer"
)

// fakeState captures the inputs SaveImport receives so tests can
// inspect them without touching SQLite.
type fakeState struct {
	saved         [][]importer.RouteInput
	pinned        map[string]importer.Pin
	saveErr       error
	revokedRoutes []string
	revokedPubs   []string
	saveCalls     int
}

func newFakeState() *fakeState {
	return &fakeState{pinned: map[string]importer.Pin{}}
}

func (f *fakeState) LookupPublisher(fp string) (importer.Pin, bool, error) {
	p, ok := f.pinned[fp]
	return p, ok, nil
}

func (f *fakeState) SaveImport(p importer.PublisherInput, routes []importer.RouteInput) error {
	f.saveCalls++
	if f.saveErr != nil {
		return f.saveErr
	}
	cp := append([]importer.RouteInput(nil), routes...)
	f.saved = append(f.saved, cp)
	// Pin the publisher so a subsequent ImportBytes is silent.
	f.pinned[p.Fingerprint] = importer.Pin{
		TrustLevel:    p.TrustLevel,
		KeyStatus:     p.KeyStatus,
		DisplayName:   p.DisplayName,
		RotationChain: p.RotationChain,
	}
	return nil
}

func (f *fakeState) MarkPublisherRevoked(fp, source, reason string, now time.Time) error {
	f.revokedPubs = append(f.revokedPubs, fp)
	return nil
}

func (f *fakeState) MarkRouteRevoked(routeID string) error {
	f.revokedRoutes = append(f.revokedRoutes, routeID)
	return nil
}

// ----------------------------------------------------------------
// Fixture builders.
// ----------------------------------------------------------------

func wordlists() bundle.Wordlists {
	// Minimal in-test wordlists; the importer renders fingerprints
	// for UI surfaces but tests don't depend on the rendered words.
	return bundle.Wordlists{
		English: []string{"a", "b", "c", "d", "e", "f", "g", "h"},
		Persian: []string{"الف", "ب", "پ", "ت", "ث", "ج", "چ", "ح"},
	}
}

// makeBundle builds a signed bundle whose manifest the caller
// customises via the optional `mutate` callback. Returns the
// sealed .sbp bytes.
func makeBundle(t *testing.T, mutate func(m *bundle.Manifest)) []byte {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	m := bundle.Manifest{
		SpecVersion: 1,
		Publisher: bundle.PublisherInfo{
			Name:              "FRP-2 Importer Test",
			KeyFingerprintHex: bundle.PublisherFingerprint(pub).Hex,
			KeyCreatedAt:      now.Format(time.RFC3339),
			TrustClass:        "unknown",
		},
		Bundle: bundle.BundleInfo{
			ID:             "bundle-frp2-test",
			Type:           "provider",
			CreatedAt:      now.Format(time.RFC3339),
			ExpiresAt:      now.Add(24 * time.Hour).Format(time.RFC3339),
			SupersedesKeys: []string{},
		},
		Routes: []bundle.RouteManifestEntry{
			{
				ID:              "rA",
				ScarcityClass:   "normal",
				TransportFamily: "vless-reality",
				ConfigPath:      "profiles/rA.json",
				ValidUntil:      now.Add(24 * time.Hour).Format(time.RFC3339),
			},
			{
				ID:              "rB",
				ScarcityClass:   "normal",
				TransportFamily: "vless-reality",
				ConfigPath:      "profiles/rB.json",
				ValidUntil:      now.Add(24 * time.Hour).Format(time.RFC3339),
			},
		},
	}
	if mutate != nil {
		mutate(&m)
	}
	profiles := map[string][]byte{
		"profiles/rA.json": []byte(`{"type":"direct"}`),
		"profiles/rB.json": []byte(`{"type":"direct"}`),
	}
	data, err := bundle.BuildSignedBundle(m, profiles, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// addRelayPack populates the bundle slot and per-candidate
// _relaypack sub-objects with V1.5-positive values shared across
// both rA and rB.
func addRelayPack(t *testing.T, m *bundle.Manifest) {
	t.Helper()
	m.SpecVersion = 3
	m.RelayPack = &bundle.RelayPack{
		RelayPackID: "rp-importer-test-001",
		SharedRiskGraph: []bundle.SharedRiskEdge{
			{Tag: "public_ip:5.75.0.1", Members: []string{"rA", "rB"}},
			{Tag: "public_asn:24940", Members: []string{"rA", "rB"}},
		},
	}
	for i := range m.Routes {
		entry := bundle.RelayPackEntry{
			ExposureMode:     "direct_vps",
			FamilyClass:      "vps-native",
			ProbingRiskClass: "low",
			PublicRiskTags: []string{
				"public_ip:5.75.0.1",
				"public_asn:24940",
			},
			OriginRiskTags: []string{},
		}
		fcBytes, err := json.Marshal(map[string]any{"_relaypack": entry})
		if err != nil {
			t.Fatal(err)
		}
		m.Routes[i].FamilySpecificConfig = json.RawMessage(fcBytes)
	}
}

// ----------------------------------------------------------------
// Tests.
// ----------------------------------------------------------------

// TestImport_RelayPackEntryFlowsToFakeState — bundle with
// _relaypack. Importer parses, validates (V1.5 OK), builds
// RelayPackMeta on every RouteInput, and SaveImport receives
// the fully-populated structs. Bundle-level fields (RelayPackID,
// SharedRiskGraphJSON) are denormalised across all routes.
func TestImport_RelayPackEntryFlowsToFakeState(t *testing.T) {
	body := makeBundle(t, func(m *bundle.Manifest) { addRelayPack(t, m) })
	st := newFakeState()
	now := time.Now().UTC()

	// First import is silent because publisher is pinned via
	// AcceptTrustPrompt below — but the first call yields a
	// trust prompt.
	v, err := importer.ImportBytes(body, st, wordlists(), now)
	if err != nil {
		t.Fatalf("first import error: %v verdict=%+v", err, v)
	}
	if v.Kind != importer.VerdictTrustPromptNeeded {
		t.Fatalf("expected trust prompt; got %+v", v)
	}
	v2, err := importer.AcceptTrustPrompt("trust", body, st, wordlists(), now)
	if err != nil {
		t.Fatalf("accept-trust err: %v verdict=%+v", err, v2)
	}
	if v2.Kind != importer.VerdictImported {
		t.Fatalf("expected VerdictImported; got %+v", v2)
	}
	if len(st.saved) == 0 || len(st.saved[0]) != 2 {
		t.Fatalf("expected 2 routes saved; got %v", st.saved)
	}
	for i, ri := range st.saved[0] {
		if ri.RelayPack == nil {
			t.Fatalf("route[%d] RelayPack must be non-nil", i)
		}
		if ri.RelayPack.ExposureMode != "direct_vps" {
			t.Errorf("route[%d] ExposureMode = %q want direct_vps", i, ri.RelayPack.ExposureMode)
		}
		if ri.RelayPack.FamilyClass != "vps-native" {
			t.Errorf("route[%d] FamilyClass = %q", i, ri.RelayPack.FamilyClass)
		}
		if ri.RelayPack.RelayPackID != "rp-importer-test-001" {
			t.Errorf("route[%d] RelayPackID = %q", i, ri.RelayPack.RelayPackID)
		}
		if ri.RelayPack.FreshnessURL != "" {
			t.Errorf("route[%d] FreshnessURL must be '' at V1.5; got %q", i, ri.RelayPack.FreshnessURL)
		}
		if ri.RelayPack.SharedRiskGraphJSON == "" || ri.RelayPack.SharedRiskGraphJSON == "[]" {
			t.Errorf("route[%d] SharedRiskGraphJSON must be populated; got %q", i, ri.RelayPack.SharedRiskGraphJSON)
		}
		if ri.RelayPack.ModifiersJSON != "" {
			t.Errorf("route[%d] ModifiersJSON must be '' at V1.5 (RP013); got %q", i, ri.RelayPack.ModifiersJSON)
		}
	}
	// Bundle-level metadata is the SAME on every per-route entry.
	if st.saved[0][0].RelayPack.SharedRiskGraphJSON != st.saved[0][1].RelayPack.SharedRiskGraphJSON {
		t.Errorf("SharedRiskGraphJSON must be identical across routes (denormalised)")
	}
	if st.saved[0][0].RelayPack.RelayPackID != st.saved[0][1].RelayPack.RelayPackID {
		t.Errorf("RelayPackID must be identical across routes (denormalised)")
	}
}

// TestImport_NoRelayPack_LegacyPath — bundle without _relaypack.
// All RouteInputs have RelayPack == nil; importer succeeds.
func TestImport_NoRelayPack_LegacyPath(t *testing.T) {
	body := makeBundle(t, nil) // no RelayPack
	st := newFakeState()
	now := time.Now().UTC()

	if _, err := importer.AcceptTrustPrompt("trust", body, st, wordlists(), now); err != nil {
		t.Fatalf("accept-trust err: %v", err)
	}
	if len(st.saved) == 0 {
		t.Fatal("nothing saved")
	}
	for i, ri := range st.saved[0] {
		if ri.RelayPack != nil {
			t.Errorf("route[%d] RelayPack must be nil for non-RelayPack bundle; got %+v", i, ri.RelayPack)
		}
	}
}

// TestImport_RelayPackV15_RejectsCDNFronted — RP004. Bundle with
// cdn_fronted candidate at V1.5 is rejected; Verdict.Reason carries
// the lint code.
func TestImport_RelayPackV15_RejectsCDNFronted(t *testing.T) {
	body := makeBundle(t, func(m *bundle.Manifest) {
		addRelayPack(t, m)
		// Override route rA's exposure_mode to cdn_fronted.
		entry := bundle.RelayPackEntry{
			ExposureMode:     "cdn_fronted",
			FamilyClass:      "vps-native",
			ProbingRiskClass: "low",
			PublicRiskTags:   []string{"cdn:cloudflare", "public_domain:test.example"},
			OriginRiskTags:   []string{"origin_ip:10.0.0.1"},
		}
		fc, _ := json.Marshal(map[string]any{"_relaypack": entry})
		m.Routes[0].FamilySpecificConfig = fc
	})
	st := newFakeState()
	now := time.Now().UTC()

	// AcceptTrustPrompt invokes apply() which runs the validator.
	v, err := importer.AcceptTrustPrompt("trust", body, st, wordlists(), now)
	if err == nil {
		t.Fatalf("expected validator error at V1.5; got nil (verdict=%+v)", v)
	}
	if v.Kind != importer.VerdictRejected {
		t.Fatalf("expected VerdictRejected; got %v", v.Kind)
	}
	if v.Reason != "relaypack_RP004" {
		t.Errorf("Reason = %q want relaypack_RP004", v.Reason)
	}
	if len(st.saved) != 0 {
		t.Errorf("nothing must be saved on validator-reject; got %d save calls", len(st.saved))
	}
}

// TestImportBytes_RelayPackV15RejectsBeforeTrustPrompt verifies that
// invalid first-seen RelayPacks do not reach the trust-prompt surface.
// FRP-6 relies on the initial import verdict carrying relaypack_RPxxx.
func TestImportBytes_RelayPackV15RejectsBeforeTrustPrompt(t *testing.T) {
	body := makeBundle(t, func(m *bundle.Manifest) {
		addRelayPack(t, m)
		entry := bundle.RelayPackEntry{
			ExposureMode:     "cdn_fronted",
			FamilyClass:      "vps-native",
			ProbingRiskClass: "low",
			PublicRiskTags:   []string{"cdn:cloudflare", "public_domain:test.example"},
			OriginRiskTags:   []string{"origin_ip:10.0.0.1"},
		}
		fc, _ := json.Marshal(map[string]any{"_relaypack": entry})
		m.Routes[0].FamilySpecificConfig = fc
	})
	st := newFakeState()
	now := time.Now().UTC()

	v, err := importer.ImportBytes(body, st, wordlists(), now)
	if err == nil || v.Kind != importer.VerdictRejected {
		t.Fatalf("expected initial ImportBytes rejection; got verdict=%+v err=%v", v, err)
	}
	if v.Reason != "relaypack_RP004" {
		t.Errorf("Reason = %q want relaypack_RP004", v.Reason)
	}
	if st.saveCalls != 0 || len(st.saved) != 0 {
		t.Errorf("invalid first-seen RelayPack must not be saved; saveCalls=%d saved=%d", st.saveCalls, len(st.saved))
	}
}

func TestImportBytes_RevokedPublisherStillTakesPriorityOverRelayPackValidation(t *testing.T) {
	body := makeBundle(t, func(m *bundle.Manifest) {
		addRelayPack(t, m)
		entry := bundle.RelayPackEntry{
			ExposureMode:     "cdn_fronted",
			FamilyClass:      "vps-native",
			ProbingRiskClass: "low",
			PublicRiskTags:   []string{"cdn:cloudflare", "public_domain:test.example"},
			OriginRiskTags:   []string{"origin_ip:10.0.0.1"},
		}
		fc, _ := json.Marshal(map[string]any{"_relaypack": entry})
		m.Routes[0].FamilySpecificConfig = fc
	})
	parsed, err := bundle.ParseSBP(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	fp := bundle.PublisherFingerprint(parsed.PublisherPub)
	st := newFakeState()
	st.pinned[fp.Hex] = importer.Pin{TrustLevel: "revoked"}

	v, err := importer.ImportBytes(body, st, wordlists(), time.Now().UTC())
	if err == nil || v.Kind != importer.VerdictRejected {
		t.Fatalf("expected revoked publisher rejection; got verdict=%+v err=%v", v, err)
	}
	if v.Reason != "publisher_revoked" {
		t.Errorf("Reason = %q want publisher_revoked", v.Reason)
	}
	if st.saveCalls != 0 {
		t.Errorf("revoked publisher must not save; saveCalls=%d", st.saveCalls)
	}
}

// TestImport_RelayPackV15_RejectsModifiers — RP013. Bundle with
// non-empty modifiers[] at V1.5 is rejected.
func TestImport_RelayPackV15_RejectsModifiers(t *testing.T) {
	body := makeBundle(t, func(m *bundle.Manifest) {
		addRelayPack(t, m)
		entry := bundle.RelayPackEntry{
			ExposureMode:     "direct_vps",
			FamilyClass:      "vps-native",
			ProbingRiskClass: "low",
			PublicRiskTags:   []string{"public_ip:5.75.0.1", "public_asn:24940"},
			OriginRiskTags:   []string{},
			Modifiers: []bundle.Modifier{
				{Kind: "tls_fragment"},
			},
		}
		fc, _ := json.Marshal(map[string]any{"_relaypack": entry})
		m.Routes[0].FamilySpecificConfig = fc
	})
	st := newFakeState()
	now := time.Now().UTC()

	v, err := importer.AcceptTrustPrompt("trust", body, st, wordlists(), now)
	if err == nil || v.Kind != importer.VerdictRejected {
		t.Fatalf("expected VerdictRejected; got verdict=%+v err=%v", v, err)
	}
	if v.Reason != "relaypack_RP013" {
		t.Errorf("Reason = %q want relaypack_RP013", v.Reason)
	}
}

// TestImport_RelayPackV15_RejectsFreshnessURL — RP021. Bundle with
// non-empty freshness_url at V1.5 is rejected.
func TestImport_RelayPackV15_RejectsFreshnessURL(t *testing.T) {
	body := makeBundle(t, func(m *bundle.Manifest) {
		addRelayPack(t, m)
		m.RelayPack.FreshnessURL = "https://frp.example/relaypack.json"
	})
	st := newFakeState()
	now := time.Now().UTC()

	v, err := importer.AcceptTrustPrompt("trust", body, st, wordlists(), now)
	if err == nil || v.Kind != importer.VerdictRejected {
		t.Fatalf("expected VerdictRejected; got verdict=%+v err=%v", v, err)
	}
	if v.Reason != "relaypack_RP021" {
		t.Errorf("Reason = %q want relaypack_RP021", v.Reason)
	}
}

// TestApplyVerifiedRefresh_UsesV16Phase ensures the freshness-driven
// no-QR swap path accepts the FRP-8 `freshness_url` lift. A regression
// here means ApplyVerifiedRefresh validated V16 and then accidentally
// persisted through the V15 QR-import helper, causing RP021.
func TestApplyVerifiedRefresh_UsesV16Phase(t *testing.T) {
	body := makeBundle(t, func(m *bundle.Manifest) {
		addRelayPack(t, m)
		m.RelayPack.FreshnessURL = "https://frp.example/relaypack-freshness.json"
	})
	parsed, err := bundle.ParseSBP(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	fp := bundle.PublisherFingerprint(parsed.PublisherPub)
	st := newFakeState()
	st.pinned[fp.Hex] = importer.Pin{
		TrustLevel:  "tofu_friend",
		KeyStatus:   "active",
		DisplayName: "FRP-2 Importer Test",
	}
	sum := sha256.Sum256(body)

	v, err := importer.ApplyVerifiedRefresh(body, hex.EncodeToString(sum[:]), st, wordlists(), time.Now().UTC())
	if err != nil {
		t.Fatalf("ApplyVerifiedRefresh err: %v verdict=%+v", err, v)
	}
	if v.Kind != importer.VerdictImported {
		t.Fatalf("expected VerdictImported, got %+v", v)
	}
	if len(st.saved) != 1 || len(st.saved[0]) == 0 {
		t.Fatalf("expected saved routes, got %+v", st.saved)
	}
	if got := st.saved[0][0].RelayPack.FreshnessURL; got == "" {
		t.Fatalf("freshness_url was not preserved on V16 refresh import")
	}
}

// TestImport_RouteRelayPackWithoutBundleSlot_Rejected — RP001.
// Bundle has route-level _relaypack but the bundle slot is absent.
// This is the regression test for the unconditional-validation
// requirement: gating on slot presence here would silently bypass
// RP001.
func TestImport_RouteRelayPackWithoutBundleSlot_Rejected(t *testing.T) {
	body := makeBundle(t, func(m *bundle.Manifest) {
		// Do NOT set m.RelayPack.
		entry := bundle.RelayPackEntry{
			ExposureMode:     "direct_vps",
			FamilyClass:      "vps-native",
			ProbingRiskClass: "low",
			PublicRiskTags:   []string{"public_ip:5.75.0.1"},
		}
		fc, _ := json.Marshal(map[string]any{"_relaypack": entry})
		m.Routes[0].FamilySpecificConfig = fc
	})
	st := newFakeState()
	now := time.Now().UTC()

	v, err := importer.AcceptTrustPrompt("trust", body, st, wordlists(), now)
	if err == nil || v.Kind != importer.VerdictRejected {
		t.Fatalf("expected VerdictRejected; got verdict=%+v err=%v", v, err)
	}
	if v.Reason != "relaypack_RP001" {
		t.Errorf("Reason = %q want relaypack_RP001 (regression test for unconditional validation)", v.Reason)
	}
}
