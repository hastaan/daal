package abi

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"daal/core/routestore"
)

func TestSubscriptionAddListRemoveRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	out, err := SubscriptionAdd("publisherFP", "https://example.invalid/sub", "Test Sub")
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if !strings.Contains(out, "subscription_id") {
		t.Fatalf("missing subscription_id in %s", out)
	}
	subID := extractField(out, "subscription_id")
	if subID == "" {
		t.Fatalf("could not parse id from %s", out)
	}
	listed, err := SubscriptionList()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(listed, subID) {
		t.Fatalf("subscription not listed: %s", listed)
	}
	if strings.Contains(listed, "https://example.invalid") {
		t.Fatalf("URL leaked into list output: %s", listed)
	}
	if err := SubscriptionRemove(subID); err != nil {
		t.Fatalf("remove: %v", err)
	}
	listed2, _ := SubscriptionList()
	if strings.Contains(listed2, subID) {
		t.Fatalf("subscription still listed after remove: %s", listed2)
	}
}

func TestRevocationRefreshAllNoTargets(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })
	out, err := RevocationRefreshAll(2000)
	if err != nil {
		t.Fatalf("refresh-all: %v", err)
	}
	if !strings.Contains(out, "results") {
		t.Fatalf("expected results key: %s", out)
	}
}

func TestPointerRotationStatusEmbeddedOnly(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })
	out, err := PointerRotationStatus()
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !strings.Contains(out, `"primary_source":"embedded"`) {
		t.Fatalf("expected embedded source: %s", out)
	}
}

func TestDiagnosticsExplainNoActiveRoute(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })
	out, err := DiagnosticsExplain()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"state":"NoRoute"`) {
		t.Fatalf("expected NoRoute state: %s", out)
	}
	if !strings.Contains(out, `"pick"`) {
		t.Fatalf("expected FRP-3 Explanation pick field: %s", out)
	}
}

func TestDiagnosticsExplainCarriesExplanationPickForActiveRoute(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	c := mustCore()
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	if err := c.store.UpsertPublisher(routestore.PublisherRow{
		PublisherID: "fp1", DisplayName: "Pub 1", TrustLevel: "tofu_friend",
		FirstSeen: "2026-05-03T12:00:00Z", LastSeenBundle: "2026-05-03T12:00:00Z",
		KeyStatus: "active", RotationChain: []string{}, RevocationSources: []string{},
	}); err != nil {
		t.Fatal(err)
	}
	if err := c.store.UpsertRoute(routestore.RouteRow{
		RouteID: "r-frp6", TransportFamily: "vless-reality", Engine: "sing-box",
		SourceType: "trusted_provider", PublisherID: "fp1",
		PublisherLabel: "Pub 1", TrustState: "tofu", ScarcityClass: "normal",
		ModesAllowed: []string{"normal"}, ExpiresAt: "2026-06-03T12:00:00Z",
		ImportedAt:   routestore.HourBucket(now),
		ExposureMode: "direct_vps", FamilyClass: "vps-native",
		ProbingRiskClass: "low", PublicRiskTags: []string{"public_ip:5.75.0.1"},
		RelayPackID: "rp-test",
	}); err != nil {
		t.Fatal(err)
	}
	c.pm.Attempt("r-frp6", "vless-reality")
	c.pm.Connected()

	out, err := DiagnosticsExplain()
	if err != nil {
		t.Fatal(err)
	}
	var blob struct {
		Pick struct {
			RouteID      string `json:"route_id"`
			Family       string `json:"family"`
			ExposureMode string `json:"exposure_mode"`
		} `json:"pick"`
		State       string `json:"state"`
		ActiveRoute string `json:"active_route"`
	}
	if err := json.Unmarshal([]byte(out), &blob); err != nil {
		t.Fatalf("decode diagnostics explain: %v\n%s", err, out)
	}
	if blob.Pick.RouteID != "r-frp6" || blob.Pick.Family != "vless-reality" || blob.Pick.ExposureMode != "direct_vps" {
		t.Fatalf("unexpected Explanation pick: %+v\n%s", blob.Pick, out)
	}
	if blob.State != "Connected" || blob.ActiveRoute != "r-frp6" {
		t.Fatalf("legacy compatibility fields missing: state=%q active=%q\n%s", blob.State, blob.ActiveRoute, out)
	}
}

// TestEngineVersionIsV3Transport — Phase 3A bumped the version
// string to signal the V3 transport-agility line; Phase 3B
// bumped the patch component to signal the Snowflake +
// 5-channel rendezvous landing; Phase 3C bumps to 0.7.2 to
// signal the MASQUE ladder; Phase 3D bumps to 0.7.3 to signal
// the refraction-family hooks (psiphon + conjure); Phase 3E
// bumps to 0.8.0 to mark the V3 success-metric milestone (a
// new transport shipped without an app update — the WASM
// transport slot). ABI is still append-only; the version
// bump is informative.
func TestEngineVersionIsV3Transport(t *testing.T) {
	if VersionString() != "daal-core 0.9.0+v3-share" {
		t.Fatalf("version: %s", VersionString())
	}
}
