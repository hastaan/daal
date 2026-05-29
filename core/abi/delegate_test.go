//go:build !no_delegate_share

package abi

import (
	"encoding/json"
	"strings"
	"testing"

	"daal/core/routestore"
)

// initFor3FTest spins up an engine session against a fresh
// state-dir and tears it down at end of test.
func initFor3FTest(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	if err := Init(dir, "info"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Shutdown() })
}

// TestExportDiagnostics_3FFieldsAlwaysPresent — locks the
// diagnostics shape: three new fields, all default-present.
func TestExportDiagnostics_3FFieldsAlwaysPresent(t *testing.T) {
	initFor3FTest(t)
	body, err := ExportDiagnostics()
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if v, ok := m["delegate_share_compiled_in"].(bool); !ok || !v {
		t.Errorf("delegate_share_compiled_in: got %v", m["delegate_share_compiled_in"])
	}
	if v, ok := m["delegate_share_counters"].(map[string]interface{}); !ok || len(v) != 0 {
		t.Errorf("delegate_share_counters: got %v", m["delegate_share_counters"])
	}
	if v, ok := m["last_delegate_share_outcome"].(string); !ok || v != "" {
		t.Errorf("last_delegate_share_outcome: got %v", m["last_delegate_share_outcome"])
	}
}

// TestRedistributeRoute_RouteUnknown — calling on a missing
// route returns the locked closed-enum error envelope.
func TestRedistributeRoute_RouteUnknown(t *testing.T) {
	initFor3FTest(t)
	body := RedistributeRoute("does-not-exist", "recipient-fp")
	if !strings.Contains(body, `"error":"route_unknown"`) {
		t.Errorf("body: %s", body)
	}
	if got := LastDelegateShareOutcome(); got != "route_unknown" {
		t.Errorf("LastDelegateShareOutcome: %q", got)
	}
}

// TestRedistributeRoute_PolicyNoneRefuses — a route whose
// policy is "" or "none" refuses re-share.
func TestRedistributeRoute_PolicyNoneRefuses(t *testing.T) {
	initFor3FTest(t)
	c := tryGetCore()
	if c == nil {
		t.Fatal("engine not initialised")
	}
	if err := c.store.UpsertPublisher(publisherForTest3F("p-3f")); err != nil {
		t.Fatal(err)
	}
	if err := c.store.UpsertRoute(routeForTest3F("r-3f-none", "p-3f", "none", 0)); err != nil {
		t.Fatal(err)
	}
	body := RedistributeRoute("r-3f-none", "rcp")
	if !strings.Contains(body, `"error":"policy_refuses"`) {
		t.Errorf("body: %s", body)
	}
}

// TestRedistributeRoute_DelegatedNHappyPath — first share
// succeeds; counter increments to 1; the wire envelope carries
// chain + caps.
func TestRedistributeRoute_DelegatedNHappyPath(t *testing.T) {
	initFor3FTest(t)
	c := tryGetCore()
	if err := c.store.UpsertPublisher(publisherForTest3F("p-3f")); err != nil {
		t.Fatal(err)
	}
	if err := c.store.UpsertRoute(routeForTest3F("r-3f-deln", "p-3f", "delegated_n", 3)); err != nil {
		t.Fatal(err)
	}
	body := RedistributeRoute("r-3f-deln", "alice-fp")
	if strings.Contains(body, `"error"`) {
		t.Fatalf("unexpected error envelope: %s", body)
	}
	var env struct {
		Type           string                   `json:"type"`
		RouteID        string                   `json:"route_id"`
		RecipientFPHex string                   `json:"recipient_fp_hex"`
		Chain          []map[string]interface{} `json:"redistribution_chain"`
		Caps           []map[string]interface{} `json:"delegate_caps"`
	}
	if err := json.Unmarshal([]byte(body), &env); err != nil {
		t.Fatalf("unmarshal: %v / body=%s", err, body)
	}
	if env.Type != "delegated_share" || env.RouteID != "r-3f-deln" || env.RecipientFPHex != "alice-fp" {
		t.Errorf("envelope shape: %+v", env)
	}
	if len(env.Chain) != 1 || len(env.Caps) != 1 {
		t.Errorf("chain=%d caps=%d", len(env.Chain), len(env.Caps))
	}
	if got := LastDelegateShareOutcome(); got != "ok" {
		t.Errorf("outcome: %q", got)
	}
	// Counter should be 1 after one successful share.
	counters := DelegateShareCountersForDiagnostics()
	if c2, ok := counters["r-3f-deln"]; !ok || c2.SharedWithCount != 1 || c2.Cap != 3 {
		t.Errorf("counters: %+v", counters)
	}
}

// TestRedistributeRoute_CapExhausted — sharing past the cap
// returns cap_exhausted and DOES NOT increment further.
func TestRedistributeRoute_CapExhausted(t *testing.T) {
	initFor3FTest(t)
	c := tryGetCore()
	if err := c.store.UpsertPublisher(publisherForTest3F("p-3f")); err != nil {
		t.Fatal(err)
	}
	if err := c.store.UpsertRoute(routeForTest3F("r-3f-cap", "p-3f", "delegated_n", 2)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		body := RedistributeRoute("r-3f-cap", "alice")
		if strings.Contains(body, `"error"`) {
			t.Fatalf("unexpected error on share %d: %s", i, body)
		}
	}
	// Third share — cap_exhausted.
	body := RedistributeRoute("r-3f-cap", "alice")
	if !strings.Contains(body, `"error":"cap_exhausted"`) {
		t.Errorf("third share: %s", body)
	}
	if got := LastDelegateShareOutcome(); got != "cap_exhausted" {
		t.Errorf("outcome: %q", got)
	}
	counters := DelegateShareCountersForDiagnostics()
	if c2 := counters["r-3f-cap"]; c2.SharedWithCount != 2 {
		t.Errorf("counter should be exactly 2: %+v", c2)
	}
}

// TestRedistributeRoute_TransitiveAllowed — transitive policy
// admits unconditionally (depth enforced receiver-side).
func TestRedistributeRoute_TransitiveAllowed(t *testing.T) {
	initFor3FTest(t)
	c := tryGetCore()
	if err := c.store.UpsertPublisher(publisherForTest3F("p-3f")); err != nil {
		t.Fatal(err)
	}
	if err := c.store.UpsertRoute(routeForTest3F("r-3f-tx", "p-3f", "transitive", 0)); err != nil {
		t.Fatal(err)
	}
	body := RedistributeRoute("r-3f-tx", "alice")
	if strings.Contains(body, `"error"`) {
		t.Fatalf("transitive: %s", body)
	}
	if got := LastDelegateShareOutcome(); got != "ok" {
		t.Errorf("outcome: %q", got)
	}
}

// publisherForTest3F builds the minimal PublisherRow needed for
// the route-foreign-key check. Mirrors the helper pattern from
// other 3X test files.
func publisherForTest3F(id string) routestore.PublisherRow {
	return routestore.PublisherRow{
		PublisherID: id, DisplayName: "T", TrustLevel: "trusted_provider",
		FirstSeen: "2026-04-28T00:00:00Z", LastSeenBundle: "2026-04-28T00:00:00Z",
		KeyStatus: "active", RotationChain: []string{}, RevocationSources: []string{},
	}
}

// routeForTest3F builds a minimal RouteRow for share-counter
// tests.
func routeForTest3F(id, pubID, policy string, cap uint8) routestore.RouteRow {
	return routestore.RouteRow{
		RouteID: id, TransportFamily: "vless-reality", Engine: "sing-box",
		SourceType: "trusted_provider", PublisherID: pubID, PublisherLabel: "T",
		TrustState: "tofu", ScarcityClass: "normal", ModesAllowed: []string{"normal"},
		ExpiresAt: "2026-05-28T00:00:00Z", ImportedAt: "2026-04-28T00:00:00Z",
		RedistributionPolicy: policy, RedistributionCap: cap,
	}
}
