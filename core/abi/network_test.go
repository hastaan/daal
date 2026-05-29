package abi

import (
	"encoding/json"
	"strings"
	"testing"

	"daal/core/budget"
	"daal/core/netmem"
)

// Phase 2C ABI tests. Cover:
//   - engine_network_changed round-trip (fresh / restore on roam).
//   - SSID/carrier/raw-input no-leak guarantee (the canonical
//     V0.1 + CC.6 privacy regression).
//   - Active-network labelling propagates to budget engine + path-
//     manager.
//   - Mode change still does NOT bump the session epoch (carry-over).

func TestNetworkChangedRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	defer Shutdown()

	// Connect-time tag a route so the budget engine has rows.
	if _, err := SetRouteBudget("r1", "normal"); err != nil {
		t.Fatalf("SetRouteBudget: %v", err)
	}

	// First call: fresh = true.
	out, err := NetworkChanged("wifi", "", "TestSSID-A")
	if err != nil {
		t.Fatalf("NetworkChanged: %v", err)
	}
	var resp struct {
		NetworkID      string `json:"network_id"`
		Mode           string `json:"mode"`
		RestoredRoutes int    `json:"restored_routes"`
		Fresh          bool   `json:"fresh"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.NetworkID == "" || resp.NetworkID == netmem.SentinelUnset {
		t.Fatalf("network_id should be a real hash, got %q", resp.NetworkID)
	}
	if !resp.Fresh {
		t.Fatalf("first NetworkChanged should be fresh; got %+v", resp)
	}

	// Second call to the SAME network: fresh = false.
	out2, err := NetworkChanged("wifi", "", "TestSSID-A")
	if err != nil {
		t.Fatalf("NetworkChanged 2: %v", err)
	}
	var resp2 struct {
		Fresh     bool   `json:"fresh"`
		NetworkID string `json:"network_id"`
	}
	_ = json.Unmarshal([]byte(out2), &resp2)
	if resp2.Fresh {
		t.Fatalf("second NetworkChanged on same SSID should NOT be fresh")
	}
	if resp2.NetworkID != resp.NetworkID {
		t.Fatalf("hash unstable: %q vs %q", resp.NetworkID, resp2.NetworkID)
	}
}

// TestSSIDDoesNotLeakIntoDiagnostics is the canonical V0.1 +
// CC.6 privacy regression. After driving engine_network_changed
// with a distinctive SSID + carrier, exporting the diagnostics
// blob MUST NOT contain those raw strings anywhere.
func TestSSIDDoesNotLeakIntoDiagnostics(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	defer Shutdown()

	const distinctSSID = "TopSecretSSID-CAFE-DEADBEEF"
	const distinctCarrier = "MCI-DEADBEEF"

	if _, err := NetworkChanged("wifi", distinctCarrier, distinctSSID); err != nil {
		t.Fatalf("NetworkChanged: %v", err)
	}

	body, err := ExportDiagnostics()
	if err != nil {
		t.Fatalf("ExportDiagnostics: %v", err)
	}
	if strings.Contains(body, distinctSSID) {
		t.Fatalf("SSID leaked into diagnostics: %s", body)
	}
	if strings.Contains(body, distinctCarrier) {
		t.Fatalf("Carrier leaked into diagnostics: %s", body)
	}
	// The hashed network ID MUST appear (the user is entitled to
	// see it; that's the point).
	if !strings.Contains(body, "current_network_id") {
		t.Fatalf("current_network_id missing from diagnostics: %s", body)
	}
}

func TestNetworkChangedRejectsInvalidKind(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	defer Shutdown()
	if _, err := NetworkChanged("bogus", "", "x"); err == nil {
		t.Fatalf("NetworkChanged should reject invalid kind")
	}
}

func TestNetworkChangedDoesNotBumpSessionEpoch(t *testing.T) {
	// Phase 2A-Polish carry-over: the canonical session boundary is
	// engine_init only. Network roams MUST NOT reset the session
	// counter (that would let a hostile network reset the cap).
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	defer Shutdown()

	// Force the budget engine to instantiate so SessionEpoch is
	// observable.
	if _, err := SetRouteBudget("r1", "normal"); err != nil {
		t.Fatalf("SetRouteBudget: %v", err)
	}
	eng := budgetEngineIfPresent()
	if eng == nil {
		t.Fatalf("budget engine not instantiated after SetRouteBudget")
	}
	before := eng.SessionEpoch()

	if _, err := NetworkChanged("wifi", "", "Foo"); err != nil {
		t.Fatalf("NetworkChanged 1: %v", err)
	}
	if _, err := NetworkChanged("wifi", "", "Bar"); err != nil {
		t.Fatalf("NetworkChanged 2: %v", err)
	}
	after := eng.SessionEpoch()
	if before != after {
		t.Fatalf("NetworkChanged bumped session epoch: %d → %d", before, after)
	}
}

func TestNetworkChangedPropagatesActiveNetworkLabel(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	defer Shutdown()

	// At Init, the active network is the sentinel.
	if got := activeNetworkID(); got != netmem.SentinelUnset {
		t.Fatalf("active network at Init = %q, want %q", got, netmem.SentinelUnset)
	}

	// A real NetworkChanged should propagate to budget engine + pm.
	if _, err := SetRouteBudget("r1", "normal"); err != nil {
		t.Fatalf("SetRouteBudget: %v", err)
	}
	if _, err := NetworkChanged("wifi", "", "TestNet"); err != nil {
		t.Fatalf("NetworkChanged: %v", err)
	}
	want := netmem.HashID(netmem.KindWiFi, "", "TestNet")
	if got := activeNetworkID(); got != want {
		t.Fatalf("active network = %q, want %q", got, want)
	}
	if got := mustCore().pm.ActiveNetwork(); got != want {
		t.Fatalf("pm active network = %q, want %q", got, want)
	}
	if eng := budgetEngineIfPresent(); eng != nil {
		if got := eng.ActiveNetwork(); got != want {
			t.Fatalf("budget engine active network = %q, want %q", got, want)
		}
	}
}

// Compile-time guard: budget.Engine has the fields we need.
var _ = (&budget.Engine{}).ActiveNetwork
