package abi

import (
	"encoding/json"
	"strings"
	"testing"

	"daal/core/routestore"
)

// TestSetRouteBudgetUnknownTagRejected asserts that the ABI surfaces
// the closed cap-map check.
func TestSetRouteBudgetUnknownTagRejected(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	body, err := SetRouteBudget("r1", "definitely-not-a-tag")
	if err == nil {
		t.Fatalf("expected error for unknown tag, got body=%s", body)
	}
	if !strings.Contains(body, `"error":"unknown_budget_tag"`) {
		t.Fatalf("missing error key: %s", body)
	}
}

// TestSetRouteBudgetRoundTripWithDiagnostics seeds a route, sets its
// tag via the ABI, then asserts engine_export_diagnostics shows the
// route in the new `budgets` array.
func TestSetRouteBudgetRoundTripWithDiagnostics(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	c := mustCore()
	if err := c.store.UpsertPublisher(routestore.PublisherRow{
		PublisherID:    "pub-x",
		DisplayName:    "X",
		TrustLevel:     "tofu",
		FirstSeen:      "2026-04-26T00:00:00Z",
		LastSeenBundle: "2026-04-26T00:00:00Z",
		KeyStatus:      "active",
	}); err != nil {
		t.Fatalf("upsert publisher: %v", err)
	}
	if err := c.store.UpsertRoute(routestore.RouteRow{
		RouteID:         "r1",
		TransportFamily: "vless-reality",
		Engine:          "sing-box",
		SourceType:      "imported",
		PublisherID:     "pub-x",
		TrustState:      "trusted",
		ScarcityClass:   "normal",
		ExpiresAt:       "2027-01-01T00:00:00Z",
		ImportedAt:      "2026-04-26T00:00:00Z",
	}); err != nil {
		t.Fatalf("upsert route: %v", err)
	}

	body, err := SetRouteBudget("r1", "emergency")
	if err != nil {
		t.Fatalf("SetRouteBudget: %v", err)
	}
	var resp struct {
		Applied        bool   `json:"applied"`
		RouteID        string `json:"route_id"`
		BudgetTag      string `json:"budget_tag"`
		HourlyCapBytes uint64 `json:"hourly_cap_bytes"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode SetRouteBudget body %q: %v", body, err)
	}
	if !resp.Applied || resp.RouteID != "r1" || resp.BudgetTag != "emergency" {
		t.Fatalf("response wrong: %+v", resp)
	}
	if resp.HourlyCapBytes != 50*1024*1024 {
		t.Errorf("hourly_cap_bytes = %d, want 50 MiB", resp.HourlyCapBytes)
	}

	// Force the engine to instantiate so diagnostics renders the array.
	_ = ensureBudget()

	diag, err := ExportDiagnostics()
	if err != nil {
		t.Fatalf("ExportDiagnostics: %v", err)
	}
	if !strings.Contains(diag, `"budgets"`) {
		t.Fatalf("expected budgets[] in diagnostics: %s", diag)
	}
	if !strings.Contains(diag, `"emergency"`) {
		t.Fatalf("expected emergency tag in diagnostics: %s", diag)
	}

	// Phase 2A-Polish: budgets[] rows must carry the additive
	// session_cap_bytes, session_consumed_bytes, modes_allowed fields.
	var fullDiag struct {
		Budgets []struct {
			RouteID              string   `json:"route_id"`
			BudgetTag            string   `json:"budget_tag"`
			HourlyCapBytes       uint64   `json:"hourly_cap_bytes"`
			ConsumedBytes        uint64   `json:"consumed_bytes"`
			SessionCapBytes      uint64   `json:"session_cap_bytes"`
			SessionConsumedBytes uint64   `json:"session_consumed_bytes"`
			ModesAllowed         []string `json:"modes_allowed"`
			Exhausted            bool     `json:"exhausted"`
		} `json:"budgets"`
	}
	if err := json.Unmarshal([]byte(diag), &fullDiag); err != nil {
		t.Fatalf("decode diagnostics: %v\n%s", err, diag)
	}
	if len(fullDiag.Budgets) != 1 {
		t.Fatalf("expected 1 budget row, got %d: %s", len(fullDiag.Budgets), diag)
	}
	row := fullDiag.Budgets[0]
	if row.RouteID != "r1" || row.BudgetTag != "emergency" {
		t.Errorf("budgets[0] = %+v, want route_id=r1 budget_tag=emergency", row)
	}
	if row.HourlyCapBytes != 50*1024*1024 {
		t.Errorf("hourly_cap_bytes = %d, want 50 MiB", row.HourlyCapBytes)
	}
	if row.SessionCapBytes != 200*1024*1024 {
		t.Errorf("session_cap_bytes = %d, want 200 MiB", row.SessionCapBytes)
	}
	if row.SessionConsumedBytes != 0 {
		t.Errorf("session_consumed_bytes = %d, want 0 (fresh session)", row.SessionConsumedBytes)
	}
	if len(row.ModesAllowed) != 1 || row.ModesAllowed[0] != "lifeline" {
		t.Errorf("modes_allowed = %v, want [lifeline]", row.ModesAllowed)
	}
	if row.Exhausted {
		t.Errorf("emergency route should not be exhausted at zero bytes")
	}
}

// TestBudgetEngineEnforcesCapAtByteBoundary drives the in-process
// budget engine through SetRouteBudget + Add and asserts ErrExhausted
// at exactly 50 MiB on an emergency-tagged route.
func TestBudgetEngineEnforcesCapAtByteBoundary(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	c := mustCore()
	_ = c.store.UpsertPublisher(routestore.PublisherRow{
		PublisherID:    "pub-x",
		DisplayName:    "X",
		TrustLevel:     "tofu",
		FirstSeen:      "2026-04-26T00:00:00Z",
		LastSeenBundle: "2026-04-26T00:00:00Z",
		KeyStatus:      "active",
	})
	_ = c.store.UpsertRoute(routestore.RouteRow{
		RouteID:         "r-em",
		TransportFamily: "vless-reality",
		Engine:          "sing-box",
		SourceType:      "imported",
		PublisherID:     "pub-x",
		TrustState:      "trusted",
		ScarcityClass:   "normal",
		ExpiresAt:       "2027-01-01T00:00:00Z",
		ImportedAt:      "2026-04-26T00:00:00Z",
	})
	if _, err := SetRouteBudget("r-em", "emergency"); err != nil {
		t.Fatalf("SetRouteBudget: %v", err)
	}
	eng := ensureBudget()
	const MiB uint64 = 1024 * 1024
	if err := eng.Add("r-em", 49*MiB); err != nil {
		t.Fatalf("Add 49 MiB: %v", err)
	}
	// Charge another 2 MiB → ErrExhausted.
	err := eng.Add("r-em", 2*MiB)
	if err == nil || err.Error() != "budget: hourly cap exhausted" {
		t.Fatalf("expected budget-exhausted error, got %v", err)
	}
	// Snapshot reflects exhaustion.
	snap := eng.Snapshot()
	var found bool
	for _, s := range snap {
		if s.RouteID == "r-em" {
			found = true
			if !s.Exhausted {
				t.Errorf("expected exhausted snapshot: %+v", s)
			}
			if s.Consumed != 50*MiB {
				t.Errorf("consumed = %d, want 50 MiB", s.Consumed)
			}
		}
	}
	if !found {
		t.Fatalf("r-em not in snapshot: %+v", snap)
	}
}
