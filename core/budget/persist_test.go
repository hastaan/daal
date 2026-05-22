package budget

import (
	"testing"
	"time"

	"daal/core/routestore"
)

func TestRoutestoreStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	rs, err := routestore.Open(dir)
	if err != nil {
		t.Fatalf("routestore open: %v", err)
	}
	defer rs.Close()

	// Seed a publisher and a route.
	if err := rs.UpsertPublisher(routestore.PublisherRow{
		PublisherID:    "pub-x",
		DisplayName:    "Pub X",
		TrustLevel:     "tofu",
		FirstSeen:      "2026-04-26T00:00:00Z",
		LastSeenBundle: "2026-04-26T00:00:00Z",
		KeyStatus:      "active",
	}); err != nil {
		t.Fatalf("upsert publisher: %v", err)
	}
	if err := rs.UpsertRoute(routestore.RouteRow{
		RouteID:         "r-budget",
		TransportFamily: "vless-reality",
		Engine:          "sing-box",
		SourceType:      "imported",
		PublisherID:     "pub-x",
		PublisherLabel:  "Pub X",
		TrustState:      "trusted",
		ScarcityClass:   "normal",
		ExpiresAt:       "2027-01-01T00:00:00Z",
		ImportedAt:      "2026-04-26T00:00:00Z",
	}); err != nil {
		t.Fatalf("upsert route: %v", err)
	}

	store := &RoutestoreStore{S: rs}
	bucket := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	if err := store.SetRouteBytesHour("r-budget", 12345, bucket); err != nil {
		t.Fatalf("SetRouteBytesHour: %v", err)
	}
	tag, consumed, gotBucket, err := store.GetRouteBudget("r-budget")
	if err != nil {
		t.Fatalf("GetRouteBudget: %v", err)
	}
	if tag != "normal" {
		t.Errorf("tag = %q", tag)
	}
	if consumed != 12345 {
		t.Errorf("consumed = %d", consumed)
	}
	if !gotBucket.Equal(bucket) {
		t.Errorf("bucket = %v want %v", gotBucket, bucket)
	}

	// SetTag round-trip.
	if err := store.SetRouteScarcity("r-budget", "emergency"); err != nil {
		t.Fatalf("SetRouteScarcity: %v", err)
	}
	tag2, _, _, _ := store.GetRouteBudget("r-budget")
	if tag2 != "emergency" {
		t.Errorf("tag after update = %q", tag2)
	}

	// EnumerateBudgets sees the row.
	rows, err := store.EnumerateBudgets()
	if err != nil {
		t.Fatalf("EnumerateBudgets: %v", err)
	}
	if len(rows) != 1 || rows[0].RouteID != "r-budget" || rows[0].Tag != "emergency" || rows[0].Consumed != 12345 {
		t.Errorf("rows = %+v", rows)
	}
}

func TestEngineWithRoutestoreEnforcesCap(t *testing.T) {
	dir := t.TempDir()
	rs, err := routestore.Open(dir)
	if err != nil {
		t.Fatalf("routestore open: %v", err)
	}
	defer rs.Close()
	_ = rs.UpsertPublisher(routestore.PublisherRow{
		PublisherID:    "pub-x",
		DisplayName:    "X",
		TrustLevel:     "tofu",
		FirstSeen:      "2026-04-26T00:00:00Z",
		LastSeenBundle: "2026-04-26T00:00:00Z",
		KeyStatus:      "active",
	})
	_ = rs.UpsertRoute(routestore.RouteRow{
		RouteID:         "r-em",
		TransportFamily: "vless-reality",
		Engine:          "sing-box",
		SourceType:      "imported",
		PublisherID:     "pub-x",
		TrustState:      "trusted",
		ScarcityClass:   "emergency",
		ExpiresAt:       "2027-01-01T00:00:00Z",
		ImportedAt:      "2026-04-26T00:00:00Z",
	})
	clk := &advanceableClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	e := New(&RoutestoreStore{S: rs}, clk.Now)

	// Burn 49 MiB on the emergency-tagged route.
	if err := e.Add("r-em", 49*MiB); err != nil {
		t.Fatalf("Add 49 MiB: %v", err)
	}
	// Crossing 50 MiB cap exhausts.
	if err := e.Add("r-em", 2*MiB); err != ErrExhausted {
		t.Fatalf("expected ErrExhausted, got %v", err)
	}
	// Snapshot reflects the saturation.
	snap := e.Snapshot()
	if len(snap) != 1 || !snap[0].Exhausted || snap[0].Consumed != 50*MiB {
		t.Errorf("snapshot = %+v", snap)
	}

	// Hour rollover restores Healthy.
	clk.advance(time.Hour)
	rolled := e.HourRollover(clk.Now())
	if rolled != 1 {
		t.Errorf("rolled = %d", rolled)
	}
	if err := e.Add("r-em", 10*MiB); err != nil {
		t.Fatalf("post-rollover Add: %v", err)
	}
}
