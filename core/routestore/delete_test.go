package routestore

import (
	"testing"
	"time"
)

func seedPubRoute(t *testing.T, s *Store, pub, route string) {
	t.Helper()
	if err := s.UpsertPublisher(PublisherRow{
		PublisherID: pub, DisplayName: "P", TrustLevel: "tofu_friend",
		FirstSeen: "2026-04-26T19:00:00Z", LastSeenBundle: "2026-04-26T19:00:00Z",
		KeyStatus: "active", RotationChain: []string{}, RevocationSources: []string{},
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 4, 26, 19, 30, 0, 0, time.UTC)
	if err := s.UpsertRoute(RouteRow{
		RouteID: route, TransportFamily: "vless-reality", Engine: "sing-box",
		SourceType: "trusted_provider", PublisherID: pub, TrustState: "tofu",
		ScarcityClass: "normal", ModesAllowed: []string{"normal"},
		ExpiresAt: "2026-05-26T19:00:00Z", ImportedAt: HourBucket(now),
	}); err != nil {
		t.Fatal(err)
	}
	// A per-route secret that a delete must also purge.
	if err := s.PutSecret("budget:bucket:"+route, []byte("2026-04-26T19:00:00Z")); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteRoute(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	seedPubRoute(t, s, "fp1", "r1")

	if err := s.DeleteRoute("r1"); err != nil {
		t.Fatalf("delete route: %v", err)
	}
	if _, err := s.GetRoute("r1"); err == nil {
		t.Fatal("route still present after delete")
	}
	if _, err := s.GetSecret("budget:bucket:r1"); err == nil {
		t.Fatal("per-route secret survived delete")
	}
	// Deleting an absent route is a no-op.
	if err := s.DeleteRoute("nope"); err != nil {
		t.Fatalf("delete absent route should be nil: %v", err)
	}
}

func TestDeletePublisher(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	seedPubRoute(t, s, "fp1", "r1")
	seedPubRoute(t, s, "fp1", "r2")
	seedPubRoute(t, s, "fp2", "r3") // a second publisher must survive

	n, err := s.DeletePublisher("fp1")
	if err != nil {
		t.Fatalf("delete publisher: %v", err)
	}
	if n != 2 {
		t.Fatalf("routes removed: want 2 got %d", n)
	}
	if _, err := s.GetPublisher("fp1"); err == nil {
		t.Fatal("publisher fp1 still present")
	}
	all, err := s.ListRoutes()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || all[0].RouteID != "r3" {
		t.Fatalf("expected only r3 to survive, got %+v", all)
	}
	if _, err := s.GetPublisher("fp2"); err != nil {
		t.Fatal("publisher fp2 should survive")
	}
}
