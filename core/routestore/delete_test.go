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
	// The standby address as signed (open mode holds the address) and an
	// accepted standby key: both are the route's and go with it.
	if err := s.PutSecret("standby:"+route, []byte(`{"v":1,"mode":"open","server":"203.0.113.20"}`)); err != nil {
		t.Fatal(err)
	}
	if err := s.PutSecret("standby-key:"+route, make([]byte, 16)); err != nil {
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
	for _, k := range []string{"budget:bucket:r1", "standby:r1", "standby-key:r1"} {
		if _, err := s.GetSecret(k); err == nil {
			t.Fatalf("per-route secret %s survived delete", k)
		}
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
