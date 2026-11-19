package routestore

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func seedRoutes(t *testing.T, s *Store, n int) {
	t.Helper()
	if err := s.UpsertPublisher(PublisherRow{
		PublisherID: "fp1", DisplayName: "Pub 1", TrustLevel: "tofu_friend",
		FirstSeen: "2026-04-26T19:00:00Z", LastSeenBundle: "2026-04-26T19:00:00Z",
		KeyStatus: "active", RotationChain: []string{}, RevocationSources: []string{},
	}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("r%d", i+1)
		if err := s.UpsertRoute(RouteRow{
			RouteID: id, TransportFamily: "vless-reality", Engine: "sing-box",
			SourceType: "trusted_provider", PublisherID: "fp1",
			PublisherLabel: "Pub 1", TrustState: "tofu", ScarcityClass: "normal",
			ModesAllowed: []string{"normal"}, ExpiresAt: "2027-05-26T19:00:00Z",
			ImportedAt: "2026-04-26T19:00:00Z",
		}); err != nil {
			t.Fatal(err)
		}
		if err := s.PutSecret("route:"+id, []byte(`{"type":"vless"}`)); err != nil {
			t.Fatal(err)
		}
	}
}

// The app's shape: several pollers reading (the route list, one route,
// its profile) while one writer records outcomes. None of them may ever
// get an error. Before the store was pinned to one connection with a
// busy timeout, database/sql opened a connection per concurrent caller
// and a reader that met the writer's lock failed at once with "database
// is locked" — which the UI rendered as a red banner or, where the
// error was swallowed, as "No route selected".
func TestConcurrentReadersAndOneWriterNeverError(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	seedRoutes(t, s, 4)

	const readers = 8
	deadline := time.Now().Add(1500 * time.Millisecond)
	var (
		wg       sync.WaitGroup
		errCount atomic.Int64
		firstErr atomic.Value
		reads    atomic.Int64
		writes   atomic.Int64
	)
	fail := func(what string, err error) {
		errCount.Add(1)
		firstErr.CompareAndSwap(nil, fmt.Sprintf("%s: %v", what, err))
	}
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for time.Now().Before(deadline) {
				if rows, err := s.ListRoutes(); err != nil {
					fail("ListRoutes", err)
				} else if len(rows) != 4 {
					fail("ListRoutes", fmt.Errorf("%d rows", len(rows)))
				}
				if _, err := s.GetRoute(fmt.Sprintf("r%d", i%4+1)); err != nil {
					fail("GetRoute", err)
				}
				if _, err := s.GetSecret(fmt.Sprintf("route:r%d", i%4+1)); err != nil {
					fail("GetSecret", err)
				}
				if _, err := s.ListSubscriptions(); err != nil {
					fail("ListSubscriptions", err)
				}
				reads.Add(1)
			}
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		now := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
		for n := 0; time.Now().Before(deadline); n++ {
			id := fmt.Sprintf("r%d", n%4+1)
			if err := s.RecordSuccess(id, now); err != nil {
				fail("RecordSuccess", err)
			}
			if err := s.RecordFailure(id, "timeout", now.Add(time.Minute), now); err != nil {
				fail("RecordFailure", err)
			}
			if err := s.PutDiagnosticsExplain(HourBucket(now), fmt.Sprintf("why %d", n), "[]"); err != nil {
				fail("PutDiagnosticsExplain", err)
			}
			if err := s.PutSecret("scratch", []byte("x")); err != nil {
				fail("PutSecret", err)
			}
			writes.Add(1)
		}
	}()
	wg.Wait()
	if n := errCount.Load(); n != 0 {
		t.Fatalf("%d store calls failed under %d readers + 1 writer (%d read rounds, %d write rounds); first: %v",
			n, readers, reads.Load(), writes.Load(), firstErr.Load())
	}
	if reads.Load() == 0 || writes.Load() == 0 {
		t.Fatalf("the test did not exercise both sides: %d read rounds, %d write rounds", reads.Load(), writes.Load())
	}
}

// The per-connection settings the schema asks for must hold on EVERY
// connection the store uses. They are per-connection in SQLite, and the
// schema script only ever ran on the first one: any further pooled
// connection had foreign keys off and secure_delete off.
func TestStoreUsesOneConnectionWithItsPragmas(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	seedRoutes(t, s, 2)

	// Force the pool to want more than one connection.
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				_, _ = s.ListRoutes()
			}
		}()
	}
	wg.Wait()

	if got := s.db.Stats().MaxOpenConnections; got != 1 {
		t.Fatalf("MaxOpenConnections = %d, want 1", got)
	}
	if got := s.db.Stats().OpenConnections; got != 1 {
		t.Fatalf("OpenConnections = %d, want 1", got)
	}
	for pragma, want := range map[string]int{
		"foreign_keys":  1,
		"secure_delete": 1,
		"busy_timeout":  busyTimeoutMs,
	} {
		var got int
		if err := s.db.QueryRow("PRAGMA " + pragma).Scan(&got); err != nil {
			t.Fatalf("PRAGMA %s: %v", pragma, err)
		}
		if got != want {
			t.Fatalf("PRAGMA %s = %d, want %d", pragma, got, want)
		}
	}
	var mode string
	if err := s.db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil || mode != "delete" {
		t.Fatalf("journal_mode = %q (%v), want delete", mode, err)
	}
}
