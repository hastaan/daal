package routestore

import (
	"testing"
	"time"
)

// seedRoute inserts a minimal route so the outcome UPDATEs have a row
// to hit. UpsertRoute hard-codes the five history columns to NULL/0,
// which is exactly the "no writer ever" starting state this file is
// about.
func seedRoute(t *testing.T, s *Store, id string) {
	t.Helper()
	if err := s.UpsertPublisher(PublisherRow{
		PublisherID: "fp1", DisplayName: "Pub 1", TrustLevel: "tofu_friend",
		FirstSeen: "2026-08-18T00:00:00Z", LastSeenBundle: "2026-08-18T00:00:00Z",
		KeyStatus: "active", RotationChain: []string{}, RevocationSources: []string{},
	}); err != nil {
		t.Fatalf("seed publisher: %v", err)
	}
	if err := s.UpsertRoute(RouteRow{
		RouteID: id, TransportFamily: "vless-reality", Engine: "sing-box",
		SourceType: "trusted_provider", PublisherID: "fp1",
		TrustState: "tofu", ScarcityClass: "normal",
		ModesAllowed: []string{"normal"},
	}); err != nil {
		t.Fatalf("seed %s: %v", id, err)
	}
}

func TestRecordOutcome_FreshRouteHasNoHistory(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	seedRoute(t, s, "r1")

	got, err := s.GetRoute("r1")
	if err != nil {
		t.Fatal(err)
	}
	// This is the invariant abi.hasDurableOutcome depends on: an
	// imported-but-never-attempted route must be indistinguishable
	// from "nothing measured", so the UI renders "not tested yet"
	// rather than a fabricated score.
	if got.LastSuccessBucket != "" || got.LastFailureBucket != "" ||
		got.LastFailureCategory != "" || got.ConsecutiveFailures != 0 ||
		got.CooldownUntil != "" {
		t.Fatalf("fresh route must have empty history, got %+v", got)
	}
}

func TestRecordSuccess_StampsHourBucketAndProves(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	seedRoute(t, s, "r1")

	now := time.Date(2026, 8, 18, 14, 37, 42, 0, time.UTC)
	if err := s.RecordSuccess("r1", now); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetRoute("r1")
	// Hour granularity is the privacy contract, not an accident: the
	// row must not be able to say the user was online at 14:37.
	if got.LastSuccessBucket != "2026-08-18T14:00:00Z" {
		t.Fatalf("last_success_bucket = %q, want the hour bucket", got.LastSuccessBucket)
	}
	if got.ConsecutiveFailures != 0 {
		t.Fatalf("consecutive_failures = %d, want 0", got.ConsecutiveFailures)
	}
}

func TestRecordFailure_IncrementsAndCarriesCategory(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	seedRoute(t, s, "r1")

	now := time.Date(2026, 8, 18, 14, 5, 0, 0, time.UTC)
	cool := now.Add(30 * time.Minute)
	for i := 1; i <= 3; i++ {
		if err := s.RecordFailure("r1", "tls_handshake_failed", cool, now); err != nil {
			t.Fatal(err)
		}
		got, _ := s.GetRoute("r1")
		if got.ConsecutiveFailures != i {
			t.Fatalf("after %d failures consecutive_failures = %d", i, got.ConsecutiveFailures)
		}
	}
	got, _ := s.GetRoute("r1")
	if got.LastFailureBucket != "2026-08-18T14:00:00Z" {
		t.Fatalf("last_failure_bucket = %q", got.LastFailureBucket)
	}
	if got.LastFailureCategory != "tls_handshake_failed" {
		t.Fatalf("last_failure_category = %q", got.LastFailureCategory)
	}
	if got.CooldownUntil != "2026-08-18T14:35:00Z" {
		t.Fatalf("cooldown_until = %q", got.CooldownUntil)
	}
	// A success after failures must clear the counter and the
	// cooldown, but must NOT erase the failure history — "worked, but
	// broke at 14:00 with a TLS handshake failure" is the shape a
	// selector needs to tell flaky from solid.
	if err := s.RecordSuccess("r1", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetRoute("r1")
	if got.ConsecutiveFailures != 0 || got.CooldownUntil != "" {
		t.Fatalf("success did not clear failure state: %+v", got)
	}
	if got.LastFailureCategory != "tls_handshake_failed" {
		t.Fatalf("success erased the failure history: %+v", got)
	}
}

func TestRecordFailure_NoCooldownClassClearsTheColumn(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	seedRoute(t, s, "r1")

	now := time.Date(2026, 8, 18, 14, 0, 0, 0, time.UTC)
	// auth_failed is the explicit never-cools-down class (V0.3). The
	// caller passes the zero time; the column must end up empty, not
	// back-dated to the epoch, or observeRoute would parse
	// "0001-01-01" and report the route as out of cooldown by way of a
	// value nobody wrote.
	if err := s.RecordFailure("r1", "auth_failed", time.Time{}, now); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetRoute("r1")
	if got.CooldownUntil != "" {
		t.Fatalf("cooldown_until = %q, want empty for a no-cooldown class", got.CooldownUntil)
	}
	if got.ConsecutiveFailures != 1 {
		t.Fatalf("consecutive_failures = %d, want 1", got.ConsecutiveFailures)
	}
}

func TestRecordFailure_CounterSaturates(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	seedRoute(t, s, "r1")

	now := time.Date(2026, 8, 18, 14, 0, 0, 0, time.UTC)
	for i := 0; i < maxConsecutiveFailures+25; i++ {
		if err := s.RecordFailure("r1", "tcp_connect_timeout", time.Time{}, now); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := s.GetRoute("r1")
	if got.ConsecutiveFailures != maxConsecutiveFailures {
		t.Fatalf("consecutive_failures = %d, want saturation at %d",
			got.ConsecutiveFailures, maxConsecutiveFailures)
	}
}

func TestRecordOutcome_RejectsEmptyRouteAndIgnoresUnknown(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.RecordSuccess("", time.Now()); err == nil {
		t.Fatal("RecordSuccess(\"\") must error")
	}
	if err := s.RecordFailure("", "unknown", time.Time{}, time.Now()); err == nil {
		t.Fatal("RecordFailure(\"\") must error")
	}
	// An UPDATE against a route that is not there affects zero rows.
	// That must be a silent no-op, not an error: the engine can race a
	// route deletion against an in-flight connect attempt, and a
	// failed telemetry write must never surface as a connect failure.
	if err := s.RecordSuccess("nope", time.Now()); err != nil {
		t.Fatalf("RecordSuccess on absent route: %v", err)
	}
	if err := s.RecordFailure("nope", "unknown", time.Time{}, time.Now()); err != nil {
		t.Fatalf("RecordFailure on absent route: %v", err)
	}
}
