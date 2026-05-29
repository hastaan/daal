package budget

import (
	"testing"
	"time"
)

// Phase 2C: per-network capture/restore tests. These cover the
// engine-side seam used by core/abi/engine_network_changed; the
// netmem JSON marshalling is covered in core/netmem/store_test.go.

func atTime(t time.Time) func() time.Time {
	return func() time.Time { return t.UTC() }
}

func TestSetActiveNetworkRoundTrip(t *testing.T) {
	st := newFakeStore()
	e := New(st, atTime(time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)))
	if e.ActiveNetwork() != "" {
		t.Fatalf("default ActiveNetwork = %q, want empty", e.ActiveNetwork())
	}
	e.SetActiveNetwork("0fffaaaaaaaaaaaa")
	if e.ActiveNetwork() != "0fffaaaaaaaaaaaa" {
		t.Fatalf("ActiveNetwork roundtrip: %q", e.ActiveNetwork())
	}
}

func TestSetActiveNetworkDoesNotBumpSession(t *testing.T) {
	st := newFakeStore()
	e := New(st, atTime(time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)))
	before := e.SessionEpoch()
	e.SetActiveNetwork("aaaa000000000000")
	e.SetActiveNetwork("bbbb000000000000")
	if e.SessionEpoch() != before {
		t.Fatalf("SetActiveNetwork bumped session epoch: %d → %d", before, e.SessionEpoch())
	}
}

func TestCaptureNetworkReturnsCurrentBucketUsageOnly(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 30, 0, 0, time.UTC)
	st := newFakeStore()
	e := New(st, atTime(now))

	// route r1: tagged + used in current bucket
	_ = e.SetTag("r1", "normal")
	if err := e.Add("r1", 100_000); err != nil {
		t.Fatalf("Add r1: %v", err)
	}
	// route r2: tagged but used in a STALE bucket (hour ago)
	_ = e.SetTag("r2", "normal")
	stale := now.Add(-2 * time.Hour).Truncate(time.Hour)
	_ = st.SetRouteBytesHour("r2", 999_000, stale)

	usage, bucket := e.CaptureNetwork()
	if got, want := bucket, now.Truncate(time.Hour); !got.Equal(want) {
		t.Fatalf("CaptureNetwork bucket = %v, want %v", got, want)
	}
	if usage["r1"] != 100_000 {
		t.Fatalf("CaptureNetwork r1 = %d, want 100_000", usage["r1"])
	}
	if _, ok := usage["r2"]; ok {
		t.Fatalf("CaptureNetwork should drop stale-bucket r2; got %d", usage["r2"])
	}
}

func TestRestoreNetworkSeedsCurrentBucketCounters(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 30, 0, 0, time.UTC)
	st := newFakeStore()
	e := New(st, atTime(now))
	_ = e.SetTag("r1", "normal")
	_ = e.SetTag("r2", "normal")

	usage := map[string]uint64{"r1": 250_000, "r2": 0}
	bucket := now.Truncate(time.Hour)
	written := e.RestoreNetwork(usage, bucket)
	if written != 1 {
		t.Fatalf("RestoreNetwork written = %d, want 1 (zero entries skipped)", written)
	}
	// Snapshot should reflect the restored counter.
	snap := e.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("Snapshot rows = %d, want 2", len(snap))
	}
	for _, row := range snap {
		if row.RouteID == "r1" && row.Consumed != 250_000 {
			t.Fatalf("r1 restored consumed = %d, want 250_000", row.Consumed)
		}
		if row.RouteID == "r2" && row.Consumed != 0 {
			t.Fatalf("r2 should be 0; got %d", row.Consumed)
		}
	}
}

func TestRestoreNetworkDropsStaleBucket(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 30, 0, 0, time.UTC)
	st := newFakeStore()
	e := New(st, atTime(now))
	_ = e.SetTag("r1", "normal")

	// Pretend we saved this snapshot two hours ago.
	stale := now.Add(-2 * time.Hour).Truncate(time.Hour)
	written := e.RestoreNetwork(map[string]uint64{"r1": 999_000}, stale)
	if written != 0 {
		t.Fatalf("RestoreNetwork should drop stale bucket; written = %d", written)
	}
	// The route's persisted counter must NOT have been overwritten.
	tag, consumed, _, _ := st.GetRouteBudget("r1")
	if tag != "normal" {
		t.Fatalf("tag clobbered: %q", tag)
	}
	if consumed != 0 {
		t.Fatalf("Restore from stale bucket leaked into store: %d", consumed)
	}
}
