package routestore

import (
	"testing"
	"time"
)

// Both of these tables were append-only, unbounded, and — the fact that
// decides the retention window — had NO production reader. These tests
// pin the bound so a future reader cannot quietly restore an unbounded
// history by adding a SELECT.

func TestRefreshAudit_ProunesBeyondTheWindow(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	base := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	// One row per hour going back 10 days, written in chronological
	// order the way the scheduler would.
	for h := 240; h >= 0; h-- {
		if err := s.AppendRefreshAudit("subscription", "sub-A", "ok", 0, true,
			base.Add(-time.Duration(h)*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	n, err := s.CountRefreshAudit()
	if err != nil {
		t.Fatal(err)
	}
	// 72-hour window + the row at the cutoff hour itself. The exact
	// count matters less than the bound: ten days of attempts must not
	// survive as ten days of attempts.
	if n > 74 {
		t.Fatalf("refresh_audit retained %d rows; window is %v", n, LocalHistoryWindow)
	}
	if n < 70 {
		t.Fatalf("refresh_audit retained only %d rows; the recent window was over-pruned", n)
	}
}

func TestDiagnosticsExplain_CollapsesPerHourAndPrunes(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	base := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	// Many writes inside one hour must collapse to one row — this is
	// the path the Android UI drives at 2 Hz.
	for i := 0; i < 50; i++ {
		if err := s.PutDiagnosticsExplain(HourBucket(base), "why-"+string(rune('a'+i%26)), "[]"); err != nil {
			t.Fatal(err)
		}
	}
	n, _ := s.CountDiagnosticsExplain()
	if n != 1 {
		t.Fatalf("50 writes in one hour produced %d rows, want 1", n)
	}

	// Now walk forward 10 days, one bucket per hour.
	for h := 1; h <= 240; h++ {
		if err := s.PutDiagnosticsExplain(HourBucket(base.Add(time.Duration(h)*time.Hour)), "why", "[]"); err != nil {
			t.Fatal(err)
		}
	}
	n, _ = s.CountDiagnosticsExplain()
	if n > 74 {
		t.Fatalf("diagnostics_explain retained %d rows; window is %v", n, LocalHistoryWindow)
	}
	// The newest row must still be there — pruning must not eat the
	// row the reader would actually want.
	bucket, _, _, err := s.LatestDiagnosticsExplain()
	if err != nil {
		t.Fatal(err)
	}
	if bucket != HourBucket(base.Add(240*time.Hour)) {
		t.Fatalf("latest bucket = %q, want the newest write", bucket)
	}
}

func TestDiagnosticsExplain_MalformedBucketDoesNotPrune(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	base := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	if err := s.PutDiagnosticsExplain(HourBucket(base), "why", "[]"); err != nil {
		t.Fatal(err)
	}
	// A caller that supplies a bucket this store cannot parse must not
	// cause a delete with a garbage cutoff. Failing to prune is the
	// safe direction; deleting the user's only diagnostic row is not.
	if err := s.PutDiagnosticsExplain("not-a-bucket", "why", "[]"); err != nil {
		t.Fatal(err)
	}
	n, _ := s.CountDiagnosticsExplain()
	if n != 2 {
		t.Fatalf("row count = %d, want 2 (nothing pruned on an unparseable bucket)", n)
	}
}

// The write-path prune only runs when a new row is born, so a store
// that stops being written to keeps whatever it last held — which is
// precisely the seized-device case the window exists for. PruneLocalHistory
// is the reader-free path that closes it; this pins that it works on a
// store nobody has written to since.
func TestPruneLocalHistory_AgesOutAStoreNobodyIsWritingTo(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	base := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	for h := 10; h >= 0; h-- {
		at := base.Add(-time.Duration(h) * time.Hour)
		if err := s.AppendRefreshAudit("subscription", "sub-A", "ok", 0, true, at); err != nil {
			t.Fatal(err)
		}
		if err := s.PutDiagnosticsExplain(HourBucket(at), "why", "[]"); err != nil {
			t.Fatal(err)
		}
	}
	n, err := s.CountRefreshAudit()
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("precondition: nothing was written")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// The device is switched on a week later. Nothing writes; the
	// tunnel never comes up. Without a prune here the rows are immortal.
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if err := s2.PruneLocalHistory(base.Add(7 * 24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if n, err := s2.CountRefreshAudit(); err != nil {
		t.Fatal(err)
	} else if n != 0 {
		t.Fatalf("refresh_audit kept %d rows a week past the window", n)
	}
	if n, err := s2.CountDiagnosticsExplain(); err != nil {
		t.Fatal(err)
	} else if n != 0 {
		t.Fatalf("diagnostics_explain kept %d rows a week past the window", n)
	}
}
