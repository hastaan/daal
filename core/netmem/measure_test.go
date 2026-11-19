package netmem

import (
	"testing"
	"time"
)

func carriedIn(ms int) RouteOutcome {
	return RouteOutcome{Carried: true, HasSetup: true, SetupMs: ms}
}

func feed(m *RouteMemory, outs ...RouteOutcome) {
	for i, o := range outs {
		m.apply(o, m.CarriedSeq+m.FailedSeq+uint64(i)+1, 1_700_000_000/3600*3600)
	}
}

// The bands, at their edges.
func TestGrade_Thresholds(t *testing.T) {
	cases := []struct {
		ms   int
		want string
	}{
		{0, GradeGood}, {300, GradeGood}, {GradeGoodMaxMs, GradeGood},
		{GradeGoodMaxMs + 1, GradeOK}, {GradeOKMaxMs, GradeOK},
		{GradeOKMaxMs + 1, GradeSlow}, {20000, GradeSlow},
	}
	for _, c := range cases {
		var m RouteMemory
		feed(&m, carriedIn(c.ms))
		if got := m.Grade(); got != c.want {
			t.Errorf("first sample %d ms: grade %q, want %q", c.ms, got, c.want)
		}
	}
	if got := (RouteMemory{}).Grade(); got != GradeUnknown {
		t.Errorf("nothing recorded: %q", got)
	}
	var never RouteMemory
	feed(&never, RouteOutcome{Category: "tls_handshake_failed"})
	if got := never.Grade(); got != GradeFailing {
		t.Errorf("never carried, failed once: %q, want failing", got)
	}
}

// THE rule: one sample never moves a settled grade. Two in a row do.
func TestGrade_DoesNotFlipOnOneSample(t *testing.T) {
	var m RouteMemory
	feed(&m, carriedIn(300), carriedIn(320), carriedIn(280))
	if m.Grade() != GradeGood {
		t.Fatalf("premise: %q", m.Grade())
	}
	// One terrible sample, then normal again: good throughout.
	feed(&m, carriedIn(12000))
	if m.Grade() != GradeGood {
		t.Fatalf("one 12 s sample moved a good route to %q", m.Grade())
	}
	feed(&m, carriedIn(300))
	if m.Grade() != GradeGood {
		t.Fatalf("the sample after an outlier moved a good route to %q (the smoothed time is %d ms: the grade must not be read from it)", m.Grade(), m.SetupMs)
	}
	// Two slow samples in a row: now it is slow.
	feed(&m, carriedIn(6000))
	if m.Grade() != GradeGood {
		t.Fatalf("first of two slow samples already moved it to %q", m.Grade())
	}
	feed(&m, carriedIn(7000))
	if m.Grade() != GradeSlow {
		t.Fatalf("two slow samples in a row left it %q", m.Grade())
	}
	// Two samples in two DIFFERENT other bands do not agree on anything.
	feed(&m, carriedIn(2000))
	feed(&m, carriedIn(300))
	if m.Grade() != GradeSlow {
		t.Fatalf("an ok sample and a good sample moved a slow route to %q", m.Grade())
	}
	feed(&m, carriedIn(300))
	if m.Grade() != GradeGood {
		t.Fatalf("two good samples in a row left it %q", m.Grade())
	}

	// One failure of a route that carries here is not "failing".
	feed(&m, RouteOutcome{Category: "tcp_connect_timeout"})
	if m.Grade() != GradeGood {
		t.Fatalf("one failure moved a good route to %q", m.Grade())
	}
	feed(&m, RouteOutcome{Category: "tcp_connect_timeout"})
	if m.Grade() != GradeFailing {
		t.Fatalf("two failures in a row left it %q", m.Grade())
	}
	// It carries again: "did not work here last time" would be untrue.
	feed(&m, RouteOutcome{Carried: true})
	if m.Grade() != GradeGood {
		t.Fatalf("a route that carried again is %q", m.Grade())
	}

	// Slow checks of a connected route: one is nothing, two are "slow".
	feed(&m, RouteOutcome{Carried: true, Slow: true})
	if m.Grade() != GradeGood {
		t.Fatalf("one slow check moved it to %q", m.Grade())
	}
	feed(&m, RouteOutcome{Carried: true, Slow: true})
	if m.Grade() != GradeSlow {
		t.Fatalf("two slow checks in a row left it %q", m.Grade())
	}
	feed(&m, RouteOutcome{Carried: true})
	if m.Grade() != GradeGood {
		t.Fatalf("a check that was not slow left it %q", m.Grade())
	}
}

func TestMeasured_CountsSmoothingAndBuckets(t *testing.T) {
	var m RouteMemory
	feed(&m, carriedIn(1004))
	if m.SetupMs != 1000 || m.Samples != 1 {
		t.Fatalf("first sample: setup=%d samples=%d (rounded to %d ms)", m.SetupMs, m.Samples, SetupRoundMs)
	}
	feed(&m, carriedIn(2000))
	if m.SetupMs != 1300 {
		t.Fatalf("smoothed setup = %d, want 1300 (three tenths of the way)", m.SetupMs)
	}
	feed(&m, RouteOutcome{Carried: true}, RouteOutcome{Category: "udp_no_reply"})
	got := m.Measured()
	if got.Samples != 2 || got.Carried != 3 || got.Failed != 1 || got.SetupMs != 1300 {
		t.Fatalf("measured = %+v", got)
	}
	if got.Last%3600 != 0 || got.Last == 0 {
		t.Fatalf("last = %d: not an hour bucket", got.Last)
	}
	// A record from before counts were kept is one carry, never timed.
	old := RouteMemory{CarriedSeq: 4, CarriedHour: 3600}
	if g := old.Measured(); g.Grade != GradeOK || g.Carried != 1 || g.Samples != 0 {
		t.Fatalf("legacy record = %+v", g)
	}
	if g := (RouteMemory{}).Measured(); g != (Measured{Grade: GradeUnknown}) {
		t.Fatalf("empty record = %+v", g)
	}
}

// Through the store: hour buckets only, and the first named network of
// a kind adopts the old shared record exactly once.
func TestStore_RecordOutcomeAndAdopt(t *testing.T) {
	s := New(newFakeKV())
	at := time.Date(2026, 11, 19, 14, 37, 12, 0, time.UTC)
	if err := s.RecordRouteOutcome("legacy", "r1", carriedIn(400), at); err != nil {
		t.Fatal(err)
	}
	m := s.LookupRouteMemory("legacy")["r1"]
	if m.Measured().Last != at.Truncate(time.Hour).Unix() || m.SetupMs != 400 {
		t.Fatalf("record = %+v", m)
	}
	moved, err := s.AdoptRouteMemory("legacy", "home", at)
	if err != nil || !moved {
		t.Fatalf("adopt: %v %v", moved, err)
	}
	if got := s.LookupRouteMemory("home")["r1"]; got.SetupMs != 400 || !got.CarriedLast() {
		t.Fatalf("the adopted record = %+v", got)
	}
	if _, err := s.Get("legacy"); err == nil {
		t.Fatal("the old shared record is still there: the next new network would adopt it again")
	}
	if moved, _ := s.AdoptRouteMemory("legacy", "office", at); moved {
		t.Fatal("a second network adopted a record that is gone")
	}
	// A network that remembers something of its own adopts nothing.
	_ = s.RecordRouteOutcome("legacy2", "r9", carriedIn(100), at)
	if moved, _ := s.AdoptRouteMemory("legacy2", "home", at); moved {
		t.Fatal("a network with its own memory was overwritten")
	}
}
