package budget

import (
	"sort"
	"sync"
	"testing"
	"time"
)

// fakeStore is a recording in-memory Store for tests.
type fakeStore struct {
	mu      sync.Mutex
	tag     map[string]string
	consume map[string]uint64
	bucket  map[string]time.Time
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		tag:     map[string]string{},
		consume: map[string]uint64{},
		bucket:  map[string]time.Time{},
	}
}

func (f *fakeStore) SetRouteScarcity(routeID, tag string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tag[routeID] = tag
	return nil
}

func (f *fakeStore) SetRouteBytesHour(routeID string, consumed uint64, bucket time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.consume[routeID] = consumed
	f.bucket[routeID] = bucket
	return nil
}

func (f *fakeStore) GetRouteBudget(routeID string) (string, uint64, time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tag[routeID], f.consume[routeID], f.bucket[routeID], nil
}

func (f *fakeStore) EnumerateBudgets() ([]Row, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Row, 0, len(f.tag))
	for id, tag := range f.tag {
		out = append(out, Row{
			RouteID:  id,
			Tag:      tag,
			Consumed: f.consume[id],
			Bucket:   f.bucket[id],
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RouteID < out[j].RouteID })
	return out, nil
}

func clock(s string) func() time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return func() time.Time { return t.UTC() }
}

func TestSetTagRejectsUnknown(t *testing.T) {
	e := New(newFakeStore(), clock("2026-04-26T12:00:00Z"))
	if err := e.SetTag("r1", "nonsense"); err != ErrUnknownTag {
		t.Fatalf("expected ErrUnknownTag, got %v", err)
	}
}

func TestAddBelowCap(t *testing.T) {
	s := newFakeStore()
	e := New(s, clock("2026-04-26T12:00:00Z"))
	if err := e.SetTag("r1", TagEmergency); err != nil {
		t.Fatalf("SetTag: %v", err)
	}
	if err := e.Add("r1", 10*MiB); err != nil {
		t.Fatalf("Add 10 MiB: %v", err)
	}
	if got := s.consume["r1"]; got != 10*MiB {
		t.Errorf("consumed = %d, want %d", got, 10*MiB)
	}
}

func TestAddCrossesCapExhausts(t *testing.T) {
	s := newFakeStore()
	e := New(s, clock("2026-04-26T12:00:00Z"))
	_ = e.SetTag("r1", TagEmergency) // 50 MiB cap
	// Charge 49 MiB — fits.
	if err := e.Add("r1", 49*MiB); err != nil {
		t.Fatalf("Add 49 MiB: %v", err)
	}
	// Charge another 2 MiB — crosses 50 MiB cap.
	if err := e.Add("r1", 2*MiB); err != ErrExhausted {
		t.Fatalf("expected ErrExhausted on cap crossing, got %v", err)
	}
	if got := s.consume["r1"]; got != 50*MiB {
		t.Errorf("consumed should be clamped to 50 MiB, got %d", got)
	}
	// Subsequent Add still ErrExhausted.
	if err := e.Add("r1", 1); err != ErrExhausted {
		t.Fatalf("expected ErrExhausted on saturated route, got %v", err)
	}
}

func TestAddBulkCapableNeverExhausts(t *testing.T) {
	s := newFakeStore()
	e := New(s, clock("2026-04-26T12:00:00Z"))
	_ = e.SetTag("r1", TagBulkCapable)
	// 100 GiB on a bulk-capable route must succeed.
	for i := 0; i < 100; i++ {
		if err := e.Add("r1", 1*GiB); err != nil {
			t.Fatalf("bulk-capable Add %d: %v", i, err)
		}
	}
	if got := s.consume["r1"]; got != 100*GiB {
		t.Errorf("bulk-capable consumed = %d, want %d", got, 100*GiB)
	}
}

func TestHourBucketResetsCounter(t *testing.T) {
	s := newFakeStore()
	hour := time.Hour
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	clk := &advanceableClock{now: now}
	e := New(s, clk.Now)
	_ = e.SetTag("r1", TagEmergency)
	// Burn 49 MiB at HH=12.
	if err := e.Add("r1", 49*MiB); err != nil {
		t.Fatalf("Add: %v", err)
	}
	// Advance to HH=13. The next Add must succeed even with another 49 MiB.
	clk.advance(hour)
	if err := e.Add("r1", 49*MiB); err != nil {
		t.Fatalf("post-rollover Add: %v", err)
	}
	if got := s.consume["r1"]; got != 49*MiB {
		t.Errorf("after rollover consumed = %d, want %d", got, 49*MiB)
	}
}

func TestSnapshotSortedAndExhaustedFlag(t *testing.T) {
	s := newFakeStore()
	e := New(s, clock("2026-04-26T12:00:00Z"))
	_ = e.SetTag("z-route", TagNormal)
	_ = e.SetTag("a-route", TagEmergency)
	_ = e.Add("a-route", 50*MiB) // exhausts
	snap := e.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("len(snap) = %d", len(snap))
	}
	if snap[0].RouteID != "a-route" || snap[1].RouteID != "z-route" {
		t.Errorf("snapshot not sorted: %+v", snap)
	}
	if !snap[0].Exhausted {
		t.Errorf("a-route should be exhausted: %+v", snap[0])
	}
	if snap[1].Exhausted {
		t.Errorf("z-route should NOT be exhausted: %+v", snap[1])
	}
}

func TestHourRollover(t *testing.T) {
	s := newFakeStore()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	clk := &advanceableClock{now: now}
	e := New(s, clk.Now)
	_ = e.SetTag("r1", TagEmergency)
	_ = e.SetTag("r2", TagEmergency)
	_ = e.Add("r1", 30*MiB)
	_ = e.Add("r2", 5*MiB)

	// Rollover to next hour.
	clk.advance(time.Hour)
	rolled := e.HourRollover(clk.Now())
	if rolled != 2 {
		t.Errorf("expected 2 routes rolled over, got %d", rolled)
	}
	if s.consume["r1"] != 0 || s.consume["r2"] != 0 {
		t.Errorf("counters not reset after rollover: %v", s.consume)
	}
}

// === Phase 2A-Polish: per-session cap tests ===

// TestSessionCapTrips drives 5 successive 50 MiB charges on an
// emergency-tagged route, advancing the clock by exactly 1 hour
// between each so the hourly bucket starts fresh every time. The
// per-session cap (200 MiB) must trip during the 5th charge — i.e.,
// the 4 successful charges total 200 MiB, the 5th returns
// ErrExhausted.
func TestSessionCapTrips(t *testing.T) {
	s := newFakeStore()
	clk := &advanceableClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	e := New(s, clk.Now)
	_ = e.SetTag("r1", TagEmergency) // hourly 50 MiB, session 200 MiB

	for i := 0; i < 4; i++ {
		if err := e.Add("r1", 50*MiB); err != nil {
			t.Fatalf("charge %d (50 MiB): unexpected error %v", i, err)
		}
		clk.advance(time.Hour) // fresh hourly bucket
	}
	// Cumulative 200 MiB charged; session is now at cap. Next byte trips.
	if err := e.Add("r1", 1); err != ErrExhausted {
		t.Fatalf("expected ErrExhausted after 200 MiB on emergency tag, got %v", err)
	}
}

// TestSessionResetOnNewSession exhausts a session, calls NewSession,
// and verifies the next Add succeeds. SessionEpoch must increment.
func TestSessionResetOnNewSession(t *testing.T) {
	s := newFakeStore()
	clk := &advanceableClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	e := New(s, clk.Now)
	_ = e.SetTag("r1", TagLifelineOnly) // hourly 100 MiB, session 500 MiB

	for i := 0; i < 5; i++ {
		if err := e.Add("r1", 100*MiB); err != nil {
			t.Fatalf("charge %d: %v", i, err)
		}
		clk.advance(time.Hour)
	}
	// Session at cap.
	if err := e.Add("r1", 1); err != ErrExhausted {
		t.Fatalf("expected ErrExhausted, got %v", err)
	}
	beforeEpoch := e.SessionEpoch()
	e.NewSession()
	if e.SessionEpoch() != beforeEpoch+1 {
		t.Errorf("session epoch did not advance: before=%d after=%d", beforeEpoch, e.SessionEpoch())
	}
	// Fresh session — Add must succeed (still in the rolled-over hour
	// bucket, hourly cap has fresh headroom).
	clk.advance(time.Hour)
	if err := e.Add("r1", 1*MiB); err != nil {
		t.Fatalf("post-NewSession Add: %v", err)
	}
}

// TestSessionCounterUnlimitedForBulkCapable drives 100 GiB through a
// bulk-capable route. Neither axis must trip and the in-process
// session map must NOT grow (bulk-capable has Session=0; map stays
// bounded).
func TestSessionCounterUnlimitedForBulkCapable(t *testing.T) {
	s := newFakeStore()
	e := New(s, clock("2026-04-26T12:00:00Z"))
	_ = e.SetTag("r-bulk", TagBulkCapable)
	for i := 0; i < 100; i++ {
		if err := e.Add("r-bulk", 1*GiB); err != nil {
			t.Fatalf("bulk charge %d: %v", i, err)
		}
	}
	e.mu.Lock()
	mapLen := len(e.sessionConsumed)
	e.mu.Unlock()
	if mapLen != 0 {
		t.Errorf("bulk-capable should NOT populate sessionConsumed map, got len=%d", mapLen)
	}
}

// TestHourlyTripBeforeSessionWhenHourlyTighter pins the clock so no
// rollover occurs and asserts hourly trips first when its headroom
// is smaller than session's. After the trip both counters MUST be
// at the same byte total (50 MiB) — partial-credit invariant.
func TestHourlyTripBeforeSessionWhenHourlyTighter(t *testing.T) {
	s := newFakeStore()
	e := New(s, clock("2026-04-26T12:00:00Z"))
	_ = e.SetTag("r1", TagEmergency) // hourly 50 MiB, session 200 MiB

	if err := e.Add("r1", 49*MiB); err != nil {
		t.Fatalf("Add 49 MiB: %v", err)
	}
	if err := e.Add("r1", 2*MiB); err != ErrExhausted {
		t.Fatalf("expected ErrExhausted on hourly cap crossing, got %v", err)
	}
	if got := s.consume["r1"]; got != 50*MiB {
		t.Errorf("hourly counter not clamped to 50 MiB: %d", got)
	}
	e.mu.Lock()
	sc := e.sessionConsumed["r1"]
	e.mu.Unlock()
	if sc != 50*MiB {
		t.Errorf("session counter inconsistent with hourly: got %d, want %d", sc, 50*MiB)
	}
}

// TestAllowBulkCapableClearedOnNewSession — the 2D per-session
// bulk-capable opt-in MUST NOT survive a session boundary
// (engine_init).
func TestAllowBulkCapableClearedOnNewSession(t *testing.T) {
	s := newFakeStore()
	e := New(s, nil)
	e.SetAllowBulkCapableThisSession(true)
	if !e.AllowsBulkCapableThisSession() {
		t.Fatal("flag did not stick after Set")
	}
	e.NewSession()
	if e.AllowsBulkCapableThisSession() {
		t.Error("session bulk-capable opt-in survived NewSession()")
	}
}

// TestAllowBulkCapableSurvivesModeToggle — mode change MUST NOT
// touch the 2D per-session bulk-capable opt-in.
func TestAllowBulkCapableSurvivesModeToggle(t *testing.T) {
	s := newFakeStore()
	e := New(s, nil)
	e.SetAllowBulkCapableThisSession(true)

	for _, m := range []string{"lifeline", "lifeline-strict", "normal", "bulk"} {
		e.SetMode(m)
		if !e.AllowsBulkCapableThisSession() {
			t.Errorf("flag cleared after SetMode(%q)", m)
		}
	}
}

type advanceableClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *advanceableClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *advanceableClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}
