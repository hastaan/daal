package netmem

import "time"

// Measurement — how a route has done ON ONE NETWORK, kept inside the
// same RouteMemory record the automatic connect already orders by.
//
// WHAT IS KEPT (all of it in the encrypted per-network snapshot, all of
// it forgotten with the route and by the panic wipe):
//
//	setup_ms   the time from "start this route" to its first completed
//	           round trip, smoothed over the samples (SetupSmoothing).
//	           Rounded to SetupRoundMs. A duration, not a time of day.
//	samples    how many setup times went into it.
//	carried    how many recorded checks carried; failed how many did not.
//	last       the HOUR BUCKET of the latest of them — the resolution
//	           the store keeps every other time at.
//
// THE GRADE is a closed word derived from those, and it is held to one
// rule: one sample never moves it from one settled word to another.
//
//	unknown  nothing was ever recorded for the route on this network.
//	failing  it failed here GradeFailStreak times in a row since it last
//	         carried — or it has never carried here and has failed.
//	slow     GradeSlowStreak checks in a row called it slow, or two setup
//	         samples in a row took longer than GradeOKMaxMs.
//	ok       two setup samples in a row between GradeGoodMaxMs and
//	         GradeOKMaxMs (or: carried here, never timed).
//	good     two setup samples in a row at or under GradeGoodMaxMs.
//
// The speed word (good / ok / slow) is COMMITTED: a sample that falls in
// another band is remembered as a candidate (SpeedNext) and changes the
// word only when the next sample falls in that same band. The first
// sample ever commits at once — leaving "unknown" is not a flip.
//
// The one direction that takes a single observation: a route that
// CARRIES stops being "failing" at once. "Did not work here last time"
// about a route that worked a moment ago would be untrue.
const (
	GradeUnknown = "unknown"
	GradeGood    = "good"
	GradeOK      = "ok"
	GradeSlow    = "slow"
	GradeFailing = "failing"
)

const (
	// GradeGoodMaxMs / GradeOKMaxMs: the bands of one setup sample.
	GradeGoodMaxMs = 1500
	GradeOKMaxMs   = 4000
	// GradeFailStreak: failures in a row, since the last time it carried,
	// that make a route that HAS carried here "failing".
	GradeFailStreak = 2
	// GradeSlowStreak: checks in a row that called a carrying route slow.
	GradeSlowStreak = 2
	// SetupSmoothing: each new sample moves the kept setup time this many
	// tenths of the way toward itself.
	SetupSmoothing = 3
	// SetupRoundMs: the kept setup time is rounded to this.
	SetupRoundMs = 10
)

// RouteOutcome is one recorded check of a route on a network.
type RouteOutcome struct {
	// Carried: a round trip completed. Otherwise Category is the closed
	// failure category.
	Carried  bool
	Category string
	// HasSetup / SetupMs: the check was a fresh start of the route and
	// this is how long it took. A check of a route that was already
	// connected has none.
	HasSetup bool
	SetupMs  int
	// Slow: it carried, and the check called it slow.
	Slow bool
}

// speedBand is the word one setup sample alone would get.
func speedBand(ms int) string {
	switch {
	case ms <= GradeGoodMaxMs:
		return GradeGood
	case ms <= GradeOKMaxMs:
		return GradeOK
	}
	return GradeSlow
}

// apply folds one outcome into the record. seq / hour are the ordering
// counter and the hour bucket the caller took (Store.recordRoute).
func (m *RouteMemory) apply(o RouteOutcome, seq uint64, hour int64) {
	if !o.Carried {
		m.FailedSeq, m.FailedHour, m.FailedCategory = seq, hour, o.Category
		m.Failed++
		m.FailStreak++
		return
	}
	m.CarriedSeq, m.CarriedHour = seq, hour
	m.Carried++
	m.FailStreak = 0
	if o.Slow {
		m.SlowStreak++
	} else {
		m.SlowStreak = 0
	}
	if !o.HasSetup {
		return
	}
	ms := o.SetupMs
	if ms < 0 {
		ms = 0
	}
	if m.Samples == 0 {
		m.SetupMs = ms
	} else {
		m.SetupMs += (ms - m.SetupMs) * SetupSmoothing / 10
	}
	m.SetupMs = (m.SetupMs + SetupRoundMs/2) / SetupRoundMs * SetupRoundMs
	m.Samples++
	switch band := speedBand(ms); {
	case m.Speed == "":
		m.Speed, m.SpeedNext = band, ""
	case band == m.Speed:
		m.SpeedNext = ""
	case band == m.SpeedNext:
		m.Speed, m.SpeedNext = band, ""
	default:
		m.SpeedNext = band
	}
}

// carriedCount / failedCount read the counts, counting a record written
// before counts were kept (a sequence number and no count) as one.
func (m RouteMemory) carriedCount() int {
	if m.Carried == 0 && m.CarriedSeq > 0 {
		return 1
	}
	return m.Carried
}

func (m RouteMemory) failedCount() int {
	if m.Failed == 0 && m.FailedSeq > 0 {
		return 1
	}
	return m.Failed
}

// Grade is the closed word for the record. See the top of this file.
func (m RouteMemory) Grade() string {
	carried, failed := m.carriedCount(), m.failedCount()
	switch {
	case carried == 0 && failed == 0:
		return GradeUnknown
	case carried == 0:
		return GradeFailing
	case m.FailStreak >= GradeFailStreak:
		return GradeFailing
	case m.SlowStreak >= GradeSlowStreak:
		return GradeSlow
	case m.Speed != "":
		return m.Speed
	}
	// It carried here and was never timed (a record older than the
	// measurement, or only ever seen by a check of a connected route).
	return GradeOK
}

// Measured is the record as the route listing reports it.
type Measured struct {
	Grade   string `json:"grade"`
	SetupMs int    `json:"setup_ms"`
	Samples int    `json:"samples"`
	Carried int    `json:"carried"`
	Failed  int    `json:"failed"`
	// Last: unix seconds of the hour bucket of the latest recorded
	// check; 0 when there is none.
	Last int64 `json:"last"`
}

// Measured projects the record. The zero record is {"unknown", 0, …}.
func (m RouteMemory) Measured() Measured {
	last := m.CarriedHour
	if m.FailedHour > last {
		last = m.FailedHour
	}
	return Measured{Grade: m.Grade(), SetupMs: m.SetupMs, Samples: m.Samples,
		Carried: m.carriedCount(), Failed: m.failedCount(), Last: last}
}

// GradeRank orders the words for "is this one better": higher is
// better; unknown and failing are not comparable speeds and rank 0.
func GradeRank(grade string) int {
	switch grade {
	case GradeGood:
		return 3
	case GradeOK:
		return 2
	case GradeSlow:
		return 1
	}
	return 0
}

// RecordRouteOutcome folds one check of routeID on networkID into its
// record. The rest of the snapshot is kept as it is.
func (s *Store) RecordRouteOutcome(networkID, routeID string, o RouteOutcome, now time.Time) error {
	return s.recordRoute(networkID, routeID, now, func(m *RouteMemory, seq uint64, hour int64) {
		m.apply(o, seq, hour)
	})
}

// AdoptRouteMemory moves what is remembered about the routes on network
// `from` to network `to`, when `to` remembers nothing and `from` does,
// and then forgets `from`. Reports whether anything was moved.
//
// For the day a host starts naming networks one by one: until then
// every Wi-Fi shared one record (the kind was the whole identity), and
// what it holds is the best first guess for the first real network of
// that kind. It is moved ONCE — the record is deleted, so the next new
// network of the kind starts empty rather than inheriting a guess made
// somewhere else.
func (s *Store) AdoptRouteMemory(from, to string, now time.Time) (bool, error) {
	if from == "" || to == "" || from == to {
		return false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	old, err := s.Get(from)
	if err != nil || len(old.RouteMemory) == 0 {
		return false, nil
	}
	dst, err := s.Get(to)
	if err != nil {
		dst = Snapshot{}
	}
	if len(dst.RouteMemory) != 0 {
		return false, nil
	}
	dst.RouteMemory, dst.RouteMemorySeq = old.RouteMemory, old.RouteMemorySeq
	if dst.Mode == "" {
		dst.Mode = old.Mode
	}
	if err := s.Put(to, dst, now); err != nil {
		return false, err
	}
	return true, s.Forget(from)
}
