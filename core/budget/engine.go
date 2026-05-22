package budget

import (
	"sort"
	"sync"
	"time"
)

// Store is the persistence seam Engine talks to. The production
// binding wraps routestore.Store; tests use a recording stub.
//
// All methods MUST be safe to call concurrently. The Engine itself
// also serializes mutating calls, but reads (Snapshot) may race with
// writes from other goroutines through the Store layer if the
// implementation does not lock.
type Store interface {
	// SetRouteScarcity assigns or updates the route's tag.
	SetRouteScarcity(routeID, tag string) error

	// SetRouteBytesHour writes the route's per-hour consumed counter
	// AND its hour-bucket cursor in one atomic-ish update. The
	// production routestore writes the row and the secrets_kv key in
	// a single transaction; tests use a map.
	SetRouteBytesHour(routeID string, consumed uint64, bucket time.Time) error

	// GetRouteBudget returns (tag, consumed, bucket) for routeID. If
	// the route does not exist the implementation returns
	// (\"\", 0, time.Time{}) without an error — Engine treats that as
	// \"untagged\" and lets Add charge through.
	GetRouteBudget(routeID string) (tag string, consumed uint64, bucket time.Time, err error)

	// EnumerateBudgets returns the snapshot rows for every known
	// route, sorted by route_id. Used by Engine.Snapshot.
	EnumerateBudgets() ([]Row, error)
}

// Row is the persisted budget state for one route.
type Row struct {
	RouteID  string
	Tag      string
	Consumed uint64
	Bucket   time.Time
}

// Snapshot is the immutable per-route view returned by Engine.Snapshot
// and embedded in engine_export_diagnostics.
//
// Phase 2A-Polish widens this struct additively with three fields:
// SessionCap, SessionConsumed, ModesAllowed. Existing 2A consumers
// (which read RouteID, BudgetTag, HourlyCap, Consumed, Exhausted)
// are unaffected; the JSON-tagged additive fields appear as new keys
// on every row whenever the engine is instantiated.
type Snapshot struct {
	RouteID         string    `json:"route_id"`
	BudgetTag       string    `json:"budget_tag"`
	HourlyCap       uint64    `json:"hourly_cap_bytes"`
	Consumed        uint64    `json:"consumed_bytes"`
	SessionCap      uint64    `json:"session_cap_bytes"`
	SessionConsumed uint64    `json:"session_consumed_bytes"`
	ModesAllowed    []string  `json:"modes_allowed"`
	HourBucket      time.Time `json:"-"`
	Exhausted       bool      `json:"exhausted"`
}

// Engine is the per-route byte counter + cap enforcer. Phase 2A
// landed the hourly counter; Phase 2A-Polish adds the per-session
// counter on the same struct. The session axis lives in-process
// only — it is NOT persisted across engine_init, because engine_init
// IS the canonical session boundary.
type Engine struct {
	store Store
	now   func() time.Time
	mu    sync.Mutex

	// sessionEpoch increments on every NewSession() call. Tests
	// observe it via SessionEpoch().
	sessionEpoch uint64

	// sessionConsumed is keyed by routeID and holds the per-session
	// byte total. Routes with a `Cap.Session == 0` (unlimited) are
	// NOT tracked in this map (avoids unbounded growth on bulk
	// traffic).
	sessionConsumed map[string]uint64

	// mode is the V2.2 mode dial: "lifeline", "normal", "bulk", or
	// "lifeline-strict" (2D). Empty string means "normal" (the
	// default; pre-2B behaviour). Mode change does NOT bump the
	// session epoch and does NOT clear hourly counters — rolling
	// caps are mode-neutral; only the *ceiling* changes.
	mode string

	// activeNetwork is the V2.4 network ID label the engine is
	// currently bound to. It is informative — it does NOT key the
	// persisted bucket counters, which remain device-wide for
	// 30-day-soak parity. Per-network state lives one layer up in
	// core/netmem; the engine exposes CaptureNetwork /
	// RestoreNetwork for the swap path. Empty string == sentinel
	// "unset" until engine_network_changed lands the first ID.
	activeNetwork string

	// allowBulkCapableThisSession is the V2.5/2D per-session opt-in
	// flag: in lifeline-strict mode, bulk-capable routes are filtered
	// OUT of the ranker by default; setting this flag returns them
	// to the selectable set. Zeroed by NewSession (engine_init);
	// untouched by SetMode and SetActiveNetwork.
	allowBulkCapableThisSession bool
}

// New constructs an Engine bound to store. now defaults to
// time.Now().UTC.
func New(store Store, now func() time.Time) *Engine {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Engine{
		store:           store,
		now:             now,
		sessionConsumed: map[string]uint64{},
	}
}

// NewSession bumps the session epoch and zeroes per-session counters.
// Phase 2A-Polish wires this into the canonical session boundary —
// every successful engine_init triggers exactly one NewSession.
//
// MUST NOT be called from engine_set_mode (mode change must not
// launder session caps) or engine_network_changed (network roams
// are 2C territory and intentionally do not reset the session).
func (e *Engine) NewSession() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.sessionEpoch++
	e.sessionConsumed = map[string]uint64{}
	// Phase 2D: the per-session bulk-capable opt-in does NOT
	// survive a session boundary — engine_init zeroes it.
	e.allowBulkCapableThisSession = false
}

// SetAllowBulkCapableThisSession sets the V2.5/2D per-session opt-in
// for bulk-capable routes in lifeline-strict mode. Phase 2D. Cleared
// by NewSession (engine_init); untouched by SetMode and
// SetActiveNetwork.
func (e *Engine) SetAllowBulkCapableThisSession(v bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.allowBulkCapableThisSession = v
}

// AllowsBulkCapableThisSession reports the V2.5/2D per-session opt-in.
// Used by pathmanager.RankWithView to decide whether to filter
// bulk-capable in lifeline-strict.
func (e *Engine) AllowsBulkCapableThisSession() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.allowBulkCapableThisSession
}

// SessionEpoch returns the current session epoch. For tests and
// diagnostics. Not part of the release ABI.
func (e *Engine) SessionEpoch() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.sessionEpoch
}

// SetMode updates the active mode dial. Phase 2B. Mode change MUST
// NOT touch the session epoch (2A-Polish rule) and MUST NOT clear
// hourly counters (rolling caps are mode-neutral; only the cap
// ceiling moves).
func (e *Engine) SetMode(mode string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.mode = mode
}

// Mode returns the active mode. Empty internal state surfaces as
// "normal" (the default).
func (e *Engine) Mode() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.mode == "" {
		return "normal"
	}
	return e.mode
}

// SetActiveNetwork records the network ID the engine is currently
// bound to. Phase 2C. Informative only — it does NOT change the
// persisted hourly counters' keying, which remain device-wide so
// the 30-day soak parity ledger stays byte-for-byte identical.
// Per-network restore-on-roam lives in core/netmem; the engine
// emits CaptureNetwork() / RestoreNetwork() to support that swap.
//
// MUST NOT bump the session epoch (the session axis is independent
// of network roams; 2A-Polish carry-over).
func (e *Engine) SetActiveNetwork(networkID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.activeNetwork = networkID
}

// ActiveNetwork returns the engine's currently bound network ID.
func (e *Engine) ActiveNetwork() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.activeNetwork
}

// CaptureNetwork returns the per-route hourly-bucket consumed map
// at the current hour for the active network. The returned map +
// bucket are intended to be written into a netmem.Snapshot before
// a network swap. Stale (rolled-over) buckets are excluded.
func (e *Engine) CaptureNetwork() (map[string]uint64, time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now().Truncate(time.Hour).UTC()
	rows, err := e.store.EnumerateBudgets()
	if err != nil {
		return map[string]uint64{}, now
	}
	out := map[string]uint64{}
	for _, r := range rows {
		if !sameBucket(r.Bucket, now) {
			// Stale: counter has rolled; capturing zero would be
			// indistinguishable from "no use", which is the
			// correct semantic.
			continue
		}
		if r.Consumed == 0 {
			continue
		}
		out[r.RouteID] = r.Consumed
	}
	return out, now
}

// RestoreNetwork seeds per-route hourly-bucket consumed counters
// from a previously captured snapshot. Used on network swap-in via
// engine_network_changed. Counters whose persisted bucket is older
// than the supplied bucket are written; if the supplied bucket has
// itself rolled past the current hour, no counters are restored
// (stale data drop).
func (e *Engine) RestoreNetwork(usage map[string]uint64, bucket time.Time) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now().Truncate(time.Hour).UTC()
	if !sameBucket(bucket, now) {
		// Saved bucket is from a previous hour; the V2.1 invariant
		// is "rolling caps are time-bounded, not session-bounded",
		// so a stale snapshot is silently dropped.
		return 0
	}
	written := 0
	for routeID, consumed := range usage {
		if consumed == 0 {
			continue
		}
		if err := e.store.SetRouteBytesHour(routeID, consumed, now); err == nil {
			written++
		}
	}
	return written
}

// SetTag assigns the route's budget tag. Returns ErrUnknownTag if tag
// is not in the closed caps map.
func (e *Engine) SetTag(routeID, tag string) error {
	if _, err := CapFor(tag); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.store.SetRouteScarcity(routeID, tag)
}

// Add charges n bytes against routeID's current hour bucket AND its
// per-session counter. Returns ErrExhausted if EITHER axis would be
// exceeded; the first axis to trip wins. On exhaustion both counters
// advance to their cap values (partial credit), so the diagnostics
// snapshot reads exactly at-cap.
//
// The dual-axis invariant is: when either axis trips, the BYTES
// charged on each axis are equal — i.e., both counters advance by the
// same `charge` value. This keeps `consumed_bytes` and
// `session_consumed_bytes` mutually consistent and lets the snapshot
// flag whichever axis is at its cap.
//
// Add is safe to call from any goroutine.
func (e *Engine) Add(routeID string, n uint64) error {
	if n == 0 {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	tag, consumed, bucket, err := e.store.GetRouteBudget(routeID)
	if err != nil {
		return err
	}

	full, capErr := FullCapFor(tag)
	newBucket := e.now().Truncate(time.Hour).UTC()
	if !sameBucket(bucket, newBucket) {
		consumed = 0
	}

	if capErr != nil {
		// Untagged: still record the consumed counter (so diagnostics
		// shows usage) but never exhaust.
		return e.store.SetRouteBytesHour(routeID, consumed+n, newBucket)
	}

	// Phase 2B: apply the active mode's multiplier to BOTH axes.
	// 0 (unlimited) stays 0; the mode dial cannot enlarge an
	// already-unlimited cap. ModeFactor(unknown) defaults to 1.0.
	f := ModeFactor(e.mode)
	hourCap := applyFactor(full.Hourly, f)
	sessCap := applyFactor(full.Session, f)
	sessConsumed := e.sessionConsumed[routeID]

	// Pre-trip: if either axis is already at or past its cap, refuse.
	if hourCap > 0 && consumed >= hourCap {
		return ErrExhausted
	}
	if sessCap > 0 && sessConsumed >= sessCap {
		return ErrExhausted
	}

	// Determine the largest `charge` (≤ n) that fits in BOTH axes.
	// Whichever axis has the smallest headroom dictates whether we
	// trip on this call.
	charge := n
	willTrip := false
	if hourCap > 0 {
		if room := hourCap - consumed; room < charge {
			charge = room
			willTrip = true
		}
	}
	if sessCap > 0 {
		if room := sessCap - sessConsumed; room < charge {
			charge = room
			willTrip = true
		}
	}

	// Persist hourly counter and update session counter under the
	// engine mu. Session map is touched only when the tag has a
	// finite session cap — `bulk-capable` (Session == 0) stays out of
	// the map, keeping it bounded.
	if sessCap > 0 {
		e.sessionConsumed[routeID] = sessConsumed + charge
	}
	if err := e.store.SetRouteBytesHour(routeID, consumed+charge, newBucket); err != nil {
		// Best-effort: roll back the session-side advance to keep
		// the two axes consistent on persistence failure.
		if sessCap > 0 {
			e.sessionConsumed[routeID] = sessConsumed
		}
		return err
	}

	if willTrip {
		return ErrExhausted
	}
	return nil
}

// Snapshot returns the current per-route view. Sorted by route_id for
// stable diagnostics output.
//
// Phase 2A-Polish: each row now carries SessionCap, SessionConsumed,
// and ModesAllowed. SessionConsumed reads from the in-process map
// (so a fresh engine started by engine_init reports zero session use
// for every route, matching the "session boundary == init" model).
// Exhausted is true if EITHER axis is at cap.
func (e *Engine) Snapshot() []Snapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	rows, err := e.store.EnumerateBudgets()
	if err != nil {
		return nil
	}
	out := make([]Snapshot, 0, len(rows))
	now := e.now().Truncate(time.Hour).UTC()
	// Phase 2B: surface the *effective* cap (after mode factor) so
	// the desktop's RouteBudgetTable shows what's actually enforced.
	f := ModeFactor(e.mode)
	for _, r := range rows {
		full, capErr := FullCapFor(r.Tag) // ErrUnknownTag → zero-value Cap
		consumed := r.Consumed
		if !sameBucket(r.Bucket, now) {
			// The persisted counter belongs to a stale hour; report
			// the current hour's view as zero.
			consumed = 0
		}
		sessConsumed := e.sessionConsumed[r.RouteID]

		hourCap := applyFactor(full.Hourly, f)
		sessCap := applyFactor(full.Session, f)

		hourExh := hourCap > 0 && consumed >= hourCap
		sessExh := sessCap > 0 && sessConsumed >= sessCap

		// Always emit a non-nil ModesAllowed slice so JSON renders
		// `"modes_allowed": []` rather than `null` for unknown tags.
		modes := full.ModesAllowed
		if modes == nil {
			modes = []string{}
		}
		_ = capErr

		out = append(out, Snapshot{
			RouteID:         r.RouteID,
			BudgetTag:       r.Tag,
			HourlyCap:       hourCap,
			Consumed:        consumed,
			SessionCap:      sessCap,
			SessionConsumed: sessConsumed,
			ModesAllowed:    modes,
			HourBucket:      now,
			Exhausted:       hourExh || sessExh,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RouteID < out[j].RouteID })
	return out
}

// Reset clears the consumed counter for routeID at the current hour
// bucket. Used by the scheduler at hour rollover and by the
// `engine_apply_cooldown` path when a manual reset is requested.
func (e *Engine) Reset(routeID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now().Truncate(time.Hour).UTC()
	_ = e.store.SetRouteBytesHour(routeID, 0, now)
}

// HourRollover sweeps every known route, resetting any whose cached
// bucket is older than now. This is the action the scheduler's
// budget-reset task fires every hour. Returning the count is helpful
// for diagnostics ("3 routes rolled over this tick").
func (e *Engine) HourRollover(now time.Time) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	target := now.Truncate(time.Hour).UTC()
	rows, err := e.store.EnumerateBudgets()
	if err != nil {
		return 0
	}
	rolled := 0
	for _, r := range rows {
		if sameBucket(r.Bucket, target) {
			continue
		}
		if err := e.store.SetRouteBytesHour(r.RouteID, 0, target); err == nil {
			rolled++
		}
	}
	return rolled
}

// sameBucket reports whether a and b are in the same hour bucket.
// Both arguments are already-truncated by the callers, but we
// re-truncate defensively.
func sameBucket(a, b time.Time) bool {
	return a.Truncate(time.Hour).Equal(b.Truncate(time.Hour))
}
