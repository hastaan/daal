package scheduler

import (
	"context"
	"encoding/json"
	"sync"
	"time"
)

// Executor performs the side-effecting refresh work. The scheduler
// owns the *when*; the executor owns the *what*. Splitting them keeps
// the planner pure (testable without I/O) and lets the soak driver
// stub the executor with a recorder for parity testing.
//
// Each method should be safe to call concurrently from multiple Tick
// invocations only if the underlying refresh.Refresher is; the
// scheduler itself serializes calls per kind+ref.
type Executor interface {
	RefreshSubscription(ctx context.Context, id string) error
	RefreshRevocation(ctx context.Context, publisherID string) error
	RefreshBootstrap(ctx context.Context) error
	// RefreshBudgetReset (Phase 2A) sweeps every route's hourly byte
	// counter at the new hour bucket. The implementation calls
	// budget.Engine.HourRollover(now). Returning an error is logged
	// but does not stop the tick.
	RefreshBudgetReset(ctx context.Context, now time.Time) error
	// RefreshFreshness (Step 8) polls one RelayPack's freshness
	// endpoints and, when the publisher has published a newer signed
	// pack, fetches and applies it. relayPackID is the Ref of a
	// KindFreshness action.
	//
	// The implementation MUST persist a last-success / last-failure
	// stamp before returning, whatever the outcome: the planner's only
	// defence against a tick storm is that stamp, and an executor that
	// silently returns without writing one converts a 15-minute floor
	// into a per-tick beacon.
	RefreshFreshness(ctx context.Context, relayPackID string) error
}

// Scheduler is the in-engine ticker. Production hosts call
// Start(ctx) once at engine init; tests and the parity flow call
// Tick(now) directly.
type Scheduler struct {
	src Source
	exe Executor
	cad Cadence

	// Production cadence between Tick invocations when Start() drives
	// the loop. Defaults to 1 minute. Tests using Tick directly do
	// not care about this value.
	tickEvery time.Duration

	mu      sync.Mutex
	stopped bool
	cancel  context.CancelFunc

	// wg tracks the goroutine spawned by Start so that Stop can join
	// it. Joining is what gives callers a happens-before edge over
	// everything the background Tick wrote; without it, reading any
	// state the executor touched after Stop() returns is a data race.
	wg sync.WaitGroup

	// observability
	lastTick   time.Time
	tickCount  int64
	dueLastRun []Action
	now        func() time.Time
}

// New constructs a Scheduler. Now defaults to time.Now.UTC; tests
// override it with a fake clock.
func New(src Source, exe Executor, cad Cadence) *Scheduler {
	if cad.Revocation == 0 {
		cad = DefaultCadence()
	}
	return &Scheduler{
		src:       src,
		exe:       exe,
		cad:       cad,
		tickEvery: time.Minute,
		now:       func() time.Time { return time.Now().UTC() },
	}
}

// SetNow overrides the scheduler's clock. Useful for the parity test
// and for soak rigs that drive simulated time.
func (s *Scheduler) SetNow(f func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = f
}

// SetTickEvery overrides the production tick cadence.
func (s *Scheduler) SetTickEvery(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d > 0 {
		s.tickEvery = d
	}
}

// Start spawns a background goroutine that calls Tick at TickEvery
// cadence until ctx is cancelled or Stop is called. The host (Tauri,
// Android service) calls this from engine_init's hot path.
func (s *Scheduler) Start(ctx context.Context) {
	s.mu.Lock()
	if s.cancel != nil {
		s.mu.Unlock()
		return
	}
	cctx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	every := s.tickEvery
	s.mu.Unlock()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-cctx.Done():
				return
			case <-t.C:
				s.Tick(s.now())
			}
		}
	}()
}

// Stop cancels the background goroutine if Start was called, then waits
// for it to exit. Idempotent. On return, everything the background Tick
// observed or wrote is safely visible to the caller.
//
// The mutex must be released before the join: Tick takes s.mu, so
// waiting under the lock would deadlock against an in-flight tick.
func (s *Scheduler) Stop() {
	s.mu.Lock()
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
	s.stopped = true
	s.mu.Unlock()

	s.wg.Wait()
}

// Tick computes the due list at `now` and executes each action through
// the Executor. Errors are not returned; per-action errors are recorded
// for the next Status() snapshot. Callers that want strict-error
// semantics can wrap a failing Executor.
//
// Tick is safe to call concurrently with itself only if the executor
// is; production code calls Tick from a single goroutine.
func (s *Scheduler) Tick(now time.Time) {
	due := Plan(s.src, s.cad, now)

	s.mu.Lock()
	s.lastTick = now
	s.tickCount++
	s.dueLastRun = due
	s.mu.Unlock()

	if s.exe == nil {
		return
	}
	ctx := context.Background()
	for _, a := range due {
		switch a.Kind {
		case KindSubscription:
			_ = s.exe.RefreshSubscription(ctx, a.Ref)
		case KindRevocation:
			_ = s.exe.RefreshRevocation(ctx, a.Ref)
		case KindBootstrap:
			_ = s.exe.RefreshBootstrap(ctx)
		case KindBudgetReset:
			_ = s.exe.RefreshBudgetReset(ctx, now)
		case KindFreshness:
			_ = s.exe.RefreshFreshness(ctx, a.Ref)
		}
	}
}

// Status is the JSON snapshot exposed via engine_scheduler_status. It
// reports the next-due time per registered item, the last-tick
// timestamp, and the total tick count since process start. The shape
// is documented in specs/scheduler-v1.md so the GUI / CLI can render
// it without parsing the engine source.
type Status struct {
	Cadence  CadenceJSON  `json:"cadence"`
	LastTick string       `json:"last_tick,omitempty"`
	Ticks    int64        `json:"ticks"`
	NextDue  []ActionJSON `json:"next_due"`
}

// CadenceJSON is the JSON-friendly view of Cadence. Additive only —
// the GUI and the CLI parse this shape from specs/scheduler-v1.md.
type CadenceJSON struct {
	RevocationSec int64 `json:"revocation_sec"`
	BootstrapSec  int64 `json:"bootstrap_sec"`
	// Step 8. The freshness floor and ceiling, so a diagnostics screen
	// can say "next freshness poll no sooner than X" without hard-coding
	// the policy a second time.
	FreshnessMinIntervalSec  int64 `json:"freshness_min_interval_sec"`
	FreshnessMaxStalenessSec int64 `json:"freshness_max_staleness_sec"`
}

// ActionJSON is the JSON-friendly view of Action.
type ActionJSON struct {
	Kind    string `json:"kind"`
	Ref     string `json:"ref,omitempty"`
	NextDue string `json:"next_due"`
}

// StatusJSON returns a Status snapshot ready to JSON-marshal. The
// engine_scheduler_status ABI calls this and writes the result through
// copyOut.
func (s *Scheduler) StatusJSON() ([]byte, error) {
	s.mu.Lock()
	last := s.lastTick
	ticks := s.tickCount
	cad := s.cad
	now := s.now()
	s.mu.Unlock()

	all := AllNextDues(s.src, cad, now)
	fresh := defaultedFreshness(cad.Freshness)
	out := Status{
		Cadence: CadenceJSON{
			RevocationSec:            int64(cad.Revocation.Seconds()),
			BootstrapSec:             int64(cad.Bootstrap.Seconds()),
			FreshnessMinIntervalSec:  int64(fresh.MinInterval.Seconds()),
			FreshnessMaxStalenessSec: int64(fresh.MaxStaleness.Seconds()),
		},
		Ticks: ticks,
	}
	if !last.IsZero() {
		out.LastTick = last.UTC().Format(time.RFC3339)
	}
	for _, a := range all {
		out.NextDue = append(out.NextDue, ActionJSON{
			Kind:    string(a.Kind),
			Ref:     a.Ref,
			NextDue: a.NextDue.UTC().Format(time.RFC3339),
		})
	}
	return json.Marshal(out)
}
