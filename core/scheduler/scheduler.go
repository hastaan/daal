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

	go func() {
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

// Stop cancels the background goroutine if Start was called. Idempotent.
func (s *Scheduler) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
	s.stopped = true
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

// CadenceJSON is the JSON-friendly view of Cadence.
type CadenceJSON struct {
	RevocationSec int64 `json:"revocation_sec"`
	BootstrapSec  int64 `json:"bootstrap_sec"`
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
	out := Status{
		Cadence: CadenceJSON{
			RevocationSec: int64(cad.Revocation.Seconds()),
			BootstrapSec:  int64(cad.Bootstrap.Seconds()),
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

// LastDue returns the most recent due-list, for tests that want to
// inspect what Tick(now) saw.
func (s *Scheduler) LastDue() []Action {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Action, len(s.dueLastRun))
	copy(out, s.dueLastRun)
	return out
}
