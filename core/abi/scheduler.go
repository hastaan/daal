package abi

import (
	"context"
	"errors"
	"sync"
	"time"

	"daal/core/bootstrap"
	"daal/core/refresh"
	"daal/core/routestore"
	"daal/core/scheduler"
)

// schedulerState owns the singleton scheduler.Scheduler. The scheduler
// is constructed lazily on the first engine_scheduler_status call (or,
// in production hosts that want autostart, by Init via StartScheduler).
type schedulerState struct {
	mu  sync.Mutex
	sch *scheduler.Scheduler
}

var globalScheduler = &schedulerState{}

// resetSchedulerForShutdown clears the cached scheduler on Shutdown so
// a subsequent Init in the same process picks up the new store.
func resetSchedulerForShutdown() {
	globalScheduler.mu.Lock()
	defer globalScheduler.mu.Unlock()
	if globalScheduler.sch != nil {
		globalScheduler.sch.Stop()
	}
	globalScheduler.sch = nil
}

// ensureScheduler returns a Scheduler bound to the current core's
// store + Refresher. Idempotent.
func ensureScheduler() (*scheduler.Scheduler, error) {
	// Snapshot loadedCore() once. A concurrent Shutdown can null it out
	// between the entry-point's check and our access, so re-checking
	// here keeps the gomobile contract ("never panic; always return
	// a clean error if not ready") regardless of timing.
	c := loadedCore()
	if c == nil {
		return nil, errors.New("abi: not initialized")
	}
	subs, rev, err := ensureRefresh()
	if err != nil {
		return nil, err
	}
	bsProvider, err := ensureBootstrap()
	if err != nil {
		return nil, err
	}

	globalScheduler.mu.Lock()
	defer globalScheduler.mu.Unlock()
	if globalScheduler.sch != nil {
		return globalScheduler.sch, nil
	}
	src := storeSource{store: c.store, now: nowUTC}
	exe := &refreshExecutor{
		subs:  subs,
		rev:   rev,
		bs:    bsProvider,
		store: c.store,
		now:   nowUTC,
	}
	s := scheduler.New(src, exe, scheduler.DefaultCadence())
	s.SetNow(nowUTC)
	globalScheduler.sch = s
	return s, nil
}

// SchedulerStatus is engine_scheduler_status.
func SchedulerStatus() (string, error) {
	if loadedCore() == nil {
		return "", errors.New("abi: not initialized")
	}
	s, err := ensureScheduler()
	if err != nil {
		return "", err
	}
	body, err := s.StatusJSON()
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// StartScheduler is a convenience the host can call once after Init to
// drive the scheduler on a real ticker. Tests and the soak parity
// driver bypass this and call Tick directly.
func StartScheduler(ctx context.Context, every time.Duration) error {
	s, err := ensureScheduler()
	if err != nil {
		return err
	}
	if every > 0 {
		s.SetTickEvery(every)
	}
	s.Start(ctx)
	return nil
}

// SchedulerTick is an exported helper that ensures the scheduler exists
// and runs one Tick. Used by the soak driver's `--mode in-engine` flag
// to drive the scheduler from outside the engine on simulated time.
//
// Phase 2G: every Tick also evaluates the auto-promotion detector.
// If the verdict says promote AND the user hasn't manually overridden
// AND the detector hasn't already fired this hour, the engine flips
// into lifeline-strict via the auto-path. The flip happens BEFORE the
// scheduler's own Tick so the new mode applies to any refreshes the
// tick decides to dispatch.
func SchedulerTick(now time.Time) error {
	_ = EvaluateAutoPromotion(now)
	s, err := ensureScheduler()
	if err != nil {
		return err
	}
	s.Tick(now)
	return nil
}

// storeSource is the read-only snapshot of the routestore the scheduler
// needs. It satisfies scheduler.Source.
type storeSource struct {
	store *routestore.Store
	now   func() time.Time
}

func (s storeSource) Subscriptions() []scheduler.SubscriptionState {
	rows, err := s.store.ListSubscriptions()
	if err != nil {
		return nil
	}
	out := make([]scheduler.SubscriptionState, 0, len(rows))
	for _, r := range rows {
		t, _ := time.Parse(time.RFC3339, r.LastGoodRefreshBkt)
		out = append(out, scheduler.SubscriptionState{
			SubscriptionID:   r.SubscriptionID,
			ProfileUpdateMin: r.ProfileUpdateMin,
			LastGoodRefresh:  t.UTC(),
		})
	}
	return out
}

func (s storeSource) PublishersWithRevocation() []scheduler.PublisherState {
	rows, err := s.store.ListPublishersWithRevocationURL()
	if err != nil {
		return nil
	}
	out := make([]scheduler.PublisherState, 0, len(rows))
	for _, p := range rows {
		t, _ := time.Parse(time.RFC3339, p.LastRevocationCheck)
		out = append(out, scheduler.PublisherState{
			PublisherID:         p.PublisherID,
			LastRevocationCheck: t.UTC(),
		})
	}
	return out
}

func (s storeSource) LastBootstrapRefresh() time.Time {
	// We do not yet persist a top-level "last bootstrap refresh"; until
	// the directory-refresh flow stamps a row, treat it as zero so the
	// scheduler considers it always due. The 24-h cadence then keeps
	// it from re-firing once the executor records its first success.
	val, err := s.store.GetSecret("scheduler:last-bootstrap-refresh")
	if err != nil || len(val) == 0 {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, string(val))
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// LastBudgetReset (Phase 2A) tracks the wall-clock of the last
// hour-rollover sweep. Persisted in secrets_kv so the cadence survives
// restart.
func (s storeSource) LastBudgetReset() time.Time {
	val, err := s.store.GetSecret("scheduler:last-budget-reset")
	if err != nil || len(val) == 0 {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, string(val))
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// refreshExecutor satisfies scheduler.Executor by delegating to the
// existing refresh.Refresher / RevocationRefresher and the bootstrap
// provider. It is the production binding; tests use a recorder.
type refreshExecutor struct {
	subs  *refresh.Refresher
	rev   *refresh.RevocationRefresher
	bs    *bootstrap.Provider
	store *routestore.Store
	now   func() time.Time
}

func (e *refreshExecutor) RefreshSubscription(ctx context.Context, id string) error {
	if e.subs == nil {
		return nil
	}
	_, err := e.subs.Refresh(ctx, id, 15*time.Second)
	return err
}

func (e *refreshExecutor) RefreshRevocation(ctx context.Context, _ string) error {
	if e.rev == nil {
		return nil
	}
	// The current RevocationRefresher API is RefreshAll-shaped (one
	// pass over every publisher); per-publisher dispatch lands when
	// 2A wires per-publisher cadence. For now the scheduler asks for
	// a refresh and we honor it with the broader sweep.
	_, err := e.rev.RefreshAll(ctx, 15*time.Second)
	return err
}

func (e *refreshExecutor) RefreshBootstrap(ctx context.Context) error {
	if e.bs == nil {
		// Bootstrap provider not initialized yet; benign.
		return nil
	}
	if _, err := e.bs.Refresh(ctx, 15*time.Second); err != nil {
		return err
	}
	// Stamp the new last-refresh so the scheduler knows not to re-fire
	// for the next 24 h.
	return e.store.PutSecret(
		"scheduler:last-bootstrap-refresh",
		[]byte(e.now().UTC().Format(time.RFC3339)),
	)
}

// RefreshBudgetReset (Phase 2A) is the executor binding for
// KindBudgetReset. It calls budget.Engine.HourRollover at the new
// hour bucket and stamps the wall-clock so the next Plan call gates
// on cadence.
func (e *refreshExecutor) RefreshBudgetReset(ctx context.Context, now time.Time) error {
	_ = ctx
	eng := ensureBudget()
	_ = eng.HourRollover(now)
	return e.store.PutSecret(
		"scheduler:last-budget-reset",
		[]byte(now.UTC().Format(time.RFC3339)),
	)
}
