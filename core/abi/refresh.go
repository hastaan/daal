package abi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"daal/core/bootstrap"
	"daal/core/internal/selection"
	"daal/core/refresh"
	"daal/core/routestore"
)

// refreshState wraps the Refresher (subscriptions) and RevocationRefresher
// behind a sync.Mutex. Init lazily on first use because the device share
// identity is also lazy.
type refreshState struct {
	mu     sync.Mutex
	subs   *refresh.Refresher
	revoke *refresh.RevocationRefresher
}

var globalRefresh = &refreshState{}

// resetRefreshForShutdown clears the cached Refreshers so a subsequent
// Init() in the same process picks up the new store. Called from
// Shutdown.
func resetRefreshForShutdown() {
	globalRefresh.mu.Lock()
	globalRefresh.subs = nil
	globalRefresh.revoke = nil
	globalRefresh.mu.Unlock()
}

func ensureRefresh() (*refresh.Refresher, *refresh.RevocationRefresher, error) {
	// Snapshot for the same reason ensureBootstrap and ensureScheduler
	// do — gomobile entry points the UI polls reach this code path.
	c := loadedCore()
	if c == nil {
		return nil, nil, errors.New("abi: not initialized")
	}
	if err := initShare(c); err != nil {
		return nil, nil, fmt.Errorf("refresh: identity: %w", err)
	}
	globalRefresh.mu.Lock()
	defer globalRefresh.mu.Unlock()
	if globalRefresh.subs == nil {
		// The Phase 1D bootstrap dialer is the same primitive a tunnel
		// would supply; in Phase 1.5A it is wired direct. Phase 1.5B
		// will replace the dialer with a TunnelDialer when the engine
		// exposes a SOCKS5 inlet.
		dialerFn := refresh.DialerFn(func() (bootstrap.Dialer, bool, error) {
			return bootstrap.NewDirectDialer(15 * time.Second), false, nil
		})
		globalRefresh.subs = &refresh.Refresher{
			Store:    refreshStoreAdapter{S: c.store},
			Identity: globalShare.identity,
			Adapter:  c.adapter,
			Dialer:   dialerFn,
			Now:      nowUTC,
		}
		globalRefresh.revoke = &refresh.RevocationRefresher{
			Store:  revocationStoreAdapter{S: c.store},
			Dialer: dialerFn,
			Now:    nowUTC,
		}
	}
	// Phase 2D: thread the live mode into both refreshers on every
	// access. The mode mutates via SetMode but we don't fire a
	// notify; this keeps the refresher mode-aware without coupling.
	c.mu.Lock()
	mode := c.mode
	c.mu.Unlock()
	globalRefresh.subs.Mode = mode
	globalRefresh.revoke.Mode = mode
	return globalRefresh.subs, globalRefresh.revoke, nil
}

// SubscriptionAdd is engine_subscription_add.
func SubscriptionAdd(publisherFP, url, displayName string) (string, error) {
	subs, _, err := ensureRefresh()
	if err != nil {
		return "", err
	}
	out, err := subs.Add(refresh.AddInput{
		PublisherID: publisherFP,
		URL:         url,
		DisplayName: displayName,
	})
	if err != nil {
		return "", err
	}
	body, _ := json.Marshal(out)
	return string(body), nil
}

// SubscriptionRefresh is engine_subscription_refresh. Phase 2D: this
// is the user-triggered surface; it bypasses the lifeline-strict
// gate. Scheduler-driven refreshes go through SubscriptionRefreshAll
// and ARE gated.
func SubscriptionRefresh(subscriptionID string, timeoutMs int) (string, error) {
	subs, _, err := ensureRefresh()
	if err != nil {
		return "", err
	}
	if timeoutMs <= 0 {
		timeoutMs = 15000
	}
	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(timeoutMs)*time.Millisecond)
	defer cancel()
	res, err := subs.RefreshUser(ctx, subscriptionID, time.Duration(timeoutMs)*time.Millisecond)
	body, _ := json.Marshal(res)
	if err != nil {
		return string(body), err
	}
	return string(body), nil
}

// SubscriptionRemove is engine_subscription_remove.
func SubscriptionRemove(subscriptionID string) error {
	subs, _, err := ensureRefresh()
	if err != nil {
		return err
	}
	return subs.Remove(subscriptionID)
}

// SubscriptionList is a helper used by the CLI; not part of the C ABI but
// exposed via gomobile.
func SubscriptionList() (string, error) {
	if loadedCore() == nil {
		return "", errors.New("abi: not initialized")
	}
	c := loadedCore()
	rows, err := c.store.ListSubscriptions()
	if err != nil {
		return "", err
	}
	type item struct {
		SubscriptionID     string `json:"subscription_id"`
		PublisherID        string `json:"publisher_id"`
		DisplayName        string `json:"display_name"`
		ProfileTitle       string `json:"profile_title"`
		LastRefreshBucket  string `json:"last_refresh_bucket"`
		LastRefreshOutcome string `json:"last_refresh_outcome"`
		LastGoodRefreshBkt string `json:"last_good_refresh_bucket"`
	}
	out := make([]item, 0, len(rows))
	for _, r := range rows {
		out = append(out, item{
			SubscriptionID:     r.SubscriptionID,
			PublisherID:        r.PublisherID,
			DisplayName:        r.DisplayName,
			ProfileTitle:       r.ProfileTitle,
			LastRefreshBucket:  r.LastRefreshBucket,
			LastRefreshOutcome: r.LastRefreshOutcome,
			LastGoodRefreshBkt: r.LastGoodRefreshBkt,
		})
	}
	body, _ := json.Marshal(map[string]any{"subscriptions": out})
	return string(body), nil
}

// RevocationRefreshAll is engine_revocation_refresh_all. Phase 2D:
// this is the user-triggered surface; it bypasses the lifeline-strict
// gate. Scheduler-driven revocation refreshes go through the
// scheduler's RefreshExecutor and ARE gated.
func RevocationRefreshAll(timeoutMs int) (string, error) {
	_, rev, err := ensureRefresh()
	if err != nil {
		return "", err
	}
	if timeoutMs <= 0 {
		timeoutMs = 15000
	}
	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(timeoutMs)*time.Millisecond)
	defer cancel()
	out, err := rev.RefreshAllUser(ctx, time.Duration(timeoutMs)*time.Millisecond)
	body, _ := json.Marshal(map[string]any{"results": out})
	if err != nil {
		return string(body), err
	}
	return string(body), nil
}

// PointerRotationStatus is engine_pointer_rotation_status.
func PointerRotationStatus() (string, error) {
	if loadedCore() == nil {
		return "", errors.New("abi: not initialized")
	}
	c := loadedCore()
	p, err := ensureBootstrap()
	if err != nil {
		return "", err
	}
	_ = p
	st := globalBootstrap.manifest.StatusFromStore(c.store)
	body, _ := json.Marshal(st)
	return string(body), nil
}

// DiagnosticsExplain is engine_diagnostics_explain.
//
// Returns a non-panicking error if the engine isn't initialised yet.
// The Android UI polls this every 500 ms from the moment the
// composable resumes, which can race ahead of the async `Init()`
// coroutine. A panic on a gomobile-bound thread is fatal to the
// whole process (the goroutine is `LockOSThread`'d to the JNI
// worker), so entry points that callers may legitimately invoke
// during the init window MUST return an error instead.
func DiagnosticsExplain() (string, error) {
	if loadedCore() == nil {
		return "", errors.New("abi: not initialized")
	}
	c := loadedCore()
	w := c.pm.Explain()
	// Persist to diagnostics_explain so the CLI / next-launch UI can
	// surface it without needing the Manager to still be in memory.
	skipped, _ := json.Marshal(w.SkippedFamilies)
	_ = c.store.PutDiagnosticsExplain(w.Bucket, w.WhyChoseRoute, string(skipped))

	exp := selection.NewExplanation("diagnostics-"+w.Bucket, selection.PhaseV15)
	exp.Reason = w.WhyChoseRoute
	if w.ActiveRoute != "" {
		if row, err := c.store.GetRoute(w.ActiveRoute); err == nil {
			out := selection.Decide(selection.Input{
				Routes:     []routestore.RouteRow{row},
				Mode:       selection.ModeNormal,
				Phase:      selection.PhaseV15,
				Now:        time.Now().UTC(),
				DecisionID: "diagnostics-" + w.Bucket,
			})
			if out.Explanation != nil {
				exp = out.Explanation
				// Preserve the legacy FSM sentence when the selector
				// projection is being used as a diagnostics carrier.
				if w.WhyChoseRoute != "" {
					exp.Reason = w.WhyChoseRoute
				}
			}
		}
	}

	var payload map[string]any
	expBody, _ := json.Marshal(exp)
	_ = json.Unmarshal(expBody, &payload)
	if payload == nil {
		payload = map[string]any{}
	}
	// Compatibility fields for pre-FRP-6 renderers and store-backed
	// diagnostics. FRP-6 clients bind to the Explanation keys above;
	// older clients can keep reading the pathmanager shape.
	payload["bucket"] = w.Bucket
	payload["state"] = w.State
	if w.ActiveRoute != "" {
		payload["active_route"] = w.ActiveRoute
	}
	payload["why_chose_route"] = w.WhyChoseRoute
	payload["skipped_families"] = w.SkippedFamilies
	if w.LastFailure != nil {
		payload["last_failure"] = w.LastFailure
	}

	body, _ := json.Marshal(payload)
	return string(body), nil
}

// refreshStoreAdapter routes the routestore.Store to the refresh.Store
// interface. It is a thin wrapper because Store has the same method set
// already; this gives us a typed seam for tests.
type refreshStoreAdapter struct{ S *routestore.Store }

func (a refreshStoreAdapter) GetSecret(k string) ([]byte, error) {
	return a.S.GetSecret(k)
}
func (a refreshStoreAdapter) PutSecret(k string, v []byte) error {
	return a.S.PutSecret(k, v)
}
func (a refreshStoreAdapter) GetSubscription(id string) (routestore.SubscriptionRow, error) {
	return a.S.GetSubscription(id)
}
func (a refreshStoreAdapter) UpsertSubscription(r routestore.SubscriptionRow) error {
	return a.S.UpsertSubscription(r)
}
func (a refreshStoreAdapter) ListSubscriptions() ([]routestore.SubscriptionRow, error) {
	return a.S.ListSubscriptions()
}
func (a refreshStoreAdapter) DeleteSubscription(id string) error {
	return a.S.DeleteSubscription(id)
}
func (a refreshStoreAdapter) AppendRefreshAudit(kind, refID, outcome string,
	bytesIn int64, viaTunnel bool, now time.Time) error {
	return a.S.AppendRefreshAudit(kind, refID, outcome, bytesIn, viaTunnel, now)
}

type revocationStoreAdapter struct{ S *routestore.Store }

func (a revocationStoreAdapter) ListPublishersWithRevocationURL() ([]routestore.PublisherRow, error) {
	return a.S.ListPublishersWithRevocationURL()
}
func (a revocationStoreAdapter) MarkRouteRevoked(id string) error {
	return a.S.MarkRouteRevoked(id)
}
func (a revocationStoreAdapter) MarkPublisherRoutesRevoked(id string) error {
	return a.S.MarkPublisherRoutesRevoked(id)
}
func (a revocationStoreAdapter) MarkPublisherRevocationChecked(id string, now time.Time) error {
	return a.S.MarkPublisherRevocationChecked(id, now)
}
func (a revocationStoreAdapter) AppendRefreshAudit(kind, refID, outcome string,
	bytesIn int64, viaTunnel bool, now time.Time) error {
	return a.S.AppendRefreshAudit(kind, refID, outcome, bytesIn, viaTunnel, now)
}

var _ = errors.New
