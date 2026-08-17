// refresh_freshness.go binds Step 8's recipient half into the engine:
// the scheduler's freshness kind, the executor that runs it, and the
// bootstrap-pointer recovery hook it falls through to.
//
// This is the file that turns core/refresh/relaypack.go from a
// well-tested library with zero callers into a behaviour. Everything
// here is plumbing; the policy lives in core/scheduler (when) and
// core/refresh (what).

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

// relayPackRefreshState wraps the singleton RelayPackRefresher, for the
// same reason refreshState wraps the others: the store it binds to is
// replaced by Init/Shutdown and the gomobile entry points can race that.
type relayPackRefreshState struct {
	mu sync.Mutex
	rp *refresh.RelayPackRefresher
}

var globalRelayPackRefresh = &relayPackRefreshState{}

// resetRelayPackRefreshForShutdown clears the cached refresher so a
// subsequent Init in the same process picks up the new store.
func resetRelayPackRefreshForShutdown() {
	globalRelayPackRefresh.mu.Lock()
	globalRelayPackRefresh.rp = nil
	globalRelayPackRefresh.mu.Unlock()
}

// ensureRelayPackRefresh builds (once) the RelayPack freshness
// refresher bound to the current core.
func ensureRelayPackRefresh() (*refresh.RelayPackRefresher, error) {
	c := loadedCore()
	if c == nil {
		return nil, errors.New("abi: not initialized")
	}
	globalRelayPackRefresh.mu.Lock()
	defer globalRelayPackRefresh.mu.Unlock()
	if globalRelayPackRefresh.rp == nil {
		globalRelayPackRefresh.rp = &refresh.RelayPackRefresher{
			Store:   relayPackStoreAdapter{S: c.store},
			Adapter: c.adapter,
			// The SAME fail-closed dialer shape the subscription and
			// revocation refreshers use. A freshness fetch that
			// reached the network any other way would be a second,
			// unaudited egress path with the leak Wave 1 closed on
			// the first one — and the publisher-side doc.go names
			// this exact hazard: the guard is not automatic on a
			// caller-supplied-dialer API, so the wiring is where it
			// is either honoured or lost.
			Dialer: refresh.DialerFn(func() (bootstrap.Dialer, bool, error) {
				if refresh.TunnelRequired() {
					return nil, false, refresh.ErrTunnelRequired
				}
				return bootstrap.NewDirectDialer(15 * time.Second), false, nil
			}),
			Now:     nowUTC,
			Recover: recoverViaBootstrapPointers,
		}
	}
	c.mu.Lock()
	mode := c.mode
	c.mu.Unlock()
	globalRelayPackRefresh.rp.Mode = mode
	return globalRelayPackRefresh.rp, nil
}

// recoverViaBootstrapPointers is the layer beneath the freshness
// endpoints: when every mirror in the pack is blocked, the only thing
// that can hand this device a NEW endpoint set is a channel the pack
// does not name. That channel is the project-root-signed bootstrap
// pointer list, which Provider.Refresh walks (primary then fallback,
// persisted rotation overlaid on embedded) and whose fetched directory
// can carry both a fresh pointer-rotation envelope and routes bearing a
// new freshness slot.
//
// It inherits the same guard: bootstrapDialer refuses rather than
// dialling direct while a route is active with no tunnel, so recovery
// cannot become the leak's back door.
//
// REAL POINTERS ARE STILL REQUIRED. The embedded fixtures point at
// `bootstrap-primary.daal.example`, which is not a host — it is a
// genfixtures placeholder. Shipping this layer for real needs, per
// pointer: a domain the project controls, on infrastructure whose
// blocking is expensive for the censor (a large shared CDN or a
// provider whose other tenants matter), serving a directory .sbp signed
// by a Tier-1 publisher, with the pointer set re-signed by the project
// root before its valid_until lapses. Inventing plausible-looking
// hostnames here would be worse than the placeholder, because a
// placeholder fails visibly and a wrong hostname fails like censorship.
func recoverViaBootstrapPointers(ctx context.Context) (string, error) {
	p, err := ensureBootstrap()
	if err != nil {
		return "", err
	}
	res, err := p.Refresh(ctx, 20*time.Second)
	if err != nil {
		return res.Reason, err
	}
	return res.PointerUsed, nil
}

// relayPackStoreAdapter is the routestore projection the RelayPack
// refresher needs. Separate from refreshStoreAdapter because that one
// is subscription-shaped (and because a typed seam per consumer is what
// keeps the store's surface from becoming everything).
type relayPackStoreAdapter struct{ S *routestore.Store }

func (a relayPackStoreAdapter) GetSecret(k string) ([]byte, error) { return a.S.GetSecret(k) }
func (a relayPackStoreAdapter) PutSecret(k string, v []byte) error { return a.S.PutSecret(k, v) }
func (a relayPackStoreAdapter) ListRoutes() ([]routestore.RouteRow, error) {
	return a.S.ListRoutes()
}
func (a relayPackStoreAdapter) AppendRefreshAudit(kind, refID, outcome string,
	bytesIn int64, viaTunnel bool, now time.Time) error {
	return a.S.AppendRefreshAudit(kind, refID, outcome, bytesIn, viaTunnel, now)
}

// RelayPacks satisfies scheduler.Source. It reads the persisted
// per-pack stamps so the cadence survives a restart: on a phone the
// engine is killed and relaunched constantly, and a floor that lives
// only in memory is not a floor at all.
func (s storeSource) RelayPacks() []scheduler.RelayPackState {
	if s.store == nil {
		return nil
	}
	// Deliberately a bare projection rather than ensureRelayPackRefresh:
	// Plan() is called from Status() as well as Tick(), including
	// before any refresher has been constructed, and building network
	// machinery as a side effect of rendering a status screen is how
	// a read turns into a fetch.
	probe := &refresh.RelayPackRefresher{Store: relayPackStoreAdapter{S: s.store}}
	states, err := probe.States()
	if err != nil {
		return nil
	}
	out := make([]scheduler.RelayPackState, 0, len(states))
	for _, st := range states {
		out = append(out, scheduler.RelayPackState{
			RelayPackID:   st.RelayPackID,
			LastSuccessAt: st.LastSuccessAt,
			LastFailureAt: st.LastFailureAt,
			// CARRY THE WHOLE STATE, NOT JUST THE TIMESTAMPS.
			//
			// These two used to be dropped here, and this adapter is
			// the ONLY production path from the persisted record to
			// the planner — so on every real device the planner ran
			// on ConsecutiveFailures=0, JitterOffset=0 while
			// core/refresh ran on the true values. That breaks the
			// two-gates-must-agree invariant the design is built on
			// (selection.FreshnessState.JitterOffset says so in as
			// many words), with two visible consequences:
			//
			//   * scheduler.Status()/AllNextDues reported a
			//     next-freshness-poll instant EARLIER than the one
			//     the trigger policy will actually accept — a
			//     diagnostics screen asserting a time that then
			//     silently passes with nothing happening, which
			//     reads as a stuck device;
			//   * Plan() emitted a due KindFreshness action on every
			//     tick through the whole escalated backoff window,
			//     each one dispatched into RelayPackRefresher.Refresh
			//     and immediately suppressed as rate-limited. Safe
			//     (the refresher re-reads the real record, so no
			//     endpoint was stormed) but the escalation and the
			//     per-device jitter were inert wherever they were
			//     supposed to be read.
			ConsecutiveFailures: st.ConsecutiveFailures,
			JitterOffset:        st.JitterOffset,
		})
	}
	return out
}

// RefreshFreshness satisfies scheduler.Executor.
func (e *refreshExecutor) RefreshFreshness(ctx context.Context, relayPackID string) error {
	rp, err := ensureRelayPackRefresh()
	if err != nil {
		return err
	}
	_, err = rp.Refresh(ctx, relayPackID)
	return err
}
