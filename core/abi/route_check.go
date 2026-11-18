package abi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sync"
	"time"

	"daal/core/diagnostics"
	"daal/core/engine"
	"daal/core/pathmanager"
	"daal/core/refresh"
	"daal/core/routestore"
)

// The connection check — the ABI half of the proof in
// core/engine/proof.go.
//
// A route is in exactly one of these states from the moment SetRoute
// starts the engine instance for it:
//
//	verifying  the instance is up; one real round trip through the
//	           route's outbound is being attempted. NOT connected.
//	ok         the round trip completed. Connected.
//	degraded   it completed, too slowly to call usable (path_too_slow).
//	           Connected, and said to be slow.
//	failed     no round trip could be made. At connect time the instance
//	           is torn down and SetRoute returns the error — the path a
//	           Start failure has always taken. While connected (the
//	           liveness check) the instance is LEFT RUNNING: see
//	           failRouteLocked.
//
// `route_check` in the diagnostics blob carries the state; "" means no
// route is active. The UI reads it to show "Checking the connection…"
// where it used to show "Connected".
//
// "failed" alone does not say which of the two failures happened, and
// they are opposite things to tell a user: after a failed CONNECT
// nothing is running and nothing will retry; after a failed liveness
// check the instance is up and is re-proved every RecheckInterval.
// `route_running` in the same blob is the difference — true exactly
// while an engine instance for a route is up. A UI that showed
// "Connecting…" for both (as it did: the posture is Recovery in both)
// was promising a retry that, after a failed connect, never comes.

const (
	RouteCheckNone      = ""
	RouteCheckVerifying = "verifying"
	RouteCheckOK        = "ok"
	RouteCheckDegraded  = "degraded"
	RouteCheckFailed    = "failed"
)

// ErrRouteNotCarrying is wrapped by the error SetRoute returns when the
// engine started and the route then failed its connection proof. A host
// can tell it from a route the engine refused to try at all.
var ErrRouteNotCarrying = errors.New("abi: the route started but carried no traffic")

// ErrConnectCancelled is returned by a SetRoute whose proof was
// abandoned because the user disconnected or picked another route
// meanwhile. Nothing is recorded about the route.
var ErrConnectCancelled = errors.New("abi: connection attempt cancelled")

// routeCheck is the per-Core connection-check state. Its own mutex, not
// Core.mu: the diagnostics pollers read it while SetRoute is mid-proof,
// and ClearRoute must be able to cancel a proof without waiting for the
// lock SetRoute's bookkeeping takes.
type routeCheck struct {
	mu       sync.Mutex
	state    string
	category diagnostics.Category // failed / degraded: why
	// running: an engine instance for the route is up. Implied by every
	// state but failed (verifying / ok / degraded: yes; none: no);
	// failed is the one state that exists both ways.
	running bool
	// cancelProof abandons the connect-time proof in flight, if any.
	cancelProof context.CancelFunc
	// cancelLive stops the liveness loop of the connected route.
	cancelLive context.CancelFunc
	kick       chan struct{}
	// checkMu serialises proofs of the connected route (timer, network
	// change, an explicit CheckActiveRoute).
	checkMu sync.Mutex
}

// set records a state other than failed; whether an instance is running
// follows from the state. A failure goes through setFailed.
func (rc *routeCheck) set(state string, cat diagnostics.Category) {
	rc.mu.Lock()
	rc.state, rc.category = state, cat
	rc.running = state == RouteCheckVerifying || state == RouteCheckOK || state == RouteCheckDegraded
	rc.mu.Unlock()
}

// setFailed records a failed check. running says whether the instance
// was left up (a liveness failure) or torn down (a failed connect).
func (rc *routeCheck) setFailed(cat diagnostics.Category, running bool) {
	rc.mu.Lock()
	rc.state, rc.category, rc.running = RouteCheckFailed, cat, running
	rc.mu.Unlock()
}

func (rc *routeCheck) get() (string, diagnostics.Category) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.state, rc.category
}

// snapshot is get plus running, read under one lock: the diagnostics
// blob must never pair one check's state with another's instance.
func (rc *routeCheck) snapshot() (state string, cat diagnostics.Category, running bool) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.state, rc.category, rc.running
}

// abandon cancels whatever proof is in flight and stops the liveness
// loop. Safe to call with or without Core.mu held; it takes neither.
func (rc *routeCheck) abandon() {
	rc.mu.Lock()
	cp, cl := rc.cancelProof, rc.cancelLive
	rc.cancelProof, rc.cancelLive = nil, nil
	rc.mu.Unlock()
	if cp != nil {
		cp()
	}
	if cl != nil {
		cl()
	}
}

// ---- configuration --------------------------------------------------

// EngineConfigFile is the optional engine configuration file in the
// state directory. Absent means "every default"; it is the only way to
// change what the connection check does. See specs/engine-abi-v1.md
// "Engine configuration file".
const EngineConfigFile = "engine-config.json"

type engineConfigFile struct {
	ConnectionCheck *struct {
		Targets           []string `json:"targets"`
		AttemptTimeoutMs  int      `json:"attempt_timeout_ms"`
		Attempts          int      `json:"attempts"`
		SlowAfterMs       int      `json:"slow_after_ms"`
		LivenessIntervalS int      `json:"liveness_interval_s"`
		RecheckIntervalS  int      `json:"recheck_interval_s"`
	} `json:"connection_check"`
}

// loadProofConfig reads the connection-check configuration. A missing
// file is the default; a file that does not parse, names an unknown
// field or an unusable target is an ERROR — the file exists only when
// someone wrote it on purpose, and silently running the default instead
// would hide exactly the mistake they need to see.
func loadProofConfig(stateDir string) (engine.ProofConfig, error) {
	cfg := engine.ProofConfig{}
	body, err := os.ReadFile(filepath.Join(stateDir, EngineConfigFile))
	if errors.Is(err, os.ErrNotExist) {
		return cfg.Normalised()
	}
	if err != nil {
		return cfg, fmt.Errorf("abi: read %s: %w", EngineConfigFile, err)
	}
	var f engineConfigFile
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return cfg, fmt.Errorf("abi: %s: %w", EngineConfigFile, err)
	}
	if cc := f.ConnectionCheck; cc != nil {
		if cc.AttemptTimeoutMs < 0 || cc.Attempts < 0 || cc.SlowAfterMs < 0 || cc.LivenessIntervalS < 0 || cc.RecheckIntervalS < 0 {
			return cfg, fmt.Errorf("abi: %s: connection_check values must not be negative", EngineConfigFile)
		}
		cfg.Targets = cc.Targets
		cfg.AttemptTimeout = time.Duration(cc.AttemptTimeoutMs) * time.Millisecond
		cfg.Attempts = cc.Attempts
		cfg.SlowAfter = time.Duration(cc.SlowAfterMs) * time.Millisecond
		cfg.LivenessInterval = time.Duration(cc.LivenessIntervalS) * time.Second
		cfg.RecheckInterval = time.Duration(cc.RecheckIntervalS) * time.Second
	}
	out, err := cfg.Normalised()
	if err != nil {
		return out, fmt.Errorf("abi: %s: %w", EngineConfigFile, err)
	}
	return out, nil
}

// ---- outcomes (all called with Core.mu held) -------------------------

// advancePosture fires a posture transition only when the table allows
// it. Manager.SetPosture overwrites LastReason with "illegal transition
// …" on a refused edge, and LastReason is the `why` the diagnostics blob
// publishes — a second failure in a row must not replace the failure's
// own explanation with FSM plumbing.
func (c *Core) advancePosture(event pathmanager.PostureEvent, to pathmanager.Posture) {
	if pathmanager.IsLegal(c.pm.Posture(), event, to) {
		_ = c.pm.SetPosture(event, to)
	}
}

// routeUpLocked records a proof that succeeded: the ONLY place the
// engine concludes a route works. `proven` and `health_pct` are
// downstream of the RecordSuccess / RecordDegraded here.
func (c *Core) routeUpLocked(routeID, family string, res engine.ProofResult) {
	c.pm.Resume(routeID, family)
	c.pm.Connected()
	if res.Slow {
		c.pm.MarkDegraded(diagnostics.PathTooSlow)
		_ = c.store.RecordDegraded(routeID, string(diagnostics.PathTooSlow), nowUTC())
		c.check.set(RouteCheckDegraded, diagnostics.PathTooSlow)
		c.driver.PublishState(engine.StateDegraded)
	} else {
		_ = c.store.RecordSuccess(routeID, nowUTC())
		c.check.set(RouteCheckOK, "")
		c.driver.PublishState(engine.StateConnected)
	}
	// Posture axis (Phase-3-Soak): consumers read `posture`. Gap 5:
	// an experimental-family route advances to PostureExperimental so
	// the UI shows the warning. From Recovery (a previous route failed
	// its proof, or this one failed a liveness check and came back) the
	// table's event is recovery_selected.
	exp := routestore.IsExperimentalFamily(family)
	switch {
	case exp:
		c.advancePosture(pathmanager.EventExperimentalSelected, pathmanager.PostureExperimental)
	case c.pm.Posture() == pathmanager.PostureRecovery:
		c.advancePosture(pathmanager.EventRecoverySelected, pathmanager.PostureImportedActive)
	default:
		c.advancePosture(pathmanager.EventImportedSelected, pathmanager.PostureImportedActive)
	}
}

// routeDownLocked records a classified failure of routeID — from a
// Start error or from a failed proof — and returns the category.
//
// teardown: stop the engine instance. True at connect time: a route
// that never carried anything has no tunnel worth keeping, and the
// caller is told the connect failed. False for a liveness failure of a
// route that WAS connected: stopping the instance there would leave the
// platform's VPN interface up with nothing behind it and no way back
// short of the user reconnecting, while a running instance heals by
// itself the moment the path returns (sing-box dials per connection).
// Nothing leaks either way — the tunnel stays the only way out, and
// refresh stays tunnel-required — and the state the user is shown is
// "failed", not "Connected", until a later proof succeeds.
func (c *Core) routeDownLocked(routeID, family string, cat diagnostics.Category, reason string, teardown bool) {
	c.driver.PublishFailure(cat, reason)
	if teardown {
		_ = c.driver.Stop()
		// No tunnel, so bootstrap/refresh may dial direct.
		refresh.SetTunnelRequired(false)
		c.activeRoute, c.activeFamily = "", ""
	}
	c.pm.Resume(routeID, family)
	c.pm.Failed(routeID, family, cat)
	// Persist the outcome the FSM just computed (privacy shape: hour
	// bucket + closed category vocabulary, one row per route — see
	// routestore.RecordFailure).
	_ = c.store.RecordFailure(routeID, string(cat), pmCooldownUntil(c, routeID), nowUTC())
	c.advancePosture(pathmanager.EventActiveFailed, pathmanager.PostureRecovery)
	c.check.setFailed(cat, !teardown)
}

// ---- liveness ---------------------------------------------------------

// CheckResult is what one check of the connected route found.
type CheckResult struct {
	RouteID  string `json:"route_id"`
	State    string `json:"route_check"`
	Category string `json:"category,omitempty"`
	// Checked is false when there was nothing to check (no connected
	// route) or the check was abandoned by a disconnect.
	Checked bool `json:"checked"`
}

// CheckActiveRoute proves the connected route once, now, and moves it
// between ok / degraded / failed accordingly. It is the function the
// liveness timer, the network-change signal and (next stage) the prober
// call; it never selects or switches a route.
//
// A route that fails is recorded exactly as a failed connect is — the
// classified category, the FSM cooldown, the durable failure row,
// posture → Recovery — but the instance is left running (see
// routeDownLocked). A failed route that proves again goes back to ok.
// A route that is already failed and fails again records nothing new:
// one outage is one failure, not one per recheck.
func CheckActiveRoute() (string, error) {
	c := loadedCore()
	if c == nil {
		return "", errors.New("abi: not initialized")
	}
	res := c.checkActiveRoute(context.Background())
	body, _ := json.Marshal(res)
	return string(body), nil
}

func (c *Core) checkActiveRoute(ctx context.Context) CheckResult {
	c.check.checkMu.Lock()
	defer c.check.checkMu.Unlock()

	c.mu.Lock()
	epoch, routeID, family, cfg := c.routeEpoch, c.activeRoute, c.activeFamily, c.proofCfg
	state, _ := c.check.get()
	c.mu.Unlock()
	if routeID == "" || state == RouteCheckVerifying || state == RouteCheckNone {
		return CheckResult{}
	}

	res := c.driver.Prove(ctx, cfg)

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.routeEpoch != epoch || res.Cancelled {
		return CheckResult{RouteID: routeID}
	}
	prev, prevCat := c.check.get()
	switch {
	case res.OK:
		c.routeUpLocked(routeID, family, res)
	case prev == RouteCheckFailed:
		// Still down. Keep the first classification of this outage.
		return CheckResult{RouteID: routeID, State: prev, Category: string(prevCat), Checked: true}
	default:
		c.routeDownLocked(routeID, family, res.Category(), proofFailureText(res), false)
	}
	st, cat := c.check.get()
	return CheckResult{RouteID: routeID, State: st, Category: string(cat), Checked: true}
}

// startLivenessLocked starts the loop that re-proves the connected
// route. Called with Core.mu held, after a successful connect.
func (c *Core) startLivenessLocked() {
	ctx, cancel := context.WithCancel(context.Background())
	kick := make(chan struct{}, 1)
	c.check.mu.Lock()
	if c.check.cancelLive != nil {
		c.check.cancelLive()
	}
	c.check.cancelLive, c.check.kick = cancel, kick
	c.check.mu.Unlock()
	cfg := c.proofCfg
	go func() {
		for {
			wait := cfg.LivenessInterval
			if st, _ := c.check.get(); st == RouteCheckFailed {
				wait = cfg.RecheckInterval
			}
			t := time.NewTimer(jittered(wait, cfg.LivenessJitter))
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-kick:
				t.Stop()
			case <-t.C:
			}
			c.checkActiveRoute(ctx)
			if ctx.Err() != nil {
				return
			}
		}
	}()
}

// jittered spreads d by ±frac so the check is not a metronome an
// observer of the relay's traffic could key on.
func jittered(d time.Duration, frac float64) time.Duration {
	if d <= 0 || frac <= 0 {
		return d
	}
	return time.Duration(float64(d) * (1 - frac + 2*frac*rand.Float64()))
}

// kickLiveness asks the liveness loop to check now. The platform's
// network-change signal calls it: a route that worked on Wi-Fi says
// nothing about the cellular network the phone just moved to.
func (c *Core) kickLiveness() {
	c.check.mu.Lock()
	kick := c.check.kick
	live := c.check.cancelLive != nil
	c.check.mu.Unlock()
	if !live || kick == nil {
		return
	}
	select {
	case kick <- struct{}{}:
	default:
	}
}

// proofFailureText is the raw account of a failed proof for the
// in-process event stream and the error SetRoute returns: each failed
// attempt's phase and error. It can carry addresses and is never
// stored — the route store gets the category only.
func proofFailureText(res engine.ProofResult) string {
	if len(res.Failed) == 0 {
		if res.Err != nil {
			return res.Err.Error()
		}
		return ""
	}
	out := ""
	for i, o := range res.Failed {
		if i > 0 {
			out += " | "
		}
		ph := string(o.Phase)
		if ph == "" {
			ph = "?"
		}
		out += fmt.Sprintf("attempt %d (%s): %s", i+1, ph, o.Message)
	}
	return out
}
