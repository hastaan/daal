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
	// failedRoute / failedFamily / failedCooled describe the route a
	// FAILED CONNECT was about (state failed, running false): which
	// route, and whether the failure put it in a cooldown. When that
	// cooldown has run out the error has nothing left to say and is
	// cleared (expireFailedConnect).
	failedRoute, failedFamily string
	failedCooled              bool
	// refused / refusedRoute: the last SetRoute that was REFUSED before
	// anything was tried, as a closed code (ConnectRefused*). Cleared by
	// the next SetRoute that gets past its refusals and by a ClearRoute
	// that stops something. One that finds nothing running keeps it.
	refused, refusedRoute string
	// switchBack: the last manual switch went to a route that carried
	// nothing and the engine went back to the route that was connected
	// (SetRoute). Cleared by the next SetRoute that gets past its
	// refusals, by an automatic connect and by a disconnect.
	switchBack SwitchBack
}

// SwitchBack is `switch_back` in the diagnostics blob: what became of
// the last switch to a route that turned out to carry nothing.
// FailedRoute "" means there is nothing to report.
type SwitchBack struct {
	// FailedRoute / FailedFamily / Category: the route the person
	// switched to, and the category it failed with.
	FailedRoute  string `json:"failed_route"`
	FailedFamily string `json:"failed_family"`
	Category     string `json:"category"`
	// RestoredRoute is the route that was connected before the switch;
	// Restored says whether it carried again when the engine went back
	// to it. false: it did not, and nothing is connected.
	RestoredRoute string `json:"restored_route"`
	Restored      bool   `json:"restored"`
}

func (rc *routeCheck) setSwitchBack(sb SwitchBack) {
	rc.mu.Lock()
	rc.switchBack = sb
	rc.mu.Unlock()
}

func (rc *routeCheck) getSwitchBack() SwitchBack {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.switchBack
}

// Why a SetRoute was refused before anything was started. A closed
// vocabulary: `connect_refused` in the diagnostics blob. On Android the
// error SetRoute returns never reaches the app (the VpnService calls it
// on a worker thread long after the connect command has resolved), so
// this field is the only way the person learns why nothing happened.
const (
	ConnectRefusedNone = ""
	// The route was imported from a pack made before packs carried
	// signed endpoints. Only a new file fixes it.
	ConnectRefusedNeedsNewFile = "needs_new_file"
	// The route is cooling down after a failure.
	ConnectRefusedCooldown = "cooldown"
	// The route's publisher revoked it, or it expired.
	ConnectRefusedRevoked = "revoked"
	ConnectRefusedExpired = "expired"
	// Anything else (unknown route, unreadable profile, an outbound
	// that does not match what was signed).
	ConnectRefusedOther = "other"
)

func (rc *routeCheck) setRefused(code, routeID string) {
	rc.mu.Lock()
	rc.refused, rc.refusedRoute = code, routeID
	rc.mu.Unlock()
}

func (rc *routeCheck) refusal() (code, routeID string) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.refused, rc.refusedRoute
}

// refusedCode maps the error of a refused SetRoute onto the vocabulary.
func refusedCode(err error) string {
	switch {
	case errors.Is(err, ErrRouteNeedsNewFile):
		return ConnectRefusedNeedsNewFile
	case errors.Is(err, errRouteCooling):
		return ConnectRefusedCooldown
	case errors.Is(err, errRouteRevoked):
		return ConnectRefusedRevoked
	case errors.Is(err, errRouteExpired):
		return ConnectRefusedExpired
	}
	return ConnectRefusedOther
}

// routeRefusal is the error of a SetRoute that was refused before
// anything was started. It reads and unwraps exactly as the error it
// carries; the code rides along so a log line can name the refusal
// without quoting the error text.
type routeRefusal struct {
	code string
	err  error
}

func (e *routeRefusal) Error() string { return e.err.Error() }
func (e *routeRefusal) Unwrap() error { return e.err }

// routeFailure is the error of a SetRoute whose route started and then
// failed its connection proof. It wraps ErrRouteNotCarrying; reason is
// the raw account of the proof and can carry addresses — it is in
// Error() for the in-process caller and is never logged.
type routeFailure struct {
	routeID  string
	category diagnostics.Category
	reason   string
}

func (e *routeFailure) Error() string {
	return fmt.Sprintf("%v (route %s: %s): %s", ErrRouteNotCarrying, e.routeID, e.category, e.reason)
}
func (e *routeFailure) Unwrap() error { return ErrRouteNotCarrying }

// prepareRouteLocked is everything SetRoute checks before it starts
// anything: the route exists, is not revoked or expired, is not cooling
// down, has a readable profile that still points where its publisher
// signed, and builds into a config. On success it returns the row and
// the config. On refusal it records the reason (connect_refused /
// connect_refused_route) and returns a *routeRefusal; nothing else
// changes — the route that was connected stays connected.
//
// Called with mu held. RouteConnectPrecheck runs the same function, so
// "would this be refused" and "this was refused" cannot drift apart.
func (c *Core) prepareRouteLocked(routeID string) (routestore.RouteRow, []byte, error) {
	return c.prepareRouteOpts(routeID, true, false)
}

// prepareRouteOpts is prepareRouteLocked with the two things the
// automatic connect needs to vary (connect_auto.go):
//
//   - record=false leaves connect_refused alone. The automatic connect
//     asks about every route the person holds; "refused: cooldown" for
//     a route nobody picked is not something to tell them.
//   - ignoreCooldown=true skips the cooldown check and nothing else.
//     Only for putting BACK the instance of a route that was connected
//     and stopped carrying, after everything else was tried: that is
//     not a new attempt at the route, it is the instance that was
//     already running. Revocation, expiry and the endpoint guard are
//     never skipped.
func (c *Core) prepareRouteOpts(routeID string, record, ignoreCooldown bool) (routestore.RouteRow, []byte, error) {
	refuse := func(err error) (routestore.RouteRow, []byte, error) {
		code := refusedCode(err)
		if record {
			c.check.setRefused(code, routeID)
		}
		return routestore.RouteRow{}, nil, &routeRefusal{code: code, err: err}
	}
	row, err := c.store.GetRoute(routeID)
	if err != nil {
		return refuse(fmt.Errorf("abi: route %s not found: %w", routeID, err))
	}
	switch row.TrustState {
	case "revoked":
		return refuse(fmt.Errorf("abi: route %s is %s and cannot be activated%.0w", routeID, row.TrustState, errRouteRevoked))
	case "expired":
		return refuse(fmt.Errorf("abi: route %s is %s and cannot be activated%.0w", routeID, row.TrustState, errRouteExpired))
	}
	if ok, reason := c.pm.CanAttempt(routeID, row.TransportFamily); !ok && !ignoreCooldown {
		return refuse(fmt.Errorf("abi: %s%.0w", reason, errRouteCooling))
	}
	profile, err := c.store.GetSecret("route:" + routeID)
	if err != nil {
		return refuse(fmt.Errorf("abi: load profile for %s: %w", routeID, err))
	}
	// Defence in depth behind the importer (endpoint_guard.go): the
	// outbound about to be dialled must still point where its publisher
	// signed. Refused BEFORE pm.Attempt, so a refusal is never filed as
	// a network failure of the route.
	if err := routeEndpointGuard(c.store, row, profile); err != nil {
		return refuse(err)
	}
	cfg, err := engine.BuildSingBoxConfig(row, profile)
	if err != nil {
		return refuse(err)
	}
	body, err := engine.MarshalSingBox(cfg)
	if err != nil {
		return refuse(err)
	}
	return row, body, nil
}

// logRouteRefused writes the one line a refused connect leaves in the
// log: which route, the closed refusal code, and what stays running.
func logRouteRefused(routeID string, err error, active string) {
	code := ConnectRefusedOther
	var rr *routeRefusal
	if errors.As(err, &rr) {
		code = rr.code
	}
	staying := "-"
	if active != "" {
		staying = engine.LogID(active)
	}
	engine.LogInfo(fmt.Sprintf("route refused route=%s code=%s still_running=%s", engine.LogID(routeID), code, staying))
}

// RouteConnectPrecheck is engine_route_precheck: would engine_set_route
// for this route be refused right now? It runs exactly the checks
// SetRoute runs before it starts anything, and starts nothing.
//
// It exists for a host that has to do something irreversible BEFORE it
// can call engine_set_route — on Android, replacing the running route's
// TUN. Asked first, a host can leave the working tunnel alone when the
// new route would be refused anyway.
//
// A refusal is RECORDED exactly as a refused SetRoute records it
// (connect_refused / connect_refused_route in the diagnostics blob), so
// a host that stops there has already told the page why. A route that
// would not be refused changes nothing at all. The answer can go stale
// (a cooldown can start between this call and the SetRoute), so
// SetRoute still checks for itself.
//
// Returns {"route_id", "refused": "" | code, "active_route"}; the codes
// are the connect_refused vocabulary plus "no_data_plane" for a build
// that cannot tunnel (which is not recorded). The error is non-nil only
// when the engine is not initialised.
func RouteConnectPrecheck(routeID string) (string, error) {
	c := loadedCore()
	if c == nil {
		return "", errors.New("abi: not initialized")
	}
	refused := ConnectRefusedNone
	if !dataPlaneLinked {
		refused = "no_data_plane"
	}
	c.mu.Lock()
	active := c.activeRoute
	var perr error
	if refused == ConnectRefusedNone {
		_, _, perr = c.prepareRouteLocked(routeID)
	}
	c.mu.Unlock()
	if perr != nil {
		refused = ConnectRefusedOther
		var rr *routeRefusal
		if errors.As(perr, &rr) {
			refused = rr.code
		}
		logRouteRefused(routeID, perr, active)
	}
	body, _ := json.Marshal(map[string]any{
		"route_id":     routeID,
		"refused":      refused,
		"active_route": active,
	})
	return string(body), nil
}

var (
	errRouteCooling = errors.New("abi: route is cooling down")
	errRouteRevoked = errors.New("abi: route is revoked")
	errRouteExpired = errors.New("abi: route is expired")
)

// expireFailedConnect clears the error a failed connect left behind
// once the cooldown that failure started has run out.
//
// After a failed connect nothing is running and nothing retries: the
// state is `failed`, the posture Recovery, and the app says "Could not
// connect on this route". That is true for as long as the route is
// cooling down — and then it is just an old error on a route that may
// be tried again, which the app kept showing until the person picked a
// route (the end-to-end rig's CEN-5 remainder). A
// failure with NO cooldown (wrong credentials, a path that is only
// slow, a relay with no way out) is left alone: nothing about it
// changes with time.
//
// Called from the read paths, so no timer has to outlive a route. It
// never waits for Core.mu: a poll that arrives mid-SetRoute simply
// looks again next time.
func (c *Core) expireFailedConnect() {
	st, _, running := c.check.snapshot()
	if st != RouteCheckFailed || running {
		return
	}
	if !c.mu.TryLock() {
		return
	}
	defer c.mu.Unlock()
	c.check.mu.Lock()
	route, family, cooled := c.check.failedRoute, c.check.failedFamily, c.check.failedCooled
	stillFailed := c.check.state == RouteCheckFailed && !c.check.running
	c.check.mu.Unlock()
	if !stillFailed || !cooled || route == "" {
		return
	}
	if ok, _ := c.pm.CanAttempt(route, family); !ok {
		return
	}
	c.check.set(RouteCheckNone, "")
	c.advancePosture(pathmanager.EventDisconnected, pathmanager.PostureNoRoute)
	// The automatic connect's verdict was about the same pass.
	c.auto.expireFailed()
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
	rc.failedRoute, rc.failedFamily, rc.failedCooled = "", "", false
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
		SlowBudgetMs      int      `json:"slow_budget_ms"`
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
		if cc.AttemptTimeoutMs < 0 || cc.Attempts < 0 || cc.SlowAfterMs < 0 || cc.SlowBudgetMs < 0 || cc.LivenessIntervalS < 0 || cc.RecheckIntervalS < 0 {
			return cfg, fmt.Errorf("abi: %s: connection_check values must not be negative", EngineConfigFile)
		}
		cfg.Targets = cc.Targets
		cfg.AttemptTimeout = time.Duration(cc.AttemptTimeoutMs) * time.Millisecond
		cfg.Attempts = cc.Attempts
		cfg.SlowAfter = time.Duration(cc.SlowAfterMs) * time.Millisecond
		cfg.SlowBudget = time.Duration(cc.SlowBudgetMs) * time.Millisecond
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
	// One line per CHANGE of state, not one per liveness check.
	if prev, _ := c.check.get(); (prev != RouteCheckOK && !res.Slow) || (prev != RouteCheckDegraded && res.Slow) {
		result := RouteCheckOK
		if res.Slow {
			result = RouteCheckDegraded
		}
		engine.LogInfo(fmt.Sprintf("route up route=%s family=%s result=%s", engine.LogID(routeID), engine.LogID(family), result))
	}
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
	c.routeDownOptsLocked(routeID, family, cat, reason, teardown, false)
}

// routeDownOptsLocked is routeDownLocked with one thing varied.
//
// candidate: the route failed as one candidate of an automatic pass.
// Its cooldown is the same; it does not feed the family's
// three-in-an-hour count (pathmanager.FailedCandidate), and its durable
// failure row and this network's memory of it are NOT written here —
// the pass writes them, or forgives the failure altogether, when it
// knows whether anything at all answered (autoSettleLocked).
func (c *Core) routeDownOptsLocked(routeID, family string, cat diagnostics.Category, reason string, teardown, candidate bool) {
	c.driver.PublishFailure(cat, reason)
	if teardown {
		_ = c.driver.Stop()
		// No tunnel, so bootstrap/refresh may dial direct.
		refresh.SetTunnelRequired(false)
		c.setActiveLocked("", "")
	}
	engine.LogInfo(fmt.Sprintf("route down route=%s family=%s result=failed category=%s running=%t",
		engine.LogID(routeID), engine.LogID(family), engine.LogID(string(cat)), !teardown))
	c.pm.Resume(routeID, family)
	if candidate {
		c.pm.FailedCandidate(routeID, family, cat)
	} else {
		c.pm.Failed(routeID, family, cat)
	}
	until := pmCooldownUntil(c, routeID)
	if cat == diagnostics.PathTooSlow {
		// Nothing completed on a path that was seen moving. That is not
		// a failure OF THE ROUTE (specs/failure-taxonomy-v1.md:
		// path_too_slow is never a failure row, never a cooldown, never
		// a network signal) — and it is not a success either, so the
		// route's durable record is left exactly as it was.
		until = time.Time{}
	} else if !candidate {
		// Persist the outcome the FSM just computed (privacy shape: hour
		// bucket + closed category vocabulary, one row per route — see
		// routestore.RecordFailure).
		_ = c.store.RecordFailure(routeID, string(cat), until, nowUTC())
	}
	c.advancePosture(pathmanager.EventActiveFailed, pathmanager.PostureRecovery)
	c.check.setFailed(cat, !teardown)
	if teardown {
		c.check.mu.Lock()
		c.check.failedRoute, c.check.failedFamily = routeID, family
		c.check.failedCooled = !until.IsZero()
		c.check.mu.Unlock()
	}
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
// call; it never selects or switches a route. (The liveness LOOP does,
// after this returns "failed", when the automatic connect is in charge:
// startLivenessLocked, autoFallOver.)
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
		if prev == RouteCheckFailed {
			// Back after an outage: worth remembering for this network,
			// and the automatic connect is connected again.
			c.rememberRoute(routeID, true, "")
			c.auto.recovered(routeID, family)
			c.auto.fallPasses, c.auto.nextFallAt = 0, time.Time{}
		}
	case prev == RouteCheckFailed && (autoFallsOverFor(prevCat) || !autoFallsOverFor(res.Category())):
		// Still down. Keep the first classification of this outage.
		return CheckResult{RouteID: routeID, State: prev, Category: string(prevCat), Checked: true}
	default:
		// A new failure — or one that has changed in kind: a route that
		// was only slow (or whose relay had no way out, or whose device
		// had no network) and now gets no answer at all is a different
		// outage, and the one the automatic connect moves away from.
		c.routeDownLocked(routeID, family, res.Category(), proofFailureText(res), false)
		c.rememberRoute(routeID, false, res.Category())
	}
	st, cat := c.check.get()
	return CheckResult{RouteID: routeID, State: st, Category: string(cat), Checked: true}
}

// autoConfirmAfter is how soon a connected route that has just failed a
// check is checked AGAIN before the automatic connect moves away from
// it (never longer than RecheckInterval). One failed check is one lost
// round trip: right after a network change it is usually the new
// network not being usable yet, and moving on it would restart the
// instance under every open connection and mark the other routes as
// failing on a network nothing has been tried on.
const autoConfirmAfter = 5 * time.Second

// autoFallsOverFor: is a liveness failure of this category a reason to
// try the other routes? Not when the instance may still be carrying
// (path_too_slow: the path was seen moving; relay_no_egress: the relay
// answered, and what it could not reach was the check's own targets) and
// not when the device itself says there is no network — no other route
// would fare better, and replacing the instance resets every connection
// the person has open.
func autoFallsOverFor(cat diagnostics.Category) bool {
	switch cat {
	case diagnostics.PathTooSlow, diagnostics.RelayNoEgress, diagnostics.NetworkOffline:
		return false
	}
	return true
}

// startLivenessLocked starts the loop that re-proves the connected
// route. Called with Core.mu held, after a successful connect.
//
// WHAT MOVES THE AUTOMATIC CONNECT. This loop, and nothing else: no host
// call. It checks the route every LivenessInterval (and at once on
// engine_network_changed: kickLiveness). When a check fails with a
// category that autoFallsOverFor, and the automatic connect is in
// charge, it checks once more after autoConfirmAfter; a second failure
// in a row calls autoFallOver, which tries the other routes. After a
// pass in which nothing else carried the route's own instance is back,
// re-checked every RecheckInterval, and the next pass the engine starts
// by itself waits out a back-off that doubles per pass of the outage
// (autoFallBackoff).
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
		// failedInARow: consecutive failed checks seen by THIS loop.
		failedInARow := 0
		for {
			wait := cfg.LivenessInterval
			if st, cat := c.check.get(); st == RouteCheckFailed {
				wait = cfg.RecheckInterval
				if _, mode := c.auto.snapshot(); mode && failedInARow == 1 && autoFallsOverFor(cat) && autoConfirmAfter < wait {
					wait = autoConfirmAfter
				}
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
			res := c.checkActiveRoute(ctx)
			if ctx.Err() != nil {
				return
			}
			if !res.Checked {
				continue
			}
			if res.State != RouteCheckFailed {
				failedInARow = 0
				continue
			}
			failedInARow++
			// The automatic connect: a route that has stopped carrying
			// is not waited for while another may work — once a second
			// check in a row has said so. A pass that starts anything
			// replaces this loop (its context is cancelled by the
			// start); one that finds nothing to try leaves it running,
			// and the route is checked again.
			if failedInARow >= 2 {
				c.autoFallOver(ctx)
				if ctx.Err() != nil {
					return
				}
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
