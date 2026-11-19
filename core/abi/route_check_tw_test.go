package abi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"daal/core/diagnostics"
	"daal/core/engine"
	"daal/core/pathmanager"
	"daal/core/routestore"
)

// Backlog items TW-7, TW-10, TW-14 and "old routes are refused with no
// explanation", as far as the ABI decides them.

func slowFailedProof() engine.ProofResult {
	res := failedProof(context.DeadlineExceeded, diagnostics.PhaseHandshake, false, true)
	res.Observation.Progress = true
	res.Failed[0].Progress = true
	res.Extended = true
	return res
}

// TW-10: a path that was seen moving and finished nothing is not a
// failure OF THE ROUTE. The connect fails (nothing is running), and the
// route is not cooled down, not given a failure row, and produces no
// network signal — the person can try again at once.
func TestSetRoute_SlowPathFailureIsNotCooledDown(t *testing.T) {
	c, stub := checkInit(t, "r-st")
	stub.InjectProof(slowFailedProof())
	err := SetRoute("r-st")
	if !errors.Is(err, ErrRouteNotCarrying) {
		t.Fatalf("SetRoute = %v; nothing was carried, so the connect must fail", err)
	}
	if got := diagField(t, "route_check_category"); got != "path_too_slow" {
		t.Fatalf("route_check_category = %v, want path_too_slow", got)
	}
	if diagField(t, "route_check") != RouteCheckFailed || diagField(t, "route_running") != false {
		t.Fatal("a failed connect must read failed / not running")
	}
	row, _ := c.store.GetRoute("r-st")
	if row.LastFailureCategory != "" || row.ConsecutiveFailures != 0 || row.CooldownUntil != "" {
		t.Fatalf("a slow path was filed as a route failure: %+v", row)
	}
	if row.LastSuccessBucket != "" {
		t.Fatal("a connect that carried nothing was filed as a success")
	}
	if sig := activeNetworkSignals(c, nowUTC()); len(sig) != 0 {
		t.Fatalf("a slow path produced network signals %v", sig)
	}
	if ok, why := c.pm.CanAttempt("r-st", "vless-reality"); !ok {
		t.Fatalf("the route is cooling down after a slow connect: %s", why)
	}
	// And the very next tap connects.
	if err := SetRoute("r-st"); err != nil {
		t.Fatalf("second connect right after a slow one: %v", err)
	}
}

// The same timeout WITHOUT anything seen moving is what it always was.
func TestSetRoute_SilentTimeoutStillCoolsDown(t *testing.T) {
	c, stub := checkInit(t, "r-st")
	stub.InjectProof(failedProof(context.DeadlineExceeded, diagnostics.PhaseHandshake, false, true))
	if err := SetRoute("r-st"); err == nil {
		t.Fatal("SetRoute succeeded")
	}
	row, _ := c.store.GetRoute("r-st")
	if row.LastFailureCategory != "tls_handshake_failed" || row.CooldownUntil == "" {
		t.Fatalf("got %+v", row)
	}
}

// TW-14: a relay that answers and reaches nothing is reported as that,
// and is not held against the route (no cooldown; three relays' worth of
// it must not cool a whole family down either).
func TestSetRoute_RelayNoEgressIsReportedAndNotCooledDown(t *testing.T) {
	c, stub := checkInit(t, "r-st")
	for i := 0; i < 4; i++ {
		res := failedProof(context.DeadlineExceeded, diagnostics.PhaseCarry, false, true)
		res.Observation.RelayNoEgress = true
		stub.InjectProof(res)
		if err := SetRoute("r-st"); !errors.Is(err, ErrRouteNotCarrying) || !strings.Contains(err.Error(), "relay_no_egress") {
			t.Fatalf("attempt %d: SetRoute = %v", i, err)
		}
	}
	if got := diagField(t, "route_check_category"); got != "relay_no_egress" {
		t.Fatalf("route_check_category = %v", got)
	}
	row, _ := c.store.GetRoute("r-st")
	if row.LastFailureCategory != "relay_no_egress" || row.CooldownUntil != "" {
		t.Fatalf("got %+v; want the category recorded and no cooldown", row)
	}
	if ok, why := c.pm.CanAttempt("r-st", "vless-reality"); !ok {
		t.Fatalf("route or family cooled down for the relay's own outage: %s", why)
	}
}

// TW-7: the error a failed connect leaves behind clears when the
// cooldown it started has run out — it used to stay until the person
// picked a route or disconnected.
func TestFailedConnectErrorClearsWhenTheCooldownEnds(t *testing.T) {
	c, stub := checkInit(t, "r-st")
	now := time.Now()
	c.pm.SetNow(func() time.Time { return now })
	stub.InjectProof(failedProof(errSYNTimeout, diagnostics.PhaseHandshake, false, true))
	if err := SetRoute("r-st"); err == nil {
		t.Fatal("SetRoute succeeded")
	}
	if diagField(t, "route_check") != RouteCheckFailed {
		t.Fatal("premise: the failed connect is shown")
	}
	// Still cooling down: still shown.
	c.pm.SetNow(func() time.Time { return now.Add(4 * time.Minute) })
	if diagField(t, "route_check") != RouteCheckFailed || diagField(t, "posture") != string(pathmanager.PostureRecovery) {
		t.Fatal("the error went away while the route was still cooling down")
	}
	// The cooldown (5 min for tcp_connect_timeout) is over.
	c.pm.SetNow(func() time.Time { return now.Add(5*time.Minute + time.Second) })
	if got := diagField(t, "route_check"); got != RouteCheckNone {
		t.Fatalf("route_check = %q after the cooldown ended; the stale error is still shown", got)
	}
	if got := diagField(t, "posture"); got != string(pathmanager.PostureNoRoute) {
		t.Fatalf("posture = %v after the error cleared; Recovery would read as \"Connecting…\" with nothing running", got)
	}
	// The record of the failure is history, not erased.
	row, _ := c.store.GetRoute("r-st")
	if row.LastFailureCategory != "tcp_connect_timeout" {
		t.Fatalf("the failure row was touched: %+v", row)
	}
	if err := SetRoute("r-st"); err != nil {
		t.Fatalf("connect after the cooldown: %v", err)
	}
}

// A LOST connection (instance running, being re-checked) is not a failed
// connect and is never cleared by time.
func TestLostConnectionIsNotClearedByTime(t *testing.T) {
	c, stub := checkInit(t, "r-st")
	c.proofCfg.LivenessInterval, c.proofCfg.RecheckInterval = time.Hour, time.Hour
	now := time.Now()
	c.pm.SetNow(func() time.Time { return now })
	if err := SetRoute("r-st"); err != nil {
		t.Fatal(err)
	}
	stub.SetProofHook(func(context.Context, engine.ProofConfig) engine.ProofResult {
		return failedProof(errSYNTimeout, diagnostics.PhaseHandshake, false, true)
	})
	c.checkActiveRoute(context.Background())
	c.pm.SetNow(func() time.Time { return now.Add(time.Hour) })
	if diagField(t, "route_check") != RouteCheckFailed || diagField(t, "route_running") != true {
		t.Fatal("a lost connection that is still being retried stopped being reported")
	}
}

// A failure with no cooldown has nothing that ends: it stays until the
// person acts.
func TestFailedConnectWithNoCooldownStays(t *testing.T) {
	c, stub := checkInit(t, "r-st")
	now := time.Now()
	c.pm.SetNow(func() time.Time { return now })
	stub.InjectProof(failedProof(errors.New("authentication failed"), diagnostics.PhaseHandshake, false, true))
	if err := SetRoute("r-st"); err == nil {
		t.Fatal("SetRoute succeeded")
	}
	c.pm.SetNow(func() time.Time { return now.Add(24 * time.Hour) })
	if diagField(t, "route_check") != RouteCheckFailed {
		t.Fatal("an auth failure was cleared by the clock")
	}
}

// A route imported from a pack made before packs carried signed
// endpoints is refused at connect. On Android nobody sees the returned
// error, so the reason must be in the diagnostics blob as a closed code.
func TestConnectRefused_OldFileSaysSo(t *testing.T) {
	c, stub := checkInit(t, "r-st")
	if got := diagField(t, "connect_refused"); got != ConnectRefusedNone {
		t.Fatalf("connect_refused = %q before any connect", got)
	}
	old, _ := c.store.GetRoute("r-st")
	old.RouteID, old.RelayPackID = "r-old", "rp-before-endpoints"
	if err := c.store.UpsertRoute(old); err != nil {
		t.Fatal(err)
	}
	prof, _ := c.store.GetSecret("route:r-st")
	if err := c.store.PutSecret("route:r-old", prof); err != nil {
		t.Fatal(err)
	}
	if row, _ := c.store.GetRoute("r-old"); row.RelayPackID == "" {
		t.Skip("the route store did not keep RelayPackID on this path")
	}
	stub.SetProofHook(func(context.Context, engine.ProofConfig) engine.ProofResult {
		t.Error("a connection check ran for a refused route")
		return engine.ProofResult{OK: true}
	})
	err := SetRoute("r-old")
	if !errors.Is(err, ErrRouteNeedsNewFile) || !errors.Is(err, ErrRouteEndpoint) {
		t.Fatalf("SetRoute = %v; want the endpoint refusal, marked as needing a new file", err)
	}
	if got := diagField(t, "connect_refused"); got != ConnectRefusedNeedsNewFile {
		t.Fatalf("connect_refused = %q, want needs_new_file", got)
	}
	if got := diagField(t, "connect_refused_route"); got != "r-old" {
		t.Fatalf("connect_refused_route = %q", got)
	}
	// A connect that is not refused clears it; so does disconnect.
	stub.SetProofHook(nil)
	if err := SetRoute("r-st"); err != nil {
		t.Fatal(err)
	}
	if got := diagField(t, "connect_refused"); got != ConnectRefusedNone {
		t.Fatalf("connect_refused = %q after a connect that went ahead", got)
	}
	_ = SetRoute("r-old")
	if err := ClearRoute(); err != nil {
		t.Fatal(err)
	}
	if got := diagField(t, "connect_refused"); got != ConnectRefusedNone {
		t.Fatalf("connect_refused = %q after disconnect", got)
	}
}

// The other refusals have codes too, and a mismatch (not an old file) is
// never told "ask for a new file".
func TestConnectRefused_Codes(t *testing.T) {
	c, stub := checkInit(t, "r-st")
	stub.InjectProof(failedProof(errSYNTimeout, diagnostics.PhaseHandshake, false, true))
	_ = SetRoute("r-st")
	if err := SetRoute("r-st"); err == nil {
		t.Fatal("a cooling route was attempted")
	}
	if got := diagField(t, "connect_refused"); got != ConnectRefusedCooldown {
		t.Fatalf("connect_refused = %q, want cooldown", got)
	}
	if err := SetRoute("no-such-route"); err == nil {
		t.Fatal("unknown route accepted")
	}
	if got := diagField(t, "connect_refused"); got != ConnectRefusedOther {
		t.Fatalf("connect_refused = %q, want other", got)
	}
	row, _ := c.store.GetRoute("r-st")
	row.RouteID, row.TrustState = "r-rev", "revoked"
	_ = c.store.UpsertRoute(row)
	if err := SetRoute("r-rev"); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("revoked route: %v", err)
	}
	if got := diagField(t, "connect_refused"); got != ConnectRefusedRevoked {
		t.Fatalf("connect_refused = %q, want revoked", got)
	}
	if got := refusedCode(ErrRouteEndpoint); got != ConnectRefusedOther {
		t.Fatalf("an endpoint MISMATCH maps to %q; only a missing endpoint is an old file", got)
	}
	_ = routestore.RouteRow{}
}

func TestEngineConfigFile_SlowBudget(t *testing.T) {
	dir := t.TempDir()
	cfg, err := loadProofConfig(dir)
	if err != nil || cfg.SlowBudget != engine.DefaultProofConfig().SlowBudget || cfg.SlowBudget < 10*time.Second {
		t.Fatalf("default slow budget: %v %v", cfg.SlowBudget, err)
	}
	if err := os.WriteFile(filepath.Join(dir, EngineConfigFile), []byte(`{"connection_check":{"slow_budget_ms":7000}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if cfg, err = loadProofConfig(dir); err != nil || cfg.SlowBudget != 7*time.Second {
		t.Fatalf("slow_budget_ms not taken: %v %v", cfg.SlowBudget, err)
	}
	_ = os.WriteFile(filepath.Join(dir, EngineConfigFile), []byte(`{"connection_check":{"slow_budget_ms":-1}}`), 0o600)
	if _, err = loadProofConfig(dir); err == nil {
		t.Fatal("a negative slow budget was accepted")
	}
}

// The Android VPN service calls ClearRoute as part of tearing itself
// down after EVERY connect that did not come up (failed start → stopSelf
// → onDestroy → teardown). The connect command resolved long before, so
// the diagnostics blob is the only place the page can read why — and a
// ClearRoute that stopped nothing used to wipe it: every failed or
// refused connect on a phone ended on "Press to connect." with no
// reason. A ClearRoute that finds nothing running and nothing being
// checked must leave the verdict of the last connect where it is.
func TestClearRoute_KeepsTheVerdictOfAConnectThatAlreadyFailed(t *testing.T) {
	c, stub := checkInit(t, "r-st")
	now := time.Now()
	c.pm.SetNow(func() time.Time { return now })
	stub.InjectProof(failedProof(errSYNTimeout, diagnostics.PhaseHandshake, false, true))
	if err := SetRoute("r-st"); !errors.Is(err, ErrRouteNotCarrying) {
		t.Fatalf("SetRoute = %v", err)
	}
	// The service's sequence: once in start(), once more in teardown.
	for i := 0; i < 2; i++ {
		if err := ClearRoute(); err != nil {
			t.Fatal(err)
		}
	}
	if got := diagField(t, "route_check"); got != RouteCheckFailed {
		t.Fatalf("route_check = %q after the service's teardown; the page is told nothing", got)
	}
	if got := diagField(t, "route_check_category"); got != "tcp_connect_timeout" {
		t.Fatalf("route_check_category = %v", got)
	}
	if diagField(t, "route_running") != false {
		t.Fatal("route_running must stay false: nothing is running")
	}
	if got := diagField(t, "posture"); got != string(pathmanager.PostureRecovery) {
		t.Fatalf("posture = %v", got)
	}
	// The retry is refused for the cooldown; the teardown that follows
	// must not erase that either.
	if err := SetRoute("r-st"); err == nil {
		t.Fatal("a cooling route was attempted")
	}
	if err := ClearRoute(); err != nil {
		t.Fatal(err)
	}
	if got := diagField(t, "connect_refused"); got != ConnectRefusedCooldown {
		t.Fatalf("connect_refused = %q after the service's teardown, want cooldown", got)
	}
	if got := diagField(t, "connect_refused_route"); got != "r-st" {
		t.Fatalf("connect_refused_route = %q", got)
	}
	// Kept, not frozen: the error still ends with the cooldown...
	c.pm.SetNow(func() time.Time { return now.Add(5*time.Minute + time.Second) })
	if got := diagField(t, "route_check"); got != RouteCheckNone {
		t.Fatalf("route_check = %q after the cooldown ended", got)
	}
	if got := diagField(t, "posture"); got != string(pathmanager.PostureNoRoute) {
		t.Fatalf("posture = %v after the cooldown ended", got)
	}
	// ...and the next connect that goes ahead clears the refusal.
	if err := SetRoute("r-st"); err != nil {
		t.Fatal(err)
	}
	if got := diagField(t, "connect_refused"); got != ConnectRefusedNone {
		t.Fatalf("connect_refused = %q after a connect that went ahead", got)
	}
}

// A refusal with nothing running at all (the old-file case on a phone:
// state "", then the service's teardown).
func TestClearRoute_KeepsARefusalWhenNothingWasRunning(t *testing.T) {
	checkInit(t, "r-st")
	if err := SetRoute("no-such-route"); err == nil {
		t.Fatal("unknown route accepted")
	}
	if err := ClearRoute(); err != nil {
		t.Fatal(err)
	}
	if got := diagField(t, "connect_refused"); got != ConnectRefusedOther {
		t.Fatalf("connect_refused = %q after a ClearRoute that stopped nothing", got)
	}
}

// What ClearRoute STOPS, it still clears: a connected route, a lost one
// that is being re-checked, and a check in flight.
func TestClearRoute_StillClearsWhatItStops(t *testing.T) {
	c, stub := checkInit(t, "r-st")
	// Connected, then a refused connect on top of it, then disconnect.
	if err := SetRoute("r-st"); err != nil {
		t.Fatal(err)
	}
	_ = SetRoute("no-such-route")
	if err := ClearRoute(); err != nil {
		t.Fatal(err)
	}
	if diagField(t, "route_check") != RouteCheckNone || diagField(t, "connect_refused") != ConnectRefusedNone {
		t.Fatal("disconnecting a connected route left a verdict behind")
	}
	// A lost connection (failed, instance running), then disconnect.
	if err := SetRoute("r-st"); err != nil {
		t.Fatal(err)
	}
	stub.InjectProof(failedProof(errSYNTimeout, diagnostics.PhaseHandshake, false, true))
	CheckActiveRoute()
	if diagField(t, "route_check") != RouteCheckFailed || diagField(t, "route_running") != true {
		t.Fatal("premise: a lost connection reads failed / running")
	}
	if err := ClearRoute(); err != nil {
		t.Fatal(err)
	}
	if got := diagField(t, "route_check"); got != RouteCheckNone {
		t.Fatalf("route_check = %q after disconnecting a lost connection", got)
	}
	if got := diagField(t, "posture"); got != string(pathmanager.PostureNoRoute) {
		t.Fatalf("posture = %v after disconnect", got)
	}
	_ = c
}
