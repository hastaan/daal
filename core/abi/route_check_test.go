package abi

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"daal/core/diagnostics"
	"daal/core/engine"
	"daal/core/pathmanager"
	"daal/core/refresh"
)

// The connection check (route_check.go). Until it existed SetRoute took
// "the engine instance started" for "the route works": a route to a
// null-routed relay came out Connected, was recorded as a success and
// listed `proven: true`, `health_pct: 100` (the end-to-end rig's finding
// CEN-1). Every test here drives the Stub driver's Prove.

func checkInit(t *testing.T, routeID string) (*Core, *engine.Stub) {
	t.Helper()
	if err := Init(t.TempDir(), "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Shutdown() })
	c := mustCore()
	seedStableRoute(t, c, routeID)
	stub, ok := c.driver.(*engine.Stub)
	if !ok {
		t.Skipf("driver is %T, not the stub", c.driver)
	}
	return c, stub
}

func diagField(t *testing.T, key string) any {
	t.Helper()
	body, err := ExportDiagnostics()
	if err != nil {
		t.Fatal(err)
	}
	var blob map[string]any
	if err := json.Unmarshal([]byte(body), &blob); err != nil {
		t.Fatal(err)
	}
	v, ok := blob[key]
	if !ok {
		t.Fatalf("diagnostics blob has no %q", key)
	}
	return v
}

func failedProof(err error, phase diagnostics.Phase, udp, tls bool) engine.ProofResult {
	obs := diagnostics.Observe(err, phase, udp, tls)
	return engine.ProofResult{Err: err, Observation: obs, Failed: []diagnostics.Observation{obs}, Attempts: 2}
}

var errSYNTimeout = &net.OpError{Op: "dial", Net: "tcp", Err: context.DeadlineExceeded}

// THE defect: the engine starts, the relay is unreachable. SetRoute must
// fail, nothing may say Connected, and the route must come out failed,
// classified, cooling down — and not proven.
func TestSetRoute_StartedButCarriesNothingIsNotConnected(t *testing.T) {
	c, stub := checkInit(t, "r-st")
	stub.InjectProof(failedProof(errSYNTimeout, diagnostics.PhaseHandshake, false, true))

	err := SetRoute("r-st")
	if err == nil {
		t.Fatal("SetRoute returned nil for a route that carried nothing")
	}
	if !errors.Is(err, ErrRouteNotCarrying) {
		t.Fatalf("error %v does not wrap ErrRouteNotCarrying: a host cannot tell it from a refused route", err)
	}
	if stub.Connected() {
		t.Fatal("the engine instance was left running after its route failed the proof")
	}
	if refresh.TunnelRequired() {
		t.Fatal("tunnel-required is still set although the instance was torn down")
	}
	if p := c.pm.Posture(); p != pathmanager.PostureRecovery {
		t.Fatalf("posture = %s, want Recovery", p)
	}
	if st := c.pm.State(); st == pathmanager.StateConnected {
		t.Fatal("FSM state is Connected")
	}
	if got := diagField(t, "route_check"); got != RouteCheckFailed {
		t.Fatalf("route_check = %v, want failed", got)
	}
	if got := diagField(t, "route_check_category"); got != "tcp_connect_timeout" {
		t.Fatalf("route_check_category = %v, want tcp_connect_timeout", got)
	}
	row, err := c.store.GetRoute("r-st")
	if err != nil {
		t.Fatal(err)
	}
	if row.LastSuccessBucket != "" {
		t.Fatal("a success was recorded for a route that carried nothing")
	}
	if row.LastFailureCategory != "tcp_connect_timeout" || row.ConsecutiveFailures != 1 || row.CooldownUntil == "" {
		t.Fatalf("failure not recorded: category=%q consecutive=%d cooldown=%q", row.LastFailureCategory, row.ConsecutiveFailures, row.CooldownUntil)
	}
	sum := routeSummary(t, "r-st")
	if sum.Proven {
		t.Fatal("the route reports proven")
	}
	if sum.HealthPct != nil {
		t.Fatalf("health_pct = %v for a route that never worked; want null", *sum.HealthPct)
	}
	if sum.InCooldown == nil || !*sum.InCooldown {
		t.Fatal("the route is not cooling down")
	}
	// The explanation the UI and the publisher's recommender read.
	exp, err := DiagnosticsExplain()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(exp, `"classification":"tcp_connect_timeout"`) {
		t.Fatalf("failures[] does not carry the classified failure: %s", exp)
	}
	// And a second attempt is refused by the cooldown, not silently retried.
	if err := SetRoute("r-st"); err == nil || !strings.Contains(err.Error(), "cooling down") {
		t.Fatalf("second SetRoute: %v, want the cooldown refusal", err)
	}
}

// The error reaching the classifier carries its PHASE (CEN-2): the same
// reset is a name-keyed block suspicion after a ClientHello and plain
// tcp_reset anywhere else, and a UDP route's silence is never a claim
// about the network.
func TestSetRoute_FailedProofIsClassifiedByPhase(t *testing.T) {
	reset := errors.New("read tcp 198.51.100.2:5000->203.0.113.10:443: read: connection reset by peer")
	cases := []struct {
		name string
		res  engine.ProofResult
		want string
	}{
		{"reset after the ClientHello", failedProof(reset, diagnostics.PhaseHandshake, false, true), "tls_sni_or_cert_block_suspected"},
		{"reset on an opaque flow", failedProof(reset, diagnostics.PhaseCarry, false, false), "tcp_reset"},
		{"ClientHello swallowed", failedProof(context.DeadlineExceeded, diagnostics.PhaseHandshake, false, true), "tls_handshake_failed"},
		{"QUIC heard nothing", failedProof(errors.New("timeout: no recent network activity"), diagnostics.PhaseHandshake, true, true), "udp_no_reply"},
		{"credential refused", failedProof(errors.New("authentication failed"), diagnostics.PhaseHandshake, true, true), "auth_failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, stub := checkInit(t, "r-st")
			stub.InjectProof(tc.res)
			if err := SetRoute("r-st"); err == nil {
				t.Fatal("SetRoute succeeded")
			}
			row, _ := c.store.GetRoute("r-st")
			if row.LastFailureCategory != tc.want {
				t.Fatalf("recorded %q, want %q", row.LastFailureCategory, tc.want)
			}
			if tc.want == "auth_failed" && row.CooldownUntil != "" {
				t.Fatal("auth_failed must never start a cooldown")
			}
			_ = Shutdown()
		})
	}
}

// While the proof runs the route is "verifying", visible to a concurrent
// diagnostics poll, and nothing reads as connected.
func TestSetRoute_IsVerifyingUntilProved(t *testing.T) {
	c, stub := checkInit(t, "r-st")
	entered, release := make(chan struct{}), make(chan struct{})
	stub.SetProofHook(func(ctx context.Context, _ engine.ProofConfig) engine.ProofResult {
		close(entered)
		<-release
		return engine.ProofResult{OK: true, Attempts: 1}
	})
	done := make(chan error, 1)
	go func() { done <- SetRoute("r-st") }()
	<-entered

	if got := diagField(t, "route_check"); got != RouteCheckVerifying {
		t.Fatalf("route_check = %v during the proof, want verifying", got)
	}
	if p := c.pm.Posture(); p == pathmanager.PostureImportedActive {
		t.Fatal("posture is ImportedActive before the route has carried anything")
	}
	if st := c.pm.State(); st != pathmanager.StateVerifying {
		t.Fatalf("FSM state = %s, want Verifying", st)
	}
	row, _ := c.store.GetRoute("r-st")
	if row.LastSuccessBucket != "" {
		t.Fatal("a success was recorded before the proof finished")
	}
	if !refresh.TunnelRequired() {
		t.Fatal("the instance is up but refresh may still egress direct")
	}
	// SetMode must not wait for a connection check.
	modeDone := make(chan error, 1)
	go func() { modeDone <- SetMode("normal") }()
	select {
	case <-modeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("SetMode blocked behind a connection check")
	}

	close(release)
	if err := <-done; err != nil {
		t.Fatalf("SetRoute: %v", err)
	}
	if got := diagField(t, "route_check"); got != RouteCheckOK {
		t.Fatalf("route_check = %v after the proof, want ok", got)
	}
	if p := c.pm.Posture(); p != pathmanager.PostureImportedActive {
		t.Fatalf("posture = %s, want ImportedActive", p)
	}
	if !routeSummary(t, "r-st").Proven {
		t.Fatal("a proved route is not proven")
	}
}

// O-2, the ABI half: Disconnect during a connection check returns at
// once, the check is abandoned, and NOTHING is recorded about the route.
func TestClearRoute_DoesNotWaitForAConnectionCheck(t *testing.T) {
	c, stub := checkInit(t, "r-st")
	entered := make(chan struct{})
	stub.SetProofHook(func(ctx context.Context, _ engine.ProofConfig) engine.ProofResult {
		close(entered)
		<-ctx.Done() // a relay that never answers
		return engine.ProofResult{Cancelled: true, Err: engine.ErrProofCancelled}
	})
	done := make(chan error, 1)
	go func() { done <- SetRoute("r-st") }()
	<-entered

	t0 := time.Now()
	if err := ClearRoute(); err != nil {
		t.Fatalf("ClearRoute: %v", err)
	}
	if d := time.Since(t0); d > time.Second {
		t.Fatalf("ClearRoute took %s during a connection check", d)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrConnectCancelled) {
			t.Fatalf("SetRoute returned %v, want ErrConnectCancelled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SetRoute did not return after its check was abandoned")
	}
	row, _ := c.store.GetRoute("r-st")
	if row.LastSuccessBucket != "" || row.LastFailureCategory != "" || row.ConsecutiveFailures != 0 {
		t.Fatalf("an abandoned check recorded an outcome: %+v", row)
	}
	if p := c.pm.Posture(); p != pathmanager.PostureNoRoute {
		t.Fatalf("posture = %s, want NoRoute", p)
	}
	if got := diagField(t, "route_check"); got != RouteCheckNone {
		t.Fatalf("route_check = %v after disconnect, want empty", got)
	}
	if ok, why := c.pm.CanAttempt("r-st", "vless-reality"); !ok {
		t.Fatalf("an abandoned check put the route in cooldown: %s", why)
	}
}

// CEN-3: a proof that completes too slowly is a DEGRADED route — it is
// connected, it is not healthy, and it is not a failure.
func TestSetRoute_SlowProofIsDegradedNotFailed(t *testing.T) {
	c, stub := checkInit(t, "r-st")
	stub.InjectProof(engine.ProofResult{OK: true, Slow: true, Attempts: 1, RoundTrip: 3 * time.Second})
	if err := SetRoute("r-st"); err != nil {
		t.Fatalf("a slow route must still connect: %v", err)
	}
	if got := diagField(t, "route_check"); got != RouteCheckDegraded {
		t.Fatalf("route_check = %v, want degraded", got)
	}
	if got := diagField(t, "route_check_category"); got != "path_too_slow" {
		t.Fatalf("route_check_category = %v", got)
	}
	row, _ := c.store.GetRoute("r-st")
	if row.LastFailureCategory != "" || row.ConsecutiveFailures != 0 || row.CooldownUntil != "" {
		t.Fatalf("a degraded route was recorded as a failure: %+v", row)
	}
	if row.LastDegradedCategory != "path_too_slow" || row.LastDegradedBucket == "" || row.LastSuccessBucket == "" {
		t.Fatalf("degraded outcome not recorded: %+v", row)
	}
	exp, _ := DiagnosticsExplain()
	var blob struct {
		Failures []map[string]any `json:"failures"`
		Degraded []map[string]any `json:"degraded"`
	}
	if err := json.Unmarshal([]byte(exp), &blob); err != nil {
		t.Fatal(err)
	}
	if len(blob.Failures) != 0 {
		t.Fatalf("a slow route is in failures[]: %s", exp)
	}
	if len(blob.Degraded) != 1 || blob.Degraded[0]["classification"] != "path_too_slow" || blob.Degraded[0]["route_id"] != "r-st" {
		t.Fatalf("degraded[] = %v", blob.Degraded)
	}
	if ok, _ := c.pm.CanAttempt("r-st", "vless-reality"); !ok {
		t.Fatal("a degraded route is cooling down")
	}
	// A later clean proof clears it.
	if res := c.checkActiveRoute(context.Background()); res.State != RouteCheckOK {
		t.Fatalf("after a clean check: %+v", res)
	}
	row, _ = c.store.GetRoute("r-st")
	if row.LastDegradedCategory != "" {
		t.Fatal("a clean success left the degraded mark in place")
	}
}

// The liveness check: a connected route that stops carrying moves to
// failed with a classified category; the instance is NOT torn down (the
// tunnel stays the only way out); and it comes back when the path does.
func TestCheckActiveRoute_ConnectedToFailedAndBack(t *testing.T) {
	c, stub := checkInit(t, "r-st")
	if err := SetRoute("r-st"); err != nil {
		t.Fatal(err)
	}
	if got := diagField(t, "route_check"); got != RouteCheckOK {
		t.Fatalf("route_check = %v", got)
	}

	reset := errors.New("read tcp 198.51.100.2:5000->203.0.113.10:443: read: connection reset by peer")
	stub.InjectProof(failedProof(reset, diagnostics.PhaseHandshake, false, true))
	body, err := CheckActiveRoute()
	if err != nil {
		t.Fatal(err)
	}
	var res CheckResult
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatal(err)
	}
	if !res.Checked || res.State != RouteCheckFailed || res.Category != "tls_sni_or_cert_block_suspected" || res.RouteID != "r-st" {
		t.Fatalf("check result = %s", body)
	}
	if p := c.pm.Posture(); p != pathmanager.PostureRecovery {
		t.Fatalf("posture = %s, want Recovery", p)
	}
	if !stub.Connected() {
		t.Fatal("a liveness failure tore the instance down: the VPN interface would be left with nothing behind it")
	}
	if !refresh.TunnelRequired() {
		t.Fatal("a failed route released the tunnel requirement: refresh could now egress from the real address")
	}
	row, _ := c.store.GetRoute("r-st")
	if row.LastFailureCategory != "tls_sni_or_cert_block_suspected" || row.ConsecutiveFailures != 1 {
		t.Fatalf("failure not recorded: %+v", row)
	}

	// Still down: one outage is one failure, not one per recheck.
	stub.InjectProof(failedProof(errSYNTimeout, diagnostics.PhaseHandshake, false, true))
	if res := c.checkActiveRoute(context.Background()); res.State != RouteCheckFailed || res.Category != "tls_sni_or_cert_block_suspected" {
		t.Fatalf("second failed check: %+v", res)
	}
	row, _ = c.store.GetRoute("r-st")
	if row.ConsecutiveFailures != 1 {
		t.Fatalf("consecutive_failures = %d after a recheck of the same outage, want 1", row.ConsecutiveFailures)
	}

	// The path returns.
	if res := c.checkActiveRoute(context.Background()); res.State != RouteCheckOK {
		t.Fatalf("recovered check: %+v", res)
	}
	if p := c.pm.Posture(); p != pathmanager.PostureImportedActive {
		t.Fatalf("posture = %s after recovery, want ImportedActive", p)
	}
	if why := diagField(t, "why"); strings.Contains(why.(string), "illegal transition") {
		t.Fatalf("why = %q", why)
	}
	row, _ = c.store.GetRoute("r-st")
	if row.ConsecutiveFailures != 0 || row.CooldownUntil != "" {
		t.Fatalf("recovery not recorded: %+v", row)
	}
}

func TestCheckActiveRoute_NothingToCheck(t *testing.T) {
	_, stub := checkInit(t, "r-st")
	body, err := CheckActiveRoute()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(body, `"checked":true`) || stub.ProofCount() != 0 {
		t.Fatalf("a check ran with no route connected: %s", body)
	}
}

// The liveness loop runs on its own, and a platform network-change
// signal makes it check NOW instead of at the next tick.
func TestLiveness_TimerAndNetworkChange(t *testing.T) {
	dir := t.TempDir()
	cfg := `{"connection_check":{"targets":["192.0.2.44:443"],"liveness_interval_s":3600,"recheck_interval_s":3600}}`
	if err := os.WriteFile(filepath.Join(dir, EngineConfigFile), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	defer Shutdown()
	c := mustCore()
	seedStableRoute(t, c, "r-st")
	stub, ok := c.driver.(*engine.Stub)
	if !ok {
		t.Skip("not the stub driver")
	}
	if err := SetRoute("r-st"); err != nil {
		t.Fatal(err)
	}
	if n := stub.ProofCount(); n != 1 {
		t.Fatalf("proofs after connect = %d, want 1", n)
	}
	// An hour-long interval: only the network change can cause a check.
	stub.InjectProof(failedProof(errSYNTimeout, diagnostics.PhaseHandshake, false, true))
	if _, err := NetworkChanged("wifi", "", "cafe"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if st, _ := c.check.get(); st == RouteCheckFailed {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if st, cat := c.check.get(); st != RouteCheckFailed || cat != diagnostics.TCPConnectTimeout {
		t.Fatalf("after a network change the route is %q/%q; want failed/tcp_connect_timeout", st, cat)
	}
	// Disconnect stops the loop: no further proofs.
	if err := ClearRoute(); err != nil {
		t.Fatal(err)
	}
	n := stub.ProofCount()
	_, _ = NetworkChanged("cell", "carrier", "")
	time.Sleep(100 * time.Millisecond)
	if stub.ProofCount() != n {
		t.Fatal("the liveness loop outlived the route")
	}
}

func TestLiveness_TimerFires(t *testing.T) {
	c, stub := checkInit(t, "r-st")
	c.proofCfg.LivenessInterval = 30 * time.Millisecond
	c.proofCfg.RecheckInterval = 30 * time.Millisecond
	if err := SetRoute("r-st"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for stub.ProofCount() < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := stub.ProofCount(); n < 3 {
		t.Fatalf("the liveness timer ran %d checks in 3 s at a 30 ms interval", n-1)
	}
}

func TestJitterStaysInItsBand(t *testing.T) {
	d := 3 * time.Minute
	lo, hi := d, d
	for i := 0; i < 2000; i++ {
		j := jittered(d, 0.25)
		if j < lo {
			lo = j
		}
		if j > hi {
			hi = j
		}
	}
	if lo < d*3/4 || hi > d*5/4 {
		t.Fatalf("jitter left ±25%%: %s … %s", lo, hi)
	}
	if hi-lo < d/4 {
		t.Fatalf("jitter is barely there (%s … %s): the check would be a metronome", lo, hi)
	}
}

// The engine configuration file: the default without it, the named
// targets with it, and a loud failure for a file that is wrong.
func TestEngineConfigFile(t *testing.T) {
	dir := t.TempDir()
	cfg, err := loadProofConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Targets) != len(engine.DefaultProofTargets) || cfg.Attempts < 2 {
		t.Fatalf("no file must mean the production default, got %+v", cfg)
	}
	write := func(body string) {
		if err := os.WriteFile(filepath.Join(dir, EngineConfigFile), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"connection_check":{"targets":["192.0.2.44:443","192.0.2.30:443"],"slow_after_ms":1500}}`)
	cfg, err = loadProofConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Targets) != 2 || cfg.Targets[0] != "192.0.2.44:443" || cfg.SlowAfter != 1500*time.Millisecond {
		t.Fatalf("configured values not taken: %+v", cfg)
	}
	if cfg.AttemptTimeout != engine.DefaultProofConfig().AttemptTimeout {
		t.Fatal("a field the file does not set must keep its default")
	}
	for _, bad := range []string{
		`{"connection_check":{"targets":["no-port"]}}`,
		`{"connection_check":{"targetz":["192.0.2.44:443"]}}`,
		`{"connection_check":{"attempts":-1}}`,
		`not json`,
	} {
		write(bad)
		if _, err := loadProofConfig(dir); err == nil {
			t.Errorf("config %s was accepted", bad)
		}
		if err := Init(dir, "warn"); err == nil {
			_ = Shutdown()
			t.Errorf("Init succeeded with config %s", bad)
		}
	}
}

// A route switch during a check: the first SetRoute's proof is abandoned
// and it must not overwrite what the second one established.
func TestSetRoute_SupersededProofRecordsNothing(t *testing.T) {
	c, stub := checkInit(t, "r-st")
	seedStableRoute(t, c, "r-two")
	entered := make(chan struct{})
	var calls atomic.Int32
	stub.SetProofHook(func(ctx context.Context, _ engine.ProofConfig) engine.ProofResult {
		if calls.Add(1) == 1 {
			close(entered)
			<-ctx.Done()
			// Returns a FAILURE, not "cancelled": even so, a proof whose
			// route was replaced must not be recorded.
			return failedProof(errSYNTimeout, diagnostics.PhaseHandshake, false, true)
		}
		return engine.ProofResult{OK: true, Attempts: 1}
	})
	first := make(chan error, 1)
	go func() { first <- SetRoute("r-st") }()
	<-entered
	if err := SetRoute("r-two"); err != nil {
		t.Fatalf("second SetRoute: %v", err)
	}
	if err := <-first; !errors.Is(err, ErrConnectCancelled) {
		t.Fatalf("first SetRoute returned %v, want ErrConnectCancelled", err)
	}
	row, _ := c.store.GetRoute("r-st")
	if row.LastFailureCategory != "" || row.LastSuccessBucket != "" {
		t.Fatalf("the superseded attempt recorded an outcome: %+v", row)
	}
	if got := diagField(t, "route_check"); got != RouteCheckOK {
		t.Fatalf("route_check = %v; the second route's state was overwritten", got)
	}
	if !stub.Connected() {
		t.Fatal("the superseded attempt tore down the second route's instance")
	}
}

// After a failed proof the posture is Recovery; connecting another route
// must reach an active posture and leave no FSM plumbing in `why`.
func TestSetRoute_AfterAFailureTheNextRouteConnectsCleanly(t *testing.T) {
	c, stub := checkInit(t, "r-st")
	seedStableRoute(t, c, "r-two")
	stub.InjectProof(failedProof(errSYNTimeout, diagnostics.PhaseHandshake, false, true))
	if err := SetRoute("r-st"); err == nil {
		t.Fatal("want failure")
	}
	// A second failure in a row must keep the failure's own explanation.
	stub.InjectProof(failedProof(errSYNTimeout, diagnostics.PhaseHandshake, false, true))
	if err := SetRoute("r-two"); err == nil {
		t.Fatal("want failure")
	}
	if why := diagField(t, "why").(string); strings.Contains(why, "illegal transition") || !strings.Contains(why, "tcp_connect_timeout") {
		t.Fatalf("why = %q after two failures", why)
	}
	_ = c
}

// A SetRoute the engine REFUSES replaces nothing: the route that was
// connected is still the tunnel, so its liveness loop must still be
// watching it. Before the fix SetRoute abandoned the loop ahead of its
// refusals, and the route stayed "Connected" with nothing ever
// re-checking it (CEN-1 through a side door).
func TestSetRoute_RefusedLeavesTheConnectedRouteWatched(t *testing.T) {
	c, stub := checkInit(t, "r-st")
	c.proofCfg.LivenessInterval = time.Hour
	c.proofCfg.RecheckInterval = time.Hour
	if err := SetRoute("r-st"); err != nil {
		t.Fatal(err)
	}
	if err := SetRoute("no-such-route"); err == nil {
		t.Fatal("SetRoute of a route that does not exist succeeded")
	}
	if c.activeRoute != "r-st" || !stub.Connected() {
		t.Fatalf("the refused call disturbed the connected route: active=%q connected=%v", c.activeRoute, stub.Connected())
	}
	// The path dies and the network changes: the loop must notice.
	n := stub.ProofCount()
	stub.InjectProof(failedProof(errSYNTimeout, diagnostics.PhaseHandshake, false, true))
	if _, err := NetworkChanged("wifi", "", "cafe"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if st, _ := c.check.get(); st == RouteCheckFailed {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if stub.ProofCount() == n {
		t.Fatal("a refused SetRoute stopped the liveness loop of the route that stayed up: no check ran after a network change")
	}
	if st, _ := c.check.get(); st != RouteCheckFailed {
		t.Fatalf("route_check = %q on a dead path; want failed", st)
	}
}

// The main button's case: the connected route failed a liveness check
// (instance kept, recovery loop running) and the user taps Connect on
// the same route. That call is refused — the route is cooling down — and
// the recovery loop must go on, or the route never comes back.
func TestSetRoute_RefusedForCooldownKeepsTheRecoveryLoop(t *testing.T) {
	c, stub := checkInit(t, "r-st")
	c.proofCfg.LivenessInterval = time.Hour
	c.proofCfg.RecheckInterval = 30 * time.Millisecond
	if err := SetRoute("r-st"); err != nil {
		t.Fatal(err)
	}
	// Hold the path down while the tap happens.
	var down atomic.Bool
	down.Store(true)
	stub.SetProofHook(func(context.Context, engine.ProofConfig) engine.ProofResult {
		if down.Load() {
			return failedProof(errSYNTimeout, diagnostics.PhaseHandshake, false, true)
		}
		return engine.ProofResult{OK: true, Attempts: 1}
	})
	if res := c.checkActiveRoute(context.Background()); res.State != RouteCheckFailed {
		t.Fatalf("liveness check: %+v", res)
	}
	err := SetRoute("r-st")
	if err == nil || !strings.Contains(err.Error(), "cool") {
		t.Fatalf("SetRoute on a cooling-down route returned %v; want a cooldown refusal", err)
	}
	if !stub.Connected() {
		t.Fatal("the refused call stopped the instance")
	}
	// The path returns; the loop the refused call must not have stopped
	// brings the route back.
	down.Store(false)
	c.kickLiveness()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if st, _ := c.check.get(); st == RouteCheckOK {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if st, _ := c.check.get(); st != RouteCheckOK {
		t.Fatalf("route_check = %q with the path back; the recovery loop was stopped by a refused SetRoute", st)
	}
	if p := c.pm.Posture(); p != pathmanager.PostureImportedActive {
		t.Fatalf("posture = %s after recovery, want ImportedActive", p)
	}
}

// "failed" is two different things to a user, and `route_running` is
// what tells them apart (review finding: the app said "Connecting…" for
// good after a failed connect, because posture=Recovery and
// route_check=failed read the same as a connected route that is being
// retried). After a failed CONNECT nothing runs and nothing retries;
// after a failed liveness check the instance is up and re-checked.
func TestRouteRunning_TellsAFailedConnectFromALostConnection(t *testing.T) {
	_, stub := checkInit(t, "r-st")
	if got := diagField(t, "route_running"); got != false {
		t.Fatalf("route_running = %v before any route, want false", got)
	}

	// A failed connect: torn down, cooling down, nothing will retry.
	stub.InjectProof(failedProof(errSYNTimeout, diagnostics.PhaseHandshake, false, true))
	if err := SetRoute("r-st"); err == nil {
		t.Fatal("SetRoute returned nil for a route that carried nothing")
	}
	if got := diagField(t, "route_check"); got != RouteCheckFailed {
		t.Fatalf("route_check = %v, want failed", got)
	}
	if got := diagField(t, "posture"); got != string(pathmanager.PostureRecovery) {
		t.Fatalf("posture = %v, want Recovery", got)
	}
	if stub.Connected() {
		t.Fatal("the instance is still up after a failed connect")
	}
	if got := diagField(t, "route_running"); got != false {
		t.Fatalf("route_running = %v after a failed connect: a UI would say it is still connecting", got)
	}
	// The cooldown refusal that follows changes nothing about that.
	if err := SetRoute("r-st"); err == nil {
		t.Fatal("second SetRoute was not refused")
	}
	if got := diagField(t, "route_running"); got != false {
		t.Fatalf("route_running = %v after a refused retry, want false", got)
	}
	if err := ClearRoute(); err != nil {
		t.Fatal(err)
	}
	if got := diagField(t, "route_running"); got != false {
		t.Fatalf("route_running = %v after ClearRoute, want false", got)
	}
}

func TestRouteRunning_LostConnectionKeepsRunning(t *testing.T) {
	_, stub := checkInit(t, "r-st")
	if err := SetRoute("r-st"); err != nil {
		t.Fatal(err)
	}
	if got := diagField(t, "route_running"); got != true {
		t.Fatalf("route_running = %v while connected, want true", got)
	}
	// A connected route that stops carrying: same posture, same
	// route_check as a failed connect — but the instance is up and the
	// engine re-checks it.
	stub.InjectProof(failedProof(errSYNTimeout, diagnostics.PhaseHandshake, false, true))
	if _, err := CheckActiveRoute(); err != nil {
		t.Fatal(err)
	}
	if got := diagField(t, "route_check"); got != RouteCheckFailed {
		t.Fatalf("route_check = %v, want failed", got)
	}
	if got := diagField(t, "posture"); got != string(pathmanager.PostureRecovery) {
		t.Fatalf("posture = %v, want Recovery", got)
	}
	if got := diagField(t, "route_running"); got != true {
		t.Fatalf("route_running = %v for a connected route that is being retried, want true", got)
	}
	// It comes back.
	if _, err := CheckActiveRoute(); err != nil {
		t.Fatal(err)
	}
	if got := diagField(t, "route_check"); got != RouteCheckOK {
		t.Fatalf("route_check = %v after recovery", got)
	}
	if got := diagField(t, "route_running"); got != true {
		t.Fatalf("route_running = %v after recovery, want true", got)
	}
	if err := ClearRoute(); err != nil {
		t.Fatal(err)
	}
	if got := diagField(t, "route_running"); got != false {
		t.Fatalf("route_running = %v after ClearRoute, want false", got)
	}
}

// A SetRoute the engine REFUSES while ANOTHER SetRoute's connection
// check is still running must not cancel that check. Before the fix
// SetRoute abandoned the check in flight ahead of its refusals: the
// first call saw its proof cancelled, returned ErrConnectCancelled and
// recorded nothing ("the state is theirs") — but the refused call owned
// nothing either, so the instance stayed up carrying traffic over a
// route nobody had proved, `route_check` stuck at "verifying", with no
// liveness loop and CheckActiveRoute skipping it, until a disconnect.
// Both refusals a user can cause by tapping are driven here: a route
// that does not exist and a route that is cooling down.
func TestSetRoute_RefusedLeavesTheCheckInFlightRunning(t *testing.T) {
	c, stub := checkInit(t, "r-st")
	seedStableRoute(t, c, "r-two")
	c.proofCfg.LivenessInterval = time.Hour
	c.proofCfg.RecheckInterval = time.Hour
	// r-two fails its own connect first, so it is cooling down.
	stub.InjectProof(failedProof(errSYNTimeout, diagnostics.PhaseHandshake, false, true))
	if err := SetRoute("r-two"); err == nil {
		t.Fatal("want r-two's connect to fail")
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	stub.SetProofHook(func(ctx context.Context, _ engine.ProofConfig) engine.ProofResult {
		if calls.Add(1) > 1 {
			return engine.ProofResult{OK: true, Attempts: 1}
		}
		close(entered)
		select {
		case <-release:
			return engine.ProofResult{OK: true, Attempts: 1}
		case <-ctx.Done():
			return engine.ProofResult{Cancelled: true}
		}
	})
	first := make(chan error, 1)
	go func() { first <- SetRoute("r-st") }()
	<-entered

	if err := SetRoute("no-such-route"); err == nil || errors.Is(err, ErrConnectCancelled) {
		t.Fatalf("SetRoute of a route that does not exist returned %v; want a refusal", err)
	}
	if err := SetRoute("r-two"); err == nil || !strings.Contains(err.Error(), "cool") {
		t.Fatalf("SetRoute on a cooling-down route returned %v; want a cooldown refusal", err)
	}
	select {
	case err := <-first:
		t.Fatalf("a refused SetRoute ended the connection check of the one in flight: first SetRoute returned %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if got := diagField(t, "route_check"); got != RouteCheckVerifying {
		t.Fatalf("route_check = %v while the first check is still running; want verifying", got)
	}

	close(release)
	select {
	case err := <-first:
		if err != nil {
			t.Fatalf("first SetRoute returned %v; its check passed and nothing replaced it", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("first SetRoute never returned")
	}
	if got := diagField(t, "route_check"); got != RouteCheckOK {
		t.Fatalf("route_check = %v after the check passed; want ok", got)
	}
	if c.activeRoute != "r-st" || !stub.Connected() {
		t.Fatalf("active=%q connected=%v; want r-st connected", c.activeRoute, stub.Connected())
	}
	if p := c.pm.Posture(); p != pathmanager.PostureImportedActive {
		t.Fatalf("posture = %s, want ImportedActive", p)
	}
	if res := c.checkActiveRoute(context.Background()); !res.Checked {
		t.Fatalf("CheckActiveRoute did not check the connected route: %+v", res)
	}
	// And it is watched: a network change must run a check.
	n := stub.ProofCount()
	if _, err := NetworkChanged("wifi", "", "cafe"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && stub.ProofCount() == n {
		time.Sleep(10 * time.Millisecond)
	}
	if stub.ProofCount() == n {
		t.Fatal("no liveness loop is watching the route: no check ran after a network change")
	}
}
