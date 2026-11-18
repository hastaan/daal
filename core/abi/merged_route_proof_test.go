package abi

// Where the signed endpoint commitment (endpoint_guard.go) meets the
// connection check (route_check.go) inside SetRoute.
//
// Each was built and tested on its own. Two properties exist only in
// their combination, and each is the kind of thing a later edit to
// SetRoute's ordering would break without turning either suite red:
//
//   - a route whose address arrived by a freshness MERGE (an L3 move:
//     the publisher's signed, credential-less pack laid over the
//     device's own credentials) is still nothing but a claim until the
//     connection check has carried a round trip through it;
//   - a route the endpoint guard refuses is refused BEFORE the engine is
//     started or a check is begun, and leaves no trace of an attempt.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"daal/core/bootstrap"
	"daal/core/engine"
	"daal/core/pathmanager"
	"daal/core/refresh"
	"daal/core/routestore"
)

// healedFixture imports the pre-rotation pack as a user does, then
// applies the post-rotation (L3) pack over the freshness channel — the
// same real publisher output TestRotationHealsAnImportedPackOverTheNetwork
// uses — and returns the merged vless-reality route.
func healedFixture(t *testing.T) (*Core, *engine.Stub, routestore.RouteRow) {
	t.Helper()
	if err := Init(t.TempDir(), "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Shutdown() })
	c := mustCore()
	stub, ok := c.driver.(*engine.Stub)
	if !ok {
		t.Skipf("driver is %T, not the stub", c.driver)
	}
	v := importFixture(t, freshnessFixture)
	if _, err := ResolveTrustPrompt(v.Fingerprint, 0); err != nil {
		t.Fatalf("ResolveTrustPrompt: %v", err)
	}
	refresh.SetTunnelRequired(false)
	t.Cleanup(func() { refresh.SetTunnelRequired(false) })

	rp, err := ensureRelayPackRefresh()
	if err != nil {
		t.Fatal(err)
	}
	targets, err := rp.Targets()
	if err != nil || len(targets) != 1 {
		t.Fatalf("targets: %+v %v", targets, err)
	}
	rotatedPack, err := os.ReadFile(fixtureRotatedPack)
	if err != nil {
		t.Fatal(err)
	}
	served := map[string][]byte{"https://cdn-r2.invalid/daal/packs/abc.sbp": rotatedPack}
	for _, ep := range targets[0].Endpoints {
		served[ep] = readDoc(t, docRotated)
	}
	rp.Fetch = func(_ context.Context, url string, _ bootstrap.Dialer, _ time.Duration) ([]byte, error) {
		body, ok := served[url]
		if !ok {
			return nil, errors.New("no route to " + url)
		}
		return body, nil
	}
	rp.Now = func() time.Time { return fixtureNow }
	res, err := rp.RefreshUser(context.Background(), fixturePackID)
	if err != nil || !res.Applied {
		t.Fatalf("the rotated pack was not applied: %v (outcome=%s verdict=%s)", err, res.Outcome, res.Verdict)
	}

	rows, err := c.store.ListRoutes()
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.TransportFamily != "vless-reality" {
			continue
		}
		profile, err := c.store.GetSecret("route:" + row.RouteID)
		if err != nil {
			t.Fatal(err)
		}
		var ob map[string]any
		if err := json.Unmarshal(profile, &ob); err != nil {
			t.Fatal(err)
		}
		if ob["server"] != fixtureRotatedServer || ob["uuid"] != fixtureRecipientUUID {
			t.Fatalf("the route is not the merged one: server=%v uuid=%v", ob["server"], ob["uuid"])
		}
		return c, stub, row
	}
	t.Fatal("no vless-reality route after the rotation")
	return nil, nil, routestore.RouteRow{}
}

// A freshness-merged route is not Connected because the merge was
// accepted. It passes the endpoint guard, the engine starts, and it is
// "verifying" until the connection check has carried something.
func TestSetRoute_MergedRouteIsConnectedOnlyAfterTheConnectionCheck(t *testing.T) {
	c, stub, row := healedFixture(t)

	entered, release := make(chan struct{}), make(chan struct{})
	stub.SetProofHook(func(context.Context, engine.ProofConfig) engine.ProofResult {
		close(entered)
		<-release
		return engine.ProofResult{OK: true, Attempts: 1}
	})
	done := make(chan error, 1)
	go func() { done <- SetRoute(row.RouteID) }()
	select {
	case <-entered:
	case err := <-done:
		t.Fatalf("SetRoute returned (%v) without running a connection check on the merged route", err)
	case <-time.After(5 * time.Second):
		t.Fatal("no connection check was started for the merged route")
	}

	if st := c.pm.State(); st != pathmanager.StateVerifying {
		t.Fatalf("FSM state = %s during the check, want Verifying", st)
	}
	if got := diagField(t, "route_check"); got != RouteCheckVerifying {
		t.Fatalf("route_check = %v during the check, want verifying", got)
	}
	if routeSummary(t, row.RouteID).Proven {
		t.Fatal("the merged route reports proven before anything crossed it")
	}
	if mid, _ := c.store.GetRoute(row.RouteID); mid.LastSuccessBucket != "" {
		t.Fatal("a success was recorded for the merged route before the check finished")
	}

	close(release)
	if err := <-done; err != nil {
		t.Fatalf("SetRoute on the merged route: %v", err)
	}
	if st := c.pm.State(); st != pathmanager.StateConnected {
		t.Fatalf("FSM state = %s after the check, want Connected", st)
	}
	if got := diagField(t, "route_check"); got != RouteCheckOK {
		t.Fatalf("route_check = %v after the check, want ok", got)
	}
	if !routeSummary(t, row.RouteID).Proven {
		t.Fatal("the merged route is not proven after a passed check")
	}
	if n := stub.ProofCount(); n != 1 {
		t.Fatalf("connection checks run = %d, want 1", n)
	}
}

// The other direction: the merge moved the route to the new signed
// address, and that address carries nothing. The signature on the
// address is not evidence that it works.
func TestSetRoute_MergedRouteThatCarriesNothingIsNotConnected(t *testing.T) {
	c, stub, row := healedFixture(t)
	stub.InjectProof(failedProof(errSYNTimeout, "handshake", false, true))

	err := SetRoute(row.RouteID)
	if !errors.Is(err, ErrRouteNotCarrying) {
		t.Fatalf("SetRoute = %v, want ErrRouteNotCarrying", err)
	}
	if errors.Is(err, ErrRouteEndpoint) {
		t.Fatalf("a network failure was reported as an endpoint refusal: %v", err)
	}
	if st := c.pm.State(); st == pathmanager.StateConnected {
		t.Fatal("FSM state is Connected")
	}
	if stub.Connected() {
		t.Fatal("the engine instance was left running")
	}
	after, _ := c.store.GetRoute(row.RouteID)
	if after.LastSuccessBucket != "" || after.ConsecutiveFailures != 1 || after.LastFailureCategory != "tcp_connect_timeout" {
		t.Fatalf("outcome not recorded as a failure: %+v", after)
	}
	if routeSummary(t, row.RouteID).Proven {
		t.Fatal("the route reports proven")
	}
}

// A profile that no longer matches its signed endpoint is refused with
// nothing begun: the engine is not started, no connection check runs,
// the FSM never leaves its resting state, the posture does not move,
// and neither a failure nor a cooldown is filed against the route — so
// the genuine route is immediately usable once the profile is right.
func TestSetRoute_EndpointRefusalComesBeforeAnyConnectionAttempt(t *testing.T) {
	c, stub, row := healedFixture(t)
	genuine, err := c.store.GetSecret("route:" + row.RouteID)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.store.PutSecret("route:"+row.RouteID,
		[]byte(rewriteProfileField(t, genuine, "server", "198.51.100.66"))); err != nil {
		t.Fatal(err)
	}
	stateBefore, postureBefore := c.pm.State(), c.pm.Posture()
	stub.SetProofHook(func(context.Context, engine.ProofConfig) engine.ProofResult {
		t.Error("a connection check was run on a route the endpoint guard refuses")
		return engine.ProofResult{OK: true, Attempts: 1}
	})

	if err := SetRoute(row.RouteID); !errors.Is(err, ErrRouteEndpoint) {
		t.Fatalf("SetRoute = %v, want ErrRouteEndpoint", err)
	} else if errors.Is(err, ErrRouteNotCarrying) {
		t.Fatalf("an endpoint refusal was reported as a network failure: %v", err)
	}
	if stub.Connected() {
		t.Fatal("the engine was started for a refused route")
	}
	if n := stub.ProofCount(); n != 0 {
		t.Fatalf("connection checks run = %d, want 0", n)
	}
	if refresh.TunnelRequired() {
		t.Fatal("tunnel-required was raised although nothing was started")
	}
	if st := c.pm.State(); st != stateBefore {
		t.Fatalf("FSM state moved %s -> %s on a refusal", stateBefore, st)
	}
	if p := c.pm.Posture(); p != postureBefore {
		t.Fatalf("posture moved %s -> %s on a refusal", postureBefore, p)
	}
	if got := diagField(t, "route_check"); got != RouteCheckNone {
		t.Fatalf("route_check = %q after a refusal, want none", got)
	}
	after, _ := c.store.GetRoute(row.RouteID)
	if after.ConsecutiveFailures != 0 || after.LastFailureCategory != "" || after.CooldownUntil != "" || after.LastSuccessBucket != "" {
		t.Fatalf("the refusal left an outcome on the route: %+v", after)
	}
	if ok, reason := c.pm.CanAttempt(row.RouteID, row.TransportFamily); !ok {
		t.Fatalf("the refusal cooled the route down: %s", reason)
	}

	// Put the genuine profile back: the very next attempt goes through.
	if err := c.store.PutSecret("route:"+row.RouteID, genuine); err != nil {
		t.Fatal(err)
	}
	stub.SetProofHook(nil)
	if err := SetRoute(row.RouteID); err != nil {
		t.Fatalf("the genuine route was not usable after a refusal: %v", err)
	}
}
