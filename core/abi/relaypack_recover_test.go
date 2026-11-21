package abi

// C0 (blackout plan §3): a route that is "connected" and carries nothing
// because its relay's address was null-routed. These tests drive the
// real imported fixture pack (testdata/freshness-3mirrors.sbp) and its
// real rotated successor (an L3: only the address moved), the Stub
// driver, and a proof hook that answers by the ADDRESS the running
// route's stored profile dials — so "the censor null-routes the old
// address" is one map entry, and "the route now dials the new one" is
// something the engine has to have done for itself.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"daal/core/bootstrap"
	"daal/core/engine"
	"daal/core/refresh"
)

type c0Fetch struct {
	url string
	// routeActive: an instance was serving a route (refresh.RouteActive).
	// window: the recovery window was open — every ordinary fetcher saw
	// TunnelRequired() all the same.
	routeActive  bool
	window       bool
	tunnelDialer bool
}

type c0Rig struct {
	t       *testing.T
	c       *Core
	rp      *refresh.RelayPackRefresher
	oldHost string

	mu      sync.Mutex
	dead    map[string]bool
	served  map[string][]byte
	fetches []c0Fetch
	// reset: a dead address answers with a reset (not silence), so the
	// pass charges cooldowns.
	reset bool
	// gate: when non-nil, every fetch waits on it (or on its context).
	gate chan struct{}
}

func newC0Rig(t *testing.T) *c0Rig {
	t.Helper()
	if err := Init(t.TempDir(), "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Shutdown() })
	v := importFixture(t, freshnessFixture)
	if _, err := ResolveTrustPrompt(v.Fingerprint, 0); err != nil {
		t.Fatalf("ResolveTrustPrompt: %v", err)
	}
	// The guard is process-global; state it rather than inherit it.
	refresh.SetTunnelRequired(false)
	refresh.SetGlobalDialer(nil)
	t.Cleanup(func() { refresh.SetTunnelRequired(false); refresh.SetGlobalDialer(nil) })
	// Inside every fixture's validity window, and a clock the test moves.
	clockOverride.Store(fixtureNow.Unix())
	t.Cleanup(func() { clockOverride.Store(0) })

	c := mustCore()
	stub, ok := c.driver.(*engine.Stub)
	if !ok {
		t.Skipf("driver is %T, not the stub", c.driver)
	}
	r := &c0Rig{t: t, c: c, dead: map[string]bool{}, served: map[string][]byte{}}
	rows, err := c.store.ListRoutes()
	if err != nil || len(rows) == 0 {
		t.Fatalf("routes: %v %v", rows, err)
	}
	r.oldHost = r.hostOf(rows[0].RouteID)
	if r.oldHost == "" || r.oldHost == fixtureRotatedServer {
		t.Fatalf("premise: the fixture dials %q", r.oldHost)
	}
	stub.SetProofHook(func(ctx context.Context, cfg engine.ProofConfig) engine.ProofResult {
		id, _ := c.activeRouteFromMemory()
		host := r.hostOf(id)
		r.mu.Lock()
		dead, reset := r.dead[host], r.reset
		r.mu.Unlock()
		if dead && reset {
			return answeredReset()
		}
		if dead {
			return deadSYN()
		}
		return engine.ProofResult{OK: true, Attempts: 1}
	})
	rp, err := ensureRelayPackRefresh()
	if err != nil {
		t.Fatal(err)
	}
	rp.Fetch = func(ctx context.Context, url string, d bootstrap.Dialer, _ time.Duration) ([]byte, error) {
		_, viaTunnel := d.(*bootstrap.TunnelDialer)
		r.mu.Lock()
		r.fetches = append(r.fetches, c0Fetch{url: url, routeActive: refresh.RouteActive(),
			window: refresh.RecoveryWindowOpen(), tunnelDialer: viaTunnel})
		gate := r.gate
		r.mu.Unlock()
		if gate != nil {
			select {
			case <-gate:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		body, ok := r.served[url]
		if !ok {
			return nil, errors.New("connect timeout")
		}
		return body, nil
	}
	r.rp = rp
	fastRecheck(c)
	return r
}

func (r *c0Rig) hostOf(routeID string) string {
	if routeID == "" {
		return ""
	}
	profile, err := r.c.store.GetSecret("route:" + routeID)
	if err != nil {
		return ""
	}
	h, _, _ := profileRelay(profile)
	return h
}

// serveRotation puts the publisher's L3 on every mirror: the rotated
// document, and the rotated credential-less pack at the URL it names.
func (r *c0Rig) serveRotation() {
	r.t.Helper()
	pack, err := os.ReadFile(fixtureRotatedPack)
	if err != nil {
		r.t.Fatal(err)
	}
	doc := readDoc(r.t, docRotated)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.served["https://cdn-r2.invalid/daal/packs/abc.sbp"] = pack
	for _, ep := range fixtureMirrors {
		r.served[ep] = doc
	}
}

func (r *c0Rig) block(host string) {
	r.mu.Lock()
	r.dead[host] = true
	r.mu.Unlock()
}

func (r *c0Rig) fetchLog() []c0Fetch {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]c0Fetch(nil), r.fetches...)
}

func (r *c0Rig) record(packID string) map[string]any {
	r.t.Helper()
	body, err := r.c.store.GetSecret("freshness:" + packID)
	if err != nil {
		return map[string]any{}
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		r.t.Fatal(err)
	}
	return m
}

func recoveryBlock(t *testing.T) map[string]any {
	t.Helper()
	b, ok := diagBlob(t)["relay_recovery"].(map[string]any)
	if !ok {
		t.Fatal("diagnostics blob has no `relay_recovery` object")
	}
	return b
}

func (r *c0Rig) connected() bool {
	st, _, running := r.c.check.snapshot()
	as, _ := r.c.auto.snapshot()
	return running && (st == RouteCheckOK || st == RouteCheckDegraded) && as == AutoStateConnected
}

func (r *c0Rig) deadButRunning() bool {
	id, _ := r.c.activeRouteFromMemory()
	st, _, running := r.c.check.snapshot()
	return id != "" && running && st == RouteCheckFailed
}

func (r *c0Rig) fallPasses() int {
	r.c.mu.Lock()
	defer r.c.mu.Unlock()
	return r.c.auto.fallPasses
}

func advanceClock(d time.Duration) { clockOverride.Add(int64(d / time.Second)) }

// THE STATE MACHINE, the case it exists for: connected → the address is
// null-routed → the route fails → a pass finds nothing → the instance is
// stopped, the guard lowered, ONE direct walk finds the publisher's
// rotation and applies it through the verified path → the route is put
// back on its NEW address and carries → connected. The host does
// nothing.
func TestC0_FailedButRunningFindsTheNewAddressAndReconnects(t *testing.T) {
	r := newC0Rig(t)
	if res := r.connectAutoOrFail(); !res.Connected {
		t.Fatalf("premise: %+v", res)
	}
	if !refresh.TunnelRequired() {
		t.Fatal("premise: a connected route raises the guard")
	}
	r.serveRotation()
	r.block(r.oldHost)
	r.c.kickLiveness()

	waitFor(t, "the engine to reconnect on the rotated address", func() bool {
		id, _ := r.c.activeRouteFromMemory()
		return r.connected() && r.hostOf(id) == fixtureRotatedServer
	})

	// Every fetch of the walk went out with NO route up and not through
	// a (dead) tunnel inlet; and there was a walk at all.
	log := r.fetchLog()
	if len(log) < 2 {
		t.Fatalf("expected a document and a pack fetch, got %+v", log)
	}
	for _, f := range log {
		if f.routeActive || f.tunnelDialer || !f.window {
			t.Fatalf("a recovery fetch went out while a route was up, through a tunnel dialer, or outside the window: %+v", f)
		}
	}
	if refresh.RecoveryWindowOpen() {
		t.Fatal("the recovery window is still open after the walk")
	}
	if !refresh.TunnelRequired() {
		t.Fatal("the guard is down again although a route is running")
	}
	b := recoveryBlock(t)
	if b["state"] != RecoverUpdated || b["trigger"] != RecoverTriggerFailure || b["outcome"] != refresh.OutcomeFreshnessOK {
		t.Fatalf("relay_recovery = %v", b)
	}
	if bucket, _ := b["bucket"].(string); len(bucket) != len("2006-01-02T15:00:00Z") || bucket[14:] != "00:00Z" {
		t.Fatalf("relay_recovery.bucket %q is not hour-bucketed", bucket)
	}
	// The pack moved to its new id, and no scheduled-poll escalation
	// was charged along the way.
	rec := r.record(fixtureRotatedPackID)
	if rec["consecutive_failures"] != nil || rec["last_failure_at"] != nil || rec["on_failure_misses"] != nil {
		t.Fatalf("the recovery walk inflated the scheduled back-off: %v", rec)
	}
	if rec["on_failure_at"] == nil {
		t.Fatalf("the walk was not stamped (its own rate limit has nothing to count from): %v", rec)
	}
	a := autoBlock(t)
	if a["state"] != AutoStateConnected || a["mode"] != true {
		t.Fatalf("auto = %v", a)
	}
}

// Nothing new on the mirrors (here: every mirror unreachable). The route
// is put back exactly as before C0 — failed, running, healing by itself
// — the engine says what the walk found, the scheduled back-off is not
// touched, and the next walk waits for its own floor (and for the
// pass back-off), escalating per walk that found nothing.
func TestC0_NothingNewIsHonestBoundedAndDoesNotInflateTheBackoff(t *testing.T) {
	r := newC0Rig(t)
	if res := r.connectAutoOrFail(); !res.Connected {
		t.Fatalf("premise: %+v", res)
	}
	r.block(r.oldHost)
	r.c.kickLiveness()

	waitFor(t, "the walk to come back empty and the route to be running again", func() bool {
		b := recoveryBlock(t)
		as, _ := r.c.auto.snapshot()
		return b["state"] == RecoverUnreachable && r.deadButRunning() && as == AutoStateFailed
	})
	walked := len(r.fetchLog())
	if walked == 0 || walked > len(fixtureMirrors) {
		t.Fatalf("one walk is at most one fetch per mirror; saw %d", walked)
	}
	rec := r.record(fixturePackID)
	if rec["consecutive_failures"] != nil || rec["last_failure_at"] != nil {
		t.Fatalf("a failure-triggered walk escalated the scheduled poll: %v", rec)
	}
	if rec["on_failure_misses"] != float64(1) {
		t.Fatalf("on_failure_misses = %v, want 1", rec["on_failure_misses"])
	}
	if a := autoBlock(t); a["verdict"] == "" || a["mode"] != true {
		t.Fatalf("auto = %v: a failed pass must keep saying why", a)
	}

	// The next pass of this outage (its back-off run out): the walk's
	// own floor has not, so the pass does NOT walk again.
	advanceClock(6 * time.Minute)
	waitFor(t, "a second fall-over pass", func() bool { return r.fallPasses() >= 2 })
	waitFor(t, "the route to be running again after it", r.deadButRunning)
	if n := len(r.fetchLog()); n != walked {
		t.Fatalf("a second walk went out %s after the first (floor %s): %d fetches", 6*time.Minute, refresh.DefaultFailureFloor, n-walked)
	}

	// A different network is new information: after a minute there, the
	// next pass walks again although neither floor has run out.
	if _, err := NetworkChanged("cell", "carrier-b", ""); err != nil {
		t.Fatal(err)
	}
	advanceClock(2 * time.Minute)
	r.c.kickLiveness()
	waitFor(t, "a walk on the new network", func() bool { return len(r.fetchLog()) > walked })
	waitFor(t, "the route to be running again", func() bool {
		return r.deadButRunning() && recoveryBlock(t)["state"] == RecoverUnreachable
	})
	rec = r.record(fixturePackID)
	if rec["consecutive_failures"] != nil || rec["last_failure_at"] != nil {
		t.Fatalf("scheduled back-off inflated: %v", rec)
	}
	if rec["on_failure_misses"] != float64(2) {
		t.Fatalf("on_failure_misses = %v, want 2", rec["on_failure_misses"])
	}
}

// THE GUARD IS NOT WEAKENED. With a route that carries, the person's
// button rides the tunnel or does not happen (no tunnel dialer here):
// no fetch, the route untouched, and the refused press does not use up
// the button's minute. The engine's own failure-triggered walk is
// refused outright while the guard is up, and stamps nothing.
func TestC0_GuardStillRefusesDirectFetchesWhileAHealthyRouteIsUp(t *testing.T) {
	r := newC0Rig(t)
	r.serveRotation()
	if res := r.connectAutoOrFail(); !res.Connected {
		t.Fatalf("premise: %+v", res)
	}
	for i := 0; i < 2; i++ {
		body, err := RelayPackRefresh("")
		if err != nil {
			t.Fatal(err)
		}
		var out RelayPackRefreshResult
		if err := json.Unmarshal([]byte(body), &out); err != nil {
			t.Fatal(err)
		}
		if out.Outcome != RecoverTunnelRequired || out.RoutePaused {
			t.Fatalf("press %d: %s", i+1, body)
		}
	}
	if n := len(r.fetchLog()); n != 0 {
		t.Fatalf("%d fetches left the device while a healthy route was up with no tunnel dialer", n)
	}
	if !r.connected() || !refresh.TunnelRequired() {
		t.Fatal("the press touched a healthy route")
	}
	res, err := r.rp.RefreshFailureTriggered(context.Background(), fixturePackID, activeNetworkID())
	if !errors.Is(err, refresh.ErrTunnelRequired) || res.Outcome != refresh.OutcomeFreshnessTunnel {
		t.Fatalf("failure-triggered walk under the guard: %+v %v", res, err)
	}
	if rec := r.record(fixturePackID); rec["on_failure_at"] != nil {
		t.Fatalf("a refused walk was stamped: %v", rec)
	}
	if n := len(r.fetchLog()); n != 0 {
		t.Fatalf("%d fetches under the guard", n)
	}
}

// The person's button on a route that is running and carrying nothing
// (picked by hand, so the automatic connect is not in charge): the
// instance is paused for the walk, the rotation is applied, the route is
// put back and checked at once — and carries.
func TestC0_ButtonOnADeadRouteFindsTheNewAddress(t *testing.T) {
	r := newC0Rig(t)
	rows, _ := r.c.store.ListRoutes()
	var pick string
	for _, row := range rows {
		if row.TransportFamily == "vless-reality" {
			pick = row.RouteID
		}
	}
	if pick == "" {
		t.Fatal("fixture has no vless-reality route")
	}
	if err := SetRoute(pick); err != nil {
		t.Fatal(err)
	}
	r.block(r.oldHost)
	r.c.kickLiveness()
	waitFor(t, "the route to be failed and running", r.deadButRunning)
	if !refresh.TunnelRequired() {
		t.Fatal("premise: a running route keeps the guard up")
	}
	r.serveRotation()
	body, err := RelayPackRefresh(fixturePackID)
	if err != nil {
		t.Fatal(err)
	}
	var out RelayPackRefreshResult
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if out.Outcome != RecoverUpdated || !out.RoutePaused || !out.Rechecking || len(out.Packs) != 1 || !out.Packs[0].Applied {
		t.Fatalf("press: %s", body)
	}
	waitFor(t, "the route to carry on its new address", func() bool {
		id, _ := r.c.activeRouteFromMemory()
		st, _, running := r.c.check.snapshot()
		return id == pick && running && st == RouteCheckOK && r.hostOf(id) == fixtureRotatedServer
	})
	for _, f := range r.fetchLog() {
		if f.routeActive || !f.window {
			t.Fatalf("a fetch went out with a route up or outside the window: %+v", f)
		}
	}
	// A second press inside the minute dials nothing and stops nothing.
	n := len(r.fetchLog())
	body, _ = RelayPackRefresh("")
	_ = json.Unmarshal([]byte(body), &out)
	if out.Outcome != RecoverRateLimited || out.RetryAfterS <= 0 || out.RoutePaused || len(r.fetchLog()) != n {
		t.Fatalf("second press: %s", body)
	}
}

// An unknown pack id is said, not guessed.
func TestC0_ButtonUnknownPack(t *testing.T) {
	newC0Rig(t)
	body, err := RelayPackRefresh("rp-nothing-like-it")
	if err != nil {
		t.Fatal(err)
	}
	var out RelayPackRefreshResult
	_ = json.Unmarshal([]byte(body), &out)
	if out.Outcome != RecoverUnknownPack || out.Packs == nil {
		t.Fatalf("%s", body)
	}
}

func (r *c0Rig) connectAutoOrFail() AutoResult {
	r.t.Helper()
	body, err := ConnectAuto()
	if err != nil {
		r.t.Fatal(err)
	}
	var res AutoResult
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		r.t.Fatal(err)
	}
	return res
}

// ---- review fixes (C0 review, 2026-11-20) -------------------------------

func (r *c0Rig) walks() uint64 {
	r.c.mu.Lock()
	defer r.c.mu.Unlock()
	return r.c.recover.seq
}

func (r *c0Rig) walking() bool {
	r.c.mu.Lock()
	defer r.c.mu.Unlock()
	return r.c.recover.done != nil
}

func (r *c0Rig) holdFetches() func() {
	r.mu.Lock()
	r.gate = make(chan struct{})
	g := r.gate
	r.mu.Unlock()
	var once sync.Once
	release := func() {
		once.Do(func() {
			r.mu.Lock()
			r.gate = nil
			r.mu.Unlock()
			close(g)
		})
	}
	r.t.Cleanup(release)
	return release
}

// waitSettled: no walk in flight and the dead route is running again.
func (r *c0Rig) waitSettled(what string) {
	r.t.Helper()
	waitFor(r.t, what, func() bool { return !r.walking() && r.deadButRunning() })
}

// REVIEW H1. A holder of a ONE-route file: the fall-over pass has no
// other candidate at all, and that is exactly when the walk is the only
// thing that can help. It walks, and when the first walk finds nothing
// the next one comes after its own floor — no other candidate needed.
func TestC0_OneRouteFileWalksAndRetries(t *testing.T) {
	r := newC0Rig(t)
	rows, _ := r.c.store.ListRoutes()
	for _, row := range rows[1:] {
		if err := r.c.store.DeleteRoute(row.RouteID); err != nil {
			t.Fatal(err)
		}
	}
	if res := r.connectAutoOrFail(); !res.Connected {
		t.Fatalf("premise: %+v", res)
	}
	r.block(r.oldHost)
	r.c.kickLiveness()
	waitFor(t, "a first walk", func() bool { return r.walks() >= 1 })
	r.waitSettled("the first walk to come back empty")
	if b := recoveryBlock(t); b["state"] != RecoverUnreachable || b["trigger"] != RecoverTriggerFailure {
		t.Fatalf("relay_recovery = %v", b)
	}
	if a := autoBlock(t); a["state"] != AutoStateFailed || a["verdict"] == AutoVerdictLookingForAddress || a["verdict"] == "" {
		t.Fatalf("auto after an empty walk = %v", a)
	}
	// Inside the floor: the dead route is checked again and again, and
	// nothing walks.
	advanceClock(5 * time.Minute)
	time.Sleep(100 * time.Millisecond)
	if n := r.walks(); n != 1 {
		t.Fatalf("%d walks inside the floor", n)
	}
	// The publisher rotates; the floor runs out: the second walk finds it.
	r.serveRotation()
	advanceClock(6 * time.Minute)
	r.c.kickLiveness()
	waitFor(t, "the one route to carry on its new address", func() bool {
		id, _ := r.c.activeRouteFromMemory()
		return r.connected() && r.hostOf(id) == fixtureRotatedServer
	})
	if n := r.walks(); n != 2 {
		t.Fatalf("walks = %d, want 2", n)
	}
}

// REVIEW H1, second half. A block that RESETS (not silence) charges the
// other routes' cooldowns, so later passes may have nothing to try; the
// walk's retry does not depend on them.
func TestC0_ANonSilentBlockStillRetriesTheWalk(t *testing.T) {
	r := newC0Rig(t)
	r.reset = true
	if res := r.connectAutoOrFail(); !res.Connected {
		t.Fatalf("premise: %+v", res)
	}
	r.block(r.oldHost)
	r.c.kickLiveness()
	waitFor(t, "a first walk", func() bool { return r.walks() >= 1 })
	r.waitSettled("the first walk to come back empty")
	r.serveRotation()
	advanceClock(refresh.DefaultFailureFloor + time.Minute)
	r.c.kickLiveness()
	waitFor(t, "the route to carry on its new address", func() bool {
		id, _ := r.c.activeRouteFromMemory()
		return r.connected() && r.hostOf(id) == fixtureRotatedServer
	})
}

// REVIEW H2. Wi-Fi ↔ cellular every 61 s for nine minutes (inside the
// first floor): one walk per network, not one per flap.
func TestC0_NetworkFlappingIsNotABeacon(t *testing.T) {
	r := newC0Rig(t)
	if _, err := NetworkChanged("wifi", "", "home"); err != nil {
		t.Fatal(err)
	}
	if res := r.connectAutoOrFail(); !res.Connected {
		t.Fatalf("premise: %+v", res)
	}
	r.block(r.oldHost)
	r.c.kickLiveness()
	waitFor(t, "a first walk", func() bool { return r.walks() >= 1 })
	r.waitSettled("the first walk to come back empty")
	for i := 0; i < 9; i++ {
		advanceClock(61 * time.Second)
		if i%2 == 0 {
			_, _ = NetworkChanged("cell", "carrier-b", "")
		} else {
			_, _ = NetworkChanged("wifi", "", "home")
		}
		time.Sleep(60 * time.Millisecond) // a few liveness checks
		r.waitSettled("the route to be back after the flap")
	}
	if n := r.walks(); n != 2 {
		t.Fatalf("nine minutes of flapping walked %d times, want 2 (one per network)", n)
	}
	if n := len(r.fetchLog()); n > 2*len(fixtureMirrors) {
		t.Fatalf("%d direct fetches in nine minutes of flapping", n)
	}
}

// REVIEW M1. A walk cut off by a disconnect gives its floor back, is not
// a miss, and is not recorded as "unreachable". The guard is down only
// because nothing is running any more.
func TestC0_ADisconnectMidWalkSpendsNothing(t *testing.T) {
	r := newC0Rig(t)
	release := r.holdFetches()
	if res := r.connectAutoOrFail(); !res.Connected {
		t.Fatalf("premise: %+v", res)
	}
	r.block(r.oldHost)
	r.c.kickLiveness()
	waitFor(t, "the walk's first fetch", func() bool { return len(r.fetchLog()) > 0 })
	if err := ClearRoute(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the walk to end", func() bool { return !r.walking() })
	release()
	rec := r.record(fixturePackID)
	if rec["on_failure_at"] != nil || rec["on_failure_misses"] != nil || rec["last_outcome"] == refresh.OutcomeFreshnessUnreachable {
		t.Fatalf("a cancelled walk spent the floor or counted as a miss: %v", rec)
	}
	if b := recoveryBlock(t); b["state"] != RecoverCancelled {
		t.Fatalf("relay_recovery = %v", b)
	}
	if refresh.RecoveryWindowOpen() || refresh.TunnelRequired() {
		t.Fatal("after a disconnect nothing is running: no window, no guard")
	}
	if id, _ := r.c.activeRouteFromMemory(); id != "" {
		t.Fatalf("a cancelled walk put route %s back", id)
	}
}

// REVIEW M2, M4, M6. While the walk has the dead route paused:
//   - every ordinary fetcher still sees the guard (bootstrap refuses, the
//     scheduled poll of the same pack is busy and dials nothing);
//   - the button answers in_progress and stops nothing;
//   - engine_connect_auto answers AT ONCE: looking_for_address, trying.
func TestC0_DuringTheWalk(t *testing.T) {
	r := newC0Rig(t)
	release := r.holdFetches()
	if res := r.connectAutoOrFail(); !res.Connected {
		t.Fatalf("premise: %+v", res)
	}
	r.block(r.oldHost)
	r.c.kickLiveness()
	waitFor(t, "the walk's first fetch", func() bool { return len(r.fetchLog()) > 0 })
	n := len(r.fetchLog())

	if !refresh.TunnelRequired() || refresh.RouteActive() || !refresh.RecoveryWindowOpen() {
		t.Fatalf("window: TunnelRequired=%v RouteActive=%v open=%v", refresh.TunnelRequired(), refresh.RouteActive(), refresh.RecoveryWindowOpen())
	}
	if _, ok := bootstrapDialer().(refusingDialer); !ok {
		t.Fatalf("bootstrap got %T beside the walk", bootstrapDialer())
	}
	if res, _ := r.rp.Refresh(context.Background(), fixturePackID); res.Outcome != refresh.OutcomeFreshnessRateLimited {
		t.Fatalf("scheduled poll beside the walk: %+v", res)
	}
	body, _ := RelayPackRefresh("")
	var press RelayPackRefreshResult
	_ = json.Unmarshal([]byte(body), &press)
	if press.Outcome != RecoverInProgress || press.RoutePaused {
		t.Fatalf("button beside the walk: %s", body)
	}
	start := time.Now()
	res := r.connectAutoOrFail()
	if res.Verdict != AutoVerdictLookingForAddress || res.Connected || time.Since(start) > time.Second {
		t.Fatalf("connect_auto beside the walk: %+v after %s", res, time.Since(start))
	}
	if a := autoBlock(t); a["state"] != AutoStateTrying || a["verdict"] != AutoVerdictLookingForAddress || a["mode"] != true {
		t.Fatalf("auto beside the walk = %v", a)
	}
	if b := recoveryBlock(t); b["state"] != RecoverLooking {
		t.Fatalf("relay_recovery = %v", b)
	}
	if got := len(r.fetchLog()); got != n {
		t.Fatalf("%d fetches beside the walk", got-n)
	}

	release()
	r.waitSettled("the empty walk to put the route back")
	if a := autoBlock(t); a["state"] != AutoStateFailed || a["verdict"] == AutoVerdictLookingForAddress {
		t.Fatalf("auto after the walk = %v", a)
	}
	if refresh.RecoveryWindowOpen() || !refresh.TunnelRequired() || !refresh.RouteActive() {
		t.Fatal("after the walk the route is back and the guard is up")
	}
}

// REVIEW M5. lifeline-strict is "nothing unless I ask": the engine does
// not walk by itself there; the person's button still does.
func TestC0_LifelineStrictWalksOnlyOnTheButton(t *testing.T) {
	r := newC0Rig(t)
	if res := r.connectAutoOrFail(); !res.Connected {
		t.Fatalf("premise: %+v", res)
	}
	if err := SetMode("lifeline-strict"); err != nil {
		t.Fatal(err)
	}
	r.block(r.oldHost)
	r.c.kickLiveness()
	waitFor(t, "a fall-over pass", func() bool { return r.fallPasses() >= 1 })
	waitFor(t, "the route to be running again", r.deadButRunning)
	time.Sleep(60 * time.Millisecond)
	if n := r.walks(); n != 0 || len(r.fetchLog()) != 0 {
		t.Fatalf("lifeline-strict: %d walks, %d fetches", n, len(r.fetchLog()))
	}
	r.serveRotation()
	body, _ := RelayPackRefresh("")
	var out RelayPackRefreshResult
	_ = json.Unmarshal([]byte(body), &out)
	if out.Outcome != RecoverUpdated || !out.RoutePaused {
		t.Fatalf("the button in lifeline-strict: %s", body)
	}
}

// REVIEW L4. Shutdown cuts a walk off and waits for it to let go of the
// store.
func TestC0_ShutdownDuringTheWalk(t *testing.T) {
	r := newC0Rig(t)
	r.holdFetches()
	if res := r.connectAutoOrFail(); !res.Connected {
		t.Fatalf("premise: %+v", res)
	}
	r.block(r.oldHost)
	r.c.kickLiveness()
	waitFor(t, "the walk's first fetch", func() bool { return len(r.fetchLog()) > 0 })
	start := time.Now()
	if err := Shutdown(); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) >= recoverShutdownWait {
		t.Fatalf("Shutdown waited %s: the walk did not end on its cancel", time.Since(start))
	}
	if refresh.RecoveryWindowOpen() {
		t.Fatal("Shutdown left the recovery window open")
	}
}

// REVIEW M3. A hand-picked route (no automatic walk) goes dead with a
// tunnel dialer installed: the scheduled poll does not ride the dead
// tunnel, does not escalate, and does not try the pointer layer — so the
// first poll after the person disconnects is not hours away.
func TestC0_ScheduledPollOverADeadTunnelDoesNotEscalate(t *testing.T) {
	r := newC0Rig(t)
	rows, _ := r.c.store.ListRoutes()
	if err := SetRoute(rows[0].RouteID); err != nil {
		t.Fatal(err)
	}
	if _, err := SetTunnelSocks("127.0.0.1", 1, "", ""); err != nil {
		t.Fatal(err)
	}
	r.block(r.oldHost)
	r.c.kickLiveness()
	waitFor(t, "the route to be failed and running", r.deadButRunning)
	for i := 0; i < 3; i++ {
		res, _ := r.rp.Refresh(context.Background(), fixturePackID)
		if res.Outcome != refresh.OutcomeFreshnessTunnel && res.Outcome != refresh.OutcomeFreshnessRateLimited {
			t.Fatalf("poll %d over a dead tunnel: %+v", i+1, res)
		}
		advanceClock(7 * time.Hour)
	}
	if n := len(r.fetchLog()); n != 0 {
		t.Fatalf("%d fetches through a dead tunnel", n)
	}
	rec := r.record(fixturePackID)
	if rec["consecutive_failures"] != nil || rec["last_failure_at"] == nil {
		t.Fatalf("dead tunnel: %v (want a stamp, no escalation)", rec)
	}
	if rec["last_outcome"] != refresh.OutcomeFreshnessTunnel {
		t.Fatalf("last_outcome = %v", rec["last_outcome"])
	}
}
