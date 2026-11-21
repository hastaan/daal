package refresh

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"daal/core/bootstrap"
)

// The unscheduled kinds (relaypack_recover.go): what they bypass, what
// they must not touch, and the guard they never get around.

func recoverFixture(t *testing.T) (*RelayPackRefresher, *fakeRelayStore, *scriptedFetch, *time.Time) {
	t.Helper()
	t.Cleanup(func() { SetTunnelRequired(false); SetGlobalDialer(nil) })
	SetTunnelRequired(false)
	SetGlobalDialer(nil)
	r, store, sf, _, _ := newRelayFixture(t, []string{"https://a.example.com/f.json", "https://b.example.com/f.json"})
	now := time.Now().UTC().Truncate(time.Second)
	r.Now = func() time.Time { return now }
	r.DirectDialer = DialerFn(func() (bootstrap.Dialer, bool, error) { return bootstrap.NewDirectDialer(time.Second), false, nil })
	return r, store, sf, &now
}

// A dead relay is not a reason to escalate the mirrors' cadence: the
// failure-triggered walk bypasses the cadence floor, and an empty-handed
// walk leaves LastFailureAt / ConsecutiveFailures alone. lifeline-strict
// ("nothing unless I ask") is NOT bypassed by the engine's own walk.
func TestFailureTriggered_BypassesFloorAndDoesNotInflate(t *testing.T) {
	r, _, sf, now := recoverFixture(t)
	pointerWalks := 0
	r.Recover = func(context.Context) (string, error) { pointerWalks++; return "", nil }
	// A scheduled poll a minute ago: the cadence floor is closed.
	r.saveRecord("rp-1", freshnessRecord{V: 1, LastSuccessAt: now.Add(-time.Minute).Format(time.RFC3339)})
	if res, _ := r.Refresh(context.Background(), "rp-1"); res.Outcome != OutcomeFreshnessRateLimited {
		t.Fatalf("premise: scheduled = %q", res.Outcome)
	}

	r.Mode = "lifeline-strict"
	if res, _ := r.RefreshFailureTriggered(context.Background(), "rp-1", "net-a"); res.Outcome != SkippedLifelineStrict || len(sf.tried()) != 0 {
		t.Fatalf("lifeline-strict: the engine's own walk ran: %+v fetches=%d", res, len(sf.tried()))
	}
	if rec := r.loadRecord("rp-1"); rec.OnFailureAt != "" {
		t.Fatalf("a skipped walk was stamped: %+v", rec)
	}
	r.Mode = ""

	res, err := r.RefreshFailureTriggered(context.Background(), "rp-1", "net-a")
	if err == nil || res.Outcome != OutcomeFreshnessUnreachable || res.Kind != "failure" {
		t.Fatalf("res %+v err %v", res, err)
	}
	if len(sf.tried()) != 2 {
		t.Fatalf("walk tried %v", sf.tried())
	}
	rec := r.loadRecord("rp-1")
	if rec.ConsecutiveFailures != 0 || rec.LastFailureAt != "" {
		t.Fatalf("scheduled back-off inflated: %+v", rec)
	}
	if rec.OnFailureMisses != 1 || rec.OnFailureAt == "" || len(rec.OnFailureNets) != 1 || rec.OnFailureNets[0].Misses != 1 ||
		rec.OnFailureNets[0].Tag == "" || rec.OnFailureNets[0].Tag == "net-a" || len(rec.OnFailureLog) != 1 {
		t.Fatalf("own bookkeeping: %+v (the network is stored as a tag, never as given)", rec)
	}
	if res.Recovered || pointerWalks != 0 {
		t.Fatal("the failure-triggered walk went on to the pointer layer")
	}
}

// Bounded: once per floor per pack on one network; the floor doubles per
// empty walk up to the cap; another network opens it after a minute.
func TestFailureTriggered_FloorEscalatesAndANewNetworkOpensIt(t *testing.T) {
	r, _, sf, now := recoverFixture(t)
	ctx := context.Background()
	_, _ = r.RefreshFailureTriggered(ctx, "rp-1", "net-a")
	n := len(sf.tried())

	*now = now.Add(DefaultFailureFloor - time.Second)
	res, err := r.RefreshFailureTriggered(ctx, "rp-1", "net-a")
	if err != nil || res.Outcome != OutcomeFreshnessRateLimited || res.RetryAfterS != 1 || len(sf.tried()) != n {
		t.Fatalf("inside the floor: %+v %v (fetches %d→%d)", res, err, n, len(sf.tried()))
	}
	*now = now.Add(time.Second)
	_, _ = r.RefreshFailureTriggered(ctx, "rp-1", "net-a")
	if len(sf.tried()) == n {
		t.Fatal("the floor did not open")
	}
	// Two empty walks: the floor is now 2× the base.
	*now = now.Add(DefaultFailureFloor + time.Second)
	if due, wait := r.FailureTriggeredDue("rp-1", "net-a"); due || wait <= 0 {
		t.Fatalf("after two empty walks the floor should be %s: due=%v wait=%s", 2*DefaultFailureFloor, due, wait)
	}
	// ...but another network is new information.
	if due, _ := r.FailureTriggeredDue("rp-1", "net-b"); !due {
		t.Fatal("a different network did not open the floor")
	}
	*now = now.Add(-DefaultFailureFloor) // a few seconds after the last walk
	if due, _ := r.FailureTriggeredDue("rp-1", "net-b"); due {
		t.Fatal("a network flap opened the floor at once")
	}
	if r.failureFloor(50) != MaxFailureFloor {
		t.Fatalf("cap: %s", r.failureFloor(50))
	}
}

// A clock that jumped backwards must not freeze recovery.
func TestFailureTriggered_FutureStampIsNotAFloor(t *testing.T) {
	r, _, _, now := recoverFixture(t)
	r.saveRecord("rp-1", freshnessRecord{V: 1, OnFailureAt: now.Add(48 * time.Hour).Format(time.RFC3339)})
	if due, _ := r.FailureTriggeredDue("rp-1", "net-a"); !due {
		t.Fatal("a stamp in the future held the walk back")
	}
}

// THE GUARD. While a route is active the failure-triggered walk does not
// happen, is not stamped, and does not escalate anything.
func TestFailureTriggered_RefusedWhileARouteIsActive(t *testing.T) {
	r, store, sf, _ := recoverFixture(t)
	SetTunnelRequired(true)
	SetGlobalDialer(func() (bootstrap.Dialer, bool, error) { return bootstrap.NewDirectDialer(time.Second), true, nil })
	res, err := r.RefreshFailureTriggered(context.Background(), "rp-1", "net-a")
	if !errors.Is(err, ErrTunnelRequired) || res.Outcome != OutcomeFreshnessTunnel {
		t.Fatalf("%+v %v", res, err)
	}
	if len(sf.tried()) != 0 {
		t.Fatal("a fetch happened under the guard")
	}
	if rec := r.loadRecord("rp-1"); rec.OnFailureAt != "" || rec.ConsecutiveFailures != 0 {
		t.Fatalf("a refused walk left a mark: %+v", rec)
	}
	if outcomeOf(store) != OutcomeFreshnessTunnel {
		t.Fatalf("audit %q", outcomeOf(store))
	}
}

// The walk's dialer re-asks the guard on every dial: a route that comes
// up half-way through turns the rest of the walk into refusals.
func TestDirectDial_RefusesOnceARouteComesUp(t *testing.T) {
	r, _, _, _ := recoverFixture(t)
	called := 0
	r.DirectDialer = DialerFn(func() (bootstrap.Dialer, bool, error) {
		return dialFunc(func(context.Context, string, string) (net.Conn, error) {
			called++
			return nil, errors.New("would dial")
		}), false, nil
	})
	d, err := r.directDial()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.DialContext(context.Background(), "tcp", "192.0.2.1:443"); err == nil || errors.Is(err, ErrTunnelRequired) || called != 1 {
		t.Fatalf("no route: err=%v called=%d", err, called)
	}
	SetTunnelRequired(true)
	if _, err := d.DialContext(context.Background(), "tcp", "192.0.2.1:443"); !errors.Is(err, ErrTunnelRequired) || called != 1 {
		t.Fatalf("route up: err=%v called=%d", err, called)
	}
	if _, err := r.directDial(); !errors.Is(err, ErrTunnelRequired) {
		t.Fatalf("directDial under the guard: %v", err)
	}
}

type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

func (f dialFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

// An applied pack resets the escalation of the failure-triggered floor,
// and is a success for the scheduled poll too.
func TestFailureTriggered_AppliedPackResetsTheMisses(t *testing.T) {
	t.Cleanup(func() { SetTunnelRequired(false); SetGlobalDialer(nil) })
	SetTunnelRequired(false)
	SetGlobalDialer(nil)
	r, store, sf, pub, priv := newRelayFixture(t, []string{"https://a.example.com/f.json", "https://b.example.com/f.json"})
	now := time.Now().UTC()
	r.saveRecord("rp-1", freshnessRecord{V: 1, OnFailureMisses: 3, ConsecutiveFailures: 2,
		LastFailureAt: now.Add(-time.Hour).Format(time.RFC3339)})
	packBody := makePackSBP(t, pub, priv, []string{"r-1"}, now)
	packURL := "https://packs.example.com/current.sbp"
	sf.bodies[packURL] = packBody
	doc := servedDoc(t, pub, priv, func(d *FreshnessDocument) {
		d.CurrentBundleSHA256 = sha256Hex(packBody)
		d.CurrentSignedURL = packURL
	})
	sf.bodies["https://a.example.com/f.json"] = doc
	sf.bodies["https://b.example.com/f.json"] = doc
	res, err := r.RefreshFailureTriggered(context.Background(), "rp-1", "net-a")
	if err != nil || !res.Applied || res.Outcome != OutcomeFreshnessOK {
		t.Fatalf("%+v %v", res, err)
	}
	if rec := r.loadRecord(res.RelayPackID); rec.OnFailureMisses != 0 || rec.ConsecutiveFailures != 0 || rec.LastSuccessAt == "" {
		t.Fatalf("after an applied pack: %+v", rec)
	}
	if store.saveCalls == 0 {
		t.Fatal("the importer never wrote the pack")
	}
}

// A refused scheduled poll (route up, no tunnel dialer) keeps its stamp
// but no longer escalates: nothing reached the network.
func TestScheduled_TunnelRefusalDoesNotEscalate(t *testing.T) {
	r, _, _, _ := recoverFixture(t)
	r.Dialer = nil
	SetTunnelRequired(true)
	for i := 0; i < 3; i++ {
		res, err := r.RefreshUser(context.Background(), "rp-1")
		if !errors.Is(err, ErrTunnelRequired) || res.Outcome != OutcomeFreshnessTunnel {
			t.Fatalf("%+v %v", res, err)
		}
	}
	rec := r.loadRecord("rp-1")
	if rec.ConsecutiveFailures != 0 || rec.LastFailureAt == "" {
		t.Fatalf("refusals: %+v (want a stamp, no escalation)", rec)
	}
}

// The person's button: one walk a minute per pack; a press the guard
// refuses does not use the minute; with no route it dials direct even
// when a stale tunnel dialer is still installed.
func TestOnDemand_FloorGuardAndDirectWhenNoRoute(t *testing.T) {
	r, _, sf, now := recoverFixture(t)
	r.Dialer = nil
	ctx := context.Background()

	SetTunnelRequired(true)
	if res, err := r.RefreshOnDemand(ctx, "rp-1"); !errors.Is(err, ErrTunnelRequired) || res.Outcome != OutcomeFreshnessTunnel {
		t.Fatalf("under the guard: %+v %v", res, err)
	}
	if len(sf.tried()) != 0 || r.loadRecord("rp-1").OnDemandAt != "" {
		t.Fatal("a refused press fetched or used up the minute")
	}

	SetTunnelRequired(false)
	stale := 0
	SetGlobalDialer(func() (bootstrap.Dialer, bool, error) { stale++; return nil, true, errors.New("dead inlet") })
	res, _ := r.RefreshOnDemand(ctx, "rp-1")
	if res.Outcome != OutcomeFreshnessUnreachable || res.ViaTunnel || stale != 0 || len(sf.tried()) != 2 {
		t.Fatalf("no route: %+v stale-dialer calls=%d fetches=%d", res, stale, len(sf.tried()))
	}
	if rec := r.loadRecord("rp-1"); rec.ConsecutiveFailures != 0 || rec.LastFailureAt != "" {
		t.Fatalf("a press escalated the scheduled poll: %+v", rec)
	}
	*now = now.Add(30 * time.Second)
	if res, _ := r.RefreshOnDemand(ctx, "rp-1"); res.Outcome != OutcomeFreshnessRateLimited || res.RetryAfterS != 30 || len(sf.tried()) != 2 {
		t.Fatalf("second press: %+v", res)
	}
	*now = now.Add(30 * time.Second)
	if res, _ := r.RefreshOnDemand(ctx, "rp-1"); res.Outcome == OutcomeFreshnessRateLimited {
		t.Fatal("the minute did not open")
	}
}

// REVIEW H2. A phone flapping between Wi-Fi and cellular every 61 s must
// not walk once a minute: each network keeps its own escalating floor,
// and a hard ceiling holds whatever the networks.
func TestFailureTriggered_FlappingNetworksAreHeldToTheirOwnFloorsAndACeiling(t *testing.T) {
	r, _, sf, now := recoverFixture(t)
	ctx := context.Background()
	walks := 0
	nets := []string{"wifi", "cell"}
	for i := 0; i < 10; i++ { // ~10 minutes of flapping
		before := len(sf.tried())
		_, _ = r.RefreshFailureTriggered(ctx, "rp-1", nets[i%2])
		if len(sf.tried()) > before {
			walks++
		}
		*now = now.Add(61 * time.Second)
	}
	if walks != 2 {
		t.Fatalf("10 minutes of Wi-Fi/cell flapping walked %d times, want 2 (one per network)", walks)
	}
	// Many networks (more than the per-network memory): the ceiling.
	walks = 0
	for i := 0; i < 60; i++ { // an hour, a new network every minute
		before := len(sf.tried())
		_, _ = r.RefreshFailureTriggered(ctx, "rp-1", "net-"+string(rune('a'+i%26))+string(rune('a'+i/26)))
		if len(sf.tried()) > before {
			walks++
		}
		*now = now.Add(61 * time.Second)
	}
	if walks > failureHourCeiling+1 { // the window straddles two hours at most once
		t.Fatalf("an hour of new networks walked %d times (ceiling %d an hour)", walks, failureHourCeiling)
	}
	rec := r.loadRecord("rp-1")
	if len(rec.OnFailureNets) > failureNetsMax || len(rec.OnFailureLog) > failureDayCeiling {
		t.Fatalf("bookkeeping unbounded: nets=%d log=%d", len(rec.OnFailureNets), len(rec.OnFailureLog))
	}
	// A day of it: at most the day ceiling.
	total := len(rec.OnFailureLog)
	for i := 0; i < 24*60; i++ {
		_, _ = r.RefreshFailureTriggered(ctx, "rp-1", "z-"+time.Duration(i).String())
		*now = now.Add(time.Minute)
		if l := len(pruneFailureLog(r.loadRecord("rp-1").OnFailureLog, *now)); l > failureDayCeiling {
			t.Fatalf("%d walks inside 24 h (ceiling %d)", l, failureDayCeiling)
		}
	}
	_ = total
}

// REVIEW M1. A walk cut off from outside (Disconnect, a hand-picked
// route, a newer pass, Shutdown) gives its floor back, is not a miss, and
// is never recorded as "unreachable".
func TestFailureTriggered_CancelledWalkGivesTheFloorBack(t *testing.T) {
	r, store, sf, _ := recoverFixture(t)
	sf.hang["https://a.example.com/f.json"] = true
	sf.hang["https://b.example.com/f.json"] = true
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for len(sf.tried()) == 0 {
			time.Sleep(time.Millisecond)
		}
		cancel()
	}()
	res, _ := r.RefreshFailureTriggered(ctx, "rp-1", "net-a")
	if res.Outcome != OutcomeFreshnessCancelled {
		t.Fatalf("outcome %q, want %q", res.Outcome, OutcomeFreshnessCancelled)
	}
	rec := r.loadRecord("rp-1")
	if rec.OnFailureAt != "" || rec.OnFailureMisses != 0 || len(rec.OnFailureNets) != 0 || rec.LastOutcome == OutcomeFreshnessUnreachable {
		t.Fatalf("a cancelled walk spent the floor or counted as a miss: %+v", rec)
	}
	if len(rec.OnFailureLog) != 1 {
		t.Fatalf("the ceiling must still count a walk that went out: %+v", rec.OnFailureLog)
	}
	if outcomeOf(store) == OutcomeFreshnessUnreachable {
		t.Fatal("audit says unreachable for a cancel")
	}
	if due, _ := r.FailureTriggeredDue("rp-1", "net-a"); !due {
		t.Fatal("the next real outage waits for a walk that learned nothing")
	}
}

// REVIEW M3. The scheduled poll rides the tunnel dialer of a route whose
// check has failed: it does not dial through the dead tunnel, does not
// escalate, and does not reach for the pointer layer.
func TestScheduled_DeadTunnelDoesNotEscalate(t *testing.T) {
	r, _, sf, now := recoverFixture(t)
	SetTunnelRequired(true)
	tunnelCalls := 0
	SetGlobalDialer(func() (bootstrap.Dialer, bool, error) {
		tunnelCalls++
		return bootstrap.NewDirectDialer(time.Second), true, nil
	})
	healthy := false
	r.TunnelHealthy = func() bool { return healthy }
	pointer := 0
	r.Recover = func(context.Context) (string, error) { pointer++; return "", nil }
	for i := 0; i < 3; i++ {
		res, _ := r.Refresh(context.Background(), "rp-1")
		if res.Outcome != OutcomeFreshnessTunnel && res.Outcome != OutcomeFreshnessRateLimited {
			t.Fatalf("poll %d: %+v", i, res)
		}
		*now = now.Add(48 * time.Hour)
	}
	rec := r.loadRecord("rp-1")
	if rec.ConsecutiveFailures != 0 || rec.LastFailureAt == "" || len(sf.tried()) != 0 || pointer != 0 {
		t.Fatalf("dead tunnel: rec=%+v fetches=%d pointer=%d", rec, len(sf.tried()), pointer)
	}
	if tunnelCalls == 0 {
		t.Fatal("premise: the tunnel dialer was never chosen")
	}
	// The tunnel carries again: the poll rides it.
	healthy = true
	if res, _ := r.Refresh(context.Background(), "rp-1"); !res.ViaTunnel || len(sf.tried()) == 0 {
		t.Fatalf("healthy tunnel: %+v fetches=%d", res, len(sf.tried()))
	}
}

// REVIEW M2. While the engine has paused a dead route for its walk (the
// recovery window), every ordinary fetcher still sees TunnelRequired:
// the scheduled poll is refused without a dial, the stale tunnel dialer
// is not consulted, and the walk's own direct dialer is the only one.
func TestRecoveryWindow_OnlyTheWalkLeavesDirect(t *testing.T) {
	r, _, sf, _ := recoverFixture(t)
	t.Cleanup(func() { SetRecoveryWindow(false) })
	stale := 0
	SetGlobalDialer(func() (bootstrap.Dialer, bool, error) { stale++; return nil, true, errors.New("dead inlet") })
	SetTunnelRequired(false)
	SetRecoveryWindow(true)
	if !TunnelRequired() || RouteActive() {
		t.Fatalf("window: TunnelRequired=%v RouteActive=%v", TunnelRequired(), RouteActive())
	}
	if _, _, err := directFallback(); !errors.Is(err, ErrTunnelRequired) {
		t.Fatalf("an ordinary fetcher got a direct dialer inside the window: %v", err)
	}
	res, err := r.Refresh(context.Background(), "rp-1")
	if !errors.Is(err, ErrTunnelRequired) || res.Outcome != OutcomeFreshnessTunnel || len(sf.tried()) != 0 || stale != 0 {
		t.Fatalf("scheduled inside the window: %+v %v fetches=%d stale=%d", res, err, len(sf.tried()), stale)
	}
	if rec := r.loadRecord("rp-1"); rec.ConsecutiveFailures != 0 {
		t.Fatalf("a refused poll escalated: %+v", rec)
	}
	res, _ = r.RefreshFailureTriggered(context.Background(), "rp-1", "net-a")
	if res.Outcome != OutcomeFreshnessUnreachable || res.ViaTunnel || stale != 0 || len(sf.tried()) != 2 {
		t.Fatalf("the walk inside the window: %+v fetches=%d stale=%d", res, len(sf.tried()), stale)
	}
}

// REVIEW M4. One attempt per pack at a time: a second one beside a walk
// in flight returns at once, stamps nothing and dials nothing.
func TestPackLock_ASecondAttemptBesideAWalkDoesNothing(t *testing.T) {
	r, _, sf, _ := recoverFixture(t)
	sf.hang["https://a.example.com/f.json"] = true
	sf.hang["https://b.example.com/f.json"] = true
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _, _ = r.RefreshFailureTriggered(ctx, "rp-1", "net-a"); close(done) }()
	for len(sf.tried()) == 0 {
		time.Sleep(time.Millisecond)
	}
	n := len(sf.tried())
	for _, f := range []func() (RelayPackResult, error){
		func() (RelayPackResult, error) { return r.Refresh(context.Background(), "rp-1") },
		func() (RelayPackResult, error) { return r.RefreshOnDemand(context.Background(), "rp-1") },
		func() (RelayPackResult, error) { return r.RefreshFailureTriggered(context.Background(), "rp-1", "net-b") },
	} {
		res, err := f()
		if err != nil || res.Outcome != OutcomeFreshnessRateLimited || res.RetryAfterS <= 0 {
			t.Fatalf("beside a walk: %+v %v", res, err)
		}
	}
	if len(sf.tried()) != n {
		t.Fatal("a second attempt dialled beside the first")
	}
	if rec := r.loadRecord("rp-1"); rec.OnDemandAt != "" {
		t.Fatalf("a busy press was stamped: %+v", rec)
	}
	cancel()
	<-done
}

// REVIEW L3. The button's floor escalates on presses in a row that found
// nothing new: 1, 2, then 5 minutes.
func TestOnDemand_FloorEscalates(t *testing.T) {
	r, _, sf, now := recoverFixture(t)
	ctx := context.Background()
	wants := []time.Duration{time.Minute, 2 * time.Minute, 5 * time.Minute, 5 * time.Minute}
	for i, want := range wants {
		n := len(sf.tried())
		if res, _ := r.RefreshOnDemand(ctx, "rp-1"); len(sf.tried()) == n {
			t.Fatalf("press %d did not walk: %+v", i+1, res)
		}
		*now = now.Add(want - time.Second)
		if due, _ := r.OnDemandDue("rp-1"); due {
			t.Fatalf("after press %d the floor is shorter than %s", i+1, want)
		}
		*now = now.Add(time.Second)
		if due, _ := r.OnDemandDue("rp-1"); !due {
			t.Fatalf("after press %d the floor is longer than %s", i+1, want)
		}
	}
	// An hour later the count starts again.
	*now = now.Add(time.Hour)
	_, _ = r.RefreshOnDemand(ctx, "rp-1")
	*now = now.Add(time.Minute)
	if due, _ := r.OnDemandDue("rp-1"); !due {
		t.Fatal("the streak survived an hour")
	}
}
