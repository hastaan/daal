//go:build singbox

package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	boxoption "github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Side probes on the REAL embedded sing-box. The relays are local HTTP
// CONNECT proxies (connectProxy) and the far side a local TLS server:
// everything a side probe does except leave the machine.

func httpRoute(port int) string {
	return fmt.Sprintf(`{"type":"http","server":"127.0.0.1","server_port":%d}`, port)
}

func tlsTarget(t *testing.T) string {
	t.Helper()
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(target.Close)
	return target.Listener.Addr().String()
}

// runningDriver is a singBox driver whose tunnel instance is a real
// sing-box started from the engine's own config for `profile` — minus
// the TUN inbound, which needs a kernel device no unit test has.
func runningDriver(t *testing.T, profile string) *singBox {
	t.Helper()
	sub, cancel := startTestSubject(t, profile)
	s := newSingBox()
	s.instance, s.kind, s.twin, s.cancel = sub.inst, sub.kind, sub.twin, cancel
	s.Stub.connected = true
	t.Cleanup(func() { _ = s.Stop() })
	return s
}

func openFDs(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("cannot count fds here: %v", err)
	}
	return len(ents)
}

// settles waits for count() to come back down to want.
func settles(count func() int, want int) (int, bool) {
	deadline := time.Now().Add(5 * time.Second)
	got := count()
	for got > want && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		got = count()
	}
	return got, got <= want
}

// swallowingRelay is silentRelay without the bookkeeping that would hide
// a leak here: it answers nothing, and lets go of a connection the
// moment the client does — so every descriptor still open after a probe
// is the probe's own.
func swallowingRelay(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(io.Discard, c) }()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// echoServer answers every line with the same line.
func echoServer(t *testing.T) *net.TCPAddr {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return ln.Addr().(*net.TCPAddr)
}

// THE property the design rests on: route A carries through the
// driver's instance, route B is proved in a side instance, and A is
// exactly as it was — the same instance, a connection that was open
// through it still moving, its own proof still passing.
func TestSideProbe_LeavesTheRunningRouteCarrying(t *testing.T) {
	target := tlsTarget(t)
	proxyA, tunnelsA := connectProxy(t)
	proxyB, tunnelsB := connectProxy(t)
	echo := echoServer(t)

	s := runningDriver(t, httpRoute(proxyA.Port))
	if res := s.Prove(context.Background(), quickProof(target)); !res.OK {
		t.Fatalf("premise: route A does not carry: %+v (%v)", res, res.Err)
	}
	instA := s.instance
	// An app connection through A, open across the whole side probe.
	ob, _ := instA.Outbound().Outbound(activeTag)
	app, err := ob.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddrHostPort("127.0.0.1", uint16(echo.Port)))
	if err != nil {
		t.Fatalf("premise: no connection through A: %v", err)
	}
	defer app.Close()
	roundTrip := func(when string) {
		t.Helper()
		_ = app.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := app.Write([]byte("ping\n")); err != nil {
			t.Fatalf("%s: the connection through A is dead: %v", when, err)
		}
		buf := make([]byte, 5)
		if _, err := io.ReadFull(app, buf); err != nil || string(buf) != "ping\n" {
			t.Fatalf("%s: the connection through A no longer carries: %q %v", when, buf, err)
		}
	}
	roundTrip("before the side probe")
	inletBefore := CurrentRefreshInlet()

	tunnelsABefore := tunnelsA.Load()
	res, err := s.SideProbe(context.Background(), sideCfgFor(t, "other", httpRoute(proxyB.Port)), quickProof(target))
	if err != nil || !res.OK {
		t.Fatalf("the side probe of a working route B did not prove: %+v err=%v", res, err)
	}
	if tunnelsB.Load() == 0 {
		t.Fatal("the side probe succeeded without relay B carrying it")
	}
	if tunnelsA.Load() != tunnelsABefore {
		t.Fatal("the side probe of B went through relay A")
	}

	if s.instance != instA {
		t.Fatal("the side probe replaced the driver's instance")
	}
	roundTrip("after the side probe")
	if res := s.Prove(context.Background(), quickProof(target)); !res.OK {
		t.Fatalf("route A stopped proving after a side probe of B: %+v (%v)", res, res.Err)
	}
	if got := CurrentRefreshInlet(); (got == nil) != (inletBefore == nil) || (got != nil && *got != *inletBefore) {
		t.Fatal("the side probe changed the published refresh inlet")
	}
	if n := s.SideProbesInFlight(); n != 0 {
		t.Fatalf("%d side probes in flight after SideProbe returned", n)
	}
}

// Two side probes at once; the one that proves wins and the other is
// stopped. Afterwards nothing is left: no instance in flight, no file
// descriptor, no goroutine. And a third at the same time is refused.
func TestSideProbe_TwoRunConcurrentlyAndTheLoserLeavesNothing(t *testing.T) {
	target := tlsTarget(t)
	proxyA, _ := connectProxy(t)
	proxyB, _ := connectProxy(t)
	dead := swallowingRelay(t)
	s := runningDriver(t, httpRoute(proxyA.Port))
	cfgB := sideCfgFor(t, "other", httpRoute(proxyB.Port))
	cfgDead := sideCfgFor(t, "vless-reality", fmt.Sprintf(muxedVless, dead))
	slow := ProofConfig{Targets: []string{target}, AttemptTimeout: 20 * time.Second, Attempts: 1, SlowAfter: time.Second}

	// Warm everything that allocates once per process (the registries,
	// the resolver, the TLS session of the target).
	if res, err := s.SideProbe(context.Background(), cfgB, quickProof(target)); err != nil || !res.OK {
		t.Fatalf("premise: %+v %v", res, err)
	}
	fdsBefore := openFDs(t)
	goBefore := runtime.NumGoroutine()
	startedBefore, closedBefore := sideInstancesStarted.Load(), sideInstancesClosed.Load()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	var loser ProofResult
	var loserErr error
	loserDone := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(loserDone)
		loser, loserErr = s.SideProbe(ctx, cfgDead, slow)
	}()
	deadline := time.Now().Add(3 * time.Second)
	for s.SideProbesInFlight() < 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	// The third, while two would be in flight: hold a second slot open
	// with another hanging probe for the length of the check.
	ctx2, cancel2 := context.WithCancel(context.Background())
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = s.SideProbe(ctx2, cfgDead, slow)
	}()
	for s.SideProbesInFlight() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if _, err := s.SideProbe(context.Background(), cfgB, quickProof(target)); !errors.Is(err, ErrSideProbeBusy) {
		t.Fatalf("a third side probe was admitted: err = %v", err)
	}
	cancel2()
	for s.SideProbesInFlight() > 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}

	// The winner, beside the one still hanging on a silent relay.
	winner, err := s.SideProbe(ctx, cfgB, quickProof(target))
	if err != nil || !winner.OK {
		t.Fatalf("the working route did not win: %+v %v", winner, err)
	}
	// The loser is stopped at once.
	t0 := time.Now()
	cancel()
	select {
	case <-loserDone:
	case <-time.After(3 * time.Second):
		t.Fatal("the loser was still running 3 s after it was stopped")
	}
	if d := time.Since(t0); d > time.Second {
		t.Fatalf("stopping the loser took %s", d)
	}
	if loserErr != nil || !loser.Cancelled {
		t.Fatalf("the stopped loser came back %+v err=%v; a stopped probe says nothing about its route", loser, loserErr)
	}
	wg.Wait()

	if n := s.SideProbesInFlight(); n != 0 {
		t.Fatalf("%d side probes in flight after both returned", n)
	}
	if started, closed := sideInstancesStarted.Load()-startedBefore, sideInstancesClosed.Load()-closedBefore; started != 3 || closed != started {
		t.Fatalf("%d side instances were started in the race and %d closed; every one must be closed when its probe returns", started, closed)
	}
	if _, peak := s.SideProbeStats(); peak != MaxSideProbes {
		t.Fatalf("peak in flight = %d, want exactly %d", peak, MaxSideProbes)
	}
	if got, ok := settles(func() int { return openFDs(t) }, fdsBefore); !ok {
		t.Fatalf("file descriptors: %d before the race, %d after", fdsBefore, got)
	}
	if got, ok := settles(runtime.NumGoroutine, goBefore); !ok {
		buf := make([]byte, 1<<16)
		t.Fatalf("goroutines: %d before the race, %d after\n%s", goBefore, got, buf[:runtime.Stack(buf, true)])
	}
}

// Cancel during a race: both probes, each stuck on a relay that will
// never answer, are back within a second, and say nothing about their
// routes.
func TestSideProbe_CancelStopsBothPromptly(t *testing.T) {
	target := tlsTarget(t)
	proxyA, _ := connectProxy(t)
	s := runningDriver(t, httpRoute(proxyA.Port))
	slow := ProofConfig{Targets: []string{target}, AttemptTimeout: 20 * time.Second, Attempts: 1, SlowAfter: time.Second}
	cfgs := [][]byte{
		sideCfgFor(t, "vless-reality", fmt.Sprintf(muxedVless, silentRelay(t))),
		sideCfgFor(t, "other", fmt.Sprintf(muxedTrojan, silentRelay(t))),
	}
	ctx, cancel := context.WithCancel(context.Background())
	results := make([]ProofResult, 2)
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i := range cfgs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = s.SideProbe(ctx, cfgs[i], slow)
		}(i)
	}
	deadline := time.Now().Add(3 * time.Second)
	for s.SideProbesInFlight() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond) // both are inside their handshakes
	t0 := time.Now()
	cancel()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("a cancelled race was still running after 3 s")
	}
	if d := time.Since(t0); d > time.Second {
		t.Fatalf("cancelling the race took %s", d)
	}
	for i := range results {
		if errs[i] != nil || !results[i].Cancelled {
			t.Errorf("probe %d: %+v err=%v, want Cancelled", i, results[i], errs[i])
		}
	}
	if started, closed := sideInstancesStarted.Load(), sideInstancesClosed.Load(); started != closed {
		t.Fatalf("%d side instances started in this process, %d closed", started, closed)
	}
	if res := s.Prove(context.Background(), quickProof(target)); !res.OK {
		t.Fatalf("the running route stopped proving after a cancelled race: %+v", res)
	}
}

// Engine shutdown: StopSideProbes returns only when the instances are
// closed.
func TestSideProbe_StopSideProbesWaitsForTeardown(t *testing.T) {
	target := tlsTarget(t)
	s := newSingBox()
	cfg := sideCfgFor(t, "vless-reality", fmt.Sprintf(muxedVless, silentRelay(t)))
	slow := ProofConfig{Targets: []string{target}, AttemptTimeout: 20 * time.Second, Attempts: 1}
	got := make(chan ProofResult, 1)
	go func() {
		res, _ := s.SideProbe(context.Background(), cfg, slow)
		got <- res
	}()
	deadline := time.Now().Add(3 * time.Second)
	for s.SideProbesInFlight() < 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	t0 := time.Now()
	s.StopSideProbes()
	if d := time.Since(t0); d > time.Second {
		t.Fatalf("StopSideProbes took %s", d)
	}
	if n := s.SideProbesInFlight(); n != 0 {
		t.Fatalf("StopSideProbes returned with %d probes in flight", n)
	}
	select {
	case res := <-got:
		if !res.Cancelled {
			t.Fatalf("a probe stopped by shutdown came back %+v", res)
		}
	case <-time.After(time.Second):
		t.Fatal("the probe did not return")
	}
}

// A side instance has no way in and no TUN: what sing-box is handed
// carries no inbound at all, the platform refuses to open an interface,
// and a whole side probe duplicates the host's TUN fd zero times.
func TestSideProbe_HoldsNoTunAndNoInlet(t *testing.T) {
	target := tlsTarget(t)
	proxy, _ := connectProxy(t)
	cfg := sideCfgFor(t, "other", httpRoute(proxy.Port))

	var engineSide map[string]any
	_ = json.Unmarshal(cfg, &engineSide)
	if in, _ := engineSide["inbounds"].([]any); len(in) == 0 {
		t.Fatal("premise: the engine-side config carries no refresh inlet to strip")
	}
	merged, _, err := sideConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var handed map[string]any
	_ = json.Unmarshal(merged, &handed)
	if in, ok := handed["inbounds"].([]any); ok {
		// (Not printed: the inlet's inbound carries its credential.)
		t.Fatalf("a side instance was handed %d inbound(s)", len(in))
	}

	p := &sidePlatform{newAndroidPlatform()}
	if _, err := p.OpenInterface(tunOptions(), boxoption.TunPlatformOptions{}); err == nil {
		t.Fatal("a side instance's platform opened a TUN")
	}

	host := pipeRead(t)
	SetCurrentTunFD(host)
	t.Cleanup(func() { SetCurrentTunFD(-1) })
	dups := 0
	origDup := dupFD
	dupFD = func(fd int) (int, error) { dups++; return origDup(fd) }
	t.Cleanup(func() { dupFD = origDup })
	cc := countCloses(t)

	s := newSingBox()
	if res, err := s.SideProbe(context.Background(), cfg, quickProof(target)); err != nil || !res.OK {
		t.Fatalf("side probe: %+v %v", res, err)
	}
	if dups != 0 {
		t.Fatalf("a side probe duplicated the TUN fd %d time(s)", dups)
	}
	cc.mu.Lock()
	closed := cc.closes[host]
	cc.mu.Unlock()
	if closed != 0 || !fdOpen(host) {
		t.Fatal("a side probe closed the host's TUN fd")
	}
	if CurrentRefreshInlet() != nil {
		t.Fatal("a side probe published a refresh inlet")
	}
}

// The hand-over the ABI makes: the route a side probe just proved is
// started as an ordinary instance and proves again. (With the TUN
// inbound it would be the tunnel's instance; no unit test has a TUN.)
// What it costs is that second proof.
func TestSideProbe_TheWinnerThenStartsAndProvesAsTheMainInstance(t *testing.T) {
	target := tlsTarget(t)
	proxy, tunnels := connectProxy(t)
	s := newSingBox()
	res, err := s.SideProbe(context.Background(), sideCfgFor(t, "other", httpRoute(proxy.Port)), quickProof(target))
	if err != nil || !res.OK {
		t.Fatalf("side probe: %+v %v", res, err)
	}
	after := tunnels.Load()
	main := runningDriver(t, httpRoute(proxy.Port))
	if res := main.Prove(context.Background(), quickProof(target)); !res.OK {
		t.Fatalf("the route a side probe proved did not prove as the main instance: %+v (%v)", res, res.Err)
	}
	if tunnels.Load() == after {
		t.Fatal("the main instance's proof did not go through the relay")
	}
}

// A route that cannot be side-probed is refused before anything is
// built, and a side-probeable type is always one a diagnosis twin may be
// made of (the same "private and side-effect-free" rule).
func TestSideProbe_RefusesWhatCannotRace(t *testing.T) {
	s := newSingBox()
	naive := sideCfgFor(t, "naive", `{"type":"naive","server":"203.0.113.1","server_port":443}`)
	if s.CanSideProbe(naive) {
		t.Fatal("naive was called side-probeable")
	}
	if _, err := s.SideProbe(context.Background(), naive, ProofConfig{}); !errors.Is(err, ErrSideProbeUnsupported) {
		t.Fatalf("err = %v", err)
	}
	if total, _ := s.SideProbeStats(); total != 0 {
		t.Fatal("a refused route was counted as a side probe")
	}
	for typ := range sideProbeTypes {
		if !twinTypes[typ] {
			t.Errorf("%s may be side-probed but not twinned", typ)
		}
	}
	// A dead relay is a failed proof, classified — not an error.
	res, err := s.SideProbe(context.Background(), sideCfgFor(t, "other", httpRoute(1)), quickProof("127.0.0.1:9"))
	if err != nil || res.OK || res.Cancelled {
		t.Fatalf("dead relay: %+v err=%v", res, err)
	}
}
