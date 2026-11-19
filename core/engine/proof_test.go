package engine

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"daal/core/diagnostics"
)

func TestDefaultProofConfigIsBoundedAndNotOneHost(t *testing.T) {
	c := DefaultProofConfig()
	if len(c.Targets) < 3 {
		t.Fatalf("the default proof targets are %d host(s); one host every client touches on every connect is a fingerprint and a single point of failure", len(c.Targets))
	}
	for _, tg := range c.Targets {
		if _, _, err := splitProofTarget(tg); err != nil {
			t.Errorf("default target %q: %v", tg, err)
		}
	}
	if total := c.AttemptTimeout * time.Duration(c.Attempts); total > 10*time.Second {
		t.Fatalf("the default proof may take %s; connect must stay bounded in seconds", total)
	}
	if c.Attempts < 2 {
		t.Fatal("one attempt means one unreachable TARGET fails a working route")
	}
	if c.SlowAfter >= c.AttemptTimeout {
		t.Fatalf("slow_after (%s) is not below the attempt timeout (%s): a slow proof could never be told from a failed one", c.SlowAfter, c.AttemptTimeout)
	}
}

func TestProofConfigRejectsUnusableTargets(t *testing.T) {
	for _, bad := range []string{"example.com", "example.com:0", ":443", "example.com:https"} {
		if _, err := (ProofConfig{Targets: []string{bad}}).Normalised(); err == nil {
			t.Errorf("target %q was accepted", bad)
		}
	}
	c, err := (ProofConfig{Targets: []string{"192.0.2.44:443"}}).Normalised()
	if err != nil || len(c.Targets) != 1 || c.Attempts == 0 || c.AttemptTimeout == 0 {
		t.Fatalf("a config that only names targets must take every other default: %+v %v", c, err)
	}
}

func cfgFor(targets ...string) ProofConfig {
	return ProofConfig{Targets: targets, AttemptTimeout: 200 * time.Millisecond, Attempts: 2, SlowAfter: 50 * time.Millisecond}
}

func TestRunProofTriesADifferentTargetBeforeGivingUp(t *testing.T) {
	var tried []string
	timeout := &net.OpError{Op: "dial", Net: "tcp", Err: context.DeadlineExceeded}
	res := runProof(context.Background(), cfgFor("a.example:443", "b.example:443", "c.example:443"),
		func(n int) int { return 1 },
		func(ctx context.Context, host string, port uint16) (diagnostics.Observation, error) {
			tried = append(tried, host)
			return diagnostics.Observe(timeout, diagnostics.PhaseHandshake, false, true), timeout
		})
	if res.OK || res.Attempts != 2 {
		t.Fatalf("want a failed proof after 2 attempts, got %+v", res)
	}
	if len(tried) != 2 || tried[0] != "b.example" || tried[1] != "c.example" {
		t.Fatalf("attempts went to %v; want two DIFFERENT targets from a random start", tried)
	}
	if got := res.Category(); got != diagnostics.TCPConnectTimeout {
		t.Fatalf("category = %s, want tcp_connect_timeout (the error is a failed connect)", got)
	}
}

func TestRunProofSecondTargetRescuesTheRoute(t *testing.T) {
	n := 0
	res := runProof(context.Background(), cfgFor("a.example:443", "b.example:443"), func(int) int { return 0 },
		func(ctx context.Context, host string, port uint16) (diagnostics.Observation, error) {
			n++
			if n == 1 {
				err := errors.New("EOF")
				return diagnostics.Observe(err, diagnostics.PhaseCarry, false, true), err
			}
			return diagnostics.Observation{}, nil
		})
	if !res.OK || res.Attempts != 2 || res.Err != nil {
		t.Fatalf("a dead first TARGET must not fail the route: %+v", res)
	}
	if res.Slow {
		t.Fatalf("a first target that failed at once made the proof slow (elapsed %s)", res.Elapsed)
	}
}

func TestRunProofSlowIsSuccessMarkedSlow(t *testing.T) {
	res := runProof(context.Background(), cfgFor("a.example:443"), func(int) int { return 0 },
		func(ctx context.Context, host string, port uint16) (diagnostics.Observation, error) {
			time.Sleep(80 * time.Millisecond) // over SlowAfter (50 ms), under the attempt timeout
			return diagnostics.Observation{}, nil
		})
	if !res.OK || !res.Slow {
		t.Fatalf("a round trip over slow_after must be OK and Slow, got %+v", res)
	}
}

// A first attempt that ran out its whole budget AFTER the relay had
// answered (PhaseCarry), then a second that succeeded quickly: the person
// waited the whole of it, and the route is "connected, but slow". Before,
// a carry-phase timeout was read as a dead target and the connect was
// reported as plain "Connected" — the end-to-end rig's throttle-56k saw
// websocket-tls, hysteria2 and tuic do exactly that after 4.7–5.5 s.
func TestRunProofTimedOutCarryAttemptThenSuccessIsSlow(t *testing.T) {
	n := 0
	res := runProof(context.Background(), cfgFor("a.example:443", "b.example:443"), func(int) int { return 0 },
		func(ctx context.Context, host string, port uint16) (diagnostics.Observation, error) {
			n++
			if n == 1 {
				<-ctx.Done() // the whole attempt budget (200 ms), relay already answered
				return diagnostics.Observe(ctx.Err(), diagnostics.PhaseCarry, false, true), ctx.Err()
			}
			return diagnostics.Observation{}, nil // well under slow_after
		})
	if !res.OK || res.Attempts != 2 {
		t.Fatalf("the second target must rescue the route: %+v", res)
	}
	if res.RoundTrip > 50*time.Millisecond {
		t.Skipf("the machine is too slow for this test to mean anything (round trip %s)", res.RoundTrip)
	}
	if !res.Slow {
		t.Fatalf("a proof that took %s because an attempt timed out in the carry phase was not marked slow (slow_after 50ms)", res.Elapsed)
	}
}

// Slow is the whole proof's time against slow_after — nothing else.
func TestProofWasSlowJudgesTheWholeProof(t *testing.T) {
	timedOut := diagnostics.Observation{Phase: diagnostics.PhaseCarry, Timeout: true}
	closed := diagnostics.Observation{Phase: diagnostics.PhaseCarry, Closed: true}
	const slowAfter = 2 * time.Second
	for _, c := range []struct {
		name string
		res  ProofResult
		want bool
	}{
		{"one quick round trip", ProofResult{OK: true, RoundTrip: time.Second, Elapsed: time.Second}, false},
		{"one slow round trip", ProofResult{OK: true, RoundTrip: 3 * time.Second, Elapsed: 3 * time.Second}, true},
		{"attempt timed out after the relay answered, then quick", ProofResult{OK: true, RoundTrip: time.Second, Elapsed: 5 * time.Second, Failed: []diagnostics.Observation{timedOut}}, true},
		{"target closed at once, then quick", ProofResult{OK: true, RoundTrip: time.Second, Elapsed: 1010 * time.Millisecond, Failed: []diagnostics.Observation{closed}}, false},
		{"target closed after seconds, then quick", ProofResult{OK: true, RoundTrip: time.Second, Elapsed: 3 * time.Second, Failed: []diagnostics.Observation{closed}}, true},
		{"failed", ProofResult{Elapsed: 8 * time.Second, Failed: []diagnostics.Observation{timedOut, timedOut}}, false},
	} {
		if got := proofWasSlow(c.res, slowAfter); got != c.want {
			t.Errorf("%s: slow = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestRunProofCancelledIsNotAFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	res := runProof(ctx, cfgFor("a.example:443", "b.example:443"), func(int) int { return 0 },
		func(actx context.Context, host string, port uint16) (diagnostics.Observation, error) {
			cancel()
			<-actx.Done()
			return diagnostics.Observe(actx.Err(), diagnostics.PhaseHandshake, false, true), actx.Err()
		})
	if !res.Cancelled || res.OK {
		t.Fatalf("an abandoned proof must be reported as cancelled, got %+v", res)
	}
	if res.Attempts != 1 {
		t.Fatalf("a cancelled proof went on to attempt %d", res.Attempts)
	}
}

func TestStubProveNeedsARunningInstance(t *testing.T) {
	s := NewStub()
	if res := s.Prove(context.Background(), ProofConfig{}); res.OK || !errors.Is(res.Err, ErrNotRunning) {
		t.Fatalf("a driver with no instance proved a route: %+v", res)
	}
	if err := s.Start(context.Background(), []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	s.InjectProof(ProofResult{Err: errors.New("x")})
	if res := s.Prove(context.Background(), ProofConfig{}); res.OK {
		t.Fatal("the injected failure was not returned")
	}
	if res := s.Prove(context.Background(), ProofConfig{}); !res.OK {
		t.Fatal("with nothing injected the stub proves")
	}
}

// ---- slow is not silent (backlog TW-10, the rig's CEN-O5) ---------------

func timeoutObs(phase diagnostics.Phase, progress bool) (diagnostics.Observation, error) {
	o := diagnostics.Observe(context.DeadlineExceeded, phase, false, true)
	o.Progress = progress
	return o, context.DeadlineExceeded
}

func slowCfg(targets ...string) ProofConfig {
	c := cfgFor(targets...)
	c.SlowBudget = 2 * time.Second
	return c
}

// Every ordinary attempt runs out of time on a path that was seen
// moving: the proof makes ONE more attempt with the long budget, and a
// route that completes it is connected and slow — not "could not
// connect", and not a cooldown.
func TestRunProof_SlowPathGetsTheLongAttemptAndConnectsSlow(t *testing.T) {
	var budgets []time.Duration
	res := runProof(context.Background(), slowCfg("a.example:443", "b.example:443", "c.example:443"), func(int) int { return 0 },
		func(ctx context.Context, host string, port uint16) (diagnostics.Observation, error) {
			dl, _ := ctx.Deadline()
			budgets = append(budgets, time.Until(dl).Round(100*time.Millisecond))
			if len(budgets) <= 2 {
				return timeoutObs(diagnostics.PhaseCarry, true)
			}
			return diagnostics.Observation{}, nil
		})
	if !res.OK || !res.Slow || !res.Extended || res.Attempts != 3 {
		t.Fatalf("want connected-and-slow after the long attempt, got %+v", res)
	}
	if len(budgets) != 3 || budgets[2] != 2*time.Second || budgets[0] != 200*time.Millisecond {
		t.Fatalf("attempt budgets = %v; the third must be the slow budget", budgets)
	}
}

// A path on which nothing was seen moving gets no extra time: a dead
// route still fails within attempts × attempt_timeout.
func TestRunProof_SilentPathGetsNoExtraTime(t *testing.T) {
	n := 0
	res := runProof(context.Background(), slowCfg("a.example:443", "b.example:443"), func(int) int { return 0 },
		func(ctx context.Context, host string, port uint16) (diagnostics.Observation, error) {
			n++
			return timeoutObs(diagnostics.PhaseHandshake, false)
		})
	if res.OK || res.Extended || n != 2 {
		t.Fatalf("a silent path was given %d attempts (extended=%v)", n, res.Extended)
	}
	if got := res.Category(); got != diagnostics.TLSHandshakeFailed {
		t.Fatalf("category = %s, want tls_handshake_failed", got)
	}
}

// A moving path that does not finish even the long attempt is
// path_too_slow — whatever phase the last timeout was in. In particular
// a timeout after the ClientHello on a slow path is NOT
// tls_handshake_failed (30 min of cooldown) and nothing a recommender
// could read as a name-keyed block.
func TestRunProof_SlowPathThatNeverFinishesIsPathTooSlow(t *testing.T) {
	n := 0
	res := runProof(context.Background(), slowCfg("a.example:443", "b.example:443"), func(int) int { return 0 },
		func(ctx context.Context, host string, port uint16) (diagnostics.Observation, error) {
			n++
			// Only the first attempt saw the path move; the evidence
			// must carry to the verdict.
			return timeoutObs(diagnostics.PhaseHandshake, n == 1)
		})
	if res.OK || !res.Extended || n != 3 {
		t.Fatalf("got %+v after %d attempts", res, n)
	}
	if got := res.Category(); got != diagnostics.PathTooSlow {
		t.Fatalf("category = %s, want path_too_slow", got)
	}
}

// The reach check's finding (aids.settle) counts as evidence too: a SYN
// answered late is a slow path.
func TestRunProof_SettleCanSupplyTheEvidence(t *testing.T) {
	n := 0
	res := runProofWith(context.Background(), slowCfg("a.example:443", "b.example:443"), func(int) int { return 0 },
		func(ctx context.Context, host string, port uint16) (diagnostics.Observation, error) {
			n++
			if n <= 2 {
				return timeoutObs(diagnostics.PhaseHandshake, false)
			}
			return diagnostics.Observation{}, nil
		},
		proofAids{settle: func(_ context.Context, o *diagnostics.Observation) { o.Progress = true }})
	if !res.OK || !res.Slow || n != 3 {
		t.Fatalf("got %+v after %d attempts", res, n)
	}
}

// ---- the carry-phase timeout is asked again on a fresh connection ------

// A timeout after the outbound handed over a connection says nothing
// about the relay when the outbound answered from a session it already
// held — every dial on a route that has been connected for a while. The
// driver's fresh-connection attempt is believed instead: a mid-session
// block is classified as the connect-time proof would classify it.
func TestRunProof_CarryTimeoutIsAskedAgainOnAFreshConnection(t *testing.T) {
	carry := func(ctx context.Context, host string, port uint16) (diagnostics.Observation, error) {
		return timeoutObs(diagnostics.PhaseCarry, false)
	}
	cases := []struct {
		name string
		diag func() (diagnostics.Observation, error, bool)
		want diagnostics.Category
	}{
		{"ClientHello swallowed", func() (diagnostics.Observation, error, bool) {
			o, err := timeoutObs(diagnostics.PhaseHandshake, false)
			return o, err, true
		}, diagnostics.TLSHandshakeFailed},
		{"address dead", func() (diagnostics.Observation, error, bool) {
			err := &net.OpError{Op: "dial", Net: "tcp", Err: context.DeadlineExceeded}
			return diagnostics.Observe(err, diagnostics.PhaseHandshake, false, true), err, true
		}, diagnostics.TCPConnectTimeout},
		{"reset after the ClientHello", func() (diagnostics.Observation, error, bool) {
			err := errors.New("read: connection reset by peer")
			return diagnostics.Observe(err, diagnostics.PhaseHandshake, false, true), err, true
		}, diagnostics.TLSSNIOrCertBlockSuspected},
		{"relay answers, nothing beyond it does", func() (diagnostics.Observation, error, bool) {
			o, err := timeoutObs(diagnostics.PhaseCarry, false)
			o.RelayNoEgress = true
			return o, err, true
		}, diagnostics.RelayNoEgress},
		{"no fresh connection to offer", func() (diagnostics.Observation, error, bool) {
			return diagnostics.Observation{}, nil, false
		}, diagnostics.Unknown},
		{"the fresh connection works: a stale session, nothing known", func() (diagnostics.Observation, error, bool) {
			return diagnostics.Observation{}, nil, true
		}, diagnostics.Unknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var asked []string
			res := runProofWith(context.Background(), cfgFor("a.example:443", "b.example:443", "c.example:443"), func(int) int { return 0 }, carry,
				proofAids{diagnose: func(_ context.Context, host string, _ uint16) (diagnostics.Observation, error, bool) {
					asked = append(asked, host)
					return tc.diag()
				}})
			if res.OK {
				t.Fatal("proved")
			}
			if len(asked) != 1 || asked[0] != "c.example" {
				t.Fatalf("diagnosis asked %v; want once, on a host the attempts did not use", asked)
			}
			if got := res.Category(); got != tc.want {
				t.Fatalf("category = %s, want %s (%+v)", got, tc.want, res.Observation)
			}
		})
	}
}

// Only the carry-phase timeout is ambiguous. A failure that already
// names its phase is not asked again (no extra connection to the relay
// on an ordinary dead route).
func TestRunProof_DiagnosisIsOnlyForTheCarryTimeout(t *testing.T) {
	for name, attempt := range map[string]proofAttempt{
		"handshake timeout": func(context.Context, string, uint16) (diagnostics.Observation, error) {
			return timeoutObs(diagnostics.PhaseHandshake, false)
		},
		"carry EOF": func(context.Context, string, uint16) (diagnostics.Observation, error) {
			err := errors.New("EOF")
			return diagnostics.Observe(err, diagnostics.PhaseCarry, false, true), err
		},
	} {
		res := runProofWith(context.Background(), cfgFor("a.example:443", "b.example:443"), func(int) int { return 0 }, attempt,
			proofAids{diagnose: func(context.Context, string, uint16) (diagnostics.Observation, error, bool) {
				t.Errorf("%s: diagnosis was run", name)
				return diagnostics.Observation{}, nil, false
			}})
		if res.OK || res.Attempts != 2 {
			t.Fatalf("%s: %+v", name, res)
		}
	}
}

// ---- the default targets (backlog TW-14) ---------------------------------

func proofOwner(op string) string {
	if o, ok := proofOperatorOwner[op]; ok {
		return o
	}
	return op
}

// Rule 4: no one company can fail a working route. The attempts of one
// check go to neighbours in the list (proofOrder), so neighbours —
// including the pair that wraps around — must belong to different
// companies, and any three in a row to at least two.
func TestDefaultProofTargets_NeighboursAreDifferentCompanies(t *testing.T) {
	set := DefaultProofTargetSet
	if len(set) < 5 {
		t.Fatalf("%d default targets; want at least 5", len(set))
	}
	owners := map[string]bool{}
	hosts := map[string]bool{}
	for i, tg := range set {
		next := set[(i+1)%len(set)]
		if proofOwner(tg.Operator) == proofOwner(next.Operator) {
			t.Errorf("%s and %s are neighbours and both depend on %s", tg.Addr, next.Addr, proofOwner(tg.Operator))
		}
		owners[proofOwner(tg.Operator)] = true
		if hosts[tg.Addr] {
			t.Errorf("%s is listed twice", tg.Addr)
		}
		hosts[tg.Addr] = true
	}
	if len(owners) < 5 {
		t.Fatalf("the default targets depend on %d companies; want at least 5", len(owners))
	}
	// And the order the attempts really take them in obeys it for every
	// starting point.
	for start := range set {
		order := proofOrder(DefaultProofTargets, DefaultProofConfig().Attempts, func(int) int { return start })
		seen := map[string]bool{}
		for _, addr := range order {
			for _, tg := range set {
				if tg.Addr == addr {
					if seen[proofOwner(tg.Operator)] {
						t.Errorf("start %d: two attempts of one check depend on %s", start, proofOwner(tg.Operator))
					}
					seen[proofOwner(tg.Operator)] = true
				}
			}
		}
	}
}

// Rule 3: TLS on 443 to a name, and nothing that could carry a request.
// (That no request is sent is proveOnce's property: it never writes to
// the connection. This pins the list's half.)
func TestDefaultProofTargets_AreNamesOnPort443(t *testing.T) {
	for _, tg := range DefaultProofTargetSet {
		host, port, err := splitProofTarget(tg.Addr)
		if err != nil || port != 443 {
			t.Errorf("%s: want a name on port 443 (%v)", tg.Addr, err)
		}
		if net.ParseIP(host) != nil {
			t.Errorf("%s is an address: a ClientHello with no name in it is rarer than one with", tg.Addr)
		}
		if tg.Operator == "" {
			t.Errorf("%s has no operator recorded", tg.Addr)
		}
	}
	if len(DefaultProofTargets) != len(DefaultProofTargetSet) {
		t.Fatal("DefaultProofTargets is not DefaultProofTargetSet")
	}
}

// The choice is random: every target is some check's first.
func TestProofOrderStartsAnywhere(t *testing.T) {
	first := map[string]bool{}
	for i := range DefaultProofTargets {
		first[proofOrder(DefaultProofTargets, 2, func(n int) int { return i % n })[0]] = true
	}
	if len(first) != len(DefaultProofTargets) {
		t.Fatalf("only %d of %d targets can be drawn first", len(first), len(DefaultProofTargets))
	}
}
