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
