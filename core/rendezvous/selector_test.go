package rendezvous

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// Phase 3B selector tests. Canonical regressions called out in
// specs/rendezvous-channels-v1.md and specs/engine-abi-v1.md.

func makeChannel(id string, latency time.Duration, succeed bool) Channel {
	return &solicitorChannel{
		id: id,
		solicit: func(ctx context.Context, req Request) (Hint, error) {
			select {
			case <-time.After(latency):
				if !succeed {
					return Hint{}, errors.New("synthetic failure")
				}
				return Hint{ChannelID: id, BridgeFP: "fp-" + id}, nil
			case <-ctx.Done():
				return Hint{}, ctx.Err()
			}
		},
	}
}

func TestKnownChannels_ClosedList(t *testing.T) {
	all := KnownChannels()
	if len(all) != 5 {
		t.Fatalf("v1 channel list MUST be 5; got %d (%v)", len(all), all)
	}
	for _, want := range []string{
		ChannelDomainFrontedBroker, ChannelSQS, ChannelAMPCache,
		ChannelPush, ChannelOfflineHint,
	} {
		if !IsKnownChannel(want) {
			t.Errorf("missing channel %q", want)
		}
	}
	if IsKnownChannel("not-a-channel") {
		t.Error("unknown channel should not be reported as known")
	}
}

// TestSelector_FastPriorityWins — when the priority channel
// succeeds quickly, no hedge fires.
func TestSelector_FastPriorityWins(t *testing.T) {
	s := New([]Channel{
		makeChannel("domain_fronted_broker", 10*time.Millisecond, true),
		makeChannel("sqs", 50*time.Millisecond, true),
	}, nil)
	s.SetHedge(100 * time.Millisecond)
	id, h, err := s.Race(context.Background(), Request{}, []string{
		"domain_fronted_broker", "sqs",
	})
	if err != nil {
		t.Fatalf("race: %v", err)
	}
	if id != "domain_fronted_broker" {
		t.Errorf("winner: got %q want domain_fronted_broker", id)
	}
	if h.BridgeFP != "fp-domain_fronted_broker" {
		t.Errorf("hint: got %+v", h)
	}
}

// TestHedgedSelectionFiresAtFourSeconds — when the priority
// channel is slow, a lower-priority channel wins via the hedge.
//
// We use a 50ms hedge interval (vs the v1-locked 4s) for test
// speed; the selector's `SetHedge` knob is test-only.
func TestHedgedSelectionFiresAtFourSeconds(t *testing.T) {
	s := New([]Channel{
		makeChannel("domain_fronted_broker", 1*time.Second, true),
		makeChannel("sqs", 10*time.Millisecond, true),
	}, nil)
	s.SetHedge(50 * time.Millisecond)

	start := time.Now()
	id, _, err := s.Race(context.Background(), Request{}, []string{
		"domain_fronted_broker", "sqs",
	})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("race: %v", err)
	}
	if id != "sqs" {
		t.Errorf("winner: got %q want sqs (hedge fallback)", id)
	}
	// Hedge fires at ~50ms; sqs solves in ~10ms; total < 200ms.
	if elapsed > 200*time.Millisecond {
		t.Errorf("hedge did not fire promptly: elapsed %v", elapsed)
	}
}

// TestNetmemHintBiasesT0 — when netmem records a winning
// channel for the active network, it fires at t=0 even if the
// priority list orders it later.
func TestNetmemHintBiasesT0(t *testing.T) {
	var firedFirst atomic.Value // string
	wrap := func(id string, latency time.Duration) Channel {
		return &solicitorChannel{
			id: id,
			solicit: func(ctx context.Context, req Request) (Hint, error) {
				firedFirst.CompareAndSwap(nil, id)
				select {
				case <-time.After(latency):
					return Hint{ChannelID: id}, nil
				case <-ctx.Done():
					return Hint{}, ctx.Err()
				}
			},
		}
	}
	s := New([]Channel{
		wrap("domain_fronted_broker", 30*time.Millisecond),
		wrap("sqs", 30*time.Millisecond),
	}, func(networkID string) string {
		if networkID == "net-1" {
			return "sqs"
		}
		return ""
	})
	s.SetHedge(500 * time.Millisecond)

	id, _, err := s.Race(context.Background(), Request{NetworkID: "net-1"},
		[]string{"domain_fronted_broker", "sqs"})
	if err != nil {
		t.Fatal(err)
	}
	if id != "sqs" {
		t.Errorf("winner: got %q, want sqs (netmem hint)", id)
	}
	if firedFirst.Load() != "sqs" {
		t.Errorf("netmem hint did not fire at t=0; first-fire was %v", firedFirst.Load())
	}
}

// TestAllFailReturnsErr — when every channel returns an error,
// Race returns ErrAllChannelsFailed and the route burns.
func TestAllFailReturnsErr(t *testing.T) {
	s := New([]Channel{
		makeChannel("domain_fronted_broker", 5*time.Millisecond, false),
		makeChannel("sqs", 5*time.Millisecond, false),
	}, nil)
	s.SetHedge(20 * time.Millisecond)
	_, _, err := s.Race(context.Background(), Request{}, []string{
		"domain_fronted_broker", "sqs",
	})
	if !errors.Is(err, ErrAllChannelsFailed) {
		t.Fatalf("got %v, want ErrAllChannelsFailed", err)
	}
}

// TestDisabledChannelDoesNotCountAsFail — push channel returns
// ErrChannelDisabled when the user has not opted in; the
// Selector MUST skip it silently rather than counting it as an
// all-fail contributor.
func TestDisabledChannelDoesNotCountAsFail(t *testing.T) {
	pushDisabled := NewPush(
		func(ctx context.Context, req Request) (Hint, error) {
			t.Error("disabled push channel solicitor must not be invoked")
			return Hint{}, nil
		},
		func() bool { return false }, // opt-in OFF
	)
	good := makeChannel("domain_fronted_broker", 10*time.Millisecond, true)
	s := New([]Channel{pushDisabled, good}, nil)
	s.SetHedge(500 * time.Millisecond)

	id, _, err := s.Race(context.Background(), Request{}, []string{
		"push", "domain_fronted_broker",
	})
	if err != nil {
		t.Fatalf("disabled-push race: %v", err)
	}
	if id != "domain_fronted_broker" {
		t.Errorf("winner: got %q want domain_fronted_broker", id)
	}
}

// TestUnknownChannelInPriorityIgnored — bundle priority entries
// that aren't in the v1 closed list MUST be skipped (the bundle
// parser also rejects them; this is defence-in-depth).
func TestUnknownChannelInPriorityIgnored(t *testing.T) {
	s := New([]Channel{
		makeChannel("domain_fronted_broker", 10*time.Millisecond, true),
	}, nil)
	id, _, err := s.Race(context.Background(), Request{}, []string{
		"not-a-channel", "domain_fronted_broker",
	})
	if err != nil {
		t.Fatal(err)
	}
	if id != "domain_fronted_broker" {
		t.Errorf("winner: got %q", id)
	}
}

// TestRaceCancelsLosers — when a channel wins, the in-flight
// losers must observe context cancellation.
func TestRaceCancelsLosers(t *testing.T) {
	cancellations := make(chan string, 5)
	wrap := func(id string, latency time.Duration, succeed bool) Channel {
		return &solicitorChannel{
			id: id,
			solicit: func(ctx context.Context, req Request) (Hint, error) {
				select {
				case <-time.After(latency):
					if !succeed {
						return Hint{}, errors.New("fail")
					}
					return Hint{ChannelID: id}, nil
				case <-ctx.Done():
					cancellations <- id
					return Hint{}, ctx.Err()
				}
			},
		}
	}
	s := New([]Channel{
		wrap("domain_fronted_broker", 10*time.Millisecond, true),
		wrap("sqs", 1*time.Second, true),
	}, nil)
	s.SetHedge(5 * time.Millisecond)

	_, _, err := s.Race(context.Background(), Request{}, []string{
		"domain_fronted_broker", "sqs",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Allow goroutines to observe cancel.
	select {
	case got := <-cancellations:
		if got != "sqs" {
			t.Errorf("unexpected cancelled channel: %s", got)
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("loser did not observe cancellation")
	}
}

// TestEmptyPriorityWithoutOffline — with no priority list, no
// netmem hint, and no offline_hint registered, Race returns
// ErrNoCandidates rather than blocking.
func TestEmptyPriorityWithoutOffline(t *testing.T) {
	s := New([]Channel{
		makeChannel("domain_fronted_broker", 10*time.Millisecond, true),
	}, nil)
	_, _, err := s.Race(context.Background(), Request{}, nil)
	if !errors.Is(err, ErrNoCandidates) {
		t.Errorf("got %v, want ErrNoCandidates", err)
	}
}

// TestEmptyPriorityFallsThroughToOffline — with no priority
// list but the offline_hint channel registered, Race fires it.
func TestEmptyPriorityFallsThroughToOffline(t *testing.T) {
	offline := NewOfflineHint(func(ctx context.Context, req Request) (Hint, error) {
		return Hint{ChannelID: "offline_hint", BridgeFP: "offline-fp"}, nil
	})
	s := New([]Channel{offline}, nil)
	id, _, err := s.Race(context.Background(), Request{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if id != "offline_hint" {
		t.Errorf("winner: got %q want offline_hint", id)
	}
}
