package engine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"daal/core/diagnostics"
)

// Event is a structured engine event published to subscribers.
type Event struct {
	Type     string               `json:"type"` // "state" | "failure" | "stat"
	State    string               `json:"state,omitempty"`
	Category diagnostics.Category `json:"category,omitempty"`
	Reason   string               `json:"reason,omitempty"`
	Bucket   string               `json:"bucket,omitempty"` // hour-bucketed timestamp
	BytesIn  int64                `json:"bytes_in,omitempty"`
	BytesOut int64                `json:"bytes_out,omitempty"`
}

// Driver is the platform-engine abstraction the ABI uses. Phase 1B's
// default Driver is a Stub; the real sing-box driver is gated behind the
// `singbox` build tag in engine_singbox.go.
type Driver interface {
	Start(ctx context.Context, configJSON []byte) error
	Stop() error
	Stats() (bytesIn, bytesOut int64, err error)
	Subscribe(ch chan<- Event)
	// Prove makes one real round trip through the running instance's
	// active outbound (proof.go). Start returning nil is NOT a tunnel;
	// only a successful Prove is. A driver with no instance returns a
	// failed result with ErrNotRunning. Prove never changes the
	// driver's lifecycle: tearing a route down after a failed proof is
	// the caller's decision.
	Prove(ctx context.Context, cfg ProofConfig) ProofResult
	// PublishState tells subscribers what the ABI concluded from a
	// proof ("Connected", "Degraded") — the driver itself only ever
	// knows "Verifying".
	PublishState(state string)
	// PublishFailure tells subscribers a route failed its proof.
	PublishFailure(cat diagnostics.Category, reason string)
}

// Stub is a deterministic in-process Driver suitable for unit tests and
// for the no-sing-box build of daal-core. It "connects" instantly,
// reports zero bytes, and can be told to fail via InjectFailure.
type Stub struct {
	mu        sync.Mutex
	connected bool
	resets    int
	subs      []chan<- Event
	failure   error
	// proofs is the queue of results InjectProof staged; proofHook, when
	// set, is asked instead. With neither, Prove succeeds — the Stub has
	// no data plane to disprove, and the ABI refuses to activate a route
	// on a build whose driver is the Stub (abi/dataplane.go).
	proofs    []ProofResult
	proofHook func(ctx context.Context, cfg ProofConfig) ProofResult
	proved    int
	// startHook, when set, is called on every successful Start (tests:
	// what a real driver does at that moment — publish a new inlet).
	startHook func()
	// side / sideHook: the side probes in flight and, for the Stub
	// itself, what answers them (side.go).
	side     sideSet
	sideHook func(ctx context.Context, configJSON []byte, cfg ProofConfig) (ProofResult, error)
}

// SetStartHook installs f to be called, with the stub's lock released,
// each time Start succeeds. nil removes it.
func (s *Stub) SetStartHook(f func()) {
	s.mu.Lock()
	s.startHook = f
	s.mu.Unlock()
}

// NewStub returns a fresh Stub.
func NewStub() *Stub { return &Stub{} }

// Start "starts" the stub tunnel.
func (s *Stub) Start(ctx context.Context, configJSON []byte) error {
	err := s.start(configJSON)
	s.mu.Lock()
	hook := s.startHook
	s.mu.Unlock()
	if err == nil && hook != nil {
		hook()
	}
	return err
}

func (s *Stub) start(configJSON []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failure != nil {
		err := s.failure
		s.failure = nil
		s.publishLocked(Event{Type: "failure",
			Category: diagnostics.Classify(err.Error()),
			Reason:   err.Error(),
			Bucket:   hourBucket(time.Now()),
		})
		return err
	}
	if len(configJSON) == 0 {
		return errors.New("engine: empty config")
	}
	s.connected = true
	// "Verifying", not "Connected": the instance is up and nothing has
	// been proved about the route yet. See proof.go.
	s.publishLocked(Event{Type: "state", State: StateVerifying, Bucket: hourBucket(time.Now())})
	return nil
}

// The state strings a driver and the ABI publish on the event stream.
const (
	StateVerifying    = "Verifying"
	StateConnected    = "Connected"
	StateDegraded     = "Degraded"
	StateDisconnected = "Disconnected"
)

// Prove returns the next injected result, or success.
func (s *Stub) Prove(ctx context.Context, cfg ProofConfig) ProofResult {
	s.mu.Lock()
	if !s.connected {
		s.mu.Unlock()
		return ProofResult{Err: ErrNotRunning, Observation: diagnostics.Observation{Message: ErrNotRunning.Error()}}
	}
	s.proved++
	hook := s.proofHook
	var next *ProofResult
	if hook == nil && len(s.proofs) > 0 {
		r := s.proofs[0]
		s.proofs = s.proofs[1:]
		next = &r
	}
	s.mu.Unlock()
	if hook != nil {
		return hook(ctx, cfg)
	}
	if next != nil {
		return *next
	}
	return ProofResult{OK: true, Attempts: 1}
}

// InjectProof stages the results of the next Prove calls, in order.
func (s *Stub) InjectProof(results ...ProofResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.proofs = append(s.proofs, results...)
}

// SetProofHook makes every Prove call f instead (nil restores the
// default). For tests that need a proof to block or to watch its
// context.
func (s *Stub) SetProofHook(f func(ctx context.Context, cfg ProofConfig) ProofResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.proofHook = f
}

// ProofCount reports how many times Prove has run on a live stub.
// ResetNetwork implements NetworkResetter: the Stub has no connections,
// it counts the calls (ResetCount) so a test can see the ABI asked.
func (s *Stub) ResetNetwork() {
	s.mu.Lock()
	s.resets++
	s.mu.Unlock()
}

// ResetCount is how many times ResetNetwork was called.
func (s *Stub) ResetCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.resets
}

func (s *Stub) ProofCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.proved
}

// PublishState publishes a state event.
func (s *Stub) PublishState(state string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.publishLocked(Event{Type: "state", State: state, Bucket: hourBucket(time.Now())})
}

// PublishFailure publishes a failure event.
func (s *Stub) PublishFailure(cat diagnostics.Category, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.publishLocked(Event{Type: "failure", Category: cat, Reason: reason, Bucket: hourBucket(time.Now())})
}

// Stop stops the stub tunnel.
func (s *Stub) Stop() error {
	// The stub never promotes a refresh inlet (nothing is listening on
	// one), but a build that swaps drivers mid-process must not leave a
	// stale record behind. Retiring is cheap and unconditional.
	retireRefreshInlet()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.connected {
		return nil
	}
	s.connected = false
	s.publishLocked(Event{Type: "state", State: StateDisconnected, Bucket: hourBucket(time.Now())})
	return nil
}

// Stats returns redacted stats. The stub reports zero.
func (s *Stub) Stats() (int64, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.connected {
		return 0, 0, errors.New("engine: not connected")
	}
	return 0, 0, nil
}

// Subscribe registers ch to receive events. The caller owns ch.
func (s *Stub) Subscribe(ch chan<- Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.subs = append(s.subs, ch)
}

// InjectFailure makes the next Start return err and emit a failure event.
func (s *Stub) InjectFailure(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failure = err
}

// Connected reports the in-memory state.
func (s *Stub) Connected() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connected
}

func (s *Stub) publishLocked(ev Event) {
	for _, ch := range s.subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

func hourBucket(t time.Time) string {
	return t.UTC().Truncate(time.Hour).Format("2006-01-02T15:04:05Z")
}

// Version reports the stub driver version. The sing-box driver overrides
// this string at build time.
func (s *Stub) Version() string {
	return fmt.Sprintf("daal-core stub-engine 0.2.0 (no sing-box)")
}

// NetworkResetter is a Driver that can drop what its running instance
// holds from the network the device has just LEFT: open connections and
// what the outbounds pool (a multiplexed session, a QUIC connection, a
// DNS transport). Seen on a phone (2026-11-19): mobile data -> Wi-Fi
// leaves the mobile network up but in the background for ~30 s, and a
// connection on it neither works nor fails; the route's check failed
// twice on such a connection and the engine left a route that was
// fine. sing-box does this itself where it watches interfaces; this
// embedding has no interface monitor, so the ABI asks for it when the
// host says the network changed. A no-op with no instance.
type NetworkResetter interface {
	ResetNetwork()
}
