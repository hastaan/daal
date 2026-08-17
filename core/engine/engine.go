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
}

// Stub is a deterministic in-process Driver suitable for unit tests and
// for the no-sing-box build of daal-core. It "connects" instantly,
// reports zero bytes, and can be told to fail via InjectFailure.
type Stub struct {
	mu        sync.Mutex
	connected bool
	subs      []chan<- Event
	failure   error
}

// NewStub returns a fresh Stub.
func NewStub() *Stub { return &Stub{} }

// Start "starts" the stub tunnel.
func (s *Stub) Start(ctx context.Context, configJSON []byte) error {
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
	s.publishLocked(Event{Type: "state", State: "Connected", Bucket: hourBucket(time.Now())})
	return nil
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
	s.publishLocked(Event{Type: "state", State: "Disconnected", Bucket: hourBucket(time.Now())})
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
