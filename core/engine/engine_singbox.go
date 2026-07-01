//go:build singbox

package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"daal/core/diagnostics"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	boxoption "github.com/sagernet/sing-box/option"

	// Feature registrations. Without these blank imports the box.New
	// registry-resolution panics with "unknown inbound/outbound type".
	_ "github.com/sagernet/sing-box/include"
)

// NewDefaultDriver returns the real in-process sing-box driver. The ABI
// dispatcher in core/abi/abi.go calls NewDefaultDriver() at engine_init
// time; the //go:build tag chooses between this and engine_default.go's
// stub.
func NewDefaultDriver() Driver {
	return newSingBox()
}

// singBox embeds Stub so Subscribe / event publishing / hourBucket all
// stay shared with the stub driver — only the lifecycle below differs.
type singBox struct {
	*Stub

	mu       sync.Mutex
	instance *box.Box
	platform *androidPlatform
}

func newSingBox() *singBox {
	return &singBox{Stub: NewStub()}
}

// Start parses the engine-side config produced by BuildSingBoxConfig,
// rewrites it into sing-box's option.Options, attaches a TUN inbound
// from the file descriptor the Android VpnService handed to the ABI,
// and boots a *box.Box. The route's "udp_gated" flag is honored by the
// caller's path manager (engine doesn't activate the route unless the
// UDP probe passed); when Start is reached the route is considered
// activatable.
func (s *singBox) Start(ctx context.Context, configJSON []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.instance != nil {
		return errors.New("engine: already started")
	}

	var raw map[string]any
	if err := json.Unmarshal(configJSON, &raw); err != nil {
		return fmt.Errorf("engine: parse config: %w", err)
	}

	// Inject the TUN inbound iff we have a fd. The Android service
	// owns the fd's lifetime; sing-box dups it internally so detach
	// on the Java side is safe after Start returns.
	tunFD := CurrentTunFD()
	if tunFD < 0 {
		return errors.New("engine: TUN fd not set; VpnService must call engine_set_tun_fd before engine_start")
	}
	inbounds, _ := raw["inbounds"].([]any)
	tun := map[string]any{
		"tag":         "tun-in",
		"type":        "tun",
		"interface_name": "daal-tun",
		"inet4_address":  "172.19.0.1/30",
		"mtu":            1500,
		"auto_route":     true,
		"strict_route":   false,
		"endpoint_independent_nat": true,
		"sniff":         true,
		"file_descriptor": tunFD,
	}
	raw["inbounds"] = append([]any{tun}, inbounds...)

	merged, err := json.Marshal(raw)
	if err != nil {
		return fmt.Errorf("engine: re-marshal: %w", err)
	}

	var options boxoption.Options
	if err := options.UnmarshalJSON(merged); err != nil {
		return fmt.Errorf("engine: option parse: %w", err)
	}

	// PlatformInterface lets sing-box ask us for socket-protection
	// each time it opens an upstream socket (essential — without it
	// outbound packets are routed *back* through the TUN, causing a
	// loop that wedges the VPN).
	s.platform = newAndroidPlatform()
	bctx := context.WithValue(ctx, adapter.PlatformInterfaceKey{}, s.platform)

	inst, err := box.New(box.Options{Context: bctx, Options: options})
	if err != nil {
		return fmt.Errorf("engine: box.New: %w", err)
	}
	if err := inst.Start(); err != nil {
		_ = inst.Close()
		s.Stub.mu.Lock()
		s.Stub.publishLocked(Event{
			Type:     "failure",
			Category: diagnostics.Classify(err.Error()),
			Reason:   err.Error(),
			Bucket:   hourBucket(time.Now()),
		})
		s.Stub.mu.Unlock()
		return err
	}
	s.instance = inst

	s.Stub.mu.Lock()
	s.Stub.connected = true
	s.Stub.publishLocked(Event{Type: "state", State: "Connected", Bucket: hourBucket(time.Now())})
	s.Stub.mu.Unlock()
	return nil
}

func (s *singBox) Stop() error {
	s.mu.Lock()
	inst := s.instance
	s.instance = nil
	s.mu.Unlock()
	if inst == nil {
		return nil
	}
	err := inst.Close()
	s.Stub.mu.Lock()
	s.Stub.connected = false
	s.Stub.publishLocked(Event{Type: "state", State: "Disconnected", Bucket: hourBucket(time.Now())})
	s.Stub.mu.Unlock()
	return err
}

// Stats reads bytes via the clash tracker the box wires up internally.
// For Phase 45 we report zero from this path and rely on routestore's
// per-route counters; the device proof for Gap 2 is "real traffic
// flows", not "stats are accurate". A follow-up phase upgrades this.
func (s *singBox) Stats() (int64, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.instance == nil {
		return 0, 0, errors.New("engine: not connected")
	}
	if s.platform != nil {
		in := atomic.LoadInt64(&s.platform.bytesIn)
		out := atomic.LoadInt64(&s.platform.bytesOut)
		return in, out, nil
	}
	return 0, 0, nil
}
