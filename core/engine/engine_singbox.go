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
	"github.com/sagernet/sing-box/include"
	boxoption "github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
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

	// The fd itself is NOT written into the config — sing-box v1.13's
	// TUN options have no file_descriptor field. It travels through
	// androidPlatform.OpenInterface, which sing-tun consults because a
	// PlatformInterface is present in the box context. We only refuse
	// early here so the error names the actual contract violation.
	if CurrentTunFD() < 0 {
		androidLog("TUN fd not set before set_route")
		return errors.New("engine: TUN fd not set; VpnService must call engine_set_tun_fd before engine_set_route")
	}
	inbounds, _ := raw["inbounds"].([]any)
	tun := map[string]any{
		"tag":            "tun-in",
		"type":           "tun",
		"interface_name": "daal-tun",
		"address":        []any{"172.19.0.1/30"},
		"mtu":            1500,
		"auto_route":     true,
		"strict_route":   false,
	}
	raw["inbounds"] = append([]any{tun}, inbounds...)

	// route.udp_gated is daal's marker (BuildSingBoxConfig), not
	// sing-box schema — the path manager already enforced the gate
	// before this route reached Start, so strip it. And when the host
	// registered a protect callback, upstream sockets must be routed
	// through the platform control (VpnService.protect) or they loop
	// straight back into the TUN and wedge the VPN.
	route, _ := raw["route"].(map[string]any)
	if route == nil {
		route = map[string]any{}
	}
	delete(route, "udp_gated")
	if CurrentProtectCallback() != 0 {
		route["auto_detect_interface"] = true
	}
	raw["route"] = route

	merged, err := json.Marshal(raw)
	if err != nil {
		return fmt.Errorf("engine: re-marshal: %w", err)
	}

	// PlatformInterface lets sing-box ask us for socket-protection
	// each time it opens an upstream socket (essential — without it
	// outbound packets are routed *back* through the TUN, causing a
	// loop that wedges the VPN) and for the TUN device built from the
	// host-supplied fd.
	s.platform = newAndroidPlatform()
	bctx := include.Context(ctx)
	bctx = service.ContextWith[adapter.PlatformInterface](bctx, s.platform)

	options, err := singjson.UnmarshalExtendedContext[boxoption.Options](bctx, merged)
	if err != nil {
		androidLog("option parse: " + err.Error() + " | config=" + string(merged))
		return fmt.Errorf("engine: option parse: %w", err)
	}

	inst, err := box.New(box.Options{Context: bctx, Options: options})
	if err != nil {
		androidLog("box.New: " + err.Error())
		return fmt.Errorf("engine: box.New: %w", err)
	}
	if err := inst.Start(); err != nil {
		androidLog("instance.Start: " + err.Error())
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
