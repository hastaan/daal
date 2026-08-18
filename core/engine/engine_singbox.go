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

// HasRealDataPlane — see the twin in engine_default.go. TRUE here: this
// build links the in-process sing-box driver, whose Start() refuses to
// run without a TUN fd and returns a real error when the instance
// cannot be brought up. The ABI's fail-closed guard in
// core/abi/dataplane.go is therefore inert on singbox builds.
const HasRealDataPlane = true

// HasByteAccounting — see the twin in engine_default.go.
//
// FALSE, and deliberately so on a build that CAN carry traffic. The
// counters singBox.Stats() reads live in platformInterface
// (platform_singbox.go) and are declared "reserved for the stats
// follow-up phase": nothing in this repository ever writes them, so
// Stats() returns (0, 0, nil) on a tunnel that is moving megabytes.
// Reporting that as a measured zero is the lie; core/abi's
// ThroughputSnapshot reads this constant and reports "unmeasured"
// instead. Flip it to true in the same change that starts writing
// platformInterface.bytesIn/bytesOut, and the UI begins rendering
// numbers with no further edits.
const HasByteAccounting = false

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
	// From here the previously-live refresh inlet is gone (either this
	// call tears the old instance down, or it fails and leaves nothing
	// running). Retract it before doing anything else so no window
	// exists in which the host is told to dial a dead loopback port —
	// the staged inlet for THIS activation survives, and is published
	// again only once the new instance is up. See engine/inlet.go.
	unpublishRefreshInlet()
	if s.instance != nil {
		// Route switch: the host establishes a fresh TUN and calls
		// set_route for the new route, which can race ahead of the old
		// VpnService's onRevoke teardown — so the previous instance is
		// still live here. Tear it down and start the new one rather
		// than failing "already started" (which left the switch dead).
		_ = s.instance.Close()
		s.instance = nil
		s.Stub.mu.Lock()
		s.Stub.connected = false
		s.Stub.mu.Unlock()
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
	// TUN inbound over the fd the host (Android VpnService / desktop
	// tun-helper) already established. Critical constraints for that
	// topology:
	//   - stack MUST be "gvisor": the userspace netstack reads/writes
	//     packets on the fd and never binds a host socket. The default
	//     "system"/"mixed" stack tries to `listen` on the tun address,
	//     which fails on Android ("bind: cannot assign requested
	//     address") because the OS owns the interface.
	//   - auto_route stays true so sing-box wires the netstack's packet
	//     forwarding to the router. It does NOT manipulate system
	//     routing here: with a PlatformInterface present
	//     (androidPlatform.UsePlatformInterface()==true) sing-box skips
	//     the ip-rule/iptables work — the VpnService Builder already
	//     installed 0.0.0.0/0 + ::/0 into the fd. Setting it false
	//     leaves the gvisor TCP forwarder unwired, so the netstack RSTs
	//     every connection ("Connection refused" from the tun address).
	//   - address MUST match what the VpnService established
	//     (10.20.30.40/30, see DaalVpnService.onStartCommand).
	// NB: no `sniff` — it is a legacy inbound field removed in sing-box
	// 1.13 (box.New rejects it: "legacy inbound fields … removed").
	// route.final sends all traffic to the single outbound, so
	// destination sniffing is unnecessary.
	tun := map[string]any{
		"tag":            "tun-in",
		"type":           "tun",
		"interface_name": "daal-tun",
		"address":        []any{"10.20.30.40/30"},
		"mtu":            1500,
		"auto_route":     true,
		"strict_route":   false,
		"stack":          "gvisor",
	}
	raw["inbounds"] = append([]any{tun}, inbounds...)

	// route.udp_gated is daal's marker (BuildSingBoxConfig), not
	// sing-box schema — the path manager already enforced the gate
	// before this route reached Start, so strip it.
	//
	// We deliberately do NOT set auto_detect_interface. On Android that
	// flag makes the dialer bind every upstream socket to an auto-
	// detected underlying interface, which requires enumerating
	// interfaces — impossible in the app sandbox (netlink RTM_GETLINK,
	// /proc/net/*, and /sys/class/net are all SELinux-denied), so it
	// fails every dial with "no available network interface". Instead
	// the VpnService excludes our own package (addDisallowedApplication),
	// so the engine's upstream sockets bypass the TUN at the routing
	// layer and can dial normally without binding to an interface.
	route, _ := raw["route"].(map[string]any)
	if route == nil {
		route = map[string]any{}
	}
	delete(route, "udp_gated")
	raw["route"] = route

	// DNS must resolve THROUGH the tunnel (detour=active) or the whole
	// point is defeated (and, more immediately, name lookups fail so no
	// connection starts). Use DNS-over-TCP (tcp://): the active outbound
	// may be a TCP-only transport (naive is an HTTP proxy) that cannot
	// carry UDP, so plain UDP DNS fails "UDP is not supported by
	// outbound". TCP DNS works over every transport. Only add a default
	// if the profile didn't bring its own dns block. Legacy server shape —
	// still accepted in v1.13.
	if _, ok := raw["dns"]; !ok {
		raw["dns"] = map[string]any{
			"servers": []any{
				map[string]any{"tag": "remote", "address": "tcp://1.1.1.1", "detour": "active"},
			},
			"final":    "remote",
			"strategy": "prefer_ipv4",
		}
	}

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

	// Load libcronet.so before box.New builds any naive outbound (no-op
	// unless the engine was built with the naive/Cronet tags). See
	// cronet_loader_naive.go.
	loadCronet()

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

	// The instance is up, which means sing-box has bound every inbound
	// in the config — including the loopback SOCKS5 refresh inlet. Only
	// NOW may the host be told the inlet exists: publishing it earlier
	// would let the first scheduled refresh dial a port nobody is
	// listening on. See engine/inlet.go.
	promoteRefreshInlet()

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
	// Unconditionally — even on the no-instance path — so a stop can
	// never leave a live inlet record behind a dead listener.
	retireRefreshInlet()
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
