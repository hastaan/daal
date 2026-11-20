//go:build singbox

package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"

	"daal/core/desync"
	"daal/core/diagnostics"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	boxoption "github.com/sagernet/sing-box/option"
	tun "github.com/sagernet/sing-tun"
	singjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

// THE SIDE INSTANCE — how a route that is not the tunnel's route is
// proved.
//
// WHAT IT IS. A second, short-lived sing-box in this process, built
// from the SAME engine-side config Driver.Start takes for the route,
// with two things taken out before sing-box ever sees it:
//
//   - every inbound. No TUN inbound is added (Start adds one; this path
//     does not), and the loopback refresh inlet the config carries is
//     removed. So the instance has no way in: no app packet, no
//     in-process fetch and no co-resident app can send anything through
//     it. The only traffic it ever carries is the connection proof,
//     which dials its "active" outbound directly (proof.go) — the same
//     proof, the same targets, the same classification as a connect.
//   - nothing else. The outbound, its credentials and the route's dns
//     block are the route's own.
//
// WHAT IT OWNS. Its own box.Box, its own context, its own outbound
// sockets. Those sockets are protected exactly like the tunnel
// instance's: the box context carries a PlatformInterface whose
// AutoDetectInterfaceControl calls the host's registered protect
// callback (sidePlatform embeds the tunnel instance's androidPlatform
// for that and nothing else).
//
// WHY IT CANNOT TOUCH THE TUN. It never asks for one — there is no tun
// inbound to open — and if anything ever did, sidePlatform.OpenInterface
// refuses instead of duplicating the host's fd. It never calls
// dupTunFD, AdoptTunFD or ReleaseTunFD.
//
// WHY IT CANNOT TOUCH THE RUNNING ROUTE. It shares no object with the
// driver's instance: SideProbe reads nothing from singBox but the
// counter of side probes, and never takes singBox.mu, so a Start, a
// Stop or a Prove of the tunnel instance neither waits for a side probe
// nor is seen by one. It does not publish, promote or retire the
// refresh inlet (inlet.go), and it publishes no event: what a side
// probe found is the caller's to record.
//
// WHO CLOSES IT. SideProbe itself, before it returns, on every path:
// success, failure, a start that failed half-way, cancellation. The
// instance's context is a child of the caller's, so cancelling the
// caller's context ends its dials at once (the reason closeInstance
// cancels before it closes), and StopSideProbes — engine shutdown —
// cancels every one in flight and waits until they are closed.
//
// WHAT IT COSTS. One more sing-box (no netstack: gvisor comes with the
// TUN inbound, which is absent) for the length of one connection check
// — at most the check's own bound — and never more than MaxSideProbes
// at once.
//
// WHICH ROUTES. Only the outbound types in sideProbeTypes (side.go),
// where a second outbound is private and side-effect-free. Everything
// else — naive, tor, wireguard, anything detoured — answers
// CanSideProbe false and is tried alone through the tunnel's instance.

// sidePlatform is the PlatformInterface of a side instance: socket
// protection, and no TUN.
type sidePlatform struct{ *androidPlatform }

var errSideHoldsNoTun = errors.New("engine: a side instance holds no TUN")

func (p *sidePlatform) OpenInterface(*tun.Options, boxoption.TunPlatformOptions) (tun.Tun, error) {
	return nil, errSideHoldsNoTun
}

var _ adapter.PlatformInterface = (*sidePlatform)(nil)

func (s *singBox) CanSideProbe(configJSON []byte) bool { return SideProbeable(configJSON) }

// SideProbe is the sing-box driver's side probe. See the top of this
// file, and SideProber (side.go) for the contract.
func (s *singBox) SideProbe(ctx context.Context, configJSON []byte, cfg ProofConfig) (ProofResult, error) {
	if !SideProbeable(configJSON) {
		return ProofResult{}, ErrSideProbeUnsupported
	}
	pctx, leave, err := s.Stub.side.enter(ctx)
	if err != nil {
		return ProofResult{}, err
	}
	// Runs last: only once the instance below is closed is this probe
	// no longer "in flight" for StopSideProbes.
	defer leave()
	inst, kind, cancel, err := startSideInstance(pctx, configJSON)
	if err != nil {
		if pctx.Err() != nil {
			return ProofResult{Cancelled: true, Err: ErrProofCancelled}, nil
		}
		return ProofResult{}, err
	}
	defer func() { _ = closeInstance(inst, cancel); sideInstancesClosed.Add(1) }()
	return proofSubject{inst: inst, kind: kind}.prove(pctx, cfg), nil
}

// sideInstancesStarted / sideInstancesClosed count the side instances
// of this process: every one that started must be closed by the time
// its SideProbe returns. A test holds the two equal.
var sideInstancesStarted, sideInstancesClosed atomic.Int64

// sideConfig is the engine-side config with everything a side instance
// must not have taken out. Separate from startSideInstance so a test can
// read what sing-box is handed.
func sideConfig(configJSON []byte) ([]byte, map[string]any, error) {
	var raw map[string]any
	if err := json.Unmarshal(configJSON, &raw); err != nil {
		return nil, nil, fmt.Errorf("engine: parse config: %w", err)
	}
	// No way in: not the TUN (never added here), not the refresh inlet.
	delete(raw, "inbounds")
	if route, _ := raw["route"].(map[string]any); route != nil {
		delete(route, "udp_gated")
		// The hijack-dns rule is about app lookups arriving on the TUN.
		delete(route, "rules")
	}
	if _, ok := raw["dns"]; !ok {
		raw["dns"] = defaultDNSBlock()
	}
	merged, err := json.Marshal(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("engine: re-marshal: %w", err)
	}
	return merged, raw, nil
}

// startSideInstance builds and starts the side instance. On success the
// caller owns it and must closeInstance(inst, cancel); on failure
// nothing is left behind.
func startSideInstance(ctx context.Context, configJSON []byte) (*box.Box, outboundKind, context.CancelFunc, error) {
	merged, raw, err := sideConfig(configJSON)
	if err != nil {
		return nil, outboundKind{}, nil, err
	}
	ictx, cancel := context.WithCancel(ctx)
	inst, err := buildSideInstance(ictx, merged, raw)
	if err != nil {
		cancel()
		return nil, outboundKind{}, nil, err
	}
	if err := inst.Start(); err != nil {
		LogError(fmt.Sprintf("side: instance.Start failed class=%s category=%s outbound=%s", errorClass(err), diagnostics.Classify(err.Error()), activeOutboundType(raw)))
		_ = closeInstance(inst, cancel)
		return nil, outboundKind{}, nil, err
	}
	sideInstancesStarted.Add(1)
	return inst, kindOfActive(raw), cancel, nil
}

// buildSideInstance is the part of the start that must not run beside
// another instance's build (boxBuildMu).
func buildSideInstance(ictx context.Context, merged []byte, raw map[string]any) (*box.Box, error) {
	boxBuildMu.Lock()
	defer boxBuildMu.Unlock()
	bctx := desync.BoxContext(ictx) // include.Context + daal-desync: see singBox.Start
	bctx = service.ContextWith[adapter.PlatformInterface](bctx, &sidePlatform{newAndroidPlatform()})
	options, err := singjson.UnmarshalExtendedContext[boxoption.Options](bctx, merged)
	if err != nil {
		// Class and outbound kind only: see singBox.Start.
		LogError(fmt.Sprintf("side: option parse failed class=%s outbound=%s", errorClass(err), activeOutboundType(raw)))
		return nil, fmt.Errorf("engine: option parse: %w", err)
	}
	inst, err := box.New(box.Options{Context: bctx, Options: options})
	if err != nil {
		LogError(fmt.Sprintf("side: box.New failed class=%s category=%s outbound=%s", errorClass(err), diagnostics.Classify(err.Error()), activeOutboundType(raw)))
		return nil, fmt.Errorf("engine: box.New: %w", err)
	}
	return inst, nil
}
