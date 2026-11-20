package engine

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
)

// Side probes — proving a route that is NOT the tunnel's route.
//
// The design, and everything that keeps it safe, is written at the top
// of side_singbox.go (the real driver). This file holds what every
// build shares: the interface the ABI asks through, which routes may be
// probed that way at all, and the Stub's scripted twin for the ABI's
// unit tests.

// MaxSideProbes is how many side probes one driver runs at a time.
// The ABI never asks for more (core/abi/connect_race.go); the driver
// refuses a third regardless (ErrSideProbeBusy).
const MaxSideProbes = 2

var (
	// ErrSideProbeBusy: MaxSideProbes are already in flight.
	ErrSideProbeBusy = errors.New("engine: too many side probes in flight")
	// ErrSideProbeUnsupported: this route cannot be probed beside the
	// running one (SideProbeable), or this driver cannot do it.
	ErrSideProbeUnsupported = errors.New("engine: this route cannot be probed beside the running one")
)

// SideProber is implemented by a Driver that can prove a route in an
// instance of its own, beside whatever the driver is running.
type SideProber interface {
	// CanSideProbe: may the route with this engine-side config (the
	// bytes Driver.Start takes) be proved in a side instance?
	CanSideProbe(configJSON []byte) bool
	// CanSurveyProbe: CanSideProbe, or a naive route this driver can
	// prove in a side instance when the caller says so
	// (ProofConfig.SideCronet). The survey's question, not a race's.
	CanSurveyProbe(configJSON []byte) bool
	// SideProbe starts a side instance for the config, makes the
	// connection proof through it, and tears it down — on every path —
	// before it returns. It blocks; cancelling ctx ends it promptly
	// (ProofResult.Cancelled). The error is non-nil when no proof was
	// made: the instance could not be built or started, the route is
	// not SideProbeable, or MaxSideProbes are in flight.
	//
	// It never touches the driver's running instance, the TUN or the
	// refresh inlet, and it publishes no event.
	SideProbe(ctx context.Context, configJSON []byte, cfg ProofConfig) (ProofResult, error)
	// StopSideProbes cancels every side probe in flight and returns
	// when their instances are closed.
	StopSideProbes()
}

// sideProbeTypes are the sing-box outbound types a side instance may be
// built for. The rule is the diagnosis twin's (proof_singbox.go,
// twinTypes): a second outbound of the kind must be a private, cheap,
// side-effect-free thing to open.
//
// NOT here, and so never raced — tried alone, in order, through the
// tunnel's own instance:
//
//   - naive — for a RACE. The outbound lives inside Cronet. This was
//     first left out because the library, its network thread and its
//     session state were thought process-wide. Looked at again
//     (2026-11-20): the library is loaded once, but each naive outbound
//     builds its own Cronet engine (its own network thread, socket pool
//     and HTTP/2 sessions; cronet-go keys its dialer table by engine),
//     and its sockets come from the outbound's Go dialer — protected
//     exactly like the tunnel's. A side instance of a naive route beside
//     a carrying naive tunnel proves, repeatedly and when stopped
//     half-way, and the tunnel's open connection and its own proof are
//     untouched (side_naive_singbox_test.go, real libcronet.so). So the
//     SURVEY may prove naive beside the tunnel (cronetSideTypes, asked
//     for per call: ProofConfig.SideCronet). Races and the speed move
//     still may not: a Cronet engine costs far more to build than any
//     outbound here, a race's point is speed, and that change has not
//     been made on a phone.
//   - tor: a second tor process on the same data directory, and minutes
//     of bootstrap.
//   - wireguard / amneziawg (endpoints, not outbounds): a second
//     handshake with the same key moves the peer's session at the
//     server, which is how to break a tunnel that is carrying.
//   - anything dialled through a detour, and every type this list does
//     not name (ssh, shadowtls, a transport module, …).
var sideProbeTypes = map[string]bool{"vless": true, "vmess": true, "trojan": true, "shadowsocks": true, "anytls": true,
	"hysteria": true, "hysteria2": true, "tuic": true, "http": true, "socks": true}

// cronetSideTypes: the outbound types a side instance may ALSO be built
// for when the caller asks (ProofConfig.SideCronet) — the survey only.
// See naive above.
var cronetSideTypes = map[string]bool{"naive": true}

// SideProbeable reports whether the route with this engine-side config
// may be proved in a side instance. It reads the config the same way on
// every build, so the ABI's ordering does not depend on the driver.
func SideProbeable(configJSON []byte) bool {
	return sideProbeableAs(configJSON, func(t string) bool { return sideProbeTypes[t] })
}

// SurveyProbeable is SideProbeable with cronetSideTypes allowed too: may
// the SURVEY prove this route in a side instance?
func SurveyProbeable(configJSON []byte) bool {
	return sideProbeableAs(configJSON, func(t string) bool { return sideProbeTypes[t] || cronetSideTypes[t] })
}

// cronetSide: the route is one only the survey may side-probe.
func cronetSide(configJSON []byte) bool {
	return SurveyProbeable(configJSON) && !SideProbeable(configJSON)
}

// sideAllowed: may a side probe asked for with cfg be made of this
// route?
func sideAllowed(configJSON []byte, cfg ProofConfig) bool {
	return SideProbeable(configJSON) || (cfg.SideCronet && SurveyProbeable(configJSON))
}

func sideProbeableAs(configJSON []byte, allowed func(string) bool) bool {
	var raw struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if json.Unmarshal(configJSON, &raw) != nil {
		return false
	}
	for _, ob := range raw.Outbounds {
		if ob["tag"] != "active" {
			continue
		}
		t, _ := ob["type"].(string)
		// The engine's own desync detour is not "a detour" here: it adds
		// no hop and holds no state (desync.go, ownDesyncDetour).
		if _, detoured := ob["detour"]; (detoured && !ownDesyncDetour(ob, raw.Outbounds)) || !allowed(t) {
			return false
		}
		server, _ := ob["server"].(string)
		return server != ""
	}
	// No active OUTBOUND: an endpoint (wireguard), or nothing at all.
	return false
}

// ---- bookkeeping shared by every driver --------------------------------

// sideSet counts the side probes of one driver, refuses one too many,
// and can end them all.
type sideSet struct {
	mu       sync.Mutex
	inFlight int
	peak     int
	total    int
	seq      int
	cancels  map[int]context.CancelFunc
	wg       sync.WaitGroup
}

// enter admits one side probe: the context it must run on, and the
// function it must call when its instance is closed. ErrSideProbeBusy
// when MaxSideProbes are already in flight.
func (sd *sideSet) enter(ctx context.Context) (context.Context, func(), error) {
	sd.mu.Lock()
	defer sd.mu.Unlock()
	if sd.inFlight >= MaxSideProbes {
		return nil, nil, ErrSideProbeBusy
	}
	pctx, cancel := context.WithCancel(ctx)
	sd.inFlight++
	sd.total++
	if sd.inFlight > sd.peak {
		sd.peak = sd.inFlight
	}
	if sd.cancels == nil {
		sd.cancels = map[int]context.CancelFunc{}
	}
	sd.seq++
	id := sd.seq
	sd.cancels[id] = cancel
	sd.wg.Add(1)
	return pctx, func() {
		cancel()
		sd.mu.Lock()
		sd.inFlight--
		delete(sd.cancels, id)
		sd.mu.Unlock()
		sd.wg.Done()
	}, nil
}

func (sd *sideSet) stopAll() {
	sd.mu.Lock()
	for _, cancel := range sd.cancels {
		cancel()
	}
	sd.mu.Unlock()
	sd.wg.Wait()
}

// SideProbeStats: how many side probes this driver ran in all, and the
// most that were ever in flight at once.
func (s *Stub) SideProbeStats() (total, peak int) {
	s.side.mu.Lock()
	defer s.side.mu.Unlock()
	return s.side.total, s.side.peak
}

// SideProbesInFlight reports how many side probes are running now.
func (s *Stub) SideProbesInFlight() int {
	s.side.mu.Lock()
	defer s.side.mu.Unlock()
	return s.side.inFlight
}

// StopSideProbes cancels every side probe in flight and waits for their
// instances to be closed. (The sing-box driver embeds the Stub and
// shares this.)
func (s *Stub) StopSideProbes() { s.side.stopAll() }

// ---- the Stub's twin -------------------------------------------------

// A Stub side-probes only once a hook is installed: without one it
// answers CanSideProbe false, and the ABI stays on its sequential path —
// which is what every test written before side probes existed expects.

// SetSideProbeHook makes the Stub answer side probes with f (nil turns
// side probing off again).
func (s *Stub) SetSideProbeHook(f func(ctx context.Context, configJSON []byte, cfg ProofConfig) (ProofResult, error)) {
	s.side.mu.Lock()
	s.sideHook = f
	s.side.mu.Unlock()
}

func (s *Stub) stubSideHook() func(ctx context.Context, configJSON []byte, cfg ProofConfig) (ProofResult, error) {
	s.side.mu.Lock()
	defer s.side.mu.Unlock()
	return s.sideHook
}

func (s *Stub) CanSideProbe(configJSON []byte) bool {
	return s.stubSideHook() != nil && SideProbeable(configJSON)
}

func (s *Stub) CanSurveyProbe(configJSON []byte) bool {
	return s.stubSideHook() != nil && SurveyProbeable(configJSON)
}

func (s *Stub) SideProbe(ctx context.Context, configJSON []byte, cfg ProofConfig) (ProofResult, error) {
	hook := s.stubSideHook()
	if hook == nil || !sideAllowed(configJSON, cfg) {
		return ProofResult{}, ErrSideProbeUnsupported
	}
	pctx, leave, err := s.side.enter(ctx)
	if err != nil {
		return ProofResult{}, err
	}
	defer leave()
	res, err := hook(pctx, configJSON, cfg)
	if err == nil && !res.OK && pctx.Err() != nil {
		return ProofResult{Cancelled: true, Err: ErrProofCancelled}, nil
	}
	return res, err
}
