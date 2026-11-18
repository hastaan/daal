//go:build singbox

package engine

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"math/rand/v2"
	"net"
	"time"

	"daal/core/diagnostics"

	box "github.com/sagernet/sing-box"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// activeTag is the tag BuildSingBoxConfig gives the route's outbound (or
// endpoint) and route.final points at.
const activeTag = "active"

// outboundKind is what the proof needs to know about the active
// outbound in order to read its failures (diagnostics.Observation).
type outboundKind struct {
	Type string
	// UDP: the transport to the relay is UDP.
	UDP bool
	// TLS: the first flight to the relay is a TLS ClientHello.
	TLS bool
	// Lazy: DialContext returns before anything has been sent to the
	// relay (naive: the whole connection lives inside Cronet), so an
	// error from the round trip may be from any phase.
	Lazy bool
	// Server / ServerPort: where the outbound dials, for the reach check.
	Server     string
	ServerPort uint16
	// SlowStart: the outbound needs far longer than a handshake before
	// its first connection can succeed (tor builds circuits). The
	// attempt timeout is stretched for it; the meaning of the proof is
	// not.
	SlowStart bool
}

// udpOutboundTypes are the sing-box types whose transport to the relay
// is UDP. tlsOutboundTypes are the ones that speak TLS to the relay
// whether or not the profile carries a "tls" block.
var (
	udpOutboundTypes = map[string]bool{"hysteria": true, "hysteria2": true, "tuic": true, "wireguard": true}
	tlsOutboundTypes = map[string]bool{"naive": true, "anytls": true, "trojan": true, "shadowtls": true}
)

// kindOfActive reads the active outbound's kind out of the config Start
// was handed (the engine-side JSON, before sing-box parses it).
func kindOfActive(raw map[string]any) outboundKind {
	var k outboundKind
	for _, key := range []string{"outbounds", "endpoints"} {
		list, _ := raw[key].([]any)
		for _, x := range list {
			ob, _ := x.(map[string]any)
			if ob == nil || ob["tag"] != activeTag {
				continue
			}
			k.Type, _ = ob["type"].(string)
			k.UDP = udpOutboundTypes[k.Type]
			k.TLS = tlsOutboundTypes[k.Type]
			if t, _ := ob["tls"].(map[string]any); t != nil {
				if on, _ := t["enabled"].(bool); on {
					k.TLS = true
				}
			}
			if tr, _ := ob["transport"].(map[string]any); tr != nil && tr["type"] == "quic" {
				k.UDP = true
			}
			k.SlowStart = k.Type == "tor"
			k.Lazy = k.Type == "naive"
			k.Server, _ = ob["server"].(string)
			if p, ok := ob["server_port"].(float64); ok && p > 0 && p < 65536 {
				k.ServerPort = uint16(p)
			}
			return k
		}
	}
	return k
}

func kindFromJSON(configJSON []byte) outboundKind {
	var raw map[string]any
	_ = json.Unmarshal(configJSON, &raw)
	return kindOfActive(raw)
}

// torAttemptTimeout is one proof attempt on a tor route: a cold tor
// bootstraps and builds a circuit before it can carry anything.
const torAttemptTimeout = 90 * time.Second

// Prove is the singBox driver's connection proof. See proof.go.
func (s *singBox) Prove(ctx context.Context, cfg ProofConfig) ProofResult {
	s.mu.Lock()
	inst, kind := s.instance, s.kind
	s.mu.Unlock()
	if inst == nil {
		return ProofResult{Err: ErrNotRunning, Observation: diagnostics.Observation{Message: ErrNotRunning.Error()}}
	}
	return proveInstance(ctx, inst, kind, cfg)
}

// proveInstance makes the round trip through inst's active outbound. It
// is a function of the instance, not of the driver, so the singbox test
// build can prove a box that was started without a TUN.
func proveInstance(ctx context.Context, inst *box.Box, kind outboundKind, cfg ProofConfig) ProofResult {
	ob, ok := inst.Outbound().Outbound(activeTag)
	if !ok {
		err := ErrNotRunning
		return ProofResult{Err: err, Observation: diagnostics.Observation{Message: "engine: no active outbound"}}
	}
	if kind.SlowStart && cfg.AttemptTimeout < torAttemptTimeout {
		cfg.AttemptTimeout = torAttemptTimeout
	}
	if norm, err := cfg.Normalised(); err == nil {
		cfg = norm
	}
	var reach *reachCheck
	res := runProof(ctx, cfg, rand.IntN, func(actx context.Context, host string, port uint16) (diagnostics.Observation, error) {
		obs, err := proveOnce(actx, ob, kind, host, port)
		if err != nil && reach == nil && timeoutPhaseIsUnknown(obs, kind) {
			// Runs alongside the next attempt, on the proof's context
			// (not the attempt's, which is about to end).
			reach = startReachCheck(ctx, inst, kind, cfg.AttemptTimeout)
		}
		return obs, err
	})
	if !res.OK && !res.Cancelled && reach != nil && timeoutPhaseIsUnknown(res.Observation, kind) {
		reach.settle(ctx, &res.Observation)
		if n := len(res.Failed); n > 0 {
			res.Failed[n-1] = res.Observation
		}
	}
	return res
}

// proveOnce is one round trip: open a connection through the outbound,
// read a TLS ServerHello back from the far side.
func proveOnce(ctx context.Context, ob N.Dialer, kind outboundKind, host string, port uint16) (diagnostics.Observation, error) {
	// Everything before DialContext returns is between the device and
	// the relay. Which half of that (the SYN, or the family's own
	// handshake) is read from the error where it can be: a failed
	// connect() is a *net.OpError with Op "dial" (diagnostics.Observe).
	// For a TIMEOUT that reading is not trustworthy — see
	// timeoutPhaseIsUnknown — and the reach check settles it.
	conn, err := ob.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddrHostPort(host, port))
	if err != nil {
		return diagnostics.Observe(err, diagnostics.PhaseHandshake, kind.UDP, kind.TLS), err
	}
	defer conn.Close()
	// An abandoned proof must let go at once (disconnect must not wait
	// for it), and a deadline keeps a silent far end from holding the
	// attempt past its budget.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	tcfg := &tls.Config{
		// Nothing is authenticated here, deliberately: see "THE TARGET"
		// in proof.go. No application data is ever written to this
		// connection.
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}
	if net.ParseIP(host) == nil {
		tcfg.ServerName = host
	}
	tc := tls.Client(conn, tcfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		// The outbound handed over a connection: for most families the
		// relay has answered by now. Families that dial lazily report
		// their connect error here instead, and Observe moves those
		// back to the reach phase.
		return diagnostics.Observe(err, diagnostics.PhaseCarry, kind.UDP, kind.TLS), err
	}
	return diagnostics.Observation{}, nil
}

// timeoutPhaseIsUnknown reports whether a failed attempt is a timeout
// whose phase the error cannot be trusted to give.
//
// Two ways that happens, both observed against sing-box 1.13.12:
//
//   - A multiplexed outbound (the vless routes a relay mints carry
//     h2mux) retries its session dial once inside DialContext. When the
//     first try used up the attempt's deadline in the TLS handshake, the
//     retry dials on an expired context and Go answers "dial tcp …: i/o
//     timeout" at once — a *net.OpError with Op "dial" for a connection
//     whose SYN was answered seconds ago. Read literally that turns a
//     swallowed ClientHello (tls_handshake_failed) into a dead address
//     (tcp_connect_timeout).
//   - A lazy outbound (naive) reports every timeout from the round trip,
//     as a bare "context deadline exceeded".
//
// UDP routes are excluded: silence is udp_no_reply whatever the phase.
func timeoutPhaseIsUnknown(o diagnostics.Observation, kind outboundKind) bool {
	if kind.UDP || !o.Timeout {
		return false
	}
	return o.Phase != diagnostics.PhaseCarry || kind.Lazy
}

// reachCheck answers one question about a route whose attempt timed out:
// does the relay's address answer a SYN at all?
//
// It is a bare TCP connect to the outbound's own server and port, made
// through the same instance's "direct" outbound — so the socket is
// protected from the tunnel exactly as the family's own are, and what
// the network sees is the first packet the family itself sends, to the
// endpoint the device is already known to be talking to. It runs only
// AFTER an attempt has failed, never on a healthy connect.
type reachCheck struct {
	done chan struct{}
	err  error
	ran  bool
}

func startReachCheck(ctx context.Context, inst *box.Box, kind outboundKind, budget time.Duration) *reachCheck {
	r := &reachCheck{done: make(chan struct{})}
	direct, ok := inst.Outbound().Outbound("direct")
	// A server given by name would be resolved through the tunnel that
	// is being diagnosed; only a literal address can be checked.
	if !ok || kind.ServerPort == 0 || net.ParseIP(kind.Server) == nil {
		close(r.done)
		return r
	}
	r.ran = true
	go func() {
		defer close(r.done)
		rctx, cancel := context.WithTimeout(ctx, budget)
		defer cancel()
		conn, err := direct.DialContext(rctx, N.NetworkTCP, M.ParseSocksaddrHostPort(kind.Server, kind.ServerPort))
		if err == nil {
			_ = conn.Close()
		}
		r.err = err
	}()
	return r
}

// settle waits for the check and writes what it found into the
// observation of the timed-out attempt.
func (r *reachCheck) settle(ctx context.Context, o *diagnostics.Observation) {
	select {
	case <-r.done:
	case <-ctx.Done():
		return
	}
	if !r.ran {
		return
	}
	if r.err == nil {
		// The SYN is answered, so the silence came after it.
		o.Phase = diagnostics.PhaseHandshake
		return
	}
	probe := diagnostics.Observe(r.err, diagnostics.PhaseReach, false, false)
	o.Phase = diagnostics.PhaseReach
	if probe.Refused || probe.Reset {
		o.Timeout, o.Refused = false, true
	}
}
