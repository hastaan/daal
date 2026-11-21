//go:build singbox

package engine

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net"
	"sync/atomic"
	"time"

	"daal/core/diagnostics"

	box "github.com/sagernet/sing-box"
	boxoption "github.com/sagernet/sing-box/option"
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
	// HandshakeAtDial: DialContext on a connection the outbound has to
	// open returns only after the RELAY has answered the family's own
	// handshake (TLS to the relay, or QUIC and its authentication). A
	// dial that succeeds on a fresh outbound of such a kind is the
	// relay, alive and accepting, a moment ago.
	HandshakeAtDial bool
	// Twin: a second outbound with the same options can be opened
	// beside the active one for the length of one attempt (see
	// proofSubject.twin). False for kinds where that is not a private,
	// cheap, side-effect-free thing to do: naive (a whole Cronet
	// engine), tor (a second tor), anything dialled through a detour.
	Twin bool
}

// twinTypes are the outbound types a diagnosis twin may be made of.
// handshakeAtDialTypes are the ones whose dial includes the relay's
// answer, given TLS or QUIC to the relay.
var (
	twinTypes = map[string]bool{"vless": true, "vmess": true, "trojan": true, "shadowsocks": true, "anytls": true,
		"hysteria": true, "hysteria2": true, "tuic": true, "http": true, "socks": true}
	handshakeAtDialTypes = map[string]bool{"vless": true, "vmess": true, "trojan": true, "anytls": true,
		"hysteria": true, "hysteria2": true, "tuic": true}
)

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
			_, detoured := ob["detour"]
			if detoured && key == "outbounds" && ownDesyncDetour(ob, objects(list)) {
				detoured = false // the engine's own desync detour: a twin shares it harmlessly
			}
			k.Twin = key == "outbounds" && twinTypes[k.Type] && !detoured
			k.HandshakeAtDial = handshakeAtDialTypes[k.Type] && (k.TLS || k.UDP) && k.Type != "wireguard"
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
	sub := proofSubject{inst: s.instance, kind: s.kind, twin: s.twin}
	s.mu.Unlock()
	if sub.inst == nil {
		return ProofResult{Err: ErrNotRunning, Observation: diagnostics.Observation{Message: ErrNotRunning.Error()}}
	}
	return sub.prove(ctx, cfg)
}

// proofSubject is what a proof is made of: the instance, what its
// active outbound is, and — where the kind allows it — a way to open a
// second outbound exactly like it.
type proofSubject struct {
	inst *box.Box
	kind outboundKind
	// twin opens an outbound with the active one's own options under a
	// tag of its own, and returns it with the function that removes it.
	// nil: no twin for this route.
	twin func() (N.Dialer, func(), error)
}

// proveInstance makes the round trip through inst's active outbound. It
// is a function of the instance, not of the driver, so the singbox test
// build can prove a box that was started without a TUN.
func proveInstance(ctx context.Context, inst *box.Box, kind outboundKind, cfg ProofConfig) ProofResult {
	return proofSubject{inst: inst, kind: kind}.prove(ctx, cfg)
}

func (p proofSubject) prove(ctx context.Context, cfg ProofConfig) ProofResult {
	inst, kind := p.inst, p.kind
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
	sign := slowSign(cfg)
	var reach *reachCheck
	attempt := func(actx context.Context, host string, port uint16) (diagnostics.Observation, error) {
		obs, _, err := proveOnce(actx, ob, kind, host, port, sign)
		if err != nil && reach == nil && cfg.TimeHelloStop && !kind.UDP && kind.TLS && (obs.Reset || obs.Closed) &&
			obs.Phase == diagnostics.PhaseHandshake && obs.DialMs > 0 {
			// A TLS first flight reset or closed on an open connection,
			// in a connect-time proof that asked for it (the automatic
			// connect's: its connect ladder reads the answer): one bare
			// connect to the same address and port times a round trip
			// (Observation.ConnectMs), so a stop that came back sooner
			// than the relay could have sent it (FastReset), or no sooner
			// (ServerStop), can be told. After a failure only, once per
			// proof, nothing written after the handshake, and on a short
			// budget: a SYN the censor now drops must not hold the proof
			// for a whole attempt. Never on a liveness check.
			reach = startReachCheck(ctx, inst, kind, min(helloTimingBudget, cfg.AttemptTimeout))
		}
		if err != nil && reach == nil && timeoutPhaseIsUnknown(obs, kind) {
			// Only where the answer is needed: a timeout whose phase
			// the error does give (the carry phase of a family that
			// dials eagerly — the usual way a liveness check fails)
			// starts nothing. The reach check is a connection to the
			// relay's port that carries no payload, and a failed route
			// is checked again every RecheckInterval; "is the path
			// slow" is already measured on the family's own
			// connections (proveOnce: the dial time, the bytes back).
			//
			// Runs alongside the next attempt, on the proof's context
			// (not the attempt's, which is about to end).
			reach = startReachCheck(ctx, inst, kind, cfg.AttemptTimeout)
		}
		return obs, err
	}
	aids := proofAids{
		settle: func(sctx context.Context, o *diagnostics.Observation) {
			if reach != nil {
				reach.settle(sctx, o, kind, sign)
			}
		},
	}
	if p.twin != nil && kind.Twin {
		aids.diagnose = func(actx context.Context, host string, port uint16) (diagnostics.Observation, error, bool) {
			return p.diagnose(actx, host, port, sign, func(o *diagnostics.Observation) {
				if reach == nil {
					reach = startReachCheck(ctx, inst, kind, cfg.AttemptTimeout)
				}
				reach.settle(ctx, o, kind, sign)
			})
		}
	}
	return runProofWith(ctx, cfg, rand.IntN, attempt, aids)
}

// diagnose is the carry-phase timeout asked again on a connection to
// the relay that did not exist a moment ago.
//
// WHY. An outbound that multiplexes (the vless routes a relay mints),
// pools sessions (anytls) or rides one QUIC connection (hysteria2,
// tuic) answers DialContext from the session it already holds. On a
// route that has been connected for a while that is every dial, so
// when a censor starts dropping the route mid-session the liveness
// check saw "the outbound handed over a connection, then nothing" —
// the carry phase, which classifies as `unknown` — on exactly the
// families where the connect-time proof, dialling fresh, names the
// failure. A twin outbound has no session: its dial is a new SYN, a new
// ClientHello, a new QUIC handshake, and fails where and how a connect
// would.
//
// And when the twin's dial SUCCEEDS on a kind whose dial includes the
// relay's answer, the relay is alive and accepted this device a moment
// ago; if the far side then stays silent through it as well — the third
// host in a row, run by a third party — what is left is a relay that
// does not reach the internet (relay_no_egress).
//
// What the network sees is one more connection of the family's own
// kind to the endpoint the device is already talking to, and only after
// two attempts have failed.
func (p proofSubject) diagnose(actx context.Context, host string, port uint16, sign time.Duration, settle func(*diagnostics.Observation)) (diagnostics.Observation, error, bool) {
	tw, remove, err := p.twin()
	if err != nil {
		return diagnostics.Observation{}, nil, false
	}
	defer remove()
	obs, relayAnswered, err := proveOnce(actx, tw, p.kind, host, port, sign)
	if err == nil {
		return obs, nil, true
	}
	if obs.Timeout && !p.kind.UDP && timeoutPhaseIsUnknown(obs, p.kind) {
		// The twin's own dial timed out in a way that hides the phase:
		// the reach check settles it, as it does for a connect.
		settle(&obs)
	}
	if relayAnswered && obs.Timeout && obs.Phase == diagnostics.PhaseCarry && !obs.Progress {
		obs.RelayNoEgress = true
	}
	return obs, err, true
}

var twinSeq atomic.Uint64

// makeTwin returns proofSubject.twin for the active outbound of inst,
// or nil when the parsed options do not carry one.
func makeTwin(bctx context.Context, inst *box.Box, outbounds []boxoption.Outbound) func() (N.Dialer, func(), error) {
	var active *boxoption.Outbound
	for i := range outbounds {
		if outbounds[i].Tag == activeTag {
			active = &outbounds[i]
		}
	}
	if active == nil {
		return nil
	}
	typ, opts := active.Type, active.Options
	return func() (N.Dialer, func(), error) {
		tag := fmt.Sprintf("%s-check-%d", activeTag, twinSeq.Add(1))
		mgr := inst.Outbound()
		logger := inst.LogFactory().NewLogger("outbound/" + typ + "[" + tag + "]")
		if err := mgr.Create(bctx, inst.Router(), logger, tag, typ, opts); err != nil {
			return nil, nil, err
		}
		tw, ok := mgr.Outbound(tag)
		if !ok {
			return nil, nil, fmt.Errorf("engine: outbound %s vanished", tag)
		}
		return tw, func() { _ = mgr.Remove(tag) }, nil
	}
}

// countingConn counts what comes BACK on the connection the outbound
// handed over: bytes from the far side, through the relay.
type countingConn struct {
	net.Conn
	back atomic.Int64
}

func (c *countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.back.Add(int64(n))
	return n, err
}

// proveOnce is one round trip: open a connection through the outbound,
// complete a TLS handshake with the far side, send nothing, close.
//
// relayAnswered: the dial succeeded on a kind whose dial includes the
// relay's own handshake. It is a fact about the relay only when the
// outbound had to open the connection (a twin); on the active outbound
// it may be the echo of a session opened minutes ago.
func proveOnce(ctx context.Context, ob N.Dialer, kind outboundKind, host string, port uint16, sign time.Duration) (obs diagnostics.Observation, relayAnswered bool, err error) {
	// Everything before DialContext returns is between the device and
	// the relay. Which half of that (the SYN, or the family's own
	// handshake) is read from the error where it can be: a failed
	// connect() is a *net.OpError with Op "dial" (diagnostics.Observe).
	// For a TIMEOUT that reading is not trustworthy — see
	// timeoutPhaseIsUnknown — and the reach check settles it.
	dialStart := time.Now()
	raw, err := ob.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddrHostPort(host, port))
	if err != nil {
		obs := diagnostics.Observe(err, diagnostics.PhaseHandshake, kind.UDP, kind.TLS)
		obs.DialMs = int(time.Since(dialStart) / time.Millisecond)
		return obs, false, err
	}
	dialTook := time.Since(dialStart)
	relayAnswered = kind.HandshakeAtDial
	conn := &countingConn{Conn: raw}
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
		obs := diagnostics.Observe(err, diagnostics.PhaseCarry, kind.UDP, kind.TLS)
		// Slow, not silent: something came back from the far side
		// before the time ran out, or the relay needed a second or more
		// to answer a connection it did answer (a dial served from a
		// session the outbound already held takes no time at all, and
		// says nothing either way).
		if obs.Timeout && (conn.back.Load() > 0 || (!kind.SlowStart && !kind.Lazy && dialTook >= sign)) {
			obs.Progress = true
		}
		return obs, relayAnswered, err
	}
	// The handshake is the whole exchange. Say goodbye the way a TLS
	// client does (close_notify) rather than vanish mid-connection.
	_ = tc.Close()
	return diagnostics.Observation{}, relayAnswered, nil
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
// AFTER an attempt has failed, never on a healthy connect, and only for
// a timeout whose phase is unknown (timeoutPhaseIsUnknown): unlike the
// family's own first flight it sends nothing after the handshake, so it
// is not something to repeat on every failed liveness check.
type reachCheck struct {
	done chan struct{}
	err  error
	ran  bool
	// took: how long the address needed to answer (either way).
	took time.Duration
}

// helloTimingBudget bounds the bare connect that times a stopped hello
// (ProofConfig.TimeHelloStop).
const helloTimingBudget = 2 * time.Second

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
		t0 := time.Now()
		defer func() { r.took = time.Since(t0) }()
		conn, err := direct.DialContext(rctx, N.NetworkTCP, M.ParseSocksaddrHostPort(kind.Server, kind.ServerPort))
		if err == nil {
			_ = conn.Close()
		}
		r.err = err
	}()
	return r
}

// settle waits for the check and writes what it found into the
// observation of the timed-out attempt:
//
//   - WHERE the silence was, when the attempt's own error could not be
//     trusted to say (timeoutPhaseIsUnknown);
//   - whether the path is SLOW: a SYN that was answered, and took a
//     second or more to be, was queued or resent on the way. A filter
//     that swallows a ClientHello does not delay the SYN before it.
//     (Read off a check that ran for the first reason; one is never
//     started for this alone.)
func (r *reachCheck) settle(ctx context.Context, o *diagnostics.Observation, kind outboundKind, sign time.Duration) {
	select {
	case <-r.done:
	case <-ctx.Done():
		return
	}
	if r.ran && r.err == nil {
		o.ConnectMs = int(r.took / time.Millisecond)
		if o.ConnectMs == 0 {
			o.ConnectMs = 1
		}
	}
	if !r.ran || !o.Timeout {
		return
	}
	unknown := timeoutPhaseIsUnknown(*o, kind)
	if r.err == nil {
		if unknown {
			// The SYN is answered, so the silence came after it.
			o.Phase = diagnostics.PhaseHandshake
		}
		if r.took >= sign {
			o.Progress = true
		}
		return
	}
	if !unknown {
		return
	}
	probe := diagnostics.Observe(r.err, diagnostics.PhaseReach, false, false)
	o.Phase = diagnostics.PhaseReach
	if probe.Refused || probe.Reset {
		o.Timeout, o.Refused = false, true
	}
}
