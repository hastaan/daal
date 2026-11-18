package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"daal/core/diagnostics"
)

// The connection proof — what "this route works" means.
//
// Driver.Start returning nil means the engine instance is running. It
// does NOT mean the route carries anything: sing-box dials the relay
// lazily, on the first connection an app opens, so a route to a
// null-routed address "starts" exactly like a healthy one. Until this
// file existed the ABI took Start's nil for a tunnel, published
// "Connected", recorded a success and marked the route proven — under
// every blocking censor the end-to-end rig has (its finding CEN-1).
//
// A route is proven when ONE REAL ROUND TRIP has been made through its
// own outbound: a connection opened through the active outbound to a
// host on the far side, and a TLS ServerHello read back from it. That
// exercises everything a censor can break between the device and the
// relay (reach, the family's handshake, the credential) plus the relay's
// ability to carry, and nothing leaves the device except through the
// tunnel.
//
// WHY IT DIALS THE OUTBOUND DIRECTLY, AND NOT THROUGH THE REFRESH INLET.
// The inlet (inlet.go) is the other in-process path that genuinely rides
// the tunnel, and the proof would work through it — but only as a
// yes/no. A SOCKS5 inbound answers a failed dial with a one-byte reply
// code; the error that says WHY (a SYN timeout, a reset after the
// ClientHello, a QUIC handshake that heard nothing) stays inside
// sing-box, whose log is discarded when a PlatformInterface is present.
// Classifying the failure is half the point, so the proof asks the
// outbound itself and keeps the error. It is the same outbound object
// route.final hands app traffic to.
//
// THE TARGET. The far-side host must not be a Daal host (one name every
// Daal client touches on every connect is a fingerprint for whoever
// watches the relay's upstream, and a single point of failure for every
// user), so it is drawn at random from a small set of very common
// hosts, and a second, different one is tried before a route is called
// dead. The set is configuration (ProofConfig.Targets) with a production
// default. The handshake does NOT verify the target's certificate, on
// purpose: nothing is being authenticated — no data is sent, no secret
// is exchanged, no trust decision in the product depends on who answered
// — and a phone with a wrong clock must not be told its route is dead.
// What is established is that bytes went out through the relay and bytes
// came back.

// ProofConfig is the connection-check configuration. Zero values mean
// "the production default"; see DefaultProofConfig.
type ProofConfig struct {
	// Targets are "host:port" TLS endpoints on the far side of the
	// relay. One is drawn at random per attempt.
	Targets []string
	// AttemptTimeout bounds one attempt; Attempts is how many are made
	// (each to a different target when there is more than one). The
	// whole proof is bounded by their product.
	AttemptTimeout time.Duration
	Attempts       int
	// SlowAfter: a proof that succeeded but took longer than this in all
	// (failed attempts included) is a DEGRADED route
	// (diagnostics.PathTooSlow), not a failed one. It must be below
	// AttemptTimeout to mean anything.
	SlowAfter time.Duration
	// LivenessInterval is how often a connected route is proved again;
	// each wait is jittered by ±LivenessJitter (a fraction, 0..1).
	// RecheckInterval replaces it while the route is failed, so a path
	// that comes back is noticed quickly.
	LivenessInterval time.Duration
	LivenessJitter   float64
	RecheckInterval  time.Duration
}

// DefaultProofTargets are hosts a relay anywhere can be expected to
// reach and that an observer of the relay's upstream sees constantly
// from everything. Order is irrelevant: the choice is random.
var DefaultProofTargets = []string{
	"www.google.com:443",
	"www.cloudflare.com:443",
	"www.microsoft.com:443",
	"www.apple.com:443",
	"www.amazon.com:443",
	"www.wikipedia.org:443",
}

// DefaultProofConfig is what an install with no configuration runs.
func DefaultProofConfig() ProofConfig {
	return ProofConfig{
		Targets:          append([]string(nil), DefaultProofTargets...),
		AttemptTimeout:   4 * time.Second,
		Attempts:         2,
		SlowAfter:        2 * time.Second,
		LivenessInterval: 3 * time.Minute,
		LivenessJitter:   0.25,
		RecheckInterval:  30 * time.Second,
	}
}

// Normalised fills every zero field from the default and validates the
// targets. A config that names no usable target is an error rather than
// a silent fallback: someone wrote that file on purpose.
func (c ProofConfig) Normalised() (ProofConfig, error) {
	d := DefaultProofConfig()
	if len(c.Targets) == 0 {
		c.Targets = d.Targets
	}
	for _, t := range c.Targets {
		if _, _, err := splitProofTarget(t); err != nil {
			return c, err
		}
	}
	if c.AttemptTimeout <= 0 {
		c.AttemptTimeout = d.AttemptTimeout
	}
	if c.Attempts <= 0 {
		c.Attempts = d.Attempts
	}
	if c.SlowAfter <= 0 {
		c.SlowAfter = d.SlowAfter
	}
	if c.LivenessInterval <= 0 {
		c.LivenessInterval = d.LivenessInterval
	}
	if c.LivenessJitter <= 0 || c.LivenessJitter >= 1 {
		c.LivenessJitter = d.LivenessJitter
	}
	if c.RecheckInterval <= 0 {
		c.RecheckInterval = d.RecheckInterval
	}
	return c, nil
}

func splitProofTarget(t string) (host string, port uint16, err error) {
	h, p, err := net.SplitHostPort(strings.TrimSpace(t))
	if err != nil || h == "" {
		return "", 0, fmt.Errorf("engine: connection-check target %q is not host:port", t)
	}
	n, err := strconv.ParseUint(p, 10, 16)
	if err != nil || n == 0 {
		return "", 0, fmt.Errorf("engine: connection-check target %q has no usable port", t)
	}
	return h, uint16(n), nil
}

// ProofResult is the outcome of one proof.
type ProofResult struct {
	// OK: a round trip completed through the route's outbound.
	OK bool
	// Elapsed is the whole proof, failed attempts included. RoundTrip
	// is the attempt that succeeded, alone.
	Elapsed   time.Duration
	RoundTrip time.Duration
	// Slow: OK, but the whole proof (Elapsed: every attempt, failed
	// ones included) took longer than ProofConfig.SlowAfter. See
	// proofWasSlow.
	Slow bool
	// Attempts actually made.
	Attempts int
	// Err and Observation describe the LAST failed attempt when !OK.
	// Err's text can carry addresses: it is for the in-process event
	// stream and the classifier, never for the route store.
	Err         error
	Observation diagnostics.Observation
	// Failed lists every failed attempt in order (the last one is
	// Observation), so a proof that failed two different ways can be
	// read as that.
	Failed []diagnostics.Observation
	// Cancelled: the proof was abandoned (disconnect, route switch,
	// shutdown). It says nothing about the route and must not be
	// recorded as an outcome.
	Cancelled bool
}

// Category is the taxonomy category of a failed proof.
func (r ProofResult) Category() diagnostics.Category {
	return diagnostics.ClassifyObservation(r.Observation)
}

// ErrProofCancelled is the Err of a cancelled proof.
var ErrProofCancelled = errors.New("engine: connection check cancelled")

// ErrNotRunning is the Err of a proof asked of a driver with no
// instance.
var ErrNotRunning = errors.New("engine: not connected")

// proofOrder returns up to n targets in the order they will be tried:
// a random start, then the following ones, so two attempts never hit
// the same host unless there is only one.
func proofOrder(targets []string, n int, rnd func(int) int) []string {
	if len(targets) == 0 || n <= 0 {
		return nil
	}
	start := rnd(len(targets))
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, targets[(start+i)%len(targets)])
	}
	return out
}

// proofAttempt is one round trip, as the driver implements it.
type proofAttempt func(ctx context.Context, host string, port uint16) (diagnostics.Observation, error)

// runProof is the attempt loop shared by every driver: bounded attempts,
// a different target each time, total time measured, cancellation told
// apart from failure.
func runProof(ctx context.Context, cfg ProofConfig, rnd func(int) int, attempt proofAttempt) ProofResult {
	cfg, err := cfg.Normalised()
	if err != nil {
		return ProofResult{Err: err, Observation: diagnostics.Observation{Message: err.Error()}}
	}
	start := time.Now()
	var res ProofResult
	for _, target := range proofOrder(cfg.Targets, cfg.Attempts, rnd) {
		host, port, _ := splitProofTarget(target)
		if ctx.Err() != nil {
			break
		}
		actx, cancel := context.WithTimeout(ctx, cfg.AttemptTimeout)
		attemptStart := time.Now()
		obs, aerr := attempt(actx, host, port)
		cancel()
		res.Attempts++
		if aerr == nil {
			res.OK, res.Err = true, nil
			res.Observation = diagnostics.Observation{}
			res.RoundTrip = time.Since(attemptStart)
			break
		}
		res.Err, res.Observation = aerr, obs
		res.Failed = append(res.Failed, obs)
	}
	res.Elapsed = time.Since(start)
	if !res.OK && ctx.Err() != nil {
		// The caller gave up; whatever error the abandoned attempt
		// returned is an artefact of that, not a fact about the route.
		return ProofResult{Cancelled: true, Err: ErrProofCancelled, Elapsed: res.Elapsed, Attempts: res.Attempts}
	}
	if res.OK {
		res.Slow = proofWasSlow(res, cfg.SlowAfter)
	}
	return res
}

// proofWasSlow decides "connected, but slow" for a proof that succeeded:
// the WHOLE proof took longer than slowAfter, attempts that failed
// included.
//
// It is the wait of the person who tapped Connect that is judged, and
// they waited through every attempt. Which side of the relay an earlier
// attempt died on does not change that, and cannot be read from its
// phase anyway: on a path capped at a few tens of kbit/s the relay
// answers (the attempt reaches PhaseCarry) and the round trip through it
// still does not fit in the budget. Reading a carry-phase timeout as "a
// dead TARGET, says nothing about the route" had the end-to-end rig's
// throttle-56k report three families plainly "Connected" after 4.7–5.5 s.
//
// The cost, accepted: one proof target that is silent from the relay's
// side makes the connects that draw it first read "slow" (they were: the
// person waited out a whole attempt). A target that refuses or closes at
// once costs no time and changes nothing.
func proofWasSlow(res ProofResult, slowAfter time.Duration) bool {
	return res.OK && res.Elapsed > slowAfter
}
