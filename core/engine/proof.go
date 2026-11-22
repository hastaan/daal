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
// default (DefaultProofTargetSet, and the rules it is held to). The
// exchange is a TLS handshake and its close_notify, on port 443, and
// nothing else: no HTTP request, no application data, no name of ours.
// The handshake does NOT verify the target's certificate, on
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
	// SlowBudget is the extra time ONE further attempt is given when
	// every ordinary attempt ran out of time on a path the engine saw
	// moving (diagnostics.Observation.Progress): bytes came back, or
	// the relay's own answer took seconds. A dead route never gets it —
	// nothing was seen moving — so "could not connect" still arrives
	// within AttemptTimeout × Attempts. See "SLOW IS NOT SILENT" below.
	SlowBudget time.Duration
	// LivenessInterval is how often a connected route is proved again;
	// each wait is jittered by ±LivenessJitter (a fraction, 0..1).
	// RecheckInterval replaces it while the route is failed, so a path
	// that comes back is noticed quickly.
	LivenessInterval time.Duration
	LivenessJitter   float64
	RecheckInterval  time.Duration
	// StopAtUnreachedRelay ends the ordinary attempts after the first
	// one that never got as far as the relay (diagnostics.PhaseReach,
	// nothing seen moving). The attempts differ only in the far-side
	// TARGET, and a target is not consulted until the relay has
	// answered: a second attempt at a relay whose address is silent
	// asks the same question again and makes the person wait
	// AttemptTimeout for the same answer. Off by default (a connect to
	// one route the person picked keeps every attempt); the automatic
	// connect sets it, because it has other routes to get to
	// (core/abi/connect_auto.go). Not part of the configuration file.
	StopAtUnreachedRelay bool
	// TimeHelloStop: when a TLS first flight is reset or closed, time
	// one bare connect to the same address and port (at most
	// helloTimingBudget), so the observation can say whether the stop
	// came back sooner than the relay could have sent it
	// (diagnostics.Observation FastReset / ServerStop). Set by the
	// automatic connect for its candidates only — the connect ladder
	// (core/abi connect_ladder.go) is what reads it; a liveness check
	// never pays for it. Not part of the configuration file.
	TimeHelloStop bool
	// SideCronet: the caller of a SIDE probe accepts a naive route —
	// a Cronet engine in the side instance (side.go, cronetSideTypes).
	// Only the survey sets it (core/abi/survey.go); races and the speed
	// move never do. Not part of the configuration file.
	SideCronet bool
}

// ProofTarget is one default far-side host and who runs it.
type ProofTarget struct {
	// Addr is "host:port".
	Addr string
	// Operator is the organisation whose network answers for the host.
	// It exists so a test can hold the list to its rule: two attempts
	// in a row never depend on one operator.
	Operator string
}

// DefaultProofTargetSet is the production default of
// connection_check.targets. The rules it is held to, each of them
// checked by TestDefaultProofTargets_* and argued in
// specs/engine-abi-v1.md "The default targets":
//
//  1. The front page of a service that datacentre machines and phones
//     alike open all day. The connection leaves the RELAY, so the party
//     that sees it is the relay's hosting network; what it sees must be
//     what every other tenant's traffic already looks like.
//  2. Answered from an anycast or multi-region edge that accepts TCP and
//     completes TLS for any source address. Services that turn
//     datacentre addresses away do it in HTTP (a challenge page), and
//     the check never sends an HTTP request.
//  3. Port 443 only, and nothing after the handshake: no request, no
//     header, no path, no name of ours anywhere.
//  4. No one operator can fail a working route: neighbours in this list
//     are run by different organisations, and the attempts of one check
//     go to neighbours (proofOrder).
//  5. Not infrastructure run on donations. A volunteer-funded site is
//     not ours to use as a beacon, however small the cost.
//
// The order is NOT irrelevant: it is what rule 4 is written in. The
// starting point is random.
var DefaultProofTargetSet = []ProofTarget{
	{"www.google.com:443", "google"},
	{"www.microsoft.com:443", "microsoft"},
	{"www.cloudflare.com:443", "cloudflare"},
	{"github.com:443", "github"},
	{"www.apple.com:443", "apple"},
	{"www.amazon.com:443", "amazon"},
}

// proofOperatorOwner folds operators that belong to one company, for
// rule 4: GitHub runs its own network but is owned by Microsoft, so the
// two are never neighbours.
var proofOperatorOwner = map[string]string{"github": "microsoft"}

// DefaultProofTargets is DefaultProofTargetSet as the "host:port" list
// the configuration carries.
var DefaultProofTargets = func() []string {
	out := make([]string, 0, len(DefaultProofTargetSet))
	for _, t := range DefaultProofTargetSet {
		out = append(out, t.Addr)
	}
	return out
}()

// DefaultProofConfig is what an install with no configuration runs.
func DefaultProofConfig() ProofConfig {
	return ProofConfig{
		Targets:          append([]string(nil), DefaultProofTargets...),
		AttemptTimeout:   4 * time.Second,
		Attempts:         2,
		SlowAfter:        2 * time.Second,
		SlowBudget:       20 * time.Second,
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
	if c.SlowBudget <= 0 {
		c.SlowBudget = d.SlowBudget
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
	// Extended: the ordinary attempts all ran out of time on a path
	// that was seen moving, and the one long attempt of
	// ProofConfig.SlowBudget was made. OK && Extended is always Slow.
	Extended bool
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

// proofAids are the two things a driver can add to the attempt loop
// once the ordinary attempts have all failed. Both are optional, both
// run on the PROOF's context, and neither is ever called on a proof
// that succeeded.
type proofAids struct {
	// settle refines the observation of the last failed attempt with
	// what a check that ran beside the attempts found (the sing-box
	// driver's reach check: was the relay's SYN answered, and how long
	// did the answer take).
	settle func(ctx context.Context, o *diagnostics.Observation)
	// diagnose repeats one attempt on a connection to the relay opened
	// for the purpose, and returns what THAT attempt saw. It is asked
	// only about a timeout in the carry phase — the one failure whose
	// observation says nothing about the relay, because the outbound
	// may have answered from a session it already held (always, on a
	// route that has been connected for a while). ok=false: the driver
	// has no such connection to offer; the observation stands.
	diagnose func(ctx context.Context, host string, port uint16) (o diagnostics.Observation, err error, ok bool)
}

// runProof is the attempt loop shared by every driver: bounded attempts,
// a different target each time, total time measured, cancellation told
// apart from failure.
func runProof(ctx context.Context, cfg ProofConfig, rnd func(int) int, attempt proofAttempt) ProofResult {
	return runProofWith(ctx, cfg, rnd, attempt, proofAids{})
}

// SLOW IS NOT SILENT (the end-to-end rig's observation CEN-O5).
//
// Behind seconds of queue the ordinary attempts finish nothing, and the
// silence of a handshake that is still crawling is, from the error
// alone, the silence of one a filter swallowed. Calling it that cooled
// a working route down for 5–30 minutes and told the person "could not
// connect" on a link that connects ten seconds later.
//
// What tells the two apart is whether anything was seen MOVING: bytes
// back from the far side, a relay whose handshake took seconds rather
// than milliseconds to complete, a SYN answered late. With any of
// those, the proof makes one more attempt with a long budget
// (SlowBudget). If that one completes the route is connected and slow;
// if it does not, the failure is path_too_slow — no cooldown, no
// network signal, and the person can try again at once. With none of
// them the proof ends where it always did.
func runProofWith(ctx context.Context, cfg ProofConfig, rnd func(int) int, attempt proofAttempt, aids proofAids) ProofResult {
	cfg, err := cfg.Normalised()
	if err != nil {
		return ProofResult{Err: err, Observation: diagnostics.Observation{Message: err.Error()}}
	}
	start := time.Now()
	var res ProofResult
	// One target beyond the ordinary attempts for each of the two
	// follow-ups, so neither repeats a host unless the list is short.
	order := proofOrder(cfg.Targets, cfg.Attempts+2, rnd)
	next := 0
	try := func(timeout time.Duration, fn proofAttempt) bool {
		host, port, _ := splitProofTarget(order[next%len(order)])
		next++
		actx, cancel := context.WithTimeout(ctx, timeout)
		attemptStart := time.Now()
		obs, aerr := fn(actx, host, port)
		cancel()
		res.Attempts++
		if aerr == nil {
			res.OK, res.Err = true, nil
			res.Observation = diagnostics.Observation{}
			res.RoundTrip = time.Since(attemptStart)
			return true
		}
		res.Err, res.Observation = aerr, obs
		res.Failed = append(res.Failed, obs)
		return false
	}
	for i := 0; i < cfg.Attempts && ctx.Err() == nil; i++ {
		if try(cfg.AttemptTimeout, attempt) {
			break
		}
		if cfg.StopAtUnreachedRelay && res.Observation.Phase == diagnostics.PhaseReach && !res.Observation.Progress {
			break
		}
	}
	setLast := func(o diagnostics.Observation) {
		res.Observation = o
		if n := len(res.Failed); n > 0 {
			res.Failed[n-1] = o
		}
	}
	if !res.OK && ctx.Err() == nil && len(res.Failed) > 0 {
		if aids.settle != nil {
			o := res.Observation
			aids.settle(ctx, &o)
			setLast(o)
		}
		// The carry-phase timeout: ask again on a fresh connection to
		// the relay, and believe that attempt about the relay.
		if aids.diagnose != nil && ctx.Err() == nil && !sawProgress(res.Failed) &&
			res.Observation.Timeout && res.Observation.Phase == diagnostics.PhaseCarry {
			host, port, _ := splitProofTarget(order[next%len(order)])
			actx, cancel := context.WithTimeout(ctx, cfg.AttemptTimeout)
			o, derr, ok := aids.diagnose(actx, host, port)
			cancel()
			if ok && ctx.Err() == nil {
				next++
				res.Attempts++
				// derr == nil: the fresh connection carried a round
				// trip and the route's own did not — its session is
				// stale. Nothing is known to be wrong with the route,
				// so the attempts that failed stand as they are and the
				// next check finds out which it was.
				if derr != nil {
					res.Err, res.Observation = derr, o
					res.Failed = append(res.Failed, o)
				}
			}
		}
		if ctx.Err() == nil && res.Observation.Timeout && sawProgress(res.Failed) {
			res.Extended = true
			if !try(cfg.SlowBudget, attempt) && res.Observation.Timeout {
				// Still nothing finished, on a path that was moving.
				o := res.Observation
				o.Progress = true
				setLast(o)
			}
		}
	}
	res.Elapsed = time.Since(start)
	if !res.OK && ctx.Err() != nil {
		// The caller gave up; whatever error the abandoned attempt
		// returned is an artefact of that, not a fact about the route.
		return ProofResult{Cancelled: true, Err: ErrProofCancelled, Elapsed: res.Elapsed, Attempts: res.Attempts}
	}
	if res.OK {
		res.Slow = res.Extended || proofWasSlow(res, cfg.SlowAfter)
	}
	return res
}

// sawProgress: did any failed attempt see the path moving?
func sawProgress(failed []diagnostics.Observation) bool {
	for _, o := range failed {
		if o.Progress {
			return true
		}
	}
	return false
}

// slowSign is how long an answer from the relay must have taken to
// count as evidence of a slow path rather than a quick one: half the
// "slow" threshold, and never under a second — a SYN is retransmitted
// after one second, so an answer that late was queued or resent, which
// no filter that swallows a ClientHello makes happen.
func slowSign(cfg ProofConfig) time.Duration {
	if d := cfg.SlowAfter / 2; d > time.Second {
		return d
	}
	return time.Second
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
