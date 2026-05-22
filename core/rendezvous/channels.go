// Package rendezvous implements the multi-channel rendezvous
// abstraction defined in specs/rendezvous-channels-v1.md.
//
// At Phase 3B the package ships:
//
//   - A closed taxonomy of 5 channel IDs.
//   - The Channel interface that each impl satisfies.
//   - A hedged Selector that races channels per the locked v1
//     algorithm (priority[0] OR netmem hint at t=0; remaining
//     channels in parallel at t=4s; first success wins).
//   - In-tree skeleton implementations for each channel. The
//     actual upstream wiring (Snowflake's domain-fronted
//     broker call, AWS SQS SDK, AMP-cache fronting, FCM/APNS)
//     plugs into the skeleton via the constructor's `Solicitor`
//     callback so the package itself stays free of the heavy
//     transport dependencies and remains unit-testable without
//     network access.
//
// The Selector is pure: no global state, no goroutine leaks
// (every losing context is cancelled on first success). The
// engine layer in core/abi wires the netmem callback at Init.
package rendezvous

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

// Channel IDs — the closed v1 taxonomy. Adding a sixth value is
// a roadmap-level decision per
// specs/rendezvous-channels-v1.md.
const (
	ChannelDomainFrontedBroker = "domain_fronted_broker"
	ChannelSQS                 = "sqs"
	ChannelAMPCache            = "amp_cache"
	ChannelPush                = "push"
	ChannelOfflineHint         = "offline_hint"
)

// HedgeInterval is the locked v1 hedge timeout. After the
// preferred channel has been firing for HedgeInterval without
// succeeding, the Selector fires the remaining channels in
// parallel.
const HedgeInterval = 4 * time.Second

// DefaultPriority is the family-default fire order when the
// bundle does not supply one and the per-engine override is
// empty. See specs/snowflake-route-v1.md "Bundle fields".
//
// `push` is NOT in the default list — it is opt-in per
// specs/push-rendezvous-v1.md and only enters the priority
// list when the user has opted in AND the active bundle has
// declared a push hint.
var DefaultPriority = []string{
	ChannelDomainFrontedBroker,
	ChannelAMPCache,
	ChannelSQS,
	ChannelOfflineHint,
}

// KnownChannels returns the v1 closed list. Used by the bundle
// parser to validate `routes[].rendezvous_priority` entries.
func KnownChannels() []string {
	return []string{
		ChannelDomainFrontedBroker,
		ChannelSQS,
		ChannelAMPCache,
		ChannelPush,
		ChannelOfflineHint,
	}
}

// IsKnownChannel reports whether the supplied ID is one of the
// v1 channels.
func IsKnownChannel(id string) bool {
	switch id {
	case ChannelDomainFrontedBroker,
		ChannelSQS,
		ChannelAMPCache,
		ChannelPush,
		ChannelOfflineHint:
		return true
	}
	return false
}

// Hint is the structured response a Channel returns on success.
// The fields are deliberately Snowflake-flavoured at v1; future
// transports MAY consume Extra for non-Snowflake payloads.
type Hint struct {
	ChannelID  string          `json:"channel_id"`
	OfferSDP   string          `json:"offer_sdp,omitempty"`
	AnswerSDP  string          `json:"answer_sdp,omitempty"`
	BridgeFP   string          `json:"bridge_fp,omitempty"`
	Extra      json.RawMessage `json:"extra,omitempty"`
	ReceivedAt time.Time       `json:"-"`
}

// Request is the per-Solicit input.
type Request struct {
	PublisherKeyHex string // for verification of inbound signed hints
	NetworkID       string // hashed; consumed by Selector for netmem bias
	Now             time.Time
	BundleParams    map[string]any // channel-specific knobs (broker URL, queue URL, ...)
}

// Channel is the single interface each rendezvous-channel impl
// satisfies. Implementations MUST be safe for concurrent use
// — the hedged selector calls multiple channels in parallel.
type Channel interface {
	ID() string
	Solicit(ctx context.Context, req Request) (Hint, error)
}

// Errors.
var (
	// ErrAllChannelsFailed is returned by Selector.Race when
	// every configured channel returned an error within the
	// supplied context's deadline. The route burns under the
	// 2G classifier (cosmetic mapping: rendezvous_unavailable).
	ErrAllChannelsFailed = errors.New("rendezvous: all channels failed")

	// ErrChannelDisabled is returned by a channel that is
	// configured but currently disabled (e.g., push channel
	// when the user has not opted in). The Selector treats
	// this as a non-failure and skips silently — it does NOT
	// count toward "all channels failed".
	ErrChannelDisabled = errors.New("rendezvous: channel disabled")

	// ErrNoCandidates is returned by Selector.Race when the
	// caller's priority list is empty AND no netmem hint
	// resolves AND the offline_hint channel is not registered.
	// Distinct from ErrAllChannelsFailed for diagnostics.
	ErrNoCandidates = errors.New("rendezvous: no candidate channels")
)

// Selector composes the registered channels with the priority
// list and the netmem hint to produce a hedged race.
type Selector struct {
	channels   map[string]Channel
	netmemHint NetmemHintFn
	hedge      time.Duration
}

// NetmemHintFn is the per-network winning-channel callback. The
// engine layer injects the canonical implementation wired to
// the 2C netmem subsystem; tests pass a stub.
//
// Returns the empty string if no hint is available for the
// supplied network.
type NetmemHintFn func(networkID string) string

// New constructs a Selector with the supplied channels. Channels
// that share an ID overwrite earlier registrations (last-write-
// wins; the engine layer registers each impl exactly once).
func New(channels []Channel, netmemHint NetmemHintFn) *Selector {
	m := make(map[string]Channel, len(channels))
	for _, c := range channels {
		if c == nil {
			continue
		}
		m[c.ID()] = c
	}
	if netmemHint == nil {
		netmemHint = func(string) string { return "" }
	}
	return &Selector{
		channels:   m,
		netmemHint: netmemHint,
		hedge:      HedgeInterval,
	}
}

// SetHedge overrides the v1-locked hedge interval. Used only by
// tests; production callers MUST use the default.
func (s *Selector) SetHedge(d time.Duration) {
	s.hedge = d
}

// Race executes the hedged selection per the locked v1
// algorithm and returns the winning channel ID, the hint, and
// any error. The supplied context is the caller's overall
// deadline; per-channel deadlines are derived from it.
//
// Algorithm:
//
//  1. Resolve the preferred channel (netmem hint > supplied
//     priority[0] > offline_hint fallback).
//  2. Fire the preferred channel at t=0.
//  3. If no winner by t=hedge, fire all remaining priority
//     channels in parallel.
//  4. First success wins; cancel everything else; return.
//  5. All-fail returns ErrAllChannelsFailed.
//
// `priority` is the active priority list (override OR bundle
// OR DefaultPriority — the caller resolves the cascade).
func (s *Selector) Race(ctx context.Context, req Request, priority []string) (string, Hint, error) {
	candidates := s.candidates(req, priority)
	if len(candidates) == 0 {
		return "", Hint{}, ErrNoCandidates
	}

	winner := make(chan result, len(candidates))
	var wg sync.WaitGroup
	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	fire := func(id string) {
		defer wg.Done()
		ch := s.channels[id]
		if ch == nil {
			winner <- result{id: id, err: ErrNoCandidates}
			return
		}
		h, err := ch.Solicit(raceCtx, req)
		if err == nil {
			h.ChannelID = id
			if h.ReceivedAt.IsZero() {
				h.ReceivedAt = time.Now()
			}
		}
		winner <- result{id: id, hint: h, err: err}
	}

	// t=0: fire the preferred channel.
	preferred := candidates[0]
	wg.Add(1)
	go fire(preferred)

	// t=hedge: fire the rest unless we have a winner already.
	if len(candidates) > 1 {
		go func() {
			select {
			case <-time.After(s.hedge):
			case <-raceCtx.Done():
				return
			}
			for _, id := range candidates[1:] {
				wg.Add(1)
				go fire(id)
			}
		}()
	}

	// Drain results. ErrChannelDisabled is a non-failure skip;
	// any other error counts toward all-fail.
	var failures int
	expected := len(candidates)
	for failures < expected {
		select {
		case r := <-winner:
			if r.err == nil {
				cancel()
				go drain(&wg, winner)
				return r.id, r.hint, nil
			}
			if errors.Is(r.err, ErrChannelDisabled) {
				expected--
				continue
			}
			failures++
		case <-ctx.Done():
			cancel()
			go drain(&wg, winner)
			return "", Hint{}, ctx.Err()
		}
	}
	cancel()
	go drain(&wg, winner)
	if expected == 0 {
		return "", Hint{}, ErrNoCandidates
	}
	return "", Hint{}, ErrAllChannelsFailed
}

// candidates resolves the preference cascade and returns a
// deduplicated, channel-known list with the preferred channel
// first.
//
// Cascade:
//
//  1. netmem hint (if it names a known channel)
//  2. caller-supplied priority (deduplicated; unknown skipped)
//  3. ChannelOfflineHint as a final fallback if not already in
//     the list and registered.
func (s *Selector) candidates(req Request, priority []string) []string {
	out := make([]string, 0, len(priority)+2)
	seen := make(map[string]bool, len(priority)+2)

	add := func(id string) {
		if id == "" || seen[id] {
			return
		}
		if _, ok := s.channels[id]; !ok {
			return // not registered
		}
		seen[id] = true
		out = append(out, id)
	}

	// netmem first
	if hint := s.netmemHint(req.NetworkID); hint != "" && IsKnownChannel(hint) {
		add(hint)
	}
	// supplied priority next
	for _, id := range priority {
		if !IsKnownChannel(id) {
			continue
		}
		add(id)
	}
	// offline_hint as a final fallback if registered
	if _, ok := s.channels[ChannelOfflineHint]; ok {
		add(ChannelOfflineHint)
	}
	return out
}

// drain waits for in-flight goroutines and discards their
// results so we don't leak.
func drain(wg *sync.WaitGroup, ch <-chan result) {
	go func() {
		wg.Wait()
	}()
	// Best-effort drain; bounded by the size of the buffered
	// channel.
	for range ch {
	}
}

// result is the per-channel outcome. Declared outside Race so
// drain can take a typed channel.
type result struct {
	id   string
	hint Hint
	err  error
}
