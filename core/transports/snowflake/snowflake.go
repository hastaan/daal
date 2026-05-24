// Package snowflake is the Phase 3B Snowflake transport-family
// integration point. It wraps upstream `snowflake/client` (Tor
// Project) with the Daal engine's family-handler interface.
//
// The wiring is:
//
//	pathmanager activates a snowflake route
//	     │
//	     ▼
//	snowflake.Handler.Dial(ctx, route)
//	     │  builds a rendezvous.Request from the route
//	     ▼
//	rendezvous.Selector.Race(ctx, req, route.RendezvousPriority)
//	     │  hedged selection per specs/rendezvous-channels-v1.md
//	     ▼
//	Hint{offer, answer, bridge_fp, ...}
//	     │
//	     ▼
//	upstream snowflake/client opens the WebRTC + DTLS + SCTP
//	DataChannel session
//	     │
//	     ▼
//	engine reports back: WinningChannelID
//	     │
//	     ▼
//	core/abi.RecordRendezvousWinner(routeID, channelID, networkID)
//
// Per the Phase 3B locked decision, snowflake/client is vendored
// unconditionally; a future `-tags no_snowflake` build MAY
// exclude it, in which case Dial returns ErrFamilyHandlerUnavailable
// and the route is filtered as if `experimental_min_engine_version`
// failed.
//
// The skeleton in this file does not import the upstream pion/
// webrtc tree directly; the upstream library is wired through
// the `WebRTCDialer` callback so this package can be tested
// without the heavy dependency, mirroring the
// `rendezvous.Solicitor` pattern.
package snowflake

import (
	"context"
	"errors"
	"sync"
	"time"

	"daal/core/rendezvous"
)

// FamilyID is the transport-family token consumed by the
// pathmanager and the bundle parser.
const FamilyID = "snowflake"

// Errors.
var (
	// ErrFamilyHandlerUnavailable is returned by Dial when the
	// engine was built with `-tags no_snowflake` and the
	// upstream snowflake/client tree is not linked. The
	// pathmanager filters the route as if
	// `experimental_min_engine_version` failed.
	ErrFamilyHandlerUnavailable = errors.New("snowflake: family handler unavailable in this build")

	// ErrRendezvousFailed is returned when every configured
	// rendezvous channel returned an error. Maps to
	// `tcp_connect_timeout` in the V0 failure taxonomy with
	// the cosmetic `rendezvous_unavailable` annotation.
	ErrRendezvousFailed = errors.New("snowflake: rendezvous unavailable")
)

// Route is the per-route input to the Snowflake handler. The
// engine layer materialises this from the routestore Row; we
// do not import core/routestore here to avoid an import cycle.
type Route struct {
	RouteID            string
	RendezvousPriority []string // from routes[].rendezvous_priority
	NetworkID          string   // hashed; consumed by the Selector for netmem bias
	PublisherKeyHex    string
	BundleParams       map[string]any // family_specific_config + rendezvous_hints[]
}

// Conn is the family-handler outbound returned by Dial. Real
// upstream wiring returns a sing-box outbound; in the skeleton
// we return a thin wrapper carrying the winning channel ID so
// the engine layer can persist it.
type Conn struct {
	WinningChannel string
	Hint           rendezvous.Hint
}

// WebRTCDialer is the upstream-snowflake adapter callback. The
// engine layer wires this to `snowflake/client`'s WebRTC dial
// path; tests pass a stub.
type WebRTCDialer func(ctx context.Context, hint rendezvous.Hint) (*Conn, error)

// Handler is the Phase 3B Snowflake family handler. It is the
// glue between the pathmanager activation surface and the
// rendezvous Selector + upstream snowflake/client.
type Handler struct {
	selector  *rendezvous.Selector
	webrtc    WebRTCDialer
	available bool

	// recordWinner is the per-route persistence callback the
	// engine wires to core/routestore + core/netmem on a
	// successful Solicit. Not called when Dial fails.
	recordWinner func(routeID, channelID, networkID string)

	// dialDeadline caps the total time spent on a single Dial.
	// Tests override; production default is 90s.
	dialDeadline time.Duration

	mu sync.Mutex
}

// HandlerOption tunes the Handler.
type HandlerOption func(*Handler)

// WithRecordWinner wires the per-route persistence callback.
func WithRecordWinner(fn func(routeID, channelID, networkID string)) HandlerOption {
	return func(h *Handler) { h.recordWinner = fn }
}

// WithDialDeadline overrides the default 90-second total Dial
// deadline.
func WithDialDeadline(d time.Duration) HandlerOption {
	return func(h *Handler) { h.dialDeadline = d }
}

// NewHandler constructs the Snowflake family handler. Pass a
// nil WebRTCDialer in `-tags no_snowflake` builds (or in test
// scenarios that only exercise the rendezvous step); Dial
// returns ErrFamilyHandlerUnavailable.
func NewHandler(selector *rendezvous.Selector, webrtc WebRTCDialer, opts ...HandlerOption) *Handler {
	h := &Handler{
		selector:     selector,
		webrtc:       webrtc,
		available:    webrtc != nil,
		dialDeadline: 90 * time.Second,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// Available reports whether the upstream snowflake/client is
// linked into this build.
func (h *Handler) Available() bool {
	if h == nil {
		return false
	}
	return h.available
}

// Dial activates a Snowflake route. The path is:
//
//  1. Race rendezvous channels per the 3B selector (hedged at
//     t=4s).
//  2. On a winning Hint, hand off to the WebRTC dialer.
//  3. On full success, persist (routeID, channelID, networkID)
//     via the per-route + per-network callback.
//
// Errors map to the V0 failure taxonomy at the engine layer;
// the handler returns the raw error for the caller to classify.
func (h *Handler) Dial(ctx context.Context, route Route) (*Conn, error) {
	if !h.available {
		return nil, ErrFamilyHandlerUnavailable
	}
	if h.dialDeadline > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, h.dialDeadline)
		defer cancel()
	}

	priority := route.RendezvousPriority
	if len(priority) == 0 {
		priority = rendezvous.DefaultPriority
	}

	req := rendezvous.Request{
		PublisherKeyHex: route.PublisherKeyHex,
		NetworkID:       route.NetworkID,
		Now:             time.Now(),
		BundleParams:    route.BundleParams,
	}

	channelID, hint, err := h.selector.Race(ctx, req, priority)
	if err != nil {
		if errors.Is(err, rendezvous.ErrAllChannelsFailed) ||
			errors.Is(err, rendezvous.ErrNoCandidates) {
			return nil, ErrRendezvousFailed
		}
		return nil, err
	}

	conn, err := h.webrtc(ctx, hint)
	if err != nil {
		return nil, err
	}
	if conn == nil {
		conn = &Conn{}
	}
	conn.WinningChannel = channelID
	conn.Hint = hint

	if h.recordWinner != nil {
		h.recordWinner(route.RouteID, channelID, route.NetworkID)
	}
	return conn, nil
}
