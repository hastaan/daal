// Package masque is the Phase 3C MASQUE transport-family
// integration point. MASQUE (RFC 9298 + RFC 9484) is a single
// transport family with three sub-modes selected by the engine
// based on per-network UDP-probe state and the user's mode.
//
// The wiring is:
//
//	pathmanager activates a masque route
//	     │
//	     ▼
//	masque.Handler.Dial(ctx, route)
//	     │  consults chooseSubmode (private cascade)
//	     │     1. ABI override
//	     │     2. lifeline-strict mode + masque family   → masque_lifeline (hint)
//	     │     3. netmem last_used_masque_submode        → start there
//	     │     4. UDPProbeOK == true                     → masque_h3_quic
//	     │     5. UDPProbeOK == false                    → masque_h2_connect
//	     │     6. h2_connect burned + mode in lifeline*  → masque_lifeline
//	     ▼
//	one of the three Dialers (H3 / H2 / Lifeline) opens a tunnel
//	     │
//	     ▼
//	recordSubmode(routeID, submode, networkID)
//	     │
//	     ▼
//	core/abi.RecordChosenMasqueSubmode (routestore + netmem)
//
// The package is stdlib-only at this layer; the upstream
// `quic-go` (H3) and `golang.org/x/net/http2` (H2) trees are
// wired through dialer callbacks so the package is unit-testable
// without those dependencies. This mirrors the 3B Snowflake
// pattern (rendezvous.Solicitor + WebRTCDialer callbacks).
//
// The sub-mode chooser is a private switch — we deliberately
// did NOT lift it into a `core/ladder/` package at 3C (locked
// decision; 3D/3E will refactor only if needed).
package masque

import (
	"context"
	"errors"
	"sync"
	"time"
)

// FamilyID is the transport-family token consumed by the
// pathmanager and the bundle parser.
const FamilyID = "masque"

// Submode is a MASQUE sub-mode token. The set is closed at v1
// per specs/masque-ladder-v1.md; a 4th value is a roadmap
// decision and requires a fresh soak run.
type Submode string

const (
	// SubmodeH3QUIC — RFC 9298 UDP-over-HTTP/3-over-QUIC. Best
	// path when the active network passes the 2C UDP probe.
	SubmodeH3QUIC Submode = "masque_h3_quic"

	// SubmodeH2Connect — HTTP/2 Extended CONNECT (RFC 8441
	// extended into MASQUE). Falls back here when UDP fails.
	SubmodeH2Connect Submode = "masque_h2_connect"

	// SubmodeLifeline — TCP-only, byte-clamped, bulk-refused.
	// Bottom rung; integrates with the 2D `lifeline-strict`
	// budget rules.
	SubmodeLifeline Submode = "masque_lifeline"
)

// IsKnownSubmode reports whether s is in the v1 closed list.
func IsKnownSubmode(s string) bool {
	switch Submode(s) {
	case SubmodeH3QUIC, SubmodeH2Connect, SubmodeLifeline:
		return true
	}
	return false
}

// AllSubmodes returns the closed v1 list in start-rung order.
// Useful for tests and the diagnostics renderer.
func AllSubmodes() []Submode {
	return []Submode{SubmodeH3QUIC, SubmodeH2Connect, SubmodeLifeline}
}

// Errors.
var (
	// ErrFamilyHandlerUnavailable is returned by Dial when the
	// engine was built with `-tags no_masque` and none of the
	// three dialer callbacks are wired. The pathmanager filters
	// the route as if `experimental_min_engine_version` failed.
	ErrFamilyHandlerUnavailable = errors.New("masque: family handler unavailable in this build")

	// ErrSubmodeUnreachable is returned by Dial when the
	// chosen sub-mode cannot be activated in this build (e.g.,
	// chooseSubmode picks SubmodeH3QUIC but no H3Dialer was
	// supplied). Distinct from ErrFamilyHandlerUnavailable so
	// the engine layer can downgrade rather than skip the
	// route entirely.
	ErrSubmodeUnreachable = errors.New("masque: chosen sub-mode unreachable")

	// ErrUnknownSubmode is returned when an explicit override
	// or netmem hint references a value outside the v1 closed
	// list. Defence-in-depth — the override setter validates,
	// but a corrupt persisted state could still surface here.
	ErrUnknownSubmode = errors.New("masque: unknown sub-mode")

	// ErrNoEndpoint is returned when a route reaches the
	// dialer without a non-empty MASQUE endpoint URL. The
	// bundle parser rejects masque routes without an endpoint;
	// this guard is defence-in-depth for engine-internal call
	// sites.
	ErrNoEndpoint = errors.New("masque: route has no MASQUE endpoint")
)

// Route is the per-route input to the MASQUE handler.
type Route struct {
	RouteID         string
	NetworkID       string // hashed; consumed for netmem bias
	MasqueEndpoint  string // https://host[:port]/path; bundle-supplied
	PublisherKeyHex string

	// LastUsedSubmode is the optional netmem hint for THIS
	// network. Empty string means "no hint." If non-empty and
	// in the v1 closed list it biases the start rung at step
	// 3 of chooseSubmode.
	LastUsedSubmode string

	// UDPProbeOK reflects the 2C per-network probe outcome on
	// this network. Drives steps 4/5 of chooseSubmode.
	UDPProbeOK bool

	// Mode is the user's current engine mode (from 2D). One
	// of {"lifeline","lifeline-strict","normal","bulk"}.
	// Drives steps 2 and 6 of chooseSubmode.
	Mode string

	// H2Burned is true when the 2G classifier has flagged the
	// h2_connect sub-mode as burned for this route within the
	// current session. Only consulted at step 6.
	H2Burned bool
}

// Conn is the family-handler outbound returned by Dial. Real
// upstream wiring returns a sing-box outbound; in the skeleton
// we return a thin wrapper carrying the chosen sub-mode so the
// engine layer can persist it.
type Conn struct {
	Submode  Submode
	Endpoint string
}

// SubmodeDialer is the upstream-MASQUE dialer callback for one
// of the three sub-modes. The engine layer wires these to
// upstream `quic-go` (H3), `golang.org/x/net/http2` (H2), and
// the lifeline-rung bytes-clamp wrapper. Tests pass stubs.
type SubmodeDialer func(ctx context.Context, endpoint string) (*Conn, error)

// Handler is the Phase 3C MASQUE family handler. It is the
// glue between the pathmanager activation surface and the
// upstream H3 / H2 / Lifeline dialers.
type Handler struct {
	h3       SubmodeDialer
	h2       SubmodeDialer
	lifeline SubmodeDialer

	// override is the engine-pinned sub-mode (set via
	// engine_set_masque_submode_override). Empty string means
	// "no override — use the cascade." Refreshed on every Dial
	// via OverrideFn so the engine layer can vary it without
	// re-constructing the handler.
	overrideFn func() string

	// recordSubmode is the per-route persistence callback the
	// engine wires to core/routestore + core/netmem in one
	// shot. Not called when Dial fails.
	recordSubmode func(routeID string, submode Submode, networkID string)

	// dialDeadline caps the total time spent on a single Dial.
	dialDeadline time.Duration

	mu sync.Mutex
}

// HandlerOption tunes the Handler.
type HandlerOption func(*Handler)

// WithRecordSubmode wires the per-route persistence callback.
func WithRecordSubmode(fn func(routeID string, submode Submode, networkID string)) HandlerOption {
	return func(h *Handler) { h.recordSubmode = fn }
}

// WithOverrideFn wires the engine-pinned override reader.
// Callers pass a closure that reads `core/abi.MasqueSubmodeOverride()`.
// Empty string from the closure means "no override."
func WithOverrideFn(fn func() string) HandlerOption {
	return func(h *Handler) { h.overrideFn = fn }
}

// WithDialDeadline overrides the default 90-second total Dial
// deadline.
func WithDialDeadline(d time.Duration) HandlerOption {
	return func(h *Handler) { h.dialDeadline = d }
}

// NewHandler constructs the MASQUE family handler. Pass nil for
// any dialer callback that is not linked in this build (e.g.,
// `-tags no_masque` may pass all three nil and Dial returns
// ErrFamilyHandlerUnavailable). The lifeline dialer is the
// last-resort rung; building without it disables the rung
// entirely.
func NewHandler(h3, h2, lifeline SubmodeDialer, opts ...HandlerOption) *Handler {
	h := &Handler{
		h3:           h3,
		h2:           h2,
		lifeline:     lifeline,
		dialDeadline: 90 * time.Second,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// Available reports whether at least one sub-mode dialer is
// linked into this build.
func (h *Handler) Available() bool {
	if h == nil {
		return false
	}
	return h.h3 != nil || h.h2 != nil || h.lifeline != nil
}

// Dial activates a MASQUE route. The path is:
//
//  1. chooseSubmode applies the cascade (override / mode /
//     netmem hint / UDP probe / burn signal).
//  2. The corresponding dialer opens the tunnel.
//  3. On success, persist (routeID, submode, networkID) via
//     the per-route + per-network callback.
//
// Errors map to the V0 failure taxonomy at the engine layer;
// the handler returns the raw error for the caller to classify.
func (h *Handler) Dial(ctx context.Context, route Route) (*Conn, error) {
	if !h.Available() {
		return nil, ErrFamilyHandlerUnavailable
	}
	if route.MasqueEndpoint == "" {
		return nil, ErrNoEndpoint
	}
	if h.dialDeadline > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, h.dialDeadline)
		defer cancel()
	}

	override := ""
	if h.overrideFn != nil {
		override = h.overrideFn()
	}
	chosen, err := chooseSubmode(route, override)
	if err != nil {
		return nil, err
	}

	dialer := h.dialerFor(chosen)
	if dialer == nil {
		return nil, ErrSubmodeUnreachable
	}

	conn, err := dialer(ctx, route.MasqueEndpoint)
	if err != nil {
		return nil, err
	}
	if conn == nil {
		conn = &Conn{}
	}
	conn.Submode = chosen
	conn.Endpoint = route.MasqueEndpoint

	if h.recordSubmode != nil {
		h.recordSubmode(route.RouteID, chosen, route.NetworkID)
	}
	return conn, nil
}

// dialerFor returns the dialer callback for the chosen
// sub-mode, or nil if the sub-mode is not linked.
func (h *Handler) dialerFor(s Submode) SubmodeDialer {
	switch s {
	case SubmodeH3QUIC:
		return h.h3
	case SubmodeH2Connect:
		return h.h2
	case SubmodeLifeline:
		return h.lifeline
	}
	return nil
}

// chooseSubmode applies the locked-at-3C cascade. Pure
// function — no I/O, no clock, deterministic given inputs.
//
// Cascade order (locked):
//
//  1. override set + valid → use override (still respects the
//     lifeline-strict clamp at step 2).
//  2. mode == "lifeline-strict" AND family = masque → hint
//     SubmodeLifeline. Override wins if set; otherwise this
//     step pins the rung. Other lifeline-* combinations fall
//     through to the netmem / probe layers.
//  3. netmem LastUsedSubmode in v1 list → start there.
//  4. UDPProbeOK true → SubmodeH3QUIC.
//  5. UDPProbeOK false → SubmodeH2Connect.
//  6. (post-pick adjustment) if H2Burned AND mode in
//     {"lifeline","lifeline-strict"} AND chosen ==
//     SubmodeH2Connect → drop to SubmodeLifeline.
func chooseSubmode(route Route, override string) (Submode, error) {
	// Step 1 — override.
	if override != "" {
		if !IsKnownSubmode(override) {
			return "", ErrUnknownSubmode
		}
		// Even with an explicit override, the lifeline-strict
		// clamp still applies: a user who pinned H3QUIC must
		// not bypass the strict rung. The override wins
		// against any non-strict mode but is *clamped down*
		// to lifeline if the user is in strict mode.
		if route.Mode == "lifeline-strict" && Submode(override) != SubmodeLifeline {
			return SubmodeLifeline, nil
		}
		return Submode(override), nil
	}

	// Step 2 — strict mode hint.
	if route.Mode == "lifeline-strict" {
		return SubmodeLifeline, nil
	}

	chosen := Submode("")

	// Step 3 — netmem hint.
	if route.LastUsedSubmode != "" && IsKnownSubmode(route.LastUsedSubmode) {
		chosen = Submode(route.LastUsedSubmode)
	}

	// Steps 4 / 5 — UDP probe outcome (only consulted if no
	// netmem hint).
	if chosen == "" {
		if route.UDPProbeOK {
			chosen = SubmodeH3QUIC
		} else {
			chosen = SubmodeH2Connect
		}
	}

	// Step 6 — burn-aware drop. Only when H2 was the chosen
	// rung AND the user is in any lifeline-mode flavour.
	if chosen == SubmodeH2Connect && route.H2Burned &&
		(route.Mode == "lifeline" || route.Mode == "lifeline-strict") {
		chosen = SubmodeLifeline
	}

	return chosen, nil
}
