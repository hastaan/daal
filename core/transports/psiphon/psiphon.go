// Package psiphon is the Phase 3D Psiphon transport-family
// integration point. It carries upstream Psiphon publisher
// bundles (Psiphon Inc., GPLv3) through the engine's family
// handler interface.
//
// The wiring is:
//
//	pathmanager activates a psiphon route
//	     │
//	     ▼
//	psiphon.Handler.Dial(ctx, route)
//	     │  validates the opaque blob (size sanity only)
//	     ▼
//	PsiphonDialer(ctx, blob)
//	     │  upstream psiphon-tunnel-core opens a tunnel
//	     ▼
//	sing-box outbound returned to the path manager
//
// Daal's bundle parser performs ONLY structural size checks on
// the Psiphon bundle bytes (256 bytes ≤ size ≤ 65536 bytes per
// `specs/psiphon-route-v1.md`). Semantic validation
// (signature / expiry / protocol selection) is the upstream
// library's responsibility — the project does NOT second-guess
// Psiphon's own validation.
//
// Per the Phase 3D licensing posture:
//   - psiphon-tunnel-core is GPLv3.
//   - The vendored copy is carried under that license.
//   - Builds for distribution channels where GPL incorporation
//     is undesirable use `-tags no_psiphon`; the upstream
//     library is then not linked, the Dialer callback is nil,
//     and Dial returns ErrFamilyHandlerUnavailable. The
//     pathmanager filters every psiphon route as if
//     `experimental_min_engine_version` failed.
//
// This skeleton does NOT import psiphon-tunnel-core directly.
// The upstream library is wired through the PsiphonDialer
// callback so this package is unit-testable without the
// upstream tree (mirroring 3B Snowflake's WebRTCDialer pattern
// and 3C MASQUE's SubmodeDialer pattern).
package psiphon

import (
	"context"
	"errors"
	"sync"
	"time"
)

// FamilyID is the transport-family token consumed by the
// pathmanager and the bundle parser.
const FamilyID = "psiphon"

// Bundle size sanity bounds, locked at 3D per
// `specs/psiphon-route-v1.md`. Below the lower bound is
// malformed; above the upper bound is refused as a
// resource-exhaustion guard. Real Psiphon publisher bundles
// land between 4 and 16 KB.
const (
	MinBundleBytes = 256
	MaxBundleBytes = 65536
)

// Errors.
var (
	// ErrFamilyHandlerUnavailable is returned by Dial when the
	// engine was built with `-tags no_psiphon` and the upstream
	// psiphon-tunnel-core tree is not linked. The pathmanager
	// filters the route as if `experimental_min_engine_version`
	// failed.
	ErrFamilyHandlerUnavailable = errors.New("psiphon: family handler unavailable in this build")

	// ErrBundleMissing is returned when a route reaches Dial
	// without a non-empty Psiphon blob. The bundle parser
	// rejects psiphon routes without a blob; this guard is
	// defence-in-depth for engine-internal call sites.
	ErrBundleMissing = errors.New("psiphon: route has no Psiphon bundle blob")

	// ErrBundleSizeOutOfRange is returned when the blob falls
	// outside the [MinBundleBytes, MaxBundleBytes] sanity
	// envelope. The bundle parser also enforces this; the
	// engine guard is defence-in-depth.
	ErrBundleSizeOutOfRange = errors.New("psiphon: bundle size out of range")
)

// Route is the per-route input to the Psiphon handler.
type Route struct {
	RouteID         string
	NetworkID       string // hashed; never the raw SSID
	PublisherKeyHex string

	// PsiphonBlob is the opaque upstream-Psiphon publisher
	// bundle bytes. Daal never inspects this; it is forwarded
	// verbatim to PsiphonDialer.
	PsiphonBlob []byte
}

// Conn is the family-handler outbound returned by Dial. Real
// upstream wiring returns a sing-box outbound; the skeleton
// returns a thin wrapper carrying the route ID so the engine
// layer can persist the active-route diagnostic field.
type Conn struct {
	RouteID string
}

// PsiphonDialer is the upstream-Psiphon adapter callback. The
// engine layer wires this to `psiphon-tunnel-core`'s public
// dial surface; tests pass a stub. The blob bytes are opaque
// to Daal and forwarded verbatim.
type PsiphonDialer func(ctx context.Context, blob []byte) (*Conn, error)

// Handler is the Phase 3D Psiphon family handler. It is the
// glue between the pathmanager activation surface and the
// upstream psiphon-tunnel-core library.
type Handler struct {
	dialer PsiphonDialer

	// recordActive is the per-route diagnostic callback the
	// engine wires to the abi diagnostics emitter. It records
	// the currently-active psiphon route ID so the
	// `psiphon_active_route` diagnostic field can render. Not
	// called when Dial fails.
	recordActive func(routeID string)

	dialDeadline time.Duration

	mu sync.Mutex
}

// HandlerOption tunes the Handler.
type HandlerOption func(*Handler)

// WithRecordActive wires the per-route active-diagnostic
// callback. The engine layer uses this to feed the
// `psiphon_active_route` diagnostic field.
func WithRecordActive(fn func(routeID string)) HandlerOption {
	return func(h *Handler) { h.recordActive = fn }
}

// WithDialDeadline overrides the default 90-second total Dial
// deadline.
func WithDialDeadline(d time.Duration) HandlerOption {
	return func(h *Handler) { h.dialDeadline = d }
}

// NewHandler constructs the Psiphon family handler. Pass a nil
// dialer in `-tags no_psiphon` builds; Dial returns
// ErrFamilyHandlerUnavailable.
func NewHandler(dialer PsiphonDialer, opts ...HandlerOption) *Handler {
	h := &Handler{
		dialer:       dialer,
		dialDeadline: 90 * time.Second,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// Available reports whether the upstream psiphon-tunnel-core is
// linked into this build.
func (h *Handler) Available() bool {
	if h == nil {
		return false
	}
	return h.dialer != nil
}

// Dial activates a Psiphon route. The path is:
//
//  1. Validate the opaque blob is present and size-sane.
//  2. Hand off to the upstream PsiphonDialer.
//  3. On success, record the active-route ID via the diag
//     callback.
//
// The upstream library performs all semantic validation
// (signature, expiry, protocol-class selection). Daal never
// inspects Psiphon bundle bytes — that's the locked-at-3D
// posture per `specs/psiphon-route-v1.md`.
//
// Errors map to the V0 failure taxonomy at the engine layer
// per the cosmetic surfaces in `specs/failure-taxonomy-v1.md`
// 3D amendment.
func (h *Handler) Dial(ctx context.Context, route Route) (*Conn, error) {
	if !h.Available() {
		return nil, ErrFamilyHandlerUnavailable
	}
	if len(route.PsiphonBlob) == 0 {
		return nil, ErrBundleMissing
	}
	if len(route.PsiphonBlob) < MinBundleBytes || len(route.PsiphonBlob) > MaxBundleBytes {
		return nil, ErrBundleSizeOutOfRange
	}
	if h.dialDeadline > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, h.dialDeadline)
		defer cancel()
	}

	conn, err := h.dialer(ctx, route.PsiphonBlob)
	if err != nil {
		return nil, err
	}
	if conn == nil {
		conn = &Conn{}
	}
	conn.RouteID = route.RouteID

	if h.recordActive != nil {
		h.recordActive(route.RouteID)
	}
	return conn, nil
}
