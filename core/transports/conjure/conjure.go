// Package conjure is the Phase 3D Conjure transport-family
// integration point. It wraps upstream `gotapdance`
// (refraction-networking, Apache-2.0) with the engine's family
// handler interface.
//
// The wiring is:
//
//	pathmanager activates a conjure route
//	     │
//	     ▼
//	conjure.Handler.Dial(ctx, route)
//	     │  validates the phantom subnets + station pubkey
//	     ▼
//	ConjureDialer(ctx, phantomSubnets, stationPubkey, decoyPool)
//	     │  upstream gotapdance registers + tunnels
//	     ▼
//	sing-box outbound returned to the path manager
//
// Per the Phase 3D licensing posture: gotapdance is Apache-2.0,
// so the upstream library is unconditionally compiled. There
// is no `-tags no_conjure` excluder at 3D — a future
// size-budget decision MAY introduce one for build-size
// trimming, mirroring the 3B `-tags no_snowflake` precedent.
//
// The phantom-pool rotation logic lives INSIDE the upstream
// gotapdance library. When the active phantom IP is detected
// and dropped by the censor mid-session, the upstream library
// reaches into the pool and selects another. Daal's shim
// observes this through the failure category returned on Dial
// errors and feeds the 2G burn classifier as usual; we do NOT
// re-implement the rotation policy in Daal.
//
// This skeleton does NOT import gotapdance directly. The
// upstream library is wired through the ConjureDialer callback
// so this package is unit-testable without the upstream tree.
package conjure

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"sync"
	"time"
)

// FamilyID is the transport-family token consumed by the
// pathmanager and the bundle parser.
const FamilyID = "conjure"

// Phantom-pool prefix-length floors locked at 3D per
// `specs/conjure-route-v1.md`. Refusing implausibly broad
// pools is defence-in-depth; a /16 IPv4 phantom range is
// either a test fixture or a misconfiguration.
const (
	MinIPv4PrefixLen = 24
	MinIPv6PrefixLen = 32
)

// StationPubkeyHexLen is the locked length of the Conjure
// station pubkey hex string (32 bytes → 64 hex chars).
const StationPubkeyHexLen = 64

// Errors.
var (
	// ErrFamilyHandlerUnavailable is returned by Dial when the
	// engine was built without the upstream gotapdance tree
	// linked. The pathmanager filters the route as if
	// `experimental_min_engine_version` failed.
	ErrFamilyHandlerUnavailable = errors.New("conjure: family handler unavailable in this build")

	// ErrNoPhantomSubnets is returned when a route reaches
	// Dial with an empty phantom subnet list. The bundle
	// parser rejects conjure routes without a non-empty pool;
	// this guard is defence-in-depth.
	ErrNoPhantomSubnets = errors.New("conjure: route has no phantom subnets")

	// ErrPhantomSubnetMalformed is returned when one of the
	// supplied phantom subnets is not a parseable CIDR or has
	// a prefix length below the locked-at-3D floor.
	ErrPhantomSubnetMalformed = errors.New("conjure: phantom subnet malformed or too broad")

	// ErrStationPubkeyMalformed is returned when the station
	// pubkey is not 32 bytes hex (64 hex chars).
	ErrStationPubkeyMalformed = errors.New("conjure: station pubkey malformed")

	// ErrDecoyHostMalformed is returned when one of the decoy
	// hostnames fails RFC 1123.
	ErrDecoyHostMalformed = errors.New("conjure: decoy host malformed")

	// ErrPhantomPoolExhausted is returned by the upstream
	// library wrapper when every phantom IP in the route's
	// pool has burned within the current session. Maps to
	// `tcp_connect_timeout` in the V0 taxonomy with the
	// cosmetic `conjure_phantom_exhausted` annotation.
	ErrPhantomPoolExhausted = errors.New("conjure: phantom pool exhausted")
)

// Route is the per-route input to the Conjure handler. Fields
// are materialised by the engine layer from the routestore Row
// (see `routes.conjure_*` columns).
type Route struct {
	RouteID         string
	NetworkID       string
	PublisherKeyHex string

	// PhantomSubnets is the non-empty list of CIDR strings
	// (IPv4 or IPv6 mix). Validated at Dial time per
	// `specs/conjure-route-v1.md`.
	PhantomSubnets []string

	// StationPubkey is the Conjure Tap-Dance station's
	// curve25519 public key, hex-encoded (64 hex chars).
	StationPubkey string

	// DecoyPool is the list of decoy hostnames the upstream
	// library MAY use as registration cover. Empty list ==
	// upstream picks its built-in defaults.
	DecoyPool []string
}

// Conn is the family-handler outbound returned by Dial. Real
// upstream wiring returns a sing-box outbound; the skeleton
// returns a thin wrapper carrying the route ID and the
// HASHED phantom IP that the upstream library ended up using
// (so the engine layer can render the
// `conjure_phantom_in_use` diagnostic without leaking the
// raw IP).
type Conn struct {
	RouteID string
	// PhantomInUseHash is the first 8 bytes of
	// SHA-256(rawPhantomIP) rendered as 16 hex chars. Empty
	// string means "upstream did not surface the chosen
	// phantom" (older library versions).
	PhantomInUseHash string
}

// ConjureDialer is the upstream-Conjure adapter callback. The
// engine layer wires this to gotapdance; tests pass a stub.
// The dialer returns the raw phantom IP it selected so the
// shim can hash it for the diagnostic field; the raw IP is
// then discarded.
type ConjureDialer func(
	ctx context.Context,
	phantomSubnets []string,
	stationPubkey []byte,
	decoyPool []string,
) (rawPhantomIP string, conn *Conn, err error)

// Handler is the Phase 3D Conjure family handler.
type Handler struct {
	dialer ConjureDialer

	recordActive       func(routeID string)
	recordPhantomInUse func(phantomHashHex string)

	dialDeadline time.Duration

	mu sync.Mutex
}

// HandlerOption tunes the Handler.
type HandlerOption func(*Handler)

// WithRecordActive wires the per-route active-diagnostic
// callback.
func WithRecordActive(fn func(routeID string)) HandlerOption {
	return func(h *Handler) { h.recordActive = fn }
}

// WithRecordPhantomInUse wires the hashed-phantom-in-use
// diagnostic callback. The engine emitter uses this to feed
// the `conjure_phantom_in_use` diagnostic field.
func WithRecordPhantomInUse(fn func(phantomHashHex string)) HandlerOption {
	return func(h *Handler) { h.recordPhantomInUse = fn }
}

// WithDialDeadline overrides the default 90-second total Dial
// deadline.
func WithDialDeadline(d time.Duration) HandlerOption {
	return func(h *Handler) { h.dialDeadline = d }
}

// NewHandler constructs the Conjure family handler.
func NewHandler(dialer ConjureDialer, opts ...HandlerOption) *Handler {
	h := &Handler{
		dialer:       dialer,
		dialDeadline: 90 * time.Second,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// Available reports whether the upstream gotapdance library is
// linked into this build.
func (h *Handler) Available() bool {
	if h == nil {
		return false
	}
	return h.dialer != nil
}

// Dial activates a Conjure route. The path is:
//
//  1. Validate phantom subnets, station pubkey, and decoy
//     hosts (defence-in-depth — bundle parser already
//     validated).
//  2. Hand off to the upstream ConjureDialer.
//  3. On success, record the active route ID + the HASHED
//     phantom IP via the diagnostic callbacks.
//
// Errors map to the V0 failure taxonomy at the engine layer
// per the cosmetic surfaces in `specs/failure-taxonomy-v1.md`
// 3D amendment.
func (h *Handler) Dial(ctx context.Context, route Route) (*Conn, error) {
	if !h.Available() {
		return nil, ErrFamilyHandlerUnavailable
	}
	if len(route.PhantomSubnets) == 0 {
		return nil, ErrNoPhantomSubnets
	}
	for _, cidr := range route.PhantomSubnets {
		if err := ValidatePhantomSubnet(cidr); err != nil {
			return nil, err
		}
	}
	pubkey, err := decodeStationPubkey(route.StationPubkey)
	if err != nil {
		return nil, err
	}
	for _, host := range route.DecoyPool {
		if !ValidDecoyHost(host) {
			return nil, ErrDecoyHostMalformed
		}
	}
	if h.dialDeadline > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, h.dialDeadline)
		defer cancel()
	}

	rawPhantom, conn, err := h.dialer(ctx, route.PhantomSubnets, pubkey, route.DecoyPool)
	if err != nil {
		return nil, err
	}
	if conn == nil {
		conn = &Conn{}
	}
	conn.RouteID = route.RouteID
	if rawPhantom != "" {
		conn.PhantomInUseHash = HashPhantom(rawPhantom)
	}

	if h.recordActive != nil {
		h.recordActive(route.RouteID)
	}
	if h.recordPhantomInUse != nil && conn.PhantomInUseHash != "" {
		h.recordPhantomInUse(conn.PhantomInUseHash)
	}
	return conn, nil
}

// ValidatePhantomSubnet enforces the locked-at-3D prefix-
// length floors and CIDR parseability. Public so the bundle
// parser can call the same code path.
func ValidatePhantomSubnet(cidr string) error {
	_, ipnet, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return ErrPhantomSubnetMalformed
	}
	ones, _ := ipnet.Mask.Size()
	if ipnet.IP.To4() != nil {
		// IPv4
		if ones < MinIPv4PrefixLen {
			return ErrPhantomSubnetMalformed
		}
	} else {
		// IPv6
		if ones < MinIPv6PrefixLen {
			return ErrPhantomSubnetMalformed
		}
	}
	return nil
}

// ValidDecoyHost checks an RFC 1123 hostname (best-effort,
// stdlib-only). Empty strings are rejected; trailing dots are
// not allowed (we want a hostname, not a fully-qualified DNS
// label).
func ValidDecoyHost(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	if len(host) > 253 {
		return false
	}
	if strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" {
			return false
		}
		if len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			isLetter := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
			isDigit := c >= '0' && c <= '9'
			isHyphen := c == '-'
			if !isLetter && !isDigit && !isHyphen {
				return false
			}
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}

// HashPhantom renders the diagnostic field
// `conjure_phantom_in_use`: first 8 bytes of SHA-256(rawIP)
// hex-encoded (16 chars). Same shape as the V2.4 hashed
// network ID. The raw IP is never persisted.
func HashPhantom(rawIP string) string {
	sum := sha256.Sum256([]byte(rawIP))
	return hex.EncodeToString(sum[:8])
}

// decodeStationPubkey validates the station-pubkey hex string
// and returns the 32-byte key material. Bundle parser also
// enforces; this guard is defence-in-depth.
func decodeStationPubkey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if len(s) != StationPubkeyHexLen {
		return nil, ErrStationPubkeyMalformed
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, ErrStationPubkeyMalformed
	}
	return b, nil
}
