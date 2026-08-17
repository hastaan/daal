package relaypack

import "daal/publisher/deploy/profiles"

// multiplex.go — Wave 2 Step 5: stream multiplexing on the TLS-family
// client outbounds.
//
// WHY. Xue et al. (USENIX Security 2024) classify nested-TLS proxies —
// REALITY+Vision included — at >70% TPR for 0.054% FPR, and the only
// documented defence they find (and explicitly recommend as the top
// mitigation) is aggressive stream multiplexing with many concurrent
// active streams, which cuts detection by >70%. The signal they key on is
// the *shape of a fresh connection*: one TCP+TLS connection per user flow
// means one classifier sample per fetch. Multiplexing collapses a page
// load's worth of flows onto a single connection, so the classifier sees
// an order of magnitude fewer samples and each one carries traffic that
// no longer looks like a single nested tunnel.
//
// It costs nothing to ship: sing-mux v0.3.4 and sagernet/smux are already
// in core/go.mod's module graph, and sing-box 1.13.12's option/vless.go
// accepts OutboundMultiplexOptions on the outbound and
// InboundMultiplexOptions on the inbound. This is a JSON object, not a
// dependency.
//
// THE TRADE, stated honestly: smux/h2mux over TCP reintroduces
// head-of-line blocking — one lost segment stalls every stream riding
// that connection. That is why the knob is per-route and why the
// QUIC-native tier (hysteria2) must never get it.
//
// COMPATIBILITY, verified in sing-box source: an inbound with
// `multiplex.enabled` wraps its router in common/mux.Router, whose
// RouteConnectionEx sends a connection to the mux service ONLY when the
// inner destination equals the mux sentinel, and otherwise delegates to
// the normal router (common/mux/router.go:70-77). So a mux-enabled relay
// still serves every already-distributed non-mux pack. The reverse is NOT
// true — NewRouterWithOptions returns the bare router when Enabled is
// false, so a mux client against a pre-Wave-2 relay routes to the literal
// sentinel host and fails. Hence: emission is opt-in per pack, driven by
// the profile of the relay being minted against, and defaults to off.

// DefaultMuxMaxStreams is the per-connection concurrent-stream ceiling
// used when a profile enables multiplex without naming one.
//
// The number matters, and 2 or 4 would buy nothing. sing-mux opens a NEW
// connection only once the least-loaded existing session already carries
// max_streams active streams (sing-mux@v0.3.4/client.go:161-177), so this
// value IS the answer to "how much traffic rides one TCP connection".
//
//   - 64 covers the peak concurrency of a real page load (a modern page
//     fans out to a few dozen parallel requests) on ONE connection, which
//     is the regime Xue et al. measure the >70% detection drop in. A
//     small value like 8 would still open a new connection — and hand the
//     classifier a fresh sample — several times per page.
//   - It stays well under the h2mux server's own ceiling: the inbound
//     runs golang.org/x/net/http2.Server with MaxConcurrentStreams unset,
//     i.e. the 250-stream default (sing-mux@v0.3.4/h2mux.go:34-41). Above
//     that the client's ClientConn stops accepting new requests and
//     sing-mux silently dials a second connection anyway, so a bigger
//     number would not buy more sharing — it would just make the real
//     ceiling implicit.
//   - It bounds the head-of-line blast radius: one lost segment stalls at
//     most this many streams, and 64 is the point where added sharing
//     stops paying for the added stall.
//
// Lower it per route in the profile if a link is loss-prone; do not raise
// it past ~250 without also raising the inbound's http2 limit, which
// sing-box does not expose.
const DefaultMuxMaxStreams = 64

// MuxPolicy is the per-route multiplexing knob. Zero value = off, which
// is the pre-Wave-2 wire shape.
type MuxPolicy struct {
	Enabled bool
	// MaxStreams is the concurrent-stream ceiling per connection; 0 means
	// DefaultMuxMaxStreams.
	MaxStreams int
}

// MultiplexFromProfile turns a toolbox profile's per-candidate multiplex
// knobs into the per-family policy map ClientConnParams carries, so the
// profile JSON is the single place the decision lives. Candidates whose
// family cannot carry mux are dropped here as well as gated in the
// renderer — a profile is data an operator may edit, so a wrong entry in
// it must be inert, not fatal.
//
// The caller is responsible for only handing this to a pack minted
// against a relay whose inbounds actually have `multiplex` (see the
// compatibility note above); a nil profile yields a nil map, i.e. off.
func MultiplexFromProfile(p *profiles.Profile) map[string]MuxPolicy {
	if p == nil {
		return nil
	}
	var out map[string]MuxPolicy
	for _, c := range p.Candidates {
		if c.Multiplex == nil || !c.Multiplex.Enabled || !familyCarriesMultiplex(c.Family) {
			continue
		}
		if out == nil {
			out = make(map[string]MuxPolicy, len(p.Candidates))
		}
		out[c.Family] = MuxPolicy{Enabled: true, MaxStreams: c.Multiplex.MaxStreams}
	}
	return out
}

// familyCarriesMultiplex reports whether a client outbound for this
// family may carry a `multiplex` block at all. This is a hard gate, not a
// default: a profile that enables mux on a family listed here as false is
// ignored rather than obeyed, because the result would be either a
// config the strict parser rejects (hysteria2 has no Multiplex field) or
// a route that is worse than no route (QUIC under a TCP stream layer).
func familyCarriesMultiplex(family string) bool {
	switch family {
	case "vless-reality", "websocket-tls":
		// Both are option.VLESSOutboundOptions, which carries Multiplex.
		return true
	case "hysteria2", "tuic":
		// QUIC-native: head-of-line blocking, and no Multiplex field.
		return false
	case "naive":
		// naive rides Cronet (HTTP/2 CONNECT through its own stack);
		// sing-mux is not in that path.
		return false
	default:
		return false
	}
}

// muxPolicyFor resolves the effective policy for one family.
func muxPolicyFor(family string, p ClientConnParams) (MuxPolicy, bool) {
	if !familyCarriesMultiplex(family) {
		return MuxPolicy{}, false
	}
	pol, ok := p.Multiplex[family]
	if !ok || !pol.Enabled {
		return MuxPolicy{}, false
	}
	if pol.MaxStreams <= 0 {
		pol.MaxStreams = DefaultMuxMaxStreams
	}
	return pol, true
}

// addMultiplex attaches the outbound `multiplex` object to a rendered
// outbound when the route's policy asks for it. h2mux is chosen over
// smux/yamux because it is sing-mux's default protocol and the only one
// whose stream layer is itself an ordinary HTTP/2 connection; padding is
// always on, since sing-mux's padded framing (Version1) is what removes
// the fixed-size handshake preamble a length-based classifier would key
// on, and there is no reason a Daal route would ever want it off.
func addMultiplex(ob map[string]any, family string, p ClientConnParams) {
	pol, ok := muxPolicyFor(family, p)
	if !ok {
		return
	}
	ob["multiplex"] = map[string]any{
		"enabled":     true,
		"protocol":    "h2mux",
		"padding":     true,
		"max_streams": pol.MaxStreams,
	}
}
