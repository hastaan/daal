package diagnostics

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

// Classify (classify.go) maps an error STRING onto the taxonomy, and its
// table is locked. A string cannot carry the two facts the taxonomy most
// needs (the end-to-end rig's finding CEN-2):
//
//   - WHERE in the attempt the failure happened. "i/o timeout" on a TCP
//     socket is a dead address when it is the SYN that went unanswered
//     and a swallowed ClientHello when it is the first read after it, and
//     Classify files both under tcp_connect_timeout.
//   - WHAT the first flight was. A reset right after a TLS ClientHello is
//     the signature of a name-keyed filter; the same reset after an
//     opaque first flight is not.
//
// The engine knows both at the moment it proves a route (core/engine
// proof.go: which call returned the error, and what the outbound is), so
// it hands them over as an Observation and ClassifyObservation decides.
// Nothing in Classify is re-mapped: where the observation settles
// nothing, the string table still has the last word.

// Phase is how far an attempt got before it failed, seen from the
// client. The phases are the points at which a censor acts, not the
// layers of any one protocol.
type Phase string

const (
	// PhaseUnknown: the caller could not tell. Only the string table
	// applies.
	PhaseUnknown Phase = ""
	// PhaseReach: opening the transport to the relay — the SYN for a
	// TCP family, the first datagram for a UDP one. Nothing of the
	// family's own protocol has been sent.
	PhaseReach Phase = "reach"
	// PhaseHandshake: the transport is open and the family's own first
	// flight (a TLS ClientHello, for most) has gone out; the relay's
	// answer to it has not arrived.
	PhaseHandshake Phase = "handshake"
	// PhaseCarry: the relay answered. The failure is in getting a round
	// trip THROUGH it: the relay refused the credential, could not reach
	// the far end, or the path is too slow to finish.
	PhaseCarry Phase = "carry"
)

// Observation is one failed attempt, described by what the engine
// knows beyond the error text.
type Observation struct {
	Phase Phase
	// UDP: the route's transport to the relay is UDP (hysteria2, tuic,
	// wireguard, masque h3). A UDP route that hears nothing cannot tell
	// a dead address from a dead port from a network without UDP.
	UDP bool
	// TLS: the family's first flight to the relay is a TLS ClientHello,
	// i.e. there is a name (or the absence of one) for a filter to key
	// on.
	TLS bool
	// What kind of failure the error chain carries. At most one is
	// normally set; all false means "something else" and the string
	// table decides.
	Timeout bool // nothing came back in time
	Reset   bool // RST after the connection was open
	Refused bool // RST in answer to the SYN
	Closed  bool // the far end closed cleanly (EOF) where an answer was due
	// Progress: the engine SAW the path moving while this attempt ran
	// out of time — bytes came back from the far side, or the relay's
	// own answer took seconds to arrive. A timeout with Progress is a
	// path that is slow, not one that is silent, and is never read as
	// a block (the end-to-end rig's observation CEN-O5).
	Progress bool
	// RelayNoEgress: the relay answered its own handshake on a
	// connection opened for this check, and every far-side host tried
	// through it stayed silent. Set by the connection proof only, after
	// at least two hosts run by different operators.
	RelayNoEgress bool
	// Message is the error text, for the locked string table.
	Message string
}

// Observe builds an Observation from an error and the context the
// caller has. It reads the error CHAIN (errors.Is / errors.As) and only
// falls back to the text for errors that crossed a boundary which
// flattened them (Cronet, quic-go).
func Observe(err error, phase Phase, udp, tls bool) Observation {
	o := Observation{Phase: phase, UDP: udp, TLS: tls}
	if err == nil {
		return o
	}
	o.Message = err.Error()
	m := strings.ToLower(o.Message)

	// A failed connect() is the reach phase whatever the caller thought:
	// an outbound that dials lazily reports its SYN timeout from the
	// first read.
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "dial" {
		o.Phase = PhaseReach
	}

	var ne net.Error
	switch {
	case errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(m, "connection refused"):
		o.Refused = true
	case errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) ||
		strings.Contains(m, "connection reset by peer") || strings.Contains(m, "broken pipe"):
		o.Reset = true
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) ||
		(errors.As(err, &ne) && ne.Timeout()) ||
		strings.Contains(m, "i/o timeout") || strings.Contains(m, "deadline exceeded") ||
		strings.Contains(m, "no recent network activity") || strings.Contains(m, "handshake did not complete in time"):
		o.Timeout = true
	case errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) ||
		strings.HasSuffix(m, "eof") || strings.Contains(m, "use of closed network connection"):
		o.Closed = true
	}

	// Cronet (the naive family) reports Chromium net errors as numbers
	// and nothing else; the number is the only place the phase survives.
	if code, ok := cronetNetError(m); ok {
		applyCronet(&o, code)
	}
	return o
}

// ClassifyObservation maps one failed attempt onto the taxonomy.
//
// Order:
//
//  1. Failures that say what they are (credentials, no network, engine
//     death) keep the category the locked string table gives them. The
//     phase adds nothing to "authentication failed".
//  2. A UDP route that heard nothing is udp_no_reply — and never
//     udp_unavailable or quic_unavailable, which are claims about the
//     NETWORK that one silent address cannot support.
//  3. TCP, by phase: see the table in specs/failure-taxonomy-v1.md
//     "Classification by phase".
//  4. Anything left goes to the string table, unchanged.
func ClassifyObservation(o Observation) Category {
	legacy := Classify(o.Message)
	switch legacy {
	case AuthFailed, EngineCrash, NetworkOffline, DNSBogon, DNSPoisoned,
		RouteExpired, PublisherRevoked, PublisherKeyChanged,
		BundleSignatureInvalid, BundleCorrupted, OriginUnhealthy:
		return legacy
	}
	// What the engine measured outranks what the silence looks like.
	// A timeout on a path that was visibly moving is slowness; and a
	// relay that answered and then carried nothing to anyone has no way
	// out. Neither is a claim about a filter.
	if o.Timeout && o.Progress {
		return PathTooSlow
	}
	if o.RelayNoEgress {
		return RelayNoEgress
	}
	if o.UDP {
		if o.Phase != PhaseCarry && (o.Timeout || legacy == QUICUnavailable || legacy == UDPUnavailable) {
			return UDPNoReply
		}
		if o.Phase == PhaseCarry && (o.Timeout || o.Closed) {
			return Unknown
		}
		return legacy
	}
	switch o.Phase {
	case PhaseReach:
		switch {
		case o.Timeout:
			return TCPConnectTimeout
		case o.Refused, o.Reset:
			return TCPReset
		}
	case PhaseHandshake:
		switch {
		case o.Refused:
			return TCPReset
		case o.Reset && o.TLS:
			// "TCP works, TLS resets immediately after ClientHello." It
			// is SUSPECTED for a reason: a filter keyed on the address
			// resets the same flow at the same moment, and only a
			// second name to the same address tells the two apart.
			return TLSSNIOrCertBlockSuspected
		case o.Reset:
			return TCPReset
		case (o.Timeout || o.Closed) && o.TLS:
			return TLSHandshakeFailed
		}
	case PhaseCarry:
		switch {
		case o.Reset, o.Refused:
			return TCPReset
		case o.Timeout, o.Closed:
			// The relay answered and then nothing came back through
			// it. That is not a connect timeout (the address is alive)
			// and not a handshake failure (it completed). The taxonomy
			// has no narrower word that would be true.
			return Unknown
		}
	}
	return legacy
}

var cronetErrRe = regexp.MustCompile(`net_error (-\d+)`)

func cronetNetError(lowerMsg string) (int, bool) {
	m := cronetErrRe.FindStringSubmatch(lowerMsg)
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	return n, err == nil
}

// applyCronet translates the Chromium net error codes that correspond to
// something a censor does (net/base/net_error_list.h). Codes not listed
// leave the observation as the text made it.
func applyCronet(o *Observation, code int) {
	clear := func() { o.Timeout, o.Reset, o.Refused, o.Closed = false, false, false, false }
	switch code {
	case -118: // ERR_CONNECTION_TIMED_OUT: the SYN went unanswered
		clear()
		o.Phase, o.Timeout = PhaseReach, true
	case -102: // ERR_CONNECTION_REFUSED
		clear()
		o.Phase, o.Refused = PhaseReach, true
	case -101: // ERR_CONNECTION_RESET: after the connection was open
		clear()
		if o.Phase == PhaseReach || o.Phase == PhaseUnknown {
			o.Phase = PhaseHandshake
		}
		o.Reset = true
	case -100, -324: // ERR_CONNECTION_CLOSED, ERR_EMPTY_RESPONSE
		clear()
		if o.Phase == PhaseReach || o.Phase == PhaseUnknown {
			o.Phase = PhaseHandshake
		}
		o.Closed = true
	case -7: // ERR_TIMED_OUT: an operation after the connect
		clear()
		if o.Phase == PhaseReach || o.Phase == PhaseUnknown {
			o.Phase = PhaseHandshake
		}
		o.Timeout = true
	}
}
