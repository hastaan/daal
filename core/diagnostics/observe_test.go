package diagnostics

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"testing"
)

func dialErr(inner error) error {
	return &net.OpError{Op: "dial", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(203, 0, 113, 10), Port: 443}, Err: inner}
}

func readErr(inner error) error {
	return &net.OpError{Op: "read", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(203, 0, 113, 10), Port: 443}, Err: inner}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// The four rows of the end-to-end rig's finding CEN-2: the error a socket sees for
// each thing a censor does, and the category the taxonomy asks for. The
// last two are the ones the string table gets wrong — the same text is
// filed under tcp_reset and tcp_connect_timeout — and the phase is what
// tells them apart.
func TestClassifyObservation_PhaseSeparatesWhatTheStringCannot(t *testing.T) {
	cases := []struct {
		name  string
		err   error
		phase Phase
		udp   bool
		tls   bool
		want  Category
	}{
		{"SYN unanswered", dialErr(timeoutErr{}), PhaseHandshake, false, true, TCPConnectTimeout},
		{"SYN refused", dialErr(syscall.ECONNREFUSED), PhaseHandshake, false, true, TCPReset},
		{"reset after an opaque first flight", readErr(syscall.ECONNRESET), PhaseCarry, false, false, TCPReset},
		{"reset after the ClientHello", readErr(syscall.ECONNRESET), PhaseHandshake, false, true, TLSSNIOrCertBlockSuspected},
		{"ClientHello swallowed (read timeout)", readErr(timeoutErr{}), PhaseHandshake, false, true, TLSHandshakeFailed},
		{"ClientHello swallowed (context deadline)", context.DeadlineExceeded, PhaseHandshake, false, true, TLSHandshakeFailed},
		{"relay closes during the handshake", io.EOF, PhaseHandshake, false, true, TLSHandshakeFailed},
		{"reset during a non-TLS handshake", readErr(syscall.ECONNRESET), PhaseHandshake, false, false, TCPReset},
		{"relay reset the carried stream", readErr(syscall.ECONNRESET), PhaseCarry, false, true, TCPReset},
		{"relay answered, nothing came back", io.EOF, PhaseCarry, false, true, Unknown},
		{"relay answered, round trip timed out", context.DeadlineExceeded, PhaseCarry, false, true, Unknown},
		// A lazy outbound reports its SYN timeout from the first read:
		// the error says "dial", and that wins over the caller's phase.
		{"lazy outbound, SYN unanswered", dialErr(timeoutErr{}), PhaseCarry, false, false, TCPConnectTimeout},
		// UDP: silence is one thing, whatever the phase.
		{"QUIC handshake heard nothing", errors.New("timeout: no recent network activity"), PhaseHandshake, true, true, UDPNoReply},
		{"QUIC handshake deadline", context.DeadlineExceeded, PhaseHandshake, true, true, UDPNoReply},
		{"QUIC idle timeout text", errors.New("quic: handshake_idle_timeout"), PhaseHandshake, true, true, UDPNoReply},
		// Failures that say what they are keep their category.
		{"credential refused", errors.New("authentication failed: bad password"), PhaseHandshake, true, true, AuthFailed},
		{"no network", dialErr(errors.New("connect: network is unreachable")), PhaseHandshake, false, true, NetworkOffline},
		// Cronet: the number is the phase.
		{"cronet connect timeout", errors.New("net_error -118"), PhaseCarry, false, true, TCPConnectTimeout},
		{"cronet reset", errors.New("net_error -101"), PhaseCarry, false, true, TCPReset},
		{"cronet reset before any answer", errors.New("open connection: net_error -101"), PhaseUnknown, false, true, TLSSNIOrCertBlockSuspected},
	}
	for _, c := range cases {
		got := ClassifyObservation(Observe(c.err, c.phase, c.udp, c.tls))
		if got != c.want {
			t.Errorf("%s (%q, phase=%s udp=%v tls=%v): got %s, want %s", c.name, c.err, c.phase, c.udp, c.tls, got, c.want)
		}
	}
}

// One silent UDP endpoint must never be read as a statement about the
// network: udp_unavailable and quic_unavailable disable whole families
// for hours (specs/failure-taxonomy-v1.md), and a null-routed address
// looks exactly the same from the route's seat.
func TestClassifyObservation_SilentUDPIsNeverANetworkClaim(t *testing.T) {
	for _, msg := range []string{"timeout: no recent network activity", "quic: handshake_idle_timeout", "udp probe failed", "context deadline exceeded"} {
		for _, ph := range []Phase{PhaseReach, PhaseHandshake} {
			got := ClassifyObservation(Observe(errors.New(msg), ph, true, true))
			if got == UDPUnavailable || got == QUICUnavailable || got == UDPCollapsed || got == QUICCollapsed {
				t.Errorf("%q at %s → %s: a network-wide category from one route's silence", msg, ph, got)
			}
		}
	}
}

// With no phase and no flags the observation classifier IS the locked
// string table: nothing is re-mapped silently.
func TestClassifyObservation_FallsBackToTheLockedTable(t *testing.T) {
	for _, msg := range []string{
		"dial tcp 203.0.113.4:443: i/o timeout",
		"read tcp 203.0.113.4:443: connection reset by peer",
		"tls: handshake failure",
		"tls: no application protocol",
		"quic: handshake_idle_timeout",
		"udp probe failed",
		"authentication failed: bad password",
		"network is unreachable",
		"unknown weird message that should not match anything",
		"cloudflare returned 522 for origin",
	} {
		o := Observation{Message: msg}
		if got, want := ClassifyObservation(o), Classify(msg); got != want {
			t.Errorf("ClassifyObservation(no context, %q) = %s; the string table says %s", msg, got, want)
		}
	}
}

func TestPathTooSlowIsNotACooldownClass(t *testing.T) {
	if IsCensorshipClass(PathTooSlow) {
		t.Fatal("path_too_slow is a degraded outcome of a route that works; it must never trigger a cooldown")
	}
	for _, c := range []Category{UDPNoReply, UDPAddressBlocked, UDPPortBlocked} {
		if !IsCensorshipClass(c) {
			t.Errorf("%s is something a censor does; it is a cooldown class", c)
		}
	}
}

func TestObserveReadsWrappedErrors(t *testing.T) {
	err := fmt.Errorf("engine: proof: %w", dialErr(timeoutErr{}))
	o := Observe(err, PhaseCarry, false, true)
	if o.Phase != PhaseReach || !o.Timeout {
		t.Fatalf("a wrapped dial timeout was not recognised: %+v", o)
	}
}

// A timeout on a path the engine saw moving is slowness, in every phase
// and for every kind of route — never a handshake failure, a dead
// address, or anything a recommender reads as a block (backlog TW-10).
func TestClassifyObservation_TimeoutWithProgressIsNeverABlock(t *testing.T) {
	for _, phase := range []Phase{PhaseReach, PhaseHandshake, PhaseCarry} {
		for _, udp := range []bool{false, true} {
			o := Observe(context.DeadlineExceeded, phase, udp, true)
			o.Progress = true
			if got := ClassifyObservation(o); got != PathTooSlow {
				t.Errorf("phase %s udp=%v: %s, want path_too_slow", phase, udp, got)
			}
		}
	}
	// Progress does not launder a failure that is not a timeout.
	o := Observe(errors.New("read: connection reset by peer"), PhaseHandshake, false, true)
	o.Progress = true
	if got := ClassifyObservation(o); got != TLSSNIOrCertBlockSuspected {
		t.Errorf("a reset with progress = %s, want tls_sni_or_cert_block_suspected", got)
	}
	// And a credential the relay refused stays that.
	o = Observe(errors.New("authentication failed"), PhaseCarry, false, true)
	o.Timeout, o.Progress = true, true
	if got := ClassifyObservation(o); got != AuthFailed {
		t.Errorf("auth failure with progress = %s", got)
	}
}

// relay_no_egress: the relay answered and nothing beyond it did. Not a
// censorship class — no cooldown follows from it (backlog TW-14).
func TestClassifyObservation_RelayNoEgress(t *testing.T) {
	for _, udp := range []bool{false, true} {
		o := Observe(context.DeadlineExceeded, PhaseCarry, udp, true)
		if got := ClassifyObservation(o); got != Unknown {
			t.Fatalf("udp=%v: a bare carry-phase timeout = %s, want unknown", udp, got)
		}
		o.RelayNoEgress = true
		if got := ClassifyObservation(o); got != RelayNoEgress {
			t.Fatalf("udp=%v: %s, want relay_no_egress", udp, got)
		}
	}
	if IsCensorshipClass(RelayNoEgress) {
		t.Fatal("relay_no_egress is the relay's problem, not the network's: it must never trigger a cooldown")
	}
}

// The timing hints: nothing is said unless both halves were measured
// and comparable.
func TestObservation_TimingHints(t *testing.T) {
	for _, c := range []struct {
		name                 string
		o                    Observation
		measured, fast, slow bool
	}{
		{"not measured", Observation{Reset: true}, false, false, false},
		{"dial only", Observation{Reset: true, DialMs: 40}, false, false, false},
		{"dial shorter than the connect", Observation{Reset: true, DialMs: 50, ConnectMs: 100}, false, false, false},
		{"a round trip too short to read", Observation{Reset: true, DialMs: 9, ConnectMs: 4}, false, false, false},
		{"injected: back well inside a round trip", Observation{Reset: true, DialMs: 120, ConnectMs: 100}, true, true, false},
		{"the relay's own reset", Observation{Reset: true, DialMs: 210, ConnectMs: 100}, true, false, true},
		{"the relay's own close", Observation{Closed: true, DialMs: 210, ConnectMs: 100}, true, false, true},
	} {
		_, measured := c.o.HelloToFailMs()
		if measured != c.measured || c.o.FastReset() != c.fast || c.o.ServerStop() != c.slow {
			t.Errorf("%s: measured=%v fast=%v server=%v", c.name, measured, c.o.FastReset(), c.o.ServerStop())
		}
	}
}
