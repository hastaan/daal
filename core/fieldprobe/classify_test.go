package fieldprobe

import (
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"daal/core/diagnostics"

	"github.com/miekg/dns"
)

func bp(b bool) *bool { return &b }

// Every row of the §1 classification table, from fixtures.
func TestClassifyTCP_EveryPath(t *testing.T) {
	rtt := 120 * time.Millisecond
	cases := []struct {
		name    string
		o       tcpObs
		control *bool
		want    string
		phase   string
	}{
		{"refused", tcpObs{ConnectKind: "refused"}, nil, "refused", "reach"},
		{"connect timeout", tcpObs{ConnectKind: "timeout"}, nil, "timeout", "reach"},
		{"unreachable", tcpObs{ConnectKind: "unreachable"}, nil, "unreachable", "reach"},
		{"protect refused", tcpObs{ConnectKind: "local_error"}, nil, "local_error", "reach"},
		{"lockdown", tcpObs{ConnectKind: "local_blocked"}, nil, "local_error", "reach"},
		{"other dial error", tcpObs{ConnectKind: "other"}, nil, "local_error", "reach"},
		{"handshake ok", tcpObs{ConnectRTT: rtt, HandshakeOK: true, Rx: 5000, EndKind: "fin", HTTPStatus: 204}, nil, "ok", "carry"},
		{"carried", tcpObs{ConnectRTT: rtt, HandshakeOK: true, Rx: 40000, EndKind: "limit"}, nil, "ok_carried", "carry"},
		{"injected reset", tcpObs{ConnectRTT: rtt, HelloWritten: true, FirstEvent: "rst", FirstAfter: 30 * time.Millisecond}, nil, "reset_injected_likely", "handshake"},
		{"reset after a round trip", tcpObs{ConnectRTT: rtt, HelloWritten: true, FirstEvent: "rst", FirstAfter: 130 * time.Millisecond}, nil, "reset", "handshake"},
		{"reset, rtt too short to judge", tcpObs{ConnectRTT: 10 * time.Millisecond, HelloWritten: true, FirstEvent: "rst", FirstAfter: 1 * time.Millisecond}, nil, "reset", "handshake"},
		{"hello never acked", tcpObs{ConnectRTT: rtt, HelloWritten: true, FirstEvent: "timeout", AckKnown: true, HelloAcked: false}, nil, "silent_drop_forward", "handshake"},
		{"acked, nothing back", tcpObs{ConnectRTT: rtt, HelloWritten: true, FirstEvent: "timeout", AckKnown: true, HelloAcked: true}, nil, "silent_no_reply", "handshake"},
		{"silent, ack unknown", tcpObs{ConnectRTT: rtt, HelloWritten: true, FirstEvent: "timeout"}, nil, "timeout", "handshake"},
		{"tls alert", tcpObs{ConnectRTT: rtt, HelloWritten: true, FirstEvent: "bytes", TLSAlert: true}, nil, "tls_alert", "handshake"},
		{"closed at hello", tcpObs{ConnectRTT: rtt, HelloWritten: true, FirstEvent: "fin"}, nil, "closed", "handshake"},
		{"stall, no control", tcpObs{ConnectRTT: rtt, HandshakeOK: true, Rx: 9000, EndKind: "timeout", CarryExpected: true}, nil, "timeout", "carry"},
		{"reset in carry, no control", tcpObs{ConnectRTT: rtt, HandshakeOK: true, Rx: 9000, EndKind: "rst", CarryExpected: true}, nil, "reset", "carry"},
		// The cap biting during the server's flight (H3).
		{"flight then stall, control carried", tcpObs{ConnectRTT: rtt, HelloWritten: true, FirstEvent: "bytes", HandshakeEnd: "timeout", Rx: 6000}, bp(true), "flow_capped_suspected", "handshake"},
		{"flight then reset, control carried", tcpObs{ConnectRTT: rtt, HelloWritten: true, FirstEvent: "bytes", HandshakeEnd: "rst", Rx: 6000}, bp(true), "flow_capped_suspected", "handshake"},
		{"flight then stall, no control", tcpObs{ConnectRTT: rtt, HelloWritten: true, FirstEvent: "bytes", HandshakeEnd: "timeout", Rx: 6000}, nil, "timeout", "handshake"},
		{"flight then reset, no control", tcpObs{ConnectRTT: rtt, HelloWritten: true, FirstEvent: "bytes", HandshakeEnd: "rst", Rx: 6000}, bp(false), "reset", "handshake"},
		{"long flight then stall", tcpObs{ConnectRTT: rtt, HelloWritten: true, FirstEvent: "bytes", HandshakeEnd: "timeout", Rx: 20000}, bp(true), "timeout", "handshake"},
		{"flight then close", tcpObs{ConnectRTT: rtt, HelloWritten: true, FirstEvent: "bytes", HandshakeEnd: "fin", Rx: 3000}, bp(true), "closed", "handshake"},
		{"not tls", tcpObs{ConnectRTT: rtt, HelloWritten: true, FirstEvent: "bytes", HandshakeEnd: "other", Rx: 300}, bp(true), "closed", "handshake"},
		{"wrong certificate", tcpObs{ConnectRTT: rtt, HandshakeOK: true, CertChecked: true, Rx: 5000}, bp(true), "cert_invalid", "handshake"},
		{"right certificate", tcpObs{ConnectRTT: rtt, HandshakeOK: true, CertChecked: true, CertValid: true, Rx: 5000, EndKind: "fin", HTTPStatus: 204}, nil, "ok", "carry"},
		{"capped, control carried", tcpObs{ConnectRTT: rtt, HandshakeOK: true, Rx: 9000, EndKind: "rst", CarryExpected: true}, bp(true), "flow_capped_suspected", "carry"},
		{"stall, control stalled too", tcpObs{ConnectRTT: rtt, HandshakeOK: true, Rx: 9000, EndKind: "timeout", CarryExpected: true}, bp(false), "timeout", "carry"},
		{"short page, clean close", tcpObs{ConnectRTT: rtt, HandshakeOK: true, Rx: 9000, EndKind: "fin", CarryExpected: true, HTTPStatus: 200}, nil, "ok", "carry"},
	}
	for _, c := range cases {
		got, phase := classifyTCP(c.o, c.control)
		if got != c.want || phase != c.phase {
			t.Errorf("%s: got %s/%s, want %s/%s", c.name, got, phase, c.want, c.phase)
		}
	}
}

func TestClassifyDNS_EveryPath(t *testing.T) {
	cal := netip.MustParsePrefix("10.10.34.0/24")
	a := func(s ...string) DNSAnswer {
		out := DNSAnswer{Typed: true}
		for _, x := range s {
			out.Addrs = append(out.Addrs, netip.MustParseAddr(x))
		}
		return out
	}
	timeout := errors.New("i/o timeout")
	te := &timeoutErr{}
	cases := []struct {
		name    string
		ans     DNSAnswer
		err     error
		ex      dnsExpect
		aAnswer bool
		want    string
	}{
		{"public answer", a("142.250.1.1"), nil, dnsExpect{qtype: dns.TypeA, calibration: cal}, false, "ok"},
		{"sinkhole", a("10.10.34.35"), nil, dnsExpect{qtype: dns.TypeA, calibration: cal}, false, "bogon"},
		{"private", a("192.168.1.9"), nil, dnsExpect{qtype: dns.TypeA, calibration: cal}, false, "bogon"},
		{"loopback v6", a("::1"), nil, dnsExpect{qtype: dns.TypeAAAA, calibration: cal}, false, "bogon"},
		{"nxdomain", DNSAnswer{Rcode: dns.RcodeNameError}, nil, dnsExpect{qtype: dns.TypeA}, false, "nxdomain"},
		{"servfail", DNSAnswer{Rcode: dns.RcodeServerFailure}, nil, dnsExpect{qtype: dns.TypeA}, false, "servfail"},
		{"timeout", DNSAnswer{}, te, dnsExpect{qtype: dns.TypeA}, false, "dns_timeout"},
		{"other type dropped", DNSAnswer{}, te, dnsExpect{qtype: dns.TypeTXT}, true, "type_dropped"},
		{"other error", DNSAnswer{}, timeout, dnsExpect{qtype: dns.TypeA}, false, "dns_timeout"},
		{"protect refused", DNSAnswer{}, fmt.Errorf("dial: %w", ErrLocal), dnsExpect{qtype: dns.TypeA}, false, "local_error"},
		{"known txt intact", DNSAnswer{Typed: true, TXT: []string{"v=spf1 include:x ~all"}}, nil, dnsExpect{qtype: dns.TypeTXT, expect: "v=spf1"}, true, "ok"},
		{"known txt altered", DNSAnswer{Typed: true, TXT: []string{"hello"}}, nil, dnsExpect{qtype: dns.TypeTXT, expect: "v=spf1"}, true, "answer_altered"},
		{"known cname empty", DNSAnswer{}, nil, dnsExpect{qtype: dns.TypeCNAME, expect: "github.com."}, true, "type_dropped"},
	}
	for _, c := range cases {
		if got := classifyDNS(c.ans, c.err, c.ex, c.aAnswer); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestClassifyRelay(t *testing.T) {
	cases := []struct {
		name string
		r    RelayOutcome
		want string
	}{
		{"unsupported", RelayOutcome{Unsupported: true}, "skipped"},
		{"cancelled", RelayOutcome{Cancelled: true}, "skipped"},
		{"ok", RelayOutcome{OK: true}, "ok"},
		{"reset at hello", RelayOutcome{Obs: diagnostics.Observation{Phase: diagnostics.PhaseHandshake, TLS: true, Reset: true}}, "reset"},
		{"syn unanswered", RelayOutcome{Obs: diagnostics.Observation{Phase: diagnostics.PhaseReach, Timeout: true}}, "timeout"},
		{"refused", RelayOutcome{Obs: diagnostics.Observation{Phase: diagnostics.PhaseReach, Refused: true}}, "refused"},
		{"closed at hello", RelayOutcome{Obs: diagnostics.Observation{Phase: diagnostics.PhaseHandshake, TLS: true, Closed: true}}, "closed"},
		{"no egress", RelayOutcome{Obs: diagnostics.Observation{Phase: diagnostics.PhaseCarry, RelayNoEgress: true}}, "ok"},
	}
	for _, c := range cases {
		if got, _ := classifyRelay(c.r); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}
