package fieldprobe

import (
	"context"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"
)

// The real probe (runTCP) driven into every path a loopback can make.
// Paths a loopback cannot make (an injected RST arrives before the
// server's would; a hello the kernel never ACKs) are covered from
// fixtures in classify_test.go, and the hello-ACK one again below
// through an injected ACK reader.

func probeAt(t *testing.T, s *server, sp tcpSpec, ack func(net.Conn, time.Duration) func() (bool, bool)) (tcpObs, string) {
	t.Helper()
	n := newFakeNet()
	to := netip.MustParseAddrPort("203.0.113.10:443")
	if s != nil {
		n.to[to] = s.addr()
	}
	sp.To = to
	o := runTCP(context.Background(), n, sp, quickTimeouts(), ack)
	// As if a control on the same network carried: a stall can be a cap.
	carried := true
	res, _ := classifyTCP(o, &carried)
	return o, res
}

func TestRunTCP_Loopback(t *testing.T) {
	big := tlsHTTP(t, func(_, _, path string) reply {
		switch path {
		case "/big":
			return reply{status: 200, body: 64 * 1024}
		case "/stall":
			return reply{status: 200, body: 6000, stall: true}
		}
		return reply{status: 204}
	})
	req := func(path string, carry bool) tcpSpec {
		return tcpSpec{SNI: "www.example.test", Request: true, Path: path, ReadLimit: 64 * 1024, CarryExpected: carry}
	}
	cases := []struct {
		name string
		srv  *server
		sp   tcpSpec
		want string
	}{
		{"handshake and a small answer", big, req("/", false), "ok"},
		{"carried 64 KB", big, req("/big", true), "ok_carried"},
		{"stalled after 6 KB", big, req("/stall", true), "flow_capped_suspected"},
		{"reset after the hello", resetServer(t), req("/", false), "reset"},
		{"tls alert", alertServer(t), req("/", false), "tls_alert"},
		{"refused", nil, req("/", false), "refused"},
		{"plain http", plainHTTP(t), tcpSpec{Request: true, Method: "HEAD", Host: "x", Path: "/"}, "ok"},
	}
	for _, c := range cases {
		o, got := probeAt(t, c.srv, c.sp, nil)
		if got != c.want {
			t.Errorf("%s: got %s (obs %+v)", c.name, got, o)
		}
	}
	// Silent after the hello: on Linux the kernel ACKs it, so the probe
	// knows the hello arrived and nothing answered.
	o, got := probeAt(t, silentServer(t), req("/", false), nil)
	want := "silent_no_reply"
	if runtime.GOOS != "linux" {
		want = "timeout"
	}
	if got != want {
		t.Errorf("silent server: got %s (obs %+v)", got, o)
	}
	// Silent and the hello never ACKed (a forward drop): the ACK reader
	// says so.
	never := func(net.Conn, time.Duration) func() (bool, bool) { return func() (bool, bool) { return false, true } }
	if _, got := probeAt(t, silentServer(t), req("/", false), never); got != "silent_drop_forward" {
		t.Errorf("forward drop: got %s", got)
	}
}

func TestRunTCP_ConnectTimeout(t *testing.T) {
	n := newFakeNet()
	to := netip.MustParseAddrPort("203.0.113.11:443")
	n.stall[to] = true
	o := runTCP(context.Background(), n, tcpSpec{To: to, SNI: "x.test"}, quickTimeouts(), nil)
	if res, phase := classifyTCP(o, nil); res != "timeout" || phase != "reach" {
		t.Fatalf("got %s/%s", res, phase)
	}
}
