package fieldprobe

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"daal/bundle-go/fieldreport"

	"github.com/miekg/dns"
)

// Regression tests for the review of network test v2: one per finding
// whose fix changes what the engine does.

// ---- H1: a refused protect() is local_error, never a timeout -----------

func TestH1_ProtectRefusalIsLocalNotTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	refuse := SysNet{Protect: func(int) error { return errors.New("host protect refused") }}
	to := netip.MustParseAddrPort(ln.Addr().String())
	o := runTCP(context.Background(), refuse, tcpSpec{To: to, SNI: "www.example.test"}, quickTimeouts(), nil)
	if res, phase := classifyTCP(o, nil); res != "local_error" || phase != "reach" {
		t.Fatalf("TCP: got %s/%s (connect %q)", res, phase, o.ConnectKind)
	}
	_, err = refuse.DialUDP(context.Background(), netip.MustParseAddrPort("127.0.0.1:53"))
	if got := classifyDNS(DNSAnswer{}, err, dnsExpect{qtype: dns.TypeA}, false); got != "local_error" {
		t.Fatalf("DNS: got %s", got)
	}

	// A whole run on a device that refuses every socket: it stops before
	// its first probe and does not read as a blackout.
	w := newWorld(t)
	env := w.env()
	env.Net = refuse
	sent := 0
	env.OnFirstSend = func() { sent++ }
	res := Run(context.Background(), env)
	if res.AbortReason != "error" || len(res.Probes) != 0 || res.Blackout || sent != 0 {
		t.Fatalf("abort=%q probes=%d blackout=%v sent=%d", res.AbortReason, len(res.Probes), res.Blackout, sent)
	}
}

// localTCPNet lets DNS through (the world's fake) and refuses every TCP
// socket on the device.
type localTCPNet struct{ *fakeNet }

func (localTCPNet) DialTCP(context.Context, netip.AddrPort) (net.Conn, error) {
	return nil, &net.OpError{Op: "dial", Net: "tcp", Err: fmt.Errorf("%w: protect", ErrLocal)}
}

func TestH1_LocalRefusalsAreNotFindings(t *testing.T) {
	w := newWorld(t)
	env := w.env()
	env.Net = localTCPNet{w.net}
	res := Run(context.Background(), env)
	if got := findResult(res, "B1", ""); got != "local_error" {
		t.Fatalf("B1 = %s", got)
	}
	if res.Blackout {
		t.Fatal("local refusals read as a blackout")
	}
	for _, f := range Failures(res) {
		if f.Category == "tcp_connect_timeout" || f.Category == "tls_handshake_failed" {
			t.Fatalf("a local refusal tallied as %s", f.Category)
		}
	}
	for _, f := range Findings(res) {
		if f.Question == "google_front_passes" || f.Question == "github_feed_fetchable" {
			t.Fatalf("a finding from local refusals: %+v", f)
		}
	}
}

// ---- H2: a public answer outside the name's blocks is never dialled ----

func TestH2_WrongPublicAnswerIsNotDialled(t *testing.T) {
	domestic := netip.MustParseAddr("5.200.200.200")
	w := newWorld(t)
	w.dns.answers[dnsKey(linkDNS, w.t.Google, dns.TypeA)] = DNSAnswer{Typed: true, Addrs: []netip.Addr{domestic}}
	res := Run(context.Background(), w.env())
	if got := findResult(res, "A1", "a"); got != "dns_wrong_public" {
		t.Fatalf("A1 = %s", got)
	}
	if got := findResult(res, "A6", "fill_google"); got != "ok" {
		t.Fatalf("A6 fill_google = %s", got)
	}
	for _, p := range res.Probes {
		if p.ID == "B1" && (p.Variant != "addr_public" || p.Result != "ok") {
			t.Fatalf("B1 %s/%s", p.Variant, p.Result)
		}
	}
	for _, d := range w.net.dials {
		if d.Addr() == domestic {
			t.Fatal("the test dialled the address outside Google's blocks")
		}
	}
	if !strings.Contains(strings.Join(Summary(res, Findings(res)), ","), SumDNSWrongAddresses) {
		t.Fatal("the summary does not say DNS gave wrong addresses")
	}

	// The public resolver says the same, on a network seen writing
	// answers on the path (the world's 1.1.1.1 calibration answer is a
	// sinkhole): the two agree, but agreement is no evidence here, so
	// Stage B has no Google address and skips it.
	w = newWorld(t)
	w.dns.answers[dnsKey(netip.AddrPort{}, w.t.Google, dns.TypeA)] = DNSAnswer{Typed: true, Addrs: []netip.Addr{domestic}}
	res = Run(context.Background(), w.env())
	if findResult(res, "A6", "calibration") != "bogon" {
		t.Fatalf("calibration = %s", findResult(res, "A6", "calibration"))
	}
	if findResult(res, "A1", "a") != "dns_unlisted" || findResult(res, "A6", "fill_google") != "dns_unlisted" || findResult(res, "B1", "") != "skipped" {
		t.Fatalf("A1=%s A6 fill_google=%s B1=%s", findResult(res, "A1", "a"), findResult(res, "A6", "fill_google"), findResult(res, "B1", ""))
	}
	for _, d := range w.net.dials {
		if d.Addr() == domestic {
			t.Fatal("dialled the injected address")
		}
	}
}

// swedishWorld is a plain network: the link resolver and 1.1.1.1 give
// real answers, nothing is written on the path, and GitHub answers from
// an address the list does not hold (it moved into new ranges).
func swedishWorld(t *testing.T, moved netip.Addr) *world {
	w := newWorld(t)
	A := func(a netip.Addr) DNSAnswer { return DNSAnswer{Typed: true, Addrs: []netip.Addr{a}} }
	w.dns.answers[dnsKey(linkDNS, w.t.WhiteName, dns.TypeA)] = A(addrWhite)
	w.dns.answers[dnsKey(netip.AddrPort{}, w.t.CFDNSName, dns.TypeA)] = A(addrCF)
	w.dns.answers[dnsKey(netip.AddrPort{}, w.t.GitHub, dns.TypeA)] = A(moved)
	w.net.byAddr[moved] = w.net.byAddr[addrGitHub]
	return w
}

// roleResult is the result of the first record of id for role/variant.
func roleResult(res *Result, id, role, variant string) string {
	for _, p := range res.Probes {
		if p.ID == id && p.TargetRole == role && p.Variant == variant {
			return p.Result
		}
	}
	return ""
}

func summaryHas(res *Result, key string) bool {
	for _, k := range Summary(res, Findings(res)) {
		if k == key {
			return true
		}
	}
	return false
}

func TestH2_UnlistedButAgreedIsUsed(t *testing.T) {
	moved := netip.MustParseAddr("198.51.100.7")
	w := swedishWorld(t, moved)
	if w.t.Allowed("github", moved) {
		t.Fatal("the test address is inside GitHub's blocks")
	}
	res := Run(context.Background(), w.env())
	if got := roleResult(res, "A1", "github", "a"); got != "dns_unlisted" {
		t.Fatalf("A1 = %s", got)
	}
	if got := findResult(res, "A6", "fill_github"); got != "dns_unlisted" {
		t.Fatalf("A6 fill_github = %s", got)
	}
	var b4 *ProbeRecord
	for i := range res.Probes {
		if res.Probes[i].ID == "B4" {
			b4 = &res.Probes[i]
		}
	}
	if b4 == nil || b4.Variant != "addr_agreed" || !okish(b4.Result) {
		t.Fatalf("B4 %+v", b4)
	}
	dialled := false
	for _, d := range w.net.dials {
		dialled = dialled || d.Addr() == moved
	}
	if !dialled {
		t.Fatal("the agreed address was not used")
	}
	for _, f := range Failures(res) {
		if f.Category == "dns_poisoned" {
			t.Fatal("an unlisted answer tallied as dns_poisoned")
		}
	}
	if summaryHas(res, SumDNSWrongAddresses) {
		t.Fatal("the summary says DNS gave wrong addresses")
	}
	if !summaryHas(res, SumGoogleGithubOpen) {
		t.Fatalf("summary %v", Summary(res, Findings(res)))
	}
	if _, err := BuildReport(res, Meta{Targets: w.t, Now: time.Now()}); err != nil {
		t.Fatalf("report: %v", err)
	}

	// The same address, but the certificate is not GitHub's: both
	// resolvers named a host that is not the name's. That is evidence.
	w = swedishWorld(t, moved)
	env := w.env()
	env.Roots = x509.NewCertPool()
	res = Run(context.Background(), env)
	if findResult(res, "B4", "") != "cert_invalid" || !summaryHas(res, SumDNSWrongAddresses) {
		t.Fatalf("B4=%s summary %v", findResult(res, "B4", ""), Summary(res, Findings(res)))
	}
}

func TestH2_UnlistedDisagreementIsWrong(t *testing.T) {
	domestic := netip.MustParseAddr("5.200.200.200")
	for _, pub := range []netip.Addr{netip.MustParseAddr("198.51.100.7"), addrGitHub} {
		w := swedishWorld(t, pub)
		w.dns.answers[dnsKey(linkDNS, w.t.GitHub, dns.TypeA)] = DNSAnswer{Typed: true, Addrs: []netip.Addr{domestic}}
		res := Run(context.Background(), w.env())
		if got := roleResult(res, "A1", "github", "a"); got != "dns_wrong_public" {
			t.Fatalf("1.1.1.1 says %s: A1 = %s", pub, got)
		}
		for _, d := range w.net.dials {
			if d.Addr() == domestic {
				t.Fatal("dialled the link resolver's address")
			}
		}
		if !summaryHas(res, SumDNSWrongAddresses) {
			t.Fatal("the summary does not say DNS gave wrong addresses")
		}
		if pub == addrGitHub {
			// 1.1.1.1's answer is inside the blocks: B4 uses it.
			if findResult(res, "A6", "fill_github") != "ok" || findResult(res, "B4", "") == "skipped" {
				t.Fatalf("fill=%s B4=%s", findResult(res, "A6", "fill_github"), findResult(res, "B4", ""))
			}
			continue
		}
		// Two unlisted answers that disagree: neither is dialled, and
		// GitHub is not "closed" — it was not checked.
		if findResult(res, "A6", "fill_github") != "dns_unlisted" || findResult(res, "B4", "") != "skipped" {
			t.Fatalf("fill=%s B4=%s", findResult(res, "A6", "fill_github"), findResult(res, "B4", ""))
		}
		for _, d := range w.net.dials {
			if d.Addr() == pub {
				t.Fatal("dialled 1.1.1.1's unconfirmed address")
			}
		}
		if summaryHas(res, SumSomeForeignOpen) || !summaryHas(res, SumGoogleOpenGithubUnchecked) {
			t.Fatalf("summary %v", Summary(res, Findings(res)))
		}
	}
}

func TestH2_UnlistedUnconfirmedIsUnknown(t *testing.T) {
	moved := netip.MustParseAddr("198.51.100.7")
	w := swedishWorld(t, moved)
	w.dns.deadAt = map[netip.Addr]bool{netip.MustParseAddr("1.1.1.1"): true}
	res := Run(context.Background(), w.env())
	if roleResult(res, "A1", "github", "a") != "dns_unlisted" || findResult(res, "A6", "fill_github") != "dns_timeout" ||
		findResult(res, "B4", "") != "skipped" {
		t.Fatalf("A1=%s fill=%s B4=%s", roleResult(res, "A1", "github", "a"), findResult(res, "A6", "fill_github"), findResult(res, "B4", ""))
	}
	for _, d := range w.net.dials {
		if d.Addr() == moved {
			t.Fatal("dialled an address no second resolver confirmed")
		}
	}
	if summaryHas(res, SumDNSWrongAddresses) || summaryHas(res, SumSomeForeignOpen) || !summaryHas(res, SumGoogleOpenGithubUnchecked) {
		t.Fatalf("summary %v", Summary(res, Findings(res)))
	}
	for _, f := range Findings(res) {
		if f.Question == "github_feed_fetchable" {
			t.Fatalf("a GitHub finding from a skipped probe: %+v", f)
		}
	}
}

func TestH2_WrongCertificateEndsTheProbe(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	srv := tlsHTTP(t, func(_, _, path string) reply {
		mu.Lock()
		paths = append(paths, path)
		mu.Unlock()
		return reply{status: 204}
	})
	n := newFakeNet()
	to := netip.MustParseAddrPort("203.0.113.10:443")
	n.to[to] = srv.addr()
	sp := tcpSpec{To: to, SNI: "www.example.test", Verify: true, Roots: x509.NewCertPool(), Request: true, Path: "/x"}
	o := runTCP(context.Background(), n, sp, quickTimeouts(), nil)
	if res, phase := classifyTCP(o, nil); res != "cert_invalid" || phase != "handshake" {
		t.Fatalf("got %s/%s", res, phase)
	}
	if s := tcpSignals(o); s.CertValid == nil || *s.CertValid {
		t.Fatal("cert_valid not reported false")
	}
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	if len(paths) != 0 {
		t.Fatalf("a request went to a host that is not the name's: %v", paths)
	}
	mu.Unlock()
	sp.Roots = testRoots(t)
	o = runTCP(context.Background(), n, sp, quickTimeouts(), nil)
	if res, _ := classifyTCP(o, nil); res != "ok" || !o.CertValid {
		t.Fatalf("with the right root: %s", res)
	}
}

// ---- H3: part of the server's flight, then a stall or a reset ---------

func TestH3_CapDuringHandshake(t *testing.T) {
	for _, reset := range []bool{false, true} {
		srv := flightThen(t, 3000, reset)
		n := newFakeNet()
		to := netip.MustParseAddrPort("203.0.113.12:443")
		n.to[to] = srv.addr()
		o := runTCP(context.Background(), n, tcpSpec{To: to, SNI: "www.example.test"}, quickTimeouts(), nil)
		wantEnd := "timeout"
		if reset {
			wantEnd = "rst"
		}
		if o.FirstEvent != "bytes" || o.HandshakeEnd != wantEnd || o.TLSAlert {
			t.Fatalf("reset=%v: first=%s end=%s alert=%v", reset, o.FirstEvent, o.HandshakeEnd, o.TLSAlert)
		}
		if res, phase := classifyTCP(o, bp(true)); res != "flow_capped_suspected" || phase != "handshake" {
			t.Fatalf("reset=%v with a control: %s/%s", reset, res, phase)
		}
		if res, _ := classifyTCP(o, nil); res == "flow_capped_suspected" || res == "tls_alert" {
			t.Fatalf("reset=%v without a control: %s", reset, res)
		}
	}
	// A real alert record stays tls_alert.
	o, _ := probeAt(t, alertServer(t), tcpSpec{SNI: "www.example.test"}, nil)
	if o.HandshakeEnd != "alert" {
		t.Fatalf("alert: end=%s", o.HandshakeEnd)
	}
}

// ---- H4: blackout while domestic resolvers answer; the time reserve ----

func TestH4_BlackoutWithDomesticDNSAnswering(t *testing.T) {
	w := newWorld(t)
	w.dns.deadAt = map[netip.Addr]bool{w.t.resolver.Addr(): true}
	for a := range w.net.byAddr {
		w.net.stall[netip.AddrPortFrom(a, 443)] = true
	}
	res := Run(context.Background(), w.env())
	if !res.Blackout || !res.ShortCircuit {
		t.Fatalf("no blackout: B1=%s", findResult(res, "B1", ""))
	}
	if got := strings.Join(ids(res), " "); got != "A1 A2 A3 A4 A5 A6 B1 C2" {
		t.Fatalf("plan %s", got)
	}
}

func TestH4_ReserveKeepsTimeForTheRelay(t *testing.T) {
	w := newWorld(t)
	env := w.env()
	env.Reserve = time.Nanosecond
	res := Run(context.Background(), env)
	if !res.TimeReserve || !res.ShortCircuit || !res.Complete {
		t.Fatalf("reserve=%v short=%v complete=%v", res.TimeReserve, res.ShortCircuit, res.Complete)
	}
	got := strings.Join(ids(res), " ")
	if strings.Contains(got, "B") || !strings.Contains(got, "C2") {
		t.Fatalf("plan %s", got)
	}
	if !strings.Contains(strings.Join(Summary(res, Findings(res)), ","), SumIncomplete) {
		t.Fatal("a run that dropped Stage B does not say it is incomplete")
	}
}

// ---- M1: the path changing under the run -------------------------------

type laConn struct {
	net.Conn
	la net.Addr
}

func (c laConn) LocalAddr() net.Addr { return c.la }

// shiftNet gives every connection after the first `after` a different
// local address: another network, or another app's VPN carrying them.
type shiftNet struct {
	*fakeNet
	mu    sync.Mutex
	n     int
	after int
}

func (s *shiftNet) DialTCP(ctx context.Context, to netip.AddrPort) (net.Conn, error) {
	c, err := s.fakeNet.DialTCP(ctx, to)
	if err != nil {
		return c, err
	}
	s.mu.Lock()
	s.n++
	moved := s.n > s.after
	s.mu.Unlock()
	if moved {
		return laConn{c, &net.TCPAddr{IP: net.ParseIP("10.111.0.2"), Port: 40000}}, nil
	}
	return laConn{c, &net.TCPAddr{IP: net.ParseIP("192.168.1.20"), Port: 40000}}, nil
}

func TestM1_PathChangeStopsTheRun(t *testing.T) {
	w := newWorld(t)
	env := w.env()
	env.Net = &shiftNet{fakeNet: w.net, after: 2}
	res := Run(context.Background(), env)
	if res.AbortReason != "network_changed" || res.Complete {
		t.Fatalf("abort=%q", res.AbortReason)
	}
	if findResult(res, "C2", "") != "" {
		t.Fatal("the run went on to the relay on another path")
	}
}

// ---- M5: the kernel's RTT ----------------------------------------------

func TestM5_KernelRTT(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("TCP_INFO is Linux/Android only")
	}
	o, _ := probeAt(t, tlsHTTP(t, func(string, string, string) reply { return reply{status: 204} }),
		tcpSpec{SNI: "www.example.test", Request: true, Path: "/"}, nil)
	if !o.RTTKernel || o.ConnectRTT <= 0 {
		t.Fatalf("kernel rtt: %v %v", o.RTTKernel, o.ConnectRTT)
	}
}

// ---- M6: no control, no cap --------------------------------------------

func TestM6_CapNeedsAControlThatCarried(t *testing.T) {
	stall := tcpObs{ConnectRTT: 50 * time.Millisecond, HandshakeOK: true, Rx: 9000, EndKind: "timeout", CarryExpected: true}
	big := tcpObs{ConnectRTT: 50 * time.Millisecond, HandshakeOK: true, Rx: 40000, EndKind: "limit"}
	rec := func(id string, o tcpObs) ProbeRecord {
		o2 := o
		return ProbeRecord{Probe: fieldreport.Probe{ID: id}, tcp: &o2}
	}
	r := &runner{res: &Result{Probes: []ProbeRecord{rec("B6", stall)}}}
	r.reclassify()
	if got := r.res.Probes[0].Result; got != "timeout" {
		t.Fatalf("alone: %s", got)
	}
	r = &runner{res: &Result{Probes: []ProbeRecord{rec("B4", big), rec("B6", stall)}}}
	r.reclassify()
	if got := r.res.Probes[1].Result; got != "flow_capped_suspected" {
		t.Fatalf("beside B4 that carried: %s", got)
	}
	// A relay name is held to the relay's own address, not to Stage B.
	r = &runner{res: &Result{Probes: []ProbeRecord{rec("B4", big), rec("C5", stall)}}}
	r.reclassify()
	if got := r.res.Probes[1].Result; got != "timeout" {
		t.Fatalf("C5 against a B control: %s", got)
	}
}

// ---- M7: the cover origin's alert is the path passing -----------------

func TestM7_RelayNameAlertMeansPassed(t *testing.T) {
	mk := func(c4, c5 string) *Result {
		return &Result{Probes: []ProbeRecord{
			{Probe: fieldreport.Probe{ID: "C4", Result: c4, Phase: "handshake"}},
			{Probe: fieldreport.Probe{ID: "C5", Result: c5, Phase: "handshake"}},
		}}
	}
	for _, c := range []struct{ c4, c5, want string }{
		{"tls_alert", "reset", "yes"},
		{"ok", "tls_alert", "no"},
		{"tls_alert", "tls_alert", "no"},
		{"reset", "silent_drop_forward", "no"},
	} {
		if got := answerOf(Findings(mk(c.c4, c.c5)), "white_name_helps_on_relay_ip"); got != c.want {
			t.Errorf("C4=%s C5=%s: %s, want %s", c.c4, c.c5, got, c.want)
		}
	}
}

// ---- M8: lockdown is seen before anything is sent ---------------------

type lockdownNet struct{ *fakeNet }

func (lockdownNet) DialUDP(context.Context, netip.AddrPort) (net.Conn, error) {
	return nil, &net.OpError{Op: "dial", Net: "udp", Err: os.NewSyscallError("connect", syscall.EPERM)}
}

func TestM8_LockdownPreflight(t *testing.T) {
	w := newWorld(t)
	env := w.env()
	env.Net = lockdownNet{w.net}
	charged := false
	env.OnFirstSend = func() { charged = true }
	res := Run(context.Background(), env)
	if res.AbortReason != "local_blocked" || !res.LocalBlocked || len(res.Probes) != 0 || charged || len(w.dns.asked) != 0 {
		t.Fatalf("abort=%q probes=%d charged=%v asked=%d", res.AbortReason, len(res.Probes), charged, len(w.dns.asked))
	}
	sum := Summary(res, Findings(res))
	if len(sum) != 2 || sum[0] != SumLocalBlocked {
		t.Fatalf("summary %v", sum)
	}
	if _, err := BuildReport(res, Meta{Targets: w.t, Now: time.Now()}); err != nil {
		t.Fatalf("a lockdown result does not make a report: %v", err)
	}
}

// ---- M9: Chrome's own hello, answered h2 ------------------------------

func TestM9_ChromeHelloOverH2(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		_, _ = rw.Write(make([]byte, 48*1024))
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	n := newFakeNet()
	to := netip.MustParseAddrPort("203.0.113.13:443")
	n.to[to] = strings.TrimPrefix(srv.URL, "https://")
	o := runTCP(context.Background(), n, tcpSpec{To: to, SNI: "example.com", FP: FPChrome, Request: true, Path: "/",
		ReadLimit: 64 * 1024, CarryExpected: true}, quickTimeouts(), nil)
	if o.ALPN != "h2" || o.HTTPStatus != 200 {
		t.Fatalf("alpn=%q status=%d end=%s", o.ALPN, o.HTTPStatus, o.EndKind)
	}
	if res, _ := classifyTCP(o, nil); res != "ok_carried" {
		t.Fatalf("got %s (rx %d)", res, o.Rx)
	}
	if s := tcpSignals(o); s.HelloFP != FPChrome {
		t.Fatalf("hello_fp %q", s.HelloFP)
	}
}

// ---- L3, L4, L5, L6 ------------------------------------------------------

func TestL3_PrivateDNSStrictSendsNoLinkQuestion(t *testing.T) {
	w := newWorld(t)
	env := w.env()
	env.PrivateDNSStrict = true
	res := Run(context.Background(), env)
	for _, a := range w.dns.askedAt {
		if a != w.t.resolver.Addr() {
			t.Fatal("a question went to the link resolver under strict Private DNS")
		}
	}
	for _, p := range res.Probes {
		if p.ID[0] == 'A' && p.ID != "A6" && p.Result != "skipped" {
			t.Fatalf("%s %s", p.ID, p.Result)
		}
	}
	if findResult(res, "B1", "") != "ok" {
		t.Fatalf("B1 = %s", findResult(res, "B1", ""))
	}
}

func TestL4_ResolverPickKeepsZone(t *testing.T) {
	rs := ParseResolvers([]string{"fe80::1%wlan0", "192.168.1.1"})
	if len(rs) != 2 || rs[0].Addr().Zone() != "wlan0" {
		t.Fatalf("parsed %v", rs)
	}
	if s, _ := PickResolver(rs); s.Addr().String() != "192.168.1.1" {
		t.Fatalf("picked %v", s)
	}
	if s, _ := PickResolver(rs[:1]); s.Addr().Zone() != "wlan0" {
		t.Fatalf("only a link-local one: %v", s)
	}
	if got := ResolverClass(rs); got != "private" {
		t.Fatalf("class %s", got)
	}
}

func TestL5_HistoryHourOnly(t *testing.T) {
	var h History
	h.Note("n", time.Date(2026, 11, 20, 12, 31, 7, 0, time.UTC))
	if at := time.Unix(h.Runs[0].At, 0).UTC(); at != time.Date(2026, 11, 20, 13, 0, 0, 0, time.UTC) {
		t.Fatalf("stored %v", at)
	}
}

func TestL6_ChargedOnceOnFirstSend(t *testing.T) {
	w := newWorld(t)
	env := w.env()
	n := 0
	env.OnFirstSend = func() { n++ }
	Run(context.Background(), env)
	if n != 1 {
		t.Fatalf("charged %d times", n)
	}
}

// ---- M3: the cover name is held to the list's rule --------------------

func TestM3_CoverNameChecked(t *testing.T) {
	w := newWorld(t)
	w.relay.target.CoverName = "www.example.ir"
	res := Run(context.Background(), w.env())
	if findResult(res, "C5", "") != "skipped" {
		t.Fatalf("C5 = %s", findResult(res, "C5", ""))
	}
}
