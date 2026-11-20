package fieldprobe

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// ---- loopback servers -------------------------------------------------------

var (
	certOnce sync.Once
	testCert tls.Certificate
)

// selfSigned is one certificate for every name of the default list (and
// the cover name), its own root: testRoots() holds it, so Stage B's
// chain check passes in the loopback world and fails without it.
func selfSigned(t *testing.T) tls.Certificate {
	certOnce.Do(func() {
		names := []string{"test", "www.example.test", coverName}
		if tg, err := DefaultTargets(); err == nil {
			names = append(names, tg.Names()...)
		}
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: names,
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
		if err != nil {
			panic(err)
		}
		testCert = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
		testLeaf, _ = x509.ParseCertificate(der)
	})
	return testCert
}

var testLeaf *x509.Certificate

func testRoots(t *testing.T) *x509.CertPool {
	selfSigned(t)
	p := x509.NewCertPool()
	p.AddCert(testLeaf)
	return p
}

// resetNames: names whose hello the loopback web server answers with a
// RST (a filter keyed on the name).
var resetNames sync.Map

// reply is what the fake HTTP server answers to one request.
type reply struct {
	status   int
	body     int
	stall    bool // write body bytes, then hold the connection open
	location string
	text     string
}

type server struct {
	ln   net.Listener
	wg   sync.WaitGroup
	done chan struct{}
}

func (s *server) addr() string { return s.ln.Addr().String() }

func (s *server) close() {
	close(s.done)
	_ = s.ln.Close()
	s.wg.Wait()
}

func serve(t *testing.T, handle func(c net.Conn, done <-chan struct{})) *server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &server{ln: ln, done: make(chan struct{})}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer c.Close()
				handle(c, s.done)
			}()
		}
	}()
	t.Cleanup(s.close)
	return s
}

// tlsHTTP serves TLS + HTTP/1.1. refuseSNI: names answered with an alert.
func tlsHTTP(t *testing.T, route func(sni, host, path string) reply, refuseSNI ...string) *server {
	cert := selfSigned(t)
	return serve(t, func(c net.Conn, done <-chan struct{}) {
		var sni string
		cfg := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"},
			GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
				sni = h.ServerName
				if _, ok := resetNames.Load(sni); ok {
					if tc, ok := c.(*net.TCPConn); ok {
						_ = tc.SetLinger(0)
					}
					_ = c.Close()
					return nil, errors.New("reset name")
				}
				for _, r := range refuseSNI {
					if r == sni {
						return nil, errors.New("refused name")
					}
				}
				return nil, nil
			}}
		tc := tls.Server(c, cfg)
		_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
		if tc.Handshake() != nil {
			return
		}
		httpReply(tc, sni, route, done)
	})
}

func plainHTTP(t *testing.T) *server {
	return serve(t, func(c net.Conn, done <-chan struct{}) {
		httpReply(c, "", func(string, string, string) reply { return reply{status: 200} }, done)
	})
}

func httpReply(c net.Conn, sni string, route func(sni, host, path string) reply, done <-chan struct{}) {
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil {
		return
	}
	f := strings.Fields(line)
	path := ""
	if len(f) >= 2 {
		path = f[1]
	}
	host := ""
	for {
		h, err := br.ReadString('\n')
		if err != nil {
			return
		}
		h = strings.TrimSpace(h)
		if h == "" {
			break
		}
		if k, v, ok := strings.Cut(h, ":"); ok && strings.EqualFold(k, "host") {
			host = strings.TrimSpace(v)
		}
	}
	r := route(sni, host, path)
	body := []byte(r.text)
	if len(body) < r.body {
		body = append(body, make([]byte, r.body-len(body))...)
	}
	hdr := fmt.Sprintf("HTTP/1.1 %d X\r\n", r.status)
	if r.location != "" {
		hdr += "Location: " + r.location + "\r\n"
	}
	if !r.stall {
		hdr += fmt.Sprintf("Content-Length: %d\r\n", len(body))
	}
	hdr += "Connection: close\r\n\r\n"
	_, _ = c.Write(append([]byte(hdr), body...))
	if r.stall {
		select {
		case <-done:
		case <-time.After(10 * time.Second):
		}
	}
}

// resetServer reads the first flight and answers with a RST.
func resetServer(t *testing.T) *server {
	return serve(t, func(c net.Conn, _ <-chan struct{}) {
		buf := make([]byte, 512)
		_, _ = c.Read(buf)
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetLinger(0)
		}
	})
}

// silentServer reads everything and never answers.
func silentServer(t *testing.T) *server {
	return serve(t, func(c net.Conn, done <-chan struct{}) {
		go func() {
			buf := make([]byte, 4096)
			for {
				if _, err := c.Read(buf); err != nil {
					return
				}
			}
		}()
		<-done
	})
}

// alertServer answers the hello with a TLS handshake_failure alert.
func alertServer(t *testing.T) *server {
	return serve(t, func(c net.Conn, _ <-chan struct{}) {
		buf := make([]byte, 2048)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28})
		time.Sleep(50 * time.Millisecond)
	})
}

// flightThen reads the hello, writes part of a server flight (a TLS
// handshake record header promising 16 KB, then n bytes of it) and then
// either holds the connection (stall) or resets it.
func flightThen(t *testing.T, n int, reset bool) *server {
	return serve(t, func(c net.Conn, done <-chan struct{}) {
		buf := make([]byte, 2048)
		_, _ = c.Read(buf)
		rec := append([]byte{0x16, 0x03, 0x03, 0x40, 0x00}, make([]byte, n)...)
		_, _ = c.Write(rec)
		if reset {
			time.Sleep(30 * time.Millisecond)
			if tc, ok := c.(*net.TCPConn); ok {
				_ = tc.SetLinger(0)
			}
			return
		}
		select {
		case <-done:
		case <-time.After(10 * time.Second):
		}
	})
}

// ---- fake Net ---------------------------------------------------------------

// fakeNet sends every dial for a mapped address to a loopback server and
// refuses the rest, the way a closed port does.
type fakeNet struct {
	mu     sync.Mutex
	to     map[netip.AddrPort]string
	byAddr map[netip.Addr]string
	stall  map[netip.AddrPort]bool // SYN never answered
	dials  []netip.AddrPort
	udp    int
}

func newFakeNet() *fakeNet {
	return &fakeNet{to: map[netip.AddrPort]string{}, byAddr: map[netip.Addr]string{}, stall: map[netip.AddrPort]bool{}}
}

func (f *fakeNet) DialTCP(ctx context.Context, to netip.AddrPort) (net.Conn, error) {
	f.mu.Lock()
	f.dials = append(f.dials, to)
	dst, ok := f.to[to]
	if !ok && to.Port() == 443 {
		dst, ok = f.byAddr[to.Addr()]
	}
	stall := f.stall[to]
	f.mu.Unlock()
	if stall {
		<-ctx.Done()
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: ctx.Err()}
	}
	if !ok {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", dst)
}

func (f *fakeNet) DialUDP(context.Context, netip.AddrPort) (net.Conn, error) {
	f.mu.Lock()
	f.udp++
	f.mu.Unlock()
	return nil, errors.New("fake: no udp")
}

func (f *fakeNet) ListenUDP(context.Context) (net.PacketConn, error) {
	return nil, errors.New("fake: no udp")
}

// ---- fake DNS, QUIC, relay --------------------------------------------------

type fakeDNS struct {
	mu      sync.Mutex
	answers map[string]DNSAnswer // "server|name|qtype"
	dead    bool
	// deadAt: servers that never answer (the others do).
	deadAt  map[netip.Addr]bool
	asked   []string
	askedAt []netip.Addr
}

func dnsKey(server netip.AddrPort, name string, qtype uint16) string {
	return fmt.Sprintf("%s|%s|%d", server.Addr(), name, qtype)
}

func (d *fakeDNS) Query(ctx context.Context, server netip.AddrPort, name string, qtype uint16) (DNSAnswer, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.asked = append(d.asked, name)
	d.askedAt = append(d.askedAt, server.Addr())
	if d.dead || d.deadAt[server.Addr()] {
		return DNSAnswer{}, timeoutErr{}
	}
	if a, ok := d.answers[dnsKey(server, name, qtype)]; ok {
		return a, nil
	}
	if a, ok := d.answers[dnsKey(netip.AddrPort{}, name, qtype)]; ok {
		return a, nil
	}
	return DNSAnswer{Rcode: 0}, nil
}

type fakeQUIC struct{ ok bool }

func (q fakeQUIC) Handshake(context.Context, netip.AddrPort, string) (bool, string) {
	if q.ok {
		return true, ""
	}
	return false, "timeout"
}

type fakeRelay struct {
	mu       sync.Mutex
	target   RelayTarget
	outcomes map[string]RelayOutcome // "handle|desync"
	calls    []string
	restored int
}

func (r *fakeRelay) Target() (RelayTarget, bool) { return r.target, true }

func (r *fakeRelay) Prove(_ context.Context, handle, desync string) RelayOutcome {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := handle + "|" + desync
	r.calls = append(r.calls, k)
	if o, ok := r.outcomes[k]; ok {
		return o
	}
	return RelayOutcome{OK: true}
}

func (r *fakeRelay) Restore() {
	r.mu.Lock()
	r.restored++
	r.mu.Unlock()
}

func quickTimeouts() Timeouts {
	return Timeouts{Connect: 800 * time.Millisecond, Handshake: 800 * time.Millisecond, Carry: 800 * time.Millisecond,
		DNS: 300 * time.Millisecond, QUIC: 300 * time.Millisecond, Relay: time.Second}
}
