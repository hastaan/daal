package abi

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"daal/core/engine"
	"daal/core/refresh"
)

// Wave 1 made refresh fail closed while a route is active: rather than
// fetch a subscription or a revocation list from the device's real
// address, it does not fetch at all. That was right, and it left every
// scheduled behaviour dead on Android. Wave 2's job is to restore the
// capability WITHOUT touching the guard — so these tests assert both
// halves: the round trip works when an inlet is live, and the refusal is
// unchanged when one is not.

// authSocks5Server is a minimum-viable SOCKS5 server that REQUIRES RFC
// 1929 username/password. It records what it was offered and what it was
// given, so the test can assert the engine's own minted credential
// actually reached the wire.
type authSocks5Server struct {
	ln       net.Listener
	wantUser string
	wantPass string

	mu             sync.Mutex
	connects       int
	sawUser        string
	sawPass        string
	offeredUserPas bool
}

func newAuthSocks5Server(t *testing.T, user, pass string, port int) *authSocks5Server {
	t.Helper()
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("listen on the inlet's reserved port: %v", err)
	}
	s := &authSocks5Server{ln: ln, wantUser: user, wantPass: pass}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	return s
}

func (s *authSocks5Server) serve(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))

	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil || hdr[0] != 0x05 {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	offered := false
	for _, m := range methods {
		if m == 0x02 {
			offered = true
		}
	}
	s.mu.Lock()
	s.offeredUserPas = offered
	s.mu.Unlock()
	if !offered {
		// This is what a co-resident app port-scanning loopback gets.
		_, _ = c.Write([]byte{0x05, 0xFF})
		return
	}
	if _, err := c.Write([]byte{0x05, 0x02}); err != nil {
		return
	}

	// RFC 1929 sub-negotiation.
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil || head[0] != 0x01 {
		return
	}
	user := make([]byte, int(head[1]))
	if _, err := io.ReadFull(c, user); err != nil {
		return
	}
	plen := make([]byte, 1)
	if _, err := io.ReadFull(c, plen); err != nil {
		return
	}
	pass := make([]byte, int(plen[0]))
	if _, err := io.ReadFull(c, pass); err != nil {
		return
	}
	s.mu.Lock()
	s.sawUser, s.sawPass = string(user), string(pass)
	s.mu.Unlock()
	if string(user) != s.wantUser || string(pass) != s.wantPass {
		_, _ = c.Write([]byte{0x01, 0x01})
		return
	}
	if _, err := c.Write([]byte{0x01, 0x00}); err != nil {
		return
	}

	// CONNECT.
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	switch req[3] {
	case 0x01:
		if _, err := io.ReadFull(c, make([]byte, 4+2)); err != nil {
			return
		}
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return
		}
		if _, err := io.ReadFull(c, make([]byte, int(l[0])+2)); err != nil {
			return
		}
	case 0x04:
		if _, err := io.ReadFull(c, make([]byte, 16+2)); err != nil {
			return
		}
	default:
		return
	}
	resp := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(resp[8:], 0)
	if _, err := c.Write(resp); err != nil {
		return
	}
	s.mu.Lock()
	s.connects++
	s.mu.Unlock()
}

func (s *authSocks5Server) snapshot() (int, string, string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connects, s.sawUser, s.sawPass, s.offeredUserPas
}

// freeLoopbackPort mirrors what core/engine's planRefreshInlet does, so
// the test's stand-in listener can occupy the address the engine would
// have handed sing-box.
func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return p
}

// THE ROUND TRIP. A live inlet (stood up here by a real SOCKS5 server on
// the inlet's address, in place of the in-process sing-box that serves it
// on a device) plus SetTunnelRefresh(true) must give core/refresh a
// dialer that reports viaTunnel=true and whose bytes actually traverse
// the inlet, authenticated with the credential the engine minted.
func TestSetTunnelRefresh_RoundTripsThroughTheAuthenticatedInlet(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })
	t.Cleanup(func() { refresh.SetTunnelRequired(false) })

	inlet := &engine.RefreshInlet{
		Host:     "127.0.0.1",
		Port:     freeLoopbackPort(t),
		Username: "u-fixture",
		Password: "p-fixture-128-bit",
	}
	srv := newAuthSocks5Server(t, inlet.Username, inlet.Password, inlet.Port)
	t.Cleanup(engine.PublishRefreshInletForTest(inlet))

	// A route is active — this is exactly the state in which Wave 1
	// forbids a direct fetch.
	refresh.SetTunnelRequired(true)

	body, err := SetTunnelRefresh(true)
	if err != nil {
		t.Fatalf("SetTunnelRefresh(true): %v", err)
	}
	if !strings.Contains(body, `"tunnelled":true`) ||
		!strings.Contains(body, `"authenticated":true`) {
		t.Fatalf("unexpected envelope: %s", body)
	}
	// The envelope must not hand the host the credential or the port.
	if strings.Contains(body, inlet.Password) || strings.Contains(body, inlet.Username) {
		t.Fatalf("envelope leaked the inlet credential: %s", body)
	}

	g := refresh.CurrentGlobalDialer()
	if g == nil {
		t.Fatal("no global dialer installed; refresh is still fail-closed")
	}
	d, viaTunnel, err := g()
	if err != nil {
		t.Fatalf("dialer factory: %v", err)
	}
	if !viaTunnel {
		t.Fatal("viaTunnel must be true: the audit trail is what tells the " +
			"user whether a fetch rode the tunnel")
	}
	if d == nil {
		t.Fatal("nil dialer with no error")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", "example.invalid:443")
	if err != nil {
		t.Fatalf("dial through the inlet: %v", err)
	}
	_ = conn.Close()

	connects, sawUser, sawPass, offered := srv.snapshot()
	if connects != 1 {
		t.Fatalf("expected exactly one CONNECT through the inlet, got %d", connects)
	}
	if !offered {
		t.Fatal("the dialer did not offer username/password auth")
	}
	if sawUser != inlet.Username || sawPass != inlet.Password {
		t.Fatalf("wrong credential on the wire: user=%q pass=%q", sawUser, sawPass)
	}

	// And turning it off must restore Wave 1's refusal, not a direct dial.
	if _, err := SetTunnelRefresh(false); err != nil {
		t.Fatalf("SetTunnelRefresh(false): %v", err)
	}
	if refresh.CurrentGlobalDialer() != nil {
		t.Fatal("dialer survived SetTunnelRefresh(false)")
	}
	assertRefreshFailsClosed(t, "after disabling the inlet")
}

// Without a live inlet the call must FAIL, and the failure must leave
// Wave 1's guard exactly as it was. The wrong fix here — quietly
// installing a direct dialer so "refresh works" — is the leak.
func TestSetTunnelRefresh_WithoutAnInletLeavesTheGuardClosed(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })
	t.Cleanup(func() { refresh.SetTunnelRequired(false) })

	// Belt and braces: no driver has published one in this process.
	engine.PublishRefreshInletForTest(nil)

	refresh.SetTunnelRequired(true)
	if _, err := SetTunnelRefresh(true); err == nil {
		t.Fatal("SetTunnelRefresh(true) must fail when no inlet is listening")
	}
	if refresh.CurrentGlobalDialer() != nil {
		t.Fatal("a failed enable must not install any dialer")
	}
	assertRefreshFailsClosed(t, "with no inlet")
}

// assertRefreshFailsClosed exercises the dialer the PRODUCTION refreshers
// actually hold — the ones abi/scheduler.go's tick fetches from
// ensureRefresh — not a bare &Refresher{}. That distinction is the whole
// bug this helper guards: Refresher.dial() prefers the global override,
// then the per-instance Dialer field, and only then reaches
// refresh.directFallback where Wave 1's refusal lives. A per-instance
// dialer that ignores TunnelRequired therefore reopens the leak while
// every unit test on the bare struct keeps passing.
func assertRefreshFailsClosed(t *testing.T, when string) {
	t.Helper()
	subs, rev, err := ensureRefresh()
	if err != nil {
		t.Fatalf("ensureRefresh: %v", err)
	}
	if !refresh.TunnelRequired() {
		t.Fatal("precondition: a route must be active for the guard to apply")
	}
	if _, _, err := subs.Dialer(); !errors.Is(err, refresh.ErrTunnelRequired) {
		t.Fatalf("%s: subscription refresh must fail closed, got %v", when, err)
	}
	if _, _, err := rev.Dialer(); !errors.Is(err, refresh.ErrTunnelRequired) {
		t.Fatalf("%s: revocation refresh must fail closed, got %v", when, err)
	}
}

// The ordering contract, from the host's point of view: calling before
// the driver has started is the mistake the API must make impossible to
// get away with silently.
func TestSetTunnelRefresh_IsRefusedBeforeTheDriverPublishesTheInlet(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	engine.PublishRefreshInletForTest(nil)
	if _, err := SetTunnelRefresh(true); err == nil {
		t.Fatal("expected refusal before the inlet is live")
	}

	inlet := &engine.RefreshInlet{Host: "127.0.0.1", Port: freeLoopbackPort(t)}
	t.Cleanup(engine.PublishRefreshInletForTest(inlet))
	if _, err := SetTunnelRefresh(true); err != nil {
		t.Fatalf("expected success once the inlet is live: %v", err)
	}
	if !TunnelRefreshActive() {
		t.Fatal("TunnelRefreshActive must report the installed dialer")
	}
	if _, err := SetTunnelRefresh(false); err != nil {
		t.Fatal(err)
	}
	if TunnelRefreshActive() {
		t.Fatal("TunnelRefreshActive must clear with the dialer")
	}
}
