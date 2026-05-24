package abi

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"daal/core/bootstrap"
	"daal/core/refresh"
)

// TestSetTunnelSocksInstallsAndClearsDialer asserts that:
//   - calling SetTunnelSocks installs the global dialer so subsequent
//     refresh fetches go through TunnelDialer;
//   - calling SetTunnelSocks with host="" clears the override;
//   - the response JSON exposes only host/port — never a URL.
func TestSetTunnelSocksInstallsAndClearsDialer(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	if refresh.CurrentGlobalDialer() != nil {
		t.Fatal("expected no global dialer before SetTunnelSocks")
	}

	body, err := SetTunnelSocks("127.0.0.1", 17891, "", "")
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	if !strings.Contains(body, `"endpoint":"127.0.0.1:17891"`) {
		t.Fatalf("unexpected body: %s", body)
	}
	if strings.Contains(body, "://") {
		t.Fatalf("body must not leak any URL: %s", body)
	}
	if refresh.CurrentGlobalDialer() == nil {
		t.Fatal("expected global dialer to be installed")
	}

	// Clear with empty host.
	body2, err := SetTunnelSocks("", 0, "", "")
	if err != nil {
		t.Fatalf("clear: %v", err)
	}
	if !strings.Contains(body2, `"endpoint":""`) {
		t.Fatalf("unexpected clear body: %s", body2)
	}
	if refresh.CurrentGlobalDialer() != nil {
		t.Fatal("expected global dialer cleared after empty host")
	}
}

// TestSetTunnelSocksRejectsBadPort guards against the obvious foot-guns.
func TestSetTunnelSocksRejectsBadPort(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })
	if _, err := SetTunnelSocks("127.0.0.1", 0, "", ""); err == nil {
		t.Fatal("expected error for port 0")
	}
	if _, err := SetTunnelSocks("127.0.0.1", 70000, "", ""); err == nil {
		t.Fatal("expected error for port 70000")
	}
}

// TestTunnelDialerRoutesThroughSocks spins up a tiny SOCKS5 listener and
// proves the dialer installed by SetTunnelSocks reaches the listener
// (NOT direct). The listener accepts the SOCKS5 handshake and immediately
// closes the upstream connection so the test does not need a real
// upstream service.
func TestTunnelDialerRoutesThroughSocks(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var (
		seenMu         sync.Mutex
		seenHits       int
		seenWantedHost string
	)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if err := acceptSocks5(c); err == nil {
					seenMu.Lock()
					seenHits++
					seenMu.Unlock()
				}
			}(c)
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	if _, err := SetTunnelSocks("127.0.0.1", addr.Port, "", ""); err != nil {
		t.Fatal(err)
	}

	// Use the installed global dialer to dial an arbitrary upstream.
	g := refresh.CurrentGlobalDialer()
	if g == nil {
		t.Fatal("global dialer not installed")
	}
	d, viaTunnel, err := g()
	if err != nil {
		t.Fatal(err)
	}
	if !viaTunnel {
		t.Fatal("expected viaTunnel=true")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	seenWantedHost = "example.invalid:443"
	conn, _ := d.DialContext(ctx, "tcp", seenWantedHost)
	if conn != nil {
		conn.Close()
	}

	// Allow goroutine to record the handshake outcome.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		seenMu.Lock()
		got := seenHits
		seenMu.Unlock()
		if got > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("tunnel dialer did not route through SOCKS5 listener")
}

// acceptSocks5 is the minimum-viable SOCKS5 server: handshake, accept
// CONNECT, reply success, close.
func acceptSocks5(c net.Conn) error {
	c.SetDeadline(time.Now().Add(2 * time.Second))
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return err
	}
	if hdr[0] != 0x05 {
		return errors.New("ver")
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return err
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return err
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return err
	}
	switch req[3] {
	case 0x01:
		if _, err := io.ReadFull(c, make([]byte, 4+2)); err != nil {
			return err
		}
	case 0x03:
		ln := make([]byte, 1)
		if _, err := io.ReadFull(c, ln); err != nil {
			return err
		}
		if _, err := io.ReadFull(c, make([]byte, int(ln[0])+2)); err != nil {
			return err
		}
	case 0x04:
		if _, err := io.ReadFull(c, make([]byte, 16+2)); err != nil {
			return err
		}
	default:
		return errors.New("atyp")
	}
	// Reply success with bound 0.0.0.0:0
	resp := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(resp[8:], 0)
	_, err := c.Write(resp)
	return err
}

var _ bootstrap.Dialer = (*bootstrap.TunnelDialer)(nil)
