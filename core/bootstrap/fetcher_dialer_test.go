package bootstrap

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// socks5Fixture is a SOCKS5 server that offers exactly one auth method.
// `requireAuth` picks USERNAME/PASSWORD (0x02) over NO AUTH (0x00), which
// is what the engine's own loopback inlet does — see core/engine/inlet.go
// for why an unauthenticated loopback SOCKS on Android is an open proxy
// for every other app on the device.
func socks5Fixture(t *testing.T, requireAuth bool, user, pass string) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				hdr := make([]byte, 2)
				if _, err := io.ReadFull(c, hdr); err != nil {
					return
				}
				methods := make([]byte, int(hdr[1]))
				if _, err := io.ReadFull(c, methods); err != nil {
					return
				}
				want := byte(0x00)
				if requireAuth {
					want = 0x02
				}
				ok := false
				for _, m := range methods {
					if m == want {
						ok = true
					}
				}
				if !ok {
					_, _ = c.Write([]byte{0x05, 0xFF})
					return
				}
				if _, err := c.Write([]byte{0x05, want}); err != nil {
					return
				}
				if requireAuth {
					head := make([]byte, 2)
					if _, err := io.ReadFull(c, head); err != nil {
						return
					}
					u := make([]byte, int(head[1]))
					if _, err := io.ReadFull(c, u); err != nil {
						return
					}
					pl := make([]byte, 1)
					if _, err := io.ReadFull(c, pl); err != nil {
						return
					}
					p := make([]byte, int(pl[0]))
					if _, err := io.ReadFull(c, p); err != nil {
						return
					}
					if string(u) != user || string(p) != pass {
						_, _ = c.Write([]byte{0x01, 0x01})
						return
					}
					if _, err := c.Write([]byte{0x01, 0x00}); err != nil {
						return
					}
				}
				req := make([]byte, 4)
				if _, err := io.ReadFull(c, req); err != nil {
					return
				}
				l := make([]byte, 1)
				if _, err := io.ReadFull(c, l); err != nil {
					return
				}
				if _, err := io.ReadFull(c, make([]byte, int(l[0])+2)); err != nil {
					return
				}
				resp := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
				binary.BigEndian.PutUint16(resp[8:], 0)
				_, _ = c.Write(resp)
			}(c)
		}
	}()
	return ln
}

func TestTunnelDialerAuthenticatesWhenGivenACredential(t *testing.T) {
	ln := socks5Fixture(t, true, "alice", "correct-horse")
	d := &TunnelDialer{
		SocksAddress: ln.Addr().String(),
		Username:     "alice",
		Password:     "correct-horse",
		Timeout:      3 * time.Second,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := d.DialContext(ctx, "tcp", "example.invalid:443")
	if err != nil {
		t.Fatalf("authenticated dial: %v", err)
	}
	_ = c.Close()
}

// A wrong credential must surface as a clean, credential-free error —
// this string lands in the refresh audit trail.
func TestTunnelDialerReportsRejectedCredential(t *testing.T) {
	ln := socks5Fixture(t, true, "alice", "correct-horse")
	d := &TunnelDialer{
		SocksAddress: ln.Addr().String(),
		Username:     "alice",
		Password:     "wrong",
		Timeout:      3 * time.Second,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := d.DialContext(ctx, "tcp", "example.invalid:443")
	if err == nil {
		t.Fatal("expected the dial to fail")
	}
	if !strings.Contains(err.Error(), "auth rejected") {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(err.Error(), "wrong") || strings.Contains(err.Error(), "alice") {
		t.Fatalf("error leaked the credential: %v", err)
	}
}

// An auth-requiring inlet must refuse a caller that holds no credential
// — that is the whole defence against a co-resident app on the phone
// finding the loopback port and using it as an open proxy.
func TestTunnelDialerWithoutCredentialIsRefusedByAnAuthRequiringInlet(t *testing.T) {
	ln := socks5Fixture(t, true, "alice", "correct-horse")
	d := &TunnelDialer{SocksAddress: ln.Addr().String(), Timeout: 3 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := d.DialContext(ctx, "tcp", "example.invalid:443"); err == nil {
		t.Fatal("an unauthenticated caller must not get through")
	}
}

// The desktop sidecar's inlet is unauthenticated; that path must keep
// working unchanged.
func TestTunnelDialerStillSpeaksNoAuth(t *testing.T) {
	ln := socks5Fixture(t, false, "", "")
	d := &TunnelDialer{SocksAddress: ln.Addr().String(), Timeout: 3 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := d.DialContext(ctx, "tcp", "example.invalid:443")
	if err != nil {
		t.Fatalf("no-auth dial: %v", err)
	}
	_ = c.Close()
}
