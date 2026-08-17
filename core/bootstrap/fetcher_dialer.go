package bootstrap

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// TunnelDialer routes outbound connections through a SOCKS5 inlet exposed
// by the engine on a loopback port (default `127.0.0.1:7891`). When the
// driver is connected, the SOCKS5 CONNECT request rides over the active
// sing-box outbound; when it is not connected, the dialer falls back to
// direct.
//
// We avoid pulling in golang.org/x/net/proxy because that package re-uses
// net/http for some helpers; instead we hand-roll the minimal SOCKS5
// CONNECT handshake, with optional RFC 1929 username/password auth.
type TunnelDialer struct {
	// SocksAddress is "host:port" of the local SOCKS5 inlet. Empty means
	// "no tunnel"; the fetcher should fall back to a direct dialer.
	SocksAddress string
	// Username/Password authenticate to the inlet per RFC 1929. Both
	// empty means "offer NO AUTHENTICATION only", which is the desktop
	// sidecar's shape.
	//
	// The in-process Android inlet (core/engine/inlet.go) DOES require
	// them: it listens on loopback, and on Android loopback has no
	// per-UID isolation, so without auth it would be an open proxy for
	// every other app on the phone. Credentials are per-activation and
	// never leave the process.
	Username string
	Password string
	// DirectFallback is used when the engine reports it is not connected.
	DirectFallback Dialer
	// Timeout per Dial.
	Timeout time.Duration
}

// DialContext satisfies the Dialer interface. If SocksAddress is empty,
// the call is forwarded to DirectFallback.
func (t *TunnelDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if t.SocksAddress == "" {
		if t.DirectFallback == nil {
			return nil, errors.New("tunnel: not connected and no direct fallback")
		}
		return t.DirectFallback.DialContext(ctx, network, address)
	}
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("tunnel: unsupported network %q", network)
	}
	timeout := t.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "tcp", t.SocksAddress)
	if err != nil {
		return nil, fmt.Errorf("tunnel: dial socks: %w", err)
	}
	if err := socks5Connect(c, address, timeout, t.Username, t.Password); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// socks5Connect performs the minimal SOCKS5 handshake + CONNECT, with
// RFC 1929 username/password auth when a credential is supplied. ATYP
// DOMAINNAME for hostnames, ATYP IPV4/IPV6 for IPs.
func socks5Connect(conn net.Conn, address string, timeout time.Duration, username, password string) error {
	conn.SetDeadline(time.Now().Add(timeout))

	// Greeting. Offer NO AUTHENTICATION alone when we hold no
	// credential; offer USERNAME/PASSWORD *first* when we do, so a
	// server that accepts both still authenticates us rather than
	// silently letting anyone in.
	greet := []byte{0x05, 0x01, 0x00}
	if username != "" || password != "" {
		greet = []byte{0x05, 0x02, 0x02, 0x00}
	}
	if _, err := conn.Write(greet); err != nil {
		return fmt.Errorf("tunnel: socks greeting: %w", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("tunnel: socks greeting reply: %w", err)
	}
	if resp[0] != 0x05 {
		return fmt.Errorf("tunnel: socks negotiation refused (ver=%d, method=%d)", resp[0], resp[1])
	}
	switch resp[1] {
	case 0x00: // no auth required
	case 0x02:
		if username == "" && password == "" {
			return errors.New("tunnel: socks server demands auth but no credential is configured")
		}
		if err := socks5UserPassAuth(conn, username, password); err != nil {
			return err
		}
	default:
		// 0xFF is "no acceptable methods" — what an unauthenticated
		// prober gets from our own inlet.
		return fmt.Errorf("tunnel: socks negotiation refused (ver=%d, method=%d)", resp[0], resp[1])
	}

	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("tunnel: bad address: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("tunnel: bad port: %w", err)
	}

	req := []byte{0x05, 0x01, 0x00} // VER, CMD=CONNECT, RSV
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, 0x01)
			req = append(req, ip4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return errors.New("tunnel: hostname too long")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], uint16(port))
	req = append(req, portBytes[:]...)
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("tunnel: socks connect: %w", err)
	}

	// Reply: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return fmt.Errorf("tunnel: socks connect reply: %w", err)
	}
	if head[0] != 0x05 {
		return fmt.Errorf("tunnel: socks bad version %d", head[0])
	}
	if head[1] != 0x00 {
		return fmt.Errorf("tunnel: socks connect refused (rep=%d)", head[1])
	}
	switch head[3] {
	case 0x01:
		if _, err := io.ReadFull(conn, make([]byte, 4+2)); err != nil {
			return err
		}
	case 0x03:
		ln := make([]byte, 1)
		if _, err := io.ReadFull(conn, ln); err != nil {
			return err
		}
		if _, err := io.ReadFull(conn, make([]byte, int(ln[0])+2)); err != nil {
			return err
		}
	case 0x04:
		if _, err := io.ReadFull(conn, make([]byte, 16+2)); err != nil {
			return err
		}
	default:
		return fmt.Errorf("tunnel: unsupported atyp %d", head[3])
	}
	conn.SetDeadline(time.Time{})
	return nil
}

// socks5UserPassAuth is the RFC 1929 sub-negotiation:
//
//	VER=1 ULEN uname PLEN passwd  →  VER=1 STATUS(0=ok)
//
// Both fields are length-prefixed with a single byte, so neither may
// exceed 255 bytes; core/engine mints 12/22-character tokens.
func socks5UserPassAuth(conn net.Conn, username, password string) error {
	if len(username) > 255 || len(password) > 255 {
		return errors.New("tunnel: socks credential too long")
	}
	req := make([]byte, 0, 3+len(username)+len(password))
	req = append(req, 0x01, byte(len(username)))
	req = append(req, username...)
	req = append(req, byte(len(password)))
	req = append(req, password...)
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("tunnel: socks auth: %w", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("tunnel: socks auth reply: %w", err)
	}
	if reply[0] != 0x01 || reply[1] != 0x00 {
		// Do NOT include the credential in the error: this string ends
		// up in the refresh audit trail.
		return fmt.Errorf("tunnel: socks auth rejected (ver=%d, status=%d)", reply[0], reply[1])
	}
	return nil
}
