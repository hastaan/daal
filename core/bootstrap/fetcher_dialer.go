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
// CONNECT handshake. Phase 1D directory pulls do not need authentication.
type TunnelDialer struct {
	// SocksAddress is "host:port" of the local SOCKS5 inlet. Empty means
	// "no tunnel"; the fetcher should fall back to a direct dialer.
	SocksAddress string
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
	if err := socks5Connect(c, address, timeout); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// socks5Connect performs the minimal SOCKS5 handshake + CONNECT. No
// authentication; ATYP DOMAINNAME for hostnames, ATYP IPV4/IPV6 for IPs.
func socks5Connect(conn net.Conn, address string, timeout time.Duration) error {
	conn.SetDeadline(time.Now().Add(timeout))

	// Greeting: VER=5, NMETHODS=1, METHOD=0x00 (no auth)
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return fmt.Errorf("tunnel: socks greeting: %w", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("tunnel: socks greeting reply: %w", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
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
