package fieldprobe

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"time"

	"github.com/sagernet/quic-go"
)

// QUICer makes one QUIC handshake (B9). The real one is quic-go (the
// fork sing-box already carries) on a protect()ed UDP socket.
type QUICer interface {
	Handshake(ctx context.Context, to netip.AddrPort, sni string) (ok bool, kind string)
}

type quicGo struct {
	net     Net
	timeout time.Duration
}

func (q quicGo) Handshake(ctx context.Context, to netip.AddrPort, sni string) (bool, string) {
	ctx, cancel := context.WithTimeout(ctx, q.timeout)
	defer cancel()
	pc, err := q.net.ListenUDP(ctx)
	if err != nil {
		return false, errKind(err)
	}
	defer pc.Close()
	conn, err := quic.Dial(ctx, pc, net.UDPAddrFromAddrPort(to),
		&tls.Config{ServerName: sni, NextProtos: []string{"h3"}, InsecureSkipVerify: true, MinVersion: tls.VersionTLS13},
		&quic.Config{HandshakeIdleTimeout: q.timeout, MaxIdleTimeout: q.timeout})
	if err != nil {
		if ctx.Err() != nil {
			return false, "timeout"
		}
		return false, errKind(err)
	}
	_ = conn.CloseWithError(0, "")
	return true, ""
}
