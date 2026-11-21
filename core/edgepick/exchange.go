package edgepick

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// NeutralName is the TLS name an Exchange probe presents by default:
// the shared outer name of the CDN's Encrypted Client Hello. It is what
// the route's own ECH hello shows on the wire anyway, it is the same
// for every site on the CDN, and it names nobody — the route's zone is
// never shown by a probe. (Whether the CDN serves a page at
// /cdn-cgi/trace under this name from inside is GATE C-2's to confirm
// on a real network; a probe that gets any HTTP answer counts.)
const NeutralName = "cloudflare-ech.com"

// ExchangeRounds is how many request/response round trips an Exchange
// makes after the handshake. With the TCP and TLS handshakes that is
// well over ten packets each way — the point of the probe: some edge
// addresses let a handshake through and cut the connection a few
// packets later, and a probe that stopped at the handshake would call
// them clean.
const ExchangeRounds = 4

// maxResponse bounds what one answer may be (headers and body).
const maxResponse = 64 << 10

// Exchange is the real Prober: TCP to the address, TLS with a neutral
// name verified against Roots, then ExchangeRounds small HTTP/1.1
// requests on the one connection, each answer read in full. Hand-rolled
// HTTP over a tls.Conn (no net/http in core: core/opsec_test.go).
type Exchange struct {
	// Dial opens the TCP connection (on Android: a socket offered to
	// the host's protect() first, so a probe never rides a tunnel).
	Dial func(ctx context.Context, to netip.AddrPort) (net.Conn, error)
	// ServerName is the name presented and verified; NeutralName when "".
	ServerName string
	// Roots verify the edge's certificate: the roots the route's own
	// outbound installs. nil: the platform's.
	Roots *x509.CertPool
	// Rounds: ExchangeRounds when 0.
	Rounds int
	// Path is the resource asked for; "/cdn-cgi/trace" when "".
	Path string
}

// ErrShortExchange: the edge answered the handshake but the connection
// did not carry the whole exchange.
var ErrShortExchange = errors.New("edgepick: the edge stopped carrying before the exchange was done")

// Probe implements Prober.
func (e Exchange) Probe(ctx context.Context, to netip.AddrPort) error {
	if e.Dial == nil {
		return errors.New("edgepick: no dialer")
	}
	name := e.ServerName
	if name == "" {
		name = NeutralName
	}
	rounds := e.Rounds
	if rounds <= 0 {
		rounds = ExchangeRounds
	}
	path := e.Path
	if path == "" {
		path = "/cdn-cgi/trace"
	}
	raw, err := e.Dial(ctx, to)
	if err != nil {
		return fmt.Errorf("edgepick: connect: %w", err)
	}
	defer raw.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { _ = raw.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	conn := tls.Client(raw, &tls.Config{
		ServerName: name,
		RootCAs:    e.Roots,
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
	})
	if err := conn.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("edgepick: handshake: %w", err)
	}
	br := bufio.NewReader(io.LimitReader(conn, int64(rounds)*maxResponse))
	req := "GET " + path + " HTTP/1.1\r\nHost: " + name + "\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n"
	for i := 0; i < rounds; i++ {
		if _, err := io.WriteString(conn, req); err != nil {
			return fmt.Errorf("%w: %v", ErrShortExchange, err)
		}
		if err := readResponse(br); err != nil {
			return fmt.Errorf("%w: %v", ErrShortExchange, err)
		}
	}
	return nil
}

// readResponse reads one HTTP/1.1 response in full: any status (the
// exchange carried, whatever the page says), a body by Content-Length
// or chunked encoding. A response that closes the connection before
// the last round is short.
func readResponse(br *bufio.Reader) error {
	status, err := br.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.HasPrefix(status, "HTTP/1.") {
		return errors.New("not an HTTP answer")
	}
	length, chunked, closes := -1, false, false
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "content-length":
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 || n > maxResponse {
				return errors.New("bad content-length")
			}
			length = n
		case "transfer-encoding":
			chunked = strings.EqualFold(v, "chunked")
		case "connection":
			closes = strings.EqualFold(v, "close")
		}
	}
	switch {
	case chunked:
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return err
			}
			size, err := strconv.ParseInt(strings.TrimSpace(strings.SplitN(line, ";", 2)[0]), 16, 32)
			if err != nil || size < 0 || size > maxResponse {
				return errors.New("bad chunk")
			}
			if _, err := io.CopyN(io.Discard, br, size+2); err != nil {
				return err
			}
			if size == 0 {
				break
			}
		}
	case length >= 0:
		if _, err := io.CopyN(io.Discard, br, int64(length)); err != nil {
			return err
		}
	default:
		return errors.New("an answer with no length cannot be followed by another")
	}
	if closes {
		return errors.New("the edge closed the connection")
	}
	return nil
}
