package bootstrap

// browserget.go — a plain HTTPS GET shaped like a browser's (study
// docs/update-ladder-v2.md §4.1 "Fetcher", build order lane 1D): the
// readers of the update-note carriers (core/refresh/carrier_*.go) fetch
// a tag feed, a version list or a small file from a public host with it.
//
// ONE CALL IS ONE CONNECTION, ONE REQUEST:
//
//	dial      host:443 through the caller's Dialer (the refresh code's;
//	          never a dialer of its own when one is given).
//	hello     uTLS's Chrome hello (HelloChrome_Auto), the one front.go
//	          uses, with SNI EQUAL to the host (no fronting), the
//	          certificate verified for that name.
//	request   GET on HTTP/2 (h2mini.go) when the server picks h2, which
//	          every host these readers name does; HTTP/1.1 with
//	          Connection: close otherwise. Browser headers; the accept
//	          header is the caller's.
//	redirect  never followed. A 3xx comes back as a status for the caller
//	          to judge ("not here"), its Location unread.
//	read      at most MaxBody bytes of body (64 KiB by default); more is
//	          ErrResponseTooLarge, never a truncation. A body that is not
//	          identity-encoded is refused.
//	deadline  Timeout bounds the whole call, dial included; ctx too.
//
// Nothing is logged, and neither the host's path nor any body byte is
// put in an error: the path names a repository and a note.

import (
	"bufio"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	utls "github.com/metacubex/utls"
)

const (
	// BrowserGetMaxBody is the default bound on a body.
	BrowserGetMaxBody = 64 << 10
	// BrowserGetMaxBodyLimit is the most a caller may ask for: a sealed
	// full note's text (bundle.MaxSealedFullNoteText, 87 436
	// characters) with any carrier's wrapping fits.
	BrowserGetMaxBodyLimit = 256 << 10
	// browserMaxHeader bounds an HTTP/1.1 response's head.
	browserMaxHeader = 16 << 10
)

// BrowserGetOptions adjusts BrowserGet. The zero value is production.
type BrowserGetOptions struct {
	// Accept is the request's accept header ("" = "*/*").
	Accept string
	// MaxBody bounds the body (0 = BrowserGetMaxBody; at most
	// BrowserGetMaxBodyLimit).
	MaxBody int
	// Timeout bounds the whole call (0 = 15 s).
	Timeout time.Duration
	// RootCAs replaces the system roots (tests).
	RootCAs *x509.CertPool
}

// BrowserResponse is one answer. Body is set for every status (bounded
// the same way); callers use it only for a 200.
type BrowserResponse struct {
	Status int
	Body   []byte
	// ContentType is the answer's content-type header, "" when absent.
	ContentType string
	// HTTP2 reports the answer came over HTTP/2.
	HTTP2 bool
}

// BrowserGet GETs https://host/path. host is a DNS name without port;
// path an absolute path with optional query. An error is a failure of
// the network or of the answer's framing (refused, reset, timed out, an
// untrusted certificate, too large); an answer of any status is not.
func BrowserGet(ctx context.Context, dialer Dialer, host, path string, opts BrowserGetOptions) (*BrowserResponse, error) {
	if !browserHostOK(host) {
		return nil, errors.New("fetcher: not a host name")
	}
	if !frontPathOK(path) {
		return nil, errors.New("fetcher: not a request path")
	}
	if !headerValueOK(opts.Accept) {
		return nil, errors.New("fetcher: bad accept header")
	}
	maxBody := BrowserGetMaxBody
	if opts.MaxBody > 0 {
		if opts.MaxBody > BrowserGetMaxBodyLimit {
			return nil, errors.New("fetcher: body bound too large")
		}
		maxBody = opts.MaxBody
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	if dialer == nil {
		dialer = NewDirectDialer(timeout)
	}
	actx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	raw, err := dialer.DialContext(actx, "tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		return nil, fmt.Errorf("fetcher: dial: %w", err)
	}
	defer raw.Close()
	stop := context.AfterFunc(actx, func() { _ = raw.SetDeadline(time.Now()) })
	defer stop()
	if dl, ok := actx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	}

	uc := utls.UClient(raw, &utls.Config{
		ServerName: host,
		RootCAs:    opts.RootCAs,
		MinVersion: utls.VersionTLS12,
	}, utls.HelloChrome_Auto)
	if err := uc.HandshakeContext(actx); err != nil {
		return nil, fmt.Errorf("fetcher: tls handshake: %w", err)
	}

	var resp *BrowserResponse
	if uc.ConnectionState().NegotiatedProtocol == "h2" {
		resp, err = browserGetH2(uc, host, path, opts.Accept, maxBody)
	} else {
		resp, err = browserGetH1(uc, host, path, opts.Accept, maxBody)
	}
	if err != nil {
		if actx.Err() != nil && !errors.Is(err, ErrResponseTooLarge) {
			return nil, fmt.Errorf("fetcher: %w", actx.Err())
		}
		return nil, err
	}
	return resp, nil
}

func browserGetH2(conn net.Conn, host, path, accept string, maxBody int) (*BrowserResponse, error) {
	c, err := newH2Client(conn, maxBody+2*h2MaxHeaderBlock+64<<10)
	if err != nil {
		return nil, err
	}
	r, err := c.getAccept(host, path, accept, maxBody)
	if err != nil {
		return nil, err
	}
	out := &BrowserResponse{Status: r.status, Body: r.body, HTTP2: true}
	out.ContentType, _ = r.header("content-type")
	if enc, ok := r.header("content-encoding"); ok && !strings.EqualFold(enc, "identity") {
		return nil, errors.New("fetcher: encoded answer")
	}
	return out, nil
}

// browserGetH1 is the HTTP/1.1 form: one request, Connection: close,
// the head bounded, the body framed by Content-Length or chunked (read
// as it arrives, so a server that keeps the connection open anyway does
// not hold us to the deadline), or by the close.
func browserGetH1(conn net.Conn, host, path, accept string, maxBody int) (*BrowserResponse, error) {
	if accept == "" {
		accept = h2DefaultAccept
	}
	req := "GET " + path + " HTTP/1.1\r\nHost: " + host +
		"\r\nUser-Agent: " + requestUserAgent +
		"\r\nAccept: " + accept +
		"\r\nAccept-Encoding: identity\r\nAccept-Language: en-US,en;q=0.9\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		return nil, fmt.Errorf("fetcher: write: %w", err)
	}
	br := bufio.NewReaderSize(conn, 4096)
	head, err := readH1Head(br)
	if err != nil {
		return nil, err
	}
	statusLine, _, _ := strings.Cut(head, "\r\n")
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/1.") || len(parts[1]) != 3 {
		return nil, errors.New("fetcher: malformed HTTP response")
	}
	status, err := strconv.Atoi(parts[1])
	if err != nil || status < 100 || status > 999 {
		return nil, errors.New("fetcher: malformed HTTP status")
	}
	if status < 200 {
		// No 1xx is asked for (no Expect, no upgrade).
		return nil, errors.New("fetcher: unexpected informational answer")
	}
	out := &BrowserResponse{Status: status}
	out.ContentType, _ = headerValue(head, "Content-Type")
	if enc, ok := headerValue(head, "Content-Encoding"); ok && !strings.EqualFold(enc, "identity") {
		return nil, errors.New("fetcher: encoded answer")
	}
	switch {
	case status == 204 || status == 304:
		return out, nil
	case isChunked(head):
		out.Body, err = readChunked(br, maxBody)
	default:
		if v, ok := headerValue(head, "Content-Length"); ok {
			n, perr := strconv.Atoi(v)
			if perr != nil || n < 0 {
				return nil, errors.New("fetcher: bad content length")
			}
			if n > maxBody {
				return nil, ErrResponseTooLarge
			}
			out.Body = make([]byte, n)
			if _, err = io.ReadFull(br, out.Body); err != nil {
				err = fmt.Errorf("fetcher: read: %w", err)
			}
		} else {
			out.Body, err = readBounded(br, maxBody)
		}
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}

// readH1Head reads up to and including the blank line, bounded.
func readH1Head(br *bufio.Reader) (string, error) {
	var sb strings.Builder
	for {
		line, err := br.ReadSlice('\n')
		if sb.Len()+len(line) > browserMaxHeader {
			return "", errors.New("fetcher: response head too long")
		}
		if err != nil {
			return "", fmt.Errorf("fetcher: read: %w", err)
		}
		if len(line) <= 2 && strings.TrimRight(string(line), "\r\n") == "" {
			return strings.TrimSuffix(sb.String(), "\r\n"), nil
		}
		sb.Write(line)
	}
}

// readChunked decodes chunked framing as it is read, bounded by max.
func readChunked(br *bufio.Reader, max int) ([]byte, error) {
	var out []byte
	for {
		line, err := br.ReadSlice('\n')
		if err != nil || len(line) > 256 {
			return nil, errors.New("fetcher: malformed chunked answer")
		}
		sizeText := strings.TrimSpace(string(line))
		if semi := strings.IndexByte(sizeText, ';'); semi >= 0 {
			sizeText = strings.TrimSpace(sizeText[:semi])
		}
		size, err := strconv.ParseInt(sizeText, 16, 64)
		if err != nil || size < 0 {
			return nil, errors.New("fetcher: malformed chunked answer")
		}
		if size == 0 {
			// Trailers are not read: the body is complete.
			return out, nil
		}
		if int64(len(out))+size > int64(max) {
			return nil, ErrResponseTooLarge
		}
		start := len(out)
		out = append(out, make([]byte, size)...)
		if _, err := io.ReadFull(br, out[start:]); err != nil {
			return nil, fmt.Errorf("fetcher: read: %w", err)
		}
		var crlf [2]byte
		if _, err := io.ReadFull(br, crlf[:]); err != nil || crlf != [2]byte{'\r', '\n'} {
			return nil, errors.New("fetcher: malformed chunked answer")
		}
	}
}

// browserHostOK: a lowercase DNS name of two or more labels, no port,
// not an address (SNI must be a name).
func browserHostOK(h string) bool {
	if len(h) == 0 || len(h) > 253 || net.ParseIP(h) != nil {
		return false
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// headerValueOK: printable ASCII and spaces only (no CR or LF), short.
func headerValueOK(v string) bool {
	if len(v) > 512 {
		return false
	}
	for i := 0; i < len(v); i++ {
		if c := v[i]; c < ' ' || c >= 0x7f {
			return false
		}
	}
	return true
}
