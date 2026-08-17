package bootstrap

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"daal/bundle-go/bundle"
)

// Dialer is an abstraction over net.Dial that lets the fetcher route
// through a tunnel when one is up. The default implementation is just
// `net.Dial`. The TunnelDialer in fetcher_dialer.go connects through the
// active sing-box outbound's local SOCKS5 inlet.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type directDialer struct{ d net.Dialer }

func (d *directDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.d.DialContext(ctx, network, address)
}

// NewDirectDialer returns a Dialer that bypasses any tunnel.
func NewDirectDialer(timeout time.Duration) Dialer {
	return &directDialer{d: net.Dialer{Timeout: timeout}}
}

// FetchResult carries the bytes and the verdict on whether the fetched
// .sbp's publisher fingerprint matched the pointer's pin.
type FetchResult struct {
	Bytes                []byte
	PublisherFingerprint string
}

// Fetch reads `url` (https://host:port/path) using `dialer`, with a hard
// `timeout`, and verifies that the returned body parses as a .sbp whose
// publisher fingerprint matches `expectedFingerprintHex`. It does not run
// the importer's trust/policy logic — that is the caller's job.
//
// HTTP semantics are intentionally minimal: GET / one-shot, Connection:
// close, no cookies, no redirects. If the server returns 3xx we treat it
// as `subscription_unreachable`. The request headers are shaped like a
// browser's — see requestUserAgent for why "no User-Agent" was a
// distinguisher rather than an absence.
//
// The fetcher must NOT import net/http. It speaks raw HTTP/1.1 over
// tls.Conn so the OPSEC source-grep test stays clean.
func Fetch(ctx context.Context, url, expectedFingerprintHex string, dialer Dialer, timeout time.Duration) (FetchResult, error) {
	respBody, err := FetchRaw(ctx, url, dialer, timeout)
	if err != nil {
		return FetchResult{}, err
	}
	parsed, err := bundle.ParseSBP(bytes.NewReader(respBody), int64(len(respBody)))
	if err != nil {
		return FetchResult{}, fmt.Errorf("fetcher: parse: %w", err)
	}
	fp := bundle.PublisherFingerprint(parsed.PublisherPub)
	if expectedFingerprintHex != "" && !strings.EqualFold(fp.Hex, expectedFingerprintHex) {
		return FetchResult{}, fmt.Errorf("fetcher: fingerprint pin mismatch (got %s, expected %s)",
			fp.Hex, expectedFingerprintHex)
	}
	return FetchResult{Bytes: respBody, PublisherFingerprint: fp.Hex}, nil
}

// FetchRaw is the body-only variant of Fetch. It applies the same minimal
// HTTP/1.1 semantics (no cookies, no redirects, no net/http), honours
// Content-Length and chunked framing, and returns the response body
// bytes. Phase 1.5A's
// subscription and revocation refreshers use FetchRaw because the
// returned bodies are NOT .sbp archives.
//
// The URL is never logged.
func FetchRaw(ctx context.Context, url string, dialer Dialer, timeout time.Duration) ([]byte, error) {
	if !strings.HasPrefix(url, "https://") {
		return nil, fmt.Errorf("fetcher: only https accepted")
	}
	host, port, path, err := splitHTTPSURL(url)
	if err != nil {
		return nil, err
	}
	if dialer == nil {
		dialer = NewDirectDialer(timeout)
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	rawConn, err := dialer.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("fetcher: dial: %w", err)
	}
	defer rawConn.Close()

	tlsCfg := &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	}
	tlsConn := tls.Client(rawConn, tlsCfg)
	tlsConn.SetDeadline(time.Now().Add(timeout))
	if err := tlsConn.HandshakeContext(dialCtx); err != nil {
		return nil, fmt.Errorf("fetcher: tls handshake: %w", err)
	}

	req := buildRequest(path, host, port)
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		return nil, fmt.Errorf("fetcher: write: %w", err)
	}
	body, err := io.ReadAll(tlsConn)
	if err != nil {
		return nil, fmt.Errorf("fetcher: read: %w", err)
	}
	return splitHTTPResponse(body)
}

// requestUserAgent is a common desktop-browser UA string.
//
// WHY THIS FILE NO LONGER SENDS A DISTINCTIVE REQUEST. The mitigation
// this whole design leans on is "put the freshness document on a host
// that serves other traffic, so a fetch is not self-identifying". That
// buys nothing if Daal's requests are separable from that traffic in
// one grep of the access log — and they were: no User-Agent at all,
// `Accept: application/octet-stream`, and a Host header carrying the
// default port (`Host: example.com:443`, which no browser sends). At
// the origin, or in a compelled/leaked log, that triple enumerates
// every recipient of a publisher by source IP and by timestamp. The
// request now looks like a browser fetching a static file, which is
// what it is.
//
// This does not hide anything from an on-path observer — the request
// is inside TLS. It closes the ORIGIN-side and log-side distinguisher,
// which is the one the "share a host with real traffic" advice depends
// on.
const requestUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

// buildRequest renders the one-shot GET. Host omits the port when it is
// the scheme default, matching every browser and every curl.
func buildRequest(path, host string, port int) string {
	hostHeader := host
	if port != 443 {
		hostHeader = net.JoinHostPort(host, strconv.Itoa(port))
	}
	return fmt.Sprintf(
		"GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
		path, hostHeader, requestUserAgent)
}

func splitHTTPSURL(u string) (host string, port int, path string, err error) {
	rest := strings.TrimPrefix(u, "https://")
	slash := strings.Index(rest, "/")
	hostPart := rest
	path = "/"
	if slash >= 0 {
		hostPart = rest[:slash]
		path = rest[slash:]
	}
	if i := strings.Index(hostPart, ":"); i >= 0 {
		host = hostPart[:i]
		port, err = strconv.Atoi(hostPart[i+1:])
		if err != nil {
			return "", 0, "", fmt.Errorf("fetcher: bad port: %w", err)
		}
	} else {
		host = hostPart
		port = 443
	}
	if host == "" {
		return "", 0, "", errors.New("fetcher: empty host")
	}
	return host, port, path, nil
}

func splitHTTPResponse(raw []byte) ([]byte, error) {
	idx := bytes.Index(raw, []byte("\r\n\r\n"))
	if idx < 0 {
		return nil, errors.New("fetcher: malformed HTTP response")
	}
	header := string(raw[:idx])
	body := raw[idx+4:]
	statusLine := strings.SplitN(header, "\r\n", 2)[0]
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 3 {
		return nil, fmt.Errorf("fetcher: bad status line %q", statusLine)
	}
	if !strings.HasPrefix(parts[0], "HTTP/1.") {
		return nil, fmt.Errorf("fetcher: bad protocol %q", parts[0])
	}
	if parts[1] != "200" {
		return nil, fmt.Errorf("fetcher: non-200 status %s", parts[1])
	}
	// FRAMING. "Everything after the blank line is the body" is only
	// correct for an identity-encoded response with Connection: close,
	// which is what the bootstrap directory host happened to send. A
	// CDN-fronted object — and the freshness mirrors are explicitly
	// CDN-fronted static hosting — routinely answers with
	// `Transfer-Encoding: chunked`, and the old rule then returned a
	// body with hex chunk-size lines embedded in it. That fails JSON
	// parsing, and the caller reports the mirror as unreachable: a
	// working endpoint indistinguishable from a censored one, which is
	// the single worst way for this layer to fail.
	if isChunked(header) {
		return dechunk(body)
	}
	if n, ok := contentLength(header); ok && n >= 0 && n <= len(body) {
		return body[:n], nil
	}
	return body, nil
}

// headerValue returns the first value of a header, case-insensitively.
func headerValue(header, name string) (string, bool) {
	for _, line := range strings.Split(header, "\r\n")[1:] {
		k, v, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(k), name) {
			return strings.TrimSpace(v), true
		}
	}
	return "", false
}

func isChunked(header string) bool {
	v, ok := headerValue(header, "Transfer-Encoding")
	return ok && strings.Contains(strings.ToLower(v), "chunked")
}

func contentLength(header string) (int, bool) {
	v, ok := headerValue(header, "Content-Length")
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0, false
	}
	return n, true
}

// dechunk decodes RFC 7230 chunked framing.
//
// Deliberately strict and allocation-bounded: it refuses a negative or
// absurd chunk size and stops at the first zero-length chunk rather
// than trusting a trailer. The input is attacker-influenced bytes from
// a host that may be hostile, and every caller has its own size cap
// above this, so the failure mode to avoid is unbounded growth here.
func dechunk(body []byte) ([]byte, error) {
	const maxChunk = 8 << 20
	out := make([]byte, 0, len(body))
	for {
		idx := bytes.Index(body, []byte("\r\n"))
		if idx < 0 {
			return nil, errors.New("fetcher: truncated chunked response")
		}
		sizeLine := string(body[:idx])
		if semi := strings.IndexByte(sizeLine, ';'); semi >= 0 {
			sizeLine = sizeLine[:semi] // chunk extensions
		}
		size, err := strconv.ParseInt(strings.TrimSpace(sizeLine), 16, 64)
		if err != nil || size < 0 || size > maxChunk {
			return nil, fmt.Errorf("fetcher: bad chunk size %q", sizeLine)
		}
		body = body[idx+2:]
		if size == 0 {
			return out, nil
		}
		if int64(len(body)) < size+2 {
			return nil, errors.New("fetcher: truncated chunk")
		}
		out = append(out, body[:size]...)
		body = body[size+2:]
	}
}
