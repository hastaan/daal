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
// close, no User-Agent, no cookies, no redirects. If the server returns
// 3xx we treat it as `subscription_unreachable`.
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
// HTTP/1.1 semantics (no User-Agent, no cookies, no redirects, no
// net/http) and returns the response body bytes. Phase 1.5A's
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

	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nAccept: application/octet-stream\r\n\r\n",
		path, addr)
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		return nil, fmt.Errorf("fetcher: write: %w", err)
	}
	body, err := io.ReadAll(tlsConn)
	if err != nil {
		return nil, fmt.Errorf("fetcher: read: %w", err)
	}
	return splitHTTPResponse(body)
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
	// Honor Content-Length / Transfer-Encoding: chunked. For Phase 1D the
	// directory body is small (< 50 KB) and the server sends Content-Length
	// + Connection: close, so the simple "everything after \r\n\r\n is the
	// body" rule is correct. We still strip a trailing chunked-trailer
	// signature defensively.
	body = bytes.TrimSuffix(body, []byte("0\r\n\r\n"))
	return body, nil
}
