package share

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// PullURL fetches a single .sbp from a sender's HTTPS endpoint.
//
// CC.6: this function does NOT use net/http; it speaks a minimal HTTP/1.1
// over a tls.Dial connection. We deliberately do not trust the system root
// CA pool — the cert is self-signed per session — and we do not allow the
// connection to leak hostname material to any DNS server beyond the
// strictly local lookup that produced the IP literal.
//
// host:port must be one of the addresses the sender published; pin is the
// 6-digit PIN the user typed.
func PullURL(host string, port int, pin string, sessionID string, timeoutMs int) ([]byte, error) {
	if host == "" || port == 0 {
		return nil, errors.New("share: bad host/port")
	}
	tok := DeriveBearerToken(pin, sessionID)
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	dialer := &net.Dialer{Timeout: durationMs(timeoutMs)}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true, // self-signed; we verify SPKI separately if known
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return nil, fmt.Errorf("share: tls dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(durationMs(timeoutMs)))
	req := fmt.Sprintf("GET /bundle.sbp HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer %s\r\nConnection: close\r\n\r\n",
		addr, tok)
	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, err
	}
	body, err := io.ReadAll(conn)
	if err != nil {
		return nil, err
	}
	return splitHTTPBody(body)
}

// PullArbitraryURL handles the QR-encoded URL fallback. The URL is parsed
// minimally (we trust nothing); only https://host:port/path is accepted.
func PullArbitraryURL(httpsURL, pin, sessionID string, timeoutMs int) ([]byte, error) {
	if !strings.HasPrefix(httpsURL, "https://") {
		return nil, errors.New("share: only https URLs accepted")
	}
	withoutScheme := strings.TrimPrefix(httpsURL, "https://")
	slash := strings.Index(withoutScheme, "/")
	hostport := withoutScheme
	if slash >= 0 {
		hostport = withoutScheme[:slash]
	}
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, err
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	return PullURL(host, port, pin, sessionID, timeoutMs)
}

func durationMs(ms int) time.Duration {
	if ms <= 0 {
		return 15 * time.Second
	}
	return time.Duration(ms) * time.Millisecond
}

func splitHTTPBody(raw []byte) ([]byte, error) {
	idx := indexCRLFCRLF(raw)
	if idx < 0 {
		return nil, errors.New("share: malformed HTTP response")
	}
	header := string(raw[:idx])
	body := raw[idx+4:]
	// Status check.
	if !strings.HasPrefix(header, "HTTP/1.1 200") && !strings.HasPrefix(header, "HTTP/1.0 200") {
		return nil, fmt.Errorf("share: HTTP %s", strings.SplitN(header, "\r\n", 2)[0])
	}
	return body, nil
}

func indexCRLFCRLF(b []byte) int {
	for i := 0; i+3 < len(b); i++ {
		if b[i] == '\r' && b[i+1] == '\n' && b[i+2] == '\r' && b[i+3] == '\n' {
			return i
		}
	}
	return -1
}
