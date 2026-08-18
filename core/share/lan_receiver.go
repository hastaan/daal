package share

import (
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

// ErrShareBodyTooLarge is returned when a pinned peer sends more than a
// bundle could legitimately be. Sharing the parser's ceiling keeps
// "what we will read" and "what we will parse" from drifting apart.
var ErrShareBodyTooLarge = errors.New("share: response exceeds bundle size limit")

// PullURL fetches a single .sbp from a sender's HTTPS endpoint.
//
// CC.6: this function does NOT use net/http; it speaks a minimal HTTP/1.1
// over a tls.Dial connection. We deliberately do not trust the system root
// CA pool — the cert is self-signed per session — and we never resolve a
// name, so no DNS query announces the pull.
//
// Trust comes from exactly two checks, both fail-closed:
//
//  1. host MUST be a private IP literal (requirePrivateHost). A hostile
//     mDNS TXT record or doctored QR cannot steer the receiver off-LAN.
//  2. expectedSPKI MUST be the base64url SHA-256 of the sender's
//     SubjectPublicKeyInfo, as published in the TXT record / QR. It is
//     compared in constant time inside the TLS handshake, so the bearer
//     token is never written to a peer that failed the pin. An empty or
//     malformed pin is an ERROR, never a skip.
//
// pin is the 6-digit PIN the user typed; it authenticates the receiver TO
// the sender and is unrelated to the SPKI pin, which authenticates the
// sender to the receiver.
func PullURL(host string, port int, pin, sessionID, expectedSPKI string, timeoutMs int) ([]byte, error) {
	if host == "" || port <= 0 || port > 65535 {
		return nil, errors.New("share: bad host/port")
	}
	if err := requirePrivateHost(host); err != nil {
		return nil, err
	}
	cfg, err := pinnedTLSConfig(expectedSPKI)
	if err != nil {
		return nil, err
	}
	tok := DeriveBearerToken(pin, sessionID)
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: durationMs(timeoutMs)}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, cfg)
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
	// Bound the response. The SPKI pin authenticates WHO the peer is; it
	// says nothing about how much they may send, and in this wave the
	// receiver reaches this code by scanning a QR the other party is
	// holding up — a hostile sender is squarely in scope. Without a
	// ceiling, a peer that passes the pin can stream for the whole
	// deadline (a gigabyte on a fast LAN) straight into memory, and then
	// hand the result to a decompressor.
	//
	// The +1 makes an over-long body detectable rather than silently
	// truncated into a corrupt bundle: we must refuse it, not parse it.
	limit := int64(bundle.MaxArchiveTotalBytes)
	body, err := io.ReadAll(io.LimitReader(conn, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, ErrShareBodyTooLarge
	}
	return splitHTTPBody(body)
}

// PullTarget is PullURL for an already-parsed Target. A Target cannot be
// constructed without a well-formed pin and a private address, so this is
// the shape callers should prefer.
func PullTarget(t Target, pin string, timeoutMs int) ([]byte, error) {
	return PullURL(t.Host, t.Port, pin, t.SessionID, t.SPKI, timeoutMs)
}

// PullArbitraryURL handles the QR-encoded fallback for mDNS-filtered
// networks. It accepts either the `daalshare://lan?u=..&p=..&s=..` wrapper
// or a bare `https://<private-ip>:<port>/bundle.sbp#spki=..`; in both
// shapes the SPKI pin travels with the URL, so there is no way to reach
// this path without one.
//
// sessionID, when non-empty, overrides whatever the URI carried — the
// caller's own record of the session is more trustworthy than the QR's.
func PullArbitraryURL(rawURI, pin, sessionID string, timeoutMs int) ([]byte, error) {
	t, err := ParseShareTarget(rawURI)
	if err != nil {
		return nil, err
	}
	if sessionID != "" {
		t.SessionID = sessionID
	}
	return PullTarget(t, pin, timeoutMs)
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
