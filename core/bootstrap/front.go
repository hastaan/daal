package bootstrap

// front.go — the recipient's fetch of an Apps Script mirror through
// Google's front (specs/relaypack-v1.md, "Mirror provider appsscript",
// "How a recipient fetches it"; docs/optional-addons-plan.md §3.2, work
// item G4; blackout plan C1/C5).
//
// ONE ATTEMPT IS ONE CONNECTION:
//
//	dial      www.google.com:443 through the caller's dialer (system DNS);
//	          if — and only if — the NAME did not resolve, one shipped
//	          front address instead. A refused or timed-out dial is not
//	          retried elsewhere: that is a connection that was made and
//	          failed, and it counts.
//	hello     uTLS's Chrome hello (metacubex/utls HelloChrome_Auto), SNI
//	          www.google.com, certificate verified for that name against
//	          the system roots. ALPN must come back h2.
//	request   HTTP/2 GET, :authority script.google.com, the mirror's
//	          path and query (h2mini.go).
//	redirect  a 3xx is followed exactly once, and only to an https URL on
//	          script.googleusercontent.com (no port, no credentials), as
//	          a second stream on the SAME connection with that authority.
//	          A second redirect, or one anywhere else, ends the attempt.
//	read      at most 64 KiB of body; more is an error, never a
//	          truncation.
//
// If the fronted attempt fails for a reason of the NETWORK (dial, TLS,
// HTTP/2 framing, a timeout), one plain attempt follows: the same, with
// SNI and certificate name script.google.com. An answer FROM Google — a
// 404 for a deleted script, a refused redirect — is not retried: the
// plain route reaches the same Google and would get the same answer.
// So a walk makes at most two connections to Google.
//
// The URL is never logged and never put in an error.

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	utls "github.com/metacubex/utls"
)

const (
	// GoogleFrontSNI is the name the fronted attempt shows on the wire.
	GoogleFrontSNI = "www.google.com"
	// AppsScriptHost is the authority every Apps Script mirror names.
	AppsScriptHost = "script.google.com"
	// AppsScriptRedirectHost is the one host a redirect may lead to.
	AppsScriptRedirectHost = "script.googleusercontent.com"
	// FrontMaxBody bounds the body read through the front: the
	// daal-refresh-v2 container's own limit.
	FrontMaxBody = 64 << 10
)

// DefaultGoogleFrontAddrs is the short shipped list a fronted attempt
// dials when the system resolver cannot resolve www.google.com at all.
// 216.239.38.120 is forcesafesearch.google.com, a long-lived Google
// front address that serves www.google.com. Unverified from inside Iran
// (GATE G-2).
var DefaultGoogleFrontAddrs = []string{"216.239.38.120"}

// FrontOptions adjusts FetchAppsScript. The zero value is production.
type FrontOptions struct {
	// RootCAs replaces the system roots (tests).
	RootCAs *x509.CertPool
	// FrontAddrs replaces DefaultGoogleFrontAddrs. Only the first one
	// is ever dialled in an attempt.
	FrontAddrs []string
	// MaxBody replaces FrontMaxBody when positive and smaller.
	MaxBody int
}

// FrontResult says how a fetch went.
type FrontResult struct {
	Body []byte
	// ViaFront: the fronted attempt carried it; false when the plain
	// one did.
	ViaFront bool
	// Connections is how many connections were attempted (1 or 2).
	Connections int
}

// ErrFrontRefused is an answer from Google that a second route would
// not change: a non-200 status, a redirect that is not allowed, a
// second redirect. Callers treat it as "this mirror has nothing for
// us", like any mirror's 404.
var ErrFrontRefused = errors.New("fetcher: the update channel did not answer with a document")

// frontErr wraps a network-shaped failure so FetchAppsScript knows the
// plain attempt is worth making.
type frontNetErr struct{ err error }

func (e *frontNetErr) Error() string { return e.err.Error() }
func (e *frontNetErr) Unwrap() error { return e.err }

// FetchAppsScript fetches an Apps Script mirror URL
// (https://script.google.com/macros/s/<id>/exec?k=<token>) the way a
// recipient does. timeout bounds each of the (at most two) attempts;
// ctx bounds the whole.
func FetchAppsScript(ctx context.Context, rawURL string, dialer Dialer, timeout time.Duration, opts FrontOptions) (FrontResult, error) {
	var res FrontResult
	path, err := appsScriptRequestPath(rawURL)
	if err != nil {
		return res, err
	}
	if dialer == nil {
		dialer = NewDirectDialer(timeout)
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	maxBody := FrontMaxBody
	if opts.MaxBody > 0 && opts.MaxBody < maxBody {
		maxBody = opts.MaxBody
	}
	var last error
	for _, sni := range []string{GoogleFrontSNI, AppsScriptHost} {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		res.Connections++
		body, err := frontAttempt(ctx, dialer, timeout, sni, path, maxBody, opts)
		if err == nil {
			res.Body = body
			res.ViaFront = sni == GoogleFrontSNI
			return res, nil
		}
		last = err
		var ne *frontNetErr
		if !errors.As(err, &ne) {
			// Google answered; the other route reaches the same
			// Google.
			return res, err
		}
	}
	return res, last
}

// appsScriptRequestPath checks the URL is an https URL on
// script.google.com with no port and no credentials, and returns its
// path and query. The exact mirror shape (id, k) is the caller's to
// enforce (core/refresh); this layer only refuses to send the request
// anywhere else.
func appsScriptRequestPath(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host != AppsScriptHost || u.User != nil || u.Fragment != "" {
		return "", errors.New("fetcher: not an Apps Script address")
	}
	p := u.EscapedPath()
	if !strings.HasPrefix(p, "/") {
		return "", errors.New("fetcher: not an Apps Script address")
	}
	if u.RawQuery != "" {
		p += "?" + u.RawQuery
	}
	return p, nil
}

// frontAttempt is one connection: dial, Chrome hello with SNI sni, GET
// on authority script.google.com, at most one allowed redirect on the
// same connection.
func frontAttempt(ctx context.Context, dialer Dialer, timeout time.Duration, sni, path string, maxBody int, opts FrontOptions) ([]byte, error) {
	actx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	raw, err := dialFront(actx, dialer, sni, opts)
	if err != nil {
		return nil, &frontNetErr{fmt.Errorf("fetcher: dial: %w", err)}
	}
	defer raw.Close()
	stop := context.AfterFunc(actx, func() { _ = raw.SetDeadline(time.Now()) })
	defer stop()
	if dl, ok := actx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	}

	uc := utls.UClient(raw, &utls.Config{
		ServerName: sni,
		RootCAs:    opts.RootCAs,
		MinVersion: utls.VersionTLS12,
	}, utls.HelloChrome_Auto)
	if err := uc.HandshakeContext(actx); err != nil {
		return nil, &frontNetErr{fmt.Errorf("fetcher: tls handshake: %w", err)}
	}
	if alpn := uc.ConnectionState().NegotiatedProtocol; alpn != "h2" {
		// Google's front always speaks h2 to a Chrome hello. Anything
		// else is not the front (a middlebox, a captive portal).
		return nil, &frontNetErr{fmt.Errorf("fetcher: the front did not speak HTTP/2 (%q)", alpn)}
	}

	// Every byte read is bounded: two responses' bodies, their
	// headers, and the connection's own frames.
	c, err := newH2Client(uc, 2*maxBody+4*h2MaxHeaderBlock+64<<10)
	if err != nil {
		return nil, &frontNetErr{err}
	}
	authority, reqPath := AppsScriptHost, path
	for hop := 0; ; hop++ {
		resp, err := c.get(authority, reqPath, maxBody)
		if err != nil {
			if errors.Is(err, ErrResponseTooLarge) {
				return nil, err
			}
			return nil, &frontNetErr{err}
		}
		switch {
		case resp.status == 200:
			if enc, ok := resp.header("content-encoding"); ok && !strings.EqualFold(enc, "identity") {
				return nil, fmt.Errorf("%w: encoded answer", ErrFrontRefused)
			}
			return resp.body, nil
		case resp.status >= 300 && resp.status < 400:
			if hop > 0 {
				return nil, fmt.Errorf("%w: more than one redirect", ErrFrontRefused)
			}
			loc, _ := resp.header("location")
			p, err := allowedRedirect(loc)
			if err != nil {
				return nil, err
			}
			authority, reqPath = AppsScriptRedirectHost, p
		default:
			return nil, fmt.Errorf("%w: HTTP %d", ErrFrontRefused, resp.status)
		}
	}
}

// allowedRedirect accepts a Location only when it is an absolute https
// URL on script.googleusercontent.com, without port or credentials, and
// returns its path and query.
func allowedRedirect(loc string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(loc))
	if err != nil || u.Scheme != "https" || u.Host != AppsScriptRedirectHost || u.User != nil {
		return "", fmt.Errorf("%w: redirect refused", ErrFrontRefused)
	}
	p := u.EscapedPath()
	if !strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("%w: redirect refused", ErrFrontRefused)
	}
	if u.RawQuery != "" {
		p += "?" + u.RawQuery
	}
	return p, nil
}

// dialFront dials sni:443 through dialer; when the name does not
// resolve, the first shipped front address instead (Google's front
// serves both names on every address).
func dialFront(ctx context.Context, dialer Dialer, sni string, opts FrontOptions) (net.Conn, error) {
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(sni, "443"))
	if err == nil {
		return conn, nil
	}
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) {
		return nil, err
	}
	addrs := opts.FrontAddrs
	if addrs == nil {
		addrs = DefaultGoogleFrontAddrs
	}
	if len(addrs) == 0 || net.ParseIP(addrs[0]) == nil {
		return nil, err
	}
	return dialer.DialContext(ctx, "tcp", net.JoinHostPort(addrs[0], strconv.Itoa(443)))
}
