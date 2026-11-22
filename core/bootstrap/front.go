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
// So one Apps Script fetch makes at most two connections to Google. The
// fronted Go-proxy reader (core/refresh, carrier_goproxy.go) makes one
// (FrontSession), and the update ladder skips it when the walk's Apps
// Script fetches already made two: a walk makes at most two connections
// to Google in all.
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
	// GoProxyHost is Google's Go module proxy (docs/update-ladder-v2.md
	// §4.2 door 3): it serves the git-tag note write's version list and
	// go.mod through the same front.
	GoProxyHost = "proxy.golang.org"
	// FrontMaxBodyLimit is the most any caller may ask the front to read
	// (FrontOptions.MaxBody above FrontMaxBody): a sealed full note's
	// text with its go.mod wrapping (bundle.MaxSealedFullNoteText is
	// 87 436 characters) fits with room to spare.
	FrontMaxBodyLimit = 128 << 10
)

// frontAuthorities is the closed list of authorities a fetch through
// the front may name (study §4.2 "Fetcher"). Apps Script is fetched by
// FetchAppsScript (one allowed redirect, a plain second attempt); every
// other authority by FetchFronted (no redirect, one connection).
// *.cdn.ampproject.org (door 2) is not built yet and is not in it.
var frontAuthorities = map[string]bool{
	AppsScriptHost: true,
	GoProxyHost:    true,
}

// FrontAuthorityAllowed reports whether a fetch through the front may
// name authority.
func FrontAuthorityAllowed(authority string) bool { return frontAuthorities[authority] }

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
	// MaxBody replaces FrontMaxBody when positive and smaller. For
	// FetchFronted it may be larger, up to FrontMaxBodyLimit.
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
		body, err := frontAttempt(ctx, dialer, timeout, sni, AppsScriptHost, true, path, maxBody, opts)
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

// FetchFronted fetches path on authority (one of the closed list other
// than Apps Script, e.g. GoProxyHost) through Google's front: one
// connection, SNI www.google.com, the same dial, hello, HTTP/2 and
// bounded read as FetchAppsScript, and NO redirect (a 3xx is
// ErrFrontRefused). There is no plain second attempt: a direct read of
// the same host is a different carrier, with its own budget. path is
// an absolute path with an optional query, sent as it is. Neither the
// authority's path nor the body is put in an error.
func FetchFronted(ctx context.Context, authority, path string, dialer Dialer, timeout time.Duration, opts FrontOptions) (FrontResult, error) {
	var res FrontResult
	if authority == AppsScriptHost || !FrontAuthorityAllowed(authority) {
		return res, errors.New("fetcher: not an authority the front may name")
	}
	if !frontPathOK(path) {
		return res, errors.New("fetcher: not a request path")
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	if dialer == nil {
		dialer = NewDirectDialer(timeout)
	}
	maxBody := FrontMaxBody
	if opts.MaxBody > 0 && opts.MaxBody <= FrontMaxBodyLimit {
		maxBody = opts.MaxBody
	}
	if err := ctx.Err(); err != nil {
		return res, err
	}
	res.Connections = 1
	body, err := frontAttempt(ctx, dialer, timeout, GoogleFrontSNI, authority, false, path, maxBody, opts)
	if err != nil {
		return res, err
	}
	res.Body, res.ViaFront = body, true
	return res, nil
}

// FrontSession is ONE connection to Google's front on which a caller
// sends successive GETs to one authority (FetchFronted's rules: SNI
// www.google.com, no redirect, bounded reads). The Go-proxy reader uses
// it so its list and .mod requests spend one connection, not two.
type FrontSession struct {
	authority string
	c         *h2Client
	closeConn func()
	cancel    context.CancelFunc
}

// OpenFrontSession dials the front for authority. timeout bounds the
// whole session; maxTotal bounds every body read on it together (up to
// 2·FrontMaxBodyLimit). Close it when done.
func OpenFrontSession(ctx context.Context, authority string, dialer Dialer, timeout time.Duration, maxTotal int, opts FrontOptions) (*FrontSession, error) {
	if authority == AppsScriptHost || !FrontAuthorityAllowed(authority) {
		return nil, errors.New("fetcher: not an authority the front may name")
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if dialer == nil {
		dialer = NewDirectDialer(timeout)
	}
	if maxTotal <= 0 || maxTotal > 2*FrontMaxBodyLimit {
		maxTotal = 2 * FrontMaxBodyLimit
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sctx, cancel := context.WithTimeout(ctx, timeout)
	c, closeConn, err := frontConnect(sctx, dialer, GoogleFrontSNI, opts, maxTotal+4*h2MaxHeaderBlock+64<<10)
	if err != nil {
		cancel()
		return nil, err
	}
	return &FrontSession{authority: authority, c: c, closeConn: closeConn, cancel: cancel}, nil
}

// Get sends one GET for path on the session's connection. A non-200
// answer is ErrFrontRefused.
func (s *FrontSession) Get(path string, maxBody int) ([]byte, error) {
	if !frontPathOK(path) {
		return nil, errors.New("fetcher: not a request path")
	}
	if maxBody <= 0 || maxBody > FrontMaxBodyLimit {
		maxBody = FrontMaxBodyLimit
	}
	return frontGet(s.c, s.authority, false, path, maxBody)
}

// Close ends the session's connection.
func (s *FrontSession) Close() {
	if s == nil {
		return
	}
	s.closeConn()
	s.cancel()
}

// frontPathOK: an absolute path (and query) of printable ASCII, no
// spaces, no fragment, of a sane length.
func frontPathOK(p string) bool {
	if len(p) == 0 || len(p) > 2048 || p[0] != '/' || strings.HasPrefix(p, "//") {
		return false
	}
	for i := 0; i < len(p); i++ {
		if c := p[i]; c <= ' ' || c >= 0x7f || c == '#' {
			return false
		}
	}
	return true
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
// on authority, and — only when redirect is set (Apps Script) — at most
// one allowed redirect on the same connection.
func frontAttempt(ctx context.Context, dialer Dialer, timeout time.Duration, sni, authority string, redirect bool, path string, maxBody int, opts FrontOptions) ([]byte, error) {
	actx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Every byte read is bounded: two responses' bodies, their
	// headers, and the connection's own frames.
	c, closeConn, err := frontConnect(actx, dialer, sni, opts, 2*maxBody+4*h2MaxHeaderBlock+64<<10)
	if err != nil {
		return nil, err
	}
	defer closeConn()
	return frontGet(c, authority, redirect, path, maxBody)
}

// frontConnect dials sni, makes the Chrome hello and starts HTTP/2 with
// readBudget bytes of reading in all. Network-shaped failures are
// frontNetErr. The caller closes with the returned func.
func frontConnect(actx context.Context, dialer Dialer, sni string, opts FrontOptions, readBudget int) (*h2Client, func(), error) {
	raw, err := dialFront(actx, dialer, sni, opts)
	if err != nil {
		return nil, nil, &frontNetErr{fmt.Errorf("fetcher: dial: %w", err)}
	}
	stop := context.AfterFunc(actx, func() { _ = raw.SetDeadline(time.Now()) })
	closeConn := func() { stop(); _ = raw.Close() }
	if dl, ok := actx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	}

	uc := utls.UClient(raw, &utls.Config{
		ServerName: sni,
		RootCAs:    opts.RootCAs,
		MinVersion: utls.VersionTLS12,
	}, utls.HelloChrome_Auto)
	if err := uc.HandshakeContext(actx); err != nil {
		closeConn()
		return nil, nil, &frontNetErr{fmt.Errorf("fetcher: tls handshake: %w", err)}
	}
	if alpn := uc.ConnectionState().NegotiatedProtocol; alpn != "h2" {
		// Google's front always speaks h2 to a Chrome hello. Anything
		// else is not the front (a middlebox, a captive portal).
		closeConn()
		return nil, nil, &frontNetErr{fmt.Errorf("fetcher: the front did not speak HTTP/2 (%q)", alpn)}
	}
	c, err := newH2Client(uc, readBudget)
	if err != nil {
		closeConn()
		return nil, nil, &frontNetErr{err}
	}
	return c, closeConn, nil
}

// frontGet is one GET (and, for Apps Script, at most one redirect) on an
// open front connection.
func frontGet(c *h2Client, authority string, redirect bool, path string, maxBody int) ([]byte, error) {
	reqPath := path
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
			if !redirect {
				return nil, fmt.Errorf("%w: redirect refused", ErrFrontRefused)
			}
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
