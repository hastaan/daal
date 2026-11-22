package appsscript

// The publisher's half of the channel after setup: one HTTPS POST per
// update (no Google sign-in, no token), and a fetch-back done the way a
// recipient fetches (specs/relaypack-v1.md, "How a recipient fetches
// it"): through the Google front first (SNI www.google.com, authority
// script.google.com), following exactly one redirect and only to
// script.googleusercontent.com, a bounded read of 64 KiB, then one plain
// attempt with SNI script.google.com. At most two connections per try.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"daal/publisher/deploy/freshness"
)

const (
	// FrontSNI is the name the fronted attempt shows on the wire.
	FrontSNI = "www.google.com"
	// RedirectHost is the one host a redirect may lead to.
	RedirectHost = "script.googleusercontent.com"
	// MaxRead bounds every response body read here.
	MaxRead = 64 << 10
)

// Network is how connections are made. The zero value dials the real
// hosts with the system roots; tests point Dial at a fake Google.
type Network struct {
	// Dial replaces the dialer (addr is always "<host>:443").
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// RootCAs replaces the system roots.
	RootCAs *x509.CertPool
	// Timeout bounds one attempt; zero means 30 s.
	Timeout time.Duration
}

// route is one way of reaching the script.
type route struct {
	name  string
	front bool
}

var routes = []route{{name: "front", front: true}, {name: "plain", front: false}}

func (n Network) client(r route) *http.Client {
	dial := n.Dial
	if dial == nil {
		d := &net.Dialer{Timeout: 15 * time.Second}
		dial = d.DialContext
	}
	tlsCfg := &tls.Config{RootCAs: n.RootCAs, MinVersion: tls.VersionTLS12}
	tr := &http.Transport{
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 15 * time.Second,
		MaxIdleConns:        2,
		DisableKeepAlives:   false,
		Proxy:               nil,
	}
	if r.front {
		// Every connection goes to the front's name, whatever host
		// the request is for; the request's authority says where
		// Google routes it.
		tlsCfg.ServerName = FrontSNI
		tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dial(ctx, network, net.JoinHostPort(FrontSNI, "443"))
		}
	} else {
		tr.DialContext = dial
	}
	tr.TLSClientConfig = tlsCfg
	timeout := n.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 1 {
				return errors.New("appsscript: more than one redirect")
			}
			if req.URL.Scheme != "https" || req.URL.Host != RedirectHost {
				return fmt.Errorf("appsscript: redirect to %q refused", req.URL.Host)
			}
			return nil
		},
	}
}

// Reasons a check reports (GoogleCheck.reason on the app side).
const (
	ReasonOK           = ""
	ReasonNotDeployed  = "not_deployed"  // no web app answering as Daal's script at this address
	ReasonRefused      = "refused"       // the script refused the update: another write key
	ReasonStale        = "stale"         // the script holds a newer update than this one
	ReasonWrongContent = "wrong_content" // it answered, but not with what was just sent
	ReasonUnreachable  = "unreachable"   // neither route reached Google
	ReasonFull         = "full"          // the account's property store is full
	ReasonBadAddress   = "bad_address"   // what was pasted is not a web app's /exec address
)

// Failure is a check or update that did not work, with its reason.
type Failure struct {
	Reason string
	Detail string
}

func (f *Failure) Error() string {
	if f.Detail == "" {
		return "appsscript: " + f.Reason
	}
	return "appsscript: " + f.Reason + ": " + f.Detail
}

func fail(reason, format string, a ...any) *Failure {
	return &Failure{Reason: reason, Detail: fmt.Sprintf(format, a...)}
}

// postAnswer is what the script answers to an update.
type postAnswer struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
	Seq   uint64 `json:"seq"`
}

// Post sends one update. It tries the front, then plain, and returns
// the route that carried it.
func (n Network) Post(ctx context.Context, execURL string, writeKey []byte, seq uint64, blob []byte) (viaFront bool, err error) {
	slot, err := slotOf(execURL, writeKey)
	if err != nil {
		return false, err
	}
	body, err := UpdateBody(writeKey, slot, seq, blob)
	if err != nil {
		return false, err
	}
	var last *Failure
	for _, r := range routes {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, execURL, bytes.NewReader(body))
		if err != nil {
			return false, err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := n.client(r).Do(req)
		if err != nil {
			last = fail(ReasonUnreachable, "%s: %v", r.name, scrubURL(err.Error()))
			continue
		}
		raw, rerr := readBounded(resp.Body)
		resp.Body.Close()
		if rerr != nil {
			last = fail(ReasonUnreachable, "%s: %v", r.name, rerr)
			continue
		}
		if resp.StatusCode/100 != 2 {
			return r.front, fail(ReasonNotDeployed, "HTTP %d", resp.StatusCode)
		}
		var a postAnswer
		if err := json.Unmarshal(raw, &a); err != nil {
			// A sign-in page or an editor error: the address is
			// not a web app open to anyone running this script.
			return r.front, fail(ReasonNotDeployed, "the answer is not from Daal's script")
		}
		if !a.OK {
			switch a.Error {
			case "refused":
				return r.front, fail(ReasonRefused, "the script has a different write key")
			case "stale":
				return r.front, fail(ReasonStale, "the script already holds update %d", a.Seq)
			case "full":
				return r.front, fail(ReasonFull, "the script's store is full")
			default:
				return r.front, fail(ReasonNotDeployed, "the script answered %q", a.Error)
			}
		}
		return r.front, nil
	}
	return false, last
}

// Fetch reads the container back the way a recipient does. It returns
// the body and whether the front carried it.
func (n Network) Fetch(ctx context.Context, execURL string) (body []byte, viaFront bool, err error) {
	if _, _, _, err := freshness.ValidateAppsScriptURL(execURL); err != nil {
		return nil, false, fail(ReasonNotDeployed, "%v", err)
	}
	var last *Failure
	for _, r := range routes {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, execURL, nil)
		if err != nil {
			return nil, false, err
		}
		resp, err := n.client(r).Do(req)
		if err != nil {
			last = fail(ReasonUnreachable, "%s: %v", r.name, scrubURL(err.Error()))
			continue
		}
		raw, rerr := readBounded(resp.Body)
		resp.Body.Close()
		if rerr != nil {
			last = fail(ReasonUnreachable, "%s: %v", r.name, rerr)
			continue
		}
		if resp.StatusCode/100 != 2 {
			return nil, r.front, fail(ReasonNotDeployed, "HTTP %d", resp.StatusCode)
		}
		return raw, r.front, nil
	}
	return nil, false, last
}

// slotOf checks a mirror URL and that its read token is this write
// key's for its slot, and returns the slot. A token made with another
// key means the address belongs to another account's script.
func slotOf(execURL string, writeKey []byte) (string, error) {
	_, slot, token, err := freshness.ValidateAppsScriptURL(execURL)
	if err != nil {
		return "", fail(ReasonNotDeployed, "%v", err)
	}
	if len(writeKey) != WriteKeySize {
		return "", errors.New("appsscript: write key must be 32 bytes")
	}
	if !hmac.Equal([]byte(token), []byte(ReadToken(writeKey, slot))) {
		return "", fail(ReasonRefused, "the address was made with another write key")
	}
	return slot, nil
}

// scrubURL drops query strings from an error text: the read token is
// public, but a URL in a log line is still more than the line needs.
func scrubURL(s string) string {
	for {
		i := strings.Index(s, "?s=")
		if i < 0 {
			return s
		}
		j := i + 3
		for j < len(s) && s[j] != '"' && s[j] != ' ' && s[j] != ':' {
			j++
		}
		s = s[:i] + s[j:]
	}
}

func readBounded(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxRead+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxRead {
		return nil, fmt.Errorf("answer longer than %d bytes", MaxRead)
	}
	return b, nil
}

// CheckResult is what a POST-and-fetch-back found.
type CheckResult struct {
	OK bool `json:"ok"`
	// ViaFront: the fetch-back came through the Google front, as
	// recipients fetch. False when only the plain attempt worked.
	ViaFront bool   `json:"via_front"`
	Posted   bool   `json:"posted"`
	Seq      uint64 `json:"seq"`
	// SHA256 of the container the script now serves (when it
	// matched); the app keeps it to compare a later fetch with.
	SHA256 string `json:"sha256,omitempty"`
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
}

func resultFrom(err error) CheckResult {
	var f *Failure
	if errors.As(err, &f) {
		return CheckResult{Reason: f.Reason, Detail: f.Detail}
	}
	return CheckResult{Reason: ReasonUnreachable, Detail: err.Error()}
}

// SendAndCheck POSTs blob as update seq, then fetches it back and
// compares byte for byte.
func (n Network) SendAndCheck(ctx context.Context, execURL string, writeKey []byte, seq uint64, blob []byte) CheckResult {
	if _, err := n.Post(ctx, execURL, writeKey, seq, blob); err != nil {
		r := resultFrom(err)
		r.Seq = seq
		return r
	}
	r := n.FetchAndCompare(ctx, execURL, sha256Hex(blob))
	r.Posted = true
	r.Seq = seq
	return r
}

// FetchAndCompare fetches the container and compares its SHA-256 with
// wantSHA256 (lower-case hex). An empty want accepts any well-formed
// container.
func (n Network) FetchAndCompare(ctx context.Context, execURL, wantSHA256 string) CheckResult {
	got, viaFront, err := n.Fetch(ctx, execURL)
	if err != nil {
		return resultFrom(err)
	}
	r := CheckResult{ViaFront: viaFront}
	_, slot, _, _ := freshness.ValidateAppsScriptURL(execURL)
	if p, perr := Parse(got); perr != nil || p.Slot != slot {
		r.Reason = ReasonWrongContent
		r.Detail = "the address does not answer with this slot's update"
		return r
	}
	sum := sha256Hex(got)
	if wantSHA256 != "" && !strings.EqualFold(sum, wantSHA256) {
		r.Reason = ReasonWrongContent
		r.Detail = "the script serves something other than the last update"
		return r
	}
	r.OK = true
	r.SHA256 = sum
	return r
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// Backend is the freshness backend for one deployed script: Put wraps
// the signed document (and the pack it names, and a standby key) in a
// container and POSTs it, numbered with the document's own sequence.
type Backend struct {
	cfg  Config
	slot string
}

// Config configures one Backend.
type Config struct {
	// ExecURL is the relay's mirror URL, ?s=<slot>&k=<read token>.
	ExecURL string
	// WriteKey is the account's 32-byte write key. The caller zeroizes it.
	WriteKey []byte
	// Pack is the signed credential-less pack the documents name;
	// optional. Left out of a container it does not fit in.
	Pack []byte
	// StandbyKey is carried when set (26 Crockford base32 symbols).
	StandbyKey string
	Network    Network
}

var _ freshness.Backend = (*Backend)(nil)

// New checks the configuration.
func New(cfg Config) (*Backend, error) {
	if _, _, _, err := freshness.ValidateAppsScriptURL(cfg.ExecURL); err != nil {
		return nil, fmt.Errorf("appsscript: %w", err)
	}
	if len(cfg.WriteKey) != WriteKeySize {
		return nil, errors.New("appsscript: write key must be 32 bytes")
	}
	slot, err := slotOf(cfg.ExecURL, cfg.WriteKey)
	if err != nil {
		return nil, err
	}
	return &Backend{cfg: cfg, slot: slot}, nil
}

// PublicURL is the mirror URL recipients fetch.
func (b *Backend) PublicURL() string { return b.cfg.ExecURL }

// Put publishes one signed freshness document.
func (b *Backend) Put(ctx context.Context, doc []byte) error {
	blob, err := b.Container(doc)
	if err != nil {
		return err
	}
	seq, err := DocSequence(doc)
	if err != nil {
		return err
	}
	_, err = b.cfg.Network.Post(ctx, b.cfg.ExecURL, b.cfg.WriteKey, seq, blob)
	return err
}

// Container is the container Put sends for doc: with the pack when it
// fits, without it when it does not.
func (b *Backend) Container(doc []byte) ([]byte, error) {
	blob, err := Build(b.slot, doc, b.cfg.Pack, b.cfg.StandbyKey)
	if errors.Is(err, ErrPackTooLarge) {
		blob, err = Build(b.slot, doc, nil, b.cfg.StandbyKey)
	}
	return blob, err
}

// ValidateBaseURL checks a script's own address (no query) and returns
// its deployment id.
func ValidateBaseURL(base string) (string, error) {
	id, err := freshness.ValidateAppsScriptBase(base)
	if err != nil {
		return "", fmt.Errorf("appsscript: %w", err)
	}
	return id, nil
}

// NormalizeExecURL turns what a publisher pastes (the web-app address
// Google shows after "Deploy") into the script's own address,
// https://script.google.com/macros/s/<id>/exec: a trailing slash, a
// query or a fragment are dropped (Google adds none; a slot is never
// pasted).
func NormalizeExecURL(pasted string) (string, error) {
	s := strings.TrimSpace(pasted)
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host != freshness.AppsScriptHost || u.User != nil {
		return "", errors.New("appsscript: that is not a script.google.com web-app address")
	}
	path := strings.TrimSuffix(u.EscapedPath(), "/")
	// The editor's test address ends in /dev and only works for the
	// owner while signed in; recipients need the deployed /exec.
	if strings.HasSuffix(path, "/dev") {
		return "", errors.New("appsscript: that is the test address (/dev); copy the web app address that ends in /exec")
	}
	out := "https://" + freshness.AppsScriptHost + path
	if _, err := ValidateBaseURL(out); err != nil {
		return "", err
	}
	return out, nil
}

// AccountCheck is the connect check of one account's script: an update
// to TestSlot carrying a fresh nonce, numbered seq (the caller passes a
// number that only goes up, the clock in milliseconds), then a read-back
// the way recipients fetch. Only when the script gave back exactly what
// was sent is the account connected.
func (n Network) AccountCheck(ctx context.Context, base string, writeKey []byte, seq uint64) CheckResult {
	u, err := SlotURL(base, writeKey, TestSlot)
	if err != nil {
		return CheckResult{Reason: ReasonNotDeployed, Detail: err.Error()}
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return CheckResult{Reason: ReasonUnreachable, Detail: err.Error()}
	}
	return n.SendAndCheck(ctx, u, writeKey, seq, CheckContainer(base64.RawURLEncoding.EncodeToString(nonce)))
}
