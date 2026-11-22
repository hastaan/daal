// Package gittag is the publisher's WRITE of the git-tag carrier
// (docs/update-ladder-v2.md §4.1, specs/update-ladder-v2.md §4): one
// public repository per relay under the publisher's GitHub account,
// holding exactly two files,
//
//	n        the sealed full note, standard base64 (bundle.EncodeFullNoteText)
//	go.mod   "module github.com/<owner>/<repo>", "go 1.21", then the same
//	         base64 in "// " comment lines (Go proxies keep comments; wave 0 §1)
//
// and one lightweight tag per publish,
//
//	v0.<seq>.0-<26 base32 symbols of the sealed micro note>  (bundle.GitNoteTag)
//
// pointing at the commit that holds those files. Every reader of the
// write (github.com tags.atom, raw.githubusercontent.com, the Go
// proxies, jsDelivr) uses the carrier label bundle.NoteCarrierGitTag.
//
// What it never writes in the clear: the relay's address, name or pack
// id. The repository name comes from the caller (the carriers member),
// the commit message is the constant "update", and the tag carries only
// the sealed micro note.
//
// Always present, constant size (study §3.3): a publish with nothing to
// reveal writes filler of the same size and shape as a note. Filler and
// the full note's nonce are derived from the audience secret, so a
// publish run twice writes the same bytes and the second run changes
// nothing (Publish).
//
// Every HTTP call goes through Config.BaseURL and Config.HTTPClient, so
// tests run against a fake GitHub (gittagtest). This package is under
// publisher/deploy/freshness/backends/, which publisher/deploy/
// opsec_test.go allows to use net/http.
package gittag

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultBaseURL is GitHub's REST API.
const DefaultBaseURL = "https://api.github.com"

// maxResponse bounds every answer read from the API.
const maxResponse = 4 << 20

// Config configures a Client.
type Config struct {
	// Token is a GitHub personal access token (classic, or fine-grained
	// with Administration and Contents: Read and write). The caller
	// zeroizes it after use; the Client keeps a reference only.
	Token []byte
	// BaseURL defaults to DefaultBaseURL. Tests point it at a fake.
	BaseURL string
	// HTTPClient defaults to a client with a 30 s timeout.
	HTTPClient *http.Client
}

// Client talks to the GitHub REST API with one token.
type Client struct {
	base  string
	token []byte
	hc    *http.Client
}

// New builds a Client.
func New(cfg Config) (*Client, error) {
	if len(cfg.Token) == 0 {
		return nil, errors.New("gittag: a token is required")
	}
	if bytes.ContainsAny(cfg.Token, " \t\r\n") {
		return nil, errors.New("gittag: the token has spaces or line breaks in it")
	}
	base := strings.TrimRight(cfg.BaseURL, "/")
	if base == "" {
		base = DefaultBaseURL
	}
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, errors.New("gittag: bad base URL")
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	// No redirects: a redirect would carry the token to wherever it
	// points (Go drops Authorization only across hosts).
	noRedirect := *hc
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{base: base, token: cfg.Token, hc: &noRedirect}, nil
}

// Error kinds: what went wrong, in the words the CLI prints.
const (
	KindInvalidToken      = "invalid_token"      // 401: GitHub does not accept the token
	KindMissingPermission = "missing_permission" // 403 (not a rate limit): Permission names what is missing
	KindRateLimited       = "rate_limited"       // 429, or 403 with the rate limit spent; RetryAfter says when
	KindNotFound          = "not_found"          // 404
	KindConflict          = "conflict"           // 409 / 422 the caller did not expect
	KindGitHub            = "github"             // any other answer (5xx, malformed)
	KindNetwork           = "network"            // no answer
)

// APIError is a failed call. Its text names the operation and the
// status, never a URL, an owner, a repository, a tag or the token.
type APIError struct {
	Op         string // e.g. "create the repository"
	Status     int    // 0 for KindNetwork
	Kind       string
	Permission string        // for KindMissingPermission: what to grant
	RetryAfter time.Duration // for KindRateLimited, when known
	cause      error
}

func (e *APIError) Error() string {
	s := "gittag: " + e.Op + ": "
	switch e.Kind {
	case KindNetwork:
		s += "no answer from GitHub"
		if e.cause != nil {
			s += " (" + e.cause.Error() + ")"
		}
	case KindRateLimited:
		s += "GitHub's rate limit is spent"
		if e.RetryAfter > 0 {
			s += fmt.Sprintf("; try again in %d s", int(e.RetryAfter.Seconds()))
		}
	case KindMissingPermission:
		s += "GitHub refused the token (missing: " + e.Permission + ")"
	case KindInvalidToken:
		s += "GitHub does not accept the token"
	default:
		s += "GitHub answered " + strconv.Itoa(e.Status)
	}
	return s
}

// Unwrap exposes a network cause (context errors in particular).
func (e *APIError) Unwrap() error { return e.cause }

// IsKind reports whether err is an *APIError of that kind.
func IsKind(err error, kind string) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Kind == kind
}

// call is one request. path starts with "/". in (if non-nil) is sent as
// JSON; out (if non-nil) receives a 2xx JSON answer. perm is what a 403
// means is missing. The answer's status and headers come back for the
// caller's own decisions (404 and 422 are often answers, not failures);
// for any non-2xx status err is an *APIError as well.
func (c *Client) call(ctx context.Context, op, method, path string, in, out any, perm string) (int, http.Header, error) {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return 0, nil, fmt.Errorf("gittag: %s: %w", op, err)
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return 0, nil, fmt.Errorf("gittag: %s: build request", op)
	}
	req.Header.Set("Authorization", "Bearer "+string(c.token))
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		// url.Error's text carries the URL (owner and repository):
		// keep only the cause.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return 0, nil, &APIError{Op: op, Kind: KindNetwork, cause: err}
	}
	defer resp.Body.Close()
	raw, rerr := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if rerr != nil {
		return resp.StatusCode, resp.Header, &APIError{Op: op, Kind: KindNetwork, cause: rerr}
	}
	if len(raw) > maxResponse {
		return resp.StatusCode, resp.Header, &APIError{Op: op, Status: resp.StatusCode, Kind: KindGitHub}
	}
	if resp.StatusCode/100 != 2 {
		return resp.StatusCode, resp.Header, statusError(op, resp.StatusCode, resp.Header, raw, perm)
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, resp.Header, &APIError{Op: op, Status: resp.StatusCode, Kind: KindGitHub}
		}
	}
	return resp.StatusCode, resp.Header, nil
}

func statusError(op string, status int, h http.Header, body []byte, perm string) *APIError {
	e := &APIError{Op: op, Status: status}
	switch {
	case status == http.StatusUnauthorized:
		e.Kind = KindInvalidToken
	case status == http.StatusTooManyRequests || (status == http.StatusForbidden && rateLimited(h, body)):
		e.Kind = KindRateLimited
		e.RetryAfter = retryAfter(h, time.Now())
	case status == http.StatusForbidden:
		e.Kind = KindMissingPermission
		e.Permission = perm
		if e.Permission == "" {
			e.Permission = "a permission this call needs"
		}
	case status == http.StatusNotFound:
		e.Kind = KindNotFound
	case status == http.StatusConflict || status == http.StatusUnprocessableEntity:
		e.Kind = KindConflict
	default:
		e.Kind = KindGitHub
	}
	return e
}

// rateLimited: GitHub answers a spent primary limit with 403 and
// X-RateLimit-Remaining: 0, and a secondary limit with 403, a
// Retry-After header and a message naming it.
func rateLimited(h http.Header, body []byte) bool {
	if h.Get("X-RateLimit-Remaining") == "0" || h.Get("Retry-After") != "" {
		return true
	}
	var m struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(body, &m)
	return strings.Contains(strings.ToLower(m.Message), "rate limit")
}

func retryAfter(h http.Header, now time.Time) time.Duration {
	if s := h.Get("Retry-After"); s != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n >= 0 {
			return time.Duration(n) * time.Second
		}
	}
	if s := h.Get("X-RateLimit-Reset"); s != "" {
		if n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64); err == nil {
			if d := time.Unix(n, 0).Sub(now); d > 0 {
				return d.Round(time.Second)
			}
		}
	}
	return 0
}

// repoPath is /repos/<owner>/<repo><rest>; owner and repo were checked
// by bundle.GitOwnerOK / GitRepoOK and need no escaping beyond this.
func repoPath(owner, repo, rest string) string {
	return "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo) + rest
}
