package cloudflare

// The Helper-side network calls of the CDN add-on, all in this one file
// so the opsec allowlist (publisher/deploy/opsec_test.go) stays one
// name long for them:
//
//   - the Cloudflare API v4 client (liveCFClient), bearer token, to
//     api.cloudflare.com only;
//   - the DoH read of a hostname's HTTPS record for its ECH config
//     (DoHECHFetcher, B-5), to the resolvers it is given;
//   - the front test (FrontTest): one TLS + WebSocket handshake to a
//     Cloudflare edge for the publisher's own hostname.
//
// All three run on the publisher's machine or phone, never on the relay
// and never on a recipient. The token goes into the Authorization
// header and nowhere else: not into a URL, an error or a log line.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const cloudflareAPIBase = "https://api.cloudflare.com/client/v4"

// liveCFClient is the production CFClient.
type liveCFClient struct {
	baseURL    string
	httpClient *http.Client
}

// NewLiveCFClient returns the production Cloudflare client. It never
// stores the token; callers pass it per call and zeroize it after.
func NewLiveCFClient() CFClient {
	return newLiveCFClient(cloudflareAPIBase, &http.Client{Timeout: 30 * time.Second})
}

func newLiveCFClient(baseURL string, client *http.Client) *liveCFClient {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	// Never follow a redirect with the bearer header on it.
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &liveCFClient{baseURL: strings.TrimRight(baseURL, "/"), httpClient: &c}
}

// statusError is a non-2xx answer. Body is Cloudflare's error JSON,
// bounded; it never carries the token.
type statusError struct {
	Method, Path string
	Status       int
	Body         string
}

func (e *statusError) Error() string {
	return fmt.Sprintf("cloudflare: %s %s: status %d: %s", e.Method, e.Path, e.Status, e.Body)
}

func (e *statusError) Unwrap() error {
	if e.Status == http.StatusUnauthorized || e.Status == http.StatusForbidden {
		return &authError{msg: "cloudflare: not authorised"}
	}
	return nil
}

func isStatus(err error, code int) bool {
	var se *statusError
	return errors.As(err, &se) && se.Status == code
}

func (c *liveCFClient) do(ctx context.Context, token []byte, method, path string, query url.Values, body any, out any) error {
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			return err
		}
	}
	return c.doRaw(ctx, token, method, path, query, raw, out)
}

func (c *liveCFClient) doRaw(ctx context.Context, token []byte, method, path string, query url.Values, body []byte, out any) error {
	if len(token) == 0 {
		return errors.New("cloudflare: token required")
	}
	u, err := url.Parse(c.baseURL + "/" + strings.TrimLeft(path, "/"))
	if err != nil {
		return err
	}
	if query != nil {
		q := u.Query()
		for k, vs := range query {
			for _, v := range vs {
				q.Add(k, v)
			}
		}
		u.RawQuery = q.Encode()
	}
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+string(token))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		// net/http errors name the URL, which carries no secret.
		return scrub(err, token)
	}
	defer resp.Body.Close()
	limited, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		b := string(limited)
		if len(b) > 512 {
			b = b[:512]
		}
		return scrub(&statusError{Method: method, Path: path, Status: resp.StatusCode, Body: b}, token)
	}
	if out == nil {
		return nil
	}
	var env struct {
		Success bool            `json:"success"`
		Result  json.RawMessage `json:"result"`
		Errors  []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(limited, &env); err != nil {
		return err
	}
	if !env.Success {
		if len(env.Errors) > 0 {
			return fmt.Errorf("cloudflare: API error %d: %s", env.Errors[0].Code, env.Errors[0].Message)
		}
		return errors.New("cloudflare: API error")
	}
	if len(env.Result) == 0 || string(env.Result) == "null" {
		return nil
	}
	return json.Unmarshal(env.Result, out)
}

func zp(zoneID string) string { return "/zones/" + url.PathEscape(zoneID) }

func (c *liveCFClient) VerifyToken(ctx context.Context, tok []byte) (TokenStatus, error) {
	var st TokenStatus
	err := c.do(ctx, tok, http.MethodGet, "/user/tokens/verify", nil, nil, &st)
	return st, err
}

type apiZone struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Account struct {
		ID string `json:"id"`
	} `json:"account"`
}

func (z apiZone) zone() Zone {
	return Zone{ID: z.ID, Name: z.Name, Status: z.Status, AccountID: z.Account.ID}
}

func (c *liveCFClient) ListZones(ctx context.Context, tok []byte) ([]Zone, error) {
	var out []Zone
	// A five-permission token sees one zone; the pages exist for the
	// too-broad case, which only needs the count to exceed one.
	for page := 1; page <= 4; page++ {
		q := url.Values{"per_page": {"50"}, "page": {strconv.Itoa(page)}}
		var zs []apiZone
		if err := c.do(ctx, tok, http.MethodGet, "/zones", q, nil, &zs); err != nil {
			return nil, err
		}
		for _, z := range zs {
			out = append(out, z.zone())
		}
		if len(zs) < 50 {
			break
		}
	}
	return out, nil
}

func (c *liveCFClient) LookupZone(ctx context.Context, tok []byte, name string) (Zone, bool, error) {
	var zs []apiZone
	if err := c.do(ctx, tok, http.MethodGet, "/zones", url.Values{"name": {name}}, nil, &zs); err != nil {
		return Zone{}, false, err
	}
	for _, z := range zs {
		if strings.EqualFold(z.Name, name) {
			return z.zone(), true, nil
		}
	}
	return Zone{}, false, nil
}

func (c *liveCFClient) ProbeRead(ctx context.Context, tok []byte, path string) (ProbeResult, error) {
	p, rawQuery, _ := strings.Cut(path, "?")
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return ProbeDenied, err
	}
	err = c.doRaw(ctx, tok, http.MethodGet, p, q, nil, nil)
	switch {
	case err == nil:
		return ProbeAllowed, nil
	case isStatus(err, http.StatusUnauthorized), isStatus(err, http.StatusForbidden):
		return ProbeDenied, nil
	case isStatus(err, http.StatusNotFound):
		return ProbeNotFound, nil
	default:
		return ProbeDenied, err
	}
}

func (c *liveCFClient) IssueOriginCert(ctx context.Context, tok []byte, hostnames []string, validityDays int) (OriginCert, error) {
	if len(hostnames) == 0 {
		return OriginCert{}, errors.New("cloudflare: hostnames required")
	}
	if validityDays <= 0 {
		validityDays = 5475
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return OriginCert{}, fmt.Errorf("cloudflare: generate origin key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: hostnames[0]},
		DNSNames: hostnames,
	}, priv)
	if err != nil {
		return OriginCert{}, fmt.Errorf("cloudflare: create csr: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return OriginCert{}, fmt.Errorf("cloudflare: marshal origin key: %w", err)
	}
	reqBody := map[string]any{
		"csr":                string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
		"hostnames":          hostnames,
		"request_type":       "origin-ecc",
		"requested_validity": validityDays,
	}
	var res struct {
		Certificate string `json:"certificate"`
		ID          string `json:"id"`
	}
	if err := c.do(ctx, tok, http.MethodPost, "/certificates", nil, reqBody, &res); err != nil {
		return OriginCert{}, err
	}
	if res.Certificate == "" || res.ID == "" {
		return OriginCert{}, errors.New("cloudflare: origin CA response missing certificate or id")
	}
	certPEM := []byte(res.Certificate)
	sum := sha256.Sum256(certPEM)
	return OriginCert{
		ID:             res.ID,
		CertPEM:        certPEM,
		KeyPEM:         pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		FingerprintHex: hex.EncodeToString(sum[:]),
	}, nil
}

func (c *liveCFClient) RevokeOriginCert(ctx context.Context, tok []byte, certID string) error {
	err := c.do(ctx, tok, http.MethodDelete, "/certificates/"+url.PathEscape(certID), nil, nil, nil)
	if isStatus(err, http.StatusNotFound) {
		return nil
	}
	return err
}

func (c *liveCFClient) UploadAOPCert(ctx context.Context, tok []byte, zoneID string, certPEM, keyPEM []byte) (string, error) {
	body := map[string]string{"certificate": string(certPEM), "private_key": string(keyPEM)}
	var res struct {
		ID string `json:"id"`
	}
	if err := c.do(ctx, tok, http.MethodPost, zp(zoneID)+"/origin_tls_client_auth", nil, body, &res); err != nil {
		return "", err
	}
	if res.ID == "" {
		return "", errors.New("cloudflare: origin pull upload returned no id")
	}
	return res.ID, nil
}

func (c *liveCFClient) DeleteAOPCert(ctx context.Context, tok []byte, zoneID, certID string) error {
	err := c.do(ctx, tok, http.MethodDelete, zp(zoneID)+"/origin_tls_client_auth/"+url.PathEscape(certID), nil, nil, nil)
	if isStatus(err, http.StatusNotFound) {
		return nil
	}
	return err
}

func (c *liveCFClient) SetAOPEnabled(ctx context.Context, tok []byte, zoneID string, enabled bool) error {
	var out any
	return c.do(ctx, tok, http.MethodPut, zp(zoneID)+"/origin_tls_client_auth/settings", nil, map[string]bool{"enabled": enabled}, &out)
}

func (c *liveCFClient) AOPEnabled(ctx context.Context, tok []byte, zoneID string) (bool, error) {
	var out struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.do(ctx, tok, http.MethodGet, zp(zoneID)+"/origin_tls_client_auth/settings", nil, nil, &out); err != nil {
		return false, err
	}
	return out.Enabled, nil
}

func (c *liveCFClient) GetZoneSetting(ctx context.Context, tok []byte, zoneID, name string) (string, error) {
	var out struct {
		Value json.RawMessage `json:"value"`
	}
	if err := c.do(ctx, tok, http.MethodGet, zp(zoneID)+"/settings/"+url.PathEscape(name), nil, nil, &out); err != nil {
		return "", err
	}
	var s string
	if err := json.Unmarshal(out.Value, &s); err != nil {
		return "", fmt.Errorf("cloudflare: setting %s is not a string value", name)
	}
	return s, nil
}

func (c *liveCFClient) SetZoneSetting(ctx context.Context, tok []byte, zoneID, name, value string) error {
	var out any
	return c.do(ctx, tok, http.MethodPatch, zp(zoneID)+"/settings/"+url.PathEscape(name), nil, map[string]string{"value": value}, &out)
}

func (c *liveCFClient) ListDNSRecords(ctx context.Context, tok []byte, zoneID, hostname string) ([]DNSRecord, error) {
	var recs []DNSRecord
	err := c.do(ctx, tok, http.MethodGet, zp(zoneID)+"/dns_records", url.Values{"name": {hostname}, "per_page": {"100"}}, nil, &recs)
	return recs, err
}

type dnsRecordPayload struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
	TTL     int    `json:"ttl"`
}

func (c *liveCFClient) EnsureProxiedRecords(ctx context.Context, tok []byte, zoneID, hostname, v4, v6 string) ([]string, error) {
	if zoneID == "" || hostname == "" || v4 == "" {
		return nil, errors.New("cloudflare: zoneID, hostname, originIPv4 required")
	}
	recs, err := c.ListDNSRecords(ctx, tok, zoneID, hostname)
	if err != nil {
		return nil, err
	}
	want := map[string]string{"A": v4}
	if v6 != "" {
		want["AAAA"] = v6
	}
	have := map[string]bool{}
	for _, r := range recs {
		if r.Type != "A" && r.Type != "AAAA" {
			continue
		}
		if !r.proxied() {
			return nil, ErrDNSOnlyRecordPresent
		}
		if w, ok := want[r.Type]; ok && w != r.Content {
			return nil, ErrHostnameInUse
		}
		have[r.Type] = true
	}
	var created []string
	for _, typ := range []string{"A", "AAAA"} {
		content, ok := want[typ]
		if !ok || have[typ] {
			continue
		}
		var out DNSRecord
		if err := c.do(ctx, tok, http.MethodPost, zp(zoneID)+"/dns_records", nil,
			dnsRecordPayload{Type: typ, Name: hostname, Content: content, Proxied: true, TTL: 1}, &out); err != nil {
			return created, err
		}
		if out.ID == "" {
			return created, errors.New("cloudflare: dns record create returned no id")
		}
		created = append(created, out.ID)
	}
	return created, nil
}

func (c *liveCFClient) SetDNSRecordContent(ctx context.Context, tok []byte, zoneID, recordID, content string) error {
	var out DNSRecord
	return c.do(ctx, tok, http.MethodPatch, zp(zoneID)+"/dns_records/"+url.PathEscape(recordID), nil, map[string]string{"content": content}, &out)
}

func (c *liveCFClient) DeleteDNSRecord(ctx context.Context, tok []byte, zoneID, recordID string) error {
	err := c.do(ctx, tok, http.MethodDelete, zp(zoneID)+"/dns_records/"+url.PathEscape(recordID), nil, nil, nil)
	if isStatus(err, http.StatusNotFound) {
		return nil
	}
	return err
}

// ---- origin rules (phase http_request_origin) ----

// rulesetRule keeps only the writable fields of a rule, so a PUT of the
// entrypoint carries every other rule back exactly as the publisher
// made it.
type rulesetRule struct {
	ID               string          `json:"id,omitempty"`
	Ref              string          `json:"ref,omitempty"`
	Expression       string          `json:"expression"`
	Action           string          `json:"action"`
	ActionParameters json.RawMessage `json:"action_parameters,omitempty"`
	Description      string          `json:"description,omitempty"`
	Enabled          *bool           `json:"enabled,omitempty"`
	Logging          json.RawMessage `json:"logging,omitempty"`
}

func (c *liveCFClient) entrypoint(ctx context.Context, tok []byte, zoneID string) ([]rulesetRule, bool, error) {
	var rs struct {
		Rules []rulesetRule `json:"rules"`
	}
	err := c.do(ctx, tok, http.MethodGet, originEntrypointPath(zoneID), nil, nil, &rs)
	if isStatus(err, http.StatusNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return rs.Rules, true, nil
}

func (c *liveCFClient) putEntrypoint(ctx context.Context, tok []byte, zoneID string, rules []rulesetRule) error {
	if rules == nil {
		rules = []rulesetRule{}
	}
	var out any
	return c.do(ctx, tok, http.MethodPut, originEntrypointPath(zoneID), nil, map[string]any{"rules": rules}, &out)
}

// hostExpression is the rule's match. The hostname was checked by
// NormalizeHostname, so it holds no quote or backslash.
func hostExpression(hostname string) string {
	return `(http.host eq "` + hostname + `")`
}

func (c *liveCFClient) EnsureOriginRule(ctx context.Context, tok []byte, zoneID, ref, hostname string, port int) error {
	if _, err := NormalizeHostname(hostname); err != nil {
		return err
	}
	rules, _, err := c.entrypoint(ctx, tok, zoneID)
	if err != nil {
		return err
	}
	params, _ := json.Marshal(map[string]any{"origin": map[string]int{"port": port}})
	t := true
	ours := rulesetRule{
		Ref:              ref,
		Expression:       hostExpression(hostname),
		Action:           "route",
		ActionParameters: params,
		Description:      "origin port",
		Enabled:          &t,
	}
	next := make([]rulesetRule, 0, len(rules)+1)
	for _, r := range rules {
		if r.Ref == ref {
			continue
		}
		next = append(next, r)
	}
	return c.putEntrypoint(ctx, tok, zoneID, append(next, ours))
}

func (c *liveCFClient) RemoveOriginRule(ctx context.Context, tok []byte, zoneID, ref string) error {
	rules, exists, err := c.entrypoint(ctx, tok, zoneID)
	if err != nil || !exists {
		return err
	}
	next := make([]rulesetRule, 0, len(rules))
	for _, r := range rules {
		if r.Ref != ref {
			next = append(next, r)
		}
	}
	if len(next) == len(rules) {
		return nil
	}
	return c.putEntrypoint(ctx, tok, zoneID, next)
}

func (c *liveCFClient) OriginRule(ctx context.Context, tok []byte, zoneID, ref string) (string, int, bool, error) {
	rules, _, err := c.entrypoint(ctx, tok, zoneID)
	if err != nil {
		return "", 0, false, err
	}
	for _, r := range rules {
		if r.Ref != ref {
			continue
		}
		var ap struct {
			Origin struct {
				Port int `json:"port"`
			} `json:"origin"`
		}
		_ = json.Unmarshal(r.ActionParameters, &ap)
		host := strings.TrimSuffix(strings.TrimPrefix(r.Expression, `(http.host eq "`), `")`)
		return host, ap.Origin.Port, true, nil
	}
	return "", 0, false, nil
}

// ---- B-5: ECH over DoH ----

// DefaultDoHResolvers are tried in order. Both are reached from the
// publisher abroad; neither sees anything but the hostname.
var DefaultDoHResolvers = []string{
	"https://cloudflare-dns.com/dns-query",
	"https://dns.google/dns-query",
}

// DoHECHFetcher reads a hostname's HTTPS record over DNS-over-HTTPS
// (RFC 8484, GET with application/dns-message) and returns its ech
// SvcParam.
type DoHECHFetcher struct {
	Resolvers []string
	Client    *http.Client
}

// NewDoHECHFetcher returns a fetcher over the given resolvers, or the
// defaults.
func NewDoHECHFetcher(resolvers ...string) *DoHECHFetcher {
	if len(resolvers) == 0 {
		resolvers = DefaultDoHResolvers
	}
	return &DoHECHFetcher{Resolvers: resolvers, Client: &http.Client{Timeout: 10 * time.Second}}
}

func (f *DoHECHFetcher) FetchECH(ctx context.Context, hostname string) ([]byte, string, error) {
	h, err := NormalizeHostname(hostname)
	if err != nil {
		return nil, "", err
	}
	var errs []string
	for _, r := range f.Resolvers {
		list, err := f.fetchOne(ctx, r, h)
		if err == nil {
			return list, r, nil
		}
		errs = append(errs, err.Error())
	}
	return nil, "", fmt.Errorf("ech: no resolver answered: %s", strings.Join(errs, "; "))
}

func (f *DoHECHFetcher) fetchOne(ctx context.Context, resolver, host string) ([]byte, error) {
	if !strings.HasPrefix(resolver, "https://") {
		return nil, fmt.Errorf("doh: resolver must be https: %q", resolver)
	}
	q, id, err := buildHTTPSQuery(host)
	if err != nil {
		return nil, err
	}
	u := resolver + "?dns=" + base64.RawURLEncoding.EncodeToString(q)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")
	client := f.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh %s: status %d", resolver, resp.StatusCode)
	}
	msg, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	return echFromDNSAnswer(msg, id)
}

// ---- cdn-test: one real handshake through the front ----

// FrontTestOpts is one front test.
type FrontTestOpts struct {
	Hostname string
	Path     string
	// Edge is "ip:port" of a Cloudflare edge. Empty: the hostname on
	// port 443, resolved by the system resolver (the publisher is
	// abroad; this is never run where local DNS lies).
	Edge string
	// ECHConfigList, when set, is offered; RequireECH fails the test
	// unless the edge accepted it.
	ECHConfigList []byte
	RequireECH    bool
	Timeout       time.Duration
	// RootCAs nil means the system roots. Tests pass a pool.
	RootCAs *x509.CertPool
	// Dial is injectable for tests.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// FrontTestResult is what cdn-test prints.
type FrontTestResult struct {
	OK          bool   `json:"ok"`
	Edge        string `json:"edge"`
	ECHOffered  bool   `json:"ech_offered"`
	ECHAccepted bool   `json:"ech_accepted"`
	TLSVersion  string `json:"tls_version,omitempty"`
	HTTPStatus  int    `json:"http_status,omitempty"`
	ElapsedMS   int64  `json:"elapsed_ms"`
	Detail      string `json:"detail,omitempty"`
}

// FrontTest opens a TLS connection to the edge for the hostname (with
// ECH when a config is given) and sends one WebSocket upgrade for the
// path. Success is a 101 with the right Sec-WebSocket-Accept: that
// proves the edge took the name, the origin rule sent the request to
// the relay's CDN port, the relay accepted Cloudflare's origin-pull
// certificate, and ws-cdn-in serves the path. It sends no VLESS bytes.
//
// It is Go's TLS stack, not the recipients' uTLS hello: it tests the
// path, not the fingerprint.
func FrontTest(ctx context.Context, o FrontTestOpts) FrontTestResult {
	start := time.Now()
	res := FrontTestResult{Edge: o.Edge, ECHOffered: len(o.ECHConfigList) > 0}
	done := func(detail string) FrontTestResult {
		res.ElapsedMS = time.Since(start).Milliseconds()
		res.Detail = detail
		return res
	}
	host, err := NormalizeHostname(o.Hostname)
	if err != nil {
		return done(err.Error())
	}
	if !ValidWSPath(o.Path) {
		return done("bad path")
	}
	if res.Edge == "" {
		res.Edge = net.JoinHostPort(host, "443")
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dial := o.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	raw, err := dial(ctx, "tcp", res.Edge)
	if err != nil {
		return done("connect: " + err.Error())
	}
	defer raw.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	}
	cfg := &tls.Config{
		ServerName: host,
		RootCAs:    o.RootCAs,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	}
	if res.ECHOffered {
		cfg.MinVersion = tls.VersionTLS13
		cfg.EncryptedClientHelloConfigList = o.ECHConfigList
	}
	conn := tls.Client(raw, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		return done("tls: " + err.Error())
	}
	st := conn.ConnectionState()
	res.ECHAccepted = st.ECHAccepted
	res.TLSVersion = tls.VersionName(st.Version)
	if o.RequireECH && !st.ECHAccepted {
		return done("the edge did not accept ECH")
	}
	var keyb [16]byte
	if _, err := rand.Read(keyb[:]); err != nil {
		return done(err.Error())
	}
	key := base64.StdEncoding.EncodeToString(keyb[:])
	req := "GET " + o.Path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"User-Agent: Mozilla/5.0\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		return done("write: " + err.Error())
	}
	br := bufio.NewReaderSize(io.LimitReader(conn, 16<<10), 4096)
	status, err := br.ReadString('\n')
	if err != nil {
		return done("read: " + err.Error())
	}
	parts := strings.SplitN(strings.TrimSpace(status), " ", 3)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/1.") {
		return done("not an HTTP answer")
	}
	res.HTTPStatus, _ = strconv.Atoi(parts[1])
	accept := ""
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return done("read headers: " + err.Error())
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "Sec-WebSocket-Accept") {
			accept = strings.TrimSpace(v)
		}
	}
	if res.HTTPStatus != http.StatusSwitchingProtocols {
		return done(fmt.Sprintf("the front answered %d, not 101", res.HTTPStatus))
	}
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	if accept != base64.StdEncoding.EncodeToString(sum[:]) {
		return done("wrong Sec-WebSocket-Accept")
	}
	res.OK = true
	return done("")
}
