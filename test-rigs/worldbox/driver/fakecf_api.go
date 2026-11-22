package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// `wb fakecf` is the Cloudflare a publisher talks to from abroad, for
// the CDN add-on (docs/optional-addons-plan.md §2.4): enough of API v4
// for the REAL publisher/deploy/cloudflare client inside the REAL
// daal-deploy to provision, check, test and remove a front; the
// published edge ranges (www.cloudflare.com/ips-v4); and the two DoH
// resolvers the publisher reads a hostname's ECH config from.
//
// Like fakecloud it knows nothing about Daal. What it models, because the
// product's correctness depends on it:
//
//   - API tokens with PERMISSIONS and a ZONE scope (cf-tokens.json, read
//     on every request so an op can hand out a new token): a call the
//     token may not make answers 403, as Cloudflare does. That is what
//     makes cdn-token-check's ok_broad / pick_zone / missing_permission verdicts
//     testable at all.
//   - State that has consequences: the proxied records, the origin rule's
//     port, SSL mode, WebSockets, origin pull and its client certificate
//     are what the edge (fakecdn.go) obeys, read from cf-state.json.
//   - Origin CA: a lab "Cloudflare Origin CA" root (cf-origin-ca.pem)
//     signs the CSR the publisher sends; under Full (strict) the edge
//     accepts an origin only with a certificate from it.
//   - Faults (cf-faults.json): the Nth call matching a method and path
//     fails with a status, so rollback is exercised against real calls.
//
// Every request is a line in cf-requests.jsonl (method, path, status,
// the token's public id — never the token). An unmodelled call answers
// 501 and is logged, so a gap is loud.
//
// Not modelled: pagination beyond what the client asks, rate limits,
// the Registrar API (Daal never calls it: plan §2.5), Workers.

const (
	cfStateFile  = "cf-state.json"
	cfTokensFile = "cf-tokens.json"
	cfFaultsFile = "cf-faults.json"
	cfReqFile    = "cf-requests.jsonl"
	cfOriginCA   = "cf-origin-ca.pem"
)

// CFToken is one API token the fake accepts.
type CFToken struct {
	Token  string   `json:"token"`
	ID     string   `json:"id"`
	Status string   `json:"status"` // active | disabled
	Zones  []string `json:"zones"`  // zone names the token's resources cover
	// Perms: zone_read dns_edit ssl_edit zone_settings_edit
	// origin_rules_edit (the five Daal asks for), *_read variants, and
	// anything more (user_details api_tokens workers_routes
	// firewall_services page_rules workers_scripts registrar billing
	// members) that makes a token too broad.
	Perms []string `json:"perms"`
}

// CFFault makes matching calls fail.
type CFFault struct {
	Method string `json:"method"`
	Path   string `json:"path"` // regexp on the request path (after /client/v4)
	Status int    `json:"status"`
	Skip   int    `json:"skip,omitempty"`  // let this many matching calls through first
	Times  int    `json:"times,omitempty"` // then fail this many (0 = every one)
}

type cfRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
	TTL     int    `json:"ttl"`
}

type cfRule struct {
	ID               string          `json:"id,omitempty"`
	Ref              string          `json:"ref,omitempty"`
	Expression       string          `json:"expression"`
	Action           string          `json:"action"`
	ActionParameters json.RawMessage `json:"action_parameters,omitempty"`
	Description      string          `json:"description,omitempty"`
	Enabled          *bool           `json:"enabled,omitempty"`
	Logging          json.RawMessage `json:"logging,omitempty"`
}

type cfAOPCert struct {
	ID      string `json:"id"`
	CertPEM string `json:"certificate"`
	KeyPEM  string `json:"private_key"`
}

type cfZone struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	AccountID   string            `json:"account_id"`
	Status      string            `json:"status"`
	Settings    map[string]string `json:"settings"`
	AOPEnabled  bool              `json:"aop_enabled"`
	AOPCerts    []cfAOPCert       `json:"aop_certs"`
	Records     []cfRecord        `json:"records"`
	Ruleset     bool              `json:"ruleset_exists"`
	OriginRules []cfRule          `json:"origin_rules"`

	// echOnAt is when the `ech` setting last went on through the API.
	// The HTTPS record carries the config only cfECHPublishLag later,
	// as Cloudflare's does: publishing is not instant.
	echOnAt time.Time
}

// cfECHPublishLag is how long after ECH is turned on the zone's HTTPS
// records start carrying the config.
const cfECHPublishLag = 3 * time.Second

type cfOriginCert struct {
	ID        string   `json:"id"`
	Hostnames []string `json:"hostnames"`
	ZoneID    string   `json:"zone_id"`
	PEM       string   `json:"certificate"`
	Revoked   bool     `json:"revoked"`
}

// CFState is cf-state.json: the account as the edge must obey it.
type CFState struct {
	Zones []*cfZone         `json:"zones"`
	Certs []*cfOriginCert   `json:"origin_certs"`
	Seq   int               `json:"seq"`
	Extra map[string]string `json:"extra,omitempty"`
}

func (s *CFState) zoneByID(id string) *cfZone {
	for _, z := range s.Zones {
		if z.ID == id {
			return z
		}
	}
	return nil
}

// ZoneFor is the zone a host name lies in (the longest suffix).
func (s *CFState) ZoneFor(host string) *cfZone {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	var best *cfZone
	for _, z := range s.Zones {
		if host == z.Name || strings.HasSuffix(host, "."+z.Name) {
			if best == nil || len(z.Name) > len(best.Name) {
				best = z
			}
		}
	}
	return best
}

// Proxied is the proxied A record for host, if any.
func (z *cfZone) Proxied(host string) (cfRecord, bool) {
	for _, r := range z.Records {
		if r.Type == "A" && r.Proxied && strings.EqualFold(r.Name, host) {
			return r, true
		}
	}
	return cfRecord{}, false
}

var hostExprRE = regexp.MustCompile(`^\(http\.host eq "([^"]+)"\)$`)

// OriginPort is the port an enabled origin rule sends host to (443 when none).
func (z *cfZone) OriginPort(host string) int {
	for _, r := range z.OriginRules {
		if r.Enabled != nil && !*r.Enabled {
			continue
		}
		m := hostExprRE.FindStringSubmatch(r.Expression)
		if r.Action != "route" || m == nil || !strings.EqualFold(m[1], host) {
			continue
		}
		var ap struct {
			Origin struct {
				Port int `json:"port"`
			} `json:"origin"`
		}
		if json.Unmarshal(r.ActionParameters, &ap) == nil && ap.Origin.Port > 0 {
			return ap.Origin.Port
		}
	}
	return 443
}

// LoadCFState reads the fake's state as the edge sees it.
func LoadCFState(run string) (*CFState, error) {
	var s CFState
	body, err := os.ReadFile(filepath.Join(run, cfStateFile))
	if err != nil {
		return nil, err
	}
	return &s, json.Unmarshal(body, &s)
}

// CFRequest is one line of cf-requests.jsonl.
type CFRequest struct {
	TS      string `json:"ts"`
	Host    string `json:"host"`
	Method  string `json:"method"`
	Path    string `json:"path"`
	Status  int    `json:"status"`
	TokenID string `json:"token_id,omitempty"`
}

func CFRequests(run string) []CFRequest {
	body, _ := os.ReadFile(filepath.Join(run, cfReqFile))
	var out []CFRequest
	for _, l := range strings.Split(string(body), "\n") {
		var q CFRequest
		if json.Unmarshal([]byte(l), &q) == nil && q.Method != "" {
			out = append(out, q)
		}
	}
	return out
}

// The lab account: the publisher's zone, and a second one only a
// too-broad token can see.
func initialCFState() *CFState {
	mk := func(id, name string) *cfZone {
		return &cfZone{ID: id, Name: name, AccountID: "0a1b2c3d4e5f60718293a4b5c6d7e8f9", Status: "active",
			// A new free zone: Flexible SSL (the edge would dial the
			// origin in plain HTTP), WebSockets on, ECH on (plan §2.5).
			Settings: map[string]string{"ssl": "flexible", "websockets": "on", "ech": "on", "min_tls_version": "1.0"}}
	}
	pub := mk("3f2e1d0c9b8a79685746352413021f0e", CDNZone)
	// The publisher's zone has ECH off, as the owner's real zone had
	// (2026-11-21: it published no ech parameter, and the CDN route
	// could not be signed). Provisioning must turn it on and wait for
	// the record; removal turns it off again.
	pub.Settings["ech"] = "off"
	return &CFState{Zones: []*cfZone{pub, mk("9e8d7c6b5a4938271605f4e3d2c1b0a9", "otherzone.example")}}
}

type fakeCF struct {
	mu     sync.Mutex
	run    string
	st     *CFState
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	faults map[int]int // fault index → matching calls seen
	reqLog *os.File
	next   int
}

func newCFID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (f *fakeCF) save() {
	f.st.Seq++
	body, _ := json.MarshalIndent(f.st, "", "  ")
	tmp := filepath.Join(f.run, cfStateFile+".tmp")
	if os.WriteFile(tmp, body, 0o600) == nil {
		_ = os.Rename(tmp, filepath.Join(f.run, cfStateFile))
	}
}

func (f *fakeCF) tokens() []CFToken {
	var ts []CFToken
	_ = loadJSON(filepath.Join(f.run, cfTokensFile), &ts)
	return ts
}

func (f *fakeCF) fault(method, path string) int {
	var fs []CFFault
	if loadJSON(filepath.Join(f.run, cfFaultsFile), &fs) != nil {
		return 0
	}
	for i, ft := range fs {
		if ft.Method != method {
			continue
		}
		if ok, _ := regexp.MatchString(ft.Path, path); !ok {
			continue
		}
		f.faults[i]++
		n := f.faults[i] - ft.Skip
		if n >= 1 && (ft.Times == 0 || n <= ft.Times) {
			return ft.Status
		}
	}
	return 0
}

func hasPerm(t CFToken, want ...string) bool {
	for _, p := range t.Perms {
		for _, w := range want {
			if p == w {
				return true
			}
		}
	}
	return false
}

func tokenSees(t CFToken, zone string) bool {
	for _, z := range t.Zones {
		if strings.EqualFold(z, zone) {
			return true
		}
	}
	return false
}

func cfEnvelope(w http.ResponseWriter, status int, result any, errs ...string) {
	type e struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	env := map[string]any{"success": status/100 == 2, "errors": []e{}, "messages": []any{}, "result": result}
	if len(errs) > 0 {
		var es []e
		for _, m := range errs {
			es = append(es, e{Code: 10000 + status, Message: m})
		}
		env["errors"] = es
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(env)
}

func cmdFakeCF(args []string) int {
	fs := flag.NewFlagSet("fakecf", flag.ExitOnError)
	run := fs.String("run-dir", "", "")
	listen := fs.String("listen", CFAPIIP, "")
	_ = fs.Parse(args)
	f, err := newFakeCF(*run)
	if err != nil {
		log.Fatalf("fakecf: %v", err)
	}
	labCA, labKey, err := loadCA(*run)
	if err != nil {
		log.Fatalf("fakecf: %v", err)
	}
	var cmu sync.Mutex
	cache := map[string]*tls.Certificate{}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cmu.Lock()
		defer cmu.Unlock()
		if c, ok := cache[h.ServerName]; ok {
			return c, nil
		}
		c, err := mintLeaf(labCA, labKey, h.ServerName)
		if err == nil {
			cache[h.ServerName] = c
		}
		return c, err
	}}
	ln, err := tls.Listen("tcp4", net.JoinHostPort(*listen, "443"), cfg)
	if err != nil {
		log.Fatalf("fakecf: %v", err)
	}
	fmt.Println("fakecf: listening")
	log.Fatal((&http.Server{Handler: f}).Serve(ln))
	return 1
}

func newFakeCF(run string) (*fakeCF, error) {
	f := &fakeCF{run: run, st: initialCFState(), faults: map[int]int{}}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1),
		Subject:   pkix.Name{CommonName: "Cloudflare Origin ECC CA (worldbox lab, not real)", Organization: []string{"worldbox"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	f.caCert, _ = x509.ParseCertificate(der)
	f.caKey = key
	if err := os.WriteFile(filepath.Join(run, cfOriginCA), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return nil, err
	}
	if f.reqLog, err = os.OpenFile(filepath.Join(run, cfReqFile), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err != nil {
		return nil, err
	}
	f.save()
	return f, nil
}

func (f *fakeCF) ServeHTTP(w0 http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w := &statusRecorder{ResponseWriter: w0, status: 200}
	host := strings.ToLower(strings.Split(r.Host, ":")[0])
	tokID := ""
	defer func() {
		line, _ := json.Marshal(CFRequest{TS: time.Now().UTC().Format(time.RFC3339Nano), Host: host, Method: r.Method, Path: r.URL.Path, Status: w.status, TokenID: tokID})
		f.reqLog.Write(append(line, '\n'))
	}()
	switch host {
	case "www.cloudflare.com":
		switch r.URL.Path {
		case "/ips-v4":
			fmt.Fprintln(w, strings.Join(CDNPublishedV4, "\n"))
		case "/ips-v6":
			fmt.Fprintln(w, "2001:db8:cf00::/40")
		default:
			http.NotFound(w, r)
		}
		return
	case "cloudflare-dns.com", "dns.google":
		f.doh(w, r)
		return
	case "api.cloudflare.com":
	default:
		http.NotFound(w, r)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/client/v4")
	auth := r.Header.Get("Authorization")
	var tok *CFToken
	for _, t := range f.tokens() {
		if t.Token != "" && auth == "Bearer "+t.Token {
			t := t
			tok = &t
		}
	}
	if tok == nil || tok.Status != "active" {
		cfEnvelope(w, 401, nil, "Invalid API Token")
		return
	}
	tokID = tok.ID
	if st := f.fault(r.Method, path); st != 0 {
		cfEnvelope(w, st, nil, "worldbox: injected fault")
		return
	}
	f.api(w, r, path, *tok)
}

func (f *fakeCF) doh(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/dns-query" {
		http.NotFound(w, r)
		return
	}
	q, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
	if err != nil {
		http.Error(w, "bad dns parameter", 400)
		return
	}
	_, name, _, _, err := dnsQuestion(q)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	exists, ech := false, []byte(nil)
	if z := f.st.ZoneFor(name); z != nil {
		if _, ok := z.Proxied(name); ok {
			exists = true
			if z.Settings["ech"] == "on" && time.Since(z.echOnAt) >= cfECHPublishLag {
				ech, _, _, _ = LabECH(f.run)
			}
		}
	}
	msg, err := dnsHTTPSAnswer(q, exists, ech)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	_, _ = w.Write(msg)
}

var (
	reZoneSub  = regexp.MustCompile(`^/zones/([0-9a-f]{32})(/.*)?$`)
	reCertID   = regexp.MustCompile(`^/certificates/([0-9a-f]{32})$`)
	reAccount  = regexp.MustCompile(`^/accounts/([0-9a-f]{32})/(.+)$`)
	reSetting  = regexp.MustCompile(`^/settings/([a-z_0-9]+)$`)
	reRecordID = regexp.MustCompile(`^/dns_records/([0-9a-f]{32})$`)
	reAOPID    = regexp.MustCompile(`^/origin_tls_client_auth/([0-9a-f]{32})$`)
)

func (f *fakeCF) api(w http.ResponseWriter, r *http.Request, path string, t CFToken) {
	deny := func() { cfEnvelope(w, 403, nil, "Authentication error") }
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	switch {
	case path == "/user/tokens/verify" && r.Method == "GET":
		cfEnvelope(w, 200, map[string]string{"id": t.ID, "status": t.Status})
		return
	case path == "/user":
		if !hasPerm(t, "user_details") {
			deny()
			return
		}
		cfEnvelope(w, 200, map[string]string{"id": "u1"})
		return
	case path == "/user/tokens":
		if !hasPerm(t, "api_tokens") {
			deny()
			return
		}
		cfEnvelope(w, 200, []any{})
		return
	case path == "/zones" && r.Method == "GET":
		if !hasPerm(t, "zone_read", "zone_edit") {
			deny()
			return
		}
		out := []map[string]any{}
		name := strings.ToLower(r.URL.Query().Get("name"))
		for _, z := range f.st.Zones {
			if tokenSees(t, z.Name) && (name == "" || name == z.Name) {
				out = append(out, map[string]any{"id": z.ID, "name": z.Name, "status": z.Status, "account": map[string]string{"id": z.AccountID}})
			}
		}
		cfEnvelope(w, 200, out)
		return
	case path == "/certificates":
		f.certificates(w, r, body, t)
		return
	case reCertID.MatchString(path) && r.Method == "DELETE":
		if !hasPerm(t, "ssl_edit") {
			deny()
			return
		}
		id := reCertID.FindStringSubmatch(path)[1]
		for _, c := range f.st.Certs {
			if c.ID == id && !c.Revoked {
				if z := f.st.zoneByID(c.ZoneID); z == nil || !tokenSees(t, z.Name) {
					deny()
					return
				}
				c.Revoked = true
				f.save()
				cfEnvelope(w, 200, map[string]string{"id": id})
				return
			}
		}
		cfEnvelope(w, 404, nil, "certificate not found")
		return
	case reAccount.MatchString(path):
		m := reAccount.FindStringSubmatch(path)
		need := map[string]string{"workers/scripts": "workers_scripts", "registrar/domains": "registrar", "billing/profile": "billing", "members": "members"}[m[2]]
		if need == "" || !hasPerm(t, need) {
			deny()
			return
		}
		cfEnvelope(w, 200, []any{})
		return
	}
	m := reZoneSub.FindStringSubmatch(path)
	if m == nil {
		cfEnvelope(w, 501, nil, "worldbox: not modelled: "+r.Method+" "+path)
		return
	}
	z := f.st.zoneByID(m[1])
	if z == nil || !tokenSees(t, z.Name) {
		deny()
		return
	}
	f.zoneAPI(w, r, z, m[2], body, t)
}

func (f *fakeCF) certificates(w http.ResponseWriter, r *http.Request, body []byte, t CFToken) {
	deny := func() { cfEnvelope(w, 403, nil, "Authentication error") }
	switch r.Method {
	case "GET":
		if !hasPerm(t, "ssl_read", "ssl_edit") {
			deny()
			return
		}
		z := f.st.zoneByID(r.URL.Query().Get("zone_id"))
		if z == nil || !tokenSees(t, z.Name) {
			deny()
			return
		}
		out := []map[string]any{}
		for _, c := range f.st.Certs {
			if c.ZoneID == z.ID && !c.Revoked {
				out = append(out, map[string]any{"id": c.ID, "hostnames": c.Hostnames})
			}
		}
		cfEnvelope(w, 200, out)
	case "POST":
		if !hasPerm(t, "ssl_edit") {
			deny()
			return
		}
		var req struct {
			CSR       string   `json:"csr"`
			Hostnames []string `json:"hostnames"`
			Type      string   `json:"request_type"`
			Validity  int      `json:"requested_validity"`
		}
		if json.Unmarshal(body, &req) != nil || len(req.Hostnames) == 0 {
			cfEnvelope(w, 400, nil, "bad request")
			return
		}
		var zone *cfZone
		for _, h := range req.Hostnames {
			z := f.st.ZoneFor(strings.TrimPrefix(h, "*."))
			if z == nil || !tokenSees(t, z.Name) || (zone != nil && z != zone) {
				cfEnvelope(w, 400, nil, "hostname "+h+" is not in a zone this token can use")
				return
			}
			zone = z
		}
		blk, _ := pem.Decode([]byte(req.CSR))
		if blk == nil {
			cfEnvelope(w, 400, nil, "csr is not PEM")
			return
		}
		csr, err := x509.ParseCertificateRequest(blk.Bytes)
		if err != nil || csr.CheckSignature() != nil {
			cfEnvelope(w, 400, nil, "csr does not parse or verify")
			return
		}
		serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
		tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: req.Hostnames[0], Organization: []string{"CloudFlare, Inc."}},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour), DNSNames: req.Hostnames,
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, f.caCert, csr.PublicKey, f.caKey)
		if err != nil {
			cfEnvelope(w, 500, nil, err.Error())
			return
		}
		c := &cfOriginCert{ID: newCFID(), Hostnames: req.Hostnames, ZoneID: zone.ID,
			PEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
		f.st.Certs = append(f.st.Certs, c)
		f.save()
		cfEnvelope(w, 200, map[string]any{"id": c.ID, "certificate": c.PEM, "hostnames": c.Hostnames, "request_type": req.Type})
	default:
		cfEnvelope(w, 501, nil, "worldbox: not modelled")
	}
}

func (f *fakeCF) zoneAPI(w http.ResponseWriter, r *http.Request, z *cfZone, sub string, body []byte, t CFToken) {
	deny := func() { cfEnvelope(w, 403, nil, "Authentication error") }
	read := func(perm string) bool { return hasPerm(t, perm+"_read", perm+"_edit") }
	edit := func(perm string) bool { return hasPerm(t, perm+"_edit") }
	isGet := r.Method == "GET"
	switch {
	case sub == "" && isGet:
		if !read("zone") {
			deny()
			return
		}
		cfEnvelope(w, 200, map[string]any{"id": z.ID, "name": z.Name, "status": z.Status, "account": map[string]string{"id": z.AccountID}})
	case reSetting.MatchString(sub):
		name := reSetting.FindStringSubmatch(sub)[1]
		if isGet && !read("zone_settings") || !isGet && !edit("zone_settings") {
			deny()
			return
		}
		if r.Method == "PATCH" {
			var v struct {
				Value string `json:"value"`
			}
			if json.Unmarshal(body, &v) != nil || v.Value == "" {
				cfEnvelope(w, 400, nil, "value required")
				return
			}
			if name == "ech" && v.Value == "on" && z.Settings[name] != "on" {
				z.echOnAt = time.Now()
			}
			z.Settings[name] = v.Value
			f.save()
		} else if !isGet {
			cfEnvelope(w, 405, nil, "method not allowed")
			return
		}
		val, ok := z.Settings[name]
		if !ok {
			cfEnvelope(w, 404, nil, "unknown setting")
			return
		}
		cfEnvelope(w, 200, map[string]any{"id": name, "value": val, "editable": true})
	case sub == "/dns_records":
		if isGet && !read("dns") || !isGet && !edit("dns") {
			deny()
			return
		}
		if isGet {
			name := strings.ToLower(r.URL.Query().Get("name"))
			out := []map[string]any{}
			for _, rec := range z.Records {
				if name == "" || strings.EqualFold(rec.Name, name) {
					p := rec.Proxied
					out = append(out, map[string]any{"id": rec.ID, "type": rec.Type, "name": rec.Name, "content": rec.Content, "proxied": &p, "ttl": rec.TTL})
				}
			}
			cfEnvelope(w, 200, out)
			return
		}
		var rec cfRecord
		if r.Method != "POST" || json.Unmarshal(body, &rec) != nil || rec.Name == "" || rec.Content == "" {
			cfEnvelope(w, 400, nil, "bad record")
			return
		}
		if zz := f.st.ZoneFor(rec.Name); zz != z {
			cfEnvelope(w, 400, nil, "record name is not in this zone")
			return
		}
		rec.ID, rec.Name = newCFID(), strings.ToLower(rec.Name)
		z.Records = append(z.Records, rec)
		f.save()
		cfEnvelope(w, 200, rec)
	case reRecordID.MatchString(sub):
		if !edit("dns") {
			deny()
			return
		}
		id := reRecordID.FindStringSubmatch(sub)[1]
		for i, rec := range z.Records {
			if rec.ID != id {
				continue
			}
			switch r.Method {
			case "DELETE":
				z.Records = append(z.Records[:i], z.Records[i+1:]...)
				f.save()
				cfEnvelope(w, 200, map[string]string{"id": id})
			case "PATCH":
				var v struct {
					Content string `json:"content"`
				}
				if json.Unmarshal(body, &v) != nil || v.Content == "" {
					cfEnvelope(w, 400, nil, "content required")
					return
				}
				z.Records[i].Content = v.Content
				f.save()
				cfEnvelope(w, 200, z.Records[i])
			default:
				cfEnvelope(w, 405, nil, "method not allowed")
			}
			return
		}
		cfEnvelope(w, 404, nil, "record not found")
	case sub == "/origin_tls_client_auth":
		if isGet && !read("ssl") || !isGet && !edit("ssl") {
			deny()
			return
		}
		if isGet {
			out := []map[string]string{}
			for _, c := range z.AOPCerts {
				out = append(out, map[string]string{"id": c.ID, "certificate": c.CertPEM})
			}
			cfEnvelope(w, 200, out)
			return
		}
		var c cfAOPCert
		if r.Method != "POST" || json.Unmarshal(body, &c) != nil || c.CertPEM == "" || c.KeyPEM == "" {
			cfEnvelope(w, 400, nil, "certificate and private_key required")
			return
		}
		if _, err := tls.X509KeyPair([]byte(c.CertPEM), []byte(c.KeyPEM)); err != nil {
			cfEnvelope(w, 400, nil, "certificate and key do not match: "+err.Error())
			return
		}
		c.ID = newCFID()
		z.AOPCerts = append(z.AOPCerts, c)
		f.save()
		cfEnvelope(w, 200, map[string]string{"id": c.ID, "status": "active"})
	case sub == "/origin_tls_client_auth/settings":
		if isGet && !read("ssl") || !isGet && !edit("ssl") {
			deny()
			return
		}
		if r.Method == "PUT" {
			var v struct {
				Enabled *bool `json:"enabled"`
			}
			if json.Unmarshal(body, &v) != nil || v.Enabled == nil {
				cfEnvelope(w, 400, nil, "enabled required")
				return
			}
			z.AOPEnabled = *v.Enabled
			f.save()
		}
		cfEnvelope(w, 200, map[string]bool{"enabled": z.AOPEnabled})
	case reAOPID.MatchString(sub) && r.Method == "DELETE":
		if !edit("ssl") {
			deny()
			return
		}
		id := reAOPID.FindStringSubmatch(sub)[1]
		for i, c := range z.AOPCerts {
			if c.ID == id {
				z.AOPCerts = append(z.AOPCerts[:i], z.AOPCerts[i+1:]...)
				f.save()
				cfEnvelope(w, 200, map[string]string{"id": id})
				return
			}
		}
		cfEnvelope(w, 404, nil, "not found")
	case sub == "/rulesets/phases/http_request_origin/entrypoint":
		if isGet && !read("origin_rules") || !isGet && !edit("origin_rules") {
			deny()
			return
		}
		if r.Method == "PUT" {
			var v struct {
				Rules []cfRule `json:"rules"`
			}
			if json.Unmarshal(body, &v) != nil {
				cfEnvelope(w, 400, nil, "rules required")
				return
			}
			for i := range v.Rules {
				if v.Rules[i].ID == "" {
					v.Rules[i].ID = newCFID()
				}
			}
			z.OriginRules, z.Ruleset = v.Rules, true
			f.save()
		} else if !z.Ruleset {
			cfEnvelope(w, 404, nil, "could not find entrypoint ruleset in the http_request_origin phase")
			return
		}
		cfEnvelope(w, 200, map[string]any{"id": "rs" + z.ID[:8], "phase": "http_request_origin", "rules": z.OriginRules})
	case sub == "/workers/routes":
		if !hasPerm(t, "workers_routes") {
			deny()
			return
		}
		cfEnvelope(w, 200, []any{})
	case sub == "/firewall/access_rules/rules":
		if !hasPerm(t, "firewall_services") {
			deny()
			return
		}
		cfEnvelope(w, 200, []any{})
	case sub == "/pagerules":
		if !hasPerm(t, "page_rules") {
			deny()
			return
		}
		cfEnvelope(w, 200, []any{})
	default:
		cfEnvelope(w, 501, nil, "worldbox: not modelled: "+r.Method+" /zones/{id}"+sub)
	}
}

// CFFiveTokenPerms is exactly what Daal asks for (plan §2.5).
var CFFiveTokenPerms = []string{"zone_read", "dns_edit", "ssl_edit", "zone_settings_edit", "origin_rules_edit"}

// certFingerprint is the SHA-256 of a PEM certificate's DER, hex.
func certFingerprint(pemBytes []byte) string {
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return ""
	}
	sum := sha256.Sum256(blk.Bytes)
	return hex.EncodeToString(sum[:])
}
