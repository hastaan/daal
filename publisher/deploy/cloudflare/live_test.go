package cloudflare

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeCFAPI is a tiny Cloudflare API: just enough state for the live
// client's DNS, settings and origin-rule calls, plus a log of every
// request so tests can check where the token went.
type fakeCFAPI struct {
	mu       sync.Mutex
	reqs     []string
	auths    []string
	rules    []map[string]any
	hasRules bool
	settings map[string]string
	records  []map[string]any
	next     int
}

func (f *fakeCFAPI) ok(w http.ResponseWriter, result any) {
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result, "errors": []any{}})
}

func (f *fakeCFAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reqs = append(f.reqs, r.Method+" "+r.URL.String())
	f.auths = append(f.auths, r.Header.Get("Authorization"))
	p := strings.TrimPrefix(r.URL.Path, "/client/v4")
	body, _ := io.ReadAll(r.Body)
	switch {
	case p == "/user/tokens/verify":
		f.ok(w, map[string]string{"id": "tok-9", "status": "active"})
	case p == "/zones" && r.URL.Query().Get("name") != "":
		if r.URL.Query().Get("name") == "example.co.uk" {
			f.ok(w, []map[string]any{{"id": "z1", "name": "example.co.uk", "status": "active", "account": map[string]string{"id": "a1"}}})
			return
		}
		f.ok(w, []any{})
	case p == "/zones":
		f.ok(w, []map[string]any{{"id": "z1", "name": "example.co.uk", "status": "active", "account": map[string]string{"id": "a1"}}})
	case p == "/user":
		// Echo the auth header, as a hostile or buggy server might.
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":9109,"message":"` + r.Header.Get("Authorization") + `"}]}`))
	case strings.HasSuffix(p, "/rulesets/phases/http_request_origin/entrypoint"):
		switch r.Method {
		case http.MethodGet:
			if !f.hasRules {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":10003,"message":"not found"}]}`))
				return
			}
			f.ok(w, map[string]any{"id": "rs1", "rules": f.rules})
		case http.MethodPut:
			var in struct {
				Rules []map[string]any `json:"rules"`
			}
			_ = json.Unmarshal(body, &in)
			f.rules, f.hasRules = in.Rules, true
			f.ok(w, map[string]any{"id": "rs1", "rules": f.rules})
		}
	case strings.Contains(p, "/settings/"):
		name := p[strings.LastIndex(p, "/")+1:]
		if r.Method == http.MethodPatch {
			var in struct {
				Value string `json:"value"`
			}
			_ = json.Unmarshal(body, &in)
			f.settings[name] = in.Value
		}
		f.ok(w, map[string]any{"id": name, "value": f.settings[name]})
	case strings.HasSuffix(p, "/dns_records") && r.Method == http.MethodGet:
		var out []map[string]any
		for _, rec := range f.records {
			if rec["name"] == r.URL.Query().Get("name") {
				out = append(out, rec)
			}
		}
		f.ok(w, out)
	case strings.HasSuffix(p, "/dns_records") && r.Method == http.MethodPost:
		var rec map[string]any
		_ = json.Unmarshal(body, &rec)
		f.next++
		rec["id"] = "rec" + string(rune('0'+f.next))
		f.records = append(f.records, rec)
		f.ok(w, rec)
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":7003,"message":"no route"}]}`))
	}
}

func newFakeAPI(t *testing.T) (*fakeCFAPI, *liveCFClient) {
	f := &fakeCFAPI{settings: map[string]string{"ssl": "flexible", "ech": "on"}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, newLiveCFClient(srv.URL+"/client/v4", srv.Client())
}

func TestLiveClient_TokenOnlyInTheHeader(t *testing.T) {
	f, c := newFakeAPI(t)
	tok := []byte(testToken)
	ctx := context.Background()
	if st, err := c.VerifyToken(ctx, tok); err != nil || st.Status != "active" {
		t.Fatalf("verify: %+v %v", st, err)
	}
	z, err := FindZone(ctx, c, tok, "relay.example.co.uk")
	if err != nil || z.ID != "z1" || z.AccountID != "a1" {
		t.Fatalf("zone: %+v %v", z, err)
	}
	// The /user handler echoes the header back: the error must not.
	r, err := c.ProbeRead(ctx, tok, "/user")
	if err != nil || r != ProbeDenied {
		t.Fatalf("probe /user: %v %v", r, err)
	}
	err = c.doRaw(ctx, tok, http.MethodGet, "/user", nil, nil, nil)
	if err == nil || strings.Contains(err.Error(), testToken) {
		t.Fatalf("token leaked into error: %v", err)
	}
	for i, req := range f.reqs {
		if strings.Contains(req, testToken) {
			t.Errorf("token in request line %q", req)
		}
		if f.auths[i] != "Bearer "+testToken {
			t.Errorf("request %q auth = %q", req, f.auths[i])
		}
	}
}

func TestLiveClient_ProbeClassification(t *testing.T) {
	_, c := newFakeAPI(t)
	ctx := context.Background()
	tok := []byte(testToken)
	if r, err := c.ProbeRead(ctx, tok, "/zones?per_page=1"); err != nil || r != ProbeAllowed {
		t.Errorf("allowed: %v %v", r, err)
	}
	if r, err := c.ProbeRead(ctx, tok, originEntrypointPath("z1")); err != nil || r != ProbeNotFound {
		t.Errorf("not found: %v %v", r, err)
	}
}

func TestLiveClient_OriginRuleKeepsOthers(t *testing.T) {
	f, c := newFakeAPI(t)
	f.hasRules = true
	f.rules = []map[string]any{{"id": "r-theirs", "ref": "theirs", "expression": `(http.host eq "www.example.co.uk")`, "action": "route",
		"action_parameters": map[string]any{"origin": map[string]any{"port": 8080}}, "version": "3", "last_updated": "x"}}
	ctx := context.Background()
	tok := []byte(testToken)
	if err := c.EnsureOriginRule(ctx, tok, "z1", "oabc", "relay.example.co.uk", 8448); err != nil {
		t.Fatal(err)
	}
	if len(f.rules) != 2 || f.rules[0]["ref"] != "theirs" || f.rules[0]["id"] != "r-theirs" {
		t.Fatalf("rules = %v", f.rules)
	}
	if _, has := f.rules[0]["version"]; has {
		t.Error("read-only field sent back")
	}
	h, port, found, err := c.OriginRule(ctx, tok, "z1", "oabc")
	if err != nil || !found || h != "relay.example.co.uk" || port != 8448 {
		t.Fatalf("read back: %s %d %v %v", h, port, found, err)
	}
	// Idempotent.
	if err := c.EnsureOriginRule(ctx, tok, "z1", "oabc", "relay.example.co.uk", 8448); err != nil || len(f.rules) != 2 {
		t.Fatalf("second ensure: %v %v", err, f.rules)
	}
	if err := c.RemoveOriginRule(ctx, tok, "z1", "oabc"); err != nil {
		t.Fatal(err)
	}
	if len(f.rules) != 1 || f.rules[0]["ref"] != "theirs" {
		t.Fatalf("after remove: %v", f.rules)
	}
	// A hostname that could break out of the expression is refused.
	if err := c.EnsureOriginRule(ctx, tok, "z1", "o2", `x") or (true`, 8448); err == nil {
		t.Fatal("expression injection accepted")
	}
}

func TestLiveClient_SettingsAndRecords(t *testing.T) {
	f, c := newFakeAPI(t)
	ctx := context.Background()
	tok := []byte(testToken)
	if err := c.SetZoneSetting(ctx, tok, "z1", "ssl", "strict"); err != nil {
		t.Fatal(err)
	}
	if v, err := c.GetZoneSetting(ctx, tok, "z1", "ssl"); err != nil || v != "strict" {
		t.Fatalf("ssl = %q %v", v, err)
	}
	ids, err := c.EnsureProxiedRecords(ctx, tok, "z1", "relay.example.co.uk", "5.75.1.2", "")
	if err != nil || len(ids) != 1 {
		t.Fatalf("ensure: %v %v", ids, err)
	}
	if f.records[0]["proxied"] != true {
		t.Errorf("record not proxied: %v", f.records[0])
	}
	if ids, err := c.EnsureProxiedRecords(ctx, tok, "z1", "relay.example.co.uk", "5.75.1.2", ""); err != nil || len(ids) != 0 {
		t.Errorf("re-ensure created %v %v", ids, err)
	}
	if _, err := c.EnsureProxiedRecords(ctx, tok, "z1", "relay.example.co.uk", "9.9.9.9", ""); err != ErrHostnameInUse {
		t.Errorf("re-point: %v", err)
	}
}

// ---- FrontTest against a local TLS server that speaks ECH ----

func selfSigned(t *testing.T, names ...string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// startEdge is a stand-in edge: TLS for the hostname (and the ECH
// public name), optional ECH keys, and a WebSocket answer for one path.
func startEdge(t *testing.T, path string, echCfg, echPriv []byte, status int) (string, *x509.CertPool) {
	t.Helper()
	cert, pool := selfSigned(t, "relay.example.co.uk", "cloudflare-ech.com")
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	if echCfg != nil {
		cfg.EncryptedClientHelloKeys = []tls.EncryptedClientHelloKey{{Config: echCfg, PrivateKey: echPriv, SendAsRetry: true}}
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				line, err := br.ReadString('\n')
				if err != nil {
					return
				}
				key := ""
				for {
					h, err := br.ReadString('\n')
					if err != nil || h == "\r\n" {
						break
					}
					if k, v, ok := strings.Cut(h, ":"); ok && strings.EqualFold(k, "Sec-WebSocket-Key") {
						key = strings.TrimSpace(v)
					}
				}
				if !strings.HasPrefix(line, "GET "+path+" ") || status != 101 {
					code := status
					if code == 101 {
						code = 404
					}
					_, _ = io.WriteString(c, "HTTP/1.1 "+strconv.Itoa(code)+" x\r\nContent-Length: 0\r\n\r\n")
					return
				}
				sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
				_, _ = io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "+
					base64.StdEncoding.EncodeToString(sum[:])+"\r\n\r\n")
			}(c)
		}
	}()
	return ln.Addr().String(), pool
}

func TestFrontTest_ECHAcceptedAndUpgraded(t *testing.T) {
	cfg, priv := newECHKey(t, "cloudflare-ech.com")
	addr, pool := startEdge(t, "/abc", cfg, priv, 101)
	res := FrontTest(context.Background(), FrontTestOpts{
		Hostname: "relay.example.co.uk", Path: "/abc", Edge: addr,
		ECHConfigList: echList(cfg), RequireECH: true, RootCAs: pool, Timeout: 5 * time.Second,
	})
	if !res.OK || !res.ECHAccepted || res.HTTPStatus != 101 || res.TLSVersion != "TLS 1.3" {
		t.Fatalf("res = %+v", res)
	}
}

func TestFrontTest_Failures(t *testing.T) {
	cfg, priv := newECHKey(t, "cloudflare-ech.com")
	otherCfg, _ := newECHKey(t, "cloudflare-ech.com")
	addr, pool := startEdge(t, "/abc", cfg, priv, 101)
	noECH, poolNo := startEdge(t, "/abc", nil, nil, 101)
	cases := map[string]FrontTestOpts{
		"wrong path":       {Path: "/nope", Edge: addr, ECHConfigList: echList(cfg), RequireECH: true, RootCAs: pool},
		"stale ech config": {Path: "/abc", Edge: addr, ECHConfigList: echList(otherCfg), RequireECH: true, RootCAs: pool},
		"no ech required":  {Path: "/abc", Edge: noECH, RequireECH: true, RootCAs: poolNo},
		"untrusted cert":   {Path: "/abc", Edge: addr, ECHConfigList: echList(cfg), RequireECH: true},
		"nothing there":    {Path: "/abc", Edge: "127.0.0.1:1", RootCAs: pool},
	}
	for name, o := range cases {
		o.Hostname, o.Timeout = "relay.example.co.uk", 3*time.Second
		if res := FrontTest(context.Background(), o); res.OK {
			t.Errorf("%s: passed: %+v", name, res)
		}
	}
	// Without requiring ECH, the plain edge passes and says ECH was off.
	res := FrontTest(context.Background(), FrontTestOpts{Hostname: "relay.example.co.uk", Path: "/abc", Edge: noECH, RootCAs: poolNo, Timeout: 3 * time.Second})
	if !res.OK || res.ECHAccepted || res.ECHOffered {
		t.Errorf("plain: %+v", res)
	}
}

// ---- the door request ----

func TestBuildDoorEnable(t *testing.T) {
	dir := t.TempDir()
	cert, _ := selfSigned(t, "example.co.uk", "*.example.co.uk")
	keyDER, _ := x509.MarshalECPrivateKey(cert.PrivateKey.(*ecdsa.PrivateKey))
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	mat, err := NewAOPMaterial(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rec := &FrontRecord{
		Hostname: "relay.example.co.uk", OriginPath: "/0123456789abcdef0123456789abcdef",
		OriginCACertPath: write("c.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})),
		OriginCAPrivPath: write("c.key", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})),
		AOPCACertPath:    write("ca.pem", mat.CACertPEM),
	}
	// No ranges for the relay's box firewall: refused.
	if _, err := BuildDoorEnable(rec); err == nil {
		t.Fatal("a door with no Cloudflare ranges for the box firewall accepted")
	}
	rec.EdgeRanges = []string{"173.245.48.0/20", "2400:cb00::/32"}
	req, err := BuildDoorEnable(rec)
	if err != nil {
		t.Fatal(err)
	}
	if req.Action != "enable" || req.Port != 8448 || req.WSPath != rec.OriginPath || len(req.EdgeRanges) != 2 {
		t.Fatalf("req = %+v", req)
	}
	// JSON names pinned against the box (cmd/daal-relay-mgmt cdnReq).
	b, _ := json.Marshal(req)
	for _, k := range []string{`"action"`, `"port"`, `"ws_path"`, `"origin_cert_pem"`, `"origin_key_pem"`, `"aop_ca_pem"`, `"edge_ranges"`} {
		if !strings.Contains(string(b), k) {
			t.Errorf("missing %s in %s", k, b)
		}
	}
	// A certificate that does not cover the hostname is refused.
	rec.Hostname = "relay.other.org"
	if _, err := BuildDoorEnable(rec); err == nil {
		t.Error("certificate for another name accepted")
	}
	// The origin-pull CA must be a CA.
	rec.Hostname = "relay.example.co.uk"
	rec.AOPCACertPath = rec.OriginCACertPath
	if _, err := BuildDoorEnable(rec); err == nil {
		t.Error("a leaf accepted as the origin-pull CA")
	}
}
