package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Hermetic tests for the add-ons' outside world: the lab ECH key, the
// DoH answer, the DPI rules the CDN scenarios use, the fake Cloudflare
// API and edge, the fake Google, and the prerequisite detection. No
// namespaces.

func labRun(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := MakeLabCA(dir, []string{"localhost"}, []string{"127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	if err := WriteLabECH(dir); err != nil {
		t.Fatal(err)
	}
	return dir
}

func labPool(t *testing.T, run string) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	b, _ := os.ReadFile(filepath.Join(run, "lab-ca.pem"))
	if !pool.AppendCertsFromPEM(b) {
		t.Fatal("lab CA")
	}
	return pool
}

// The lab key works with Go's own ECH on both ends, and the censor's
// parser sees only the outer name in such a hello.
func TestLabECHIsRealECH(t *testing.T) {
	run := labRun(t)
	list, single, priv, err := LabECH(run)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) > 512 {
		t.Fatalf("ECHConfigList is %d bytes; the signed endpoint allows 512 (bundle.MaxECHConfigSize)", len(list))
	}
	ca, key, _ := loadCA(run)
	cert, _ := mintLeaf(ca, key, CDNHost)
	srvCfg := &tls.Config{Certificates: []tls.Certificate{*cert}, EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{{Config: single, PrivateKey: priv}}}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", srvCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan tls.ConnectionState, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		tc := c.(*tls.Conn)
		_ = tc.Handshake()
		got <- tc.ConnectionState()
	}()
	c, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{ServerName: CDNHost, RootCAs: labPool(t, run), MinVersion: tls.VersionTLS13, EncryptedClientHelloConfigList: list})
	if err != nil {
		t.Fatalf("ECH handshake: %v", err)
	}
	if !c.ConnectionState().ECHAccepted {
		t.Fatal("client: ECH not accepted")
	}
	c.Close()
	if st := <-got; !st.ECHAccepted || st.ServerName != CDNHost {
		t.Fatalf("server: ECH accepted=%v inner name %q", st.ECHAccepted, st.ServerName)
	}
	hello := realClientHello(t, &tls.Config{ServerName: CDNHost, MinVersion: tls.VersionTLS13, EncryptedClientHelloConfigList: list, InsecureSkipVerify: true})
	if sni, st := parseClientHello(hello); st != chSNI || sni != ECHPublicName {
		t.Fatalf("the censor reads %q (state %d) from an ECH hello; want the outer name %q", sni, st, ECHPublicName)
	}
}

// What the lab's DoH answers is an HTTPS record carrying the ECH config.
func TestDoHAnswerCarriesECH(t *testing.T) {
	q := []byte{0xab, 0xcd, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(CDNHost, ".") {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0, 0, 65, 0, 1)
	ech := []byte{0, 3, 1, 2, 3}
	msg, err := dnsHTTPSAnswer(q, true, ech)
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(msg) != 0xabcd || binary.BigEndian.Uint16(msg[6:]) != 1 || msg[3]&0x0f != 0 {
		t.Fatalf("header %x", msg[:12])
	}
	if !bytes.HasSuffix(msg, append([]byte{0, 5, 0, byte(len(ech))}, ech...)) {
		t.Fatal("the answer does not end with the ech SvcParam")
	}
	nx, _ := dnsHTTPSAnswer(q, false, nil)
	if nx[3]&0x0f != 3 || binary.BigEndian.Uint16(nx[6:]) != 0 {
		t.Fatal("a name with no proxied record must be NXDOMAIN")
	}
}

func pktTo(dst [4]byte, seq uint32, flags byte, payload []byte) []byte {
	p := buildRST([4]byte{198, 51, 100, 2}, dst, 40001, 443, seq, 7, flags)
	p = append(p, payload...)
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	return p
}

func TestDPIBudgetAndAllowlist(t *testing.T) {
	grey, clean := [4]byte{198, 19, 8, 10}, [4]byte{198, 19, 8, 130}
	e := newDPIEngine([]DPIRule{{When: "budget", Packets: 6, Dst: "198.19.8.0/26", Action: "drop"}})
	for _, dst := range [][4]byte{grey, clean} {
		var v []bool
		seq := uint32(100)
		v = append(v, e.verdict(pktTo(dst, seq, tcpSYN, nil)))
		seq++
		for i := 0; i < 8; i++ {
			v = append(v, e.verdict(pktTo(dst, seq, tcpACK, []byte("x"))))
			seq++
		}
		want := 6
		if dst == clean {
			want = 9
		}
		n := 0
		for _, ok := range v {
			if ok {
				n++
			}
		}
		if n != want || (want < len(v) && v[want]) {
			t.Errorf("dst %v: %d of %d packets forwarded (%v), want the first %d", dst, n, len(v), v, want)
		}
	}
	allowed := realClientHello(t, &tls.Config{ServerName: "www.wb-allowed.example", InsecureSkipVerify: true, CurvePreferences: []tls.CurveID{tls.X25519}})
	other := realClientHello(t, &tls.Config{ServerName: "zone.example", InsecureSkipVerify: true, CurvePreferences: []tls.CurveID{tls.X25519}})
	for _, c := range []struct {
		hello []byte
		dst   [4]byte
		pass  bool
	}{{allowed, grey, true}, {other, grey, false}, {other, [4]byte{203, 0, 113, 10}, true}} {
		e := newDPIEngine([]DPIRule{{When: "tls_sni_not", SNI: []string{"www.wb-allowed.example"}, Dst: "198.19.8.0/24", Action: "drop"}})
		_ = e.verdict(pktTo(c.dst, 1, tcpSYN, nil))
		if got := e.verdict(pktTo(c.dst, 2, tcpACK, c.hello)); got != c.pass {
			t.Errorf("allowlist: dst %v hello forwarded=%v, want %v", c.dst, got, c.pass)
		}
	}
	for _, r := range []DPIRule{{When: "budget", Action: "drop"}, {When: "budget", Packets: 6, SNI: []string{"x"}, Action: "drop"},
		{When: "tls_sni_not", Action: "drop"}, {When: "first_data", Dst: "10.0.0.0/33", Action: "drop"}} {
		if r.validate() == nil {
			t.Errorf("rule %+v validated", r)
		}
	}
}

func cfDo(t *testing.T, h http.Handler, method, host, path, tok string, body any) (int, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	r := httptest.NewRequest(method, "https://"+host+path, rd)
	if tok != "" {
		r.Header.Set("Authorization", "Bearer "+tok)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var env map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &env)
	return w.Code, env
}

func TestFakeCloudflareAPI(t *testing.T) {
	run := labRun(t)
	f, err := newFakeCF(run)
	if err != nil {
		t.Fatal(err)
	}
	toks := []CFToken{{Token: "good", ID: "g", Status: "active", Zones: []string{CDNZone}, Perms: CFFiveTokenPerms},
		{Token: "two", ID: "t", Status: "active", Zones: []string{CDNZone, "otherzone.example"}, Perms: CFFiveTokenPerms},
		{Token: "nodns", ID: "n", Status: "active", Zones: []string{CDNZone}, Perms: []string{"zone_read"}}}
	b, _ := json.Marshal(toks)
	_ = os.WriteFile(filepath.Join(run, cfTokensFile), b, 0o600)
	api := "api.cloudflare.com"
	if code, _ := cfDo(t, f, "GET", api, "/client/v4/user/tokens/verify", "nope", nil); code != 401 {
		t.Fatalf("unknown token: %d", code)
	}
	_, env := cfDo(t, f, "GET", api, "/client/v4/zones?per_page=50", "good", nil)
	zones, _ := env["result"].([]any)
	_, env2 := cfDo(t, f, "GET", api, "/client/v4/zones?per_page=50", "two", nil)
	zones2, _ := env2["result"].([]any)
	if len(zones) != 1 || len(zones2) != 2 {
		t.Fatalf("zones: one-zone token sees %d, two-zone token %d", len(zones), len(zones2))
	}
	zid := zones[0].(map[string]any)["id"].(string)
	zp := "/client/v4/zones/" + zid
	if code, _ := cfDo(t, f, "GET", api, zp+"/dns_records?per_page=1", "nodns", nil); code != 403 {
		t.Fatalf("a token without DNS may list records: %d", code)
	}
	if code, _ := cfDo(t, f, "GET", api, "/client/v4/user", "good", nil); code != 403 {
		t.Fatalf("a five-permission token may read the user: %d", code)
	}
	if code, _ := cfDo(t, f, "GET", api, zp+"/rulesets/phases/http_request_origin/entrypoint", "good", nil); code != 404 {
		t.Fatalf("no entrypoint yet must be 404: %d", code)
	}
	cfDo(t, f, "PATCH", api, zp+"/settings/ssl", "good", map[string]string{"value": "strict"})
	cfDo(t, f, "POST", api, zp+"/dns_records", "good", map[string]any{"type": "A", "name": CDNHost, "content": "203.0.113.10", "proxied": true, "ttl": 1})
	on := true
	cfDo(t, f, "PUT", api, zp+"/rulesets/phases/http_request_origin/entrypoint", "good", map[string]any{"rules": []cfRule{{Ref: "x",
		Expression: `(http.host eq "` + CDNHost + `")`, Action: "route", ActionParameters: json.RawMessage(`{"origin":{"port":8448}}`), Enabled: &on}}})
	// Origin CA: a CSR for the zone and its wildcard.
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: CDNZone}, DNSNames: []string{CDNZone, "*." + CDNZone}}, k)
	_, env = cfDo(t, f, "POST", api, "/client/v4/certificates", "good", map[string]any{"csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})),
		"hostnames": []string{CDNZone, "*." + CDNZone}, "request_type": "origin-ecc", "requested_validity": 5475})
	res, _ := env["result"].(map[string]any)
	cpem, _ := res["certificate"].(string)
	blk, _ := pem.Decode([]byte(cpem))
	if blk == nil {
		t.Fatalf("no certificate: %v", env)
	}
	leaf, _ := x509.ParseCertificate(blk.Bytes)
	roots := x509.NewCertPool()
	rb, _ := os.ReadFile(filepath.Join(run, cfOriginCA))
	roots.AppendCertsFromPEM(rb)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: CDNHost}); err != nil {
		t.Fatalf("the origin certificate does not verify for %s against the lab Origin CA: %v", CDNHost, err)
	}
	st, err := LoadCFState(run)
	if err != nil {
		t.Fatal(err)
	}
	z := st.ZoneFor(CDNHost)
	if r, ok := z.Proxied(CDNHost); !ok || r.Content != "203.0.113.10" || z.OriginPort(CDNHost) != 8448 || z.Settings["ssl"] != "strict" {
		t.Fatalf("state the edge reads: record=%v port=%d ssl=%q", r, z.OriginPort(CDNHost), z.Settings["ssl"])
	}
	// DoH: the proxied host has an HTTPS record with the lab's ECH config
	// once ECH is on (the publisher's zone starts with it off, as the
	// owner's did) and the publishing lag has passed.
	q := []byte{0, 7, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(CDNHost, ".") {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0, 0, 65, 0, 1)
	doh := func() []byte {
		r := httptest.NewRequest("GET", "https://cloudflare-dns.com/dns-query?dns="+base64.RawURLEncoding.EncodeToString(q), nil)
		w := httptest.NewRecorder()
		f.ServeHTTP(w, r)
		return w.Body.Bytes()
	}
	list, _, _, _ := LabECH(run)
	if bytes.Contains(doh(), list) {
		t.Fatal("DoH answer carries an ECH config while the zone has ECH off")
	}
	cfDo(t, f, "PATCH", api, zp+"/settings/ech", "good", map[string]string{"value": "on"})
	if bytes.Contains(doh(), list) {
		t.Fatal("DoH answer carries the ECH config the moment ECH went on: publishing is not instant")
	}
	f.mu.Lock()
	f.st.ZoneFor(CDNHost).echOnAt = time.Now().Add(-cfECHPublishLag)
	f.mu.Unlock()
	if !bytes.Contains(doh(), list) {
		t.Fatal("DoH answer for the proxied host carries no ECH config")
	}
	// A fault fails the matching call, and only the times asked.
	fb, _ := json.Marshal([]CFFault{{Method: "PATCH", Path: `/settings/websockets$`, Status: 500, Times: 1}})
	_ = os.WriteFile(filepath.Join(run, cfFaultsFile), fb, 0o644)
	c1, _ := cfDo(t, f, "PATCH", api, zp+"/settings/websockets", "good", map[string]string{"value": "on"})
	c2, _ := cfDo(t, f, "PATCH", api, zp+"/settings/websockets", "good", map[string]string{"value": "on"})
	if c1 != 500 || c2 != 200 {
		t.Fatalf("fault: %d then %d, want 500 then 200", c1, c2)
	}
	if reqs := CFRequests(run); len(reqs) == 0 || strings.Contains(fmt.Sprint(reqs), "good") {
		t.Fatalf("request log empty, or it holds a token: %v", reqs)
	}
}

// The edge enforces SNI == Host, serves only proxied hosts, and pulls
// from the origin on the port the origin rule names.
func TestFakeCDNEdge(t *testing.T) {
	run := labRun(t)
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "origin-ok host=%s path=%s", r.Host, r.URL.Path)
	}))
	defer origin.Close()
	_, portS, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "https://"))
	port, _ := strconv.Atoi(portS)
	on := true
	st := initialCFState()
	z := st.ZoneFor(CDNHost)
	z.Settings["ssl"] = "full"
	z.Records = []cfRecord{{ID: newCFID(), Type: "A", Name: CDNHost, Content: "127.0.0.1", Proxied: true}}
	z.OriginRules = []cfRule{{Expression: `(http.host eq "` + CDNHost + `")`, Action: "route", ActionParameters: json.RawMessage(fmt.Sprintf(`{"origin":{"port":%d}}`, port)), Enabled: &on}}
	b, _ := json.Marshal(st)
	_ = os.WriteFile(filepath.Join(run, cfStateFile), b, 0o600)
	e := &edge{run: run, pullFrom: "127.0.0.1", wsIdle: time.Minute, certs: map[string]*tls.Certificate{}}
	e.logf, _ = os.Create(filepath.Join(run, cdnReqFile))
	cfg, err := e.tlsConfig()
	if err != nil {
		t.Fatal(err)
	}
	ln, _ := net.Listen("tcp4", "127.0.0.1:0")
	srv := &http.Server{Handler: e, TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}}
	go srv.Serve(tls.NewListener(ln, cfg))
	defer srv.Close()
	list, _, _, _ := LabECH(run)
	get := func(sni, host string, ech bool) (int, string) {
		tc := &tls.Config{ServerName: sni, RootCAs: labPool(t, run)}
		if ech {
			tc.MinVersion, tc.EncryptedClientHelloConfigList = tls.VersionTLS13, list
		}
		conn, err := tls.Dial("tcp4", ln.Addr().String(), tc)
		if err != nil {
			t.Fatalf("dial %s: %v", sni, err)
		}
		defer conn.Close()
		fmt.Fprintf(conn, "GET /p HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}
	if code, body := get(CDNHost, CDNHost, true); code != 200 || !strings.Contains(body, "origin-ok") {
		t.Fatalf("proxied host with ECH: %d %q", code, body)
	}
	if code, _ := get("www.wb-control.example", CDNHost, false); code != http.StatusMisdirectedRequest {
		t.Fatalf("SNI != Host: %d, want 421 (no fronting through this edge)", code)
	}
	if code, _ := get("nothing."+CDNZone, "nothing."+CDNZone, false); code != 403 {
		t.Fatalf("a host with no proxied record: %d, want 403", code)
	}
	reqs := CDNRequests(run)
	if len(reqs) != 3 || !reqs[0].ECH || reqs[0].SNI != CDNHost || reqs[1].Why != "sni_host_mismatch" {
		t.Fatalf("edge log: %+v", reqs)
	}
}

// The web app runs Code.gs's rules on the script that was deployed: the
// product's own Code.gs, filled in as the product fills it.
func TestFakeGoogleRunsTheProductScript(t *testing.T) {
	run := labRun(t)
	src, err := os.ReadFile(filepath.Join(repoRoot(t), "publisher/deploy/freshness/backends/appsscript/Code.gs"))
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	code := strings.ReplaceAll(string(src), "__DAAL_WRITE_KEY_B64__", base64.StdEncoding.EncodeToString(key))
	_ = os.MkdirAll(filepath.Join(run, googlePasteDir), 0o755)
	dep := "AKfycbTestDeployment0123456789"
	_ = os.WriteFile(filepath.Join(run, googlePasteDir, dep+".gs"), []byte(code), 0o644)
	g := &googleFake{run: run, projects: map[string]*gProject{}, apps: map[string]*gWebApp{}, echo: map[string]string{}, revoked: map[string]bool{}, stageHit: map[string]bool{}}
	g.logf, _ = os.Create(filepath.Join(run, googleReqFile))
	exec := "https://script.google.com/macros/s/" + dep + "/exec"
	call := func(method, u string, body []byte) (int, string, string) {
		r := httptest.NewRequest(method, u, bytes.NewReader(body))
		w := httptest.NewRecorder()
		g.ServeHTTP(w, r)
		return w.Code, w.Header().Get("Location"), w.Body.String()
	}
	follow := func(method, u string, body []byte) string {
		code, loc, _ := call(method, u, body)
		if code != 302 {
			t.Fatalf("%s %s: %d, want Apps Script's 302", method, u, code)
		}
		lu, _ := url.Parse(loc)
		if lu.Host != "script.googleusercontent.com" {
			t.Fatalf("redirect to %q", lu.Host)
		}
		_, _, out := call("GET", loc, nil)
		return out
	}
	// The slot's read token, as the publisher's helper derives it.
	token := func(slot string) string {
		m := hmac.New(sha256.New, key)
		m.Write([]byte("daal-read-v2\n" + slot))
		return base64.RawURLEncoding.EncodeToString(m.Sum(nil)[:16])
	}
	post := func(slot string, seq int, blob string, k []byte) string {
		m := hmac.New(sha256.New, k)
		m.Write([]byte("daal-refresh-v2\n" + slot + "\n" + strconv.Itoa(seq) + "\n" + blob))
		b, _ := json.Marshal(map[string]any{"slot": slot, "seq": seq, "blob": blob, "mac": hex.EncodeToString(m.Sum(nil))})
		return follow("POST", exec, b)
	}
	const a, b = "AAAAAAAAAAA", "BBBBBBBBBBB"
	blobA := `{"kind":"daal-refresh-v2","slot":"AAAAAAAAAAA","x":1}`
	if out := post(a, 5, blobA, key); !strings.Contains(out, `"ok":true`) {
		t.Fatalf("update: %s", out)
	}
	if out := post(a, 6, "x", []byte("another key, another key, 32 by")); !strings.Contains(out, `"refused"`) {
		t.Fatalf("stranger's key: %s", out)
	}
	if out := post(a, 4, "y", key); !strings.Contains(out, `"stale"`) {
		t.Fatalf("older update: %s", out)
	}
	// Another slot has its own numbers.
	if out := post(b, 1, `{"kind":"daal-refresh-v2","slot":"BBBBBBBBBBB"}`, key); !strings.Contains(out, `"ok":true`) {
		t.Fatalf("second slot: %s", out)
	}
	// The single-relay body of the first build (no slot) is malformed.
	old, _ := json.Marshal(map[string]any{"seq": 9, "blob": "z", "mac": "00"})
	if out := follow("POST", exec, old); !strings.Contains(out, `"malformed"`) {
		t.Fatalf("a body with no slot: %s", out)
	}
	if out := follow("GET", exec+"?s="+a+"&k="+token(a), nil); out != blobA {
		t.Fatalf("doGet with the slot's k: %q", out)
	}
	for _, q := range []string{"?s=" + a + "&k=wrong", "?s=" + a + "&k=" + token(b), "?k=" + token(a), "?s=CCCCCCCCCCC&k=" + token("CCCCCCCCCCC")} {
		if out := follow("GET", exec+q, nil); out != "Nothing here." {
			t.Fatalf("doGet %s: %q", q, out)
		}
	}
	if code, _, _ := call("GET", "https://script.google.com/macros/s/AKfycbNoSuchDeployment000000/exec", nil); code != 404 {
		t.Fatalf("unknown deployment: %d", code)
	}
}

func TestPrereqDetection(t *testing.T) {
	repo := t.TempDir()
	_ = os.MkdirAll(filepath.Join(repo, "core/abi"), 0o755)
	q := PreStandbyKey
	if q.Present(repo) {
		t.Fatal("present in an empty tree")
	}
	_ = os.WriteFile(filepath.Join(repo, "core/abi/standby_test.go"), []byte("package abi\nfunc StandbyKey(a, b string) (string, error)\n"), 0o644)
	if q.Present(repo) {
		t.Fatal("a test file must not count")
	}
	_ = os.WriteFile(filepath.Join(repo, "core/abi/standby.go"), []byte("package abi\n\nfunc StandbyKey(relayPackID, key string) (string, error) { return \"\", nil }\n"), 0o644)
	if !q.Present(repo) {
		t.Fatal("not detected")
	}
}

// A variable that is a prefix of another must not eat it.
func TestSubstVarsLongestFirst(t *testing.T) {
	vars := scenarioVars("cover.example")
	for i := 0; i < 50; i++ { // map order is random: try it many times
		if got := substVars("ip daddr $EDGE_NET_A drop; $EDGE_NET", vars); got != "ip daddr "+CDNPublishedV4[0]+" drop; "+CDNEdgeNet {
			t.Fatalf("substVars: %q", got)
		}
	}
}
