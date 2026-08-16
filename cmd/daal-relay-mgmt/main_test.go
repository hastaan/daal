package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// --- helpers ---

func newTestServer(t *testing.T) (*server, ed25519.PublicKey, ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config.json")
	if err := os.WriteFile(configPath, []byte(`{"inbounds":[{"type":"vless","users":[{"uuid":""}],"tls":{"server_name":"","reality":{"private_key":"","server_names":[]}},"transport":{"path":""}}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	srv := newServer(pub, configPath)
	srv.singboxControl = func(action string) error { return nil } // no-op
	srv.now = func() time.Time { return time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC) }
	return srv, pub, priv, configPath
}

func mintToken(priv ed25519.PrivateKey, op string, ts int64) string {
	nonce := "test-nonce"
	tsStr := fmt.Sprintf("%d", ts)
	msg := []byte(nonce + ":" + tsStr + ":" + op)
	sig := ed25519.Sign(priv, msg)
	sigB64 := base64.StdEncoding.EncodeToString(sig)
	return nonce + ":" + tsStr + ":" + op + ":" + sigB64
}

// --- tests ---

// TestExactlyNRoutes enforces FRP-14 invariant 1: the mgmt API
// surface is exactly seven routes — the original three, the
// per-recipient trio, and /whoami. Adding an eighth requires a
// supplement amendment.
func TestExactlyNRoutes(t *testing.T) {
	srv, _, _, _ := newTestServer(t)
	got := append([]string{}, srv.routeNames()...)
	sort.Strings(got)
	want := []string{
		"/health",
		"/rotate-credentials",
		"/rotate-tls",
		"/users/list",
		"/users/provision",
		"/users/revoke",
		"/whoami",
	}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("route surface drift: got %v want %v", got, want)
	}
}

func TestReadPortRejectsOutsideRandomRange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "port")
	for _, port := range []string{"8443", "9999", "65001"} {
		if err := os.WriteFile(path, []byte(port+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readPort(path); err == nil {
			t.Fatalf("readPort(%s) must reject outside random per-deploy range", port)
		}
	}
	if err := os.WriteFile(path, []byte("42424\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := readPort(path); err != nil || got != 42424 {
		t.Fatalf("readPort valid = %d, %v", got, err)
	}
}

func TestHealth_NeedsNoAuth(t *testing.T) {
	srv, _, _, _ := newTestServer(t)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("/health no-auth got %d want 200", resp.StatusCode)
	}
	if srv.healthCnt.Load() != 1 {
		t.Errorf("healthCnt = %d want 1", srv.healthCnt.Load())
	}
}

func TestRotateCreds_RejectsUnsignedRequest(t *testing.T) {
	srv, _, _, _ := newTestServer(t)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/rotate-credentials", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("expected 401 for missing auth; got %d", resp.StatusCode)
	}
}

func TestRotateCreds_RejectsWrongPubkey(t *testing.T) {
	srv, _, _, _ := newTestServer(t)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	// Sign with a different key than the server expects.
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	tok := mintToken(otherPriv, "rotate-credentials", srv.now().Unix())

	req, _ := http.NewRequest("POST", ts.URL+"/rotate-credentials", nil)
	req.Header.Set("Authorization", "Daal-Mgmt-Token "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("expected 401 for wrong-pubkey signature; got %d", resp.StatusCode)
	}
}

func TestRotateCreds_RejectsExpiredTimestamp(t *testing.T) {
	srv, _, priv, _ := newTestServer(t)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	// Mint a token with timestamp 1 hour in the past.
	old := srv.now().Add(-1 * time.Hour).Unix()
	tok := mintToken(priv, "rotate-credentials", old)

	req, _ := http.NewRequest("POST", ts.URL+"/rotate-credentials", nil)
	req.Header.Set("Authorization", "Daal-Mgmt-Token "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("expected 401 for expired timestamp; got %d", resp.StatusCode)
	}
}

func TestRotateCreds_RewritesConfigAndReturnsCreds(t *testing.T) {
	srv, _, priv, configPath := newTestServer(t)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	tok := mintToken(priv, "rotate-credentials", srv.now().Unix())
	req, _ := http.NewRequest("POST", ts.URL+"/rotate-credentials", nil)
	req.Header.Set("Authorization", "Daal-Mgmt-Token "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200; got %d", resp.StatusCode)
	}
	var got rotateCredentialsResp
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got.UUID) != 36 {
		t.Errorf("UUID wrong shape: %q", got.UUID)
	}
	if len(got.RealityPrivKey) != 64 {
		t.Errorf("RealityPrivKey wrong shape: %q (len=%d)", got.RealityPrivKey, len(got.RealityPrivKey))
	}
	// Verify config file has new UUID + key.
	body, _ := os.ReadFile(configPath)
	if !bytes.Contains(body, []byte(got.UUID)) {
		t.Errorf("config file does not contain new UUID")
	}
	// Decode reality key to confirm it's 32 bytes hex.
	if _, err := hex.DecodeString(got.RealityPrivKey); err != nil {
		t.Errorf("reality key not hex: %v", err)
	}
	if srv.rotateCredCnt.Load() != 1 {
		t.Errorf("rotateCredCnt = %d want 1", srv.rotateCredCnt.Load())
	}
}

func TestRotateTLS_RewritesConfig(t *testing.T) {
	srv, _, priv, configPath := newTestServer(t)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	tok := mintToken(priv, "rotate-tls", srv.now().Unix())
	body, _ := json.Marshal(rotateTLSReq{NewSNI: "example.com", NewDests: []string{"example.com:443"}, NewWSPath: "/r/abcdef"})
	req, _ := http.NewRequest("POST", ts.URL+"/rotate-tls", bytes.NewReader(body))
	req.Header.Set("Authorization", "Daal-Mgmt-Token "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200; got %d", resp.StatusCode)
	}
	cfg, _ := os.ReadFile(configPath)
	if !bytes.Contains(cfg, []byte(`"server_name": "example.com"`)) {
		t.Errorf("config not rewritten with new SNI: %s", cfg)
	}
	if !bytes.Contains(cfg, []byte(`"path": "/r/abcdef"`)) {
		t.Errorf("config not rewritten with new ws path: %s", cfg)
	}
}

func TestRotateTLS_RejectsMissingFields(t *testing.T) {
	srv, _, priv, _ := newTestServer(t)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	tok := mintToken(priv, "rotate-tls", srv.now().Unix())
	body, _ := json.Marshal(rotateTLSReq{NewSNI: "", NewDests: nil})
	req, _ := http.NewRequest("POST", ts.URL+"/rotate-tls", bytes.NewReader(body))
	req.Header.Set("Authorization", "Daal-Mgmt-Token "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Errorf("expected 400 for missing fields; got %d", resp.StatusCode)
	}
}

func TestSelfSignedCert_FingerprintStableAcrossRestarts(t *testing.T) {
	tmp := t.TempDir()
	certPath := filepath.Join(tmp, "cert.pem")
	keyPath := filepath.Join(tmp, "key.pem")
	fpPath := filepath.Join(tmp, "mgmt-tls.fpr")

	cert1, err := ensureSelfSignedCert(certPath, keyPath, fpPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert1.Certificate) == 0 {
		t.Fatalf("cert1 empty")
	}
	body1, _ := os.ReadFile(fpPath)
	fp1 := strings.TrimSpace(string(body1))

	// Second call: must re-use the on-disk cert (no regen).
	cert2, err := ensureSelfSignedCert(certPath, keyPath, fpPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cert1.Certificate[0], cert2.Certificate[0]) {
		t.Errorf("cert regenerated on reload (must be stable)")
	}
	body2, _ := os.ReadFile(fpPath)
	fp2 := strings.TrimSpace(string(body2))
	if fp1 != fp2 {
		t.Errorf("fingerprint drift across reload: %q vs %q", fp1, fp2)
	}
	if len(fp1) != 64 {
		t.Errorf("fingerprint wrong shape (want 64 hex chars): %q", fp1)
	}
}

func TestReadPort_FromFileOrEnv(t *testing.T) {
	tmp := t.TempDir()
	portPath := filepath.Join(tmp, "port")
	if err := os.WriteFile(portPath, []byte("42424\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if p, err := readPort(portPath); err != nil || p != 42424 {
		t.Errorf("readPort file = (%d,%v) want (42424,nil)", p, err)
	}

	// File missing, env set: env wins.
	t.Setenv("DAAL_MGMT_PORT", "31337")
	if p, err := readPort("/does/not/exist"); err != nil || p != 31337 {
		t.Errorf("readPort env = (%d,%v) want (31337,nil)", p, err)
	}
}

// TestVerifyToken_OpMustMatchEndpoint pins that signing for one
// op and presenting on another endpoint is rejected.
func TestVerifyToken_OpMustMatchEndpoint(t *testing.T) {
	srv, _, priv, _ := newTestServer(t)
	tok := mintToken(priv, "rotate-credentials", srv.now().Unix())
	if err := srv.verifyToken(tok, "rotate-tls"); err == nil {
		t.Errorf("expected mismatch error; op-bound token must not work cross-endpoint")
	}
}

// --- /whoami ---

// whoamiGet issues a signed GET against /whoami with the op string
// the endpoint expects.
func whoamiGet(t *testing.T, url string, priv ed25519.PrivateKey, ts int64) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("GET", url+"/whoami", nil)
	req.Header.Set("Authorization", "Daal-Mgmt-Token "+mintToken(priv, "whoami", ts))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// TestObservedSourceIP covers the address-extraction rule directly:
// the peer address is reported as observed and never invented. The
// malformed/absent rows matter because that value is what gets written
// into a firewall allowlist — a fabricated one would be worse than an
// empty one.
func TestObservedSourceIP(t *testing.T) {
	cases := []struct {
		name       string
		remoteAddr string
		want       string
	}{
		{"ipv4 host:port", "203.0.113.7:44444", "203.0.113.7"},
		{"ipv4 empty port", "203.0.113.7:", "203.0.113.7"},
		{"ipv4 bare literal", "203.0.113.7", "203.0.113.7"},
		{"ipv6 bracketed host:port", "[2001:db8::1]:44444", "2001:db8::1"},
		{"ipv6 loopback host:port", "[::1]:44444", "::1"},
		{"ipv6 zone preserved", "[fe80::1%eth0]:44444", "fe80::1%eth0"},
		{"ipv6 bare bracketed", "[2001:db8::1]", "2001:db8::1"},
		{"ipv6 bare unbracketed", "2001:db8::1", "2001:db8::1"},
		{"absent", "", ""},
		{"whitespace only", "   ", ""},
		{"surrounding whitespace", " 203.0.113.7:44444 ", "203.0.113.7"},
		{"malformed returned verbatim", "not-an-address", "not-an-address"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := observedSourceIP(tc.remoteAddr); got != tc.want {
				t.Errorf("observedSourceIP(%q) = %q, want %q", tc.remoteAddr, got, tc.want)
			}
		})
	}
}

func TestWhoAmI_RejectsUnsignedRequest(t *testing.T) {
	srv, _, _, _ := newTestServer(t)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/whoami")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("expected 401 for missing auth; got %d", resp.StatusCode)
	}
	if srv.whoamiCnt.Load() != 0 {
		t.Errorf("whoamiCnt = %d want 0 (handler must not run unauthenticated)", srv.whoamiCnt.Load())
	}
}

// TestWhoAmI_RejectsCrossOpToken pins that /whoami has its own op
// string, so a token minted for another endpoint cannot be replayed
// onto it.
func TestWhoAmI_RejectsCrossOpToken(t *testing.T) {
	srv, _, priv, _ := newTestServer(t)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/whoami", nil)
	req.Header.Set("Authorization", "Daal-Mgmt-Token "+mintToken(priv, "users-list", srv.now().Unix()))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("cross-op token on /whoami: got %d want 401", resp.StatusCode)
	}
}

func TestWhoAmI_ReturnsObservedSourceIP(t *testing.T) {
	srv, _, priv, _ := newTestServer(t)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	resp := whoamiGet(t, ts.URL, priv, srv.now().Unix())
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200; got %d", resp.StatusCode)
	}
	var got whoAmIResp
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP(got.SourceIP)
	if ip == nil || !ip.IsLoopback() {
		t.Errorf("source_ip = %q, want the harness's loopback peer address", got.SourceIP)
	}
	if got.ServerTimeUnix != srv.now().Unix() {
		t.Errorf("server_time_unix = %d want %d", got.ServerTimeUnix, srv.now().Unix())
	}
	if got.APIVersion != whoAmIAPIVersion {
		t.Errorf("api_version = %d want %d", got.APIVersion, whoAmIAPIVersion)
	}
	if srv.whoamiCnt.Load() != 1 {
		t.Errorf("whoamiCnt = %d want 1", srv.whoamiCnt.Load())
	}
}

// TestWhoAmI_IgnoresForwardedHeaders is the security property: the
// answer comes from the TCP peer, never from a client-supplied header.
// Nothing in this deployment puts a trusted proxy in front of the mgmt
// plane (systemd runs the binary with its own TLS listener), so
// honouring these headers would let a caller dictate the very value
// the endpoint exists to verify — and that value lands in a
// cloud-firewall allowlist.
func TestWhoAmI_IgnoresForwardedHeaders(t *testing.T) {
	srv, _, priv, _ := newTestServer(t)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	spoofed := []struct{ header, value string }{
		{"X-Forwarded-For", "203.0.113.7"},
		{"X-Real-IP", "198.51.100.9"},
		{"Forwarded", "for=192.0.2.60;proto=https"},
		{"X-Client-IP", "2001:db8::dead"},
	}
	req, _ := http.NewRequest("GET", ts.URL+"/whoami", nil)
	req.Header.Set("Authorization", "Daal-Mgmt-Token "+mintToken(priv, "whoami", srv.now().Unix()))
	for _, h := range spoofed {
		req.Header.Set(h.header, h.value)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200; got %d", resp.StatusCode)
	}
	var got whoAmIResp
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	for _, h := range spoofed {
		if strings.Contains(got.SourceIP, strings.SplitN(h.value, ";", 2)[0]) {
			t.Errorf("source_ip %q echoed spoofable header %s: %q", got.SourceIP, h.header, h.value)
		}
	}
	if ip := net.ParseIP(got.SourceIP); ip == nil || !ip.IsLoopback() {
		t.Errorf("source_ip = %q, want the harness's loopback peer address", got.SourceIP)
	}
}

// TestWhoAmI_MethodGate: GET is the natural verb, POST is accepted so
// the Helper's POST-shaped signed-request path needs no special case,
// everything else is 405.
func TestWhoAmI_MethodGate(t *testing.T) {
	cases := []struct {
		method string
		want   int
	}{
		{"GET", 200},
		{"POST", 200},
		{"PUT", 405},
		{"DELETE", 405},
		{"PATCH", 405},
	}
	for _, tc := range cases {
		t.Run(tc.method, func(t *testing.T) {
			srv, _, priv, _ := newTestServer(t)
			ts := httptest.NewServer(srv.routes())
			defer ts.Close()

			req, _ := http.NewRequest(tc.method, ts.URL+"/whoami", nil)
			req.Header.Set("Authorization", "Daal-Mgmt-Token "+mintToken(priv, "whoami", srv.now().Unix()))
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Errorf("%s /whoami: got %d want %d", tc.method, resp.StatusCode, tc.want)
			}
		})
	}
}

// TestWhoAmI_MalformedOrAbsentRemoteAddr drives the handler directly,
// because a real listener always supplies a well-formed RemoteAddr.
// The endpoint must still answer 200 with an honestly-empty (or
// verbatim) source_ip rather than guessing — the client treats an
// unparseable answer as "no answer" and keeps its stored value.
func TestWhoAmI_MalformedOrAbsentRemoteAddr(t *testing.T) {
	cases := []struct {
		name       string
		remoteAddr string
		want       string
	}{
		{"absent", "", ""},
		{"malformed", "not-an-address", "not-an-address"},
		{"ipv6 no port", "2001:db8::1", "2001:db8::1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, _, _, _ := newTestServer(t)
			req := httptest.NewRequest("GET", "/whoami", nil)
			req.RemoteAddr = tc.remoteAddr
			rec := httptest.NewRecorder()
			srv.handleWhoAmI(rec, req)

			if rec.Code != 200 {
				t.Fatalf("status = %d want 200", rec.Code)
			}
			var got whoAmIResp
			if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
				t.Fatal(err)
			}
			if got.SourceIP != tc.want {
				t.Errorf("source_ip = %q want %q", got.SourceIP, tc.want)
			}
			if got.APIVersion != whoAmIAPIVersion {
				t.Errorf("api_version = %d want %d", got.APIVersion, whoAmIAPIVersion)
			}
		})
	}
}
