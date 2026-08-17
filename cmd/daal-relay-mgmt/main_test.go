package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	// The fixture is the real four-inbound shape a provisioned box has,
	// not a single untagged inbound: two recipients, rows in both
	// vless-family inbounds, plus the two non-vless inbounds whose user
	// shapes the rewriters must never touch. The previous fixture encoded
	// the very single-index assumption the rewriters used to make, so it
	// could not have caught any of the bugs in that class.
	if err := os.WriteFile(configPath, []byte(`{
  "inbounds": [
    {"type":"vless","tag":"vless-in","listen_port":443,
     "users":[{"uuid":"uuid-1","name":"r1","flow":"xtls-rprx-vision"},
              {"uuid":"uuid-2","name":"r2","flow":"xtls-rprx-vision"}],
     "tls":{"enabled":true,"server_name":"www.cloudflare.com",
            "reality":{"enabled":true,"private_key":"","short_id":["aabbccdd","11223344"],
                       "handshake":{"server":"www.cloudflare.com","server_port":443}}}},
    {"type":"hysteria2","tag":"hy2-in","listen_port":443,
     "users":[{"name":"r1","password":"p1"},{"name":"r2","password":"p2"}],
     "tls":{"enabled":true}},
    {"type":"vless","tag":"ws-in","listen_port":8445,
     "users":[{"uuid":"uuid-1","name":"r1"},{"uuid":"uuid-2","name":"r2"}],
     "transport":{"type":"ws","path":"/r1/deadbeef"},
     "tls":{"enabled":true,"server_name":"www.cloudflare.com"}},
    {"type":"naive","tag":"naive-in","listen_port":8444,
     "users":[{"username":"r1","password":"n1"},{"username":"r2","password":"n2"}],
     "tls":{"enabled":true}}
  ]
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	srv := newServer(pub, configPath)
	srv.singboxControl = func(action string) error { return nil } // no-op
	srv.singboxCheck = func(string) error { return nil }          // no sing-box binary in unit tests
	srv.realityPubPath = filepath.Join(tmp, "reality.pub")
	srv.tlsCertPath = filepath.Join(tmp, "tls-cert.pem")
	srv.coverSNIPath = filepath.Join(tmp, "cover-sni")
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
	// base64 raw-URL, not hex: that is the only encoding sing-box's
	// reality_server.go accepts for private_key, and a hex string decodes
	// to 48 bytes and FATALs the inbound on the restart this handler runs.
	rawPriv, err := base64.RawURLEncoding.DecodeString(got.RealityPrivKey)
	if err != nil || len(rawPriv) != 32 {
		t.Errorf("RealityPrivKey must be 32 bytes base64url; got %q (err=%v)", got.RealityPrivKey, err)
	}
	rawPub, err := base64.RawURLEncoding.DecodeString(got.RealityPubKey)
	if err != nil || len(rawPub) != 32 {
		t.Errorf("RealityPubKey must be 32 bytes base64url; got %q (err=%v)", got.RealityPubKey, err)
	}
	// The public half must land on disk, or /users/provision keeps
	// handing out the retired key and every pack minted afterwards is
	// unusable against this box.
	onDisk, err := os.ReadFile(srv.realityPubPath)
	if err != nil {
		t.Fatalf("reality.pub not written: %v", err)
	}
	if strings.TrimSpace(string(onDisk)) != got.RealityPubKey {
		t.Errorf("reality.pub = %q, want %q", strings.TrimSpace(string(onDisk)), got.RealityPubKey)
	}

	// Every recipient must be rotated, in every vless-family inbound, and
	// the two rows for one recipient must still agree. Rotating row 0 of
	// inbound 0 — what this used to do — revoked nobody: r2 kept working
	// everywhere, and r1 simply moved to the untouched ws-in route.
	body, _ := os.ReadFile(configPath)
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	if len(got.Users) != 2 {
		t.Fatalf("users map = %v, want one entry per recipient", got.Users)
	}
	if got.Users["r1"] == got.Users["r2"] {
		t.Errorf("r1 and r2 share a UUID %q — per-recipient credentials collapsed", got.Users["r1"])
	}
	for _, tag := range []string{"vless-in", "ws-in"} {
		in := findInboundByTag(doc, tag)
		if in == nil {
			t.Fatalf("inbound %q missing", tag)
		}
		users, _ := in["users"].([]any)
		if len(users) != 2 {
			t.Fatalf("inbound %q has %d users, want 2", tag, len(users))
		}
		for _, raw := range users {
			u, _ := raw.(map[string]any)
			name, _ := u["name"].(string)
			uuid, _ := u["uuid"].(string)
			if uuid != got.Users[name] {
				t.Errorf("%s/%s uuid = %q, want the rotated %q", tag, name, uuid, got.Users[name])
			}
			if uuid == "uuid-1" || uuid == "uuid-2" {
				t.Errorf("%s/%s kept its pre-rotation UUID %q", tag, name, uuid)
			}
		}
	}
	// hy2-in and naive-in use different user shapes; writing a `uuid`
	// into them is an unknown field and a FATAL at boot.
	for _, tag := range []string{"hy2-in", "naive-in"} {
		in := findInboundByTag(doc, tag)
		users, _ := in["users"].([]any)
		for _, raw := range users {
			if u, _ := raw.(map[string]any); u["uuid"] != nil {
				t.Errorf("inbound %q user grew a uuid key: %v", tag, u)
			}
		}
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
	var got rotateTLSResp
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.AppliedSNI != "example.com" || got.AppliedHandshake != "example.com:443" {
		t.Errorf("response echo = %+v, want sni/handshake both on example.com", got)
	}
	cfg, _ := os.ReadFile(configPath)
	var doc map[string]any
	if err := json.Unmarshal(cfg, &doc); err != nil {
		t.Fatal(err)
	}

	// The whole point of rung L2: the advertised name and the handshake
	// dest move TOGETHER. Moving only server_name leaves the box handing
	// probes to the old cover host, which is the IP-to-SNI mismatch
	// REALITY exists to prevent — a worse signature than not rotating.
	vl := findInboundByTag(doc, "vless-in")
	vlTLS, _ := vl["tls"].(map[string]any)
	if sni, _ := vlTLS["server_name"].(string); sni != "example.com" {
		t.Errorf("vless-in server_name = %q, want example.com", sni)
	}
	reality, _ := vlTLS["reality"].(map[string]any)
	hs, _ := reality["handshake"].(map[string]any)
	if hs == nil {
		t.Fatalf("vless-in reality lost its handshake block: %v", reality)
	}
	if srv, _ := hs["server"].(string); srv != "example.com" {
		t.Errorf("reality.handshake.server = %q, want example.com (must match the advertised SNI)", hs["server"])
	}
	if port, _ := hs["server_port"].(float64); int(port) != 443 {
		t.Errorf("reality.handshake.server_port = %v, want 443", hs["server_port"])
	}
	// server_names is not a field of sing-box 1.13's InboundRealityOptions;
	// writing it makes the config unparseable and the box unbootable.
	if _, present := reality["server_names"]; present {
		t.Errorf("reality.server_names written back into the config: %v", reality)
	}

	// ws-in mirrors vless-in's server_name (appendWSUser copies it at
	// creation); a rotation that leaves it behind strands the ws tier on
	// the retired cover host.
	ws := findInboundByTag(doc, "ws-in")
	wsTLS, _ := ws["tls"].(map[string]any)
	if sni, _ := wsTLS["server_name"].(string); sni != "example.com" {
		t.Errorf("ws-in server_name = %q, want the mirrored example.com", sni)
	}
	// The ws path lives on ws-in, not on inbounds[0] (which has no
	// transport at all). This assertion used to pass against a fixture
	// with one inbound and would not have caught the real bug.
	wsTr, _ := ws["transport"].(map[string]any)
	if p, _ := wsTr["path"].(string); p != "/r/abcdef" {
		t.Errorf("ws-in transport.path = %q, want /r/abcdef", p)
	}

	// Non-vless inbounds keep their own TLS identity: hy2 and naive pin
	// the box's leaf (naive matches the literal IP SAN), so rewriting
	// their server_name would break them.
	for _, tag := range []string{"hy2-in", "naive-in"} {
		in := findInboundByTag(doc, tag)
		tb, _ := in["tls"].(map[string]any)
		if _, present := tb["server_name"]; present {
			t.Errorf("inbound %q grew a server_name: %v", tag, tb)
		}
	}
}

// The box's own statement of what it advertises must not survive the
// operation that changes the answer. cloud-init writes
// /etc/daal/cover-sni once at first boot; a rotation that leaves it
// naming the retired host is a trap for the next human who reads it
// while debugging a dead tier.
func TestRotateTLS_UpdatesTheDeclaredCoverSNIFile(t *testing.T) {
	srv, _, priv, _ := newTestServer(t)
	if err := os.WriteFile(srv.coverSNIPath, []byte("www.cloudflare.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	tok := mintToken(priv, "rotate-tls", srv.now().Unix())
	body, _ := json.Marshal(rotateTLSReq{NewSNI: "mirror.init7.net", NewDests: []string{"mirror.init7.net:443"}})
	req, _ := http.NewRequest("POST", ts.URL+"/rotate-tls", bytes.NewReader(body))
	req.Header.Set("Authorization", "Daal-Mgmt-Token "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("rotate-tls returned %d", resp.StatusCode)
	}
	declared, err := os.ReadFile(srv.coverSNIPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(declared)); got != "mirror.init7.net" {
		t.Errorf("/etc/daal/cover-sni = %q after rotation, want the applied host", got)
	}
	// And the config — which IS the source of truth — agrees.
	if got := readCoverSNI(srv.singboxConfig); got != "mirror.init7.net" {
		t.Errorf("live config advertises %q, file says otherwise", got)
	}
}

// TestRotateTLS_RejectsUnloadableConfig asserts the live config is left
// alone when the rewritten one would not start. Two shipped bugs in this
// file each produced a config sing-box FATALs on, on a box with no SSH
// path back in; the pre-write `check` is what turns that into a 500.
func TestRotateTLS_RejectsUnloadableConfig(t *testing.T) {
	srv, _, priv, configPath := newTestServer(t)
	before, _ := os.ReadFile(configPath)
	srv.singboxCheck = func(string) error { return errors.New("unknown field \"nope\"") }
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	tok := mintToken(priv, "rotate-tls", srv.now().Unix())
	body, _ := json.Marshal(rotateTLSReq{NewSNI: "example.com", NewDests: []string{"example.com:443"}})
	req, _ := http.NewRequest("POST", ts.URL+"/rotate-tls", bytes.NewReader(body))
	req.Header.Set("Authorization", "Daal-Mgmt-Token "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 500 {
		t.Fatalf("expected 500 when the rewritten config fails validation; got %d", resp.StatusCode)
	}
	after, _ := os.ReadFile(configPath)
	if !bytes.Equal(before, after) {
		t.Errorf("live config was replaced with a config that does not load")
	}
	if _, err := os.Stat(configPath + ".tmp"); err == nil {
		t.Errorf("rejected temp config left behind")
	}
}

// TestSurgicalSetSNI_RepairsLegacyServerNames covers the upgrade path
// for a box a previous rotation already wedged: the stale
// reality.server_names key must be removed, not preserved.
func TestSurgicalSetSNI_RepairsLegacyServerNames(t *testing.T) {
	doc := map[string]any{"inbounds": []any{
		map[string]any{"type": "vless", "tag": "vless-in",
			"tls": map[string]any{"server_name": "old.example",
				"reality": map[string]any{"server_names": []any{"old.example"}}}},
	}}
	if err := surgicalSetSNI(doc, "new.example", []string{"new.example:8443"}); err != nil {
		t.Fatal(err)
	}
	in, _ := doc["inbounds"].([]any)[0].(map[string]any)
	tb, _ := in["tls"].(map[string]any)
	reality, _ := tb["reality"].(map[string]any)
	if _, present := reality["server_names"]; present {
		t.Errorf("legacy server_names not removed: %v", reality)
	}
	hs, _ := reality["handshake"].(map[string]any)
	if hs["server"] != "new.example" || hs["server_port"] != 8443 {
		t.Errorf("handshake = %v, want new.example:8443", hs)
	}
}

// TestSplitDest pins the dest parser: a missing or nonsense port must
// fall back to 443 rather than be written into a config that then
// refuses to boot on an unreachable box.
func TestSplitDest(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantPort int
	}{
		{"example.com", "example.com", 443},
		{"example.com:8443", "example.com", 8443},
		{"[2001:db8::1]:8443", "2001:db8::1", 8443},
		{"example.com:notaport", "example.com", 443},
		{"example.com:0", "example.com", 443},
		{"example.com:99999", "example.com", 443},
	}
	for _, tc := range cases {
		host, port := splitDest(tc.in)
		if host != tc.wantHost || port != tc.wantPort {
			t.Errorf("splitDest(%q) = %q,%d; want %q,%d", tc.in, host, port, tc.wantHost, tc.wantPort)
		}
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
