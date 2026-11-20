package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
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
	srv.audience = testAudience
	srv.singboxControl = func(action string) error { return nil } // no-op
	srv.singboxCheck = func(string) error { return nil }          // no sing-box binary in unit tests
	srv.realityPubPath = filepath.Join(tmp, "reality.pub")
	srv.tlsCertPath = filepath.Join(tmp, "tls-cert.pem")
	srv.coverSNIPath = filepath.Join(tmp, "cover-sni")
	srv.now = func() time.Time { return time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC) }
	return srv, pub, priv, configPath
}

// testAudience is the name every test relay answers to (server.audience:
// on a real relay, the SHA-256 of its management certificate), and the
// one mintToken signs for. testServerAudience gives it to a server.
const testAudience = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"

// mintCounter keeps test nonces unique across the whole package.
var mintCounter atomic.Int64

// mintToken mints a token the way the publisher does — including a
// FRESH nonce per call.
//
// The nonce used to be the constant "test-nonce", which was harmless
// until the two address verbs became single-use (consumeAddressNonce):
// every test that called bind twice was then re-presenting one token,
// which is exactly what the box now refuses. mgmt.MintToken has always
// drawn 16 random bytes per call, so a per-call nonce is what the wire
// actually carries; a fixture that reuses one is the thing that was
// wrong. Tests that want to prove the replay refusal mint once and send
// the same string twice — see TestAddressTokenIsSingleUse.
//
// A token is for ONE request (v2: the signature covers the method, the
// path and the body's digest — tokenSigningInput), so minting takes the
// request it will ride on.
func mintToken(priv ed25519.PrivateKey, op, method, path string, body []byte, ts int64) string {
	nonce := fmt.Sprintf("test-nonce-%d", mintCounter.Add(1))
	tsStr := fmt.Sprintf("%d", ts)
	sig := ed25519.Sign(priv, tokenSigningInput(testAudience, nonce, tsStr, op, method, path, sha256.Sum256(body)))
	return "v2:" + nonce + ":" + tsStr + ":" + op + ":" + base64.StdEncoding.EncodeToString(sig)
}

// signReq authorises req the way the publisher's client does: it signs
// the request AS IT WILL BE SENT — its method, its path, its body — for
// op, and sets the Authorization header. The body is read and put back.
func signReq(req *http.Request, priv ed25519.PrivateKey, op string, ts int64) {
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	}
	req.Header.Set("Authorization", "Daal-Mgmt-Token "+mintToken(priv, op, req.Method, req.URL.Path, body, ts))
}

// --- tests ---

// TestExactlyNRoutes enforces FRP-14 invariant 1: the mgmt API
// surface is exactly eleven routes — the original three, the
// per-recipient trio, /whoami, the Wave-3c address pair that the
// pinned L3 contract requires, /identity, and /cdn (add-on 2, the
// Cloudflare door). Adding another requires a supplement amendment,
// and specs/daal-relay-mgmt-v1.md §4 needs the amendment for the
// ones added here.
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
		"/bind-address",
		"/unbind-address",
		"/identity",
		"/cdn",
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

	req, _ := http.NewRequest("POST", ts.URL+"/rotate-credentials", nil)
	signReq(req, otherPriv, "rotate-credentials", srv.now().Unix())
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

	req, _ := http.NewRequest("POST", ts.URL+"/rotate-credentials", nil)
	signReq(req, priv, "rotate-credentials", old)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("expected 401 for expired timestamp; got %d", resp.StatusCode)
	}
}

// TestRotateCreds_RewritesConfigAndReturnsCreds is the happy path for the
// TARGETED rotation: name one recipient, get one recipient's replacement
// credentials, complete enough to mint a pack from without a second call.
//
// The exhaustive isolation assertions live in rotate_test.go, over a
// three-recipient fixture — two recipients cannot distinguish "rotated the
// one I named" from "rotated everyone", which is exactly the bug.
func TestRotateCreds_RewritesConfigAndReturnsCreds(t *testing.T) {
	srv, _, priv, configPath := newTestServer(t)
	// The pinning material the publisher needs back; provision writes these
	// at first boot on a real box.
	if err := os.WriteFile(srv.realityPubPath, []byte("Ck9nvVEcYnAlUUlBl9dqfKvyEpqTFDTjHmwPmLnKvVM\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	got := rotateCreds(t, ts, priv, `{"name":"r2"}`, 200)

	if len(got.VLESSUUID) != 36 {
		t.Errorf("vless_uuid wrong shape: %q", got.VLESSUUID)
	}
	if got.Name != "r2" {
		t.Errorf("name = %q, want r2", got.Name)
	}
	if got.UUID != got.VLESSUUID {
		t.Errorf("legacy uuid alias %q != vless_uuid %q", got.UUID, got.VLESSUUID)
	}
	if len(got.Users) != 1 || got.Users["r2"] != got.VLESSUUID {
		t.Errorf("users = %v, want exactly the one rotated recipient", got.Users)
	}
	// The box keypair is a separate operation with a fleet-wide blast
	// radius; this endpoint must not have touched it, and must say so.
	if got.BoxKeysRotated {
		t.Error("box_keys_rotated = true: /rotate-credentials must never rotate the box REALITY keypair")
	}
	// It must still hand back the CURRENT public key, unchanged, or the
	// publisher cannot pin the replacement pack.
	if got.RealityPublicKey != "Ck9nvVEcYnAlUUlBl9dqfKvyEpqTFDTjHmwPmLnKvVM" {
		t.Errorf("reality_public_key = %q, want the box's unchanged key", got.RealityPublicKey)
	}
	// The ws path is shared by every recipient on this box. Rotating it to
	// revoke one person would take the ws tier from everyone else, so it is
	// echoed as-is — and it must be the path the box actually serves.
	if got.WSPath != "/r1/deadbeef" {
		t.Errorf("ws_path = %q, want the live shared path unchanged", got.WSPath)
	}
	if got.CoverSNI != "www.cloudflare.com" {
		t.Errorf("cover_sni = %q, want the live cover host", got.CoverSNI)
	}
	sort.Strings(got.UpdatedInbounds)
	want := []string{"hy2-in", "naive-in", "vless-in", "ws-in"}
	if !reflect.DeepEqual(got.UpdatedInbounds, want) {
		t.Errorf("updated_inbounds = %v, want every tier %v — a rotation that misses one leaves the leaked credential live there", got.UpdatedInbounds, want)
	}

	doc := readDoc(t, configPath)
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

// A nameless rotation must be refused. The pre-Step-7 publisher client posts
// a nil body, and under the old semantics that meant "rotate every recipient
// and the box keypair" — one mis-click away from severing a whole family.
func TestRotateCreds_NamelessRequestIsRefused(t *testing.T) {
	for _, body := range []string{"", "{}", `{"name":""}`, `{"name":"all"}`, `{"name":"../r1"}`} {
		srv, _, priv, configPath := newTestServer(t)
		before, _ := os.ReadFile(configPath)
		ts := httptest.NewServer(srv.routes())

		rotateCreds(t, ts, priv, body, 400)

		after, _ := os.ReadFile(configPath)
		if !bytes.Equal(before, after) {
			t.Errorf("body %q: config was rewritten by a request that must have been refused", body)
		}
		ts.Close()
	}
}

func TestRotateCreds_UnknownRecipientIs404(t *testing.T) {
	srv, _, priv, configPath := newTestServer(t)
	before, _ := os.ReadFile(configPath)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	rotateCreds(t, ts, priv, `{"name":"r99"}`, 404)

	after, _ := os.ReadFile(configPath)
	if !bytes.Equal(before, after) {
		t.Error("config was rewritten for a recipient that does not exist on this box")
	}
}

// The pre-write `check` is what turns "unreachable box" into "500, config
// untouched" — the same guard /rotate-tls has, on the endpoint an operator
// reaches for when something has already gone wrong.
func TestRotateCreds_RejectsUnloadableConfig(t *testing.T) {
	srv, _, priv, configPath := newTestServer(t)
	before, _ := os.ReadFile(configPath)
	srv.singboxCheck = func(string) error { return errors.New(`unknown field "nope"`) }
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	rotateCreds(t, ts, priv, `{"name":"r1"}`, 500)

	after, _ := os.ReadFile(configPath)
	if !bytes.Equal(before, after) {
		t.Error("live config was replaced with a config that does not load")
	}
	if _, err := os.Stat(configPath + ".tmp"); err == nil {
		t.Error("rejected temp config left behind")
	}
}

// rotateCreds posts a signed /rotate-credentials request, asserts the status
// and decodes the body on success.
func rotateCreds(t *testing.T, ts *httptest.Server, priv ed25519.PrivateKey, body string, wantStatus int) rotateCredentialsResp {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, _ := http.NewRequest("POST", ts.URL+"/rotate-credentials", rdr)
	signReq(req, priv, "rotate-credentials", time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC).Unix())
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != wantStatus {
		msg, _ := io.ReadAll(resp.Body)
		t.Fatalf("rotate-credentials(%s) = %d, want %d: %s", body, resp.StatusCode, wantStatus, msg)
	}
	var got rotateCredentialsResp
	if wantStatus == 200 {
		if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
	}
	return got
}

// readDoc re-reads the live config as a generic document.
func readDoc(t *testing.T, path string) map[string]any {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestRotateTLS_RewritesConfig(t *testing.T) {
	srv, _, priv, configPath := newTestServer(t)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	body, _ := json.Marshal(rotateTLSReq{NewSNI: "example.com", NewDests: []string{"example.com:443"}, NewWSPath: "/r/abcdef"})
	req, _ := http.NewRequest("POST", ts.URL+"/rotate-tls", bytes.NewReader(body))
	signReq(req, priv, "rotate-tls", srv.now().Unix())
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

	body, _ := json.Marshal(rotateTLSReq{NewSNI: "mirror.init7.net", NewDests: []string{"mirror.init7.net:443"}})
	req, _ := http.NewRequest("POST", ts.URL+"/rotate-tls", bytes.NewReader(body))
	signReq(req, priv, "rotate-tls", srv.now().Unix())
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

	body, _ := json.Marshal(rotateTLSReq{NewSNI: "example.com", NewDests: []string{"example.com:443"}})
	req, _ := http.NewRequest("POST", ts.URL+"/rotate-tls", bytes.NewReader(body))
	signReq(req, priv, "rotate-tls", srv.now().Unix())
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

// A handshake dest with no advertised name, or one that names a DIFFERENT
// host, is the IP-to-SNI mismatch REALITY exists to prevent. Refuse it
// outright rather than write a box that advertises one cover host while
// handing every probe to another.
func TestRotateTLS_RejectsContradictoryCoverIdentity(t *testing.T) {
	cases := []struct{ name, body string }{
		{"dest without sni", `{"new_dests":["example.com:443"]}`},
		{"dest host disagrees with sni", `{"new_sni":"example.com","new_dests":["other.example:443"]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, _, priv, configPath := newTestServer(t)
			before, _ := os.ReadFile(configPath)
			ts := httptest.NewServer(srv.routes())
			defer ts.Close()

			rotateTLS(t, ts, priv, tc.body, 400)

			after, _ := os.ReadFile(configPath)
			if !bytes.Equal(before, after) {
				t.Error("config was rewritten by a request that must have been refused")
			}
		})
	}
}

// The pinned contract's `POST /rotate-tls {}`. The box cannot invent a
// plausible cover host — that depends on the relay's provider and region,
// which is publisher knowledge, and a constant compiled into this binary
// would be one string match away from burning the whole fleet. So an empty
// body rotates only what the box owns, and `changed` says so, so the caller
// can tell the operator the cover host was NOT replaced instead of showing a
// green tick over a half-done job.
func TestRotateTLS_EmptyBodyRotatesOnlyWhatTheBoxOwns(t *testing.T) {
	srv, _, priv, configPath := newTestServer(t)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	got := rotateTLS(t, ts, priv, "{}", 200)

	if !reflect.DeepEqual(got.Changed, []string{"ws_path"}) {
		t.Errorf("changed = %v, want exactly [ws_path]: an empty body must not claim to have moved the cover host", got.Changed)
	}
	if got.AppliedSNI != "www.cloudflare.com" {
		t.Errorf("applied_sni = %q, want the unchanged cover host", got.AppliedSNI)
	}
	if got.AppliedWSPath == "/r1/deadbeef" || got.AppliedWSPath == "" {
		t.Errorf("applied_ws_path = %q, want a freshly minted path", got.AppliedWSPath)
	}
	// Shape-preserving: a rotated path must be indistinguishable on the wire
	// from a provisioned one (`/r<id>/<8 hex>`, see mintCreds).
	if !regexp.MustCompile(`^/r1/[0-9a-f]{8}$`).MatchString(got.AppliedWSPath) {
		t.Errorf("applied_ws_path = %q does not keep the provisioned path shape", got.AppliedWSPath)
	}
	doc := readDoc(t, configPath)
	if p := wsInboundPath(doc); p != got.AppliedWSPath {
		t.Errorf("live ws path %q != reported %q", p, got.AppliedWSPath)
	}
	// The cover-SNI declaration file must NOT be touched when the cover host
	// did not move.
	if _, err := os.Stat(srv.coverSNIPath); err == nil {
		t.Error("/etc/daal/cover-sni written on a rotation that did not change the cover host")
	}
}

// A no-op must not report success. A box with no ws inbound and no new_sni
// has nothing this endpoint can rotate; a cheerful 200 there is how an
// operator concludes a burned cover host has been replaced when it has not.
func TestRotateTLS_EmptyBodyWithNothingToRotateIsRefused(t *testing.T) {
	srv, _, priv, configPath := newTestServer(t)
	doc := readDoc(t, configPath)
	kept := []any{}
	for _, raw := range doc["inbounds"].([]any) {
		if in, _ := raw.(map[string]any); in["tag"] != tagWS {
			kept = append(kept, raw)
		}
	}
	doc["inbounds"] = kept
	if err := writeSingboxDoc(configPath, doc, nil); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	rotateTLS(t, ts, priv, "{}", 400)
}

// rotateTLS posts a signed /rotate-tls request, asserts the status and
// decodes the body on success.
func rotateTLS(t *testing.T, ts *httptest.Server, priv ed25519.PrivateKey, body string, wantStatus int) rotateTLSResp {
	t.Helper()
	req, _ := http.NewRequest("POST", ts.URL+"/rotate-tls", strings.NewReader(body))
	signReq(req, priv, "rotate-tls", time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC).Unix())
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != wantStatus {
		msg, _ := io.ReadAll(resp.Body)
		t.Fatalf("rotate-tls(%s) = %d, want %d: %s", body, resp.StatusCode, wantStatus, msg)
	}
	var got rotateTLSResp
	if wantStatus == 200 {
		if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
	}
	return got
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
	tok := mintToken(priv, "rotate-credentials", "POST", "/rotate-tls", nil, srv.now().Unix())
	if err := srv.verifyToken(tok, "rotate-tls", "POST", "/rotate-tls", sha256.Sum256(nil)); err == nil {
		t.Errorf("expected mismatch error; op-bound token must not work cross-endpoint")
	}
}

// --- /whoami ---

// whoamiGet issues a signed GET against /whoami with the op string
// the endpoint expects.
func whoamiGet(t *testing.T, url string, priv ed25519.PrivateKey, ts int64) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("GET", url+"/whoami", nil)
	signReq(req, priv, "whoami", ts)
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
	signReq(req, priv, "users-list", srv.now().Unix())
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
	signReq(req, priv, "whoami", srv.now().Unix())
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
			signReq(req, priv, "whoami", srv.now().Unix())
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

// TestHealthAdvertisesSplitRotation pins the capability advertisement
// the publisher's safety interlock reads.
//
// This is a CROSS-MODULE WIRE CONTRACT and the literals are the
// contract, not the constant names: publisher/deploy/mgmt/capability.go
// fails CLOSED, so if these strings drift the publisher stops believing
// any relay can rotate in place and every in-place rotation is refused
// — against correct new boxes as well as old ones. That failure is
// silent at compile time in both modules (separate go.mod files, no
// shared symbol), which is exactly why it is asserted here as raw text.
// The peer assertion lives in
// publisher/deploy/mgmt.TestCapabilities_AcceptsRealBoxHealthBody, and
// the two hardcode the same bytes on purpose.
func TestHealthAdvertisesSplitRotation(t *testing.T) {
	srv, _, _, _ := newTestServer(t)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d want 200", resp.StatusCode)
	}
	var got struct {
		OK             bool     `json:"ok"`
		MgmtAPIVersion int      `json:"mgmt_api_version"`
		Capabilities   []string `json:"capabilities"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	// "ok" must survive: a pre-Step-7 publisher and the provisioning
	// liveness probe both read only this field.
	if !got.OK {
		t.Error(`"ok" must stay true — the liveness probe reads it`)
	}
	if got.MgmtAPIVersion != 2 {
		t.Errorf("mgmt_api_version = %d want 2 (the split-rotation contract)", got.MgmtAPIVersion)
	}
	// Exact literals, spelled out rather than referencing the consts,
	// so renaming a const cannot quietly rename the wire value.
	for _, want := range []string{"rotate-credentials-scoped", "rotate-tls-scoped"} {
		found := false
		for _, c := range got.Capabilities {
			if c == want {
				found = true
			}
		}
		if !found {
			t.Errorf("capabilities %v missing %q — the publisher will refuse to rotate this box", got.Capabilities, want)
		}
	}
}

// TestHealthCapabilityConstantsMatchTheWire guards the other direction:
// the constants the handler emits are the ones the publisher looks for.
func TestHealthCapabilityConstantsMatchTheWire(t *testing.T) {
	if capRotateCredentialsScoped != "rotate-credentials-scoped" {
		t.Errorf("capRotateCredentialsScoped = %q; publisher looks for %q",
			capRotateCredentialsScoped, "rotate-credentials-scoped")
	}
	if capRotateTLSScoped != "rotate-tls-scoped" {
		t.Errorf("capRotateTLSScoped = %q; publisher looks for %q",
			capRotateTLSScoped, "rotate-tls-scoped")
	}
	// A box that advertises a version BELOW the split contract while
	// serving split semantics would be refused by its own publisher.
	if mgmtAPIVersion < 2 {
		t.Errorf("mgmtAPIVersion = %d; the split-rotation contract is 2", mgmtAPIVersion)
	}
}

// TestMutatingTokensAreSingleUse: a token for a mutating verb is
// honoured once. Since the v2 token format the signature covers the
// body, so the only thing a second presentation could do is repeat the
// SAME request — and for /rotate-credentials a repeat is a second
// outage for that recipient (their re-delivered file dies again). The
// in-memory nonce set refuses it. (Before v2 this set was the only
// thing between a captured token and a different body; that half is now
// TestTokenIsBoundToTheRequest, which holds across a restart.)
func TestMutatingTokensAreSingleUse(t *testing.T) {
	srv, _, priv, configPath := newTestServer(t)
	call := func(method, path, tok, body string) int {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Daal-Mgmt-Token "+tok)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		return rec.Code
	}
	fresh := func(op, method, path, body string) string {
		return mintToken(priv, op, method, path, []byte(body), srv.now().Unix())
	}
	config := func() string {
		body, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}

	for _, c := range []struct{ op, path, body string }{
		{"users-provision", "/users/provision", `{"name":"r3"}`},
		{"rotate-credentials", "/rotate-credentials", `{"name":"r2"}`},
		{"rotate-tls", "/rotate-tls", `{"new_sni":"mirror.example.net"}`},
		{"users-revoke", "/users/revoke", `{"name":"r1"}`},
	} {
		before := config()
		tok := fresh(c.op, "POST", c.path, c.body)
		if code := call("POST", c.path, tok, c.body); code != 200 {
			t.Fatalf("%s first use = %d, want 200", c.op, code)
		}
		mid := config()
		if mid == before {
			t.Fatalf("fixture: the first %s should have rewritten the config", c.op)
		}
		if code := call("POST", c.path, tok, c.body); code != 401 {
			t.Fatalf("%s: the same token presented a second time = %d, want 401", c.op, code)
		}
		if config() != mid {
			t.Errorf("%s: a replayed token was applied a second time", c.op)
		}
	}

	// A token refused for a bad signature must NOT burn anything: the
	// nonce set only ever holds tokens that verified.
	if code := call("POST", "/users/revoke", "v2:n:1:users-revoke:AAAA", `{"name":"r2"}`); code != 401 {
		t.Fatalf("garbage token = %d, want 401", code)
	}
	if n := len(srv.seenAddrNonces); n != 4 {
		t.Errorf("nonce set holds %d entries, want exactly the 4 tokens that verified", n)
	}

	// The read-only verb stays replayable: a GET may be re-sent by the
	// transport with the same token, and refusing that would turn a
	// connection hiccup into a failed operation.
	tok := fresh("users-list", "GET", "/users/list", "")
	for i := 0; i < 2; i++ {
		if code := call("GET", "/users/list", tok, ""); code != 200 {
			t.Fatalf("users-list use %d = %d, want 200 (GET tokens are deliberately replayable)", i+1, code)
		}
	}
}

// TestTokenIsBoundToTheRequest: a token authorises ONE request — this
// method, this path, these body bytes — and nothing this process
// remembers is needed to hold that.
//
// The v1 token signed "nonce:ts:op" only. A captured users-revoke token
// could be re-presented naming another recipient, and the single-use
// nonce set that refused it lives in memory: restart daal-relay-mgmt
// inside the 300 s window and it was honoured (the end-to-end rig's
// finding LC-1, residual). Each case below presents a valid token with
// a DIFFERENT body, both never-used and after-a-restart, and asserts
// the 401 and that nothing changed.
func TestTokenIsBoundToTheRequest(t *testing.T) {
	srv, _, priv, configPath := newTestServer(t)
	call := func(method, path, tok, body string) int {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Daal-Mgmt-Token "+tok)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		return rec.Code
	}
	config := func() string {
		body, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	// What a restart does to single use: the nonce set is gone.
	restart := func() {
		srv.nonceMu.Lock()
		srv.seenAddrNonces = nil
		srv.nonceMu.Unlock()
	}

	for _, c := range []struct{ op, path, signed, other string }{
		{"users-revoke", "/users/revoke", `{"name":"r1"}`, `{"name":"r2"}`},
		{"rotate-credentials", "/rotate-credentials", `{"name":"r2"}`, `{"name":"r1"}`},
		{"users-provision", "/users/provision", `{"name":"r3"}`, `{"name":"r4"}`},
		{"rotate-tls", "/rotate-tls", `{"new_sni":"mirror.example.net"}`, `{"new_sni":"other.example.net"}`},
	} {
		// 1. A token nobody has presented yet, with another body.
		before := config()
		tok := mintToken(priv, c.op, "POST", c.path, []byte(c.signed), srv.now().Unix())
		if code := call("POST", c.path, tok, c.other); code != 401 {
			t.Fatalf("%s: a token signed for %s was honoured with %s (%d)", c.op, c.signed, c.other, code)
		}
		if config() != before {
			t.Fatalf("%s: a body the publisher did not sign changed the relay", c.op)
		}
		// A refused presentation spent nothing: the request it WAS
		// signed for still goes through.
		if code := call("POST", c.path, tok, c.signed); code != 200 {
			t.Fatalf("%s: the signed request = %d, want 200", c.op, code)
		}
		// 2. The captured, used token after a restart, with another body.
		mid := config()
		restart()
		if code := call("POST", c.path, tok, c.other); code != 401 {
			t.Fatalf("%s: after a restart a used token was honoured with another body (%d)", c.op, code)
		}
		if config() != mid {
			t.Fatalf("%s: after a restart a replayed token changed the relay", c.op)
		}
	}

	// The method and the path are under the signature too.
	body := `{"name":"r2"}`
	tok := mintToken(priv, "users-revoke", "POST", "/users/revoke", []byte(body), srv.now().Unix())
	if code := call("PUT", "/users/revoke", tok, body); code != 401 {
		t.Errorf("a POST token presented as PUT = %d, want 401", code)
	}
	tok = mintToken(priv, "whoami", "GET", "/whoami", nil, srv.now().Unix())
	if code := call("POST", "/whoami", tok, ""); code != 401 {
		t.Errorf("a GET /whoami token presented as POST = %d, want 401", code)
	}
	if code := call("GET", "/whoami", tok, ""); code != 200 {
		t.Errorf("the GET it was signed for = %d, want 200", code)
	}
	// One op, signed for another route's path: the op check passes for
	// neither route.
	tok = mintToken(priv, "users-revoke", "POST", "/rotate-credentials", []byte(body), srv.now().Unix())
	for _, path := range []string{"/users/revoke", "/rotate-credentials"} {
		if code := call("POST", path, tok, body); code != 401 {
			t.Errorf("a users-revoke token signed for /rotate-credentials, sent to %s = %d, want 401", path, code)
		}
	}
}

// TestV1TokenIsRefused: the format that did not sign the request is not
// accepted from anybody — a correctly signed v1 token, from the right
// key, inside the window, is a 401.
func TestV1TokenIsRefused(t *testing.T) {
	srv, _, priv, configPath := newTestServer(t)
	before, _ := os.ReadFile(configPath)
	ts := fmt.Sprintf("%d", srv.now().Unix())
	msg := "abcdef0123456789:" + ts + ":users-revoke"
	v1 := msg + ":" + base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(msg)))
	req := httptest.NewRequest("POST", "/users/revoke", strings.NewReader(`{"name":"r1"}`))
	req.Header.Set("Authorization", "Daal-Mgmt-Token "+v1)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("a v1 token = %d, want 401", rec.Code)
	}
	if after, _ := os.ReadFile(configPath); string(after) != string(before) {
		t.Error("a v1 token changed the relay")
	}
	// Nor with the version word bolted on: the signature is over the
	// wrong bytes.
	req = httptest.NewRequest("POST", "/users/revoke", strings.NewReader(`{"name":"r1"}`))
	req.Header.Set("Authorization", "Daal-Mgmt-Token v2:"+v1)
	rec = httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("a v1 signature in a v2 envelope = %d, want 401", rec.Code)
	}
}

// TestQueryStringIsRefused: the token signs the path and nothing after
// it, so a query string would be the one part of a request the
// publisher never signed. No route takes one; a request carrying one is
// refused before the token is looked at, correct token or not, and the
// refusal spends nothing.
func TestQueryStringIsRefused(t *testing.T) {
	srv, _, priv, configPath := newTestServer(t)
	before, _ := os.ReadFile(configPath)
	ran := false
	guarded := srv.requireAuth(func(http.ResponseWriter, *http.Request) { ran = true })
	call := func(method, target, tok, body string) int {
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		req.Header.Set("Authorization", "Daal-Mgmt-Token "+tok)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		return rec.Code
	}
	tok := mintToken(priv, "users-list", "GET", "/users/list", nil, srv.now().Unix())
	for _, target := range []string{
		"/users/list?anything=1",
		"/users/list?name=r1&name=r2",
		"/users/list?", // a bare "?" is still not the request that was signed
	} {
		if code := call("GET", target, tok, ""); code != 400 {
			t.Errorf("GET %s with a token for /users/list = %d, want 400", target, code)
		}
		// The wrapper itself refuses, whatever it wraps.
		req := httptest.NewRequest("GET", target, nil)
		req.Header.Set("Authorization", "Daal-Mgmt-Token "+tok)
		rec := httptest.NewRecorder()
		guarded(rec, req)
		if rec.Code != 400 || ran {
			t.Errorf("requireAuth on %s = %d (handler ran: %v), want 400 and no handler", target, rec.Code, ran)
		}
	}
	if code := call("GET", "/users/list", tok, ""); code != 200 {
		t.Errorf("the request the token was signed for = %d, want 200", code)
	}
	// A mutating verb: refused, nothing changed, and the token is not
	// spent - the signed request still goes through once.
	body := `{"name":"r1"}`
	tok = mintToken(priv, "users-revoke", "POST", "/users/revoke", []byte(body), srv.now().Unix())
	if code := call("POST", "/users/revoke?name=r2", tok, body); code != 400 {
		t.Errorf("POST /users/revoke?name=r2 = %d, want 400", code)
	}
	if after, _ := os.ReadFile(configPath); string(after) != string(before) {
		t.Error("a request with a query string changed the relay")
	}
	if code := call("POST", "/users/revoke", tok, body); code != 200 {
		t.Errorf("the signed revoke after a refused query-string presentation = %d, want 200", code)
	}
}

// TestTokenFieldChecksHold pins the three checks verifyToken makes on a
// token's fields before it looks at the signature. In each row the
// SIGNATURE IS VALID - made by the publisher's key over exactly the
// bytes this relay would rebuild - so the only thing that can refuse
// the token is the field check itself. (None of them is the last line
// of defence: the context line is under the signature and all three
// need the publisher's key. They are pinned because the code states
// them as checks.)
func TestTokenFieldChecksHold(t *testing.T) {
	srv, _, priv, _ := newTestServer(t)
	ts := fmt.Sprintf("%d", srv.now().Unix())
	// sign builds a token whose signature is over what the relay will
	// verify for (nonce, op, GET path, empty body), under any label.
	sign := func(label, nonce, op, path string) string {
		sig := ed25519.Sign(priv, tokenSigningInput(testAudience, nonce, ts, op, "GET", path, sha256.Sum256(nil)))
		return label + ":" + nonce + ":" + ts + ":" + op + ":" + base64.StdEncoding.EncodeToString(sig)
	}
	ran := false
	guarded := srv.requireAuth(func(http.ResponseWriter, *http.Request) { ran = true })
	present := func(path, tok string) int {
		ran = false
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("Authorization", "Daal-Mgmt-Token "+tok)
		rec := httptest.NewRecorder()
		guarded(rec, req)
		return rec.Code
	}

	// The control: the same construction, with nothing wrong, is
	// honoured - so each refusal below is the check, not the helper.
	if code := present("/whoami", sign("v2", "n-control", "whoami", "/whoami")); code != 200 || !ran {
		t.Fatalf("control token = %d (handler ran: %v), want 200", code, ran)
	}
	for _, c := range []struct{ name, path, tok string }{
		// The version word is not under the signature by itself (the
		// context line is), so only the comparison refuses another one.
		{"a valid signature under a v1 label", "/whoami", sign("v1", "n-v1", "whoami", "/whoami")},
		{"a valid signature under a v3 label", "/whoami", sign("v3", "n-v3", "whoami", "/whoami")},
		{"a valid signature under an empty label", "/whoami", sign("", "n-nolabel", "whoami", "/whoami")},
		{"a valid signature over an empty nonce", "/whoami", sign("v2", "", "whoami", "/whoami")},
		// A path with no op: the token's empty op "matches" the
		// endpoint's empty op, and the signature is good for it.
		{"a wrapped path that has no op", "/no-such-op", sign("v2", "n-noop", "", "/no-such-op")},
	} {
		if code := present(c.path, c.tok); code != 401 || ran {
			t.Errorf("%s = %d (handler ran: %v), want 401 and no handler", c.name, code, ran)
		}
	}
}

// TestAuthedBodyIsBounded: the body is read before the token is
// verified (its digest is signed), so it is bounded for everybody.
func TestAuthedBodyIsBounded(t *testing.T) {
	srv, _, priv, _ := newTestServer(t)
	big := bytes.Repeat([]byte("a"), maxAuthedBody+1)
	req := httptest.NewRequest("POST", "/users/revoke", bytes.NewReader(big))
	signReq(req, priv, "users-revoke", srv.now().Unix())
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("a %d-byte body = %d, want 413", len(big), rec.Code)
	}
}

// TestTokenV2Vector_BoxAcceptsWhatThePublisherSigns reads the fixture
// the publisher's token minter is pinned to
// (publisher/deploy/mgmt, TestTokenV2Vector_PublisherProducesTheFixture).
// The two are separate Go modules that share no symbol; this file is the
// seam that keeps "what is signed" one definition.
func TestTokenV2Vector_BoxAcceptsWhatThePublisherSigns(t *testing.T) {
	raw, err := os.ReadFile("../../publisher/deploy/mgmt/testdata/token_v2_vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []struct {
		PublicKeyHex string `json:"public_key_hex"`
		Relay        string `json:"relay_mgmt_tls_fingerprint_hex"`
		Nonce        string `json:"nonce"`
		TS           int64  `json:"ts"`
		Op           string `json:"op"`
		Method       string `json:"method"`
		Path         string `json:"path"`
		Body         string `json:"body"`
		SigningInput string `json:"signing_input"`
		Token        string `json:"token"`
	}
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatal(err)
	}
	if len(vs) < 2 {
		t.Fatalf("fixture has %d vectors", len(vs))
	}
	for _, v := range vs {
		pub, err := hex.DecodeString(v.PublicKeyHex)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			t.Fatalf("fixture public key: %v", err)
		}
		srv := newServer(ed25519.PublicKey(pub), "/nonexistent")
		srv.audience = v.Relay
		srv.now = func() time.Time { return time.Unix(v.TS, 0) }
		sum := sha256.Sum256([]byte(v.Body))
		if got := string(tokenSigningInput(v.Relay, v.Nonce, fmt.Sprintf("%d", v.TS), v.Op, v.Method, v.Path, sum)); got != v.SigningInput {
			t.Errorf("%s: signing input\n got %q\nwant %q", v.Op, got, v.SigningInput)
		}
		if opFromPath(v.Path) != v.Op {
			t.Errorf("%s: this box serves %s as op %q", v.Op, v.Path, opFromPath(v.Path))
		}
		if err := srv.verifyToken(v.Token, opFromPath(v.Path), v.Method, v.Path, sum); err != nil {
			t.Errorf("%s: the publisher's token is refused: %v", v.Op, err)
		}
		other := sha256.Sum256([]byte(v.Body + " "))
		if err := srv.verifyToken(v.Token, opFromPath(v.Path), v.Method, v.Path, other); err == nil {
			t.Errorf("%s: the token verified for another body", v.Op)
		}
		// ... and for another relay that trusts the same key.
		sibling := newServer(ed25519.PublicKey(pub), "/nonexistent")
		sibling.audience = testAudience
		sibling.now = srv.now
		if v.Relay == testAudience {
			t.Fatalf("%s: the fixture's relay must not be the test relay", v.Op)
		}
		if err := sibling.verifyToken(v.Token, opFromPath(v.Path), v.Method, v.Path, sum); err == nil {
			t.Errorf("%s: the token verified on a relay it was not minted for", v.Op)
		}
	}
}

// TestTokenIsBoundToTheRelay: one publisher key can be trusted by more
// than one relay (an imported key; the old and the new box around a
// rebuild). A token minted for one of them must be refused by the other,
// whose nonce set has never seen it - before the relay's name was under
// the signature both answered 200 to the same users-revoke token and
// body.
func TestTokenIsBoundToTheRelay(t *testing.T) {
	a, pub, priv, _ := newTestServer(t)
	b, _, _, bConfig := newTestServer(t)
	b.pubkey = pub // the same publisher
	b.audience = "b1" + testAudience[2:]
	call := func(s *server, method, path, tok, body string) int {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Daal-Mgmt-Token "+tok)
		rec := httptest.NewRecorder()
		s.routes().ServeHTTP(rec, req)
		return rec.Code
	}
	before, err := os.ReadFile(bConfig)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ op, method, path, body string }{
		{"users-revoke", "POST", "/users/revoke", `{"name":"r1"}`},
		{"rotate-tls", "POST", "/rotate-tls", `{"new_sni":"mirror.example.net"}`},
		{"rotate-credentials", "POST", "/rotate-credentials", `{"name":"r2"}`},
		{"users-list", "GET", "/users/list", ""},
	} {
		tok := mintToken(priv, c.op, c.method, c.path, []byte(c.body), a.now().Unix())
		// Presented to the sibling first, so that nothing but the
		// signature can be what refuses it.
		if code := call(b, c.method, c.path, tok, c.body); code != 401 {
			t.Errorf("%s: a token minted for one relay was answered %d by another, want 401", c.op, code)
		}
		if code := call(a, c.method, c.path, tok, c.body); code != 200 {
			t.Errorf("%s: the relay the token was minted for answered %d, want 200", c.op, code)
		}
	}
	after, err := os.ReadFile(bConfig)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Error("a token minted for another relay changed this one")
	}

	// A relay that does not know its own name honours nothing.
	b.audience = ""
	nameless := ed25519.Sign(priv, tokenSigningInput("", "n-nameless", fmt.Sprintf("%d", b.now().Unix()), "users-list", "GET", "/users/list", sha256.Sum256(nil)))
	tok := fmt.Sprintf("v2:n-nameless:%d:users-list:%s", b.now().Unix(), base64.StdEncoding.EncodeToString(nameless))
	if code := call(b, "GET", "/users/list", tok, ""); code != 401 {
		t.Errorf("a relay with no name honoured a token that names no relay (%d)", code)
	}
}

// TestTokenAudienceIsTheServedCertificate: the name a relay answers to
// is the SHA-256 of the certificate it serves - the value the publisher
// pins - and it is the same after a restart, when the certificate is
// loaded from disk rather than generated.
func TestTokenAudienceIsTheServedCertificate(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, fprPath := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem"), filepath.Join(dir, "log", "fpr")
	first, err := ensureSelfSignedCert(certPath, keyPath, fprPath)
	if err != nil {
		t.Fatal(err)
	}
	got, err := tokenAudienceOf(first)
	if err != nil {
		t.Fatal(err)
	}
	published, err := os.ReadFile(fprPath)
	if err != nil {
		t.Fatal(err)
	}
	if got != strings.TrimSpace(string(published)) {
		t.Errorf("audience %s is not the fingerprint the relay publishes, %s", got, published)
	}
	sum := sha256.Sum256(first.Certificate[0])
	if got != hex.EncodeToString(sum[:]) || got != strings.ToLower(got) {
		t.Errorf("audience %s is not the lower-case hex SHA-256 of the leaf", got)
	}
	again, err := ensureSelfSignedCert(certPath, keyPath, fprPath)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded, _ := tokenAudienceOf(again); reloaded != got {
		t.Errorf("after a restart the relay answers to %s, not %s", reloaded, got)
	}
	if _, err := tokenAudienceOf(tls.Certificate{}); err == nil {
		t.Error("a relay with no certificate was given a name")
	}
}
