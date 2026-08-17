package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
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
	tok := mintToken(priv, "rotate-credentials", time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC).Unix())
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, _ := http.NewRequest("POST", ts.URL+"/rotate-credentials", rdr)
	req.Header.Set("Authorization", "Daal-Mgmt-Token "+tok)
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
	tok := mintToken(priv, "rotate-tls", time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC).Unix())
	req, _ := http.NewRequest("POST", ts.URL+"/rotate-tls", strings.NewReader(body))
	req.Header.Set("Authorization", "Daal-Mgmt-Token "+tok)
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
