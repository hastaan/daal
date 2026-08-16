package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newUsersTestServer writes a v2-shaped empty-users sing-box
// scaffold to a tempdir and returns a server wired against it.
// The kick wrapper is replaced with a counter so tests can assert
// it ran without invoking systemctl.
func newUsersTestServer(t *testing.T) (*server, ed25519.PrivateKey, string, *atomic.Int64) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config.json")
	scaffold := `{
  "log": {"level": "info"},
  "inbounds": [
    {"type":"vless","tag":"vless-in","listen":"0.0.0.0","listen_port":443,
     "users":[],
     "tls":{"enabled":true,"server_name":"sni.example.com","reality":{"enabled":true,"private_key":"00","short_id":[]}}},
    {"type":"hysteria2","tag":"hy2-in","listen":"0.0.0.0","listen_port":8443,"users":[]},
    {"type":"naive","tag":"naive-in","listen":"0.0.0.0","listen_port":8444,"users":[]}
  ],
  "outbounds":[{"type":"direct"}]
}`
	if err := os.WriteFile(configPath, []byte(scaffold), 0o644); err != nil {
		t.Fatal(err)
	}
	srv := newServer(pub, configPath)
	srv.singboxControl = func(action string) error { return nil }
	var kickCount atomic.Int64
	srv.singboxKick = func() error { kickCount.Add(1); return nil }
	srv.now = func() time.Time { return time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC) }
	return srv, priv, configPath, &kickCount
}

func postJSON(t *testing.T, url string, priv ed25519.PrivateKey, op string, body any) *http.Response {
	t.Helper()
	tok := mintToken(priv, op, time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC).Unix())
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req, _ := http.NewRequest("POST", url, &buf)
	req.Header.Set("Authorization", "Daal-Mgmt-Token "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func getURL(t *testing.T, url string, priv ed25519.PrivateKey, op string) *http.Response {
	t.Helper()
	tok := mintToken(priv, op, time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC).Unix())
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Daal-Mgmt-Token "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestUsersProvision_AppendsAcrossInbounds(t *testing.T) {
	srv, priv, configPath, _ := newUsersTestServer(t)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	resp := postJSON(t, ts.URL+"/users/provision", priv, "users-provision", provisionReq{Name: "r17"})
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := readAll(resp.Body)
		t.Fatalf("status %d body %s", resp.StatusCode, body)
	}
	var got userCreds
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Name != "r17" {
		t.Errorf("name = %q", got.Name)
	}
	if len(got.VLESSUUID) != 36 {
		t.Errorf("vless uuid: %q", got.VLESSUUID)
	}
	if len(got.RealityShortID) != 8 {
		t.Errorf("short id: %q", got.RealityShortID)
	}
	if len(got.Hy2Password) != 22 {
		t.Errorf("hy2 password len = %d", len(got.Hy2Password))
	}
	if len(got.NaivePassword) != 22 {
		t.Errorf("naive password len = %d", len(got.NaivePassword))
	}
	if !strings.HasPrefix(got.WSPath, "/r17/") {
		t.Errorf("ws path: %q", got.WSPath)
	}
	// Inspect config — all four inbounds should be populated.
	body, _ := os.ReadFile(configPath)
	if !bytes.Contains(body, []byte(got.VLESSUUID)) {
		t.Errorf("VLESS UUID not in config: %s", body)
	}
	if !bytes.Contains(body, []byte(got.Hy2Password)) {
		t.Errorf("Hy2 password not in config")
	}
	if !bytes.Contains(body, []byte(got.NaivePassword)) {
		t.Errorf("Naive password not in config")
	}
	if !bytes.Contains(body, []byte(`"tag": "ws-in"`)) {
		t.Errorf("shared ws inbound not in config: %s", body)
	}
}

func TestUsersProvision_DuplicateRejected(t *testing.T) {
	srv, priv, _, _ := newUsersTestServer(t)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	resp := postJSON(t, ts.URL+"/users/provision", priv, "users-provision", provisionReq{Name: "r5"})
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("first provision failed: %d", resp.StatusCode)
	}
	resp = postJSON(t, ts.URL+"/users/provision", priv, "users-provision", provisionReq{Name: "r5"})
	resp.Body.Close()
	if resp.StatusCode != 409 {
		t.Fatalf("dup provision: got %d want 409", resp.StatusCode)
	}
}

func TestUsersProvision_InvalidNameRejected(t *testing.T) {
	srv, priv, _, _ := newUsersTestServer(t)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	for _, bad := range []string{"", "alice", "R5", "r", "r-5", "r5x"} {
		resp := postJSON(t, ts.URL+"/users/provision", priv, "users-provision", provisionReq{Name: bad})
		resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Errorf("name %q: got %d want 400", bad, resp.StatusCode)
		}
	}
}

func TestUsersProvision_Isolation(t *testing.T) {
	srv, priv, configPath, _ := newUsersTestServer(t)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	resp := postJSON(t, ts.URL+"/users/provision", priv, "users-provision", provisionReq{Name: "r1"})
	var c1 userCreds
	_ = json.NewDecoder(resp.Body).Decode(&c1)
	resp.Body.Close()
	resp = postJSON(t, ts.URL+"/users/provision", priv, "users-provision", provisionReq{Name: "r2"})
	var c2 userCreds
	_ = json.NewDecoder(resp.Body).Decode(&c2)
	resp.Body.Close()

	cfg, _ := os.ReadFile(configPath)
	// Both recipients ride the single shared ws-in inbound (told apart by
	// UUID); a per-user ws inbound would collide on the shared port.
	for _, want := range []string{c1.VLESSUUID, c2.VLESSUUID, c1.Hy2Password, c2.Hy2Password, tagWS} {
		if !bytes.Contains(cfg, []byte(want)) {
			t.Errorf("isolation: %q missing from config", want)
		}
	}
	if n := bytes.Count(cfg, []byte(`"ws-in"`)); n != 1 {
		t.Errorf("got %d ws-in inbounds, want exactly 1 shared inbound", n)
	}
}

func TestUsersRevoke_RemovesAndKicks(t *testing.T) {
	srv, priv, configPath, kickCount := newUsersTestServer(t)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	resp := postJSON(t, ts.URL+"/users/provision", priv, "users-provision", provisionReq{Name: "r9"})
	var c userCreds
	_ = json.NewDecoder(resp.Body).Decode(&c)
	resp.Body.Close()

	resp = postJSON(t, ts.URL+"/users/revoke", priv, "users-revoke", revokeReq{Name: "r9"})
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := readAll(resp.Body)
		t.Fatalf("revoke: %d body %s", resp.StatusCode, body)
	}
	if kickCount.Load() != 1 {
		t.Errorf("kick not invoked: count=%d", kickCount.Load())
	}
	cfg, _ := os.ReadFile(configPath)
	if bytes.Contains(cfg, []byte(c.VLESSUUID)) {
		t.Errorf("config still references revoked VLESS UUID")
	}
	// r9 was the only ws user, so the shared ws-in inbound is dropped
	// (sing-box faults on a user-less inbound).
	if bytes.Contains(cfg, []byte(tagWS)) {
		t.Errorf("empty ws inbound still present in config after last user revoked")
	}
}

func TestUsersRevoke_NotFound(t *testing.T) {
	srv, priv, _, _ := newUsersTestServer(t)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	resp := postJSON(t, ts.URL+"/users/revoke", priv, "users-revoke", revokeReq{Name: "r404"})
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("got %d want 404", resp.StatusCode)
	}
}

func TestUsersRevoke_DoesNotTouchOtherUsers(t *testing.T) {
	srv, priv, configPath, _ := newUsersTestServer(t)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	// Provision two, revoke the first.
	resp := postJSON(t, ts.URL+"/users/provision", priv, "users-provision", provisionReq{Name: "r1"})
	var c1 userCreds
	_ = json.NewDecoder(resp.Body).Decode(&c1)
	resp.Body.Close()
	resp = postJSON(t, ts.URL+"/users/provision", priv, "users-provision", provisionReq{Name: "r2"})
	var c2 userCreds
	_ = json.NewDecoder(resp.Body).Decode(&c2)
	resp.Body.Close()

	resp = postJSON(t, ts.URL+"/users/revoke", priv, "users-revoke", revokeReq{Name: "r1"})
	resp.Body.Close()

	cfg, _ := os.ReadFile(configPath)
	if bytes.Contains(cfg, []byte(c1.VLESSUUID)) {
		t.Errorf("r1 still present after revoke")
	}
	if !bytes.Contains(cfg, []byte(c2.VLESSUUID)) {
		t.Errorf("r2 wrongly removed when r1 was revoked")
	}
	// r2 still rides the shared ws-in inbound after r1 is revoked.
	if !bytes.Contains(cfg, []byte(tagWS)) {
		t.Errorf("shared ws inbound wrongly removed while r2 remains")
	}
	if !bytes.Contains(cfg, []byte(c2.VLESSUUID)) {
		t.Errorf("r2 ws user wrongly removed")
	}
}

func TestUsersList_Returns(t *testing.T) {
	srv, priv, _, _ := newUsersTestServer(t)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	for _, n := range []string{"r1", "r3", "r5"} {
		resp := postJSON(t, ts.URL+"/users/provision", priv, "users-provision", provisionReq{Name: n})
		resp.Body.Close()
	}
	resp := getURL(t, ts.URL+"/users/list", priv, "users-list")
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("list: %d", resp.StatusCode)
	}
	var out listResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Users) != 3 {
		t.Fatalf("user count = %d want 3 (%+v)", len(out.Users), out.Users)
	}
	names := map[string]bool{}
	for _, u := range out.Users {
		names[u.Name] = true
	}
	for _, want := range []string{"r1", "r3", "r5"} {
		if !names[want] {
			t.Errorf("missing %q in list", want)
		}
	}
}

func TestUsersOps_TokenBinding(t *testing.T) {
	srv, priv, _, _ := newUsersTestServer(t)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	// Mint a token for users-list but post to users/provision.
	tok := mintToken(priv, "users-list", srv.now().Unix())
	body, _ := json.Marshal(provisionReq{Name: "r1"})
	req, _ := http.NewRequest("POST", ts.URL+"/users/provision", bytes.NewReader(body))
	req.Header.Set("Authorization", "Daal-Mgmt-Token "+tok)
	resp, _ := http.DefaultClient.Do(req)
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("cross-op token: got %d want 401", resp.StatusCode)
	}
}

func TestUsersProvision_CapEnforced(t *testing.T) {
	if testing.Short() {
		t.Skip("128-user cap test is slow; skipping in -short mode")
	}
	srv, priv, _, _ := newUsersTestServer(t)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	for i := 1; i <= MaxRecipientsPerServer; i++ {
		resp := postJSON(t, ts.URL+"/users/provision", priv, "users-provision",
			provisionReq{Name: fmt.Sprintf("r%d", i)})
		body, _ := readAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("provision %d failed: %d %s", i, resp.StatusCode, body)
		}
	}
	// Now the (cap+1)th must fail with 409.
	resp := postJSON(t, ts.URL+"/users/provision", priv, "users-provision",
		provisionReq{Name: fmt.Sprintf("r%d", MaxRecipientsPerServer+1)})
	resp.Body.Close()
	if resp.StatusCode != 409 {
		t.Fatalf("cap+1 provision: got %d want 409", resp.StatusCode)
	}
}

// helper
func readAll(r interface{ Read(p []byte) (int, error) }) ([]byte, error) {
	buf := make([]byte, 0, 1024)
	tmp := make([]byte, 512)
	for {
		n, err := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			if err.Error() == "EOF" {
				return buf, nil
			}
			return buf, err
		}
	}
}
