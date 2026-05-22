package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

// TestExactlyThreeRoutes enforces FRP-10 invariant 29: the mgmt
// API surface is exactly /health + /rotate-credentials +
// /rotate-tls. Adding a fourth requires a supplement amendment.
func TestExactlyThreeRoutes(t *testing.T) {
	srv, _, _, _ := newTestServer(t)
	got := append([]string{}, srv.routeNames()...)
	sort.Strings(got)
	want := []string{"/health", "/rotate-credentials", "/rotate-tls"}
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
