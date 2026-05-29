package mgmt

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"daal/publisher/deploy/provider"
)

// --- helpers ---

func mkRec(t *testing.T, fingerprint string, port int) *provider.OperatorRecord {
	t.Helper()
	return &provider.OperatorRecord{
		Provider:           "hetzner",
		ServerID:           "1",
		PublicIP:           net.ParseIP("127.0.0.1"),
		MgmtPort:           port,
		MgmtTLSFingerprint: fingerprint,
	}
}

func startTLSServer(t *testing.T, handler http.Handler) (*httptest.Server, string) {
	t.Helper()
	ts := httptest.NewTLSServer(handler)
	cert := ts.Certificate()
	sum := sha256.Sum256(cert.Raw)
	fp := hex.EncodeToString(sum[:])
	return ts, fp
}

// --- token tests ---

func TestMintToken_RoundTripsThroughParse(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	tok, err := MintToken(priv, "rotate-credentials", time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	nonce, tsStr, op, sig, err := ParseToken(tok)
	if err != nil {
		t.Fatal(err)
	}
	if op != "rotate-credentials" {
		t.Errorf("op lost: %q", op)
	}
	if tsStr == "" {
		t.Errorf("ts lost")
	}
	msg := []byte(nonce + ":" + tsStr + ":" + op)
	if !ed25519.Verify(pub, msg, sig) {
		t.Errorf("signature does not verify against pub key")
	}
}

func TestMintToken_RejectsUnknownOp(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := MintToken(priv, "rotate-everything", time.Now()); err == nil {
		t.Errorf("expected error for unknown op")
	}
}

func TestMintToken_RejectsBadKey(t *testing.T) {
	if _, err := MintToken(nil, "rotate-credentials", time.Now()); err == nil {
		t.Errorf("expected error for nil key")
	}
}

// --- client tests ---

func TestNewClient_RejectsEmptyFingerprint(t *testing.T) {
	rec := mkRec(t, "", 42424)
	if _, err := NewClient(rec); err == nil {
		t.Errorf("empty MgmtTLSFingerprint must be rejected (invariant 26)")
	}
}

func TestNewClient_RejectsZeroPort(t *testing.T) {
	rec := mkRec(t, "deadbeef", 0)
	if _, err := NewClient(rec); err == nil {
		t.Errorf("zero MgmtPort must be rejected (invariant 27)")
	}
}

func TestNewClient_RejectsPortOutsideRandomRange(t *testing.T) {
	fp := hex.EncodeToString(bytes.Repeat([]byte{0x11}, 32))
	for _, port := range []int{8443, 9999, 65001} {
		rec := mkRec(t, fp, port)
		if _, err := NewClient(rec); err == nil {
			t.Fatalf("MgmtPort %d must be rejected", port)
		}
	}
}

func TestNewClient_RejectsMalformedFingerprint(t *testing.T) {
	rec := mkRec(t, "deadbeef", 42424)
	if _, err := NewClient(rec); err == nil {
		t.Fatalf("short MgmtTLSFingerprint must be rejected")
	}
}

func TestClient_Health_ValidatesAgainstPinnedCert(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
	ts, fp := startTLSServer(t, mux)
	defer ts.Close()

	port, host := splitURL(t, ts.URL)
	rec := mkRec(t, fp, port)
	rec.PublicIP = net.ParseIP(host)
	cli, err := NewClient(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := cli.Health(context.Background(), rec); err != nil {
		t.Errorf("Health: %v", err)
	}
}

func TestClient_RejectsWrongFingerprint(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
	ts, _ := startTLSServer(t, mux)
	defer ts.Close()

	port, host := splitURL(t, ts.URL)
	// Wrong fingerprint:
	rec := mkRec(t, hex.EncodeToString(bytes.Repeat([]byte{0xAA}, 32)), port)
	rec.PublicIP = net.ParseIP(host)
	cli, err := NewClient(rec)
	if err != nil {
		t.Fatal(err)
	}
	err = cli.Health(context.Background(), rec)
	if err == nil {
		t.Fatalf("expected fingerprint mismatch error; got nil")
	}
	if !strings.Contains(err.Error(), "TLS fingerprint mismatch") {
		t.Errorf("error %v did not mention fingerprint mismatch", err)
	}
}

func TestClient_RotateCredentials_SignedTokenRequired(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	tlsFP := ""
	mux := http.NewServeMux()
	mux.HandleFunc("/rotate-credentials", func(w http.ResponseWriter, r *http.Request) {
		hdr := r.Header.Get("Authorization")
		if !strings.HasPrefix(hdr, "Daal-Mgmt-Token ") {
			http.Error(w, "no auth", 401)
			return
		}
		tok := strings.TrimPrefix(hdr, "Daal-Mgmt-Token ")
		nonce, tsStr, op, sig, err := ParseToken(tok)
		if err != nil {
			http.Error(w, "bad token", 401)
			return
		}
		if op != "rotate-credentials" {
			http.Error(w, "wrong op", 401)
			return
		}
		msg := []byte(nonce + ":" + tsStr + ":" + op)
		if !ed25519.Verify(pub, msg, sig) {
			http.Error(w, "sig fail", 401)
			return
		}
		_ = json.NewEncoder(w).Encode(Credentials{
			UUID:            "abc",
			RealityPrivKey:  hex.EncodeToString(bytes.Repeat([]byte{0x42}, 32)),
			GeneratedAtUnix: time.Now().Unix(),
		})
	})
	ts, fp := startTLSServer(t, mux)
	defer ts.Close()
	tlsFP = fp

	port, host := splitURL(t, ts.URL)
	rec := mkRec(t, tlsFP, port)
	rec.PublicIP = net.ParseIP(host)
	cli, err := NewClient(rec)
	if err != nil {
		t.Fatal(err)
	}
	creds, err := cli.RotateCredentials(context.Background(), rec, priv)
	if err != nil {
		t.Fatalf("RotateCredentials: %v", err)
	}
	if creds.UUID != "abc" {
		t.Errorf("UUID lost: %q", creds.UUID)
	}
}

func TestClient_RotateTLS_SendsProfile(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	var sawSNI string
	mux := http.NewServeMux()
	mux.HandleFunc("/rotate-tls", func(w http.ResponseWriter, r *http.Request) {
		var body TLSProfile
		_ = json.NewDecoder(r.Body).Decode(&body)
		sawSNI = body.NewSNI
		hdr := r.Header.Get("Authorization")
		tok := strings.TrimPrefix(hdr, "Daal-Mgmt-Token ")
		nonce, tsStr, op, sig, err := ParseToken(tok)
		if err != nil || op != "rotate-tls" {
			http.Error(w, "bad token", 401)
			return
		}
		msg := []byte(nonce + ":" + tsStr + ":" + op)
		if !ed25519.Verify(pub, msg, sig) {
			http.Error(w, "sig fail", 401)
			return
		}
		_ = json.NewEncoder(w).Encode(RotateTLSResp{AppliedAtUnix: time.Now().Unix()})
	})
	ts, fp := startTLSServer(t, mux)
	defer ts.Close()

	port, host := splitURL(t, ts.URL)
	rec := mkRec(t, fp, port)
	rec.PublicIP = net.ParseIP(host)
	cli, err := NewClient(rec)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cli.RotateTLS(context.Background(), rec, priv, TLSProfile{
		NewSNI: "fresh.example.com", NewDests: []string{"fresh.example.com:443"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.AppliedAtUnix == 0 {
		t.Errorf("AppliedAtUnix not set")
	}
	if sawSNI != "fresh.example.com" {
		t.Errorf("server did not see new SNI; got %q", sawSNI)
	}
}

// --- flow test ---

// stubProvider captures (Set|Remove)EphemeralFirewallRule calls.
type stubProvider struct {
	provider.Provider
	setCalls    int
	removeCalls int
	rule        *provider.EphemeralFirewallRule
}

func (s *stubProvider) SetEphemeralFirewallRule(_ context.Context, serverID, callerIP string, port, dur int) (*provider.EphemeralFirewallRule, error) {
	s.setCalls++
	s.rule = &provider.EphemeralFirewallRule{ID: "stub-rule", ServerID: serverID, CallerIP: callerIP, Port: port}
	return s.rule, nil
}

func (s *stubProvider) RemoveEphemeralFirewallRule(_ context.Context, _ *provider.EphemeralFirewallRule) error {
	s.removeCalls++
	return nil
}

func TestRotateCredentialsWithFW_OpensAndClosesRule(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	mux := http.NewServeMux()
	mux.HandleFunc("/rotate-credentials", func(w http.ResponseWriter, r *http.Request) {
		hdr := r.Header.Get("Authorization")
		tok := strings.TrimPrefix(hdr, "Daal-Mgmt-Token ")
		nonce, tsStr, op, sig, err := ParseToken(tok)
		if err != nil || !ed25519.Verify(pub, []byte(nonce+":"+tsStr+":"+op), sig) {
			http.Error(w, "auth", 401)
			return
		}
		_ = json.NewEncoder(w).Encode(Credentials{UUID: "abc"})
	})
	ts, fp := startTLSServer(t, mux)
	defer ts.Close()
	port, host := splitURL(t, ts.URL)
	rec := mkRec(t, fp, port)
	rec.PublicIP = net.ParseIP(host)

	prov := &stubProvider{}
	creds, err := RotateCredentialsWithFW(context.Background(), prov, rec, priv, "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if creds.UUID != "abc" {
		t.Errorf("UUID lost")
	}
	if prov.setCalls != 1 {
		t.Errorf("setCalls = %d want 1", prov.setCalls)
	}
	if prov.removeCalls != 1 {
		t.Errorf("removeCalls = %d want 1 (cleanup must run)", prov.removeCalls)
	}
	if prov.rule.Port != port {
		t.Errorf("rule opened wrong port; got %d want %d", prov.rule.Port, port)
	}
}

func TestRotateCredentialsWithFW_CleansUpOnError(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	// Server returns 500 to force a mgmt-side failure.
	mux := http.NewServeMux()
	mux.HandleFunc("/rotate-credentials", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", 500)
	})
	ts, fp := startTLSServer(t, mux)
	defer ts.Close()
	port, host := splitURL(t, ts.URL)
	rec := mkRec(t, fp, port)
	rec.PublicIP = net.ParseIP(host)

	prov := &stubProvider{}
	if _, err := RotateCredentialsWithFW(context.Background(), prov, rec, priv, "1.2.3.4"); err == nil {
		t.Fatalf("expected error from 500 response")
	}
	if prov.removeCalls != 1 {
		t.Errorf("cleanup must still run on error; removeCalls = %d", prov.removeCalls)
	}
}

func TestRotateCredentialsWithFW_FallsBackOnZeroPort(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	rec := mkRec(t, "fp", 0) // V1.5 record (no MgmtPort)
	prov := &stubProvider{}
	if _, err := RotateCredentialsWithFW(context.Background(), prov, rec, priv, "1.2.3.4"); err == nil {
		t.Fatalf("V1.5 record (zero MgmtPort) must error so caller falls back to redeploy")
	}
	if prov.setCalls != 0 {
		t.Errorf("must not call SetEphemeralFirewallRule on zero MgmtPort")
	}
}

// --- helpers ---

func splitURL(t *testing.T, urlStr string) (int, string) {
	t.Helper()
	// httptest URLs are https://127.0.0.1:<port>
	const prefix = "https://"
	rest := strings.TrimPrefix(urlStr, prefix)
	colon := strings.IndexByte(rest, ':')
	if colon < 0 {
		t.Fatalf("unexpected httptest URL: %q", urlStr)
	}
	host := rest[:colon]
	portStr := rest[colon+1:]
	if i := strings.IndexByte(portStr, '/'); i >= 0 {
		portStr = portStr[:i]
	}
	port := 0
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}
	return port, host
}

// silence unused tls import warning across builds
var _ = tls.VersionTLS13
