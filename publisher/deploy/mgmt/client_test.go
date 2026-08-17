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
	"errors"
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
		var req struct {
			Name string `json:"name"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Name == "" {
			// The Step-7 contract: an omitted name is an error, never
			// "rotate all". A box that accepts it is the old, conflated
			// one and the publisher must never reach this state.
			http.Error(w, "name required", 400)
			return
		}
		_ = json.NewEncoder(w).Encode(RotatedCreds{
			UserCreds:     UserCreds{Name: req.Name, VLESSUUID: "abc"},
			RotatedAtUnix: time.Now().Unix(),
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
	creds, err := cli.RotateCredentials(context.Background(), rec, priv, "r1")
	if err != nil {
		t.Fatalf("RotateCredentials: %v", err)
	}
	if creds.VLESSUUID != "abc" {
		t.Errorf("UUID lost: %q", creds.VLESSUUID)
	}
	if creds.Name != "r1" {
		t.Errorf("Name lost: %q", creds.Name)
	}
}

// The client refuses an empty name before it builds a request. Nothing
// reaches the network, so a version-skewed box never gets the chance to
// read it as "rotate everything".
func TestClient_RotateCredentials_RefusesEmptyName(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	mux := http.NewServeMux()
	reached := false
	mux.HandleFunc("/rotate-credentials", func(w http.ResponseWriter, r *http.Request) {
		reached = true
		_ = json.NewEncoder(w).Encode(RotatedCreds{})
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
	for _, name := range []string{"", "   "} {
		if _, err := cli.RotateCredentials(context.Background(), rec, priv, name); !errors.Is(err, ErrRecipientNameRequired) {
			t.Fatalf("RotateCredentials(%q) err = %v, want ErrRecipientNameRequired", name, err)
		}
	}
	if reached {
		t.Fatal("a nameless rotate-credentials reached the box")
	}
}

// A 200 for the wrong recipient is a failed rotation, not a success:
// the caller is about to mint a pack from whatever comes back.
func TestClient_RotateCredentials_RejectsWrongRecipientEcho(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	mux := http.NewServeMux()
	mux.HandleFunc("/rotate-credentials", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(RotatedCreds{UserCreds: UserCreds{Name: "r9", VLESSUUID: "x"}})
	})
	ts, fp := startTLSServer(t, mux)
	defer ts.Close()
	port, host := splitURL(t, ts.URL)
	rec := mkRec(t, fp, port)
	rec.PublicIP = net.ParseIP(host)
	cli, _ := NewClient(rec)
	if _, err := cli.RotateCredentials(context.Background(), rec, priv, "r1"); err == nil {
		t.Fatal("accepted a rotation the box performed for a different recipient")
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
