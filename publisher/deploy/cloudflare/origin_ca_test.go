package cloudflare

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIssueAndPersistOriginCert_HappyPath(t *testing.T) {
	dir := t.TempDir()
	m := NewMockCFClient("example.com")
	cert, certPath, privPath, err := IssueAndPersistOriginCert(
		context.Background(), m, []byte(testToken), []string{"example.com", "*.example.com"}, dir, 0,
	)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if cert.ID == "" || cert.FingerprintHex == "" {
		t.Fatalf("cert = %+v", cert)
	}
	if cert.KeyPEM != nil {
		t.Error("the private key is still held after it was written")
	}
	for _, p := range []string{certPath, privPath} {
		if filepath.Dir(p) != dir {
			t.Errorf("%s not under out dir", p)
		}
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %o, want 0600", p, st.Mode().Perm())
		}
	}
	if !strings.Contains(m.Calls[0], "5475") {
		t.Errorf("default validity not 5475 days: %v", m.Calls)
	}
}

func TestIssueAndPersistOriginCert_Validation(t *testing.T) {
	m := NewMockCFClient("example.com")
	if _, _, _, err := IssueAndPersistOriginCert(context.Background(), m, []byte(testToken), nil, t.TempDir(), 0); err == nil {
		t.Error("empty hostnames accepted")
	}
	if _, _, _, err := IssueAndPersistOriginCert(context.Background(), m, []byte(testToken), []string{"x.example.com"}, "", 0); err == nil {
		t.Error("empty out dir accepted")
	}
}

func TestIssueAndPersistOriginCert_ScrubsTheToken(t *testing.T) {
	m := NewMockCFClient("example.com")
	m.FailOn = map[string]error{"IssueOriginCert": errors.New("echo " + testToken)}
	_, _, _, err := IssueAndPersistOriginCert(context.Background(), m, []byte(testToken), []string{"example.com"}, t.TempDir(), 0)
	if !errors.Is(err, ErrOriginCAIssueFailed) {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), testToken) {
		t.Fatalf("token in error: %v", err)
	}
}

// The origin-pull pair: a CA that signs exactly one client certificate
// for client auth, and the CA's key gone.
func TestNewAOPMaterial(t *testing.T) {
	now := time.Now()
	mat, err := NewAOPMaterial(now)
	if err != nil {
		t.Fatal(err)
	}
	cab, _ := pem.Decode(mat.CACertPEM)
	ca, err := x509.ParseCertificate(cab.Bytes)
	if err != nil || !ca.IsCA {
		t.Fatalf("CA: %v", err)
	}
	clb, _ := pem.Decode(mat.ClientCertPEM)
	cl, err := x509.ParseCertificate(clb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := cl.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: now}); err != nil {
		t.Fatalf("client cert does not verify for client auth: %v", err)
	}
	if strings.Contains(string(mat.CACertPEM), "PRIVATE") {
		t.Fatal("CA key in the CA file")
	}
	for _, n := range []string{ca.Subject.CommonName, cl.Subject.CommonName} {
		if strings.Contains(strings.ToLower(n), "daal") {
			t.Errorf("subject names the app: %q", n)
		}
	}
}

func TestSetupAOP_UploadsAndKeepsOnlyTheCA(t *testing.T) {
	m := NewMockCFClient("example.com")
	dir := t.TempDir()
	caPath, id, err := SetupAOP(context.Background(), m, []byte(testToken), "zone-example.com", dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if id == "" || m.AOPCerts["zone-example.com"][id] == "" {
		t.Fatalf("upload: id=%q certs=%v", id, m.AOPCerts)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 || filepath.Join(dir, ents[0].Name()) != caPath {
		t.Fatalf("out dir = %v, want only the CA", ents)
	}
	b, _ := os.ReadFile(caPath)
	if strings.Contains(string(b), "PRIVATE") {
		t.Fatal("a private key reached disk")
	}
}
