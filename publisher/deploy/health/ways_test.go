package health

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func selfSigned(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "relay"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, base64.StdEncoding.EncodeToString(sum[:])
}

// tlsListener serves TLS handshakes with cert and records the SNI seen.
func tlsListener(t *testing.T, cert tls.Certificate, sawSNI *atomic.Value) int {
	t.Helper()
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		if sawSNI != nil {
			sawSNI.Store(h.ServerName)
		}
		return nil, nil
	}}
	l, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); c.Close() }()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

func tcpListener(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

func deadPort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return p
}

func TestProbeWays_EachStateFromHere(t *testing.T) {
	relayCert, pin := selfSigned(t)
	strangerCert, _ := selfSigned(t)
	var sni atomic.Value
	reality := tlsListener(t, strangerCert, &sni) // REALITY serves the cover host's certificate
	naive := tlsListener(t, relayCert, nil)
	impostor := tlsListener(t, strangerCert, nil)
	ss := tcpListener(t)
	dead := deadPort(t)

	ways := []Way{
		{Family: "vless-reality", Port: reality},
		{Family: "naive", Port: naive},
		{Family: "websocket-tls", Port: impostor},
		{Family: "shadowsocks", Port: ss},
		{Family: "anytls", Port: dead},
		{Family: "hysteria2", Port: 443, UDP: true},
	}
	got := ProbeWays(context.Background(), net.ParseIP("127.0.0.1"), ways,
		WayProbeOpts{CoverSNI: "www.example.org", CertPin: pin, Timeout: 2 * time.Second})
	want := []string{WayAnswers, WayAnswers, WayWrongServer, WayAnswers, WayNoAnswer, WayNotTestableHere}
	for i, w := range want {
		if got[i].State != w {
			t.Errorf("%s: %s (%s), want %s", got[i].Family, got[i].State, got[i].Error, w)
		}
	}
	if got, _ := sni.Load().(string); got != "www.example.org" {
		t.Errorf("REALITY probe presented SNI %q, want the cover host", got)
	}
}

func TestProbeWays_NoPinMeansAHandshakeIsEnough(t *testing.T) {
	cert, _ := selfSigned(t)
	port := tlsListener(t, cert, nil)
	got := ProbeWays(context.Background(), net.ParseIP("127.0.0.1"), []Way{{Family: "naive", Port: port}},
		WayProbeOpts{Timeout: 2 * time.Second})
	if got[0].State != WayAnswers {
		t.Fatalf("%+v", got[0])
	}
}
