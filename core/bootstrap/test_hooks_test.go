package bootstrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"
)

// ApplyForTest exposes Provider.applyDirectory + demoteTier2 to the
// external _test package. Defined in the same package as the unexported
// methods so the test can reach them without changing the public API.
func ApplyForTest(p *Provider, dir []byte, now time.Time) (int, int, error) {
	added, updated, _, err := p.applyDirectory(dir, now)
	if err != nil {
		return added, updated, err
	}
	if err := p.demoteTier2(now); err != nil {
		return added, updated, err
	}
	return added, updated, nil
}

// FetchForTest exposes the internal fetchWithTLSCfg-equivalent path so the
// bootstrap_test can issue real fetches against a self-signed listener.
func FetchForTest(ctx context.Context, url, expectedFP string, tlsCfg *tls.Config, timeout time.Duration) (FetchResult, error) {
	host, port, path, err := splitHTTPSURL(url)
	if err != nil {
		return FetchResult{}, err
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		return FetchResult{}, err
	}
	defer conn.Close()
	tlsConn := tls.Client(conn, tlsCfg)
	tlsConn.SetDeadline(time.Now().Add(timeout))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return FetchResult{}, err
	}
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host)
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		return FetchResult{}, err
	}
	buf := make([]byte, 0, 16384)
	chunk := make([]byte, 4096)
	for {
		n, err := tlsConn.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
		}
		if err != nil {
			break
		}
	}
	body, err := splitHTTPResponse(buf)
	if err != nil {
		return FetchResult{}, err
	}
	fp, err := importSBPFingerprint(body)
	if err != nil {
		return FetchResult{}, err
	}
	if expectedFP != "" && fp != expectedFP {
		return FetchResult{}, fmt.Errorf("fp mismatch: got %s want %s", fp, expectedFP)
	}
	return FetchResult{Bytes: body, PublisherFingerprint: fp}, nil
}

// testTLSEcho is shared between bootstrap_test.go and any other helper
// that needs a self-signed listener echoing fixed bytes.
func testTLSEcho(t *testing.T, body []byte) (string, *tls.Config, func()) {
	t.Helper()
	cert, tlsCfg := selfSigned(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 1024)
				_, _ = conn.Read(buf)
				resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(body))
				_, _ = conn.Write([]byte(resp))
				_, _ = conn.Write(body)
			}(c)
		}
	}()
	return listener.Addr().String(), tlsCfg, func() {
		close(stop)
		listener.Close()
	}
}

func selfSigned(t *testing.T) (tls.Certificate, *tls.Config) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyBytes, _ := x509.MarshalECPrivateKey(priv)
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}),
	)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	parsed, _ := x509.ParseCertificate(der)
	pool.AddCert(parsed)
	return cert, &tls.Config{RootCAs: pool, ServerName: "127.0.0.1"}
}
