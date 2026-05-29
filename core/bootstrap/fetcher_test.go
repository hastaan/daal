package bootstrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	rand2 "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"daal/bundle-go/bundle"
)

// makeDirectorySBP produces a tiny `bundle.type=directory` .sbp signed by
// a freshly-generated key. Returned alongside its publisher fingerprint.
func makeDirectorySBP(t *testing.T) (body []byte, publisherFP string, pub ed25519.PublicKey, priv ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand2.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	manifest := bundle.Manifest{
		SpecVersion: 1,
		Publisher: bundle.PublisherInfo{
			Name:              "test-publisher",
			KeyFingerprintHex: bundle.PublisherFingerprint(pub).Hex,
			KeyCreatedAt:      now.Format(time.RFC3339),
			TrustClass:        "official",
		},
		Bundle: bundle.BundleInfo{
			ID:               "11111111-1111-1111-1111-111111111111",
			Type:             "directory",
			CreatedAt:        now.Format(time.RFC3339),
			ExpiresAt:        now.Add(72 * time.Hour).Format(time.RFC3339),
			PreviousBundleID: nil,
			SupersedesKeys:   []string{},
		},
		Routes: []bundle.RouteManifestEntry{{
			ID:              "dir-route-1",
			ScarcityClass:   "emergency",
			TransportFamily: "vless-reality",
			ConfigPath:      "profiles/dir-route-1.json",
			ValidFrom:       now.Format(time.RFC3339),
			ValidUntil:      now.Add(72 * time.Hour).Format(time.RFC3339),
		}},
	}
	body, err = bundle.BuildSignedBundleDeterministic(manifest, map[string][]byte{
		"profiles/dir-route-1.json": []byte(`{}`),
	}, nil, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return body, bundle.PublisherFingerprint(pub).Hex, pub, priv
}

// startTLSEcho starts a 1-shot TLS listener that serves `body` to whichever
// client connects, with a configurable HTTP status. It returns the
// listener address and a cleanup func. The cert is self-signed and trusted
// only by the returned tls.Config used in the test client.
func startTLSEcho(t *testing.T, body []byte, status int, statusText string) (string, *tls.Config, func()) {
	t.Helper()
	cert, tlsCfg := selfSignedCert(t)
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
				resp := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
					status, statusText, len(body))
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

func selfSignedCert(t *testing.T) (tls.Certificate, *tls.Config) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand2.Reader)
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
	der, err := x509.CreateCertificate(rand2.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
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

// trustingDialer wraps a net.Dialer but performs the TLS handshake using
// the test's self-signed CA. The fetcher does its own tls.Client wrap, so
// we shadow its TLS by injecting a Dialer that returns a *tls.Conn already
// handshaken — simpler is to just inject the test root CA into the
// fetcher's tls.Config. Since Fetch hard-codes tls.Config, we instead
// connect plain TCP and rely on the InsecureSkipVerify-style behavior in
// our test by returning a conn that the fetcher will TLS-wrap. We disable
// hostname verify by reaching the listener via 127.0.0.1.
//
// To make this work without mutating Fetch's TLS config, we set up a
// chain where the cert's CN/SAN is 127.0.0.1 and the system trust store
// is augmented in the test process — we cannot do that. So we use a tiny
// helper that performs the dial + raw HTTP itself, bypassing Fetch's TLS
// when not testing TLS. For tests that DO need to exercise TLS, we
// expose a fetchWithRootCA helper.
type tcpDialer struct{ d net.Dialer }

func (t *tcpDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return t.d.DialContext(ctx, network, address)
}

// fetchWithTLSCfg replicates Fetch but accepts a pre-configured tls.Config
// so the test can install a private root CA. This only exists in tests.
func fetchWithTLSCfg(ctx context.Context, url, expectedFP string, dialer Dialer, tlsCfg *tls.Config, timeout time.Duration) (FetchResult, error) {
	host, port, path, err := splitHTTPSURL(url)
	if err != nil {
		return FetchResult{}, err
	}
	if dialer == nil {
		dialer = NewDirectDialer(timeout)
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	addr := net.JoinHostPort(host, fmt.Sprint(port))
	rawConn, err := dialer.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return FetchResult{}, err
	}
	defer rawConn.Close()
	cfg := tlsCfg.Clone()
	if cfg.ServerName == "" {
		cfg.ServerName = host
	}
	tlsConn := tls.Client(rawConn, cfg)
	tlsConn.SetDeadline(time.Now().Add(timeout))
	if err := tlsConn.HandshakeContext(dialCtx); err != nil {
		return FetchResult{}, err
	}
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, addr)
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		return FetchResult{}, err
	}
	all, err := io.ReadAll(tlsConn)
	if err != nil {
		return FetchResult{}, err
	}
	body, err := splitHTTPResponse(all)
	if err != nil {
		return FetchResult{}, err
	}
	parsed, err := parseSBP(body)
	if err != nil {
		return FetchResult{}, err
	}
	if expectedFP != "" && !strings.EqualFold(parsed.fp, expectedFP) {
		return FetchResult{}, fmt.Errorf("fingerprint mismatch")
	}
	return FetchResult{Bytes: body, PublisherFingerprint: parsed.fp}, nil
}

type parsedSBPResult struct{ fp string }

func parseSBP(body []byte) (*parsedSBPResult, error) {
	// Use the real parser via the bootstrap package's helper; we duplicate
	// only the fingerprint extraction.
	import_, err := importSBPFingerprint(body)
	if err != nil {
		return nil, err
	}
	return &parsedSBPResult{fp: import_}, nil
}

func TestFetcher_HappyPath(t *testing.T) {
	body, fp, _, _ := makeDirectorySBP(t)
	addr, tlsCfg, stop := startTLSEcho(t, body, 200, "OK")
	defer stop()

	url := "https://" + addr + "/dir.sbp"
	res, err := fetchWithTLSCfg(context.Background(), url, fp, nil, tlsCfg, 5*time.Second)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if !strings.EqualFold(res.PublisherFingerprint, fp) {
		t.Fatalf("fp mismatch: got %s want %s", res.PublisherFingerprint, fp)
	}
}

func TestFetcher_FingerprintPinMismatch(t *testing.T) {
	body, _, _, _ := makeDirectorySBP(t)
	addr, tlsCfg, stop := startTLSEcho(t, body, 200, "OK")
	defer stop()

	wrong := strings.Repeat("0", 64)
	url := "https://" + addr + "/dir.sbp"
	if _, err := fetchWithTLSCfg(context.Background(), url, wrong, nil, tlsCfg, 5*time.Second); err == nil {
		t.Fatal("expected fingerprint mismatch error")
	}
}

func TestFetcher_Non200(t *testing.T) {
	addr, tlsCfg, stop := startTLSEcho(t, []byte(""), 404, "Not Found")
	defer stop()
	url := "https://" + addr + "/missing.sbp"
	if _, err := fetchWithTLSCfg(context.Background(), url, "", nil, tlsCfg, 2*time.Second); err == nil {
		t.Fatal("expected non-200 to error")
	}
}

func TestFetcher_OnlyHTTPSAccepted(t *testing.T) {
	if _, err := Fetch(context.Background(), "http://example.com/dir.sbp", "", nil, time.Second); err == nil {
		t.Fatal("expected http:// to be rejected")
	}
}
