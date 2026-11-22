package bootstrap

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// browserFake is a TLS server answering for any of names, recording the
// SNI, the Host and the accept header of each request.
type browserFake struct {
	srv  *httptest.Server
	pool *x509.CertPool

	mu      sync.Mutex
	snis    []string
	hosts   []string
	accepts []string
	protos  []string
	handler http.HandlerFunc
}

func newBrowserFake(t *testing.T, h2 bool, names []string, h http.HandlerFunc) *browserFake {
	t.Helper()
	f := &browserFake{handler: h}
	cert, pool := testCertFor(t, names)
	f.pool = pool
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.hosts = append(f.hosts, r.Host)
		f.accepts = append(f.accepts, r.Header.Get("Accept"))
		f.protos = append(f.protos, r.Proto)
		f.mu.Unlock()
		if r.Header.Get("User-Agent") == "" {
			http.Error(w, "no ua", 400)
			return
		}
		f.handler(w, r)
	}))
	f.srv.EnableHTTP2 = h2
	f.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetConfigForClient: func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
			f.mu.Lock()
			f.snis = append(f.snis, hi.ServerName)
			f.mu.Unlock()
			return nil, nil
		},
	}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

func testCertFor(t *testing.T, names []string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(9),
		Subject:               pkix.Name{CommonName: "fake host"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		DNSNames:              names,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// toDialer sends every dial to target and records the address asked.
type toDialer struct {
	target string
	mu     sync.Mutex
	addrs  []string
}

func (d *toDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.addrs = append(d.addrs, address)
	d.mu.Unlock()
	var nd net.Dialer
	return nd.DialContext(ctx, network, d.target)
}

func (f *browserFake) dialer() *toDialer { return &toDialer{target: f.srv.Listener.Addr().String()} }

func TestBrowserGet_H2SNIEqualsHostAndAccept(t *testing.T) {
	f := newBrowserFake(t, true, []string{"github.com"}, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RequestURI() != "/o/r/tags.atom" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/atom+xml")
		_, _ = io.WriteString(w, "feed")
	})
	d := f.dialer()
	res, err := BrowserGet(context.Background(), d, "github.com", "/o/r/tags.atom",
		BrowserGetOptions{Accept: "application/atom+xml", RootCAs: f.pool, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != 200 || string(res.Body) != "feed" || !res.HTTP2 || res.ContentType != "application/atom+xml" {
		t.Fatalf("%+v", res)
	}
	if len(f.snis) != 1 || f.snis[0] != "github.com" || f.hosts[0] != "github.com" || f.accepts[0] != "application/atom+xml" {
		t.Fatalf("sni %v host %v accept %v", f.snis, f.hosts, f.accepts)
	}
	if len(d.addrs) != 1 || d.addrs[0] != "github.com:443" {
		t.Fatalf("dialled %v", d.addrs)
	}
}

func TestBrowserGet_HTTP11Fallback(t *testing.T) {
	big := strings.Repeat("x", 9000)
	f := newBrowserFake(t, false, []string{"goproxy.cn"}, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/chunked":
			_, _ = io.WriteString(w, big[:4000])
			w.(http.Flusher).Flush()
			_, _ = io.WriteString(w, big[4000:])
		default:
			w.Header().Set("Content-Length", "5")
			_, _ = io.WriteString(w, "hello")
		}
	})
	for path, want := range map[string]string{"/plain": "hello", "/chunked": big} {
		res, err := BrowserGet(context.Background(), f.dialer(), "goproxy.cn", path,
			BrowserGetOptions{RootCAs: f.pool, Timeout: 5 * time.Second})
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if res.HTTP2 || res.Status != 200 || string(res.Body) != want {
			t.Fatalf("%s: %v %d %d", path, res.HTTP2, res.Status, len(res.Body))
		}
	}
	if f.accepts[0] != "*/*" || f.protos[0] != "HTTP/1.1" {
		t.Fatalf("accept %v proto %v", f.accepts, f.protos)
	}
}

// A redirect comes back as a status; its target is never asked.
func TestBrowserGet_RedirectNotFollowed(t *testing.T) {
	for _, h2 := range []bool{true, false} {
		f := newBrowserFake(t, h2, []string{"raw.githubusercontent.com", "evil.example"}, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://evil.example/x", http.StatusFound)
		})
		d := f.dialer()
		res, err := BrowserGet(context.Background(), d, "raw.githubusercontent.com", "/o/r/t/n", BrowserGetOptions{RootCAs: f.pool})
		if err != nil {
			t.Fatal(err)
		}
		if res.Status != 302 || len(d.addrs) != 1 || len(f.hosts) != 1 {
			t.Fatalf("h2=%v: status %d, dials %v, requests %v", h2, res.Status, d.addrs, f.hosts)
		}
	}
}

func TestBrowserGet_BoundedRead(t *testing.T) {
	for _, h2 := range []bool{true, false} {
		for _, chunked := range []bool{true, false} {
			f := newBrowserFake(t, h2, []string{"data.jsdelivr.com"}, func(w http.ResponseWriter, r *http.Request) {
				body := bytes.Repeat([]byte("a"), 70<<10)
				if !chunked {
					w.Header().Set("Content-Length", "71680")
				}
				_, _ = w.Write(body[:100])
				w.(http.Flusher).Flush()
				_, _ = w.Write(body[100:])
			})
			_, err := BrowserGet(context.Background(), f.dialer(), "data.jsdelivr.com", "/v1/x", BrowserGetOptions{RootCAs: f.pool})
			if !errors.Is(err, ErrResponseTooLarge) {
				t.Fatalf("h2=%v chunked=%v: %v", h2, chunked, err)
			}
			res, err := BrowserGet(context.Background(), f.dialer(), "data.jsdelivr.com", "/v1/x",
				BrowserGetOptions{RootCAs: f.pool, MaxBody: 80 << 10})
			if err != nil || len(res.Body) != 70<<10 {
				t.Fatalf("h2=%v chunked=%v with a larger bound: %v", h2, chunked, err)
			}
		}
	}
	if _, err := BrowserGet(context.Background(), NoDialerForTest{}, "a.example", "/", BrowserGetOptions{MaxBody: BrowserGetMaxBodyLimit + 1}); err == nil {
		t.Fatal("a bound above the limit was accepted")
	}
}

// A server that accepts and then says nothing: the deadline ends it.
func TestBrowserGet_StalledServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { time.Sleep(5 * time.Second); c.Close() }()
		}
	}()
	start := time.Now()
	_, err = BrowserGet(context.Background(), &toDialer{target: ln.Addr().String()}, "github.com", "/",
		BrowserGetOptions{Timeout: 300 * time.Millisecond})
	if err == nil || time.Since(start) > 3*time.Second {
		t.Fatalf("err %v after %v", err, time.Since(start))
	}

	// A TLS server that answers the handshake and then stalls the body.
	f := newBrowserFake(t, true, []string{"github.com"}, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	})
	start = time.Now()
	_, err = BrowserGet(context.Background(), f.dialer(), "github.com", "/",
		BrowserGetOptions{RootCAs: f.pool, Timeout: 300 * time.Millisecond})
	if err == nil || time.Since(start) > 3*time.Second {
		t.Fatalf("stalled body: err %v after %v", err, time.Since(start))
	}
}

func TestBrowserGet_CertificateForAnotherName(t *testing.T) {
	f := newBrowserFake(t, true, []string{"other.example"}, func(w http.ResponseWriter, r *http.Request) {})
	if _, err := BrowserGet(context.Background(), f.dialer(), "github.com", "/", BrowserGetOptions{RootCAs: f.pool}); err == nil {
		t.Fatal("a certificate for another name was accepted")
	}
	if _, err := BrowserGet(context.Background(), f.dialer(), "other.example", "/", BrowserGetOptions{}); err == nil {
		t.Fatal("an untrusted certificate was accepted")
	}
}

func TestBrowserGet_EncodedAnswerRefused(t *testing.T) {
	f := newBrowserFake(t, true, []string{"github.com"}, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = io.WriteString(w, "zz")
	})
	if _, err := BrowserGet(context.Background(), f.dialer(), "github.com", "/", BrowserGetOptions{RootCAs: f.pool}); err == nil {
		t.Fatal("an encoded answer was accepted")
	}
}

// NoDialerForTest fails the test's purpose if dialled: these inputs are
// refused before any connection.
type NoDialerForTest struct{}

func (NoDialerForTest) DialContext(context.Context, string, string) (net.Conn, error) {
	panic("dialled")
}

func TestBrowserGet_RefusesBadInput(t *testing.T) {
	for _, c := range []struct{ host, path, accept string }{
		{"github.com:443", "/", ""},
		{"127.0.0.1", "/", ""},
		{"GitHub.com", "/", ""},
		{"localhost", "/", ""},
		{"github.com", "x", ""},
		{"github.com", "//evil/x", ""},
		{"github.com", "/a b", ""},
		{"github.com", "/a\r\nX: y", ""},
		{"github.com", "/a#f", ""},
		{"github.com", "/", "a\r\nX: y"},
	} {
		if _, err := BrowserGet(context.Background(), NoDialerForTest{}, c.host, c.path, BrowserGetOptions{Accept: c.accept}); err == nil {
			t.Fatalf("accepted %q %q %q", c.host, c.path, c.accept)
		}
	}
}

func TestH2RequestHeaders_DefaultAcceptUnchanged(t *testing.T) {
	old := h2RequestHeaders("script.google.com", "/x")
	if !bytes.Equal(old, h2RequestHeadersAccept("script.google.com", "/x", "*/*")) {
		t.Fatal("the default request changed")
	}
	b := h2RequestHeadersAccept("github.com", "/x", "application/atom+xml")
	d := newHPACKDecoder(4096)
	got, err := d.decode(b, 1<<16)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range got {
		if f.name == "accept" {
			found = f.value == "application/atom+xml"
		}
	}
	if !found {
		t.Fatalf("accept not sent: %v", got)
	}
}

// --- FetchFronted ---------------------------------------------------------

func newProxyFront(t *testing.T, h http.HandlerFunc) *browserFake {
	return newBrowserFake(t, true, []string{GoogleFrontSNI, GoProxyHost}, h)
}

func TestFetchFronted_GoProxyThroughTheFront(t *testing.T) {
	f := newProxyFront(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Host != GoProxyHost || r.URL.Path != "/github.com/o/r/@v/list" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, "v0.1.0\n")
	})
	d := f.dialer()
	res, err := FetchFronted(context.Background(), GoProxyHost, "/github.com/o/r/@v/list", d, 5*time.Second, FrontOptions{RootCAs: f.pool})
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Body) != "v0.1.0\n" || !res.ViaFront || res.Connections != 1 {
		t.Fatalf("%+v", res)
	}
	if f.snis[0] != GoogleFrontSNI || f.hosts[0] != GoProxyHost || d.addrs[0] != "www.google.com:443" {
		t.Fatalf("sni %v host %v dial %v", f.snis, f.hosts, d.addrs)
	}
}

func TestFetchFronted_NoRedirectNoSecondTry(t *testing.T) {
	f := newProxyFront(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://proxy.golang.org/elsewhere", http.StatusFound)
	})
	d := f.dialer()
	_, err := FetchFronted(context.Background(), GoProxyHost, "/x", d, 5*time.Second, FrontOptions{RootCAs: f.pool})
	if !errors.Is(err, ErrFrontRefused) || len(f.hosts) != 1 || len(d.addrs) != 1 {
		t.Fatalf("err %v, requests %v, dials %v", err, f.hosts, d.addrs)
	}
	f2 := newProxyFront(t, func(w http.ResponseWriter, r *http.Request) { http.Error(w, "gone", 410) })
	if _, err := FetchFronted(context.Background(), GoProxyHost, "/x", f2.dialer(), 5*time.Second, FrontOptions{RootCAs: f2.pool}); !errors.Is(err, ErrFrontRefused) {
		t.Fatalf("410: %v", err)
	}
}

func TestFetchFronted_ClosedAuthorityList(t *testing.T) {
	for _, a := range []string{AppsScriptHost, "evil.example", "amp-dev.cdn.ampproject.org", ""} {
		if _, err := FetchFronted(context.Background(), a, "/x", NoDialerForTest{}, time.Second, FrontOptions{}); err == nil {
			t.Fatalf("authority %q accepted", a)
		}
	}
	if !FrontAuthorityAllowed(GoProxyHost) || !FrontAuthorityAllowed(AppsScriptHost) || FrontAuthorityAllowed("x.example") {
		t.Fatal("list")
	}
}

func TestFetchFronted_LargerBound(t *testing.T) {
	body := strings.Repeat("b", 100<<10)
	f := newProxyFront(t, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, body) })
	if _, err := FetchFronted(context.Background(), GoProxyHost, "/x", f.dialer(), 5*time.Second, FrontOptions{RootCAs: f.pool}); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("default bound: %v", err)
	}
	res, err := FetchFronted(context.Background(), GoProxyHost, "/x", f.dialer(), 5*time.Second, FrontOptions{RootCAs: f.pool, MaxBody: FrontMaxBodyLimit})
	if err != nil || len(res.Body) != len(body) {
		t.Fatalf("raised bound: %v", err)
	}
}
