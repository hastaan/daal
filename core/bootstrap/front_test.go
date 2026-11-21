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
	"fmt"
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

// fakeFront is a local stand-in for Google's front: one TLS listener
// answering for every Google name, routing by the request's authority,
// with the Apps Script /exec → script.googleusercontent.com redirect.
// Shaped like publisher/deploy/freshness/backends/appsscript/
// appsscripttest (which core cannot import: another module).
type fakeFront struct {
	srv  *httptest.Server
	pool *x509.CertPool

	mu sync.Mutex
	// Knobs.
	body       string
	status     int    // the echo's status; 0 = 200
	location   string // replaces the redirect target when set
	redirects  int    // how many redirects in a row (default 1)
	blockFront bool   // cut connections whose SNI is www.google.com
	blockPlain bool   // cut connections with any other SNI
	noH2       bool   // answer HTTP/1.1 only
	// Observations.
	snis   []string
	calls  []string // "host path"
	protos []string
}

var fakeGoogleNames = []string{"www.google.com", "script.google.com", "script.googleusercontent.com"}

func newFakeFront(t *testing.T) *fakeFront {
	t.Helper()
	f := &fakeFront{body: "hello", redirects: 1}
	cert, pool := fakeGoogleCert(t)
	f.pool = pool
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.srv.EnableHTTP2 = true
	f.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.snis = append(f.snis, h.ServerName)
			if (h.ServerName == GoogleFrontSNI && f.blockFront) || (h.ServerName != GoogleFrontSNI && f.blockPlain) {
				return nil, errors.New("cut")
			}
			if f.noH2 {
				return &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}}, nil
			}
			return nil, nil
		},
	}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeFront) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.calls = append(f.calls, r.Host+" "+r.URL.RequestURI())
	f.protos = append(f.protos, r.Proto)
	status, body, loc, redirects := f.status, f.body, f.location, f.redirects
	f.mu.Unlock()
	if r.Header.Get("User-Agent") == "" {
		http.Error(w, "no ua", 400)
		return
	}
	switch r.Host {
	case "script.google.com":
		if !strings.HasPrefix(r.URL.Path, "/macros/s/") {
			http.NotFound(w, r)
			return
		}
		if loc == "" {
			loc = "https://script.googleusercontent.com/macros/echo?user_content_key=abc&lib=x"
		}
		http.Redirect(w, r, loc, http.StatusFound)
	case "script.googleusercontent.com":
		n := strings.Count(r.URL.RawQuery, "hop")
		if n+1 < redirects {
			http.Redirect(w, r, "https://script.googleusercontent.com/macros/echo?hop"+strings.Repeat("hop", n+1), http.StatusFound)
			return
		}
		if status == 0 {
			status = 200
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	default:
		http.NotFound(w, r)
	}
}

func fakeGoogleCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: "fake google"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		DNSNames:              fakeGoogleNames,
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

// frontDialer sends every dial to the fake and records the address
// asked for. Names in noDNS fail as a resolver would.
type frontDialer struct {
	target string
	noDNS  map[string]bool
	mu     sync.Mutex
	addrs  []string
}

func (d *frontDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.addrs = append(d.addrs, address)
	d.mu.Unlock()
	host, _, _ := net.SplitHostPort(address)
	if d.noDNS[host] {
		return nil, &net.OpError{Op: "dial", Net: network, Err: &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}}
	}
	var nd net.Dialer
	return nd.DialContext(ctx, network, d.target)
}

const testExecURL = "https://script.google.com/macros/s/AKfycbTEST0000000000000001/exec?k=AAAAAAAAAAAAAAAAAAAAAA"

func (f *fakeFront) fetch(t *testing.T, d *frontDialer) (FrontResult, error) {
	t.Helper()
	if d.target == "" {
		d.target = f.srv.Listener.Addr().String()
	}
	return FetchAppsScript(context.Background(), testExecURL, d, 5*time.Second, FrontOptions{RootCAs: f.pool})
}

func TestFetchAppsScript_FrontedWithOneRedirect(t *testing.T) {
	f := newFakeFront(t)
	d := &frontDialer{}
	res, err := f.fetch(t, d)
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Body) != "hello" || !res.ViaFront || res.Connections != 1 {
		t.Fatalf("got %+v", res)
	}
	if len(d.addrs) != 1 || d.addrs[0] != "www.google.com:443" {
		t.Fatalf("dialled %v", d.addrs)
	}
	if len(f.snis) != 1 || f.snis[0] != "www.google.com" {
		t.Fatalf("SNIs %v", f.snis)
	}
	want := []string{
		"script.google.com /macros/s/AKfycbTEST0000000000000001/exec?k=AAAAAAAAAAAAAAAAAAAAAA",
		"script.googleusercontent.com /macros/echo?user_content_key=abc&lib=x",
	}
	if fmt.Sprint(f.calls) != fmt.Sprint(want) {
		t.Fatalf("calls %v", f.calls)
	}
	for _, p := range f.protos {
		if p != "HTTP/2.0" {
			t.Fatalf("protocol %s", p)
		}
	}
}

func TestFetchAppsScript_PlainAfterFrontCut(t *testing.T) {
	f := newFakeFront(t)
	f.blockFront = true
	d := &frontDialer{}
	res, err := f.fetch(t, d)
	if err != nil {
		t.Fatal(err)
	}
	if res.ViaFront || res.Connections != 2 || string(res.Body) != "hello" {
		t.Fatalf("got %+v", res)
	}
	if fmt.Sprint(d.addrs) != "[www.google.com:443 script.google.com:443]" {
		t.Fatalf("dialled %v", d.addrs)
	}
	if fmt.Sprint(f.snis) != "[www.google.com script.google.com]" {
		t.Fatalf("SNIs %v", f.snis)
	}
}

func TestFetchAppsScript_BothCutIsTwoConnections(t *testing.T) {
	f := newFakeFront(t)
	f.blockFront, f.blockPlain = true, true
	d := &frontDialer{}
	res, err := f.fetch(t, d)
	if err == nil {
		t.Fatal("fetched through a cut front")
	}
	if res.Connections != 2 || len(d.addrs) != 2 || len(f.snis) != 2 {
		t.Fatalf("connections %d, dials %v, SNIs %v", res.Connections, d.addrs, f.snis)
	}
	if strings.Contains(err.Error(), "AKfycb") || strings.Contains(err.Error(), "k=") {
		t.Fatalf("the URL leaked into the error: %v", err)
	}
}

func TestFetchAppsScript_ShippedAddressOnlyWhenTheNameDoesNotResolve(t *testing.T) {
	f := newFakeFront(t)
	d := &frontDialer{noDNS: map[string]bool{"www.google.com": true}}
	res, err := f.fetch(t, d)
	if err != nil {
		t.Fatal(err)
	}
	if !res.ViaFront || fmt.Sprint(d.addrs) != "[www.google.com:443 216.239.38.120:443]" {
		t.Fatalf("got %+v, dialled %v", res, d.addrs)
	}
	if fmt.Sprint(f.snis) != "[www.google.com]" {
		t.Fatalf("SNIs %v", f.snis)
	}
}

func TestFetchAppsScript_RedirectAllowlist(t *testing.T) {
	for _, loc := range []string{
		"https://evil.example/macros/echo?x=1",
		"http://script.googleusercontent.com/macros/echo",
		"https://script.googleusercontent.com:8443/macros/echo",
		"https://user@script.googleusercontent.com/macros/echo",
		"https://script.googleusercontent.com.evil.example/x",
		"/relative",
		"https:///macros/echo",
	} {
		f := newFakeFront(t)
		f.location = loc
		d := &frontDialer{}
		res, err := f.fetch(t, d)
		if !errors.Is(err, ErrFrontRefused) {
			t.Fatalf("%q: got %v", loc, err)
		}
		// Google answered: no plain retry.
		if res.Connections != 1 || len(f.calls) != 1 {
			t.Fatalf("%q: connections %d, calls %v", loc, res.Connections, f.calls)
		}
	}
}

func TestFetchAppsScript_OnlyOneRedirect(t *testing.T) {
	f := newFakeFront(t)
	f.redirects = 2
	_, err := f.fetch(t, &frontDialer{})
	if !errors.Is(err, ErrFrontRefused) || !strings.Contains(err.Error(), "more than one redirect") {
		t.Fatalf("got %v", err)
	}
	if len(f.calls) != 2 {
		t.Fatalf("calls %v", f.calls)
	}
}

func TestFetchAppsScript_BoundedRead(t *testing.T) {
	f := newFakeFront(t)
	f.body = strings.Repeat("x", FrontMaxBody)
	res, err := f.fetch(t, &frontDialer{})
	if err != nil || len(res.Body) != FrontMaxBody {
		t.Fatalf("a body of exactly the limit: %v (%d)", err, len(res.Body))
	}
	f.body = strings.Repeat("x", FrontMaxBody+1)
	res, err = f.fetch(t, &frontDialer{})
	if !errors.Is(err, ErrResponseTooLarge) || res.Body != nil {
		t.Fatalf("an oversized body: %v", err)
	}
	if res.Connections != 1 {
		t.Fatalf("an oversized answer was retried: %d", res.Connections)
	}
}

func TestFetchAppsScript_NonOKIsNotRetried(t *testing.T) {
	f := newFakeFront(t)
	f.status = 404
	res, err := f.fetch(t, &frontDialer{})
	if !errors.Is(err, ErrFrontRefused) || res.Connections != 1 {
		t.Fatalf("got %v, %d connections", err, res.Connections)
	}
}

func TestFetchAppsScript_NoH2IsNotTheFront(t *testing.T) {
	f := newFakeFront(t)
	f.noH2 = true
	res, err := f.fetch(t, &frontDialer{})
	if err == nil || res.Connections != 2 {
		t.Fatalf("got %v, %d connections", err, res.Connections)
	}
	if len(f.calls) != 0 {
		t.Fatalf("a request went over HTTP/1.1: %v", f.calls)
	}
}

func TestFetchAppsScript_UntrustedCertificate(t *testing.T) {
	f := newFakeFront(t)
	d := &frontDialer{target: f.srv.Listener.Addr().String()}
	// System roots: the fake's certificate does not verify.
	_, err := FetchAppsScript(context.Background(), testExecURL, d, 5*time.Second, FrontOptions{})
	if err == nil {
		t.Fatal("a certificate no root vouches for was accepted")
	}
	if len(f.calls) != 0 {
		t.Fatalf("a request went out: %v", f.calls)
	}
}

func TestFetchAppsScript_RefusesOtherHosts(t *testing.T) {
	for _, u := range []string{
		"https://example.com/macros/s/x/exec",
		"http://script.google.com/macros/s/x/exec",
		"https://script.google.com:444/macros/s/x/exec",
		"https://u:p@script.google.com/macros/s/x/exec",
	} {
		d := &frontDialer{target: "127.0.0.1:1"}
		if _, err := FetchAppsScript(context.Background(), u, d, time.Second, FrontOptions{}); err == nil {
			t.Fatalf("%s accepted", u)
		}
		if len(d.addrs) != 0 {
			t.Fatalf("%s dialled", u)
		}
	}
}

// A context that ends mid-attempt ends the fetch without a second
// connection.
func TestFetchAppsScript_CancelledContext(t *testing.T) {
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
			go func() { time.Sleep(3 * time.Second); c.Close() }()
		}
	}()
	d := &frontDialer{target: ln.Addr().String()}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	res, err := FetchAppsScript(ctx, testExecURL, d, 5*time.Second, FrontOptions{})
	if err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("err %v after %v", err, time.Since(start))
	}
	if res.Connections != 1 {
		t.Fatalf("connections %d", res.Connections)
	}
}

// FetchRaw no longer buffers without limit: the read under it stops
// one byte past the bound.
func TestReadBounded(t *testing.T) {
	if _, err := readBounded(endless{}, 1<<20); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("an endless stream: %v", err)
	}
	b, err := readBounded(bytes.NewReader(make([]byte, 1<<20)), 1<<20)
	if err != nil || len(b) != 1<<20 {
		t.Fatalf("exactly the bound: %v %d", err, len(b))
	}
}

type endless struct{}

func (endless) Read(p []byte) (int, error) { return len(p), nil }
