package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// writeFirstBootCert writes what cloud-init's `openssl req -x509` leaves
// on a relay: a self-signed P-256 leaf, CA:TRUE, one address and one DNS
// name (the cover host at provisioning), and its PKCS#8 key. The
// subject is v2.yaml.tmpl's: the cover host, or the address.
func writeFirstBootCert(t *testing.T, srv *server, coverHost string, ips ...string) *x509.Certificate {
	t.Helper()
	cn := coverHost
	if cn == "" && len(ips) > 0 {
		cn = ips[0]
	}
	return writeFirstBootCertNamed(t, srv, cn, coverHost, ips...)
}

// writeFirstBootCertNamed is writeFirstBootCert with the subject's CN
// given: "daal-relay" is what every relay provisioned before 2026-11-20
// carries.
func writeFirstBootCertNamed(t *testing.T, srv *server, commonName, coverHost string, ips ...string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	ski := sha256.Sum256(spki)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             srv.now().Add(-80 * 24 * time.Hour),
		NotAfter:              srv.now().Add(10 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          ski[:20],
		AuthorityKeyId:        ski[:20],
	}
	if coverHost != "" {
		tmpl.DNSNames = []string{coverHost}
	}
	for _, ip := range ips {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP(ip))
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	srv.tlsKeyPath = filepath.Join(filepath.Dir(srv.tlsCertPath), "tls-key.pem")
	if err := os.WriteFile(srv.tlsCertPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(srv.tlsKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func readCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("no certificate in " + path)
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func ipStrings(ips []net.IP) []string {
	var out []string
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

// TestRotateTLS_ReissuesTheCertificateForTheNewCoverHost is TW-11's box
// half. Before it, /rotate-tls moved REALITY's cover host and left the
// certificate naming the host the relay was provisioned with — so after
// a later address move naive verified, and presented, the name the
// operator had just rotated away from.
func TestRotateTLS_ReissuesTheCertificateForTheNewCoverHost(t *testing.T) {
	srv, _, priv, _ := newTestServer(t)
	srv.primaryIface = func() (string, error) { return "eth0", nil }
	srv.addrList = func(string) ([]net.IP, error) {
		return []net.IP{
			net.ParseIP("203.0.113.10"), // the primary address
			net.ParseIP("203.0.113.77"), // bound since first boot (/bind-address)
		}, nil
	}
	old := writeFirstBootCert(t, srv, "old-cover.example.org", "203.0.113.10")
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	resp := rotateTLS(t, ts, priv, `{"new_sni":"new-cover.example.net"}`, 200)
	if !contains(resp.Changed, "cover_sni") || !contains(resp.Changed, "tls_certificate") {
		t.Fatalf("changed = %v, want cover_sni and tls_certificate", resp.Changed)
	}
	if len(resp.Warnings) != 0 {
		t.Errorf("warnings = %v", resp.Warnings)
	}
	got := readCert(t, srv.tlsCertPath)

	// The key did not move: every pin in the field is still right.
	if !reflect.DeepEqual(got.RawSubjectPublicKeyInfo, old.RawSubjectPublicKeyInfo) {
		t.Fatal("the re-issued certificate has a different key: every pinned pack would die")
	}
	// The new cover host leads; the old one is still verifiable, for
	// the naive files already handed out.
	if want := []string{"new-cover.example.net", "old-cover.example.org"}; !reflect.DeepEqual(got.DNSNames, want) {
		t.Errorf("DNS names = %v, want %v", got.DNSNames, want)
	}
	// The addresses are the first-boot ones and nothing else: an address
	// bound since is not named (TestRotateTLS_ReissuedCertificateDoesNotNameALaterBoundAddress).
	if want := []string{"203.0.113.10"}; !reflect.DeepEqual(ipStrings(got.IPAddresses), want) {
		t.Errorf("addresses = %v, want %v", ipStrings(got.IPAddresses), want)
	}
	// A client that installed the OLD certificate as its root accepts
	// the new one: same subject, signed by the same key.
	if !reflect.DeepEqual(got.RawSubject, old.RawSubject) || !reflect.DeepEqual(got.RawIssuer, old.RawSubject) {
		t.Error("subject/issuer changed: the old certificate is no longer a valid issuer for the new one")
	}
	if err := got.CheckSignatureFrom(old); err != nil {
		t.Errorf("the new certificate does not chain to the old one: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(old)
	for _, name := range []string{"new-cover.example.net", "old-cover.example.org", "203.0.113.10"} {
		if _, err := got.Verify(x509.VerifyOptions{Roots: roots, DNSName: name, CurrentTime: srv.now()}); err != nil {
			t.Errorf("a client trusting the OLD certificate refuses the new one for %s: %v", name, err)
		}
	}
	// Chromium's ceiling for a locally trusted root.
	if life := got.NotAfter.Sub(got.NotBefore); life > 100*24*time.Hour || got.NotAfter.Sub(srv.now()) != dataPlaneCertValidity {
		t.Errorf("validity %s (until %s): want %s from now, under Chromium's 100-day ceiling", life, got.NotAfter, dataPlaneCertValidity)
	}
	if got.SerialNumber.Cmp(old.SerialNumber) == 0 {
		t.Error("serial number reused")
	}
	// The reply carries it, and it is what a recipient is handed next.
	if readCert(t, srv.tlsCertPath).SerialNumber.Cmp(certFromPEM(t, resp.TLSCertPEM).SerialNumber) != 0 {
		t.Error("tls_cert_pem in the reply is not the certificate on disk")
	}
	if srv.readTLSCertPEM() != resp.TLSCertPEM {
		t.Error("/users/provision would hand out a different certificate than the one just issued")
	}
	// The key file was not rewritten.
	if st, err := os.Stat(srv.tlsKeyPath); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("key file: %v %v", st, err)
	}

	// A second rotation keeps both earlier names, newest first.
	rotateTLS(t, ts, priv, `{"new_sni":"third-cover.example.com"}`, 200)
	if got, want := readCert(t, srv.tlsCertPath).DNSNames, []string{"third-cover.example.com", "new-cover.example.net", "old-cover.example.org"}; !reflect.DeepEqual(got, want) {
		t.Errorf("after a second rotation DNS names = %v, want %v", got, want)
	}
}

// TestRotateTLS_ReissuedCertificateDoesNotNameALaterBoundAddress: the
// data-plane certificate is served to any TLS client on every
// pinned-family port, with no credentials. The primary address is
// burned, the operator swaps onto a fresh one (the primary keeps
// answering), then changes the disguise. If the re-issued certificate
// named what the interface holds, a prober of the BURNED address would
// read the fresh one out of the handshake. Read here the way that prober
// does: off the wire, with no credentials.
func TestRotateTLS_ReissuedCertificateDoesNotNameALaterBoundAddress(t *testing.T) {
	const fresh = "198.51.100.99"
	srv, _, priv, _ := newTestServer(t)
	srv.primaryIface = func() (string, error) { return "eth0", nil }
	srv.addrList = func(string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("203.0.113.10"), net.ParseIP(fresh), net.ParseIP("2001:db8::99")}, nil
	}
	writeFirstBootCert(t, srv, "old-cover.example.org", "203.0.113.10")
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	resp := rotateTLS(t, ts, priv, `{"new_sni":"new-cover.example.net"}`, 200)
	if !contains(resp.Changed, "tls_certificate") {
		t.Fatalf("changed = %v: the certificate was not re-issued, so this proves nothing", resp.Changed)
	}

	// What sing-box serves: the file and its key, to anybody.
	pair, err := tls.LoadX509KeyPair(srv.tlsCertPath, srv.tlsKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}})
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
			go func() { _ = c.(*tls.Conn).Handshake(); c.Close() }()
		}
	}()
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true}) // a prober verifies nothing
	if err != nil {
		t.Fatal(err)
	}
	served := conn.ConnectionState().PeerCertificates[0]
	conn.Close()

	if got, want := ipStrings(served.IPAddresses), []string{"203.0.113.10"}; !reflect.DeepEqual(got, want) {
		t.Errorf("an unauthenticated TLS client reads the addresses %v from the certificate; want only the first-boot %v — %s was bound later, to get away from a burned address", got, want, fresh)
	}
	for _, c := range []*x509.Certificate{served, certFromPEM(t, resp.TLSCertPEM)} {
		for _, ip := range c.IPAddresses {
			if ip.Equal(net.ParseIP(fresh)) || ip.Equal(net.ParseIP("2001:db8::99")) {
				t.Errorf("the certificate names %s, an address the relay was given after first boot", ip)
			}
		}
	}
	// A second rotation does not let it in either.
	rotateTLS(t, ts, priv, `{"new_sni":"third-cover.example.com"}`, 200)
	if got, want := ipStrings(readCert(t, srv.tlsCertPath).IPAddresses), []string{"203.0.113.10"}; !reflect.DeepEqual(got, want) {
		t.Errorf("after a second rotation the certificate names %v, want %v", got, want)
	}
}

func certFromPEM(t *testing.T, pemText string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		t.Fatal("no certificate in the reply")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestRotateTLS_WSPathOnlyLeavesTheCertificateAlone: the certificate
// follows the COVER HOST. A rotation that moves only the ws path, and a
// request naming the host the certificate already leads with, issue
// nothing.
func TestRotateTLS_WSPathOnlyLeavesTheCertificateAlone(t *testing.T) {
	srv, _, priv, _ := newTestServer(t)
	writeFirstBootCert(t, srv, "old-cover.example.org", "203.0.113.10")
	before, _ := os.ReadFile(srv.tlsCertPath)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	resp := rotateTLS(t, ts, priv, `{"new_ws_path":"/r/abcdef12"}`, 200)
	if contains(resp.Changed, "tls_certificate") || resp.TLSCertPEM != "" {
		t.Errorf("a ws-path rotation re-issued the certificate: %v", resp.Changed)
	}
	if after, _ := os.ReadFile(srv.tlsCertPath); string(after) != string(before) {
		t.Error("the certificate file changed")
	}
}

// TestRotateTLS_FailedReloadPutsTheOldCertificateBack: the certificate
// is replaced before the reload that applies the rotation, so a failed
// reload must restore it together with the config — otherwise the
// publisher's "nothing was applied" is false for naive.
func TestRotateTLS_FailedReloadPutsTheOldCertificateBack(t *testing.T) {
	srv, _, priv, configPath := newTestServer(t)
	writeFirstBootCert(t, srv, "old-cover.example.org", "203.0.113.10")
	certBefore, _ := os.ReadFile(srv.tlsCertPath)
	cfgBefore, _ := os.ReadFile(configPath)
	var seen []string
	srv.singboxControl = func(string) error {
		// What sing-box would have loaded on the first (failing) reload.
		seen = append(seen, strings.Join(readCert(t, srv.tlsCertPath).DNSNames, ","))
		if len(seen) == 1 {
			return errors.New("systemd said no")
		}
		return nil
	}
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	rotateTLS(t, ts, priv, `{"new_sni":"new-cover.example.net"}`, 500)
	if len(seen) != 2 || seen[0] != "new-cover.example.net,old-cover.example.org" || seen[1] != "old-cover.example.org" {
		t.Errorf("certificate at each reload = %v; want the new one at the failing reload and the old one at the recovery reload", seen)
	}
	if after, _ := os.ReadFile(srv.tlsCertPath); string(after) != string(certBefore) {
		t.Error("the re-issued certificate was left on disk after a rotation that was rolled back")
	}
	if after, _ := os.ReadFile(configPath); string(after) != string(cfgBefore) {
		t.Error("config not rolled back")
	}
}

// TestRotateTLS_CertificateTroubleDoesNotStopTheRotation: L2 is the
// answer to a filtered cover host. A relay whose certificate cannot be
// re-issued still moves its cover host, says so, and keeps the
// certificate it had; a relay with no data-plane certificate at all
// says nothing.
func TestRotateTLS_CertificateTroubleDoesNotStopTheRotation(t *testing.T) {
	t.Run("key file is not the certificate's key", func(t *testing.T) {
		srv, _, priv, _ := newTestServer(t)
		writeFirstBootCert(t, srv, "old-cover.example.org", "203.0.113.10")
		other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		der, _ := x509.MarshalPKCS8PrivateKey(other)
		_ = os.WriteFile(srv.tlsKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
		before, _ := os.ReadFile(srv.tlsCertPath)
		ts := httptest.NewServer(srv.routes())
		defer ts.Close()

		resp := rotateTLS(t, ts, priv, `{"new_sni":"new-cover.example.net"}`, 200)
		if !contains(resp.Changed, "cover_sni") || contains(resp.Changed, "tls_certificate") {
			t.Errorf("changed = %v, want the cover host to move and the certificate not to", resp.Changed)
		}
		if len(resp.Warnings) != 1 || !strings.Contains(resp.Warnings[0], "could not be re-issued") {
			t.Errorf("warnings = %v, want one saying the certificate was not re-issued", resp.Warnings)
		}
		if after, _ := os.ReadFile(srv.tlsCertPath); string(after) != string(before) {
			t.Error("a certificate was issued under a key that is not the pinned one")
		}
	})
	t.Run("no data-plane certificate", func(t *testing.T) {
		srv, _, priv, _ := newTestServer(t)
		ts := httptest.NewServer(srv.routes())
		defer ts.Close()
		resp := rotateTLS(t, ts, priv, `{"new_sni":"new-cover.example.net"}`, 200)
		if len(resp.Warnings) != 0 || contains(resp.Changed, "tls_certificate") {
			t.Errorf("changed = %v warnings = %v", resp.Changed, resp.Warnings)
		}
	})
}

// TestReissuedCertTemplate_BoundsTheNameHistory: one name per rotation,
// newest first, capped.
func TestReissuedCertTemplate_BoundsTheNameHistory(t *testing.T) {
	old := &x509.Certificate{}
	for i := 0; i < maxCertDNSNames+3; i++ {
		old.DNSNames = append(old.DNSNames, "h"+string(rune('a'+i))+".example.org")
	}
	got := reissuedCertTemplate(old, "new.example.net", big.NewInt(1), time.Unix(1700000000, 0))
	if len(got.DNSNames) != maxCertDNSNames || got.DNSNames[0] != "new.example.net" || got.DNSNames[1] != "ha.example.org" {
		t.Errorf("names = %v", got.DNSNames)
	}
	// Rotating BACK to a name already in the certificate moves it to
	// the front without repeating it.
	got = reissuedCertTemplate(&x509.Certificate{DNSNames: []string{"b.example.org", "a.example.org"}}, "a.example.org", big.NewInt(1), time.Unix(1700000000, 0))
	if want := []string{"a.example.org", "b.example.org"}; !reflect.DeepEqual(got.DNSNames, want) {
		t.Errorf("names = %v, want %v", got.DNSNames, want)
	}
}

// TestParseDataPlaneKey_ReadsBothOpenSSLSpellings: OpenSSL 3 writes
// PKCS#8, OpenSSL 1.1 wrote SEC1.
func TestParseDataPlaneKey_ReadsBothOpenSSLSpellings(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p8, _ := x509.MarshalPKCS8PrivateKey(key)
	sec1, _ := x509.MarshalECPrivateKey(key)
	for typ, der := range map[string][]byte{"PRIVATE KEY": p8, "EC PRIVATE KEY": sec1} {
		got, err := parseDataPlaneKey(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}))
		if err != nil || !samePublicKey(got.Public(), &key.PublicKey) {
			t.Errorf("%s: %v", typ, err)
		}
	}
	if _, err := parseDataPlaneKey([]byte("not pem")); err == nil {
		t.Error("garbage parsed as a key")
	}
}

// servedCert is what a stranger reads: it opens a TLS connection to
// whatever serves the relay's certificate file and verifies nothing.
func servedCert(t *testing.T, srv *server) *x509.Certificate {
	t.Helper()
	pair, err := tls.LoadX509KeyPair(srv.tlsCertPath, srv.tlsKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_ = c.(*tls.Conn).Handshake()
		c.Close()
	}()
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates[0]
}

// namesTheApp is the prober's test: does anything a stranger reads in
// the certificate's subject or issuer say "daal"?
func namesTheApp(c *x509.Certificate) bool {
	return strings.Contains(strings.ToLower(c.Subject.String()+" "+c.Issuer.String()), "daal")
}

// TestRotateTLS_RetiresALegacySubjectThatNamesTheApp is review C1's box
// half. Every relay provisioned before 2026-11-20 serves CN=daal-relay
// to anybody who completes a handshake on 8444, 8445 or 443/udp. The
// first re-issue replaces it with the neutral subject cloud-init now
// writes, on the same key, and says out loud what that costs: naive
// packs minted before it trusted a root found by the old name.
func TestRotateTLS_RetiresALegacySubjectThatNamesTheApp(t *testing.T) {
	srv, _, priv, _ := newTestServer(t)
	old := writeFirstBootCertNamed(t, srv, "daal-relay", "old-cover.example.org", "203.0.113.10")
	if !namesTheApp(servedCert(t, srv)) {
		t.Fatal("fixture: the legacy certificate does not name the app, so this proves nothing")
	}
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	resp := rotateTLS(t, ts, priv, `{"new_sni":"new-cover.example.net"}`, 200)
	for _, want := range []string{"cover_sni", "tls_certificate", "tls_certificate_subject"} {
		if !contains(resp.Changed, want) {
			t.Errorf("changed = %v, want %s", resp.Changed, want)
		}
	}
	if len(resp.Warnings) != 1 || !strings.Contains(resp.Warnings[0], "naive") || strings.Contains(strings.ToLower(resp.Warnings[0]), "daal") {
		t.Errorf("warnings = %v, want one that tells the operator naive links must be re-sent", resp.Warnings)
	}

	served := servedCert(t, srv)
	if namesTheApp(served) {
		t.Errorf("a stranger still reads subject %q issuer %q", served.Subject, served.Issuer)
	}
	if got, want := served.Subject.String(), "CN=new-cover.example.net"; got != want {
		t.Errorf("subject = %q, want %q (the certificate's own first name)", got, want)
	}
	if !reflect.DeepEqual(served.RawIssuer, served.RawSubject) {
		t.Error("the re-issued certificate is not self-signed")
	}
	if err := served.CheckSignatureFrom(served); err != nil {
		t.Errorf("self-signature: %v", err)
	}
	// What must not move did not.
	if !reflect.DeepEqual(served.RawSubjectPublicKeyInfo, old.RawSubjectPublicKeyInfo) {
		t.Fatal("the key moved: every pinned pack would die")
	}
	if want := []string{"new-cover.example.net", "old-cover.example.org"}; !reflect.DeepEqual(served.DNSNames, want) {
		t.Errorf("DNS names = %v, want %v", served.DNSNames, want)
	}
	if want := []string{"203.0.113.10"}; !reflect.DeepEqual(ipStrings(served.IPAddresses), want) {
		t.Errorf("addresses = %v, want %v", ipStrings(served.IPAddresses), want)
	}
	// A pack minted from now on installs the new certificate and
	// verifies by it.
	roots := x509.NewCertPool()
	roots.AddCert(certFromPEM(t, resp.TLSCertPEM))
	if _, err := served.Verify(x509.VerifyOptions{Roots: roots, DNSName: "203.0.113.10", CurrentTime: srv.now()}); err != nil {
		t.Errorf("a pack holding the new certificate refuses it: %v", err)
	}
	// The price, asserted so nobody mistakes it for free: a pack that
	// trusts the OLD certificate no longer chains.
	oldRoots := x509.NewCertPool()
	oldRoots.AddCert(old)
	if _, err := served.Verify(x509.VerifyOptions{Roots: oldRoots, DNSName: "203.0.113.10", CurrentTime: srv.now()}); err == nil {
		t.Error("a pack trusting the legacy certificate still accepts the renamed one; the warning would be false")
	}

	// Once neutral, it stays: the next rotation copies the subject and
	// says nothing about naive.
	resp = rotateTLS(t, ts, priv, `{"new_sni":"third-cover.example.com"}`, 200)
	if contains(resp.Changed, "tls_certificate_subject") || len(resp.Warnings) != 0 {
		t.Errorf("second rotation: changed = %v warnings = %v", resp.Changed, resp.Warnings)
	}
	if got := readCert(t, srv.tlsCertPath); !reflect.DeepEqual(got.RawSubject, served.RawSubject) {
		t.Errorf("second rotation moved the subject to %q", got.Subject)
	}
}

// TestNeutralCommonName: the certificate's first usable name, then its
// first address, never empty, never past X.509's 64-character bound.
func TestNeutralCommonName(t *testing.T) {
	long := strings.Repeat("a", 60) + ".example.org"
	for _, c := range []struct {
		dns  []string
		ips  []string
		want string
	}{
		{[]string{"cover.example.org", "old.example.net"}, []string{"203.0.113.10"}, "cover.example.org"},
		{[]string{long, "short.example.net"}, []string{"203.0.113.10"}, "short.example.net"},
		{[]string{long}, []string{"203.0.113.10", "2001:db8::1"}, "203.0.113.10"},
		{nil, []string{"2001:db8::1"}, "2001:db8::1"},
		{nil, nil, "localhost"},
	} {
		var ips []net.IP
		for _, ip := range c.ips {
			ips = append(ips, net.ParseIP(ip))
		}
		if got := neutralCommonName(c.dns, ips); got != c.want {
			t.Errorf("neutralCommonName(%v, %v) = %q, want %q", c.dns, c.ips, got, c.want)
		}
	}
}

// TestEnsureSelfSignedCert_NamesNothing: the management certificate is
// pinned by digest, so its name is read only by a stranger.
func TestEnsureSelfSignedCert_NamesNothing(t *testing.T) {
	dir := t.TempDir()
	pair, err := ensureSelfSignedCert(filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem"), filepath.Join(dir, "fp"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if namesTheApp(c) {
		t.Errorf("management certificate subject %q issuer %q names the app", c.Subject, c.Issuer)
	}
}

// TestRotateTLS_ACoverHostThatContainsTheLettersIsNotRenamed: the
// neutral CN is the cover host, and a cover host such as
// edaalat.example has "daal" in it. Renaming it would end every naive
// pack for nothing, on every rotation whose cover host also matched.
func TestRotateTLS_ACoverHostThatContainsTheLettersIsNotRenamed(t *testing.T) {
	srv, _, priv, _ := newTestServer(t)
	old := writeFirstBootCertNamed(t, srv, "edaalat.example", "edaalat.example", "203.0.113.10")
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	resp := rotateTLS(t, ts, priv, `{"new_sni":"daal-news.example.net"}`, 200)
	if contains(resp.Changed, "tls_certificate_subject") || len(resp.Warnings) != 0 {
		t.Errorf("changed = %v warnings = %v; a neutral subject was renamed", resp.Changed, resp.Warnings)
	}
	if got := readCert(t, srv.tlsCertPath); !reflect.DeepEqual(got.RawSubject, old.RawSubject) {
		t.Errorf("subject moved from %q to %q", old.Subject, got.Subject)
	}
}

// TestSubjectNamesTheApp_ExactLegacySubjectOnly, including the
// UTF8String encoding openssl's -subj writes (Go's encoder would pick
// PrintableString, so a RawSubject comparison would miss it).
func TestSubjectNamesTheApp_ExactLegacySubjectOnly(t *testing.T) {
	cn := asn1.ObjectIdentifier{2, 5, 4, 3}
	o := asn1.ObjectIdentifier{2, 5, 4, 10}
	utf8Subject := func(atvs ...[2]any) []byte {
		var rdns []asn1.RawValue
		for _, a := range atvs {
			v, _ := asn1.MarshalWithParams(a[1], "utf8")
			atv, err := asn1.Marshal(struct {
				Type  asn1.ObjectIdentifier
				Value asn1.RawValue
			}{a[0].(asn1.ObjectIdentifier), asn1.RawValue{FullBytes: v}})
			if err != nil {
				t.Fatal(err)
			}
			// One RDN: a SET holding the one attribute.
			rdns = append(rdns, asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: atv})
		}
		der, err := asn1.Marshal(rdns)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	for _, c := range []struct {
		name string
		raw  []byte
		want bool
	}{
		{"openssl CN=daal-relay", utf8Subject([2]any{cn, "daal-relay"}), true},
		{"cover host with the letters", utf8Subject([2]any{cn, "edaalat.example"}), false},
		{"a longer CN", utf8Subject([2]any{cn, "daal-relay-2"}), false},
		{"CN plus an O", utf8Subject([2]any{cn, "daal-relay"}, [2]any{o, "x"}), false},
		{"only an O", utf8Subject([2]any{o, "daal-relay"}), false},
	} {
		var rdn pkix.RDNSequence
		if _, err := asn1.Unmarshal(c.raw, &rdn); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		var cert x509.Certificate
		cert.Subject.FillFromRDNSequence(&rdn)
		if got := subjectNamesTheApp(&cert); got != c.want {
			t.Errorf("%s: subjectNamesTheApp = %v, want %v", c.name, got, c.want)
		}
	}
	// The Go-encoded legacy subject (the fixture above) too.
	if !subjectNamesTheApp(&x509.Certificate{Subject: pkix.Name{Names: []pkix.AttributeTypeAndValue{{Type: cn, Value: "daal-relay"}}}}) {
		t.Error("Go-encoded legacy subject not recognised")
	}
}
