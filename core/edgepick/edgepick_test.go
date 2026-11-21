package edgepick

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func seeds(t *testing.T, ss ...string) []netip.Prefix {
	t.Helper()
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func TestCandidatesStayInsideTheSeedsAndAreStable(t *testing.T) {
	sd := seeds(t, "104.16.0.0/13", "172.64.0.0/13", "2606:4700::/32", "198.51.100.7/32")
	a := Candidates(sd, "net-a|r9", 12)
	b := Candidates(sd, "net-a|r9", 12)
	if len(a) != 12 {
		t.Fatalf("got %d candidates", len(a))
	}
	seen := map[netip.Addr]bool{}
	for i, x := range a {
		if x != b[i] {
			t.Fatal("candidates are not deterministic")
		}
		if seen[x] {
			t.Fatalf("repeated %v", x)
		}
		seen[x] = true
		if !inSeeds(sd, x) {
			t.Fatalf("%v is outside the seeds", x)
		}
		if x.Is4() && (x.As4()[3] == 0 || x.As4()[3] == 255) {
			t.Fatalf("%v is a network or broadcast-looking address", x)
		}
	}
	// Round-robin: the first four come from four different seeds.
	for i := 0; i < 4; i++ {
		if !sd[i].Contains(a[i]) {
			t.Fatalf("candidate %d (%v) is not from seed %d", i, a[i], i)
		}
	}
	// Another network gets other addresses.
	c := Candidates(sd, "net-b|r9", 12)
	same := 0
	for i := range c {
		if c[i] == a[i] {
			same++
		}
	}
	if same > 2 { // the /32 seed is the same on every network
		t.Fatalf("two networks share %d of 12 candidates", same)
	}
}

type fakeProber struct {
	ok    map[netip.Addr]bool
	calls []netip.Addr
}

func (f *fakeProber) Probe(_ context.Context, ap netip.AddrPort) error {
	f.calls = append(f.calls, ap.Addr())
	if f.ok[ap.Addr()] {
		return nil
	}
	return errors.New("cut")
}

func TestPickProbesOnlyInTheFailureStateAndRemembers(t *testing.T) {
	sd := seeds(t, "104.16.0.0/13", "172.64.0.0/13")
	now := time.Unix(1_800_000_000, 0)
	cands := Candidates(sd, "s", 8)
	failed := cands[0]
	pr := &fakeProber{ok: map[netip.Addr]bool{cands[2]: true}}
	mem := Unmarshal(nil)
	res, err := Pick(context.Background(), PickInput{Seeds: sd, Port: 443, Salt: "s", Failed: failed, Mem: mem, Prober: pr, Now: now})
	if err != nil || !res.OK || res.Addr != cands[2] || res.Probed != 2 {
		t.Fatalf("res=%+v err=%v calls=%v", res, err, pr.calls)
	}
	for _, c := range pr.calls {
		if c == failed {
			t.Fatal("the address that just failed was probed again")
		}
	}
	if !mem.Bad(failed, now) || !mem.Bad(cands[1], now) {
		t.Fatal("failures were not remembered")
	}
	// The pass is remembered: the next Pick takes it without a probe.
	pr.calls = nil
	res, err = Pick(context.Background(), PickInput{Seeds: sd, Port: 443, Salt: "s", Mem: Unmarshal(mem.Marshal()), Prober: pr, Now: now.Add(time.Hour)})
	if err != nil || !res.FromMemory || res.Addr != cands[2] || len(pr.calls) != 0 {
		t.Fatalf("res=%+v calls=%v", res, pr.calls)
	}
	// A remembered pass outside the route's seeds is not used.
	if _, ok := mem.GoodIn(seeds(t, "198.51.100.0/24"), now); ok {
		t.Fatal("a pass outside the seeds was offered")
	}
	// A failure keeps an address out for BadFor, then it may be tried.
	if mem.Bad(cands[1], now.Add(BadFor)) {
		t.Fatal("a failure outlived BadFor")
	}
}

func TestPickIsBounded(t *testing.T) {
	sd := seeds(t, "104.16.0.0/13")
	pr := &fakeProber{}
	res, err := Pick(context.Background(), PickInput{Seeds: sd, Port: 443, Salt: "s", Prober: pr, MaxProbes: 2, Now: time.Unix(1, 0)})
	if !errors.Is(err, ErrNoCandidate) || res.Probed != 2 || len(pr.calls) != 2 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	mem := Unmarshal(nil)
	for i := 0; i < 3*MaxRecords; i++ {
		mem.Note(netip.AddrFrom4([4]byte{104, 16, byte(i / 200), byte(1 + i%200)}), false, time.Unix(int64(i), 0))
	}
	if len(mem.Edges) != MaxRecords {
		t.Fatalf("memory holds %d records", len(mem.Edges))
	}
}

// ---- the real exchange, against a local TLS server ----

func testCert(t *testing.T, name string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(c)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, pool
}

// serve answers `answers` requests on each connection, then closes it.
func serve(t *testing.T, cert tls.Certificate, answers int, chunked bool) netip.AddrPort {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for i := 0; i < answers; i++ {
					for {
						line, err := br.ReadString('\n')
						if err != nil {
							return
						}
						if strings.TrimSpace(line) == "" {
							break
						}
					}
					if chunked {
						c.Write([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nfl=ok\r\n0\r\n\r\n"))
					} else {
						c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfl=ok"))
					}
				}
			}(c)
		}
	}()
	return netip.MustParseAddrPort(ln.Addr().String())
}

func dialer(ctx context.Context, to netip.AddrPort) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", to.String())
}

func TestExchangeNeedsTheWholeExchange(t *testing.T) {
	cert, pool := testCert(t, NeutralName)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	e := Exchange{Dial: dialer, Roots: pool}
	if err := e.Probe(ctx, serve(t, cert, ExchangeRounds, false)); err != nil {
		t.Fatalf("a clean edge failed the probe: %v", err)
	}
	if err := e.Probe(ctx, serve(t, cert, ExchangeRounds, true)); err != nil {
		t.Fatalf("a chunked answer failed the probe: %v", err)
	}
	// An address that lets the handshake and one answer through and
	// then cuts the connection is not clean.
	if err := e.Probe(ctx, serve(t, cert, 1, false)); !errors.Is(err, ErrShortExchange) {
		t.Fatalf("a cut-after-a-few-packets edge passed: %v", err)
	}
	// An edge that does not prove itself with the roots is not clean.
	_, other := testCert(t, NeutralName)
	if err := (Exchange{Dial: dialer, Roots: other}).Probe(ctx, serve(t, cert, ExchangeRounds, false)); err == nil {
		t.Fatal("an unverified edge passed")
	}
}
