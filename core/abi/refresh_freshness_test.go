package abi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"daal/core/bootstrap"
	"daal/core/engine"
	"daal/core/refresh"
	"daal/core/routestore"
	"daal/core/scheduler"
)

// THE EVIDENCE THIS FILE PRODUCES.
//
// Wave 1 made refresh fail closed while a route is active; Wave 2 gave
// the process a loopback SOCKS5 inlet so a fetch can genuinely ride the
// tunnel. Step 8 adds a THIRD scheduled fetch kind, and the guard is
// not automatic on it — core/refresh's freshness entry point takes a
// caller-supplied dialer, so the wiring in refresh_freshness.go is
// where the guard is either honoured or silently lost.
//
// So these tests assert both halves against real sockets:
//
//   - with a live authenticated inlet, a freshness poll's bytes
//     traverse the inlet (proved by pointing it at a hostname that
//     cannot be resolved or dialled directly — success is only
//     possible through the proxy) and report ViaTunnel=true, which is
//     what the audit ledger shows the user;
//   - with no tunnel dialer installed and a route active, the poll does
//     not happen: zero connections anywhere, ErrTunnelRequired, and no
//     fall-through to the pointer-recovery layer.
//
// WHAT IS REAL AND WHAT IS STUBBED, stated exactly: the SOCKS5 server,
// its RFC 1929 authentication, the TCP connections, the origin server
// and the signed document are all real, and the dialer under test is
// the one ensureRelayPackRefresh builds for production. TLS is the one
// stubbed layer — the test's fetch function speaks plain HTTP/1.1 over
// the dialer-provided connection, because the raw-TLS fetcher pins the
// system trust store and a self-signed origin cannot be made to verify
// without weakening the fetcher itself. The property under test is
// which path the bytes take, and that is fully exercised.

// relayingSocks5Server is authSocks5Server's sibling: it completes the
// same authenticated handshake but then actually relays to a fixed
// backend, so a fetch through it can succeed end to end.
type relayingSocks5Server struct {
	ln      net.Listener
	backend string
	user    string
	pass    string

	mu       sync.Mutex
	connects int
	targets  []string
}

func newRelayingSocks5Server(t *testing.T, port int, user, pass, backend string) *relayingSocks5Server {
	t.Helper()
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("listen on the inlet's reserved port: %v", err)
	}
	s := &relayingSocks5Server{ln: ln, backend: backend, user: user, pass: pass}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	return s
}

func (s *relayingSocks5Server) serve(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))

	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil || hdr[0] != 0x05 {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	offered := false
	for _, m := range methods {
		if m == 0x02 {
			offered = true
		}
	}
	if !offered {
		_, _ = c.Write([]byte{0x05, 0xFF})
		return
	}
	if _, err := c.Write([]byte{0x05, 0x02}); err != nil {
		return
	}
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil || head[0] != 0x01 {
		return
	}
	user := make([]byte, int(head[1]))
	if _, err := io.ReadFull(c, user); err != nil {
		return
	}
	plen := make([]byte, 1)
	if _, err := io.ReadFull(c, plen); err != nil {
		return
	}
	pass := make([]byte, int(plen[0]))
	if _, err := io.ReadFull(c, pass); err != nil {
		return
	}
	if string(user) != s.user || string(pass) != s.pass {
		_, _ = c.Write([]byte{0x01, 0x01})
		return
	}
	if _, err := c.Write([]byte{0x01, 0x00}); err != nil {
		return
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	var target string
	switch req[3] {
	case 0x01:
		buf := make([]byte, 4+2)
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}
		target = net.IP(buf[:4]).String()
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return
		}
		buf := make([]byte, int(l[0])+2)
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}
		target = fmt.Sprintf("%s:%d", string(buf[:int(l[0])]),
			binary.BigEndian.Uint16(buf[int(l[0]):]))
	default:
		return
	}
	s.mu.Lock()
	s.connects++
	s.targets = append(s.targets, target)
	s.mu.Unlock()

	resp := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := c.Write(resp); err != nil {
		return
	}
	back, err := net.DialTimeout("tcp", s.backend, 3*time.Second)
	if err != nil {
		return
	}
	defer back.Close()
	_ = back.SetDeadline(time.Now().Add(5 * time.Second))
	go func() { _, _ = io.Copy(back, c) }()
	// Copy until the backend closes, then let the deferred Close on c
	// propagate EOF to the client. Waiting for the client→backend
	// direction to finish first would deadlock: the client is blocked
	// reading a response it can only get once we return.
	_, _ = io.Copy(c, back)
}

func (s *relayingSocks5Server) snapshot() (int, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connects, append([]string(nil), s.targets...)
}

// plainOrigin serves one fixed body over plain HTTP/1.1.
type plainOrigin struct {
	ln   net.Listener
	body []byte

	mu    sync.Mutex
	serve int
}

func newPlainOrigin(t *testing.T, body []byte) *plainOrigin {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	o := &plainOrigin{ln: ln, body: body}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				buf := make([]byte, 1024)
				_, _ = conn.Read(buf)
				o.mu.Lock()
				o.serve++
				o.mu.Unlock()
				fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(o.body))
				_, _ = conn.Write(o.body)
			}(c)
		}
	}()
	return o
}

func (o *plainOrigin) served() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.serve
}

// canonicalFreshnessDoc hand-builds the canonical signed document. It
// is written key-by-key in sorted order rather than through
// core/refresh's helper so that this test is an INDEPENDENT check of
// the canonical form: if the two ever disagree, the signature fails
// here rather than in the field.
func canonicalFreshnessDoc(t *testing.T, pub ed25519.PublicKey, priv ed25519.PrivateKey,
	packID, bundleSHA, signedURL string, seq uint64, now time.Time) []byte {
	t.Helper()
	q := func(s string) string {
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	body := "{" +
		`"current_bundle_sha256":` + q(bundleSHA) + "," +
		`"current_signed_url":` + q(signedURL) + "," +
		`"kind":"daal/freshness-v2",` +
		`"last_modified":` + q(now.UTC().Format(time.RFC3339)) + "," +
		`"mirrors":[],` +
		`"not_after":` + q(now.Add(72*time.Hour).UTC().Format(time.RFC3339)) + "," +
		`"pad":"",` +
		`"publisher_pub_hex":` + q(hex.EncodeToString(pub)) + "," +
		`"relay_pack_id":` + q(packID) + "," +
		fmt.Sprintf(`"sequence":%d`, seq) +
		"}"
	sig := ed25519.Sign(priv, []byte(body))
	full := body[:len(body)-1] + `,"signature_hex":` + q(hex.EncodeToString(sig)) + "}"
	return []byte(full)
}

// seedFreshnessPack pins a publisher and installs one RelayPack route
// whose freshness slot names two endpoints on distinct hosts, neither
// of which is resolvable — only the proxy can reach them.
func seedFreshnessPack(t *testing.T, endpoints []string) (ed25519.PublicKey, ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(pub)
	fp := hex.EncodeToString(sum[:])

	c := loadedCore()
	if c == nil {
		t.Fatal("engine not initialised")
	}
	if err := c.store.UpsertPublisher(routestore.PublisherRow{
		PublisherID: fp, DisplayName: "pubA", TrustLevel: "trusted",
		FirstSeen: "2026-08-17T00", LastSeenBundle: "2026-08-17T00", KeyStatus: "active",
	}); err != nil {
		t.Fatalf("pin publisher: %v", err)
	}
	if err := c.store.UpsertRoute(routestore.RouteRow{
		RouteID: "r-fresh", TransportFamily: "vless-reality", Engine: "sing-box",
		SourceType: "trusted_provider", PublisherID: fp, TrustState: "trusted",
		ScarcityClass: "normal", ExpiresAt: "2027-01-01T00:00:00Z",
		ImportedAt:   "2026-08-17T00:00:00Z",
		RelayPackID:  "rp-1",
		FreshnessURL: strings.Join(endpoints, " "),
	}); err != nil {
		t.Fatalf("upsert route: %v", err)
	}
	return pub, priv, fp
}

func TestFreshnessPollRidesTheAuthenticatedInlet(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })
	t.Cleanup(func() { refresh.SetTunnelRequired(false) })

	endpoints := []string{
		"https://freshness-a.invalid/f.json",
		"https://freshness-b.invalid/f.json",
	}
	pub, priv, _ := seedFreshnessPack(t, endpoints)

	now := time.Now().UTC()
	packSHA := strings.Repeat("de", 32)
	doc := canonicalFreshnessDoc(t, pub, priv, "rp-1", packSHA,
		"https://packs.invalid/current.sbp", 42, now)
	origin := newPlainOrigin(t, doc)

	// The device already believes this digest, so the poll takes the
	// unchanged path: one small request, no bundle fetch.
	c := loadedCore()
	rec, _ := json.Marshal(map[string]any{"v": 1, "current_bundle_sha256": packSHA})
	if err := c.store.PutSecret("freshness:rp-1", rec); err != nil {
		t.Fatal(err)
	}

	inlet := &engine.RefreshInlet{
		Host:     "127.0.0.1",
		Port:     freeLoopbackPort(t),
		Username: "u-fixture",
		Password: "p-fixture-128-bit",
	}
	srv := newRelayingSocks5Server(t, inlet.Port, inlet.Username, inlet.Password,
		origin.ln.Addr().String())
	t.Cleanup(engine.PublishRefreshInletForTest(inlet))

	// A route is active: Wave 1 forbids a direct fetch from here.
	refresh.SetTunnelRequired(true)
	if _, err := SetTunnelRefresh(true); err != nil {
		t.Fatalf("SetTunnelRefresh(true): %v", err)
	}

	rp, err := ensureRelayPackRefresh()
	if err != nil {
		t.Fatal(err)
	}
	rp.Fetch = plainHTTPFetch
	rp.PerURLTimeout = 3 * time.Second
	rp.TotalBudget = 6 * time.Second

	res, err := rp.Refresh(context.Background(), "rp-1")
	if err != nil {
		t.Fatalf("freshness poll through the inlet failed: %v (outcome %s)", err, res.Outcome)
	}
	if res.Outcome != "ok_unchanged" {
		t.Fatalf("outcome %q", res.Outcome)
	}
	if !res.ViaTunnel {
		t.Fatal("ViaTunnel=false: the audit trail would tell the user this fetch " +
			"rode the tunnel when it did not")
	}
	connects, targets := srv.snapshot()
	if connects != 1 {
		t.Fatalf("expected exactly one CONNECT through the inlet, got %d (%v)", connects, targets)
	}
	if !strings.HasSuffix(targets[0], ":443") || !strings.Contains(targets[0], ".invalid") {
		t.Fatalf("the proxy was asked for %q, not the freshness endpoint", targets[0])
	}
	if origin.served() != 1 {
		t.Fatalf("origin served %d requests", origin.served())
	}
	// The endpoint host does not resolve, so a direct dial could not
	// have produced this document: the bytes went through the inlet.

	// The audit row's via_tunnel flag is asserted in
	// core/refresh's own tests, where the store is a fake that can be
	// read back; routestore exposes no reader for refresh_audit, and
	// adding one here would be a schema-side change outside this
	// wave's scope.
}

func TestFreshnessPollRefusesWithNoInlet(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })
	t.Cleanup(func() { refresh.SetTunnelRequired(false) })

	endpoints := []string{
		"https://freshness-a.invalid/f.json",
		"https://freshness-b.invalid/f.json",
	}
	pub, priv, _ := seedFreshnessPack(t, endpoints)
	now := time.Now().UTC()
	doc := canonicalFreshnessDoc(t, pub, priv, "rp-1", strings.Repeat("de", 32),
		"https://packs.invalid/current.sbp", 42, now)
	origin := newPlainOrigin(t, doc)

	// No driver has published an inlet in this process.
	engine.PublishRefreshInletForTest(nil)
	refresh.SetTunnelRequired(true)

	rp, err := ensureRelayPackRefresh()
	if err != nil {
		t.Fatal(err)
	}
	rp.Fetch = plainHTTPFetch

	res, err := rp.Refresh(context.Background(), "rp-1")
	if err == nil {
		t.Fatal("the poll happened with no tunnel dialer installed")
	}
	if res.Outcome != "tunnel_required" {
		t.Fatalf("outcome %q, want tunnel_required", res.Outcome)
	}
	if origin.served() != 0 {
		t.Fatalf("the origin was contacted %d times — that is the leak", origin.served())
	}
	if res.ViaTunnel {
		t.Fatal("a refused fetch claimed to be tunnelled")
	}
}

// The scheduler must actually dispatch the kind on a real store: the
// planner, the source projection and the executor binding are three
// separate pieces and any one of them being wrong looks identical from
// the outside (nothing happens, forever).
func TestSchedulerPlansFreshnessForAnImportedPack(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	_, _, fp := seedFreshnessPack(t, []string{
		"https://freshness-a.invalid/f.json",
		"https://freshness-b.invalid/f.json",
	})

	c := loadedCore()
	src := storeSource{store: c.store, now: nowUTC}
	packs := src.RelayPacks()
	if len(packs) != 1 || packs[0].RelayPackID != "rp-1" {
		t.Fatalf("source did not surface the pack: %+v", packs)
	}
	due := scheduler.Plan(src, scheduler.DefaultCadence(), time.Now().UTC())
	found := false
	for _, a := range due {
		if a.Kind == scheduler.KindFreshness && a.Ref == "rp-1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("freshness was not planned: %+v", due)
	}

	// A pack with no freshness endpoint must NOT be scheduled — the
	// status screen would otherwise promise remote replacement to
	// recipients of a publisher who never enabled it.
	if err := c.store.UpsertRoute(routestore.RouteRow{
		RouteID: "r-nofresh", TransportFamily: "vless-reality", Engine: "sing-box",
		SourceType: "trusted_provider", PublisherID: fp, TrustState: "trusted",
		ScarcityClass: "normal", ExpiresAt: "2027-01-01T00:00:00Z",
		ImportedAt: "2026-08-17T00:00:00Z", RelayPackID: "rp-empty",
	}); err != nil {
		t.Fatal(err)
	}
	for _, p := range src.RelayPacks() {
		if p.RelayPackID == "rp-empty" {
			t.Fatal("a pack with no endpoint was scheduled")
		}
	}
}

// plainHTTPFetch speaks HTTP/1.1 over whatever dialer it is handed.
// Same request shape as bootstrap.FetchRaw (one-shot GET, Connection:
// close, no User-Agent) minus TLS.
func plainHTTPFetch(ctx context.Context, rawURL string, dialer bootstrap.Dialer,
	timeout time.Duration) ([]byte, error) {
	rest := strings.TrimPrefix(rawURL, "https://")
	host, path := rest, "/"
	if i := strings.Index(rest, "/"); i >= 0 {
		host, path = rest[:i], rest[i:]
	}
	addr := host
	if !strings.Contains(host, ":") {
		addr = host + ":443"
	}
	if dialer == nil {
		return nil, fmt.Errorf("no dialer")
	}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := dialer.DialContext(dctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, addr)
	raw, err := io.ReadAll(conn)
	if err != nil {
		return nil, err
	}
	idx := strings.Index(string(raw), "\r\n\r\n")
	if idx < 0 {
		return nil, fmt.Errorf("malformed response")
	}
	return raw[idx+4:], nil
}
