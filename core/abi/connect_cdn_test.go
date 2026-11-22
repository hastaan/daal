package abi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/netip"
	"strings"
	"testing"
	"time"

	"daal/bundle-go/bundle"
	"daal/core/edgepick"
	"daal/core/trust"
)

// The way in through Cloudflare on the recipient (connect_cdn.go).

const cdnTestECH = "AAT+DQAA" // a 2-byte length (4) and four bytes

type cdnFixture struct {
	ep      *bundle.CDNEndpoint
	profile string
}

// newCDNFixture is a CDN-fronted commitment and an outbound that agrees
// with it: one root (made here) inline, ECH on, the first edge address.
func newCDNFixture(t *testing.T) cdnFixture { return newCDNFixtureOpts(t, cdnTestECH, false) }

func newCDNFixtureOpts(t *testing.T, ech string, plain bool) cdnFixture {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "edge root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	ep := &bundle.CDNEndpoint{
		V: bundle.CDNEndpointVersion, Server: "w7.example.com", Port: 443, ServerName: "w7.example.com",
		CDN: bundle.CDNCloudflare, EdgeSeeds: []string{"104.16.0.0/13"}, ECHConfig: ech,
		TLSRootsSHA256: []string{base64.StdEncoding.EncodeToString(sum[:])}, PlainFallback: plain,
	}
	tls := map[string]any{
		"enabled": true, "server_name": ep.ServerName,
		"certificate": []string{strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))},
	}
	if ech != "" {
		tls["ech"] = map[string]any{"enabled": true, "config": ep.ECHConfigPEM()}
	}
	ob := map[string]any{
		"type": "vless", "server": ep.FirstEdgeAddress(), "server_port": 443, "uuid": "u",
		"transport": map[string]any{"type": "ws", "path": "/p", "headers": map[string]any{"Host": ep.ServerName}},
		"tls":       tls,
	}
	b, _ := json.Marshal(ob)
	if err := bundle.CheckCDNOutbound(ep, b); err != nil {
		t.Fatalf("fixture outbound: %v", err)
	}
	return cdnFixture{ep: ep, profile: string(b)}
}

// store keeps the CDN commitment as the route's (what an import of a
// CDN-fronted route leaves).
func (f cdnFixture) store(t *testing.T, c *Core, id string) {
	t.Helper()
	b, _ := json.Marshal(f.ep)
	if err := c.store.PutSecret(trust.RouteEndpointKey(id), b); err != nil {
		t.Fatal(err)
	}
}

func cdnRoute(t *testing.T, c *Core, id string) ladderRoute {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	lr, ok := c.ladderRouteByID(id)
	if !ok {
		t.Fatal("no route")
	}
	return lr
}

// The hello order (B-6b): ECH as stored, then ECH with the outer hello
// split, then stop — a plain hello only with the signed flag, and every
// one of them held to the commitment by the guard.
func TestCDN_HelloOrderAndThePlainFallbackRule(t *testing.T) {
	strict := newCDNFixture(t)
	plain := newCDNFixtureOpts(t, cdnTestECH, true)
	rig := newAutoRig(t, [][3]string{
		{"c1", "websocket-tls", strict.profile},
		{"c2", "websocket-tls", plain.profile},
	})
	packRoute(t, rig.c, "c1", "p1")
	packRoute(t, rig.c, "c2", "p1")
	strict.store(t, rig.c, "c1")
	plain.store(t, rig.c, "c2")

	lr := cdnRoute(t, rig.c, "c1")
	if lr.cdn == nil || !lr.ech || len(lr.names) != 0 {
		t.Fatalf("not read as a CDN-fronted route: %+v", lr)
	}
	if got := ladderList(lr); len(got) != 1 || got[0].hello != helloSplit {
		t.Fatalf("ladder without plain_fallback: %v", got)
	}
	if got := ladderList(cdnRoute(t, rig.c, "c2")); len(got) != 2 || got[1].hello != helloPlain {
		t.Fatalf("ladder with plain_fallback: %v", got)
	}
	build := func(id string, v routeVariant) (map[string]any, error) {
		rig.c.mu.Lock()
		defer rig.c.mu.Unlock()
		_, body, err := rig.c.prepareRouteVariant(id, false, false, &v)
		if err != nil {
			return nil, err
		}
		var cfg struct {
			Outbounds []map[string]any `json:"outbounds"`
		}
		_ = json.Unmarshal(body, &cfg)
		for _, ob := range cfg.Outbounds {
			if ob["tag"] == "active" {
				return ob["tls"].(map[string]any), nil
			}
		}
		return nil, nil
	}
	tls, err := build("c1", routeVariant{hello: helloSplit})
	if err != nil || tls["record_fragment"] != true || tls["fragment"] != true || tls["ech"] == nil {
		t.Fatalf("split: %v %v", tls, err)
	}
	if _, err := build("c1", routeVariant{hello: helloPlain}); err == nil {
		t.Fatal("a plain hello was built without the signed plain_fallback")
	}
	if tls, err := build("c2", routeVariant{hello: helloPlain}); err != nil || tls["ech"] != nil {
		t.Fatalf("plain with the flag: %v %v", tls, err)
	}
	// A CDN-fronted route is never offered desync presets or the
	// standby.
	for _, v := range ladderList(lr) {
		if v.preset != "" || v.name != 0 {
			t.Fatal("a preset or a name in a CDN route's ladder")
		}
	}
	if _, err := build("c1", routeVariant{standby: true}); err == nil {
		t.Fatal("a CDN-fronted route was given a standby")
	}
}

// The way in through Cloudflare goes after every direct route; the
// route that carried here last is the one exception.
func TestCDN_TriedLast(t *testing.T) {
	cands := []autoCandidate{
		{routeID: "c", cdn: true, why: AutoWhyRanked},
		{routeID: "a", why: AutoWhyRanked},
		{routeID: "b", why: AutoWhyFailedHere},
	}
	got := []string{}
	for _, cd := range cdnLast(cands) {
		got = append(got, cd.routeID)
	}
	if strings.Join(got, ",") != "a,b,c" {
		t.Fatalf("order %v", got)
	}
	cands[0].why = AutoWhyCarriedHere
	got = got[:0]
	for _, cd := range cdnLast(cands) {
		got = append(got, cd.routeID)
	}
	if strings.Join(got, ",") != "c,a,b" {
		t.Fatalf("the route that carried here last was moved: %v", got)
	}
}

// edgeProber stands in for the network: addresses in ok carry.
type edgeProber struct {
	ok    map[netip.Addr]bool
	calls int
}

func (p *edgeProber) Probe(_ context.Context, ap netip.AddrPort) error {
	p.calls++
	if p.ok[ap.Addr()] {
		return nil
	}
	return edgepick.ErrShortExchange
}

// B-6: the edge the route dials stops answering; the pass makes one
// fresh pick inside the signed seeds, dials the address that passed,
// and remembers it for the network. The direct route went first.
func TestCDN_EdgeStopsAnsweringAndThePassPicksAnother(t *testing.T) {
	f := newCDNFixture(t)
	rig := newStandbyRig(t, [][3]string{
		{"r1", "vless-reality", sbPrimaryREALITY},
		{"c1", "websocket-tls", f.profile},
	})
	packRoute(t, rig.c, "r1", "p1")
	packRoute(t, rig.c, "c1", "p1")
	f.store(t, rig.c, "c1")

	cands := edgepick.Candidates(f.ep.EdgeSeedPrefixes(), cdnPickSalt("c1"), 4)
	good := cands[1]
	pr := &edgeProber{ok: map[netip.Addr]bool{good: true}}
	prev := cdnProber
	cdnProber = func(*Core, *x509.CertPool) edgepick.Prober { return pr }
	t.Cleanup(func() { cdnProber = prev })
	rig.alive[good.String()] = true

	res := rig.connectAuto()
	if !res.Connected || res.RouteID != "c1" {
		t.Fatalf("got %+v (started %v)", res, rig.started)
	}
	if got := variants(res.Tried); !eq(got, []string{"r1//not_carrying", "c1//not_carrying", "c1//carried"}) {
		t.Fatalf("tried %v (started %v)", got, rig.started)
	}
	if last := rig.started[len(rig.started)-1]; last != "c1@"+good.String() {
		t.Fatalf("the fresh pick was not what was dialled: %v", rig.started)
	}
	if pr.calls == 0 || pr.calls > edgepick.DefaultMaxProbes {
		t.Fatalf("%d probes", pr.calls)
	}
	// Remembered: the next pass dials it at once, with no probe.
	pr.calls = 0
	_ = ClearRoute()
	res = rig.connectAuto()
	if !res.Connected || res.RouteID != "c1" || pr.calls != 0 {
		t.Fatalf("second pass: %+v probes=%d", res, pr.calls)
	}
	if last := rig.started[len(rig.started)-1]; last != "c1@"+good.String() {
		t.Fatalf("the remembered edge was not used: %v", rig.started)
	}
}

// An edge address outside the signed seeds is never dialled, whatever
// the memory says: the guard holds the moved outbound to the seeds.
func TestCDN_EdgeMemoryCannotLeaveTheSeeds(t *testing.T) {
	f := newCDNFixture(t)
	rig := newAutoRig(t, [][3]string{{"c1", "websocket-tls", f.profile}})
	packRoute(t, rig.c, "c1", "p1")
	f.store(t, rig.c, "c1")
	c := rig.c
	c.mu.Lock()
	m := c.cdnEdgeMemLocked()
	m.Note(netip.MustParseAddr("198.51.100.99"), true, nowUTC())
	c.cdnEdgeSaveLocked(m)
	_, body, err := c.prepareRouteVariant("c1", false, false, nil)
	c.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if s := activeServer(t, body); s != f.ep.FirstEdgeAddress() {
		t.Fatalf("dialled %s", s)
	}
}

// A race shows two routes to the network at once: the way in through
// Cloudflare is never the partner of a direct route.
func TestCDN_NeverRacedBesideADirectRoute(t *testing.T) {
	q := []autoCandidate{
		{routeID: "a", side: true, relayHost: "198.51.100.1", relayPort: 443},
		{routeID: "c", side: true, cdn: true, relayHost: "104.16.0.1", relayPort: 443},
	}
	if j := pickRacePartner(q, func(string) bool { return false }); j != -1 {
		t.Fatalf("partner %d", j)
	}
	q = append(q, autoCandidate{routeID: "b", side: true, relayHost: "198.51.100.2", relayPort: 8443})
	if j := pickRacePartner(q, func(string) bool { return false }); j != 2 {
		t.Fatalf("partner %d, want the direct route", j)
	}
}
