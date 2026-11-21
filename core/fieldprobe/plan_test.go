package fieldprobe

import (
	"context"
	"encoding/json"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"

	"daal/bundle-go/fieldreport"

	"github.com/miekg/dns"
)

// A whole world on loopback: Google, GitHub, Cloudflare, the white name
// and the Test relay are each an address that leads to a loopback
// server; DNS, QUIC and the relay's side instance are scripted.

var (
	addrGoogle = netip.MustParseAddr("203.0.113.20")
	addrGitHub = netip.MustParseAddr("203.0.113.21")
	addrCF     = netip.MustParseAddr("203.0.113.22")
	addrWhite  = netip.MustParseAddr("203.0.113.23")
	addrRelay  = netip.MustParseAddr("198.51.100.77")
	linkDNS    = netip.MustParseAddrPort("192.0.2.53:53")
)

const coverName = "cover-host.example.net"

type world struct {
	net    *fakeNet
	dns    *fakeDNS
	relay  *fakeRelay
	t      *Targets
	assert func()
}

func newWorld(t *testing.T) *world {
	t.Helper()
	tg, err := DefaultTargets()
	if err != nil {
		t.Fatal(err)
	}
	web := tlsHTTP(t, func(sni, host, path string) reply {
		switch {
		case path == "/generate_204":
			return reply{status: 204}
		case host == tg.GoogleFrontHost:
			return reply{status: 302, location: "https://abc." + tg.RedirectSuffix + "/x"}
		case strings.HasPrefix(path, "/__down"):
			return reply{status: 200, body: 9000, stall: true} // the grey cap
		case path == tg.WhitePath:
			return reply{status: 200, body: 64 * 1024}
		case path == tg.CFTracePath:
			return reply{status: 200, text: "sni=plaintext\n"}
		case sni == tg.WhiteName:
			return reply{status: 200, body: 40 * 1024}
		}
		return reply{status: 200, body: 2000}
	})
	// The cover name is reset on the path (a name filter): C5 fails
	// where C4's white name passes.
	resetNames.Store(coverName, true)
	t.Cleanup(func() { resetNames.Delete(coverName) })
	// The loopback world's addresses are inside every role's blocks.
	testNet := netip.MustParsePrefix("203.0.113.0/24")
	for _, role := range allowRoles {
		tg.allow[role] = append(tg.allow[role], testNet)
	}
	n := newFakeNet()
	for _, a := range []netip.Addr{addrGoogle, addrGitHub, addrCF, addrWhite, addrRelay} {
		n.byAddr[a] = web.addr()
	}
	n.to[netip.AddrPortFrom(addrRelay, 80)] = plainHTTP(t).addr()
	A := func(a netip.Addr) DNSAnswer { return DNSAnswer{Typed: true, Addrs: []netip.Addr{a}} }
	d := &fakeDNS{answers: map[string]DNSAnswer{
		dnsKey(netip.AddrPort{}, tg.Google, dns.TypeA):     A(addrGoogle),
		dnsKey(netip.AddrPort{}, tg.GitHub, dns.TypeA):     A(addrGitHub),
		dnsKey(netip.AddrPort{}, tg.CFECHOuter, dns.TypeA): A(addrCF),
		// The white name and the DoH name get the sinkhole from the link.
		dnsKey(linkDNS, tg.WhiteName, dns.TypeA):                  A(netip.MustParseAddr("10.10.34.35")),
		dnsKey(netip.AddrPort{}, tg.WhiteName, dns.TypeA):         A(addrWhite),
		dnsKey(netip.AddrPort{}, tg.CFDNSName, dns.TypeA):         A(netip.MustParseAddr("10.10.34.36")),
		dnsKey(netip.AddrPort{}, "www.github.com", dns.TypeCNAME): {Typed: true, CNAME: []string{"github.com."}},
		dnsKey(netip.AddrPort{}, "google.com", dns.TypeTXT):       {Typed: true, TXT: []string{"v=spf1 include:_spf.google.com ~all"}},
		dnsKey(netip.AddrPort{}, "www.google.com", dns.TypeAAAA):  {Typed: true, Addrs: []netip.Addr{netip.MustParseAddr("2001:db8::20")}},
	}}
	rel := &fakeRelay{
		target: RelayTarget{Addr: addrRelay, Port: 443, CoverName: coverName, PackID: "pack-test-1",
			Main: "route-main", Alt: []string{"route-8444"}, QUIC: "route-hy2", DesyncAvailable: true},
		outcomes: map[string]RelayOutcome{},
	}
	return &world{net: n, dns: d, relay: rel, t: tg}
}

func (w *world) env() Env {
	return Env{Net: w.net, DNS: w.dns, QUIC: fakeQUIC{ok: false}, Relay: w.relay, Targets: w.t,
		Resolvers: []netip.AddrPort{linkDNS}, Timeouts: quickTimeouts(), Gap: func(byte) time.Duration { return 0 },
		Roots: testRoots(nil)}
}

func ids(res *Result) []string {
	var out []string
	for _, p := range res.Probes {
		if len(out) == 0 || out[len(out)-1] != p.ID {
			out = append(out, p.ID)
		}
	}
	return out
}

func findResult(res *Result, id, variant string) string {
	for _, p := range res.Probes {
		if p.ID == id && (variant == "" || p.Variant == variant) {
			return p.Result
		}
	}
	return ""
}

func answerOf(fs []fieldreport.Finding, q string) string {
	for _, f := range fs {
		if f.Question == q && f.Variant == "" {
			return f.Answer
		}
	}
	return ""
}

func TestRun_FullPlan(t *testing.T) {
	w := newWorld(t)
	// REALITY as shipped is reset; the split hello gets through.
	w.relay.outcomes["route-main|off"] = RelayOutcome{Obs: resetAtHello()}
	res := Run(context.Background(), w.env())

	if !res.Complete || res.AbortReason != "" || res.ShortCircuit {
		t.Fatalf("run: complete=%v abort=%q short=%v", res.Complete, res.AbortReason, res.ShortCircuit)
	}
	want := "A1 A2 A3 A4 A5 A6 B1 B2 B3 B4 B5 B6 B7 B8 B9 C2 C3 C4 C5 C6 C7 C8 C9"
	if got := strings.Join(ids(res), " "); got != want {
		t.Fatalf("order\n got %s\nwant %s", got, want)
	}
	if res.Conns > DefaultMaxConns || res.Datagrams > MaxDatagrams || res.QUICs > 4 || res.RelayFlows > MaxRelayFlows {
		t.Fatalf("budget: conns=%d datagrams=%d quic=%d relay=%d", res.Conns, res.Datagrams, res.QUICs, res.RelayFlows)
	}
	for _, d := range w.net.dials {
		if d.Port() == 80 {
			t.Fatal("the run dialled port 80")
		}
	}
	for k, v := range map[string]string{
		"A3": "bogon", "A5": "bogon", "B1": "ok", "B3": "ok", "B5": "ok_carried", "B6": "flow_capped_suspected",
		"B7": "skipped", "B8": "ok", "B9": "timeout", "C2": "reset", "C3": "ok",
		"C4": "ok_carried", "C5": "reset", "C6": "ok", "C7": "ok", "C8": "ok", "C9": "reset",
	} {
		if got := findResult(res, k, ""); got != v {
			t.Errorf("%s = %s, want %s", k, got, v)
		}
	}
	if findResult(res, "B5", "") != "ok_carried" || findResult(res, "A6", "fill_white") != "ok" {
		t.Error("the white name was not re-resolved through the public resolver after the sinkhole")
	}
	if w.relay.restored != 1 {
		t.Fatalf("desync choice restored %d times", w.relay.restored)
	}
	if !strings.Contains(strings.Join(w.relay.calls, ","), "route-main|sni-cut") {
		t.Fatalf("C3 did not try the split: %v", w.relay.calls)
	}
	fs := Findings(res)
	for q, a := range map[string]string{
		"reality_443_works": "no", "split_hello_helps": "yes", "white_name_helps_on_relay_ip": "yes",
		"white_name_uncapped_on_cdn_ip": "yes", "grey_cap_seen_on_cdn_ip": "yes", "google_front_passes": "yes",
		"quic_443_alive": "no", "relay_alt_ports_open": "yes", "test_changed_outcome": "no",
		"cloudflare_edge_reachable": "yes", "dns_injection_on_path": "yes",
	} {
		if got := answerOf(fs, q); got != a {
			t.Errorf("finding %s = %q, want %s", q, got, a)
		}
	}
	sum := Summary(res, fs)
	if sum[len(sum)-1] != SumPrivacy || len(sum) < 3 || len(sum) > 8 {
		t.Fatalf("summary %v", sum)
	}
}

func TestRun_ShortCircuitOnBlackout(t *testing.T) {
	w := newWorld(t)
	w.dns.dead = true
	for a := range w.net.byAddr {
		delete(w.net.byAddr, a)
	}
	res := Run(context.Background(), w.env())
	if !res.ShortCircuit {
		t.Fatal("no short circuit on a blackout")
	}
	got := strings.Join(ids(res), " ")
	if got != "A1 A2 A3 A4 A5 A6 B1 C2" {
		t.Fatalf("blackout plan ran %s", got)
	}
	if res.Conns > 1 {
		t.Fatalf("blackout made %d connections", res.Conns)
	}
}

func TestRun_CancelKeepsPartial(t *testing.T) {
	w := newWorld(t)
	ctx, cancel := context.WithCancelCause(context.Background())
	env := w.env()
	env.Progress = func(step, of int) {
		if step == 9 {
			cancel(ErrBackgrounded)
		}
	}
	res := Run(ctx, env)
	if res.Complete || res.AbortReason != "backgrounded" {
		t.Fatalf("complete=%v abort=%q", res.Complete, res.AbortReason)
	}
	if len(res.Probes) == 0 || findResult(res, "B1", "") == "" {
		t.Fatal("the partial result was not kept")
	}
	if findResult(res, "C2", "") != "" {
		t.Fatal("the run went on after it was cancelled")
	}
	if w.relay.restored != 1 {
		t.Fatal("a cancelled run did not restore the desync choice")
	}
}

func TestRun_ConnectionCap(t *testing.T) {
	w := newWorld(t)
	env := w.env()
	env.MaxConns = 3
	res := Run(context.Background(), env)
	if res.AbortReason != "budget" || res.Conns != 3 {
		t.Fatalf("abort=%q conns=%d", res.AbortReason, res.Conns)
	}
}

func TestRun_HardStop(t *testing.T) {
	w := newWorld(t)
	env := w.env()
	env.HardStop = 50 * time.Millisecond
	env.Gap = func(byte) time.Duration { return 30 * time.Millisecond }
	res := Run(context.Background(), env)
	if res.AbortReason != "time_limit" || res.Complete {
		t.Fatalf("abort=%q", res.AbortReason)
	}
}

// THE PRIVACY INVARIANT: a report made from a full run, serialised,
// carries no address (v4 or v6), no host name of any target, no relay
// address or cover name, no resolver, no route handle, no pack id.
func TestPrivacy_ReportCarriesNoAddressNameOrID(t *testing.T) {
	w := newWorld(t)
	w.relay.outcomes["route-main|off"] = RelayOutcome{Obs: resetAtHello()}
	res := Run(context.Background(), w.env())
	r, err := BuildReport(res, Meta{Platform: "android", NetKind: "wifi", Validated: 1, Metered: 0,
		PrivateDNS: "auto", Resolvers: []string{linkDNS.Addr().String()}, NetworkLabel: "home_internet",
		Build: "daal-core-test", Targets: w.t, Now: time.Date(2026, 11, 20, 19, 42, 13, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	s := string(body)
	if regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`).MatchString(s) {
		t.Fatalf("a dotted quad in the report: %s", s)
	}
	if regexp.MustCompile(`[0-9a-fA-F]{1,4}::|::[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){3,}`).MatchString(s) {
		t.Fatalf("an IPv6 address in the report: %s", s)
	}
	forbidden := append(w.t.Names(), coverName, addrRelay.String(), linkDNS.Addr().String(), "1.1.1.1",
		"route-main", "route-8444", "route-hy2", "pack-test-1", w.t.GoogleFrontPath+"x", w.t.GitHubFeedPath,
		w.t.WhitePath, "googleusercontent", "19:42", "T19:42")
	for _, f := range forbidden {
		if f != "" && strings.Contains(s, f) {
			t.Errorf("report contains %q", f)
		}
	}
	if !strings.Contains(s, `"generated_hour_bucket":"2026-11-20T19:00Z"`) {
		t.Fatal("hour bucket")
	}
	if _, err := fieldreport.Parse(body); err != nil {
		t.Fatalf("the report does not parse as v2: %v", err)
	}
	if r.RelayRef == "none" || len(r.RelayRef) != 8 {
		t.Fatalf("relay_ref %q", r.RelayRef)
	}
}

// Every step logs ids and closed words only.
func TestRun_LogsNoAddressOrName(t *testing.T) {
	w := newWorld(t)
	var lines []string
	env := w.env()
	env.Log = func(s string) { lines = append(lines, s) }
	Run(context.Background(), env)
	all := strings.Join(lines, "\n")
	if regexp.MustCompile(`\d+\.\d+\.\d+\.\d+`).MatchString(all) {
		t.Fatal("a log line carries an address")
	}
	for _, n := range append(w.t.Names(), coverName) {
		if strings.Contains(all, n) {
			t.Fatalf("a log line carries %q", n)
		}
	}
}
