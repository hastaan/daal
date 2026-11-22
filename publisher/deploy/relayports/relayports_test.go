package relayports

import "testing"

// TestFor pins the canonical port/proto for every served family plus
// the reserved ones and the unknown-family default. This is the map
// the box config, both firewalls, and the client outbound all derive
// from, so a drift here is a cross-component drift.
func TestFor(t *testing.T) {
	cases := []struct {
		family string
		want   Endpoint
	}{
		{"vless-reality", Endpoint{Port: 443, UDP: false}},
		{"hysteria2", Endpoint{Port: 443, UDP: true}},
		{"naive", Endpoint{Port: 8444, UDP: false}},
		{"websocket-tls", Endpoint{Port: 8445, UDP: false}},
		// BUG-14: tuic must NOT share 443/udp with hysteria2 — sing-box
		// refuses to bind the second inbound and the relay never boots.
		{"tuic", Endpoint{Port: 8443, UDP: true}},
		{"shadowsocks", Endpoint{Port: 8446, UDP: false}},
		{"anytls", Endpoint{Port: 8447, UDP: false}},
		{"wireguard", Endpoint{Port: 51820, UDP: true}},
		{"amnezia-wg", Endpoint{Port: 51820, UDP: true}},
		{"amneziawg", Endpoint{Port: 51820, UDP: true}},
		{"something-else", Endpoint{Port: 443, UDP: false}},
	}
	for _, tc := range cases {
		if got := For(tc.family); got != tc.want {
			t.Errorf("For(%q) = %+v, want %+v", tc.family, got, tc.want)
		}
	}
}

// TestNoTwoFamiliesShareAnEndpoint is the general form of BUG-14, and
// it is deliberately derived from Declared() rather than from a list
// written out here.
//
// The hand-kept version of this test is what let anytls into the tree
// unchecked: its row was added to relayports.go in Wave 5 and the
// literal family list in this test was not touched, so the one family
// added on a brand-new port was the one family whose port was never
// compared with anything. A list that has to be edited twice gets
// edited once.
//
// What it costs when it fails is why it is a Fatal-grade invariant and
// not a lint: two inbounds on the same (port, protocol) is not a
// degraded relay or a dead tier. sing-box refuses the second bind, the
// process exits, and the box does not boot at all — every family on it
// goes dark, including the ones that were working. And it surfaces only
// when somebody enables the second family, months after the line landed.
func TestNoTwoFamiliesShareAnEndpoint(t *testing.T) {
	seen := map[Endpoint]string{}
	for _, f := range Declared() {
		ep := For(f)
		if prev, dup := seen[ep]; dup {
			t.Errorf("%q and %q both claim %+v; a box serving both does not boot at all", prev, f, ep)
		}
		seen[ep] = f
	}
}

// TestAliasesResolveToADeclaredFamily keeps the escape hatch honest. An
// alias exists so an alternate spelling reaches the right LISTENER; an
// alias pointing at nothing silently falls through to the 443/tcp
// default, which is vless-reality's endpoint — i.e. the misspelling
// would not fail, it would quietly claim REALITY's port in every table
// derived from this file.
func TestAliasesResolveToADeclaredFamily(t *testing.T) {
	declared := map[string]bool{}
	for _, f := range Declared() {
		declared[f] = true
	}
	for alias, canon := range familyAliases {
		if declared[alias] {
			t.Errorf("%q is both an alias and a declared family; pick one", alias)
		}
		if !declared[canon] {
			t.Errorf("alias %q resolves to %q, which is not a declared family", alias, canon)
		}
		if For(alias) != For(canon) {
			t.Errorf("For(%q) = %+v but For(%q) = %+v", alias, For(alias), canon, For(canon))
		}
	}
}

// TestDeclaredCoversEveryFamilyTheRelayServes is the other half of the
// collision guard: the table is only a source of truth if every family
// the relay actually stands up a listener for is IN it. A served family
// that is missing falls through to the 443/tcp default, which does not
// error — it silently reports REALITY's endpoint, so the firewall opens
// nothing new and the client dials 443 into an inbound that speaks a
// different protocol.
//
// This list is the box's side of the contract (cmd/daal-relay-mgmt
// creates the inbound) and it is intentionally spelled out, because
// adding a family here should be the moment someone reads the port cost
// written on its row above.
func TestDeclaredCoversEveryFamilyTheRelayServes(t *testing.T) {
	served := []string{
		"vless-reality", // cloud-init, 443/tcp
		"hysteria2",     // cloud-init, 443/udp
		"naive",         // daal-relay-mgmt, 8444/tcp
		"websocket-tls", // daal-relay-mgmt, 8445/tcp
		"shadowsocks",   // daal-relay-mgmt, 8446/tcp
		"anytls",        // daal-relay-mgmt, 8447/tcp
		"tuic",          // cloud-init when the profile selects it, 8443/udp
	}
	declared := map[string]bool{}
	for _, f := range Declared() {
		declared[f] = true
	}
	for _, f := range served {
		if !declared[f] {
			t.Errorf("%q is served by the relay but has no row in declaredFor; For(%q) = %+v is the unknown-family default, not a decision", f, f, For(f))
		}
	}
}

// TestFirewallPortsForLegacyRelay pins what a relay with NO declared
// family set gets: exactly the four tiers every relay served before the
// set became per-relay, family by family rather than by index — the
// list is consumed by BOTH firewalls (the cloud-provider ruleset and the
// box-side ufw baked into cloud-init), so a port here that For() does
// not agree with is a family served behind a shut gate or a gate open on
// nothing.
//
// The count is asserted deliberately and is meant to be uncomfortable:
// each entry is the same number on every default relay, i.e. the
// argument of a single censor rule. Adding a port to the default must
// be a decision someone made on purpose — never a line that slipped in
// with a feature. 8446 (shadowsocks) and 8447 (anytls) were briefly in
// the default and were removed on 2026-08-18 for exactly that reason.
func TestFirewallPortsForLegacyRelay(t *testing.T) {
	want := map[string]Endpoint{
		"vless-reality": {Port: 443, UDP: false},
		"hysteria2":     {Port: 443, UDP: true},
		"naive":         {Port: 8444, UDP: false},
		"websocket-tls": {Port: 8445, UDP: false},
	}
	for _, fams := range [][]string{nil, {}, LegacyFamilies()} {
		ports := FirewallPortsFor(fams)
		if len(ports) != len(want) {
			t.Fatalf("FirewallPortsFor(%v) len = %d, want %d (%v)", fams, len(ports), len(want), ports)
		}
		got := map[Endpoint]bool{}
		for _, e := range ports {
			if got[e] {
				t.Errorf("duplicate entry %+v", e)
			}
			got[e] = true
		}
		for family, ep := range want {
			if !got[ep] {
				t.Errorf("%s (%+v) is missing from FirewallPortsFor(%v)", family, ep, fams)
			}
			if forEp := For(family); forEp != ep {
				t.Errorf("For(%s) = %+v but the firewall opens %+v; one of the two is wrong and the family is either unreachable or exposed on the wrong port", family, forEp, ep)
			}
		}
	}
}

// TestFirewallPortsForFollowsTheFamilySet is the whole contract: a port
// is open on a relay if and only if the relay serves the family that
// listens on it. Both directions matter and they fail in opposite ways.
// Shut on a relay that serves the family = a route that mints and cannot
// be dialled, because the firewall drops the packet before sing-box sees
// it. Open on a relay that does not = a reachable port nobody asked for.
func TestFirewallPortsForFollowsTheFamilySet(t *testing.T) {
	all := []string{"vless-reality", "hysteria2", "naive", "websocket-tls", "tuic", "shadowsocks", "anytls"}
	has := func(ports []Endpoint, ep Endpoint) bool {
		for _, e := range ports {
			if e == ep {
				return true
			}
		}
		return false
	}
	// Every single family alone: exactly its own endpoint.
	for _, f := range all {
		got := FirewallPortsFor([]string{f})
		if len(got) != 1 || got[0] != For(f) {
			t.Errorf("FirewallPortsFor([%s]) = %+v, want exactly %+v", f, got, For(f))
		}
	}
	// Every family removed from the full set: its port goes, the rest stay.
	for _, off := range all {
		var fams []string
		for _, f := range all {
			if f != off {
				fams = append(fams, f)
			}
		}
		got := FirewallPortsFor(fams)
		if has(got, For(off)) {
			t.Errorf("%s is not served but its port %+v is open", off, For(off))
		}
		if len(got) != len(all)-1 {
			t.Errorf("FirewallPortsFor(all but %s) = %+v, want %d ports", off, got, len(all)-1)
		}
	}

	// FAM-4, the case that was wrong: a relay provisioned for the two
	// opt-in TCP families only must not open any of the four ports the
	// old unconditional baseline opened on every relay.
	narrow := FirewallPortsFor([]string{"shadowsocks", "anytls"})
	for _, f := range LegacyFamilies() {
		if has(narrow, For(f)) {
			t.Errorf("a shadowsocks+anytls relay opens %+v for %s, which it does not serve", For(f), f)
		}
	}
	if len(narrow) != 2 {
		t.Errorf("shadowsocks+anytls relay ports = %+v, want exactly 8446/tcp and 8447/tcp", narrow)
	}

	// tuic is QUIC; a TCP rule would open the wrong socket entirely.
	if got := FirewallPortsFor([]string{"tuic"}); len(got) != 1 || !got[0].UDP {
		t.Errorf("tuic firewall rule = %+v, want one UDP endpoint", got)
	}
	// Duplicates in the family list must not duplicate the rule.
	if dup := FirewallPortsFor([]string{"tuic", "tuic"}); len(dup) != 1 {
		t.Errorf("duplicate families produced %+v", dup)
	}
	// An unknown name opens nothing — in particular not For()'s 443/tcp
	// default for unknown families.
	if got := FirewallPortsFor([]string{"tiuc"}); len(got) != 0 {
		t.Errorf("an unknown family opened %+v", got)
	}
	// Order of the input must not change the rendered ruleset.
	a := FirewallPortsFor([]string{"anytls", "tuic", "shadowsocks", "naive"})
	b := FirewallPortsFor([]string{"naive", "shadowsocks", "anytls", "tuic"})
	if len(a) != 4 || len(a) != len(b) {
		t.Fatalf("got %+v and %+v", a, b)
	}
	for i := range a {
		if a[i] != b[i] {
			t.Errorf("ruleset is input-order dependent at %d: %+v vs %+v", i, a[i], b[i])
		}
	}
	// firewallOrder must cover every family the relay can serve, or a
	// served family silently gets no port.
	for _, f := range all {
		found := false
		for _, o := range firewallOrder {
			if o == f {
				found = true
			}
		}
		if !found {
			t.Errorf("%s is missing from firewallOrder: it would be served behind a shut firewall", f)
		}
	}
}

// TestTUICNeverSharesHysteria2Endpoint is BUG-14 stated as an invariant
// rather than a case: the two UDP families must never resolve to the
// same endpoint, because sing-box refuses the second bind and the relay
// does not boot at all — a total outage, not a degraded tier.
func TestTUICNeverSharesHysteria2Endpoint(t *testing.T) {
	if For("tuic") == For("hysteria2") {
		t.Fatalf("tuic and hysteria2 both claim %+v", For("tuic"))
	}
}

// TestCDNOriginIsItsOwnPortAndNeverWorldOpen: the CDN door must not
// share a listener with any family (a clash does not boot), must not be
// 443/tcp (Cloudflare would land on REALITY), and must never appear in
// the world-open firewall list whatever the family set.
func TestCDNOriginIsItsOwnPortAndNeverWorldOpen(t *testing.T) {
	if CDNOrigin.UDP || CDNOrigin.Port == 443 {
		t.Fatalf("CDNOrigin = %+v; want a TCP port that is not 443", CDNOrigin)
	}
	for _, f := range Declared() {
		if For(f) == CDNOrigin {
			t.Errorf("CDNOrigin %+v collides with family %q", CDNOrigin, f)
		}
	}
	sets := [][]string{nil, LegacyFamilies(), Declared()}
	for _, fams := range sets {
		for _, ep := range FirewallPortsFor(fams) {
			if ep == CDNOrigin {
				t.Errorf("FirewallPortsFor(%v) opens the CDN door to the world", fams)
			}
		}
	}
}
