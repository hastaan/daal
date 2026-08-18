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

// TestExtraFirewallPorts asserts the non-baseline data-plane ports stay
// in sync with For(), family by family rather than by index — the list
// is derived by BOTH firewalls (the cloud-provider ruleset and the
// box-side ufw baked into cloud-init), so a port here that For() does
// not agree with is a family served behind a shut gate or a gate open
// on nothing.
//
// The count is asserted deliberately and is meant to be uncomfortable.
// Every entry is the SAME number on every relay Daal has ever built, so
// this list is literally the argument of a single censor rule; each
// family added here widens `drop tcp dport 8444,8445,…` by one. Adding
// a port must be a decision someone made on purpose, with the cost
// written down in ExtraFirewallPorts' own comment — never a line that
// slipped in with a feature.
func TestExtraFirewallPorts(t *testing.T) {
	// ONLY families every shipped profile enables belong here. 8446
	// (shadowsocks) and 8447 (anytls) were briefly in this list and were
	// removed on 2026-08-18: both are default_enabled:false in every
	// profile, so baselining them opened two constant ports on every
	// relay for families that mint no route — exactly the "slipped in
	// with a feature" case this test exists to catch. They are opt-in
	// now; see TestExtraFirewallPortsFor.
	want := map[string]Endpoint{
		"naive":         {Port: 8444, UDP: false},
		"websocket-tls": {Port: 8445, UDP: false},
	}
	extra := ExtraFirewallPorts()
	if len(extra) != len(want) {
		t.Fatalf("ExtraFirewallPorts() len = %d, want %d (%v)", len(extra), len(want), extra)
	}
	got := map[Endpoint]bool{}
	for _, e := range extra {
		if got[e] {
			t.Errorf("duplicate entry %+v", e)
		}
		got[e] = true
	}
	for family, ep := range want {
		if !got[ep] {
			t.Errorf("%s (%+v) is missing from ExtraFirewallPorts()", family, ep)
		}
		if forEp := For(family); forEp != ep {
			t.Errorf("For(%s) = %+v but the firewall opens %+v; one of the two is wrong and the family is either unreachable or exposed on the wrong port", family, forEp, ep)
		}
	}
}

// TestExtraFirewallPortsFor covers the opt-in half: tuic's 8443/udp is
// opened for a relay whose family set includes it and for no other.
//
// Both halves matter and they fail in opposite directions. Shut on a
// relay that serves tuic = a family that mints and cannot be dialled,
// because the cloud firewall drops the packet before sing-box sees it.
// Open on a relay that does not = a third fleet-wide constant port and a
// free `drop udp dport 8443` for a tier nobody runs.
func TestExtraFirewallPortsFor(t *testing.T) {
	baseline := ExtraFirewallPorts()
	tuicEP := For("tuic")

	// No tuic in the family set ⇒ byte-identical to the baseline.
	for _, fams := range [][]string{
		nil,
		{},
		{"vless-reality", "hysteria2", "naive", "websocket-tls"},
	} {
		got := ExtraFirewallPortsFor(fams)
		if len(got) != len(baseline) {
			t.Fatalf("ExtraFirewallPortsFor(%v) = %+v, want the baseline %+v", fams, got, baseline)
		}
		for i := range baseline {
			if got[i] != baseline[i] {
				t.Errorf("ExtraFirewallPortsFor(%v)[%d] = %+v, want %+v", fams, i, got[i], baseline[i])
			}
		}
	}

	// tuic present ⇒ the baseline plus exactly its endpoint, once.
	got := ExtraFirewallPortsFor([]string{"vless-reality", "tuic", "hysteria2"})
	if len(got) != len(baseline)+1 {
		t.Fatalf("ExtraFirewallPortsFor with tuic = %+v, want baseline+1", got)
	}
	last := got[len(got)-1]
	if last != tuicEP {
		t.Errorf("tuic firewall port = %+v, want For(\"tuic\") = %+v", last, tuicEP)
	}
	if !last.UDP {
		t.Error("tuic is QUIC; a TCP rule would open the wrong socket entirely")
	}

	// Duplicates in the family list must not duplicate the rule.
	if dup := ExtraFirewallPortsFor([]string{"tuic", "tuic"}); len(dup) != len(baseline)+1 {
		t.Errorf("duplicate families produced %+v", dup)
	}

	// The same contract for every opt-in family, not just tuic. Each is
	// default_enabled:false in both shipped profiles, so a relay that
	// does not serve it must not carry its port — and a relay that does
	// must, or the family mints a route whose packets die at the
	// firewall.
	for _, f := range []string{"shadowsocks", "anytls"} {
		off := ExtraFirewallPortsFor([]string{"vless-reality", "hysteria2"})
		for _, e := range off {
			if e == For(f) {
				t.Errorf("%s port %+v is open on a relay that does not serve it", f, e)
			}
		}
		on := ExtraFirewallPortsFor([]string{"vless-reality", f})
		var found bool
		for _, e := range on {
			if e == For(f) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s is served but its port %+v was never opened — the route would mint and die at the firewall", f, For(f))
		}
		if len(on) != len(baseline)+1 {
			t.Errorf("ExtraFirewallPortsFor(%s) = %+v, want baseline+1", f, on)
		}
	}

	// All three opt-ins at once: order is fixed so a rendered ruleset is
	// byte-identical for the same family set.
	all := ExtraFirewallPortsFor([]string{"anytls", "tuic", "shadowsocks"})
	if len(all) != len(baseline)+3 {
		t.Fatalf("all opt-ins = %+v, want baseline+3", all)
	}
	if again := ExtraFirewallPortsFor([]string{"shadowsocks", "anytls", "tuic"}); len(again) != len(all) {
		t.Errorf("order of the input changed the output length")
	} else {
		for i := range all {
			if all[i] != again[i] {
				t.Errorf("ruleset is input-order dependent at %d: %+v vs %+v", i, all[i], again[i])
			}
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
