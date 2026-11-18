// Package relayports is the single source of truth for which port and
// protocol each transport family listens on at the relay. The box
// sing-box inbound generator, the cloud + box firewalls, and the client
// outbound assembler all derive their ports from here so they can never
// drift. Non-443 ports weaken censorship-resistance, so only families
// that cannot share 443 with REALITY (which owns 443/tcp) get their own.
package relayports

import "sort"

// Endpoint is a relay listen endpoint for one transport family.
type Endpoint struct {
	Port int
	UDP  bool
}

// declaredFor is the canonical family → listen-endpoint table, and it is
// the "single source of truth" this package's doc comment promises. For()
// is a lookup into it and nothing else; Declared() enumerates it; and the
// port-collision test iterates it. That last part is the whole reason the
// table exists instead of a switch: a switch pairs with a hand-kept family
// list in the test, and a hand-kept list goes stale silently. It already
// did — the anytls row landed in this file during Wave 5 and never reached
// the collision test's literal list, so anytls was never once checked for
// a port clash. A table cannot be extended without the checks extending
// with it.
//
// What a clash costs, so nobody trims this: two inbounds on one
// (port, protocol) is not a degraded relay. sing-box refuses the second
// bind and the box does not boot — every tier down, not one. That is
// BUG-14, recorded on the tuic row below.
var declaredFor = map[string]Endpoint{
	"vless-reality": {Port: 443, UDP: false},
	"hysteria2":     {Port: 443, UDP: true},

	// BUG-14. This returned 443/udp, which hysteria2 already owns —
	// two UDP inbounds on one port is not a soft conflict, sing-box
	// refuses to bind the second and the box does not boot. tuic is
	// only reachable through the (unshipped) iran-aggressive profile
	// today, so nobody has hit it; it is one line and it is fixed
	// here so the next person to enable that profile does not lose a
	// day to a relay that never comes up.
	//
	// 8443 is NOT whitelisted egress in the target country, so a
	// tuic route is worth zero there — the same honest caveat that
	// applies to naive and websocket-tls below. Serving tuic also
	// needs 8443/udp opened, which FirewallPortsFor does only for
	// a relay that serves the family; see its comment.
	"tuic": {Port: 8443, UDP: true},

	// WAVE 5 / shadowsocks-2022. Daal mints exactly ONE method under
	// this family name — 2022-blake3-aes-128-gcm — never a legacy
	// AEAD or stream cipher; see relaypack/client_outbound.go.
	//
	// THE PORT RULE, APPLIED RATHER THAN BENT. This file's own rule
	// is that only a family that cannot share 443 with REALITY gets
	// its own port, so the question is whether shadowsocks can share
	// 443/tcp. It cannot, and not for a policy reason:
	//   - 443/tcp is bound by the vless-in REALITY inbound. Two
	//     listeners on one TCP port is not a configuration sing-box
	//     supports; it refuses the second bind (BUG-14 above is the
	//     same lesson on the UDP side).
	//   - REALITY's ONE sharing mechanism is its TLS fallback: a
	//     connection that fails REALITY auth is forwarded to the
	//     handshake dest. That demultiplexer reads a TLS ClientHello.
	//     A shadowsocks-2022 connection opens with an AEAD-encrypted,
	//     uniformly-random header carrying no TLS record framing at
	//     all, so REALITY cannot recognise it and would forward it to
	//     the cover host, which drops it. Having no TLS handshake is
	//     the entire point of the family (it is why the Xue et al.
	//     nested-TLS classifier cannot see it) and it is exactly what
	//     makes port sharing with REALITY impossible.
	//   - 443/udp is hysteria2's. The inbound is TCP-only anyway
	//     (see cmd/daal-relay-mgmt/singbox_users.go appendSSUser:
	//     `"network":"tcp"` plus client-side udp_over_tcp), so one
	//     TCP port is the whole footprint.
	//
	// THE COST, stated as plainly as the 8444/8445 note below. 8446
	// is NOT whitelisted egress in the target country. Under the
	// protocol-whitelist posture there (53/80/443 only) a
	// shadowsocks route is worth zero INSIDE Iran; its value is
	// correlation-breaking diversity on networks where non-443
	// egress survives. It also widens the fleet-wide port constant
	// from two numbers to three: `drop tcp dport 8444,8445,8446` is
	// now one censor action that takes three tiers down across every
	// Daal relay at once. That is a real regression on the port axis
	// and it is accepted here only because the alternative is not
	// shipping the one family with no TLS handshake in it. The fix
	// remains port SHARING on 443, unchanged and still unspiked.
	"shadowsocks": {Port: 8446, UDP: false},

	// WAVE 5 / anytls.
	//
	// THE PORT RULE, APPLIED. Only a family that cannot share
	// 443/tcp with REALITY gets its own port. anytls cannot, for the
	// ordinary reason: 443/tcp is bound by the vless-in REALITY
	// inbound and sing-box refuses a second listener on it. Unlike
	// shadowsocks, anytls DOES open with a real TLS handshake, so
	// REALITY's fallback demultiplexer could in principle recognise
	// it — but REALITY forwards a non-authenticating ClientHello to
	// the cover HOST, not to a local sibling listener, so the
	// fallback is a way to look innocent, not a way to multiplex two
	// Daal services. Sharing 443 needs the port-sharing spike this
	// repo has recorded as unstarted (see FirewallPortsFor), not a
	// different port number.
	//
	// THE COST, stated as plainly as the 8444/8445 note below. 8447
	// is NOT whitelisted egress in the target country. Under the
	// protocol-whitelist posture there (53/80/443 only) an anytls
	// route is worth ZERO inside Iran, which is a particularly sharp
	// irony for this family: its entire reason to exist is in-
	// protocol length and burst padding against exactly the kind of
	// traffic-shape classifier a sophisticated censor runs, and on a
	// port that censor's network drops outright it never gets to
	// demonstrate it. Its value today is (a) networks without
	// protocol whitelisting, and (b) being the family best placed to
	// move to 443 the moment port sharing lands, since it is already
	// TLS on TCP.
	//
	// It also widens the fleet-wide port constant by one more
	// number. `drop tcp dport 8444,8445,8446,8447` is one censor
	// action against four tiers on every Daal relay. That is a real
	// regression on the port axis, accepted here for the same reason
	// the previous three were, and it does not get less true by
	// being repeated.
	"anytls": {Port: 8447, UDP: false},

	"naive":         {Port: 8444, UDP: false},
	"websocket-tls": {Port: 8445, UDP: false},

	// Reserved, not served: Daal mints no WireGuard route (see
	// core/routestore/family.go). The row exists so a pasted/imported
	// WireGuard config gets the protocol's canonical port instead of
	// silently falling through to the 443/tcp default and colliding
	// with vless-reality in every table derived from this file.
	"wireguard": {Port: 51820, UDP: true},
}

// familyAliases maps alternate spellings onto the canonical family whose
// LISTENER they name. These are aliases for port purposes only and say
// nothing about wire compatibility: bundle.TransportAmneziaWG is
// "amneziawg" while older profile metadata spells it "amnezia-wg", and
// both name the same 51820/udp WireGuard listener, so both must resolve
// there rather than fall through to the 443/tcp default.
//
// They are deliberately NOT rows in declaredFor. A row per spelling would
// be three families claiming one endpoint, which the collision test would
// have to special-case — and a collision test with exceptions in it is a
// collision test nobody trusts.
var familyAliases = map[string]string{
	"amneziawg":  "wireguard",
	"amnezia-wg": "wireguard",
}

// Declared returns the canonical families that have an explicit endpoint
// in this file, sorted. Aliases are not included: one entry per listener.
//
// This is what the port-collision test iterates, which is the point —
// adding a family to declaredFor adds it to the collision check with no
// second edit anywhere.
func Declared() []string {
	out := make([]string, 0, len(declaredFor))
	for f := range declaredFor {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// For returns the canonical endpoint for a transport-family string
// (bundle.TransportFamily values, e.g. "vless-reality"). Unknown
// families default to 443/tcp.
func For(family string) Endpoint {
	if canon, ok := familyAliases[family]; ok {
		family = canon
	}
	if ep, ok := declaredFor[family]; ok {
		return ep
	}
	return Endpoint{Port: 443, UDP: false}
}

// LegacyFamilies is the family set of a relay that never declared one:
// the four tiers every relay served before a relay could be provisioned
// with a narrower (or wider) set. It is what a nil family list means to
// FirewallPortsFor, and what the box's management daemon assumes on a box
// whose cloud-init predates /etc/daal/families.
func LegacyFamilies() []string {
	return []string{"vless-reality", "hysteria2", "naive", "websocket-tls"}
}

// firewallOrder fixes the order FirewallPortsFor emits ports in, so a
// rendered ruleset is byte-identical for the same family set whatever
// order the caller listed the families in.
var firewallOrder = []string{
	"vless-reality", "hysteria2", "naive", "websocket-tls",
	"tuic", "shadowsocks", "anytls",
}

// FirewallPortsFor is the COMPLETE set of data-plane ports a relay
// serving `families` must have open — in the cloud-provider firewall and
// in the box-side ufw alike — and nothing else. A nil or empty list means
// LegacyFamilies().
//
// THE RULE: A PORT FOLLOWS ITS FAMILY, EVERY FAMILY, INCLUDING THE FOUR
// DEFAULTS. This used to be "443/tcp + 443/udp + 8444 + 8445 on every
// relay, plus the ports of whichever opt-in families were enabled"
// (ExtraFirewallPorts / ExtraFirewallPortsFor). The opt-in half was
// right and the unconditional half was the same mistake it had been
// written to avoid: a relay provisioned with `--families
// shadowsocks,anytls` still carried four open ports — with four
// listening, credentialled inbounds behind them — that no pack it ever
// minted mentions (finding FAM-4, backlog W5-1). For a tool
// whose premise is not looking like a proxy, a port that is open on a
// relay and serves nothing its operator asked for is a free fingerprint
// and an unowned attack surface.
//
// So there is no baseline any more. The served family set is resolved
// ONCE, publisher-side, at provision time (relayconf.ServedFamilies),
// and three things are derived from that one list: the sing-box inbounds
// baked into cloud-init, the /etc/daal/families file the box's
// management daemon obeys when it creates the on-first-use inbounds, and
// this port list for both firewalls. A disagreement between any two is
// either a route that mints and cannot be dialled, or a listener nobody
// asked for.
//
// BOTH FIREWALLS OR NEITHER. The cloud-provider firewall and the ufw
// rules cloud-init writes are separate gates and a packet has to pass
// both. ufw rules are written once, at first boot, and there is no
// upgrade path for cloud-init: changing a relay's family set means
// reprovisioning it, not editing a rule.
//
// WHAT THE NON-443 PORTS COST, unchanged by any of this and still
// unfixed (Wave 2 Step 6). 8444 (naive) and 8445 (websocket-tls) are the
// same two numbers on every relay that serves those families, so one
// `drop tcp dport 8444,8445` is a single censor action against two
// tiers fleet-wide; 8443/udp (tuic), 8446 (shadowsocks) and 8447
// (anytls) add to that constant on the relays that enable them. None of
// those ports is whitelisted egress under the target country's
// 53/80/443 posture, so inside it those tiers are worth zero. The fix is
// port SHARING on 443, which needs a spike against a live box (can
// sing-box 1.13.12's REALITY inbound hand a fallback connection to a
// local listener while the client still completes a real TLS handshake
// to it?) before any code is written. Nothing user-visible may imply
// these ports buy a lifeline there.
//
// A family with no row in declaredFor contributes nothing: an unknown
// name must not open For()'s 443/tcp default behind the operator's back.
func FirewallPortsFor(families []string) []Endpoint {
	if len(families) == 0 {
		families = LegacyFamilies()
	}
	have := make(map[string]bool, len(families))
	for _, f := range families {
		have[f] = true
	}
	var out []Endpoint
	for _, f := range firewallOrder {
		if have[f] {
			out = append(out, declaredFor[f])
		}
	}
	return out
}
