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
	// needs 8443/udp opened, which ExtraFirewallPorts deliberately
	// does not do; see its comment.
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
	// repo has recorded as unstarted (see ExtraFirewallPorts), not a
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

// ExtraFirewallPorts lists the data-plane ports that must be opened
// BEYOND the 443/tcp + 443/udp + 80/tcp baseline for the served
// families. Keep in sync with For(): naive=8444/tcp, websocket-tls=8445/tcp.
//
// KNOWN, UNFIXED, AND DELIBERATELY RECORDED HERE (Wave 2 Step 6, not
// done). Both entries are the same two numbers on every relay Daal has
// ever built, so one `drop tcp dport 8444,8445` is a single censor
// action that takes two of four tiers down across the whole fleet —
// precisely the correlated failure this wave set out to remove, solved
// for the cover-SNI axis and untouched on the port axis. Worse, under
// the target country's protocol-whitelist posture (only 53/80/443
// egress) these two tiers cannot start there at all: they were proven
// from outside, and inside they are worth zero.
//
// The fix is port SHARING on 443, not a different port number, and it
// carries the one genuine unknown of the wave — whether sing-box
// 1.13.12's REALITY inbound can hand a fallback connection to a local
// ws listener while the client still completes a real TLS handshake to
// it. That needs a spike against a live box before any code is written,
// so it is out of this wave rather than half-done in it.
//
// anytls IS here for the same reason as shadowsocks: cmd/daal-relay-mgmt
// creates the anytls-in inbound for every recipient it provisions, with
// no profile switch in between, so a shut 8447 would be a route that
// mints and cannot be dialled. TCP only — the inbound is TCP and anytls
// carries UDP over its own session layer, so there is no 8447/udp rule.
//
// shadowsocks IS here, unlike tuic, because the box really does serve
// it: cmd/daal-relay-mgmt creates the ss-in inbound for every recipient
// it provisions, exactly as it does for naive and ws, with no profile
// switch in between. A served family with a shut port is a route that
// mints and cannot be dialled — the one outcome this wave forbids. Note
// TCP only: the inbound is `"network":"tcp"` and UDP rides
// udp_over_tcp, so there is no 8446/udp rule to add.
//
// tuic is intentionally absent from THIS list and lives in
// ExtraFirewallPortsFor instead. See that function for the decision and
// the reasoning; the short version is that tuic is the first family a
// relay can be provisioned WITHOUT, so its port must not join the
// fleet-wide constant.
// WHY 8446/8447 ARE NOT HERE, corrected 2026-08-18.
//
// They were briefly baseline, which meant a fleet-wide open port for
// two families both shipped profiles mark `default_enabled: false` —
// two credentialled, publicly reachable, UNADVERTISED listeners on
// every relay, and two more constants a single
// `drop tcp dport 8444,8445,8446,8447` takes at once. For a tool whose
// whole premise is not looking like a proxy, a port that is open on
// every relay and serves nothing is a free fingerprint.
//
// The argument for keeping them was that shutting them would strand an
// operator who DOES enable the family, minting a route whose packets
// die at the firewall — the one outcome this wave forbids. That is a
// real failure, but it is not what happens: the firewall ruleset is
// rendered PUBLISHER-side from the relay's actual family set
// (provider.go calls ExtraFirewallPortsFor(served), and the cloud-init
// template takes it as RenderInput.DataPlanePorts), so the port opens
// exactly on the relays that serve the family. That is how tuic has
// always worked; ss and anytls simply did not inherit it.
//
// WHAT IS STILL ASYMMETRIC, deliberately. cmd/daal-relay-mgmt still
// creates ss-in and anytls-in for EVERY recipient, because both are
// documented as never existing with an empty users[] and so cannot be
// pre-created by cloud-init the way tuic-in is. With the ports shut
// those listeners are unreachable from outside, so the fleet-wide
// exposure is gone — but a relay serving neither family still binds two
// local sockets and holds credentials for them in its config. Removing
// that needs the box to learn its own family set (an /etc/daal file
// written at first boot) and changes what the box boots with, on a box
// with no SSH where rescue mode is the only way back. Tracked in the
// backlog; do the box side deliberately, not as a drive-by.
func ExtraFirewallPorts() []Endpoint {
	return []Endpoint{
		{Port: 8444, UDP: false}, // naive
		{Port: 8445, UDP: false}, // websocket-tls
	}
}

// ExtraFirewallPortsFor is ExtraFirewallPorts plus the ports of the
// OPT-IN families in `families` (the relay's actual candidate set, as
// resolved from its toolbox profile). Order is stable: the baseline
// first, then opt-in ports in a fixed order, so a rendered firewall
// ruleset is byte-identical for the same family set.
//
// THE 8443/udp DECISION, and why it is conditional rather than baseline.
//
// The question ExtraFirewallPorts poses is whether to open 8443/udp for
// tuic. Both available answers are wrong on their own:
//
//   - Leave it shut. Then a publisher who enables tuic mints a route
//     whose packets are dropped by the cloud firewall before they ever
//     reach sing-box. That is a family that mints and cannot be dialled
//     — a route the recipient will select and lose — which is the one
//     outcome this wave forbids outright.
//   - Open it for everyone. Then every relay Daal builds carries a
//     third constant port whether or not it serves tuic, and
//     `drop udp dport 8443` becomes a fleet-wide censor action against a
//     tier most relays do not even run. That is precisely the
//     correlated-failure complaint ExtraFirewallPorts is written to
//     apologise for, paid for nothing.
//
// So the port follows the family. tuic is the first family a relay can
// be provisioned WITHOUT — vless/hy2 are in every cloud-init, naive/ws
// are created on first recipient — and the toolbox profile already
// decides it at provision time, which is also when both firewalls are
// written. A relay that serves tuic opens 8443/udp; one that does not
// looks exactly as it did before this wave.
//
// WHAT THE PORT COSTS WHERE IT MATTERS MOST. 8443 is not whitelisted
// egress in the primary target country. Under a 53/80/443 protocol
// whitelist a tuic route there is worth zero, exactly like naive on
// 8444 and websocket-tls on 8445 — and worse than either, because the
// adversary document states the goal as complete and permanent blocking
// of outbound UDP, and Daal already ships one UDP tier (hysteria2) that
// would fall to the same rule. Opening this port buys transport
// diversity on OTHER networks. It does not buy a new lifeline in Iran,
// and nothing user-visible may imply that it does.
//
// BOTH FIREWALLS OR NEITHER. The cloud-provider firewall (hetzner
// FirewallEnsureForServer) and the box-side ufw rules baked by
// cloud-init are separate gates and a packet has to pass both. ufw
// rules are written once, at first boot, and there is no upgrade path
// for cloud-init: turning tuic on for an existing relay means
// reprovisioning it, not editing a rule.
// optInPortFamilies are the families a relay can be provisioned
// WITHOUT. Their ports open only on relays that actually serve them, so
// the fleet does not carry a constant open port for a family nobody
// enabled. Order is fixed so a rendered ruleset is byte-identical for
// the same family set.
var optInPortFamilies = []string{"tuic", "shadowsocks", "anytls"}

func ExtraFirewallPortsFor(families []string) []Endpoint {
	out := ExtraFirewallPorts()
	have := make(map[string]bool, len(families))
	for _, f := range families {
		have[f] = true
	}
	for _, f := range optInPortFamilies {
		if have[f] {
			out = append(out, For(f))
		}
	}
	return out
}
