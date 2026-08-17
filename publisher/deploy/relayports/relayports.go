// Package relayports is the single source of truth for which port and
// protocol each transport family listens on at the relay. The box
// sing-box inbound generator, the cloud + box firewalls, and the client
// outbound assembler all derive their ports from here so they can never
// drift. Non-443 ports weaken censorship-resistance, so only families
// that cannot share 443 with REALITY (which owns 443/tcp) get their own.
package relayports

// Endpoint is a relay listen endpoint for one transport family.
type Endpoint struct {
	Port int
	UDP  bool
}

// For returns the canonical endpoint for a transport-family string
// (bundle.TransportFamily values, e.g. "vless-reality"). Unknown
// families default to 443/tcp.
func For(family string) Endpoint {
	switch family {
	case "vless-reality":
		return Endpoint{Port: 443, UDP: false}
	case "hysteria2":
		return Endpoint{Port: 443, UDP: true}
	case "tuic":
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
		return Endpoint{Port: 8443, UDP: true}
	case "naive":
		return Endpoint{Port: 8444, UDP: false}
	case "websocket-tls":
		return Endpoint{Port: 8445, UDP: false}
	case "wireguard", "amneziawg", "amnezia-wg":
		// bundle.TransportAmneziaWG is "amneziawg", but older profile
		// metadata spells it "amnezia-wg"; accept both so the port
		// never silently falls through to the 443/tcp default.
		return Endpoint{Port: 51820, UDP: true}
	default:
		return Endpoint{Port: 443, UDP: false}
	}
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
// tuic is intentionally absent even though For("tuic") now names
// 8443/udp: no shipped profile serves it, and opening a port for a
// family nobody runs would add exactly the kind of fleet-wide constant
// this file is apologising for. Add it here in the same change that
// starts serving tuic.
func ExtraFirewallPorts() []Endpoint {
	return []Endpoint{
		{Port: 8444, UDP: false}, // naive
		{Port: 8445, UDP: false}, // websocket-tls
	}
}
