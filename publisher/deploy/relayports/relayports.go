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
	case "hysteria2", "tuic":
		return Endpoint{Port: 443, UDP: true}
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
func ExtraFirewallPorts() []Endpoint {
	return []Endpoint{
		{Port: 8444, UDP: false}, // naive
		{Port: 8445, UDP: false}, // websocket-tls
	}
}
