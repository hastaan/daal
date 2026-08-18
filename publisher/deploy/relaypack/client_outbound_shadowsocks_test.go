package relaypack

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"daal/publisher/deploy/relayports"
)

// ssParams is fullParams() with the box's shadowsocks answer attached:
// a colon-joined "<iPSK>:<uPSK>", both halves padded base64-std of 16
// bytes, which is what 2022-blake3-aes-128-gcm requires.
func ssParams() ClientConnParams {
	p := fullParams()
	p.SSPassword = "bW9jay1ib3gtaXBzay0xNg==:bW9jay11c2VyLXVwc2sxNg=="
	p.SSMethod = "2022-blake3-aes-128-gcm"
	return p
}

// TestClientOutbound_Shadowsocks pins the exact wire shape against the
// real option/shadowsocks.go fields (ShadowsocksOutboundOptions:
// method, password, network, udp_over_tcp, multiplex, plus the embedded
// ServerOptions/DialerOptions). A field this struct does not carry is
// rejected by sing-box's strict decoder, so every key here is checked
// rather than assumed.
func TestClientOutbound_Shadowsocks(t *testing.T) {
	m := parseOutbound(t, "shadowsocks", 8446, ssParams())
	if m["type"] != "shadowsocks" {
		t.Fatalf("type = %v, want shadowsocks", m["type"])
	}
	if m["method"] != "2022-blake3-aes-128-gcm" {
		t.Errorf("method = %v; Daal serves 2022-blake3 only, never a legacy AEAD or stream cipher", m["method"])
	}
	if m["password"] != ssParams().SSPassword {
		t.Errorf("password = %v, want the box's assembled value verbatim", m["password"])
	}
	// Two halves, each decoding under padded base64-STD to the method's
	// key length. RawURLEncoding — what hy2/naive use — does not decode
	// there, and a bad key is an outbound sing-box refuses to build.
	parts := strings.Split(m["password"].(string), ":")
	if len(parts) != 2 {
		t.Fatalf("password %q is not two colon-joined halves", m["password"])
	}
	for _, half := range parts {
		raw, err := base64.StdEncoding.DecodeString(half)
		if err != nil {
			t.Errorf("half %q is not base64-std: %v", half, err)
			continue
		}
		if len(raw) != 16 {
			t.Errorf("half %q decodes to %d bytes, want 16 for aes-128", half, len(raw))
		}
	}
	// UDP over TCP, because the box inbound is TCP-only on one port.
	// Without it the route carries no DNS and no QUIC at all.
	uot, ok := m["udp_over_tcp"].(map[string]any)
	if !ok {
		t.Fatalf("no udp_over_tcp block: the ss-in inbound is network=tcp, so this is the route's ONLY UDP")
	}
	if uot["enabled"] != true {
		t.Errorf("udp_over_tcp.enabled = %v", uot["enabled"])
	}
	if v, _ := uot["version"].(float64); int(v) != 2 {
		t.Errorf("udp_over_tcp.version = %v, want 2", uot["version"])
	}
	// No TLS anywhere. The absence IS the feature: this is the one
	// family the Xue et al. nested-TLS classifier cannot see, and a
	// stray tls block would both break it and defeat the point.
	if _, ok := m["tls"]; ok {
		t.Errorf("shadowsocks outbound carries a tls block; it has no TLS handshake by design")
	}
	// And no multiplex: sing-box's shadowsocks outbound builds a UoT
	// client OR a mux client, never both, and silently DISCARDS the
	// loser. A pack claiming a mitigation it does not apply is worse
	// than one that claims nothing.
	if _, ok := m["multiplex"]; ok {
		t.Errorf("shadowsocks outbound carries multiplex; udp_over_tcp makes it inert, not additive")
	}
}

// TestClientOutbound_ShadowsocksNeverCarriesMultiplex proves the gate is
// a HARD one: even a profile that explicitly turns mux on for this
// family must produce no multiplex block.
func TestClientOutbound_ShadowsocksNeverCarriesMultiplex(t *testing.T) {
	if familyCarriesMultiplex("shadowsocks") {
		t.Fatalf("familyCarriesMultiplex(shadowsocks) = true")
	}
	p := ssParams()
	p.Multiplex = map[string]MuxPolicy{"shadowsocks": {Enabled: true, MaxStreams: 64}}
	m := parseOutbound(t, "shadowsocks", 8446, p)
	if _, ok := m["multiplex"]; ok {
		t.Fatalf("an operator-edited profile talked the renderer into emitting multiplex on shadowsocks")
	}
}

// TestClientOutbound_ShadowsocksRefusesOldBox is the release-coupling
// interlock. A relay whose mgmt binary predates the family reports no
// ss_password; minting the route anyway would produce one the recipient
// selects and loses, so the renderer refuses and names the fix.
func TestClientOutbound_ShadowsocksRefusesOldBox(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*ClientConnParams)
	}{
		{"no password", func(p *ClientConnParams) { p.SSPassword = "" }},
		{"no method", func(p *ClientConnParams) { p.SSMethod = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := ssParams()
			tc.mut(&p)
			_, err := ClientOutboundForFamily("shadowsocks", 8446, p)
			if err == nil {
				t.Fatalf("rendered a shadowsocks route with no usable credential")
			}
			if !strings.Contains(err.Error(), "artifacts.go") {
				t.Errorf("refusal does not tell the operator what to fix: %v", err)
			}
		})
	}
}

// TestShadowsocksPortAgreesAcrossTheChain is the "port table agrees"
// assertion. The box inbound, both firewalls and this renderer all have
// to name 8446/tcp; relayports is the single source and the firewall
// list is derived from it, so the check is that the derivation really
// carries the family.
func TestShadowsocksPortAgreesAcrossTheChain(t *testing.T) {
	ep := relayports.For("shadowsocks")
	if ep.Port != 8446 || ep.UDP {
		t.Fatalf("relayports.For(shadowsocks) = %+v, want {8446 false}", ep)
	}
	// The port must open on a relay that SERVES the family, and must not
	// open on one that does not. Baselining it (which this test used to
	// assert) opened 8446 on every relay in the fleet for a family both
	// shipped profiles default to off — a constant, unadvertised port,
	// which is a free fingerprint. Both directions fail badly and in
	// opposite ways, so both are asserted.
	var opened bool
	for _, e := range relayports.ExtraFirewallPortsFor([]string{"vless-reality", "shadowsocks"}) {
		if e.Port == ep.Port && e.UDP == ep.UDP {
			opened = true
		}
		if e.Port == ep.Port && e.UDP {
			t.Errorf("8446/udp is open; the inbound is network=tcp and UDP rides udp_over_tcp")
		}
	}
	if !opened {
		t.Fatalf("8446/tcp is not opened for a relay that serves shadowsocks: the box would serve it behind a shut firewall, which is a route that mints and cannot be dialled")
	}
	for _, e := range relayports.ExtraFirewallPortsFor([]string{"vless-reality", "hysteria2"}) {
		if e.Port == ep.Port {
			t.Errorf("8446 is open on a relay that does not serve shadowsocks — a constant port advertising nothing")
		}
	}
	// The rendered outbound must dial the port it is handed, not a
	// hard-coded one.
	m := parseOutbound(t, "shadowsocks", ep.Port, ssParams())
	if p, _ := m["server_port"].(float64); int(p) != ep.Port {
		t.Fatalf("server_port = %v, want %d", m["server_port"], ep.Port)
	}
}

// TestShadowsocksOutboundKeysAreKnownToSingBox guards the hand-sync with
// core/engine's strict-parser test: every key emitted here must exist on
// option.ShadowsocksOutboundOptions (or its embedded ServerOptions /
// DialerOptions), because sing-box's decoder rejects unknown fields and
// the failure lands on the recipient's device, not here.
func TestShadowsocksOutboundKeysAreKnownToSingBox(t *testing.T) {
	b, err := ClientOutboundForFamily("shadowsocks", 8446, ssParams())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// sing-box 1.13.12 option/shadowsocks.go + option/outbound.go.
	known := map[string]bool{
		"type": true, "tag": true, // adapter-level
		"server": true, "server_port": true, // ServerOptions
		"method": true, "password": true, "plugin": true, "plugin_opts": true,
		"network": true, "udp_over_tcp": true, "multiplex": true,
	}
	for k := range m {
		if !known[k] {
			t.Errorf("key %q is not a field of option.ShadowsocksOutboundOptions; sing-box's strict decoder will reject this outbound on the recipient's device", k)
		}
	}
}
