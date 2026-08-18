package relaypack

import (
	"daal/publisher/deploy/relayports"
	"encoding/json"
	"testing"

	"daal/publisher/deploy/profiles"
)

// testCertPEM stands in for the box's self-signed data-plane leaf.
// Only its presence matters here — nothing in this package parses it.
const testCertPEM = "-----BEGIN CERTIFICATE-----\nMIIBtest\n-----END CERTIFICATE-----\n"

func fullParams() ClientConnParams {
	return ClientConnParams{
		Server:           "78.47.152.16",
		Name:             "r1",
		VLESSUUID:        "11111111-2222-3333-4444-555555555555",
		RealityShortID:   "deadbeef",
		RealityPublicKey: "cHVia2V5LWJhc2U2NC0zMi1ieXRlcy1oZXJlLXh4eHg=",
		Hy2Password:      "hy2secretpassword22ch",
		NaivePassword:    "naivesecretpassword22",
		WSPath:           "/r1/cafebabe",
		TLSCertSHA256:    "c3BraS1zaGEyNTYtcGluLWJhc2U2NC12YWx1ZS14eHg=",
		TLSCertPEM:       testCertPEM,
		CoverSNI:         "cdn.example-host.net",
		TUICUUID:         "99999999-8888-7777-6666-555555555555",
		TUICPassword:     "tuicsecretpassword22c",
		Multiplex: map[string]MuxPolicy{
			"vless-reality": {Enabled: true, MaxStreams: 64},
			"websocket-tls": {Enabled: true, MaxStreams: 64},
		},
	}
}

func parseOutbound(t *testing.T, family string, port int, p ClientConnParams) map[string]any {
	t.Helper()
	b, err := ClientOutboundForFamily(family, port, p)
	if err != nil {
		t.Fatalf("%s: unexpected error: %v", family, err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("%s: output is not valid JSON: %v", family, err)
	}
	if m["tag"] != "active" {
		t.Errorf("%s: tag = %v, want active", family, m["tag"])
	}
	if _, ok := m["type"].(string); !ok || m["type"] == "" {
		t.Errorf("%s: missing/empty type: %v", family, m["type"])
	}
	if m["server"] != "78.47.152.16" {
		t.Errorf("%s: server = %v", family, m["server"])
	}
	return m
}

func TestClientOutbound_VlessReality(t *testing.T) {
	m := parseOutbound(t, "vless-reality", 443, fullParams())
	if m["type"] != "vless" {
		t.Fatalf("type = %v, want vless", m["type"])
	}
	tls := m["tls"].(map[string]any)
	if tls["server_name"] != "cdn.example-host.net" {
		t.Errorf("server_name = %v, want the pack's CoverSNI", tls["server_name"])
	}
	reality := tls["reality"].(map[string]any)
	if reality["public_key"] == "" || reality["short_id"] != "deadbeef" {
		t.Errorf("reality block wrong: %v", reality)
	}
	// REALITY must NOT carry a cert pin (it borrows the handshake).
	if _, has := tls["certificate_public_key_sha256"]; has {
		t.Error("vless-reality must not pin a cert")
	}
}

func TestClientOutbound_TLSFamiliesPinNotInsecure(t *testing.T) {
	// ws/hy2 pin the leaf by SPKI SHA-256.
	for _, fam := range []string{"websocket-tls", "hysteria2"} {
		m := parseOutbound(t, fam, 443, fullParams())
		tls := m["tls"].(map[string]any)
		if tls["insecure"] == true {
			t.Errorf("%s: must never set insecure:true", fam)
		}
		if tls["certificate_public_key_sha256"] == nil {
			t.Errorf("%s: expected a cert pin", fam)
		}
	}
	// naive rides Cronet, which has no SPKI-pin knob: it trusts the
	// box's leaf as a root instead. Same fail-closed contract.
	m := parseOutbound(t, "naive", 443, fullParams())
	tls := m["tls"].(map[string]any)
	if tls["insecure"] == true {
		t.Error("naive: must never set insecure:true")
	}
	certs, _ := tls["certificate"].([]any)
	if len(certs) != 1 || certs[0] != testCertPEM {
		t.Errorf("naive: expected the box leaf as trusted root, got %v", tls["certificate"])
	}
}

// A relay provisioned before the data-plane cert existed returns no
// tls_cert_pem. That must degrade the naive route (which then fails
// closed at connect, exactly as ws/hy2 do with no pin) rather than
// abort the rewrite — RewriteProfilesForRecipient returns the FIRST
// renderer error, so erroring here killed the whole pack and with it
// every other family, for every pre-existing box.
func TestClientOutbound_NaiveWithoutCertPEMStillRenders(t *testing.T) {
	p := fullParams()
	p.TLSCertPEM = ""
	m := parseOutbound(t, "naive", 443, p)
	tls := m["tls"].(map[string]any)
	if _, has := tls["certificate"]; has {
		t.Errorf("no PEM available: must not emit an empty trusted root, got %v", tls["certificate"])
	}
	if tls["insecure"] == true {
		t.Error("naive: must never set insecure:true")
	}
	if tls["enabled"] != true {
		t.Error("naive: TLS must stay on")
	}
}

// A pack minted before CoverSNI existed carries an empty field, and the
// relay it was minted against really does handshake against the old
// fleet-wide constant — so it must still render that name, not a new one
// and not an empty SNI. This is the backward-compatibility contract for
// every already-distributed pack.
func TestClientOutbound_PreChangePackFallsBackToLegacySNI(t *testing.T) {
	p := fullParams()
	p.CoverSNI = ""
	p.Multiplex = nil // pre-change packs carry no mux either
	m := parseOutbound(t, "vless-reality", 443, p)
	tls := m["tls"].(map[string]any)
	if tls["server_name"] != legacyRealityCoverSNI {
		t.Errorf("server_name = %v, want the legacy constant %q",
			tls["server_name"], legacyRealityCoverSNI)
	}
	if _, has := m["multiplex"]; has {
		t.Errorf("pre-change pack must render byte-identically to before: got multiplex %v", m["multiplex"])
	}
	// Whitespace-only is the same case as empty (a template that rendered
	// a blank line must not produce server_name:" ").
	p.CoverSNI = "   "
	m = parseOutbound(t, "vless-reality", 443, p)
	if m["tls"].(map[string]any)["server_name"] != legacyRealityCoverSNI {
		t.Error("blank CoverSNI must fall back, not advertise whitespace")
	}
}

func TestClientOutbound_MultiplexOnTLSFamiliesOnly(t *testing.T) {
	p := fullParams()
	// A profile that (wrongly) asks for mux on the QUIC and Cronet
	// families must be ignored, not obeyed.
	p.Multiplex["hysteria2"] = MuxPolicy{Enabled: true, MaxStreams: 64}
	p.Multiplex["naive"] = MuxPolicy{Enabled: true, MaxStreams: 64}

	for _, fam := range []string{"vless-reality", "websocket-tls"} {
		m := parseOutbound(t, fam, 443, p)
		mux, ok := m["multiplex"].(map[string]any)
		if !ok {
			t.Fatalf("%s: expected a multiplex block, got %v", fam, m["multiplex"])
		}
		if mux["enabled"] != true || mux["protocol"] != "h2mux" || mux["padding"] != true {
			t.Errorf("%s: multiplex = %v", fam, mux)
		}
		if n, _ := mux["max_streams"].(float64); int(n) != 64 {
			t.Errorf("%s: max_streams = %v, want 64", fam, mux["max_streams"])
		}
	}
	for _, fam := range []string{"hysteria2", "naive"} {
		m := parseOutbound(t, fam, 443, p)
		if _, has := m["multiplex"]; has {
			// hysteria2's option struct has no Multiplex field at all, so
			// this would not merely be wrong, it would fail to parse.
			t.Errorf("%s: must never carry multiplex, got %v", fam, m["multiplex"])
		}
	}
}

// A policy present but disabled, or enabled with no explicit ceiling,
// must behave as documented: off, and the default ceiling.
func TestClientOutbound_MultiplexPolicyEdges(t *testing.T) {
	p := fullParams()
	p.Multiplex = map[string]MuxPolicy{"vless-reality": {Enabled: false, MaxStreams: 64}}
	if _, has := parseOutbound(t, "vless-reality", 443, p)["multiplex"]; has {
		t.Error("enabled:false must emit no multiplex block")
	}
	p.Multiplex = map[string]MuxPolicy{"vless-reality": {Enabled: true}}
	mux := parseOutbound(t, "vless-reality", 443, p)["multiplex"].(map[string]any)
	if n, _ := mux["max_streams"].(float64); int(n) != DefaultMuxMaxStreams {
		t.Errorf("max_streams = %v, want the default %d", mux["max_streams"], DefaultMuxMaxStreams)
	}
}

// The profile JSON is the knob; this pins the mapping from it, including
// that an operator's mistaken entry on a non-mux family is inert.
func TestMultiplexFromProfile(t *testing.T) {
	prof, err := profiles.IranDefault()
	if err != nil {
		t.Fatalf("IranDefault: %v", err)
	}
	got := MultiplexFromProfile(prof)
	if pol := got["vless-reality"]; !pol.Enabled || pol.MaxStreams != 64 {
		t.Errorf("vless-reality policy = %+v", pol)
	}
	if pol := got["websocket-tls"]; !pol.Enabled || pol.MaxStreams != 64 {
		t.Errorf("websocket-tls policy = %+v", pol)
	}
	for _, fam := range []string{"hysteria2", "tuic", "naive"} {
		if _, has := got[fam]; has {
			t.Errorf("%s must not get a mux policy from a profile", fam)
		}
	}
	if MultiplexFromProfile(nil) != nil {
		t.Error("nil profile must yield no policy")
	}
	// An operator hand-editing a profile to enable mux on a QUIC family
	// must be ignored rather than crash or produce an unparseable route.
	bad := &profiles.Profile{Candidates: []profiles.ProfileCandidate{
		{Family: "hysteria2", Multiplex: &profiles.ProfileMultiplex{Enabled: true, MaxStreams: 8}},
	}}
	if len(MultiplexFromProfile(bad)) != 0 {
		t.Error("mux on hysteria2 in a profile must be dropped")
	}
}

func TestClientOutbound_MissingFieldsError(t *testing.T) {
	cases := []struct {
		family string
		mutate func(*ClientConnParams)
	}{
		{"vless-reality", func(p *ClientConnParams) { p.RealityPublicKey = "" }},
		{"vless-reality", func(p *ClientConnParams) { p.VLESSUUID = "" }},
		{"websocket-tls", func(p *ClientConnParams) { p.WSPath = "" }},
		{"hysteria2", func(p *ClientConnParams) { p.Hy2Password = "" }},
		{"naive", func(p *ClientConnParams) { p.NaivePassword = "" }},
		// The naive proxy username must match the box's naive-in user,
		// so an empty name is an unauthenticatable route, not a
		// degraded one.
		{"naive", func(p *ClientConnParams) { p.Name = "" }},
	}
	for _, c := range cases {
		p := fullParams()
		c.mutate(&p)
		if _, err := ClientOutboundForFamily(c.family, 443, p); err == nil {
			t.Errorf("%s with missing field: expected error, got nil", c.family)
		}
	}
	// empty server
	p := fullParams()
	p.Server = ""
	if _, err := ClientOutboundForFamily("vless-reality", 443, p); err == nil {
		t.Error("empty server: expected error")
	}
	// A family Daal does not SERVE has no renderer, and must not
	// acquire one by accident: there is no WireGuard inbound on any
	// relay, no per-recipient WG credential and no 51820/udp firewall
	// rule. The client half exists only for routes the user pastes in
	// from elsewhere (bundle/go/uri), which never come through here.
	if _, err := ClientOutboundForFamily("wireguard", 51820, fullParams()); err == nil {
		t.Error("wireguard: expected error — Daal serves no WireGuard")
	}
	if _, err := ClientOutboundForFamily("amneziawg", 51820, fullParams()); err == nil {
		t.Error("amneziawg: expected error — Daal serves no WireGuard")
	}
}

// TestTUICOutbound covers the whole tuic client half: the shape, the
// mandatory ALPN, and the fail-closed behaviour when the box did not
// report credentials.
func TestTUICOutbound(t *testing.T) {
	port := relayports.For("tuic").Port
	ob := parseOutbound(t, "tuic", port, fullParams())

	if ob["type"] != "tuic" {
		t.Errorf("type = %v", ob["type"])
	}
	if ob["uuid"] != "99999999-8888-7777-6666-555555555555" || ob["password"] != "tuicsecretpassword22c" {
		t.Errorf("credentials did not reach the outbound: %v", ob)
	}
	// tuic must NOT reuse the VLESS uuid: one identifier across two
	// tiers means a single leaked pack links the recipient on both, and
	// rotating one leaves the leak live on the other.
	if ob["uuid"] == fullParams().VLESSUUID {
		t.Error("tuic uuid must be independent of the VLESS uuid")
	}
	if got := int(ob["server_port"].(float64)); got != port {
		t.Errorf("server_port = %d, want relayports' %d", got, port)
	}
	if ob["congestion_control"] != "bbr" {
		t.Errorf("congestion_control = %v; it must equal the box inbound's or the session stalls", ob["congestion_control"])
	}
	if _, mux := ob["multiplex"]; mux {
		t.Error("option.TUICOutboundOptions has no Multiplex field; emitting one makes the route unbuildable")
	}
	tls, _ := ob["tls"].(map[string]any)
	if tls == nil {
		t.Fatalf("no tls block: %v", ob)
	}
	// ALPN is mandatory for tuic and only for tuic among the QUIC
	// families: sing-quic defaults hysteria2's NextProtos to h3 and
	// leaves tuic's empty, and quic-go refuses a TLS config without an
	// application protocol. An alpn-less tuic route does not degrade,
	// it never completes a handshake.
	alpn, _ := tls["alpn"].([]any)
	if len(alpn) != 1 || alpn[0] != "h3" {
		t.Errorf("tls.alpn = %v, want [h3] (must equal the box inbound's)", tls["alpn"])
	}
	if _, utls := tls["utls"]; utls {
		t.Error("QUIC brings its own TLS stack; a uTLS block does not belong here")
	}
	if tls["certificate_public_key_sha256"] != fullParams().TLSCertSHA256 {
		t.Errorf("leaf pin missing: %v", tls)
	}
	if tls["insecure"] == true {
		t.Fatal("never insecure")
	}

	// Fail closed when the relay reported no tuic credentials — which
	// is what a relay whose profile did not enable tuic sends, and what
	// a relay running an mgmt binary that predates the family sends.
	// Rendering a route anyway would ship a tier nobody can
	// authenticate against.
	for _, missing := range []func(*ClientConnParams){
		func(p *ClientConnParams) { p.TUICUUID = "" },
		func(p *ClientConnParams) { p.TUICPassword = "" },
		func(p *ClientConnParams) { p.TUICUUID, p.TUICPassword = "", "" },
	} {
		p := fullParams()
		missing(&p)
		if _, err := ClientOutboundForFamily("tuic", port, p); err == nil {
			t.Error("tuic with missing credentials must fail closed")
		}
	}
}

// TestTUICPortAgreesAcrossBoxFirewallAndClient is the cross-component
// assertion the family needs most, because its three halves are written
// in three places that cannot import each other: the sing-box inbound
// baked into cloud-init, the two firewalls, and the client outbound.
// Any two of them disagreeing is a route that mints and cannot be
// dialled, and no single-component test can see it.
func TestTUICPortAgreesAcrossBoxFirewallAndClient(t *testing.T) {
	ep := relayports.For("tuic")

	// 1. The client outbound, when the pack carries no explicit port.
	if got := defaultClientPort("tuic"); got != ep.Port {
		t.Errorf("client fallback port = %d, want %d", got, ep.Port)
	}
	ob := parseOutbound(t, "tuic", ep.Port, fullParams())
	if got := int(ob["server_port"].(float64)); got != ep.Port {
		t.Errorf("client outbound dials %d, want %d", got, ep.Port)
	}

	// 2. The firewalls — but only for a relay that serves the family.
	extra := relayports.ExtraFirewallPortsFor([]string{"tuic"})
	found := false
	for _, e := range extra {
		if e == ep {
			found = true
		}
	}
	if !found {
		t.Errorf("firewall ports %+v do not open %+v", extra, ep)
	}
	for _, e := range relayports.ExtraFirewallPortsFor(nil) {
		if e == ep {
			t.Errorf("a relay that does not serve tuic must not open %+v", ep)
		}
	}

	// 3. The box's own inbound is asserted next to the config that
	//    writes it (hetzner TestSingBoxConfigServesTUICOnlyWhenSelected)
	//    and in cmd/daal-relay-mgmt; this leg pins the value they all
	//    have to match, and pins that it is UDP.
	if !ep.UDP {
		t.Fatal("tuic is QUIC — a TCP endpoint here would silently open the wrong socket")
	}
}
