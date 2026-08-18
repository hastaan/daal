package hetzner

import (
	"encoding/json"
	"net"
	"strings"
	"testing"

	"daal/publisher/deploy/relayports"
	"daal/publisher/deploy/sni"
)

// TestDefaultSingBoxConfigStructure proves the shipped box config is
// valid JSON and carries the inbounds that can start with an empty
// users[] — vless-in (REALITY) and hy2-in — with ports and cert paths
// that agree with the canonical relayports map. hy2-in must carry a
// certificate_path; vless (REALITY) must not. naive-in is deliberately
// NOT shipped (sing-box FATALs "missing users" on an empty naive
// inbound); the mgmt service creates it with its first recipient.
func TestDefaultSingBoxConfigStructure(t *testing.T) {
	var doc map[string]any
	if err := json.Unmarshal([]byte(defaultSingBoxConfig("iran-default", "mirror.example.net")), &doc); err != nil {
		t.Fatalf("defaultSingBoxConfig is not valid JSON: %v", err)
	}

	inbounds, _ := doc["inbounds"].([]any)
	if len(inbounds) != 2 {
		t.Fatalf("want 2 inbounds, got %d", len(inbounds))
	}

	byTag := map[string]map[string]any{}
	for _, raw := range inbounds {
		in, _ := raw.(map[string]any)
		tag, _ := in["tag"].(string)
		byTag[tag] = in
	}

	// naive-in must not ship empty — it can't start without users.
	if _, ok := byTag["naive-in"]; ok {
		t.Errorf("naive-in must not be shipped (created on first recipient)")
	}

	type want struct {
		typ     string
		port    int
		wantTLS bool // data-plane cert expected (not REALITY)
	}
	cases := map[string]want{
		"vless-in": {typ: "vless", port: relayports.For("vless-reality").Port, wantTLS: false},
		"hy2-in":   {typ: "hysteria2", port: relayports.For("hysteria2").Port, wantTLS: true},
	}
	for tag, w := range cases {
		in, ok := byTag[tag]
		if !ok {
			t.Errorf("missing inbound tag %q", tag)
			continue
		}
		if typ, _ := in["type"].(string); typ != w.typ {
			t.Errorf("%s: type = %q, want %q", tag, typ, w.typ)
		}
		if port, _ := in["listen_port"].(float64); int(port) != w.port {
			t.Errorf("%s: listen_port = %v, want %d", tag, port, w.port)
		}
		tls, _ := in["tls"].(map[string]any)
		if tls == nil {
			t.Errorf("%s: missing tls block", tag)
			continue
		}
		_, hasCert := tls["certificate_path"].(string)
		if hasCert != w.wantTLS {
			t.Errorf("%s: certificate_path present = %v, want %v", tag, hasCert, w.wantTLS)
		}
		if w.wantTLS {
			if cp, _ := tls["certificate_path"].(string); cp != "/etc/daal/tls-cert.pem" {
				t.Errorf("%s: certificate_path = %q, want /etc/daal/tls-cert.pem", tag, cp)
			}
			if kp, _ := tls["key_path"].(string); kp != "/etc/daal/tls-key.pem" {
				t.Errorf("%s: key_path = %q, want /etc/daal/tls-key.pem", tag, kp)
			}
		}
	}

	// vless-in and hy2-in intentionally share 443 (tcp vs udp).
	if p := byTag["vless-in"]["listen_port"].(float64); int(p) != 443 {
		t.Errorf("vless-in port = %v, want 443", p)
	}
	if p := byTag["hy2-in"]["listen_port"].(float64); int(p) != 443 {
		t.Errorf("hy2-in port = %v, want 443", p)
	}
}

// TestPortDelegationMatchesRelayports guards that the profile helpers
// stay a thin delegation to the canonical map.
func TestPortDelegationMatchesRelayports(t *testing.T) {
	for _, fam := range []string{"vless-reality", "hysteria2", "naive", "websocket-tls", "tuic", "wireguard"} {
		ep := relayports.For(fam)
		if got := defaultPortForFamily(fam); got != ep.Port {
			t.Errorf("defaultPortForFamily(%q) = %d, want %d", fam, got, ep.Port)
		}
		wantProto := "tcp"
		if ep.UDP {
			wantProto = "udp"
		}
		if got := portProto(fam); got != wantProto {
			t.Errorf("portProto(%q) = %q, want %q", fam, got, wantProto)
		}
	}
}

// TestDefaultSingBoxConfigTemplatesCoverSNI is the Wave-2 regression:
// the REALITY cover host must be the per-relay value in BOTH
// tls.server_name and reality.handshake.server, and the fleet-wide
// constant must be gone from the source entirely.
func TestDefaultSingBoxConfigTemplatesCoverSNI(t *testing.T) {
	const want = "mirror.de.leaseweb.net"
	var doc struct {
		Inbounds []struct {
			Tag string `json:"tag"`
			TLS struct {
				ServerName string `json:"server_name"`
				Reality    struct {
					Enabled   bool `json:"enabled"`
					Handshake struct {
						Server     string `json:"server"`
						ServerPort int    `json:"server_port"`
					} `json:"handshake"`
				} `json:"reality"`
			} `json:"tls"`
		} `json:"inbounds"`
	}
	body := defaultSingBoxConfig("iran-default", want)
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	if strings.Contains(body, sni.LegacyCoverSNI) {
		t.Errorf("rendered config still contains the fleet-wide constant %q", sni.LegacyCoverSNI)
	}
	seen := 0
	for _, in := range doc.Inbounds {
		if !in.TLS.Reality.Enabled {
			continue
		}
		seen++
		if in.TLS.ServerName != want {
			t.Errorf("%s: tls.server_name = %q, want %q", in.Tag, in.TLS.ServerName, want)
		}
		if in.TLS.Reality.Handshake.Server != want {
			t.Errorf("%s: reality.handshake.server = %q, want %q", in.Tag, in.TLS.Reality.Handshake.Server, want)
		}
		if in.TLS.Reality.Handshake.ServerPort != 443 {
			t.Errorf("%s: reality.handshake.server_port = %d, want 443", in.Tag, in.TLS.Reality.Handshake.ServerPort)
		}
	}
	if seen == 0 {
		t.Fatal("no REALITY inbound in the rendered config")
	}
}

// TestDefaultSingBoxConfigQuotesTheCoverSNI: the host is interpolated
// into JSON, so a value containing a quote must not be able to break out
// of the string. ValidHost rejects such values upstream; this proves the
// renderer is not the only thing standing between us and broken JSON.
func TestDefaultSingBoxConfigQuotesTheCoverSNI(t *testing.T) {
	body := defaultSingBoxConfig("iran-default", `evil".example"`)
	var doc map[string]any
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("a hostile cover SNI produced invalid JSON: %v", err)
	}
}

// TestDefaultSingBoxConfigNeverEmptySNI: sing-box's REALITY inbound
// needs a name; an empty server_name is a box that does not start. The
// renderer must degrade to the legacy constant, never to "".
func TestDefaultSingBoxConfigNeverEmptySNI(t *testing.T) {
	var doc struct {
		Inbounds []struct {
			TLS struct {
				ServerName string `json:"server_name"`
				Reality    struct {
					Enabled   bool `json:"enabled"`
					Handshake struct {
						Server string `json:"server"`
					} `json:"handshake"`
				} `json:"reality"`
			} `json:"tls"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal([]byte(defaultSingBoxConfig("iran-default", "")), &doc); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	for _, in := range doc.Inbounds {
		if !in.TLS.Reality.Enabled {
			continue
		}
		if in.TLS.ServerName == "" || in.TLS.Reality.Handshake.Server == "" {
			t.Fatal("empty cover SNI produced an empty server_name/handshake.server")
		}
		if in.TLS.ServerName != in.TLS.Reality.Handshake.Server {
			t.Fatal("fallback path left server_name and handshake.server disagreeing")
		}
	}
}

// A bad toolbox-profile slug must be an error at the moment it is read.
// This is the L6 fix: candidatesForProfile used to swallow the load
// error and return nil, which the caller could not tell apart from
// "this profile enables no families" — producing an OperatorRecord with
// zero candidates that provisions and signs happily and yields a pack
// with no routes in it. L6 is the one rung whose entire content is
// passing a NEW profile name here, so it is the rung the silent nil was
// guaranteed to hit.
func TestCandidatesForProfile_UnknownProfileFailsLoudly(t *testing.T) {
	got, err := candidatesForProfile("tcp-only-vps-native", net.ParseIP("5.75.0.1"), nil)
	if err == nil {
		t.Fatalf("unknown profile returned %d candidates and no error", len(got))
	}
	if !strings.Contains(err.Error(), "tcp-only-vps-native") {
		t.Errorf("the error must name the profile the operator typed: %v", err)
	}
	if got != nil {
		t.Errorf("candidates returned alongside an error: %v", got)
	}
}

// The other road to a zero-route record: a profile that loads but whose
// families do not intersect the requested set. Same outcome for the
// recipient, so the same refusal.
func TestCandidatesForProfile_NoMatchingFamiliesFailsLoudly(t *testing.T) {
	_, err := candidatesForProfile("iran-default", net.ParseIP("5.75.0.1"), []string{"no-such-family"})
	if err == nil {
		t.Fatal("a family set that selects nothing must not produce a routeless record silently")
	}
}

func TestCandidatesForProfile_HappyPathStillWorks(t *testing.T) {
	got, err := candidatesForProfile("iran-default", net.ParseIP("5.75.0.1"), nil)
	if err != nil {
		t.Fatalf("iran-default: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("iran-default produced no candidates")
	}
	for _, c := range got {
		found := false
		for _, tag := range c.PublicRiskTags {
			if tag == "public_ip:5.75.0.1" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: no public_ip tag in %v", c.Family, c.PublicRiskTags)
		}
	}
}

// TestSingBoxConfigServesTUICOnlyWhenSelected pins the provision-time
// half of the tuic decision: the inbound exists iff the relay's family
// set names it, and when it does exist it agrees with relayports.
//
// Conditional, not created-on-first-use like naive/ws, because binding
// 8443/udp is a permanent, externally visible property of the relay and
// the ufw rule that has to accompany it is baked by cloud-init at first
// boot with no upgrade path. The inbound, both firewalls and the minted
// pack can only agree if the family set is decided once, here.
func TestSingBoxConfigServesTUICOnlyWhenSelected(t *testing.T) {
	inboundsByTag := func(body string) map[string]map[string]any {
		t.Helper()
		var doc struct {
			Inbounds []map[string]any `json:"inbounds"`
		}
		if err := json.Unmarshal([]byte(body), &doc); err != nil {
			t.Fatalf("config is not valid JSON: %v\n%s", err, body)
		}
		out := map[string]map[string]any{}
		for _, in := range doc.Inbounds {
			tag, _ := in["tag"].(string)
			out[tag] = in
		}
		return out
	}

	// Not selected: no tuic-in at all. A relay that does not serve the
	// family must look exactly as it did before this wave.
	off := inboundsByTag(singBoxConfigForFamilies("cdn.example-host.net",
		[]string{"vless-reality", "hysteria2", "naive", "websocket-tls"}))
	if _, present := off["tuic-in"]; present {
		t.Error("tuic-in must not exist on a relay whose profile did not enable tuic")
	}
	// The two unconditional inbounds are untouched either way.
	for _, tag := range []string{"vless-in", "hy2-in"} {
		if _, ok := off[tag]; !ok {
			t.Errorf("%s must always be present", tag)
		}
	}

	on := inboundsByTag(singBoxConfigForFamilies("cdn.example-host.net",
		[]string{"vless-reality", "hysteria2", "tuic"}))
	in, ok := on["tuic-in"]
	if !ok {
		t.Fatalf("tuic-in missing from a relay that serves tuic: %v", on)
	}
	if in["type"] != "tuic" {
		t.Errorf("tuic-in type = %v", in["type"])
	}
	ep := relayports.For("tuic")
	if got := int(in["listen_port"].(float64)); got != ep.Port {
		t.Errorf("tuic-in listen_port = %d, want relayports' %d", got, ep.Port)
	}
	// Empty users[] is correct and must stay: sing-box's tuic inbound
	// has no "missing users" fatal (unlike naive), so the inbound can
	// exist from first boot and the mgmt service fills it per recipient.
	if users, ok := in["users"].([]any); !ok || len(users) != 0 {
		t.Errorf("tuic-in users = %v, want an empty list", in["users"])
	}
	if in["congestion_control"] != "bbr" {
		t.Errorf("congestion_control = %v; a mismatch with the client stalls the session rather than failing it", in["congestion_control"])
	}
	tls, _ := in["tls"].(map[string]any)
	if tls == nil || tls["enabled"] != true {
		t.Fatalf("tuic requires TLS (protocol/tuic/inbound.go returns ErrTLSRequired): %v", in)
	}
	alpn, _ := tls["alpn"].([]any)
	if len(alpn) != 1 || alpn[0] != "h3" {
		t.Errorf("tls.alpn = %v, want [h3]: sing-quic's tuic sets no default NextProtos and quic-go refuses a TLS config without one", tls["alpn"])
	}
	if tls["certificate_path"] != "/etc/daal/tls-cert.pem" {
		t.Errorf("tuic-in must use the box's data-plane leaf: %v", tls)
	}
}

// TestServedFamiliesDrivesFirewallPorts checks the other consumer of the
// same resolution: the port list handed to both firewalls.
func TestServedFamiliesDrivesFirewallPorts(t *testing.T) {
	fams, err := servedFamilies("iran-default", []string{"vless-reality", "tuic"})
	if err != nil {
		t.Fatalf("servedFamilies: %v", err)
	}
	got := relayports.ExtraFirewallPortsFor(fams)
	want := relayports.For("tuic")
	found := false
	for _, ep := range got {
		if ep == want {
			found = true
		}
	}
	if !found {
		t.Errorf("firewall ports %+v do not open tuic's %+v", got, want)
	}

	// Default family set (no override) does not enable tuic, so the
	// port stays shut — the profile ships it default_enabled:false.
	def, err := servedFamilies("iran-default", nil)
	if err != nil {
		t.Fatalf("servedFamilies: %v", err)
	}
	for _, ep := range relayports.ExtraFirewallPortsFor(def) {
		if ep == want {
			t.Errorf("default relay must not open tuic's %+v", want)
		}
	}
	// And the sing-box config agrees with the firewall about it.
	if strings.Contains(singBoxConfigForFamilies("x.example.net", def), `"tuic-in"`) {
		t.Error("default relay must not bind a tuic inbound either")
	}
}
