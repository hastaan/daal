package hetzner

import (
	"encoding/json"
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
