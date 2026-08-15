package hetzner

import (
	"encoding/json"
	"testing"

	"daal/publisher/deploy/relayports"
)

// TestDefaultSingBoxConfigStructure proves the shipped box config is
// valid JSON and carries the full 4-tier inbound set with ports and
// cert paths that agree with the canonical relayports map. The data-
// plane TLS families (hy2, naive) must carry a certificate_path; vless
// (REALITY) must not.
func TestDefaultSingBoxConfigStructure(t *testing.T) {
	var doc map[string]any
	if err := json.Unmarshal([]byte(defaultSingBoxConfig("iran-default")), &doc); err != nil {
		t.Fatalf("defaultSingBoxConfig is not valid JSON: %v", err)
	}

	inbounds, _ := doc["inbounds"].([]any)
	if len(inbounds) != 3 {
		t.Fatalf("want 3 inbounds, got %d", len(inbounds))
	}

	byTag := map[string]map[string]any{}
	for _, raw := range inbounds {
		in, _ := raw.(map[string]any)
		tag, _ := in["tag"].(string)
		byTag[tag] = in
	}

	type want struct {
		typ     string
		port    int
		wantTLS bool // data-plane cert expected (not REALITY)
	}
	cases := map[string]want{
		"vless-in": {typ: "vless", port: relayports.For("vless-reality").Port, wantTLS: false},
		"hy2-in":   {typ: "hysteria2", port: relayports.For("hysteria2").Port, wantTLS: true},
		"naive-in": {typ: "naive", port: relayports.For("naive").Port, wantTLS: true},
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
