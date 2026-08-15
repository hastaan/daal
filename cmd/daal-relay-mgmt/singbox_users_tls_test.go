package main

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

// TestAppendWSInboundTLS asserts the per-recipient WS-TLS inbound
// lands on the canonical 8445 port and carries the pinned data-plane
// cert paths, so the client's SPKI pin has something to validate.
func TestAppendWSInboundTLS(t *testing.T) {
	doc := map[string]any{
		"inbounds": []any{
			map[string]any{
				"type": "vless", "tag": tagVLESS, "listen_port": float64(443),
				"tls": map[string]any{"enabled": true, "server_name": "www.cloudflare.com"},
			},
		},
	}
	c := userCreds{Name: "r7", VLESSUUID: "uuid-7", WSPath: "/r7/deadbeef"}
	if err := appendWSInbound(doc, c); err != nil {
		t.Fatalf("appendWSInbound: %v", err)
	}
	in := findInboundByTag(doc, "ws-r7")
	if in == nil {
		t.Fatal("ws-r7 inbound not created")
	}
	if wsListenPort != 8445 {
		t.Fatalf("wsListenPort const = %d, want 8445 (canonical relayports value)", wsListenPort)
	}
	if p, _ := in["listen_port"].(int); p != wsListenPort {
		t.Errorf("listen_port = %v, want %d", in["listen_port"], wsListenPort)
	}
	tls, _ := in["tls"].(map[string]any)
	if tls == nil {
		t.Fatal("ws inbound has no tls block")
	}
	if cp, _ := tls["certificate_path"].(string); cp != tlsCertPath {
		t.Errorf("certificate_path = %q, want %q", cp, tlsCertPath)
	}
	if kp, _ := tls["key_path"].(string); kp != tlsKeyPath {
		t.Errorf("key_path = %q, want %q", kp, tlsKeyPath)
	}
	// SNI is mirrored from vless-in.
	if sni, _ := tls["server_name"].(string); sni != "www.cloudflare.com" {
		t.Errorf("server_name = %q, want mirrored www.cloudflare.com", sni)
	}
}

// TestBootstrapFallbackTLS proves the loadSingboxDoc first-boot
// scaffold (fires only when config.json is absent) does not drift from
// the shipped config: hy2-in on 443 + naive-in on 8444, both with the
// data-plane cert paths.
func TestBootstrapFallbackTLS(t *testing.T) {
	// A path that does not exist forces the bootstrap branch.
	doc, err := loadSingboxDoc(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err != nil {
		t.Fatalf("loadSingboxDoc bootstrap: %v", err)
	}
	// Re-marshal to confirm the embedded scaffold is valid JSON.
	if _, err := json.Marshal(doc); err != nil {
		t.Fatalf("bootstrap doc not marshalable: %v", err)
	}

	cases := []struct {
		tag  string
		port float64
	}{
		{tagHy2, 443},
		{tagNaive, 8444},
	}
	for _, tc := range cases {
		in := findInboundByTag(doc, tc.tag)
		if in == nil {
			t.Errorf("bootstrap missing inbound %q", tc.tag)
			continue
		}
		if p, _ := in["listen_port"].(float64); p != tc.port {
			t.Errorf("%s: listen_port = %v, want %v", tc.tag, p, tc.port)
		}
		tls, _ := in["tls"].(map[string]any)
		if tls == nil {
			t.Errorf("%s: missing tls block in bootstrap", tc.tag)
			continue
		}
		if cp, _ := tls["certificate_path"].(string); cp != tlsCertPath {
			t.Errorf("%s: certificate_path = %q, want %q", tc.tag, cp, tlsCertPath)
		}
		if kp, _ := tls["key_path"].(string); kp != tlsKeyPath {
			t.Errorf("%s: key_path = %q, want %q", tc.tag, kp, tlsKeyPath)
		}
	}
}
