package main

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

// TestAppendWSUserSharedInbound asserts every recipient rides ONE shared
// ws-in inbound on the canonical 8445 port (a second per-user inbound
// would collide on the port and crash sing-box the moment a relay has two
// recipients — the shared-.sbp + per-recipient-.sbpx case), that it
// carries the pinned data-plane cert paths + mirrored SNI, that later
// recipients reuse the first one's ws path, and that the inbound is
// dropped only when its last user leaves.
func TestAppendWSUserSharedInbound(t *testing.T) {
	doc := map[string]any{
		"inbounds": []any{
			map[string]any{
				"type": "vless", "tag": tagVLESS, "listen_port": float64(443),
				"tls": map[string]any{"enabled": true, "server_name": "www.cloudflare.com"},
			},
		},
	}
	// First recipient creates the shared inbound and fixes the ws path.
	if err := appendWSUser(doc, userCreds{Name: "r7", VLESSUUID: "uuid-7", WSPath: "/r7/deadbeef"}); err != nil {
		t.Fatalf("appendWSUser r7: %v", err)
	}
	in := findInboundByTag(doc, tagWS)
	if in == nil {
		t.Fatalf("shared %q inbound not created", tagWS)
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
	if sni, _ := tls["server_name"].(string); sni != "www.cloudflare.com" {
		t.Errorf("server_name = %q, want mirrored www.cloudflare.com", sni)
	}
	if wsInboundPath(doc) != "/r7/deadbeef" {
		t.Errorf("shared ws path = %q, want /r7/deadbeef", wsInboundPath(doc))
	}

	// Second recipient must join the SAME inbound, not create a colliding
	// one. (Its own WSPath is ignored in favour of the shared path — the
	// provision handler reuses wsInboundPath() for the returned creds.)
	if err := appendWSUser(doc, userCreds{Name: "r8", VLESSUUID: "uuid-8", WSPath: "/r8/cafef00d"}); err != nil {
		t.Fatalf("appendWSUser r8: %v", err)
	}
	wsCount := 0
	for _, raw := range doc["inbounds"].([]any) {
		if m, _ := raw.(map[string]any); m != nil {
			if tag, _ := m["tag"].(string); tag == tagWS {
				wsCount++
			}
		}
	}
	if wsCount != 1 {
		t.Fatalf("got %d ws inbounds, want exactly 1 shared inbound (port-collision bug)", wsCount)
	}
	if users, _ := in["users"].([]any); len(users) != 2 {
		t.Errorf("shared ws-in users = %d, want 2", len(users))
	}

	// Removing one user keeps the inbound (r8 still there); removing the
	// last drops it (sing-box faults on a user-less inbound).
	if !removeWSUser(doc, "r7") {
		t.Fatalf("removeWSUser r7 returned false")
	}
	if findInboundByTag(doc, tagWS) == nil {
		t.Fatal("ws-in dropped while r8 still present")
	}
	if !removeWSUser(doc, "r8") {
		t.Fatalf("removeWSUser r8 returned false")
	}
	if findInboundByTag(doc, tagWS) != nil {
		t.Error("ws-in must be removed when its last user leaves")
	}
}

// TestBootstrapFallbackTLS proves the loadSingboxDoc first-boot
// scaffold (fires only when config.json is absent) does not drift from
// the shipped config: hy2-in on 443 with the data-plane cert paths, and
// NO naive-in (naive can't start empty; it is created on first user).
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

	if findInboundByTag(doc, tagNaive) != nil {
		t.Errorf("bootstrap must not ship naive-in (created on first user)")
	}
	in := findInboundByTag(doc, tagHy2)
	if in == nil {
		t.Fatalf("bootstrap missing inbound %q", tagHy2)
	}
	if p, _ := in["listen_port"].(float64); p != 443 {
		t.Errorf("%s: listen_port = %v, want 443", tagHy2, p)
	}
	tls, _ := in["tls"].(map[string]any)
	if tls == nil {
		t.Fatalf("%s: missing tls block in bootstrap", tagHy2)
	}
	if cp, _ := tls["certificate_path"].(string); cp != tlsCertPath {
		t.Errorf("%s: certificate_path = %q, want %q", tagHy2, cp, tlsCertPath)
	}
	if kp, _ := tls["key_path"].(string); kp != tlsKeyPath {
		t.Errorf("%s: key_path = %q, want %q", tagHy2, kp, tlsKeyPath)
	}
}

// TestAppendNaiveUserCreatesInbound proves the naive inbound is created
// on first use (with cert + port 8444) and dropped when its last user
// leaves — never left with an empty users[], which sing-box rejects.
func TestAppendNaiveUserCreatesInbound(t *testing.T) {
	doc, err := loadSingboxDoc(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if findInboundByTag(doc, tagNaive) != nil {
		t.Fatalf("naive-in unexpectedly present before any user")
	}
	if err := appendNaiveUser(doc, userCreds{Name: "r1", NaivePassword: "pw"}); err != nil {
		t.Fatalf("appendNaiveUser: %v", err)
	}
	in := findInboundByTag(doc, tagNaive)
	if in == nil {
		t.Fatalf("naive-in not created on first user")
	}
	// appendNaiveUser builds a Go map, so listen_port is an int here
	// (it becomes float64 only after a JSON write/reload round-trip).
	if p, _ := in["listen_port"].(int); p != naiveListenPort {
		t.Errorf("naive-in port = %v, want %d", in["listen_port"], naiveListenPort)
	}
	tls, _ := in["tls"].(map[string]any)
	if cp, _ := tls["certificate_path"].(string); cp != tlsCertPath {
		t.Errorf("naive-in certificate_path = %q, want %q", cp, tlsCertPath)
	}
	if users, _ := in["users"].([]any); len(users) != 1 {
		t.Errorf("naive-in users = %d, want 1", len(users))
	}
	// Removing the only user must drop the whole inbound.
	if !removeNaiveUser(doc, "r1") {
		t.Fatalf("removeNaiveUser returned false")
	}
	if findInboundByTag(doc, tagNaive) != nil {
		t.Errorf("naive-in must be removed when its last user leaves")
	}
}
