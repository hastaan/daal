package refresh

import (
	"encoding/json"
	"testing"
)

// TestClashSubscriptionUsesTheImporterMapping pins the two defects the
// old Clash reader had: it stored the Clash entry itself as the route's
// outbound (keys sing-box rejects), and it named every trojan entry
// websocket-tls — Daal's own stable VLESS+WebSocket tier.
func TestClashSubscriptionUsesTheImporterMapping(t *testing.T) {
	body := []byte(`proxies:
  - {name: tr-inline, type: trojan, server: tr.example.com, port: 443, password: pw, sni: tr.example.com, client-fingerprint: chrome}
  - name: vl-reality
    type: vless
    server: v.example.com
    port: 443
    uuid: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
    servername: www.example.com
    reality-opts:
      public-key: AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA
      short-id: "01"
  - name: vl-plain
    type: vless
    server: p.example.com
    port: 80
    uuid: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
proxy-groups:
  - name: select
`)
	sub, err := ParseSubscriptionBody(body, "test")
	if err != nil {
		t.Fatal(err)
	}
	// vl-plain is plaintext VLESS and is refused, as a vless:// link
	// with security=none is.
	if len(sub.Routes) != 2 {
		t.Fatalf("routes = %d, want 2: %+v", len(sub.Routes), sub.Routes)
	}
	want := map[string]string{"tr-inline": "other", "vl-reality": "vless-reality"}
	for _, r := range sub.Routes {
		if fam, ok := want[r.DisplayName]; !ok || r.TransportFamily != fam {
			t.Errorf("%s: family %q, want %q", r.DisplayName, r.TransportFamily, fam)
		}
		var ob map[string]any
		if err := json.Unmarshal(r.OutboundJSON, &ob); err != nil {
			t.Fatal(err)
		}
		for _, clashKey := range []string{"name", "port", "cipher", "sni", "client-fingerprint", "reality-opts"} {
			if _, has := ob[clashKey]; has {
				t.Errorf("%s: outbound carries Clash key %q: %s", r.DisplayName, clashKey, r.OutboundJSON)
			}
		}
		if ob["server_port"] != float64(443) {
			t.Errorf("%s: server_port = %v", r.DisplayName, ob["server_port"])
		}
		tls, _ := ob["tls"].(map[string]any)
		if u, _ := tls["utls"].(map[string]any); u["fingerprint"] != "chrome" {
			t.Errorf("%s: utls = %v", r.DisplayName, tls)
		}
	}
}

// Ids are positional and health, cooldown and network memory are keyed
// by them: an entry refused since the last refresh keeps its slot, so
// the entries after it keep the ids (and the history) they had.
func TestRefusedEntriesKeepTheirSlot(t *testing.T) {
	ids := func(sub ParsedSubscription) map[string]string {
		m := map[string]string{}
		for _, r := range sub.Routes {
			m[r.DisplayName] = r.RouteID
		}
		return m
	}
	clash := []byte(`proxies:
  - {name: a, type: ss, server: a.example.com, port: 8388, cipher: aes-256-gcm, password: p}
  - {name: plain, type: vless, server: p.example.com, port: 80, uuid: u}
  - {name: vm, type: vmess, server: vm.example.com, port: 443, uuid: u, cipher: auto, tls: true}
  - {name: b, type: ss, server: b.example.com, port: 8388, cipher: aes-256-gcm, password: p}
`)
	sub, err := ParseSubscriptionBody(clash, "t")
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(sub); got["a"] != "sub-t-1" || got["b"] != "sub-t-3" || got["vm"] != "sub-t-x1" || got["plain"] != "" {
		t.Errorf("clash ids = %v", got)
	}
	list := []byte("ss://aes-256-gcm:p@a.example.com:8388#a\n" +
		"vless://u@x.example.com:443?security=tls&type=xhttp#refused\n" +
		"ss://aes-256-gcm:p@b.example.com:8388#b\n")
	sub, err = ParseSubscriptionBody(list, "t")
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(sub); got["a"] != "sub-t-1" || got["b"] != "sub-t-3" || len(got) != 2 {
		t.Errorf("uri-list ids = %v", got)
	}
	sip := []byte(`{"version":1,"servers":[
		{"server":"a.example.com","server_port":8388,"method":"aes-256-gcm","password":"p","remarks":"a"},
		{"server":"n.example.com","server_port":8388,"method":"none","password":"p","remarks":"plain"},
		{"server":"b.example.com","server_port":8388,"method":"aes-256-gcm","password":"p","remarks":"b"}]}`)
	sub, err = ParseSubscriptionBody(sip, "t")
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(sub); got["a"] != "sub-t-1" || got["b"] != "sub-t-3" || len(got) != 2 {
		t.Errorf("sip008 ids = %v", got)
	}
}
