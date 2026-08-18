package uri

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestVLESSReality(t *testing.T) {
	raw := "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@example.com:443?security=reality&flow=xtls-rprx-vision&pbk=KEY&sid=ABCD&spx=%2Fpath&fp=chrome#mytag"
	p, prov, err := ParseURI(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !prov.HadReality {
		t.Errorf("expected Reality flag")
	}
	if p.TransportFamily != "vless-reality" {
		t.Errorf("family: %s", p.TransportFamily)
	}
	if p.Tag != "mytag" {
		t.Errorf("tag: %s", p.Tag)
	}
	if p.Outbound["server"] != "example.com" || p.Outbound["server_port"] != 443 {
		t.Errorf("host/port: %v", p.Outbound)
	}
	tls := p.Outbound["tls"].(map[string]any)
	if tls["server_name"] != nil { // sni was not set in URL
		// fine
	}
	r := tls["reality"].(map[string]any)
	if r["public_key"] != "KEY" || r["short_id"] != "ABCD" {
		t.Errorf("reality fields: %v", r)
	}
}

func TestVMessBase64(t *testing.T) {
	body := `{"v":"2","ps":"server-A","add":"1.2.3.4","port":"8443","id":"uuid-1","aid":"0","scy":"auto","net":"ws","host":"example.com","path":"/ws","tls":"tls"}`
	encoded := "vmess://" + base64.StdEncoding.EncodeToString([]byte(body))
	p, _, err := ParseURI(encoded)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Outbound["server"] != "1.2.3.4" || p.Outbound["server_port"] != 8443 {
		t.Errorf("host/port: %v", p.Outbound)
	}
	if p.Tag != "server-A" {
		t.Errorf("tag")
	}
	if p.Outbound["transport"].(map[string]any)["type"] != "ws" {
		t.Errorf("transport")
	}
}

func TestSSSIP002(t *testing.T) {
	raw := "ss://aes-256-gcm:secret@1.2.3.4:8388#nameA"
	p, _, err := ParseURI(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Outbound["method"] != "aes-256-gcm" || p.Outbound["password"] != "secret" {
		t.Errorf("method/password: %v", p.Outbound)
	}
	if p.TransportFamily != "shadowsocks" {
		t.Errorf("family")
	}
}

func TestSSLegacyBase64(t *testing.T) {
	userinfo := base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:secret"))
	raw := "ss://" + userinfo + "@1.2.3.4:8388"
	p, _, err := ParseURI(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Outbound["method"] != "aes-256-gcm" {
		t.Errorf("method: %v", p.Outbound)
	}
}

func TestTrojan(t *testing.T) {
	raw := "trojan://pass@example.com:443?sni=example.com#s"
	p, _, err := ParseURI(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Outbound["password"] != "pass" {
		t.Errorf("password: %v", p.Outbound)
	}
}

func TestHy2(t *testing.T) {
	raw := "hy2://pass@1.2.3.4:443?sni=h.example.com&obfs=salamander&obfs-password=opsk#h2"
	p, _, err := ParseURI(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.TransportFamily != "hysteria2" {
		t.Errorf("family")
	}
	obfs := p.Outbound["obfs"].(map[string]any)
	if obfs["type"] != "salamander" || obfs["password"] != "opsk" {
		t.Errorf("obfs: %v", obfs)
	}
}

func TestTUIC(t *testing.T) {
	raw := "tuic://uuid-1:pass@example.com:443?congestion_control=bbr&sni=t.example.com#t1"
	p, _, err := ParseURI(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Outbound["congestion_control"] != "bbr" {
		t.Errorf("cc: %v", p.Outbound)
	}
	if p.TransportFamily != "tuic" {
		t.Errorf("family")
	}
}

func TestSubscriptionEnvelopeBase64(t *testing.T) {
	inner := strings.Join([]string{
		"vless://uuid-A@a.example.com:443?security=reality&pbk=K1&sid=S1#a",
		"ss://aes-256-gcm:pw@b.example.com:8388#b",
		"# a comment",
		"hy2://pw@c.example.com:443#c",
	}, "\n")
	body := []byte(base64.StdEncoding.EncodeToString([]byte(inner)))
	profs, prov, err := ParseAny(body, "")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(profs) != 3 {
		t.Fatalf("got %d profiles", len(profs))
	}
	if prov.Scheme != "subscription" {
		t.Errorf("scheme: %s", prov.Scheme)
	}
}

func TestClashYAML(t *testing.T) {
	yaml := `port: 7890
proxies:
  - name: "ss-1"
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: secret
  - name: "trojan-1"
    type: trojan
    server: tr.example.com
    port: 443
    password: pass
    sni: tr.example.com
  - name: "vless-1"
    type: vless
    server: v.example.com
    port: 443
    uuid: uuid-1
    flow: xtls-rprx-vision
    network: reality
    public-key: PBK
    short-id: SID
proxy-groups:
  - name: select
    type: select
`
	profs, prov, err := ParseAny([]byte(yaml), "")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(profs) != 3 {
		t.Fatalf("got %d profiles", len(profs))
	}
	if prov.Scheme != "clash" {
		t.Errorf("scheme")
	}
	if profs[2].TransportFamily != "vless-reality" {
		t.Errorf("vless reality detection: %s", profs[2].TransportFamily)
	}
}

func TestSIP008(t *testing.T) {
	body := []byte(`{"version":1,"servers":[{"id":"x","remarks":"r1","server":"1.2.3.4","server_port":8388,"password":"p","method":"aes-256-gcm"}]}`)
	profs, _, err := ParseAny(body, "json")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(profs) != 1 || profs[0].Outbound["server"] != "1.2.3.4" {
		t.Errorf("sip008: %v", profs)
	}
}

func TestWireGuardPlain(t *testing.T) {
	body := []byte(`[Interface]
PrivateKey = aaaa
Address = 10.0.0.2/32
MTU = 1380

[Peer]
PublicKey = bbbb
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
`)
	profs, _, err := ParseAny(body, "")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(profs) != 1 {
		t.Fatalf("got %d", len(profs))
	}
	p := profs[0]
	if p.TransportFamily != "wireguard" {
		t.Errorf("family: %s", p.TransportFamily)
	}
	// sing-box 1.13 models WireGuard as an endpoint, not an outbound:
	// the peer lives in peers[] with address/port, and there are no
	// flat server/server_port keys. See parseWireGuard.
	if p.Outbound["type"] != "wireguard" {
		t.Errorf("type: %v", p.Outbound["type"])
	}
	peers, _ := p.Outbound["peers"].([]any)
	if len(peers) != 1 {
		t.Fatalf("peers: %v", p.Outbound["peers"])
	}
	pr := peers[0].(map[string]any)
	if pr["address"] != "vpn.example.com" || pr["port"] != 51820 {
		t.Errorf("peer endpoint: %v", pr)
	}
	if pr["public_key"] != "bbbb" {
		t.Errorf("peer public_key: %v", pr)
	}
	// AllowedIPs is the routing table and must land in allowed_ips.
	// It used to be written into `reserved`, which is the three-byte
	// WARP header — a different wire field entirely.
	if fmt.Sprint(pr["allowed_ips"]) != "[0.0.0.0/0]" {
		t.Errorf("allowed_ips: %v", pr["allowed_ips"])
	}
	if _, bad := pr["reserved"]; bad {
		t.Errorf("allowed_ips must not be written into reserved: %v", pr)
	}
	if fmt.Sprint(p.Outbound["address"]) != "[10.0.0.2/32]" {
		t.Errorf("address: %v", p.Outbound["address"])
	}
	if _, bad := p.Outbound["local_address"]; bad {
		t.Errorf("local_address is the removed 1.x outbound field: %v", p.Outbound)
	}
}

func TestWireGuardAmnezia(t *testing.T) {
	body := []byte(`[Interface]
PrivateKey = aaaa
Address = 10.0.0.2/32
Jc = 7
Jmin = 50
Jmax = 1000
S1 = 0
S2 = 0
H1 = 1
H2 = 2
H3 = 3
H4 = 4

[Peer]
PublicKey = bbbb
Endpoint = vpn.example.com:51820
`)
	profs, prov, err := ParseAny(body, "")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !prov.HadAmnezia {
		t.Errorf("expected amnezia flag")
	}
	// The engine in this build has no AmneziaWG support at all, so the
	// route that actually dials is plain WireGuard and the family says
	// so. Naming it "amneziawg" would put an AmneziaWG badge on a
	// WireGuard-shaped flow — the one thing the adversary blocks on
	// sight — which is a promise this build cannot keep.
	if profs[0].TransportFamily != "wireguard" {
		t.Errorf("family: %s", profs[0].TransportFamily)
	}
	if _, bad := profs[0].Outbound["amnezia"]; bad {
		t.Errorf("sing-box 1.13.12 has no amnezia field; emitting one is an unknown-field reject: %v", profs[0].Outbound)
	}
	if profs[0].Outbound["type"] != "wireguard" {
		t.Errorf("type: %v (there is no \"amnezia-wg\" type in sing-box 1.13.12)", profs[0].Outbound["type"])
	}
	// The loss must be reported, not swallowed: every Amnezia knob that
	// was present is named, and there is a sentence an importer can show.
	if prov.Scheme != "amneziawg" {
		t.Errorf("provenance scheme: %s", prov.Scheme)
	}
	if len(prov.DroppedParams) != 9 {
		t.Errorf("DroppedParams = %v, want all nine Amnezia knobs", prov.DroppedParams)
	}
	if prov.Downgrade == "" {
		t.Error("an AmneziaWG conf imported as plain WireGuard must carry a Downgrade notice")
	}
	if prov.WarningCount == 0 {
		t.Error("downgrade must count as a warning")
	}
}

func TestTorBridges(t *testing.T) {
	body := []byte(`obfs4 1.2.3.4:443 ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD cert=zZ iat-mode=0
webtunnel 5.6.7.8:443 1111111111111111111111111111111111111111 url=https://x.example.com/path
`)
	profs, _, err := ParseAny(body, "tor-bridge")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(profs) != 2 {
		t.Fatalf("got %d", len(profs))
	}
	// The outbound must be sing-box's REAL type. "tor-bridge" is not a
	// sing-box outbound type and the strict decoder rejects it; that
	// single word is why this family was ungradable before Wave 5.
	if profs[0].Outbound["type"] != "tor" {
		t.Errorf("type: got %v, want \"tor\"", profs[0].Outbound["type"])
	}
	args, _ := profs[0].Outbound["extra_args"].([]string)
	want := []string{"--UseBridges", "1", "--Bridge", "obfs4 1.2.3.4:443 ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD cert=zZ iat-mode=0"}
	if len(args) != len(want) {
		t.Fatalf("extra_args: got %q", args)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Errorf("extra_args[%d]: got %q want %q", i, args[i], want[i])
		}
	}
}
