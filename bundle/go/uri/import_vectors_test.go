package uri

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
)

const testRealityKey = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"

// importVectors is testdata/import_vectors.json. The same file feeds
// core/engine TestEveryImportedOutboundParses, which runs each accepted
// outbound through sing-box's strict option parse; this side checks
// families, refusals and the shapes the strict parse cannot see.
type importVectors struct {
	Accepted []struct {
		Name   string `json:"name"`
		Input  string `json:"input"`
		Hint   string `json:"hint"`
		Family string `json:"family"`
	} `json:"accepted"`
	Refused []struct {
		Name  string `json:"name"`
		Input string `json:"input"`
		Code  string `json:"code"`
	} `json:"refused"`
}

func loadImportVectors(t *testing.T) importVectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/import_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v importVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Accepted) == 0 || len(v.Refused) == 0 {
		t.Fatal("empty vector file")
	}
	return v
}

func parseVector(input, hint string) ([]Profile, Provenance, error) {
	if hint == "" && strings.Contains(input, "://") && !strings.Contains(input, "\n") {
		p, prov, err := ParseURI(input)
		if err != nil {
			return nil, prov, err
		}
		return []Profile{p}, prov, nil
	}
	return ParseAny([]byte(input), hint)
}

// portRange is the one shape sing-quic's hysteria.ParsePorts accepts
// (it errors at connect, after the option parse has passed).
var portRange = regexp.MustCompile(`^[0-9]{1,5}:[0-9]{1,5}$`)

func TestImportVectorsAccepted(t *testing.T) {
	for _, v := range loadImportVectors(t).Accepted {
		t.Run(v.Name, func(t *testing.T) {
			profs, _, err := parseVector(v.Input, v.Hint)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			for _, p := range profs {
				if v.Family != "" && p.TransportFamily != v.Family {
					t.Errorf("family = %q, want %q", p.TransportFamily, v.Family)
				}
				b, _ := json.Marshal(p.Outbound)
				s := string(b)
				for _, bad := range []string{"spider_x", `"encryption"`, `"amnezia`} {
					if strings.Contains(s, bad) {
						t.Errorf("outbound carries %s: %s", bad, s)
					}
				}
				if tls, _ := p.Outbound["tls"].(map[string]any); tls != nil {
					if alpn, ok := tls["alpn"].([]string); ok {
						for _, a := range alpn {
							if strings.Contains(a, ",") {
								t.Errorf("alpn element %q is a joined list", a)
							}
						}
					}
					if _, isReality := tls["reality"]; isReality {
						u, _ := tls["utls"].(map[string]any)
						if u == nil || u["enabled"] != true || u["fingerprint"] == "" {
							t.Errorf("reality without utls: %v", tls)
						}
					}
				}
				if sp, ok := p.Outbound["server_ports"].([]string); ok {
					for _, r := range sp {
						if !portRange.MatchString(r) {
							t.Errorf("server_ports entry %q is not start:end", r)
						}
					}
					if p.Outbound["hop_interval"] == nil {
						t.Error("server_ports without hop_interval")
					}
				}
			}
		})
	}
}

func TestImportVectorsRefused(t *testing.T) {
	for _, v := range loadImportVectors(t).Refused {
		t.Run(v.Name, func(t *testing.T) {
			_, _, err := ParseURI(v.Input)
			if err == nil {
				t.Fatal("imported; want a refusal")
			}
			if got := RefusalCode(err); got != v.Code {
				t.Errorf("code = %q, want %q (err %v)", got, v.Code, err)
			}
			// Never the credential in an error the host may show or log.
			for _, secret := range []string{"aaaaaaaa-bbbb", "pw@", testRealityKey} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("error quotes a credential: %v", err)
				}
			}
		})
	}
}

func TestRefusalsAreNotSilentInEnvelopes(t *testing.T) {
	// A subscription mixing a dialable link with an xhttp one keeps the
	// dialable one and COUNTS the other, never turning it into TCP.
	body := "vless://" + "u@x.example.com:443?security=tls&type=xhttp\n" +
		"ss://aes-256-gcm:pw@s.example.com:8388#s\n"
	profs, prov, err := ParseAny([]byte(body), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(profs) != 1 || profs[0].TransportFamily != "shadowsocks" || prov.WarningCount != 1 {
		t.Fatalf("profiles %v, warnings %d", profs, prov.WarningCount)
	}
}

func TestBadURLDoesNotQuoteTheLink(t *testing.T) {
	for _, raw := range []string{
		"vless://topsecret-uuid@host.example.com:notaport?security=tls",
		"trojan://topsecret%zz@host.example.com:443",
		"hy2://topsecret@host.example.com:4x3",
		"ss://aes-256-gcm:topsecret@host.example.com:8x388",
		"tuic://uuid:topsecret@host.example.com:4x3",
		"ss://aes-256-gcm:topsecret%zz@host.example.com:8388",
	} {
		_, _, err := ParseURI(raw)
		if err == nil {
			t.Fatalf("%s: parsed", raw)
		}
		if strings.Contains(err.Error(), "topsecret") || strings.Contains(err.Error(), "host.example.com") {
			t.Errorf("error quotes the link: %v", err)
		}
		if !errors.Is(err, ErrMalformed) {
			t.Errorf("want ErrMalformed: %v", err)
		}
	}
}

func TestVLESSRealityDefaultsAndDrops(t *testing.T) {
	p, _, err := ParseURI("vless://u@r.example.com:443?security=reality&pbk=" + testRealityKey + "&sid=ab&spx=%2Fcrawl&encryption=none")
	if err != nil {
		t.Fatal(err)
	}
	tls := p.Outbound["tls"].(map[string]any)
	if fp := tls["utls"].(map[string]any)["fingerprint"]; fp != "chrome" {
		t.Errorf("fingerprint = %v, want chrome", fp)
	}
	if r := tls["reality"].(map[string]any); len(r) != 3 {
		t.Errorf("reality = %v, want exactly enabled/public_key/short_id", r)
	}
	if _, has := p.Outbound["encryption"]; has {
		t.Error("encryption written")
	}
}

func TestWebSocketEarlyData(t *testing.T) {
	p, _, err := ParseURI("vless://u@c.example.com:443?security=tls&type=ws&path=%2Fws%3Fed%3D2048%26x%3D1&host=cdn.example.com")
	if err != nil {
		t.Fatal(err)
	}
	tr := p.Outbound["transport"].(map[string]any)
	if tr["path"] != "/ws?x=1" || tr["max_early_data"] != 2048 || tr["early_data_header_name"] != "Sec-WebSocket-Protocol" {
		t.Errorf("transport = %v", tr)
	}
	p, _, err = ParseURI("vless://u@c.example.com:443?security=tls&type=httpupgrade&path=%2Fup%3Fed%3D2048&host=cdn.example.com")
	if err != nil {
		t.Fatal(err)
	}
	tr = p.Outbound["transport"].(map[string]any)
	if tr["type"] != "httpupgrade" || tr["path"] != "/up" || tr["host"] != "cdn.example.com" {
		t.Errorf("httpupgrade transport = %v", tr)
	}
}

func TestHy2PortHopping(t *testing.T) {
	cases := []struct {
		raw   string
		port  int
		ports string
		hop   string
	}{
		{"hysteria2://pw@h.example.com:443,20000-50000/?sni=h", 443, "[443:443 20000:50000]", "30s"},
		{"hy2://pw@h.example.com:20000-50000?hopInterval=45", 20000, "[20000:50000]", "45s"},
		{"hy2://pw@h.example.com:443?mport=20000-30000,40000&hop_interval=1m", 443, "[443:443 20000:30000 40000:40000]", "1m0s"},
		{"hy2://pw@[2001:db8::1]:443,5000-6000", 443, "[443:443 5000:6000]", "30s"},
	}
	for _, c := range cases {
		p, _, err := ParseURI(c.raw)
		if err != nil {
			t.Fatalf("%s: %v", c.raw, err)
		}
		if p.Outbound["server_port"] != c.port || fmt.Sprint(p.Outbound["server_ports"]) != c.ports || p.Outbound["hop_interval"] != c.hop {
			t.Errorf("%s: %v", c.raw, p.Outbound)
		}
	}
	p, _, err := ParseURI("hy2://pw@h.example.com:443?sni=h")
	if err != nil {
		t.Fatal(err)
	}
	if _, has := p.Outbound["server_ports"]; has {
		t.Errorf("single port grew server_ports: %v", p.Outbound)
	}
	if _, has := p.Outbound["hop_interval"]; has {
		t.Errorf("single port grew hop_interval: %v", p.Outbound)
	}
}

func TestTrojanFingerprintAndFamily(t *testing.T) {
	p, _, err := ParseURI("trojan://pw@t.example.com:443?sni=t.example.com&fp=chrome&alpn=h2,http/1.1")
	if err != nil {
		t.Fatal(err)
	}
	tls := p.Outbound["tls"].(map[string]any)
	if tls["utls"].(map[string]any)["fingerprint"] != "chrome" {
		t.Errorf("fp not honoured: %v", tls)
	}
	if fmt.Sprint(tls["alpn"]) != "[h2 http/1.1]" {
		t.Errorf("alpn = %v", tls["alpn"])
	}
	if p.TransportFamily != "other" {
		t.Errorf("family = %s", p.TransportFamily)
	}
	cp, err := ProfileFromClashEntry(map[string]string{"type": "trojan", "server": "t.example.com", "port": "443", "password": "pw"})
	if err != nil {
		t.Fatal(err)
	}
	if cp.TransportFamily != p.TransportFamily {
		t.Errorf("clash trojan family %q != uri trojan family %q", cp.TransportFamily, p.TransportFamily)
	}
}

func TestAmneziaCompatibility(t *testing.T) {
	base := "[Interface]\nPrivateKey = a\nAddress = 10.0.0.2/32\n%s\n[Peer]\nPublicKey = b\nEndpoint = vpn.example.com:51820\n"
	cases := []struct {
		name, fields, family, notice string
	}{
		{"junk only", "Jc = 4\nJmin = 40\nJmax = 70", "wireguard", NoticeAmneziaDowngraded},
		{"neutral S and H", "Jc = 4\nS1 = 0\nS2 = 0\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4", "wireguard", NoticeAmneziaDowngraded},
		{"real headers", "Jc = 4\nH1 = 1234\nH2 = 2\nH3 = 3\nH4 = 4", "amneziawg", NoticeAmneziaUnsupported},
		{"padding", "Jc = 4\nS1 = 15", "amneziawg", NoticeAmneziaUnsupported},
		{"2.0 only, lower-case key", "i1 = <b 0xc0ffee>", "amneziawg", NoticeAmneziaUnsupported},
		{"2.0 S3", "S3 = 12", "amneziawg", NoticeAmneziaUnsupported},
		{"2.0 junk timer", "Jc = 4\nJ1 = <r 32>\nITIME = 60", "amneziawg", NoticeAmneziaUnsupported},
		{"plain", "", "wireguard", ""},
	}
	for _, c := range cases {
		profs, prov, err := ParseAny([]byte(fmt.Sprintf(base, c.fields)), "wireguard")
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if profs[0].TransportFamily != c.family || prov.Notice != c.notice {
			t.Errorf("%s: family %q notice %q, want %q %q", c.name, profs[0].TransportFamily, prov.Notice, c.family, c.notice)
		}
		if c.notice != "" && (!prov.HadAmnezia || prov.Scheme != "amneziawg" || prov.Downgrade == "" || len(prov.DroppedParams) == 0) {
			t.Errorf("%s: provenance %+v", c.name, prov)
		}
		if c.notice == NoticeAmneziaUnsupported && strings.Contains(prov.Downgrade, "still connect") {
			t.Errorf("%s: unsupported notice promises a connection: %s", c.name, prov.Downgrade)
		}
	}
}

func TestClashEntries(t *testing.T) {
	// REALITY without client-fingerprint gets chrome (sing-box's REALITY
	// client refuses to start without uTLS).
	p, err := ProfileFromClashEntry(map[string]string{"type": "vless", "server": "v.example.com", "port": "443",
		"uuid": "u", "public-key": testRealityKey, "short-id": "01", "servername": "www.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Outbound["tls"].(map[string]any)["utls"].(map[string]any)["fingerprint"] != "chrome" {
		t.Errorf("clash reality fp: %v", p.Outbound)
	}
	if _, err := ProfileFromClashEntry(map[string]string{"type": "vless", "server": "v.example.com", "port": "80", "uuid": "u"}); !errors.Is(err, ErrPlaintext) {
		t.Errorf("plaintext clash vless: %v", err)
	}
	if _, err := ProfileFromClashEntry(map[string]string{"type": "trojan", "server": "t.example.com", "port": "443", "password": "p", "network": "grpc"}); !errors.Is(err, ErrTransportUnsupported) {
		t.Errorf("clash trojan grpc: %v", err)
	}
	if _, err := ProfileFromClashEntry(map[string]string{"type": "vless", "server": "v.example.com", "port": "443", "uuid": "u", "tls": "true", "network": "h2"}); !errors.Is(err, ErrTransportUnsupported) {
		t.Errorf("clash vless h2: %v", err)
	}
}

func TestHy2HopIntervalHasAFloor(t *testing.T) {
	for raw, want := range map[string]string{
		"hy2://pw@h.example.com:443,20000-30000?hopInterval=1ns": "5s",
		"hy2://pw@h.example.com:443,20000-30000?hop_interval=2":  "5s",
		"hy2://pw@h.example.com:443,20000-30000?hop_interval=5s": "5s",
		"hy2://pw@h.example.com:443,20000-30000?hop_interval=90": "1m30s",
	} {
		p, _, err := ParseURI(raw)
		if err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if p.Outbound["hop_interval"] != want {
			t.Errorf("%s: hop_interval = %v, want %s", raw, p.Outbound["hop_interval"], want)
		}
	}
	if _, err := ProfileFromClashEntry(map[string]string{"type": "hysteria2", "server": "h.example.com", "port": "443",
		"password": "pw", "ports": "20000-30000", "hop-interval": "1"}); err != nil {
		t.Fatal(err)
	} else if p, _ := ProfileFromClashEntry(map[string]string{"type": "hysteria2", "server": "h.example.com", "port": "443",
		"password": "pw", "ports": "20000-30000", "hop-interval": "1"}); p.Outbound["hop_interval"] != "5s" {
		t.Errorf("clash hop-interval = %v", p.Outbound["hop_interval"])
	}
}

func TestClashVMessCarriesItsTransportOrIsRefused(t *testing.T) {
	base := func(kv ...string) map[string]string {
		e := map[string]string{"type": "vmess", "server": "vm.example.com", "port": "443", "uuid": "u", "alterId": "0"}
		for i := 0; i+1 < len(kv); i += 2 {
			e[kv[i]] = kv[i+1]
		}
		return e
	}
	// The probe that found the defect: ws + tls + zero came out as
	// raw-TCP VMess with no TLS and no encryption.
	p, err := ProfileFromClashEntry(base("network", "ws", "tls", "true", "path", "/x", "Host", "cdn.example.com",
		"cipher", "zero", "servername", "vm.example.com", "client-fingerprint", "chrome"))
	if err != nil {
		t.Fatal(err)
	}
	tls, _ := p.Outbound["tls"].(map[string]any)
	tr, _ := p.Outbound["transport"].(map[string]any)
	if tls["enabled"] != true || tls["server_name"] != "vm.example.com" || tr["type"] != "ws" || tr["path"] != "/x" ||
		tr["headers"].(map[string]any)["Host"] != "cdn.example.com" || p.Outbound["security"] != "zero" {
		t.Errorf("clash vmess ws+tls = %v", p.Outbound)
	}
	p, err = ProfileFromClashEntry(base("network", "grpc", "tls", "true", "grpc-service-name", "svc"))
	if err != nil {
		t.Fatal(err)
	}
	if tr := p.Outbound["transport"].(map[string]any); tr["type"] != "grpc" || tr["service_name"] != "svc" {
		t.Errorf("clash vmess grpc = %v", p.Outbound)
	}
	p, err = ProfileFromClashEntry(base("network", "ws", "tls", "true", "ws-path", "/legacy"))
	if err != nil {
		t.Fatal(err)
	}
	if tr := p.Outbound["transport"].(map[string]any); tr["path"] != "/legacy" {
		t.Errorf("clash vmess ws-path = %v", p.Outbound)
	}
	for _, c := range []struct {
		name string
		e    map[string]string
		want error
	}{
		{"zero without tls", base("cipher", "zero", "network", "ws", "path", "/x"), ErrPlaintext},
		{"none without tls", base("cipher", "none"), ErrPlaintext},
		{"unknown cipher", base("cipher", "rc4", "tls", "true"), ErrEncryptionUnsupported},
		{"h2", base("network", "h2", "tls", "true"), ErrTransportUnsupported},
		{"http header obfs", base("network", "http"), ErrTransportUnsupported},
	} {
		if _, err := ProfileFromClashEntry(c.e); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
	// Raw TCP with a real cipher is VMess's own encryption: kept.
	p, err = ProfileFromClashEntry(base("cipher", "aes-128-gcm"))
	if err != nil || p.Outbound["security"] != "aes-128-gcm" || p.Outbound["tls"] != nil || p.Outbound["transport"] != nil {
		t.Errorf("raw tcp vmess = %v, %v", p.Outbound, err)
	}
}

func TestClashRefusalsMatchTheURIRules(t *testing.T) {
	ss := map[string]string{"type": "ss", "server": "s.example.com", "port": "8388", "password": "p"}
	with := func(base map[string]string, kv ...string) map[string]string {
		e := map[string]string{}
		for k, v := range base {
			e[k] = v
		}
		for i := 0; i+1 < len(kv); i += 2 {
			e[kv[i]] = kv[i+1]
		}
		return e
	}
	vl := map[string]string{"type": "vless", "server": "v.example.com", "port": "443", "uuid": "u",
		"public-key": testRealityKey, "servername": "www.example.com"}
	for _, c := range []struct {
		name string
		e    map[string]string
		want error
	}{
		{"ss cipher none", with(ss, "cipher", "none"), ErrPlaintext},
		{"ss cipher plain", with(ss, "cipher", "plain"), ErrPlaintext},
		{"ss with an obfs plugin", with(ss, "cipher", "aes-256-gcm", "plugin", "obfs", "mode", "http"), ErrTransportUnsupported},
		{"reality short-id not hex", with(vl, "short-id", "zz"), ErrMalformed},
		{"reality short-id too long", with(vl, "short-id", "0102030405060708ff"), ErrMalformed},
		{"vision over ws", with(vl, "short-id", "01", "flow", "xtls-rprx-vision", "network", "ws", "path", "/x"), ErrFlowUnsupported},
	} {
		if _, err := ProfileFromClashEntry(c.e); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
	if _, err := ProfileFromClashEntry(with(ss, "cipher", "aes-256-gcm")); err != nil {
		t.Errorf("plain aead ss refused: %v", err)
	}
	if _, err := ProfileFromClashEntry(with(vl, "short-id", "01", "flow", "xtls-rprx-vision")); err != nil {
		t.Errorf("reality vision over tcp refused: %v", err)
	}
}

func TestSIP008SkipsPlaintextAndCountsIt(t *testing.T) {
	body := `{"version":1,"servers":[
		{"server":"a.example.com","server_port":8388,"method":"aes-256-gcm","password":"p"},
		{"server":"n.example.com","server_port":8388,"method":"none","password":"p"}]}`
	profs, prov, err := ParseAny([]byte(body), "json")
	if err != nil {
		t.Fatal(err)
	}
	if len(profs) != 1 || profs[0].Outbound["server"] != "a.example.com" || prov.WarningCount != 1 {
		t.Errorf("profiles %v, warnings %d", profs, prov.WarningCount)
	}
}
