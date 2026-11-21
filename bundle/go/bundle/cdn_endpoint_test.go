package bundle

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// testECHConfigList is a structurally valid ECHConfigList (a 2-byte
// length then that many bytes). Its contents are not a real key; the
// commitment only carries and compares the bytes.
var testECHConfigList = []byte{0x00, 0x06, 0xfe, 0x0d, 0x00, 0x02, 0xab, 0xcd}

func cdnCase(t *testing.T) (CDNEndpoint, map[string]any, string) {
	t.Helper()
	rootPEM, rootPin := testCert(t, nil, []string{"root.example"})
	ep := CDNEndpoint{
		V: 1, Server: "edge7.example.com", Port: 443, ServerName: "edge7.example.com",
		CDN: CDNCloudflare, EdgeSeeds: []string{"104.16.0.0/13", "2606:4700::/32"},
		ECHConfig:      base64.StdEncoding.EncodeToString(testECHConfigList),
		TLSRootsSHA256: []string{rootPin},
	}
	ob := map[string]any{
		"type": "vless", "tag": "active", "server": "104.16.1.2", "server_port": 443,
		"uuid": "11111111-2222-3333-4444-555555555555",
		"transport": map[string]any{"type": "ws", "path": "/0123456789abcdef",
			"headers": map[string]any{"Host": "edge7.example.com"}},
		"tls": map[string]any{"enabled": true, "server_name": "edge7.example.com",
			"utls":        map[string]any{"enabled": true, "fingerprint": "chrome"},
			"certificate": []any{rootPEM},
			"ech":         map[string]any{"enabled": true, "config": toAny(ep.ECHConfigPEM())}},
	}
	return ep, ob, rootPEM
}

func toAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func setPath(t *testing.T, m map[string]any, path string, v any) map[string]any {
	t.Helper()
	o := clone(t, m)
	cur := o
	parts := strings.Split(path, ".")
	for _, p := range parts[:len(parts)-1] {
		next, ok := cur[p].(map[string]any)
		if !ok {
			t.Fatalf("no %q in %s", p, path)
		}
		cur = next
	}
	if v == nil {
		delete(cur, parts[len(parts)-1])
	} else {
		cur[parts[len(parts)-1]] = v
	}
	return o
}

func TestCheckCDNOutbound_GenuineAndEveryRewrite(t *testing.T) {
	ep, ob, _ := cdnCase(t)
	if err := ep.Validate("websocket-tls"); err != nil {
		t.Fatal(err)
	}
	if err := CheckCDNOutbound(&ep, mustJSON(t, ob)); err != nil {
		t.Fatalf("genuine: %v", err)
	}
	// IPv6 edge inside the second seed.
	if err := CheckCDNOutbound(&ep, mustJSON(t, setPath(t, ob, "server", "2606:4700::6810:1"))); err != nil {
		t.Fatalf("IPv6 edge: %v", err)
	}
	// Credentials are free: uuid and ws path.
	for path, v := range map[string]any{"uuid": "99999999-0000-0000-0000-000000000000", "transport.path": "/other"} {
		if err := CheckCDNOutbound(&ep, mustJSON(t, setPath(t, ob, path, v))); err != nil {
			t.Fatalf("credential %s: %v", path, err)
		}
	}
	otherPEM, _ := testCert(t, nil, []string{"evil.example"})
	rewrites := map[string]map[string]any{
		"edge outside the seeds":    setPath(t, ob, "server", "198.51.100.66"),
		"host name as server":       setPath(t, ob, "server", "edge7.example.com"),
		"port":                      setPath(t, ob, "server_port", 8443),
		"type":                      setPath(t, ob, "type", "trojan"),
		"tls name":                  setPath(t, ob, "tls.server_name", "other.example.com"),
		"ws Host":                   setPath(t, ob, "transport.headers", map[string]any{"Host": "other.example.com"}),
		"no ws Host":                setPath(t, ob, "transport.headers", nil),
		"two Hosts":                 setPath(t, ob, "transport.headers", map[string]any{"Host": "edge7.example.com", "host": "other.example.com"}),
		"Host list":                 setPath(t, ob, "transport.headers", map[string]any{"Host": []any{"edge7.example.com", "x.example"}}),
		"not ws":                    setPath(t, ob, "transport.type", "httpupgrade"),
		"no transport":              setPath(t, ob, "transport", nil),
		"tls off":                   setPath(t, ob, "tls.enabled", false),
		"insecure":                  setPath(t, ob, "tls.insecure", true),
		"disable_sni":               setPath(t, ob, "tls.disable_sni", true),
		"key pin":                   setPath(t, ob, "tls.certificate_public_key_sha256", []any{"AAAA"}),
		"certificate_path":          setPath(t, ob, "tls.certificate_path", "/sdcard/ca.pem"),
		"certificate_directory":     setPath(t, ob, "tls.certificate_directory_path", "/sdcard"),
		"no root":                   setPath(t, ob, "tls.certificate", nil),
		"unsigned root":             setPath(t, ob, "tls.certificate", []any{otherPEM}),
		"unsigned root beside":      setPath(t, ob, "tls.certificate", toAny(append(stringList(ob["tls"].(map[string]any)["certificate"]), otherPEM))),
		"ECH off, no plain allowed": setPath(t, ob, "tls.ech", nil),
		"ECH by DNS":                setPath(t, ob, "tls.ech", map[string]any{"enabled": true}),
		"ECH other config":          setPath(t, ob, "tls.ech.config", toAny((&CDNEndpoint{ECHConfig: base64.StdEncoding.EncodeToString([]byte{0, 1, 9})}).ECHConfigPEM())),
		"ECH config_path":           setPath(t, ob, "tls.ech.config_path", "/sdcard/ech.pem"),
		"ECH query name":            setPath(t, ob, "tls.ech.query_server_name", "edge7.example.com"),
		"reality on":                setPath(t, ob, "tls.reality", map[string]any{"enabled": true, "public_key": "k"}),
		"detour":                    setPath(t, ob, "detour", "direct"),
		"server_ports":              setPath(t, ob, "server_ports", []any{"1000:2000"}),
		"folded server":             setPath(t, ob, "ſerver", "198.51.100.66"),
		"folded tls key":            setPath(t, ob, "tls.Insecure", true),
		"folded ech key":            setPath(t, ob, "tls.ech.Config_path", "/x"),
		"folded transport key":      setPath(t, ob, "transport.Type", "grpc"),
	}
	for name, o := range rewrites {
		if err := CheckCDNOutbound(&ep, mustJSON(t, o)); !errors.Is(err, ErrEndpointMismatch) {
			t.Errorf("%s: err=%v", name, err)
		}
	}
	// The signed plain_fallback flag allows ECH off — and only that.
	plain := ep
	plain.PlainFallback = true
	if err := CheckCDNOutbound(&plain, mustJSON(t, setPath(t, ob, "tls.ech", nil))); err != nil {
		t.Fatalf("plain hello with the signed flag: %v", err)
	}
	if err := CheckCDNOutbound(&plain, mustJSON(t, setPath(t, ob, "tls.ech", map[string]any{"enabled": true}))); !errors.Is(err, ErrEndpointMismatch) {
		t.Fatalf("ECH by DNS with the flag: %v", err)
	}
}

func TestCDNEndpointValidate(t *testing.T) {
	ep, _, _ := cdnCase(t)
	mut := map[string]func(e *CDNEndpoint){
		"version 2":    func(e *CDNEndpoint) { e.V = 2 },
		"other cdn":    func(e *CDNEndpoint) { e.CDN = "fastly" },
		"IP server":    func(e *CDNEndpoint) { e.Server, e.ServerName = "104.16.1.2", "104.16.1.2" },
		"one label":    func(e *CDNEndpoint) { e.Server, e.ServerName = "localhost", "localhost" },
		"upper case":   func(e *CDNEndpoint) { e.Server, e.ServerName = "Edge.example.com", "Edge.example.com" },
		"trailing dot": func(e *CDNEndpoint) { e.Server, e.ServerName = "edge.example.com.", "edge.example.com." },
		"domestic":     func(e *CDNEndpoint) { e.Server, e.ServerName = "edge.example.ir", "edge.example.ir" },
		"name differs": func(e *CDNEndpoint) { e.ServerName = "other.example.com" },
		"port 0":       func(e *CDNEndpoint) { e.Port = 0 },
		"no seeds":     func(e *CDNEndpoint) { e.EdgeSeeds = nil },
		"nine seeds": func(e *CDNEndpoint) {
			e.EdgeSeeds = strings.Split("1.0.0.0/8 2.0.0.0/8 3.0.0.0/8 4.0.0.0/8 5.0.0.0/8 6.0.0.0/8 7.0.0.0/8 8.0.0.0/8 9.0.0.0/8", " ")
		},
		"host bits set":  func(e *CDNEndpoint) { e.EdgeSeeds = []string{"104.16.0.1/13"} },
		"private seed":   func(e *CDNEndpoint) { e.EdgeSeeds = []string{"10.0.0.0/8"} },
		"repeated seed":  func(e *CDNEndpoint) { e.EdgeSeeds = []string{"104.16.0.0/13", "104.16.0.0/13"} },
		"bare address":   func(e *CDNEndpoint) { e.EdgeSeeds = []string{"104.16.0.1"} },
		"ech bad length": func(e *CDNEndpoint) { e.ECHConfig = base64.StdEncoding.EncodeToString([]byte{0, 9, 1}) },
		"ech too big": func(e *CDNEndpoint) {
			b := make([]byte, 600)
			b[0], b[1] = 0x02, 0x56
			e.ECHConfig = base64.StdEncoding.EncodeToString(b)
		},
		"ech not base64":    func(e *CDNEndpoint) { e.ECHConfig = "!!" },
		"no roots":          func(e *CDNEndpoint) { e.TLSRootsSHA256 = nil },
		"root not a digest": func(e *CDNEndpoint) { e.TLSRootsSHA256 = []string{"AAAA"} },
		"root repeated":     func(e *CDNEndpoint) { e.TLSRootsSHA256 = []string{e.TLSRootsSHA256[0], e.TLSRootsSHA256[0]} },
	}
	for name, f := range mut {
		e := ep
		e.EdgeSeeds = append([]string(nil), ep.EdgeSeeds...)
		e.TLSRootsSHA256 = append([]string(nil), ep.TLSRootsSHA256...)
		f(&e)
		if err := e.Validate("websocket-tls"); !errors.Is(err, ErrCDNEndpointMalformed) {
			t.Errorf("%s: err=%v", name, err)
		}
	}
	if err := ep.Validate("vless-reality"); !errors.Is(err, ErrCDNEndpointMalformed) {
		t.Fatalf("other family: %v", err)
	}
	// Parsing is strict: an unknown member is a commitment this build
	// would not fully enforce.
	raw := mustJSON(t, ep)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	m["edge_pick"] = "fastest"
	fsc := mustJSON(t, map[string]any{"_relaypack": map[string]any{}, CDNEndpointKey: m})
	if _, err := ParseCDNEndpoint("websocket-tls", fsc); !errors.Is(err, ErrCDNEndpointMalformed) {
		t.Fatalf("unknown member: %v", err)
	}
	if !HasCDNEndpoint(fsc) {
		t.Fatal("HasCDNEndpoint")
	}
	good := mustJSON(t, map[string]any{CDNEndpointKey: ep})
	if got, err := ParseCDNEndpoint("websocket-tls", good); err != nil || got.Server != ep.Server {
		t.Fatalf("good: %v", err)
	}
	if _, err := ParseCDNEndpoint("websocket-tls", json.RawMessage(`{"port":443}`)); !errors.Is(err, ErrNoCDNEndpoint) {
		t.Fatalf("absent: %v", err)
	}
	if !IsCDNCommitment(mustJSON(t, ep)) || IsCDNCommitment(mustJSON(t, Endpoint{V: 1, Server: "x", Port: 1})) {
		t.Fatal("IsCDNCommitment")
	}
}

// The profile wrapper: an outbound that builds before the CDN route
// cannot see, and this build unwraps.
func TestWrapCDNOutbound(t *testing.T) {
	ep, ob, _ := cdnCase(t)
	raw := mustJSON(t, ob)
	wrapped, err := WrapCDNOutbound(raw)
	if err != nil {
		t.Fatal(err)
	}
	if ProfileOutboundType(wrapped) != "" || !ProfileUnavailable(wrapped) {
		t.Fatalf("the wrapper must look like no outbound, marked unavailable: %s", wrapped)
	}
	inner, ok := CDNProfileOutbound(wrapped)
	if !ok || CheckCDNOutbound(&ep, inner) != nil {
		t.Fatalf("unwrap: %v", ok)
	}
	if top, ok := CDNProfileOutbound(raw); !ok || string(top) != string(raw) {
		t.Fatal("a top-level outbound is its own outbound")
	}
	if _, ok := CDNProfileOutbound([]byte(`{"port":443,"_relaypack":{}}`)); ok {
		t.Fatal("skeleton profile has no outbound")
	}
	if _, err := WrapCDNOutbound([]byte(`{"port":443}`)); err == nil {
		t.Fatal("wrapped a non-outbound")
	}
}

func TestMergeCDNEndpoint(t *testing.T) {
	ep, ob, rootPEM := cdnCase(t)
	device := mustJSON(t, ob)

	// The publisher moved the route to a new name in the zone, a new ECH
	// config and new seeds; the root stays.
	moved := ep
	moved.Server, moved.ServerName = "edge9.example.com", "edge9.example.com"
	moved.EdgeSeeds = []string{"172.64.0.0/13"}
	moved.ECHConfig = base64.StdEncoding.EncodeToString([]byte{0x00, 0x02, 0x01, 0x02})
	out, err := MergeCDNEndpoint(&moved, device)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckCDNOutbound(&moved, out); err != nil {
		t.Fatalf("merged outbound does not match: %v", err)
	}
	var got map[string]any
	_ = json.Unmarshal(out, &got)
	if got["uuid"] != ob["uuid"] || got["transport"].(map[string]any)["path"] != "/0123456789abcdef" {
		t.Fatalf("credentials were not kept: %s", out)
	}
	if got["server"] != "172.64.0.1" {
		t.Fatalf("edge address outside the new seeds must be replaced: %v", got["server"])
	}
	// Still inside: kept.
	same, err := MergeCDNEndpoint(&ep, device)
	if err != nil || !strings.Contains(string(same), `"server":"104.16.1.2"`) {
		t.Fatalf("edge kept: %s %v", same, err)
	}
	// A root that is no longer signed cannot be kept, and none left is a
	// new file.
	_, otherPin := testCert(t, nil, []string{"other-root.example"})
	rerooted := ep
	rerooted.TLSRootsSHA256 = []string{otherPin}
	if _, err := MergeCDNEndpoint(&rerooted, device); !errors.Is(err, ErrEndpointMismatch) {
		t.Fatalf("no signed root left: %v", err)
	}
	_ = rootPEM
	// No ECH, plain allowed: ECH removed.
	plain := ep
	plain.ECHConfig, plain.PlainFallback = "", true
	if out, err := MergeCDNEndpoint(&plain, device); err != nil || strings.Contains(string(out), `"ech"`) {
		t.Fatalf("plain: %s %v", out, err)
	}
	if _, err := MergeCDNEndpoint(&ep, []byte(`{"port":443}`)); !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("no credentials: %v", err)
	}
}
