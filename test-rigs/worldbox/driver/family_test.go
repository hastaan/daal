package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The family-side instruments are themselves claims; these pin them
// without building a world.

func TestWireVerdict(t *testing.T) {
	kib := func(n int64) WireCount { return WireCount{Packets: n, Bytes: n * 1024} }
	cases := []struct {
		name string
		s    WireSample
		want string
	}{
		{"carried on its own endpoint", WireSample{"tuic.new": {1, 1200}, "tuic.in": kib(100), "tuic.out": kib(300)}, Pass},
		{"reached the relay, nothing useful came back", WireSample{"tuic.new": {2, 2400}, "tuic.in": kib(4), "tuic.out": kib(3)}, Blocked},
		{"censor dropped it: attempts only", WireSample{"tuic.new": {3, 3600}, "tuic.in": kib(3)}, Blocked},
		{"never attempted", WireSample{"tuic.in": {}, "tuic.out": {}}, "silent"},
		// The failure this instrument exists for: the session "passes"
		// end to end, but the bytes rode another family's endpoint.
		{"a tuic session that opened a vless connection", WireSample{"tuic.in": kib(1), "tuic.out": kib(1), "vless-reality.new": {1, 60}, "vless-reality.in": kib(100), "vless-reality.out": kib(300)}, Fail},
		{"a flow to a port that is no family's", WireSample{"tuic.new": {1, 1200}, "tuic.in": kib(100), "tuic.out": kib(300), "other.new": {1, 60}}, Fail},
		// Late packets of the PREVIOUS session are not new flows.
		{"stragglers of the previous session", WireSample{"tuic.new": {1, 1200}, "tuic.in": kib(100), "tuic.out": kib(300), "hysteria2.out": {2, 120}, "anytls.in": {1, 40}}, Pass},
	}
	for _, c := range cases {
		if got, detail := c.s.Verdict("tuic", 256<<10); got != c.want {
			t.Errorf("%s: verdict %q (%s), want %q", c.name, got, detail, c.want)
		}
	}
}

func TestParseWire(t *testing.T) {
	out := `{"nftables": [{"metainfo": {"version": "1.1.6"}}, {"counter": {"family": "inet", "name": "tuic.in", "table": "wb_wire", "handle": 2, "packets": 7, "bytes": 900}}]}`
	s, err := parseWire([]byte(out))
	if err != nil || s["tuic.in"] != (WireCount{7, 900}) {
		t.Fatalf("parseWire = %v, %v", s, err)
	}
	if _, err := parseWire([]byte(`{"nftables": []}`)); err == nil {
		t.Fatal("an empty counter list must be an error: a tap that is not installed must not read as 'no traffic'")
	}
}

// A forged credential must keep its shape (or the client refuses the
// config and the relay is never asked), differ from the original, and
// leave every other field alone.
func TestForgeFieldKeepsShapeAndTouchesOneField(t *testing.T) {
	creds := map[string]any{
		"name":               "r1",
		"vless_uuid":         "bbcb1f70-05f7-45f0-b2aa-d7b020828deb",
		"tuic_uuid":          "abd80709-e2c1-4005-8a18-7fcc9e44fda2",
		"reality_short_id":   "41fe406d",
		"hy2_password":       "PRF8kvdDSGEk7xeVhf92Aw",
		"naive_password":     "rXdsDmIGKTjFLsCrD2XDPA",
		"tuic_password":      "OS4i5dwLlYwjb11SJMtKzQ",
		"anytls_password":    "vvHSHfNtnQhGZQPIAAAAAA",
		"ws_path":            "/r1/f2fdd84e",
		"ss_password":        "xwwEUBOfYDsxemaJ0p1T4Q==:Zm9vYmFyYmF6cXV4MTIzNA==",
		"reality_public_key": "U8_CBjOHwHf7K3uNx0yq4b1hJ2m5p8s1v4y7B0E3H6I",
		"tls_cert_sha256":    "qcQ6NDY2j6f4pHQmZm9vYmFyYmF6cXV4MTIzNDU2Nzg=",
	}
	for field, orig := range creds {
		if field == "name" {
			continue
		}
		forged, err := forgeField(creds, field)
		if err != nil {
			t.Errorf("%s: %v", field, err)
			continue
		}
		got := forged[field].(string)
		if got == orig || len(got) != len(orig.(string)) {
			t.Errorf("%s: forged %q from %q — must differ and keep its length", field, got, orig)
		}
		for k, v := range creds {
			if k != field && forged[k] != v {
				t.Errorf("forging %s also changed %s", field, k)
			}
		}
	}
	// the shared half of a shadowsocks credential is the box's, not the recipient's
	f, _ := forgeField(creds, "ss_password")
	if !strings.HasPrefix(f["ss_password"].(string), "xwwEUBOfYDsxemaJ0p1T4Q==:") {
		t.Errorf("ss_password: the box iPSK half must be left alone, got %q", f["ss_password"])
	}
	if _, err := forgeField(creds, "no_such_field"); err == nil {
		t.Error("forging a field the relay did not report must be an error, not a silent no-op")
	}
}

// The lab resolver and the probe's lookup must agree with each other and
// with a re-encoding resolver in between (uncompressed owner names).
func TestDNSRoundTrip(t *testing.T) {
	q := dnsQuery(0x1234, AskerName)
	resp := answerPublicDNS(q, "192.0.2.2", "test")
	if ip, err := dnsAnswerA(resp, 0x1234); err != nil || ip != "192.0.2.2" {
		t.Fatalf("asker lookup = %q, %v", ip, err)
	}
	resp = answerPublicDNS(dnsQuery(7, BlockedName), "192.0.2.2", "test")
	if ip, err := dnsAnswerA(resp, 7); err != nil || ip != TargetIP {
		t.Fatalf("site lookup = %q, %v", ip, err)
	}
	if _, err := dnsAnswerA(resp, 8); err == nil {
		t.Fatal("an answer to a different query id must not be accepted")
	}
	if _, err := dnsAnswerA(answerPublicDNS(dnsQuery(9, "elsewhere.example"), "192.0.2.2", "test"), 9); err == nil {
		t.Fatal("an unknown name must not resolve")
	}
	// the same answer with the owner name spelled out instead of a pointer
	q = dnsQuery(5, BlockedName)
	long := append([]byte{}, q...)
	long[2], long[7] = 0x84, 1
	long = append(long, q[12:len(q)-4]...) // owner name, uncompressed
	long = append(long, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 192, 0, 2, 80)
	if ip, err := dnsAnswerA(long, 5); err != nil || ip != TargetIP {
		t.Fatalf("uncompressed answer = %q, %v", ip, err)
	}
}

func TestReadPackSeesDroppedRoutes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.sbp")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	put := func(name, body string) {
		w, _ := zw.Create(name)
		_, _ = w.Write([]byte(body))
	}
	put("manifest.json", `{"spec_version":5,"routes":[
	  {"id":"r1","transport_family":"vless-reality","config_path":"profiles/r1.json","family_specific_config":{"port":443}},
	  {"id":"r6","transport_family":"anytls","config_path":"profiles/r6.json","family_specific_config":{"port":8447}}]}`)
	put("profiles/r1.json", `{"type":"vless","server":"203.0.113.10","server_port":443}`)
	put("profiles/r6.json", `{"_daal_unavailable":{"family":"anytls","reason":"no credential"}}`)
	_ = zw.Close()
	_ = f.Close()
	v, err := ReadPack(path)
	if err != nil {
		t.Fatal(err)
	}
	if v.SpecVersion != 5 || len(v.Routes) != 2 {
		t.Fatalf("pack view = %+v", v)
	}
	if r := v.Routes[0]; r.Type != "vless" || r.ServerPort != 443 || r.Unavailable != "" {
		t.Errorf("r1 = %+v", r)
	}
	if r := v.Routes[1]; r.Type != "" || r.Unavailable != "no credential" {
		t.Errorf("r6 must read as dropped, got %+v", r)
	}
}
