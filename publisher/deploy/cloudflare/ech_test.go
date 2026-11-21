package cloudflare

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// buildECHConfig marshals one ECHConfig (RFC 9849 §4) for an X25519
// key: HKDF-SHA256 / AES-128-GCM, no extensions.
func buildECHConfig(id uint8, pub []byte, publicName string) []byte {
	var c []byte
	c = append(c, id)
	c = binary.BigEndian.AppendUint16(c, 0x0020)
	c = binary.BigEndian.AppendUint16(c, uint16(len(pub)))
	c = append(c, pub...)
	suites := []byte{0x00, 0x01, 0x00, 0x01}
	c = binary.BigEndian.AppendUint16(c, uint16(len(suites)))
	c = append(c, suites...)
	c = append(c, 0)
	c = append(c, byte(len(publicName)))
	c = append(c, publicName...)
	c = binary.BigEndian.AppendUint16(c, 0)
	out := binary.BigEndian.AppendUint16(nil, echVersion)
	out = binary.BigEndian.AppendUint16(out, uint16(len(c)))
	return append(out, c...)
}

func echList(configs ...[]byte) []byte {
	var body []byte
	for _, c := range configs {
		body = append(body, c...)
	}
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(body))), body...)
}

// newECHKey returns one ECHConfig and its private key.
func newECHKey(t *testing.T, publicName string) (config, priv []byte) {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return buildECHConfig(7, k.PublicKey().Bytes(), publicName), k.Bytes()
}

func testECHConfigList(t *testing.T, publicName string) []byte {
	cfg, _ := newECHKey(t, publicName)
	return echList(cfg)
}

func TestParseECHConfigList(t *testing.T) {
	cfg, _ := newECHKey(t, "cloudflare-ech.com")
	// A config of an unknown version first: skipped, not an error.
	unknown := []byte{0xfe, 0x0a, 0x00, 0x02, 0xaa, 0xbb}
	infos, err := ParseECHConfigList(echList(unknown, cfg))
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 1 || infos[0].PublicName != "cloudflare-ech.com" || infos[0].KEMID != 0x0020 || infos[0].ConfigID != 7 {
		t.Fatalf("infos = %+v", infos)
	}
	bad := [][]byte{
		nil, {0x00}, {0x00, 0x05, 0x01}, echList(unknown),
		echList(cfg[:len(cfg)-1]), append(echList(cfg), 0),
	}
	for i, b := range bad {
		if _, err := ParseECHConfigList(b); err == nil {
			t.Errorf("bad[%d] parsed", i)
		}
	}
	if !strings.Contains(ECHConfigPEM(echList(cfg)), "BEGIN ECH CONFIGS") {
		t.Error("PEM type")
	}
}

// dnsAnswer builds a response to q carrying one HTTPS record whose
// rdata is rd.
func dnsAnswer(q []byte, rcode byte, rd []byte) []byte {
	m := append([]byte(nil), q[:2]...)
	an := byte(0)
	if rd != nil {
		an = 1
	}
	m = append(m, 0x81, 0x80|rcode, 0, 1, 0, an, 0, 0, 0, 0)
	m = append(m, q[12:]...) // question
	if rd != nil {
		m = append(m, 0xc0, 0x0c, 0, dnsTypeHTTPS, 0, 1, 0, 0, 1, 0x2c)
		m = binary.BigEndian.AppendUint16(m, uint16(len(rd)))
		m = append(m, rd...)
	}
	return m
}

func httpsRData(prio uint16, ech []byte) []byte {
	rd := binary.BigEndian.AppendUint16(nil, prio)
	rd = append(rd, 0) // target "."
	if prio == 0 {
		return rd
	}
	rd = append(rd, 0, 1, 0, 3, 2, 'h', '2') // alpn=h2
	if ech != nil {
		rd = binary.BigEndian.AppendUint16(rd, svcParamECH)
		rd = binary.BigEndian.AppendUint16(rd, uint16(len(ech)))
		rd = append(rd, ech...)
	}
	return rd
}

func TestEchFromDNSAnswer(t *testing.T) {
	list := testECHConfigList(t, "cloudflare-ech.com")
	q, id, err := buildHTTPSQuery("relay.example.com")
	if err != nil {
		t.Fatal(err)
	}
	got, err := echFromDNSAnswer(dnsAnswer(q, 0, httpsRData(1, list)), id)
	if err != nil || string(got) != string(list) {
		t.Fatalf("got %x %v", got, err)
	}
	if got, err := echFromDNSAnswer(dnsAnswer(q, 0, httpsRData(1, nil)), id); err != nil || got != nil {
		t.Errorf("no ech param: %x %v", got, err)
	}
	if got, err := echFromDNSAnswer(dnsAnswer(q, 0, httpsRData(0, nil)), id); err != nil || got != nil {
		t.Errorf("alias mode: %x %v", got, err)
	}
	if _, err := echFromDNSAnswer(dnsAnswer(q, 3, nil), id); err == nil {
		t.Error("NXDOMAIN accepted")
	}
	if _, err := echFromDNSAnswer(dnsAnswer(q, 0, httpsRData(1, list)), id+1); err == nil {
		t.Error("answer to another query accepted")
	}
	// Truncations never panic.
	full := dnsAnswer(q, 0, httpsRData(1, list))
	for i := 0; i < len(full); i++ {
		_, _ = echFromDNSAnswer(full[:i], id)
	}
	// Params out of order are refused.
	rd := binary.BigEndian.AppendUint16(nil, 1)
	rd = append(rd, 0, 0, 5, 0, 1, 0xaa, 0, 1, 0, 1, 2)
	if _, err := echFromDNSAnswer(dnsAnswer(q, 0, rd), id); err == nil {
		t.Error("out-of-order params accepted")
	}
}

func TestDoHECHFetcher(t *testing.T) {
	list := testECHConfigList(t, "cloudflare-ech.com")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/dns-message" {
			http.Error(w, "accept", 400)
			return
		}
		q, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		if err != nil || len(q) < 12 {
			http.Error(w, "dns", 400)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(dnsAnswer(q, 0, httpsRData(1, list)))
	}))
	defer srv.Close()
	dead := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "down", 503) }))
	defer dead.Close()

	f := &DoHECHFetcher{Resolvers: []string{dead.URL + "/dns-query", srv.URL + "/dns-query"}, Client: srv.Client()}
	got, resolver, err := f.FetchECH(context.Background(), "relay.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(list) || resolver != srv.URL+"/dns-query" {
		t.Fatalf("got %x from %s", got, resolver)
	}
	p := ReadECHPosture(context.Background(), f, "relay.example.com", 1)
	p.ZoneSetting = "on"
	if !p.Published || p.PublicName != "cloudflare-ech.com" || !p.NameHidden("relay.example.com") {
		t.Errorf("posture = %+v", p)
	}
	if _, _, err := (&DoHECHFetcher{Resolvers: []string{"http://plain.example/dns-query"}}).FetchECH(context.Background(), "a.example.com"); err == nil {
		t.Error("a plain-HTTP resolver was used")
	}
}

func TestECHPosture_NameHidden(t *testing.T) {
	base := ECHPosture{ZoneSetting: "on", Published: true, PublicName: "cloudflare-ech.com"}
	if !base.NameHidden("a.example.com") {
		t.Fatal("base")
	}
	for name, p := range map[string]ECHPosture{
		"zone off":      {ZoneSetting: "off", Published: true, PublicName: "cloudflare-ech.com"},
		"not published": {ZoneSetting: "on", PublicName: "cloudflare-ech.com"},
		"outer is name": {ZoneSetting: "on", Published: true, PublicName: "a.example.com"},
		"unread":        {},
	} {
		if p.NameHidden("a.example.com") {
			t.Errorf("%s: says hidden", name)
		}
	}
}
