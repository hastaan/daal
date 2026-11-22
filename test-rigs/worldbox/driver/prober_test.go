package main

import (
	"crypto/tls"
	"net"
	"regexp"
	"testing"
	"time"
)

// goHello captures the ClientHello crypto/tls sends, as TLS records.
func goHello(t *testing.T, sni string, alpn []string) []byte {
	t.Helper()
	a, b := net.Pipe()
	go func() {
		c := tls.Client(a, &tls.Config{ServerName: sni, NextProtos: alpn, InsecureSkipVerify: true})
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		_ = c.Handshake()
	}()
	_ = b.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1<<14)
	var got []byte
	for {
		n, err := b.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil || len(got) >= 5 && len(got) >= 5+int(got[3])<<8|int(got[4]) {
			break
		}
	}
	a.Close()
	b.Close()
	return got
}

var ja4Shape = regexp.MustCompile(`^t1[0-3][di]\d{4}[0-9a-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$`)

func TestJA4OfGoHello(t *testing.T) {
	raw := goHello(t, "cover.example", []string{"h2", "http/1.1"})
	h, err := helloFromFlow(flowData{Payloads: [][]byte{raw[:7], raw[7:]}})
	if err != nil {
		t.Fatal(err)
	}
	if !ja4Shape.MatchString(h.JA4) || h.JA4[:4] != "t13d" || h.JA4[8:10] != "h2" {
		t.Fatalf("ja4 %q", h.JA4)
	}
	if h.SNI != "cover.example" || len(h.ALPN) != 2 || h.ALPN[1] != "http/1.1" {
		t.Fatalf("sni %q alpn %v", h.SNI, h.ALPN)
	}
	// No SNI, no ALPN.
	h2, err := helloFromFlow(flowData{Payloads: [][]byte{goHello(t, "", nil)}})
	if err != nil {
		t.Fatal(err)
	}
	if h2.JA4[3] != 'i' || h2.JA4[8:10] != "00" {
		t.Fatalf("ja4 without sni/alpn %q", h2.JA4)
	}
	// Section b only depends on ciphers: same client, same b.
	if h.JA4[11:23] != h2.JA4[11:23] {
		t.Errorf("cipher hash moved with SNI/ALPN: %s vs %s", h.JA4, h2.JA4)
	}
	if _, err := helloFromFlow(flowData{Payloads: [][]byte{raw[:40]}}); err == nil {
		t.Error("a truncated hello parsed")
	}
}

func TestJA4GreaseAndDiff(t *testing.T) {
	for _, v := range []uint16{0x0a0a, 0x1a1a, 0xfafa} {
		if !isGREASE(v) {
			t.Errorf("%04x not GREASE", v)
		}
	}
	if isGREASE(0x0a1a) || isGREASE(0x1301) {
		t.Error("false GREASE")
	}
	if d := ja4Diff(chromeJA4, chromeJA4); len(d) != 0 {
		t.Errorf("self diff %v", d)
	}
	if d := ja4Diff("t13d1516h2_8daaf6152771_000000000000", chromeJA4); len(d) != 2 {
		t.Errorf("diff %v", d)
	}
}
