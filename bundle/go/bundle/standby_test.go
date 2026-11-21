package bundle

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
)

// The vector in specs/relaypack-v1.md "`_standby` key". Cross-checked
// with an independent implementation (Python hashlib + int encoding)
// when it was written.
var standbyVectorKey = func() StandbyKeyBytes {
	var k StandbyKeyBytes
	for i := 0; i < StandbySaltLen; i++ {
		k[i] = byte(i)
	}
	copy(k[StandbySaltLen:], []byte{203, 0, 113, 20})
	return k
}()

const (
	standbyVectorText   = "000G40 R40M3 0E209 185WP 03H2G"
	standbyVectorCommit = "oLKATgHpOx6iddfCqnGCuDAi1XSE7ysXDZ1tUmE5HHY="
	standbyVectorAAAA   = "1:203:405:607:809:a0b:cb00:7114"
)

func TestStandbyKey_Vectors(t *testing.T) {
	k := standbyVectorKey
	if got := k.Text(); got != standbyVectorText {
		t.Fatalf("text %q, want %q", got, standbyVectorText)
	}
	if got := StandbyCommit(k); got != standbyVectorCommit {
		t.Fatalf("commit %q, want %q", got, standbyVectorCommit)
	}
	if got := k.AAAA().String(); got != standbyVectorAAAA {
		t.Fatalf("AAAA %q, want %q", got, standbyVectorAAAA)
	}
	if k.Address() != "203.0.113.20" {
		t.Fatalf("address %q", k.Address())
	}
	back, err := StandbyKeyFromBytes(net.ParseIP(standbyVectorAAAA))
	if err != nil || back != k {
		t.Fatalf("DNS form round trip: %v %v", back, err)
	}
	var ones StandbyKeyBytes
	for i := range ones {
		ones[i] = 0xff
	}
	if got := ones.Text(); got != "ZZZZZZ ZZZZZ ZZZZZ ZZZZZ ZZZZW" {
		t.Fatalf("all-ones text %q (the two trailing bits are zero)", got)
	}
}

func TestParseStandbyKeyText(t *testing.T) {
	ok := []string{
		standbyVectorText,
		strings.ReplaceAll(standbyVectorText, " ", ""),
		strings.ToLower(standbyVectorText),
		"OOOG4O-R4OM3-OE2O9-185WP-O3H2G", // O reads as 0
		"000g40 r40m3 0e209 185wp 03h2g",
	}
	for _, s := range ok {
		k, err := ParseStandbyKeyText(s)
		if err != nil || k != standbyVectorKey {
			t.Errorf("%q: %v", s, err)
		}
	}
	// I and L read as 1.
	a, _ := ParseStandbyKeyText("100000 00000 00000 00000 00000")
	b, _ := ParseStandbyKeyText("I00000 00000 00000 00000 00000")
	c, _ := ParseStandbyKeyText("l00000 00000 00000 00000 00000")
	if a != b || a != c {
		t.Fatal("I and L must read as 1")
	}
	bad := map[string]string{
		"25 symbols":             "000G40 R40M3 0E209 185WP 03H2",
		"27 symbols":             "000G40 R40M3 0E209 185WP 03H2G0",
		"U is not crockford":     "000G40 R40M3 0E209 185WP 03H2U",
		"non-zero trailing bits": "000G40 R40M3 0E209 185WP 03H2H",
		"punctuation":            "000G40.R40M3 0E209 185WP 03H2G",
		"non-ASCII":              "000G40 R40M3 0E209 185WP 03H2Ｇ",
		"empty":                  "",
	}
	for name, s := range bad {
		if _, err := ParseStandbyKeyText(s); !errors.Is(err, ErrStandbyKeyMalformed) {
			t.Errorf("%s (%q): err=%v", name, s, err)
		}
	}
	if _, err := StandbyKeyFromBytes(make([]byte, 15)); !errors.Is(err, ErrStandbyKeyMalformed) {
		t.Error("15 bytes accepted")
	}
}

func TestParseStandbyJSON_Shapes(t *testing.T) {
	sealed := `{"v":1,"mode":"sealed","commit":"` + standbyVectorCommit + `"}`
	open := `{"v":1,"mode":"open","server":"203.0.113.20"}`
	for _, s := range []string{sealed, open} {
		if _, err := ParseStandbyJSON([]byte(s)); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	bad := map[string]string{
		"version 2":          `{"v":2,"mode":"open","server":"203.0.113.20"}`,
		"unknown member":     `{"v":1,"mode":"open","server":"203.0.113.20","port":443}`,
		"sealed with server": `{"v":1,"mode":"sealed","commit":"` + standbyVectorCommit + `","server":""}`,
		"open with commit":   `{"v":1,"mode":"open","server":"203.0.113.20","commit":"` + standbyVectorCommit + `"}`,
		"missing commit":     `{"v":1,"mode":"sealed"}`,
		"unknown mode":       `{"v":1,"mode":"hint","server":"203.0.113.20"}`,
		"short commit":       `{"v":1,"mode":"sealed","commit":"AAAA"}`,
		"unpadded commit":    `{"v":1,"mode":"sealed","commit":"` + strings.TrimRight(standbyVectorCommit, "=") + `"}`,
		"leading zero":       `{"v":1,"mode":"open","server":"203.0.113.020"}`,
		"private":            `{"v":1,"mode":"open","server":"10.0.0.5"}`,
		"loopback":           `{"v":1,"mode":"open","server":"127.0.0.1"}`,
		"link-local":         `{"v":1,"mode":"open","server":"169.254.1.1"}`,
		"multicast":          `{"v":1,"mode":"open","server":"224.0.0.1"}`,
		"broadcast":          `{"v":1,"mode":"open","server":"255.255.255.255"}`,
		"unspecified":        `{"v":1,"mode":"open","server":"0.0.0.0"}`,
		"IPv6":               `{"v":1,"mode":"open","server":"2001:db8::1"}`,
		"host name":          `{"v":1,"mode":"open","server":"relay.example.com"}`,
		"v as string":        `{"v":"1","mode":"open","server":"203.0.113.20"}`,
		"not an object":      `[1]`,
	}
	for name, s := range bad {
		if _, err := ParseStandbyJSON([]byte(s)); !errors.Is(err, ErrStandbyMalformed) {
			t.Errorf("%s: err=%v", name, err)
		}
	}
}

func TestStandbyForRoute(t *testing.T) {
	ep := &Endpoint{V: 1, Server: "198.51.100.10", Port: 443}
	fsc := func(sb string) json.RawMessage {
		return json.RawMessage(`{"port":443,"_standby":` + sb + `}`)
	}
	open := `{"v":1,"mode":"open","server":"203.0.113.20"}`
	if _, err := StandbyForRoute("vless-reality", fsc(open), ep); err != nil {
		t.Fatal(err)
	}
	if _, err := StandbyForRoute("shadowsocks", fsc(open), ep); !errors.Is(err, ErrStandbyNotForFamily) {
		t.Fatalf("shadowsocks: %v", err)
	}
	if _, err := StandbyForRoute("vless-reality", fsc(open), nil); !errors.Is(err, ErrStandbyNotForFamily) {
		t.Fatalf("no endpoint: %v", err)
	}
	self := `{"v":1,"mode":"open","server":"198.51.100.10"}`
	if _, err := StandbyForRoute("vless-reality", fsc(self), ep); !errors.Is(err, ErrStandbyMalformed) {
		t.Fatalf("open standby equal to the endpoint: %v", err)
	}
	if _, err := StandbyForRoute("vless-reality", json.RawMessage(`{"port":443}`), ep); !errors.Is(err, ErrNoStandby) {
		t.Fatalf("absent: %v", err)
	}
}

func TestStandby_MatchesAndDialAddress(t *testing.T) {
	k := standbyVectorKey
	sb := SealedStandby(k)
	if sb.Commit != standbyVectorCommit {
		t.Fatal(sb.Commit)
	}
	if _, ok := sb.DialAddress(nil); ok {
		t.Fatal("a sealed standby without a key gave an address")
	}
	addr, ok := sb.DialAddress(&k)
	if !ok || addr != "203.0.113.20" {
		t.Fatalf("matching key: %q %v", addr, ok)
	}
	forged := k
	forged[15] = 99 // same salt, another address
	if sb.Matches(forged) {
		t.Fatal("a key for another address matched the commitment")
	}
	if _, ok := sb.DialAddress(&forged); ok {
		t.Fatal("a forged key gave an address")
	}
	open := OpenStandby("203.0.113.20")
	if addr, ok := (&open).DialAddress(nil); !ok || addr != "203.0.113.20" {
		t.Fatal("open standby")
	}
	if open.Matches(k) {
		t.Fatal("a key matched an open standby")
	}
	// A key that matches a commitment to a non-public address still
	// gives nothing: the publisher's tool cannot make one (NewStandbyKey
	// refuses), so this is not a key to act on.
	var priv StandbyKeyBytes
	copy(priv[StandbySaltLen:], []byte{10, 0, 0, 1})
	privSB := SealedStandby(priv)
	if _, ok := privSB.DialAddress(&priv); ok {
		t.Fatal("a private standby address was offered")
	}
	if _, err := NewStandbyKey("10.0.0.1", bytes.NewReader(make([]byte, 12))); err == nil {
		t.Fatal("NewStandbyKey took a private address")
	}
	nk, err := NewStandbyKey("203.0.113.20", bytes.NewReader([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}))
	if err != nil || nk != k {
		t.Fatalf("NewStandbyKey: %v", err)
	}
	// The JSON a publisher signs parses back to itself.
	raw, _ := json.Marshal(sb)
	if back, err := ParseStandbyJSON(raw); err != nil || *back != sb {
		t.Fatalf("round trip: %s %v", raw, err)
	}
}

// The amended endpoint rule: server may be the committed one or the
// standby; nothing else moves.
func TestCheckOutboundStandby(t *testing.T) {
	ep := &Endpoint{V: 1, Server: "198.51.100.10", Port: 443, ServerName: "cover.example", RealityPublicKey: "rpk"}
	ob := map[string]any{
		"type": "vless", "server": "198.51.100.10", "server_port": 443, "uuid": "u",
		"tls": map[string]any{"enabled": true, "server_name": "cover.example",
			"reality": map[string]any{"enabled": true, "public_key": "rpk", "short_id": "ab"}},
	}
	at := func(server string, port int) []byte {
		o := clone(t, ob)
		o["server"] = server
		o["server_port"] = port
		return mustJSON(t, o)
	}
	k := standbyVectorKey
	sealed := SealedStandby(k)
	open := OpenStandby("203.0.113.20")

	if err := CheckOutboundStandby("vless-reality", ep, nil, nil, at("198.51.100.10", 443)); err != nil {
		t.Fatalf("committed server: %v", err)
	}
	if err := CheckOutboundStandby("vless-reality", ep, &open, nil, at("203.0.113.20", 443)); err != nil {
		t.Fatalf("open standby: %v", err)
	}
	if err := CheckOutboundStandby("vless-reality", ep, &sealed, &k, at("203.0.113.20", 443)); err != nil {
		t.Fatalf("sealed standby with its key: %v", err)
	}
	refused := map[string]error{
		"sealed, no key":        CheckOutboundStandby("vless-reality", ep, &sealed, nil, at("203.0.113.20", 443)),
		"no standby at all":     CheckOutboundStandby("vless-reality", ep, nil, nil, at("203.0.113.20", 443)),
		"a third address":       CheckOutboundStandby("vless-reality", ep, &open, nil, at("203.0.113.99", 443)),
		"standby, another port": CheckOutboundStandby("vless-reality", ep, &open, nil, at("203.0.113.20", 8443)),
	}
	forged := k
	forged[15] = 99
	refused["key for another address"] = CheckOutboundStandby("vless-reality", ep, &sealed, &forged, at("203.0.113.99", 443))
	o := clone(t, ob)
	o["server"] = "203.0.113.20"
	o["tls"].(map[string]any)["reality"].(map[string]any)["public_key"] = "attacker"
	refused["standby, another key"] = CheckOutboundStandby("vless-reality", ep, &open, nil, mustJSON(t, o))
	for name, err := range refused {
		if !errors.Is(err, ErrEndpointMismatch) {
			t.Errorf("%s: err=%v", name, err)
		}
	}
	// Never for shadowsocks.
	ssEP := &Endpoint{V: 1, Server: "198.51.100.10", Port: 8388, SSMethod: "2022-blake3-aes-128-gcm",
		SSServerKeySHA256: SSServerKeyDigest("ipsk")}
	ss := mustJSON(t, map[string]any{"type": "shadowsocks", "server": "203.0.113.20", "server_port": 8388,
		"method": "2022-blake3-aes-128-gcm", "password": "ipsk:upsk"})
	if err := CheckOutboundStandby("shadowsocks", ssEP, &open, nil, ss); !errors.Is(err, ErrEndpointMismatch) {
		t.Fatalf("shadowsocks at the standby: %v", err)
	}
}
