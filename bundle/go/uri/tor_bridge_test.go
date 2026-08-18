package uri

import "testing"

// Bridge lines as BridgeDB, the email autoresponder and the Telegram bot
// actually hand them out. Every one of these is a shape a user will
// paste, and a parser that mangles any of them produces a route that
// cannot authenticate.
func TestParseTorBridgeLineRealShapes(t *testing.T) {
	cases := []struct {
		name  string
		in    string
		tport string
		host  string
		port  int
		fp    string
	}{
		{"obfs4", "obfs4 38.229.1.78:80 0BAC39417268B96B9F514E7F63FA6FBA1A788955 cert=VwEFpk9F/UN9JED7XriIvK1Bcw+YHYYRIkc/NBjZ2Ryn0/Wo3v0KG2NuLQ== iat-mode=1", "obfs4", "38.229.1.78", 80, "0BAC39417268B96B9F514E7F63FA6FBA1A788955"},
		{"webtunnel", "webtunnel 192.0.2.3:443 054BF06CA6B0E6E1C05C1C0D0A0C7DCA1E8E5F0A url=https://sub.example.com/path ver=0.0.1", "webtunnel", "192.0.2.3", 443, "054BF06CA6B0E6E1C05C1C0D0A0C7DCA1E8E5F0A"},
		{"snowflake", "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://1098762253.rsc.cdn77.org/ front=www.phpmyadmin.net ice=stun:stun.l.google.com:19302", "snowflake", "192.0.2.3", 80, "2B280B23E1107BB62ABFC40DDCC8824814F80A72"},
		{"meek_lite", "meek_lite 192.0.2.20:80 97700DFE9F483596DDA6264C4D7DF7641E1E39CE url=https://meek.azureedge.net/ front=ajax.aspnetcdn.com", "meek_lite", "192.0.2.20", 80, "97700DFE9F483596DDA6264C4D7DF7641E1E39CE"},
		// No transport name at the head: a vanilla bridge, dialled by
		// tor directly. Treating "1.2.3.4:443" as a transport name (the
		// pre-Wave-5 behaviour) silently produced a route asking for a
		// pluggable transport called "1.2.3.4:443".
		{"vanilla", "78.47.152.16:9001 ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD", "", "78.47.152.16", 9001, "ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD"},
		{"vanilla-no-fingerprint", "78.47.152.16:9001", "", "78.47.152.16", 9001, ""},
		// torrc fragments get pasted at least as often as bare lines.
		{"torrc-keyword", "Bridge obfs4 1.2.3.4:443 ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD cert=x iat-mode=0", "obfs4", "1.2.3.4", 443, "ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD"},
		// IPv6 bridges are bracketed; a naive LastIndex(":") split
		// turns "[2001:db8::1]:9001" into host "[2001:db8:" .
		{"ipv6", "obfs4 [2001:db8::1]:9001 ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD cert=x iat-mode=0", "obfs4", "2001:db8::1", 9001, "ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, err := ParseTorBridgeLine(c.in)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if b.Transport != c.tport {
				t.Errorf("transport = %q, want %q", b.Transport, c.tport)
			}
			if b.Host != c.host || b.Port != c.port {
				t.Errorf("endpoint = %s:%d, want %s:%d", b.Host, b.Port, c.host, c.port)
			}
			if b.Fingerprint != c.fp {
				t.Errorf("fingerprint = %q, want %q", b.Fingerprint, c.fp)
			}
		})
	}
}

// Raw is what tor receives. It must preserve every transport-specific
// parameter verbatim: obfs4's cert= is base64 whose '+', '/' and '='
// are significant, and snowflake's url=/front= are URLs.
func TestBridgeRawIsByteExact(t *testing.T) {
	in := "obfs4 38.229.1.78:80 0BAC39417268B96B9F514E7F63FA6FBA1A788955 cert=VwEFpk9F/UN9JED7XriIvK1Bcw+YHYYRIkc/NBjZ2Ryn0/Wo3v0KG2NuLQ== iat-mode=1"
	b, err := ParseTorBridgeLine(in)
	if err != nil {
		t.Fatal(err)
	}
	if b.Raw != in {
		t.Errorf("Raw\n got %q\nwant %q", b.Raw, in)
	}
	// And the "Bridge " keyword must be stripped: tor's --Bridge takes
	// the value, not the directive.
	b2, err := ParseTorBridgeLine("Bridge " + in)
	if err != nil {
		t.Fatal(err)
	}
	if b2.Raw != in {
		t.Errorf("keyword not stripped: %q", b2.Raw)
	}
}

func TestParseTorBridgeLineRejects(t *testing.T) {
	for _, in := range []string{
		"",
		"obfs4",              // transport, no address
		"obfs4 notanaddress", // no port
		"obfs4 1.2.3.4:notaport",
		"obfs4 1.2.3.4:99999", // out of range
		"obfs4 :443",          // no host
	} {
		if _, err := ParseTorBridgeLine(in); err == nil {
			t.Errorf("accepted malformed line %q", in)
		}
	}
}

// A mangled line in a pasted set must not destroy the good ones —
// bridge sets arrive through email clients that wrap long lines.
func TestMalformedLinesAreCountedNotFatal(t *testing.T) {
	body := []byte(`# my bridges
obfs4 1.2.3.4:443 ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD cert=x iat-mode=0

obfs4 garbage
obfs4 5.6.7.8:443 1111111111111111111111111111111111111111 cert=y iat-mode=0
`)
	profs, prov, err := parseTorBridges(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(profs) != 2 {
		t.Fatalf("want 2 good profiles, got %d", len(profs))
	}
	if prov.WarningCount != 1 {
		t.Errorf("WarningCount = %d, want 1", prov.WarningCount)
	}
}

// UseBridges must lead. Without it tor ignores every Bridge line and
// connects to the public Tor network — for a user who asked for a
// bridge that is a privacy failure, not a fallback.
func TestOutboundAlwaysSetsUseBridges(t *testing.T) {
	b, err := ParseTorBridgeLine("obfs4 1.2.3.4:443 ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD cert=x")
	if err != nil {
		t.Fatal(err)
	}
	ob := TorOutboundForBridge(b)
	if ob["type"] != "tor" {
		t.Fatalf("type = %v", ob["type"])
	}
	args := ob["extra_args"].([]string)
	if args[0] != "--UseBridges" || args[1] != "1" {
		t.Fatalf("argv must open with --UseBridges 1: %q", args)
	}
	if args[2] != "--Bridge" || args[3] != b.Raw {
		t.Fatalf("bridge arg wrong: %q", args)
	}
	// No device paths: a parser is deterministic and side-effect free.
	for _, k := range []string{"executable_path", "data_directory"} {
		if _, ok := ob[k]; ok {
			t.Errorf("parser must not resolve %q — it is a device property", k)
		}
	}
}

// Autodetection is the whole import path for a user who pastes what
// BridgeDB or the bridges@torproject.org autoresponder gave them. Two
// of the three transports the Tor Project recommends for Iran —
// snowflake and meek_lite — were undetectable before Wave 5, and so was
// every reply that begins with a comment line.
func TestAutodetectTorBridgePastes(t *testing.T) {
	pastes := map[string]string{
		"obfs4":         "obfs4 38.229.1.78:80 0BAC39417268B96B9F514E7F63FA6FBA1A788955 cert=Vw== iat-mode=1\n",
		"webtunnel":     "webtunnel 192.0.2.3:443 054BF06CA6B0E6E1C05C1C0D0A0C7DCA1E8E5F0A url=https://a.example/p\n",
		"snowflake":     "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://x.example/\n",
		"meek_lite":     "meek_lite 192.0.2.20:80 97700DFE9F483596DDA6264C4D7DF7641E1E39CE url=https://m.example/\n",
		"vanilla":       "78.47.152.16:9001 ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD\n",
		"torrc-keyword": "Bridge obfs4 1.2.3.4:443 ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD cert=x\n",
		"comment-first": "# Here are your bridges:\n\nobfs4 1.2.3.4:443 ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD cert=x\n",
	}
	for name, body := range pastes {
		t.Run(name, func(t *testing.T) {
			// No hint: exactly what a paste box provides.
			profs, prov, err := ParseAny([]byte(body), "")
			if err != nil {
				t.Fatalf("autodetect failed: %v", err)
			}
			if prov.Scheme != "tor-bridge" {
				t.Errorf("scheme = %q, want tor-bridge", prov.Scheme)
			}
			if len(profs) != 1 || profs[0].Outbound["type"] != "tor" {
				t.Errorf("got %d profiles, first = %v", len(profs), profs[0].Outbound)
			}
		})
	}
}

// ...and must not claim pastes belonging to other parsers.
func TestAutodetectDoesNotClaimOtherFormats(t *testing.T) {
	for name, body := range map[string]string{
		"vless":        "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?security=reality#x\n",
		"wireguard":    "[Interface]\nPrivateKey = aaa\n",
		"clash":        "proxies:\n  - name: a\n",
		"bare-address": "1.2.3.4:443\n",
	} {
		t.Run(name, func(t *testing.T) {
			if looksLikeTorBridges(body) {
				t.Errorf("tor-bridge detector wrongly claimed a %s paste", name)
			}
		})
	}
}
