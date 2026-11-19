package engine

import (
	"strings"
	"testing"
)

func TestScrubRemovesWhatMustNotBeLogged(t *testing.T) {
	cases := []struct {
		name, in string
		gone     []string // must not survive
		kept     []string // must survive
	}{
		{"ipv4 and port", "dial tcp 203.0.113.77:8443: connect: connection refused",
			[]string{"203.0.113.77", "8443"}, []string{"dial tcp", "connection refused"}},
		{"bare ipv4", "no route to host 10.20.30.40", []string{"10.20.30.40"}, []string{"no route to host"}},
		{"ipv6 bracketed", "dial tcp [2001:db8::1]:443: i/o timeout", []string{"2001:db8", "443"}, []string{"i/o timeout"}},
		{"ipv6 bare", "lookup failed via 2001:db8:85a3::8a2e:370:7334", []string{"2001:db8", "7334"}, []string{"lookup failed"}},
		{"host name", "lookup relay-7.example.org: no such host", []string{"relay-7", "example.org"}, []string{"no such host"}},
		{"host and port", "proxyconnect tcp: dial cdn.example.com:443 failed", []string{"cdn.example.com"}, []string{"proxyconnect"}},
		{"url", "Get \"https://sub.example.net/p/abc?token=xyz\": EOF", []string{"sub.example.net", "token=xyz", "/p/abc"}, []string{"EOF"}},
		{"share uri", "cannot parse vless://5f1c0f3e-9a41-4f7b-8f55-0d5c3a1b2c9d@h.example.com:443?security=reality",
			[]string{"5f1c0f3e", "h.example.com", "reality"}, []string{"cannot parse"}},
		{"uuid", "user 5f1c0f3e-9a41-4f7b-8f55-0d5c3a1b2c9d rejected", []string{"5f1c0f3e-9a41"}, []string{"rejected"}},
		{"json password", `option parse: {"password":"hunter2","method":"aes"}`, []string{"hunter2"}, []string{"option parse"}},
		{"kv password", "auth failed: password=hunter2, user=alice", []string{"hunter2", "alice"}, []string{"auth failed"}},
		{"private key", `"private_key": "kB3vZ0mXq1"`, []string{"kB3vZ0mXq1"}, nil},
		{"base64 blob", "bad key c2VjcmV0LWtleS1tYXRlcmlhbC0xMjM0NTY3ODkw", []string{"c2VjcmV0"}, []string{"bad key"}},
		{"age identity", "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ leaked", []string{"AGE-SECRET-KEY-1QQQ"}, []string{"leaked"}},
		{"hex blob", "pin sha256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", []string{"9f86d081"}, []string{"pin sha256"}},
		{"multi-line", "first\nsecond\tthird\x00", []string{"\n", "\t", "\x00"}, []string{"first second third"}},
		{"engine names stay", "engine_subscription_list: routestore: apply schema failed, category=tcp_connect_timeout in engine-config.json and daal.db",
			nil, []string{"engine_subscription_list", "tcp_connect_timeout", "engine-config.json", "daal.db", "routestore"}},
		{"sqlite text stays", "database is locked (5) (SQLITE_BUSY)", nil, []string{"database is locked (5) (SQLITE_BUSY)"}},
	}
	for _, tc := range cases {
		got := Scrub(tc.in)
		for _, g := range tc.gone {
			if strings.Contains(got, g) {
				t.Errorf("%s: %q survived scrubbing: %q", tc.name, g, got)
			}
		}
		for _, k := range tc.kept {
			if !strings.Contains(got, k) {
				t.Errorf("%s: lost %q: %q", tc.name, k, got)
			}
		}
	}
	long := Scrub(strings.Repeat("word ", 500))
	if len(long) > scrubMax+len("…") {
		t.Errorf("a long line was not bounded: %d bytes", len(long))
	}
}

func TestLogIDReducesAnIdentifier(t *testing.T) {
	if got := LogID("r-1_a.b:c"); got != "r-1_a.b:c" {
		t.Errorf("a plain id was changed: %q", got)
	}
	if got := LogID("x\ny password=1 /etc"); strings.ContainsAny(got, "\n =/") {
		t.Errorf("an id kept characters an id is not made of: %q", got)
	}
	if got := LogID(strings.Repeat("a", 500)); len(got) > 70 {
		t.Errorf("an id was not bounded: %d", len(got))
	}
	if got := LogID(""); got != "-" {
		t.Errorf("empty id = %q", got)
	}
}

// Every line a caller logs is scrubbed on the way out, whatever it was
// built from.
func TestLogLinesAreScrubbed(t *testing.T) {
	var lines []string
	restore := SetLogTapForTest(func(_ int, line string) { lines = append(lines, line) })
	defer restore()
	LogError("start failed: dial 198.51.100.9:443 password=hunter2")
	LogInfo("route up route=r1")
	if len(lines) != 2 {
		t.Fatalf("lines = %v", lines)
	}
	if strings.Contains(lines[0], "198.51.100.9") || strings.Contains(lines[0], "hunter2") {
		t.Fatalf("an unscrubbed line reached the log: %q", lines[0])
	}
	if lines[1] != "route up route=r1" {
		t.Fatalf("a clean line was altered: %q", lines[1])
	}
}
