package main

import "testing"

func TestRelayServesTCP(t *testing.T) {
	fam := func(port int, proto string) Family {
		var f Family
		f.Endpoint.Port, f.Endpoint.Proto = port, proto
		return f
	}
	fams := map[string]Family{
		"vless-reality": fam(443, "tcp"),
		"hysteria2":     fam(443, "udp"),
		"shadowsocks":   fam(8446, "tcp"),
		"anytls":        fam(8447, "tcp"),
	}
	cases := []struct {
		serve []string
		port  int
		want  bool
	}{
		{[]string{"vless-reality", "hysteria2"}, 443, true},
		// The narrow-relay world: 443/tcp belongs to nobody.
		{[]string{"shadowsocks", "anytls"}, 443, false},
		{[]string{"shadowsocks", "anytls"}, 8446, true},
		// hysteria2 is on 443 but UDP: it does not make 443/tcp served.
		{[]string{"hysteria2"}, 443, false},
		{[]string{"a-family-the-registry-lacks"}, 443, false},
		{nil, 443, false},
	}
	for _, tc := range cases {
		if got := relayServesTCP(tc.serve, fams, tc.port); got != tc.want {
			t.Errorf("relayServesTCP(%v, %d) = %v, want %v", tc.serve, tc.port, got, tc.want)
		}
	}
}

// Only "no TCP connection was established" is acceptable on a port the
// relay does not serve. Anything that needed a listener — a completed
// handshake, a reset after the hello, bytes answered — is a red check.
func TestTCPProbeRefused(t *testing.T) {
	for _, r := range []string{"connect_timeout", "connect_reset", "unreachable", "none"} {
		if !tcpProbeRefused(r) {
			t.Errorf("%q must count as refused", r)
		}
	}
	for _, r := range []string{"ok", "reset_after_hello", "timeout_after_hello", "answered", "reset_after_data", "silent", "all", "some", "fast", "slow", ""} {
		if tcpProbeRefused(r) {
			t.Errorf("%q needed a listener; it must not count as refused", r)
		}
	}
}
