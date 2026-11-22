package main

import (
	"net"
	"strings"
	"testing"
)

// A bound IPv4 address is answered on but never chosen as the source of
// traffic the box starts: `scope link` (see addrAddArgv). The rest of
// the argv is exactly what it was, built from the parsed address.
func TestAddrAddArgv_BindsWithoutAdopting(t *testing.T) {
	got := strings.Join(addrAddArgv("eth0", net.ParseIP("203.0.113.20")), " ")
	if got != "ip addr add 203.0.113.20/32 dev eth0 scope link" {
		t.Errorf("v4 argv = %q", got)
	}
	got = strings.Join(addrAddArgv("eth0", net.ParseIP("2001:db8::20")), " ")
	if got != "ip addr add 2001:db8::20/128 dev eth0" {
		t.Errorf("v6 argv = %q", got)
	}
	// An IPv4-in-IPv6 rendering is still an IPv4 /32 with the scope.
	got = strings.Join(addrAddArgv("eth0", net.ParseIP("::ffff:203.0.113.20")), " ")
	if got != "ip addr add 203.0.113.20/32 dev eth0 scope link" {
		t.Errorf("v4-mapped argv = %q", got)
	}
}
