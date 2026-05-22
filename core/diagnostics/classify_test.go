package diagnostics

import (
	"testing"
)

func TestClassifyKnownPatterns(t *testing.T) {
	cases := map[string]Category{
		"dial tcp 203.0.113.4:443: i/o timeout":                TCPConnectTimeout,
		"read tcp 203.0.113.4:443: connection reset by peer":   TCPReset,
		"tls: handshake failure":                               TLSHandshakeFailed,
		"tls: no application protocol":                         TLSSNIOrCertBlockSuspected,
		"quic: handshake_idle_timeout":                         QUICUnavailable,
		"udp probe failed":                                     UDPUnavailable,
		"authentication failed: bad password":                  AuthFailed,
		"panic: engine died unexpectedly":                      EngineCrash,
		"route expired at 2026-04-25":                          RouteExpired,
		"publisher revoked: compromised endpoint":              PublisherRevoked,
		"publisher key changed without rotation chain":         PublisherKeyChanged,
		"bundle signature invalid":                             BundleSignatureInvalid,
		"bundle corrupted: zip parse error":                    BundleCorrupted,
		"network is unreachable":                               NetworkOffline,
		"dns: no such host":                                    DNSTimeout,
		"resolver returned 10.10.34.34 (rfc1918 sinkhole)":     DNSPoisoned,
		"unknown weird message that should not match anything": Unknown,
		// FRP-3 additions (5 v2.3.4 signal categories):
		"resolver answered dns bogon for popular host":              DNSBogon,
		"udp_collapsed: probe rejected on this network":             UDPCollapsed,
		"quic: version negotiation failure on otherwise-up network": QUICCollapsed,
		"sni_rst: server reset before serverhello":                  SNIRst,
		"cloudflare returned 522 for origin":                        OriginUnhealthy,
		"origin unhealthy 525 from cdn":                             OriginUnhealthy,
	}
	for in, want := range cases {
		if got := Classify(in); got != want {
			t.Errorf("Classify(%q): got %s want %s", in, got, want)
		}
	}
}

func TestAuthFailedIsNotCensorship(t *testing.T) {
	if IsCensorshipClass(AuthFailed) {
		t.Fatal("auth_failed must never trigger censorship cooldown (V0.3 hard rule)")
	}
	if !IsCensorshipClass(TCPReset) {
		t.Fatal("tcp_reset is censorship class")
	}
}

// TestFRP3_NewCategoriesCensorshipMembership pins which of the 5 new
// FRP-3 categories trigger cooldown. OriginUnhealthy is operator-hygiene
// per supplement §13.4 and must NOT be treated as censorship.
func TestFRP3_NewCategoriesCensorshipMembership(t *testing.T) {
	censorship := []Category{DNSBogon, UDPCollapsed, QUICCollapsed, SNIRst}
	for _, c := range censorship {
		if !IsCensorshipClass(c) {
			t.Errorf("%s must be censorship class", c)
		}
	}
	if IsCensorshipClass(OriginUnhealthy) {
		t.Fatal("origin_unhealthy is operator-hygiene per supplement §13.4; must NOT be censorship class")
	}
}

// TestFRP3_NegativeCases pins that the FRP-3 substring promotions
// don't accidentally fire on unrelated messages.
func TestFRP3_NegativeCases(t *testing.T) {
	cases := map[string]Category{
		// Normal TCP timeouts must NOT promote to OriginUnhealthy
		// just because "522" or "526" can appear elsewhere — the
		// classifier requires "cloudflare"/"cdn"/"origin" co-mention.
		"port 5226 unreachable": Unknown,
		// Generic "udp" message stays UDPUnavailable; UDPCollapsed
		// requires the explicit keyword.
		"udp probe failed for hysteria2": UDPUnavailable,
		// Generic TLS handshake error stays TLSHandshakeFailed.
		"tls: handshake failure: certificate expired": TLSHandshakeFailed,
		// SNIRst requires the explicit keyword; ordinary TCP RSTs
		// stay TCPReset.
		"read tcp 1.2.3.4:443: connection reset by peer": TCPReset,
	}
	for in, want := range cases {
		if got := Classify(in); got != want {
			t.Errorf("Classify(%q): got %s want %s", in, got, want)
		}
	}
}
