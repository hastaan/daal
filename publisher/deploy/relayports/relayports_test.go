package relayports

import "testing"

// TestFor pins the canonical port/proto for every served family plus
// the reserved ones and the unknown-family default. This is the map
// the box config, both firewalls, and the client outbound all derive
// from, so a drift here is a cross-component drift.
func TestFor(t *testing.T) {
	cases := []struct {
		family string
		want   Endpoint
	}{
		{"vless-reality", Endpoint{Port: 443, UDP: false}},
		{"hysteria2", Endpoint{Port: 443, UDP: true}},
		{"naive", Endpoint{Port: 8444, UDP: false}},
		{"websocket-tls", Endpoint{Port: 8445, UDP: false}},
		{"tuic", Endpoint{Port: 443, UDP: true}},
		{"wireguard", Endpoint{Port: 51820, UDP: true}},
		{"amneziawg", Endpoint{Port: 51820, UDP: true}},
		{"something-else", Endpoint{Port: 443, UDP: false}},
	}
	for _, tc := range cases {
		if got := For(tc.family); got != tc.want {
			t.Errorf("For(%q) = %+v, want %+v", tc.family, got, tc.want)
		}
	}
}

// TestExtraFirewallPorts asserts the non-baseline data-plane ports
// stay in sync with For(): naive and websocket-tls.
func TestExtraFirewallPorts(t *testing.T) {
	extra := ExtraFirewallPorts()
	want := []Endpoint{
		{Port: 8444, UDP: false},
		{Port: 8445, UDP: false},
	}
	if len(extra) != len(want) {
		t.Fatalf("ExtraFirewallPorts() len = %d, want %d", len(extra), len(want))
	}
	for i := range want {
		if extra[i] != want[i] {
			t.Errorf("ExtraFirewallPorts()[%d] = %+v, want %+v", i, extra[i], want[i])
		}
	}
	// Each extra port must match what For() reports for its family.
	if got := For("naive"); got != extra[0] {
		t.Errorf("For(naive) = %+v, not in sync with ExtraFirewallPorts()[0] = %+v", got, extra[0])
	}
	if got := For("websocket-tls"); got != extra[1] {
		t.Errorf("For(websocket-tls) = %+v, not in sync with ExtraFirewallPorts()[1] = %+v", got, extra[1])
	}
}
