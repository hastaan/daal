package profiles

import (
	"strings"
	"testing"
)

func TestIranDefault_LoadsAndPinsSeven(t *testing.T) {
	p, err := IranDefault()
	if err != nil {
		t.Fatalf("IranDefault: %v", err)
	}
	if p.Name != "iran-default" {
		t.Errorf("name = %q want iran-default", p.Name)
	}
	if p.SpecVersion != 1 {
		t.Errorf("spec_version = %d want 1", p.SpecVersion)
	}
	// The four field-proven tiers lead, in order, because the wizard
	// renders this list as-is.
	lead := []string{"vless-reality", "websocket-tls", "naive", "hysteria2"}
	for i, fam := range lead {
		if i >= len(p.Candidates) || p.Candidates[i].Family != fam {
			t.Fatalf("candidate[%d] = %+v, want family %q", i, p.Candidates, fam)
		}
	}
	present := map[string]bool{}
	for _, c := range p.Candidates {
		present[c.Family] = true
	}
	// EVERY candidate in a toolbox profile must be a family this relay
	// can actually SERVE. A profile row is an offer: checking it in the
	// wizard mints a route in the pack, and a family with no box inbound
	// and no client-outbound renderer does not degrade — it makes
	// RewriteProfilesForRecipient return an error, which kills the whole
	// pack for every route, not just the checked one.
	//
	// wireguard and amnezia-wg were rows here until Wave 5 and could
	// never have worked: Daal serves no WireGuard, has no WG inbound, no
	// per-recipient WG credential and no firewall rule for 51820/udp,
	// and the client half is for routes the user pastes from elsewhere.
	// They are not "unfinished"; offering them was the bug.
	for _, gone := range []string{"wireguard", "amnezia-wg", "amneziawg"} {
		if present[gone] {
			t.Errorf("profile offers %q, which this relay cannot serve — checking it in the "+
				"wizard produces a pack that fails to render for EVERY route", gone)
		}
	}
	if !present["tuic"] {
		t.Error("tuic must remain an opt-in candidate")
	}
}

func TestIranDefault_DefaultEnabledFamilies(t *testing.T) {
	p, _ := IranDefault()
	enabled := map[string]bool{}
	for _, c := range p.Candidates {
		enabled[c.Family] = c.DefaultEnabled
	}
	for _, want := range []string{"vless-reality", "websocket-tls", "naive", "hysteria2"} {
		if !enabled[want] {
			t.Errorf("family %s must be default-enabled", want)
		}
	}
	// tuic is opt-in, and stays opt-in: it binds a third UDP-adjacent
	// port (8443) that is outside the target country's egress whitelist,
	// and every relay that enables it opens that port in both firewalls.
	// It is diversity for other networks, not a default.
	if enabled["tuic"] {
		t.Error("family tuic must be default-disabled")
	}
}

func TestLoad_RejectsMalformed(t *testing.T) {
	cases := []struct {
		name string
		body []byte
	}{
		{"empty", []byte("")},
		{"not-json", []byte("hello")},
		{"no-name", []byte(`{"spec_version":1,"candidates":[{"family":"x"}]}`)},
		{"no-spec-version", []byte(`{"name":"x","candidates":[{"family":"x"}]}`)},
		{"no-candidates", []byte(`{"name":"x","spec_version":1}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(tc.body)
			if err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}

func TestIranDefault_NoCDNFrontedAtV15(t *testing.T) {
	// V1.5 is direct-VPS only; the iran-default profile MUST NOT
	// reference cdn_fronted-only families (there are none in the
	// 7-family set, but pin the invariant so FRP-8's amendment is
	// auditable).
	p, _ := IranDefault()
	for _, c := range p.Candidates {
		if strings.Contains(c.Family, "cdn") {
			t.Errorf("V1.5 iran-default must not list cdn-* families; got %s", c.Family)
		}
	}
}
