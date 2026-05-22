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
	if len(p.Candidates) != 7 {
		t.Errorf("candidate count = %d want 7", len(p.Candidates))
	}
	want := []string{"vless-reality", "websocket-tls", "naive", "hysteria2", "tuic", "wireguard", "amnezia-wg"}
	for i, c := range p.Candidates {
		if i >= len(want) {
			t.Fatalf("extra candidate at %d: %+v", i, c)
		}
		if c.Family != want[i] {
			t.Errorf("candidate[%d].family = %q want %q", i, c.Family, want[i])
		}
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
	for _, want := range []string{"tuic", "wireguard", "amnezia-wg"} {
		if enabled[want] {
			t.Errorf("family %s must be default-disabled (moderate probing risk)", want)
		}
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
