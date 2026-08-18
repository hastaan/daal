package relayconf

import (
	"encoding/json"
	"net"
	"strings"
	"testing"

	"daal/publisher/deploy/relayports"
)

// The L6 fix, asserted at its new home: an unresolvable profile is an
// error at the moment it is read. It used to be a nil slice, which the
// caller could not tell apart from "this profile enables no families" —
// so a typo'd slug produced a record that provisioned, signed, and
// yielded a pack with no routes in it. L6's whole content is passing a
// NEW profile name here.
func TestCandidatesForProfile_RefusesAnUnresolvableProfile(t *testing.T) {
	if _, err := CandidatesForProfile("no-such-profile", net.ParseIP("5.75.0.1"), nil); err == nil {
		t.Fatal("an unknown profile produced candidates instead of an error")
	}
	if _, err := CandidatesForProfile("iran-default", net.ParseIP("5.75.0.1"), []string{"no-such-family"}); err == nil {
		t.Fatal("a profile that selects nothing produced candidates instead of an error")
	}
}

// Every candidate's port comes from relayports, which is also where the
// two firewalls and the box's inbounds get theirs. A candidate whose
// port disagrees with that table is a route that mints and cannot be
// dialled.
func TestCandidatesForProfile_PortsComeFromRelayports(t *testing.T) {
	cands, err := CandidatesForProfile("iran-default", net.ParseIP("5.75.0.1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) == 0 {
		t.Fatal("no candidates")
	}
	for _, c := range cands {
		ep := relayports.For(c.Family)
		if c.Port != ep.Port {
			t.Errorf("%s: candidate port %d, relayports says %d", c.Family, c.Port, ep.Port)
		}
		proto := "tcp"
		if ep.UDP {
			proto = "udp"
		}
		want := "public_port:" + proto + itoa(ep.Port)
		found := false
		for _, tag := range c.PublicRiskTags {
			if tag == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: tags %v do not carry %q", c.Family, c.PublicRiskTags, want)
		}
		if !hasTag(c.PublicRiskTags, "public_ip:5.75.0.1") {
			t.Errorf("%s: candidate does not carry the relay's address: %v", c.Family, c.PublicRiskTags)
		}
	}
}

// The sing-box config is valid JSON with the cover host in BOTH places
// REALITY needs it. A relay whose advertised name and fallback dest
// disagree is exactly the mismatch REALITY exists to prevent.
func TestSingBoxConfig_CoverHostAppearsInBothRequiredSites(t *testing.T) {
	const host = "mirror.example-host.net"
	body := DefaultSingBoxConfig("iran-default", host)

	var doc struct {
		Inbounds []struct {
			Type string `json:"type"`
			Tag  string `json:"tag"`
			TLS  struct {
				ServerName string `json:"server_name"`
				Reality    struct {
					Handshake struct {
						Server string `json:"server"`
					} `json:"handshake"`
				} `json:"reality"`
			} `json:"tls"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("config is not valid JSON: %v", err)
	}
	seen := false
	for _, in := range doc.Inbounds {
		if in.Tag != "vless-in" {
			continue
		}
		seen = true
		if in.TLS.ServerName != host {
			t.Errorf("tls.server_name = %q, want %q", in.TLS.ServerName, host)
		}
		if in.TLS.Reality.Handshake.Server != host {
			t.Errorf("reality.handshake.server = %q, want %q", in.TLS.Reality.Handshake.Server, host)
		}
	}
	if !seen {
		t.Fatal("no vless-in inbound")
	}
}

// tuic is CONDITIONAL on the family set, because binding 8443/udp is a
// permanent property of the box and the ufw rule that accompanies it is
// baked at first boot. The renderer and the firewall must agree about
// it, on every provider.
func TestSingBoxConfig_TuicIsConditional(t *testing.T) {
	def, err := ServedFamilies("iran-default", nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(SingBoxConfigForFamilies("x.example.net", def), `"tuic-in"`) {
		t.Error("tuic-in is in the default config; nothing opens 8443/udp for it")
	}
	on := SingBoxConfigForFamilies("x.example.net", append(append([]string{}, def...), "tuic"))
	if !strings.Contains(on, `"tuic-in"`) {
		t.Error("tuic-in is missing from a config whose family set includes tuic")
	}
	if !strings.Contains(on, `"alpn": ["h3"]`) {
		t.Error("the tuic inbound has no alpn; quic-go refuses a TLS config with no application protocol")
	}
}

func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
