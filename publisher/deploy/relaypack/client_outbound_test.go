package relaypack

import (
	"encoding/json"
	"testing"
)

// testCertPEM stands in for the box's self-signed data-plane leaf.
// Only its presence matters here — nothing in this package parses it.
const testCertPEM = "-----BEGIN CERTIFICATE-----\nMIIBtest\n-----END CERTIFICATE-----\n"

func fullParams() ClientConnParams {
	return ClientConnParams{
		Server:           "78.47.152.16",
		Name:             "r1",
		VLESSUUID:        "11111111-2222-3333-4444-555555555555",
		RealityShortID:   "deadbeef",
		RealityPublicKey: "cHVia2V5LWJhc2U2NC0zMi1ieXRlcy1oZXJlLXh4eHg=",
		Hy2Password:      "hy2secretpassword22ch",
		NaivePassword:    "naivesecretpassword22",
		WSPath:           "/r1/cafebabe",
		TLSCertSHA256:    "c3BraS1zaGEyNTYtcGluLWJhc2U2NC12YWx1ZS14eHg=",
		TLSCertPEM:       testCertPEM,
	}
}

func parseOutbound(t *testing.T, family string, port int, p ClientConnParams) map[string]any {
	t.Helper()
	b, err := ClientOutboundForFamily(family, port, p)
	if err != nil {
		t.Fatalf("%s: unexpected error: %v", family, err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("%s: output is not valid JSON: %v", family, err)
	}
	if m["tag"] != "active" {
		t.Errorf("%s: tag = %v, want active", family, m["tag"])
	}
	if _, ok := m["type"].(string); !ok || m["type"] == "" {
		t.Errorf("%s: missing/empty type: %v", family, m["type"])
	}
	if m["server"] != "78.47.152.16" {
		t.Errorf("%s: server = %v", family, m["server"])
	}
	return m
}

func TestClientOutbound_VlessReality(t *testing.T) {
	m := parseOutbound(t, "vless-reality", 443, fullParams())
	if m["type"] != "vless" {
		t.Fatalf("type = %v, want vless", m["type"])
	}
	tls := m["tls"].(map[string]any)
	if tls["server_name"] != RealityServerName {
		t.Errorf("server_name = %v, want %s", tls["server_name"], RealityServerName)
	}
	reality := tls["reality"].(map[string]any)
	if reality["public_key"] == "" || reality["short_id"] != "deadbeef" {
		t.Errorf("reality block wrong: %v", reality)
	}
	// REALITY must NOT carry a cert pin (it borrows the handshake).
	if _, has := tls["certificate_public_key_sha256"]; has {
		t.Error("vless-reality must not pin a cert")
	}
}

func TestClientOutbound_TLSFamiliesPinNotInsecure(t *testing.T) {
	// ws/hy2 pin the leaf by SPKI SHA-256.
	for _, fam := range []string{"websocket-tls", "hysteria2"} {
		m := parseOutbound(t, fam, 443, fullParams())
		tls := m["tls"].(map[string]any)
		if tls["insecure"] == true {
			t.Errorf("%s: must never set insecure:true", fam)
		}
		if tls["certificate_public_key_sha256"] == nil {
			t.Errorf("%s: expected a cert pin", fam)
		}
	}
	// naive rides Cronet, which has no SPKI-pin knob: it trusts the
	// box's leaf as a root instead. Same fail-closed contract.
	m := parseOutbound(t, "naive", 443, fullParams())
	tls := m["tls"].(map[string]any)
	if tls["insecure"] == true {
		t.Error("naive: must never set insecure:true")
	}
	certs, _ := tls["certificate"].([]any)
	if len(certs) != 1 || certs[0] != testCertPEM {
		t.Errorf("naive: expected the box leaf as trusted root, got %v", tls["certificate"])
	}
}

// A relay provisioned before the data-plane cert existed returns no
// tls_cert_pem. That must degrade the naive route (which then fails
// closed at connect, exactly as ws/hy2 do with no pin) rather than
// abort the rewrite — RewriteProfilesForRecipient returns the FIRST
// renderer error, so erroring here killed the whole pack and with it
// every other family, for every pre-existing box.
func TestClientOutbound_NaiveWithoutCertPEMStillRenders(t *testing.T) {
	p := fullParams()
	p.TLSCertPEM = ""
	m := parseOutbound(t, "naive", 443, p)
	tls := m["tls"].(map[string]any)
	if _, has := tls["certificate"]; has {
		t.Errorf("no PEM available: must not emit an empty trusted root, got %v", tls["certificate"])
	}
	if tls["insecure"] == true {
		t.Error("naive: must never set insecure:true")
	}
	if tls["enabled"] != true {
		t.Error("naive: TLS must stay on")
	}
}

func TestClientOutbound_MissingFieldsError(t *testing.T) {
	cases := []struct {
		family string
		mutate func(*ClientConnParams)
	}{
		{"vless-reality", func(p *ClientConnParams) { p.RealityPublicKey = "" }},
		{"vless-reality", func(p *ClientConnParams) { p.VLESSUUID = "" }},
		{"websocket-tls", func(p *ClientConnParams) { p.WSPath = "" }},
		{"hysteria2", func(p *ClientConnParams) { p.Hy2Password = "" }},
		{"naive", func(p *ClientConnParams) { p.NaivePassword = "" }},
		// The naive proxy username must match the box's naive-in user,
		// so an empty name is an unauthenticatable route, not a
		// degraded one.
		{"naive", func(p *ClientConnParams) { p.Name = "" }},
	}
	for _, c := range cases {
		p := fullParams()
		c.mutate(&p)
		if _, err := ClientOutboundForFamily(c.family, 443, p); err == nil {
			t.Errorf("%s with missing field: expected error, got nil", c.family)
		}
	}
	// empty server
	p := fullParams()
	p.Server = ""
	if _, err := ClientOutboundForFamily("vless-reality", 443, p); err == nil {
		t.Error("empty server: expected error")
	}
	// unknown family
	if _, err := ClientOutboundForFamily("wireguard", 51820, fullParams()); err == nil {
		t.Error("unknown family: expected error")
	}
}
