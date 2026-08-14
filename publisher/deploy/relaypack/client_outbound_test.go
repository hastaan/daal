package relaypack

import (
	"encoding/json"
	"testing"
)

func fullParams() ClientConnParams {
	return ClientConnParams{
		Server:           "78.47.152.16",
		VLESSUUID:        "11111111-2222-3333-4444-555555555555",
		RealityShortID:   "deadbeef",
		RealityPublicKey: "cHVia2V5LWJhc2U2NC0zMi1ieXRlcy1oZXJlLXh4eHg=",
		Hy2Password:      "hy2secretpassword22ch",
		NaivePassword:    "naivesecretpassword22",
		WSPath:           "/r1/cafebabe",
		TLSCertSHA256:    "c3BraS1zaGEyNTYtcGluLWJhc2U2NC12YWx1ZS14eHg=",
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
	for _, fam := range []string{"websocket-tls", "hysteria2", "naive"} {
		m := parseOutbound(t, fam, 443, fullParams())
		tls := m["tls"].(map[string]any)
		if tls["insecure"] == true {
			t.Errorf("%s: must never set insecure:true", fam)
		}
		if tls["certificate_public_key_sha256"] == nil {
			t.Errorf("%s: expected a cert pin", fam)
		}
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
