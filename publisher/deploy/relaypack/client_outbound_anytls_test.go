package relaypack

import (
	"encoding/json"
	"strings"
	"testing"
)

func anytlsParams() ClientConnParams {
	return ClientConnParams{
		Server:         "78.47.152.16",
		Name:           "r1",
		AnyTLSPassword: "YW55dGxzLXBlci1yZWNpcGllbnQtcGFzc3dvcmQtMzJi",
		TLSCertSHA256:  "c3BraS1zaGEyNTYtcGluLWJpbi1iYXNlNjQ=",
	}
}

// TestAnyTLSOutboundMatchesPinnedShape locks the rendered outbound
// against option.AnyTLSOutboundOptions field by field.
//
// The publisher module does not depend on sing-box, so it cannot run
// the strict decoder itself. The decoder runs in
// core/engine/client_outbound_singbox_test.go
// (TestAssembledClientOutboundsParse/anytls, build tag `singbox`)
// against a JSON literal, and the usual weakness of that arrangement is
// that the literal is "kept in sync by hand" — which is a promise, not
// a check. This test is the check: it asserts the renderer really emits
// that shape, so the two halves cannot drift apart silently.
//
// The field names below are transcribed from
// sing-box@v1.13.12/option/anytls.go:
//
//	Password                 string             `json:"password,omitempty"`
//	IdleSessionCheckInterval badoption.Duration `json:"idle_session_check_interval,omitempty"`
//	IdleSessionTimeout       badoption.Duration `json:"idle_session_timeout,omitempty"`
//	MinIdleSession           int                `json:"min_idle_session,omitempty"`
//
// plus DialerOptions / ServerOptions / OutboundTLSOptionsContainer.
func TestAnyTLSOutboundMatchesPinnedShape(t *testing.T) {
	raw, err := ClientOutboundForFamily("anytls", 8447, anytlsParams())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Exact key set. A key sing-box does not define is not a cosmetic
	// extra — the recipient's decoder is strict and rejects the whole
	// outbound, which is a dead tier rather than a degraded one.
	wantKeys := map[string]bool{
		"type": true, "tag": true, "server": true, "server_port": true,
		"password": true, "min_idle_session": true,
		"idle_session_check_interval": true, "idle_session_timeout": true,
		"tls": true,
	}
	for k := range got {
		if !wantKeys[k] {
			t.Errorf("outbound carries key %q, which option.AnyTLSOutboundOptions does not define", k)
		}
	}
	for k := range wantKeys {
		if _, ok := got[k]; !ok {
			t.Errorf("outbound is missing key %q", k)
		}
	}

	if got["type"] != "anytls" {
		t.Errorf("type = %v, want anytls", got["type"])
	}
	if got["tag"] != "active" {
		t.Errorf("tag = %v, want active (BuildSingBoxConfig / route.final expect it)", got["tag"])
	}
	if got["password"] != anytlsParams().AnyTLSPassword {
		t.Errorf("password not carried through verbatim")
	}
	// The idle-session knobs are the native session reuse that is the
	// whole reason for adding this family. Silently dropping them would
	// leave a working route that has lost the property it was chosen for.
	if got["min_idle_session"] != float64(1) {
		t.Errorf("min_idle_session = %v, want 1", got["min_idle_session"])
	}
	if got["idle_session_check_interval"] != "30s" || got["idle_session_timeout"] != "30s" {
		t.Errorf("idle-session durations = %v / %v, want 30s / 30s",
			got["idle_session_check_interval"], got["idle_session_timeout"])
	}

	// PADDING IS NOT A CLIENT-SIDE KEY. option.AnyTLSOutboundOptions has
	// no padding_scheme field: the server chooses the scheme and the
	// client adopts it over the wire (sing-anytls
	// session/session.go:264-278). If this ever fails, someone has
	// invented a field sing-box does not have, and the recipient's
	// strict decoder will reject the entire outbound.
	if _, ok := got["padding_scheme"]; ok {
		t.Error("outbound carries padding_scheme; the anytls OUTBOUND has no such option — " +
			"the scheme is server-dictated and negotiated in band")
	}

	tls, _ := got["tls"].(map[string]any)
	if tls == nil {
		t.Fatal("no tls block")
	}
	// Pinned by SPKI, never `insecure`. anytls uses sing-box's standard
	// TLS stack, so uTLS applies here (unlike hysteria2's QUIC stack).
	if tls["certificate_public_key_sha256"] != anytlsParams().TLSCertSHA256 {
		t.Errorf("leaf not pinned by SPKI SHA-256")
	}
	if _, bad := tls["insecure"]; bad {
		t.Error("tls.insecure must never be emitted")
	}
	if _, ok := tls["utls"].(map[string]any); !ok {
		t.Error("expected uTLS mimicry on anytls (standard TLS stack, unlike hysteria2)")
	}
}

// TestAnyTLSRefusesWithoutPassword is the interlock that keeps an
// undialable route out of a pack.
//
// An empty AnyTLSPassword means the box did not report one, which means
// its daal-relay-mgmt binary predates the family and there is no
// anytls-in inbound to authenticate against. Minting the route anyway
// would produce exactly the outcome this wave forbids: a route the user
// can select and lose. The refusal names the remediation because the
// operator cannot otherwise tell "too old" from "misconfigured".
func TestAnyTLSRefusesWithoutPassword(t *testing.T) {
	p := anytlsParams()
	p.AnyTLSPassword = ""
	_, err := ClientOutboundForFamily("anytls", 8447, p)
	if err == nil {
		t.Fatal("expected refusal when the box reported no anytls password")
	}
	if !strings.Contains(err.Error(), "artifacts.go") {
		t.Errorf("refusal should name the re-release remediation, got: %v", err)
	}
}

// TestAnyTLSNeverCarriesMultiplex pins the negative decision at the
// renderer, not just at the policy table: even a profile that asks for
// mux on this family must not get it. anytls has its own session layer,
// and option.AnyTLSOutboundOptions has no Multiplex field, so the key
// would make the recipient's strict decoder reject the outbound whole.
func TestAnyTLSNeverCarriesMultiplex(t *testing.T) {
	if familyCarriesMultiplex("anytls") {
		t.Fatal("anytls must not carry sing-mux: it already multiplexes, and the option does not exist")
	}
	p := anytlsParams()
	p.Multiplex = map[string]MuxPolicy{"anytls": {Enabled: true, MaxStreams: 64}}
	raw, err := ClientOutboundForFamily("anytls", 8447, p)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, bad := got["multiplex"]; bad {
		t.Error("renderer emitted multiplex on anytls despite the profile being ignored for this family")
	}
}
