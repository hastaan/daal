package mgmt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// TestUserCreds_ShadowsocksSurvivesDecode is the silent-drop guard for
// the shadowsocks fields, and it exists because this exact bug has
// already shipped twice in this project — once in Go (cover_sni and
// mux_inbound echoed by the box, omitted from this struct, discarded by
// encoding/json with no error anywhere) and once again in Rust (serde
// does the same). A transport whose credential vanishes in the middle
// does not fail loudly; it produces a pack with a route nobody can
// authenticate.
//
// The body below is byte-for-byte what cmd/daal-relay-mgmt's
// /users/provision handler encodes today for a box that serves the
// family.
func TestUserCreds_ShadowsocksSurvivesDecode(t *testing.T) {
	const body = `{
      "name":"r1",
      "vless_uuid":"831c3050-b834-4165-ae73-18dc092df511",
      "reality_short_id":"deadbeef",
      "hy2_password":"aGkyLXBhc3N3b3JkLTIyY2g",
      "naive_password":"bmFpdmUtcGFzc3dvcmQtMjJj",
      "ws_path":"/r1/cafebabe",
      "provisioned_at_unix":1777000000,
      "cover_sni":"ftp.plusline.net",
      "mux_inbound":true,
      "ss_password":"bW9jay1ib3gtaXBzay0xNg==:bW9jay11c2VyLXVwc2sxNg==",
      "ss_method":"2022-blake3-aes-128-gcm"
    }`
	var got UserCreds
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.SSMethod != "2022-blake3-aes-128-gcm" {
		t.Fatalf("ss_method = %q; the method must survive decode — the PSK length follows from it", got.SSMethod)
	}
	if got.SSPassword == "" {
		t.Fatalf("ss_password was dropped on decode: the box served the family and the publisher will now refuse to mint it")
	}
	// Two colon-joined halves, each PADDED base64-STANDARD decoding to
	// the method's 16-byte key. The publisher must carry this verbatim
	// and never re-encode it; RawURLEncoding (what hy2/naive use) does
	// not decode at the other end.
	parts := strings.Split(got.SSPassword, ":")
	if len(parts) != 2 {
		t.Fatalf("ss_password %q is not <iPSK>:<uPSK>", got.SSPassword)
	}
	for _, half := range parts {
		raw, err := base64.StdEncoding.DecodeString(half)
		if err != nil {
			t.Errorf("half %q is not base64-std: %v", half, err)
			continue
		}
		if len(raw) != 16 {
			t.Errorf("half %q decodes to %d bytes, want 16", half, len(raw))
		}
	}
	// Round-trip: the creds file the publisher re-serialises for the
	// pack step must still carry both fields.
	out, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	if !strings.Contains(string(out), `"ss_password"`) || !strings.Contains(string(out), `"ss_method"`) {
		t.Fatalf("re-encoded creds lost the shadowsocks fields: %s", out)
	}
}

// TestUserCreds_OldBoxIsDistinguishable pins the fail-closed signal. A
// relay whose mgmt binary predates the family says nothing about it, and
// SILENCE — not any inferred value — is what the pack minter reads.
func TestUserCreds_OldBoxIsDistinguishable(t *testing.T) {
	const legacy = `{"name":"r1","vless_uuid":"u","ws_path":"/r1/x","provisioned_at_unix":1}`
	var got UserCreds
	if err := json.Unmarshal([]byte(legacy), &got); err != nil {
		t.Fatalf("a pre-Wave-5 box's response must still decode: %v", err)
	}
	if got.SSPassword != "" || got.SSMethod != "" {
		t.Fatalf("an old box appeared to serve shadowsocks: %q / %q", got.SSPassword, got.SSMethod)
	}
}

// TestCapShadowsocksHasNoVersionFallback: the token is the ONLY signal.
// mgmt_api_version rides the wire contract, not the pinned artifact, so
// a box could report any version and still be running a binary with no
// ss-in in it. Has() must not infer the capability from a number.
func TestCapShadowsocksHasNoVersionFallback(t *testing.T) {
	if CapShadowsocks2022 != "shadowsocks-2022" {
		t.Fatalf("token = %q, want shadowsocks-2022 (wire contract with cmd/daal-relay-mgmt)", CapShadowsocks2022)
	}
	high := &BoxCapabilities{OK: true, MgmtAPIVersion: 99}
	if high.Has(CapShadowsocks2022) {
		t.Fatalf("a high mgmt_api_version alone claimed the shadowsocks capability")
	}
	advertised := &BoxCapabilities{OK: true, Capabilities: []string{CapShadowsocks2022}}
	if !advertised.Has(CapShadowsocks2022) {
		t.Fatalf("an explicit token was not honoured")
	}
	var old *BoxCapabilities
	if old.Has(CapShadowsocks2022) {
		t.Fatalf("a nil (unreachable/silent) box claimed the capability")
	}
}
