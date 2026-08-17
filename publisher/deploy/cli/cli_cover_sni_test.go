package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"daal/publisher/deploy/relaypack"
)

// The cover-host chain's last hop. The provisioner picks a per-relay
// REALITY cover host, cloud-init writes it into the box's vless-in
// inbound, and /users/provision reads it back off that live config into
// the creds payload as `cover_sni`. If this mapping drops it, the minted
// pack advertises the legacy fleet-wide constant while the box
// handshakes something else — the exact IP/SNI mismatch REALITY exists
// to prevent, and a failure NO unit test on either side can see, because
// each half is internally consistent. It only shows up on the wire.
func TestClientParamsFromCredsFile_CarriesCoverSNI(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.json")
	if err := os.WriteFile(path, []byte(`{
  "name":"r1","vless_uuid":"831c3050-b834-4165-ae73-18dc092df511",
  "reality_short_id":"f219cd8d","reality_public_key":"F3oIDzfjiaDmYwQgEJJlL5oGUdy5x0lllgs8_2ctxzo",
  "hy2_password":"h","naive_password":"n","ws_path":"/r1/1a18aad0",
  "tls_cert_sha256":"c","tls_cert_pem":"p",
  "cover_sni":"ftp.plusline.net"
}`), 0o600); err != nil {
		t.Fatal(err)
	}
	params, err := clientParamsFromCredsFile(path, "203.0.113.7", "")
	if err != nil {
		t.Fatal(err)
	}
	if params.CoverSNI != "ftp.plusline.net" {
		t.Fatalf("CoverSNI = %q, want the box's own cover host", params.CoverSNI)
	}
	// End to end: the rendered outbound must actually advertise it.
	ob, err := relaypack.ClientOutboundForFamily("vless-reality", 443, params)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ob), `"server_name":"ftp.plusline.net"`) {
		t.Fatalf("outbound does not advertise the box's cover host: %s", ob)
	}
}

// A box provisioned before the field existed sends no cover_sni, and the
// publisher has no record value either (a pre-Wave-2 record has no
// cover_sni key). That box really is serving the legacy constant, so
// falling back to it is what keeps an old relay working against a new
// publisher.
func TestClientParamsFromCredsFile_LegacyBoxOmitsCoverSNI(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.json")
	if err := os.WriteFile(path, []byte(`{"name":"r1","vless_uuid":"u","reality_short_id":"s","reality_public_key":"k"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	params, err := clientParamsFromCredsFile(path, "203.0.113.7", "")
	if err != nil {
		t.Fatal(err)
	}
	if params.CoverSNI != "" {
		t.Fatalf("CoverSNI = %q, want empty so relaypack applies its legacy fallback", params.CoverSNI)
	}
	ob, err := relaypack.ClientOutboundForFamily("vless-reality", 443, params)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ob), `"server_name":"www.cloudflare.com"`) {
		t.Fatalf("legacy box must still get the legacy cover host: %s", ob)
	}
}

// Emitting a mux outbound against a relay whose inbound has none routes
// the client to the literal mux sentinel destination and fails hard. A
// box that does not report the capability — every relay in the field
// today, and every box whose operator edited the block out — must leave
// Multiplex nil.
func TestClientParamsFromCredsFile_NoMultiplexUnlessTheBoxReportsIt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.json")
	if err := os.WriteFile(path, []byte(`{
  "name":"r1","vless_uuid":"831c3050-b834-4165-ae73-18dc092df511",
  "reality_short_id":"f219cd8d","reality_public_key":"F3oIDzfjiaDmYwQgEJJlL5oGUdy5x0lllgs8_2ctxzo",
  "cover_sni":"ftp.plusline.net"
}`), 0o600); err != nil {
		t.Fatal(err)
	}
	params, err := clientParamsFromCredsFile(path, "203.0.113.7", "")
	if err != nil {
		t.Fatal(err)
	}
	if params.Multiplex != nil {
		t.Fatalf("Multiplex = %v, want nil when the box reports no mux capability", params.Multiplex)
	}
	ob, err := relaypack.ClientOutboundForFamily("vless-reality", 443, params)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(ob), `"multiplex"`) {
		t.Fatalf("outbound carries a multiplex block against a box that has none: %s", ob)
	}
}

// The mirror image: once the box says its vless-family inbounds carry
// the block, the pack must actually emit one — otherwise Step 5 is a
// relay-side change with no client that uses it, and the classifier this
// whole step exists to defeat still sees one connection per flow.
func TestClientParamsFromCredsFile_EnablesMultiplexWhenTheBoxReportsIt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.json")
	if err := os.WriteFile(path, []byte(`{
  "name":"r1","vless_uuid":"831c3050-b834-4165-ae73-18dc092df511",
  "reality_short_id":"f219cd8d","reality_public_key":"F3oIDzfjiaDmYwQgEJJlL5oGUdy5x0lllgs8_2ctxzo",
  "hy2_password":"h","cover_sni":"ftp.plusline.net","mux_inbound":true
}`), 0o600); err != nil {
		t.Fatal(err)
	}
	params, err := clientParamsFromCredsFile(path, "203.0.113.7", "")
	if err != nil {
		t.Fatal(err)
	}
	if pol, ok := params.Multiplex["vless-reality"]; !ok || !pol.Enabled {
		t.Fatalf("Multiplex = %v, want vless-reality enabled from the profile", params.Multiplex)
	}
	ob, err := relaypack.ClientOutboundForFamily("vless-reality", 443, params)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"multiplex"`, `"protocol":"h2mux"`, `"padding":true`} {
		if !strings.Contains(string(ob), want) {
			t.Fatalf("outbound missing %s: %s", want, ob)
		}
	}
	// hysteria2 is QUIC-native; a mux block there is both a strict-parser
	// rejection and a head-of-line-blocking regression.
	hy2, err := relaypack.ClientOutboundForFamily("hysteria2", 443, params)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(hy2), `"multiplex"`) {
		t.Fatalf("hysteria2 outbound must never carry multiplex: %s", hy2)
	}
}

// The mgmt-artifact skew guard. A relay provisioned by a Wave-2
// daal-deploy whose box still runs the SHA-pinned pre-Wave-2 mgmt binary
// serves a pool cover host and reports none. Without the record value
// the pack would advertise www.cloudflare.com against a box serving
// something else, and utls fails the SNI check before REALITY auth — the
// whole vless tier dies silently for every recipient.
func TestClientParamsFromCredsFile_RecordCoversAMgmtBinaryThatCannotEcho(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.json")
	if err := os.WriteFile(path, []byte(`{"name":"r1","vless_uuid":"u","reality_short_id":"s","reality_public_key":"k"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	params, err := clientParamsFromCredsFile(path, "203.0.113.7", "mirror.dogado.de")
	if err != nil {
		t.Fatal(err)
	}
	if params.CoverSNI != "mirror.dogado.de" {
		t.Fatalf("CoverSNI = %q, want the record's value", params.CoverSNI)
	}
}

// ...and the box still wins when it speaks, because /rotate-tls can move
// the live value after the record was written.
func TestClientParamsFromCredsFile_BoxEchoBeatsTheRecord(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.json")
	if err := os.WriteFile(path, []byte(`{"name":"r1","cover_sni":"mirror.init7.net"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	params, err := clientParamsFromCredsFile(path, "203.0.113.7", "mirror.dogado.de")
	if err != nil {
		t.Fatal(err)
	}
	if params.CoverSNI != "mirror.init7.net" {
		t.Fatalf("CoverSNI = %q, want the box's live value to win", params.CoverSNI)
	}
}
