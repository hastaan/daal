package mgmt

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

// The /rotate-credentials wire format changed in Wave 2: the box now
// returns `reality_private_key` as 43 base64url characters instead of 64
// hex ones, because sing-box decodes that field with
// base64.RawURLEncoding and a hex string decodes to 48 bytes — a FATAL
// on the restart the handler performs, on a box with no SSH way back in.
//
// The publisher decodes the field as an untyped string, so a skewed pair
// (Wave-2 publisher against an old box, or the reverse) produces no
// error anywhere. This test is the only thing standing between that and
// a dead relay: it pins what a CURRENT box sends, so anyone changing the
// encoding on either side has to change it here too and read why.
func TestCredentials_RealityPrivKeyIsBase64Raw32Bytes(t *testing.T) {
	// Byte-for-byte the shape cmd/daal-relay-mgmt's handleRotateCreds
	// encodes today.
	const body = `{
      "uuid":"831c3050-b834-4165-ae73-18dc092df511",
      "users":{"r1":"831c3050-b834-4165-ae73-18dc092df511","r2":"22222222-b834-4165-ae73-18dc092df511"},
      "reality_private_key":"cME1Aymm3sBpsq_LOR-avwT8Cy5b6vXQhSTBpIrhtVI",
      "reality_public_key":"F3oIDzfjiaDmYwQgEJJlL5oGUdy5x0lllgs8_2ctxzo",
      "generated_at_unix":1777000000
    }`
	var got Credentials
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(got.RealityPrivKey)
	if err != nil {
		t.Fatalf("reality_private_key is not base64url — sing-box will FATAL on it: %v", err)
	}
	if len(raw) != 32 {
		t.Fatalf("reality_private_key decodes to %d bytes, want 32 (X25519)", len(raw))
	}
	if _, err := base64.RawURLEncoding.DecodeString(got.RealityPubKey); err != nil {
		t.Fatalf("reality_public_key is not base64url: %v", err)
	}
	// The per-recipient map is what makes the rotation a revocation.
	// A response carrying only `uuid` came from a pre-Wave-2 box that
	// rotated inbounds[0].users[0] and left everyone else connected.
	if len(got.Users) != 2 {
		t.Fatalf("Users = %v, want one entry per recipient", got.Users)
	}
}

// A pre-Wave-2 box answers without reality_public_key and without users.
// That absence — not the private key's length — is the signal a caller
// should branch on, so pin that it survives decoding as the zero value
// rather than erroring.
func TestCredentials_LegacyBoxIsDistinguishable(t *testing.T) {
	const legacy = `{"uuid":"u","reality_private_key":"` +
		"aabbccddeeff00112233445566778899aabbccddeeff001122334455667788990" + `","generated_at_unix":1}`
	var got Credentials
	if err := json.Unmarshal([]byte(legacy), &got); err != nil {
		t.Fatal(err)
	}
	if got.RealityPubKey != "" || got.Users != nil {
		t.Fatalf("legacy response decoded as Wave-2 shaped: %+v", got)
	}
}
