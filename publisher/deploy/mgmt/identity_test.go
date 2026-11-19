package mgmt

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"

	"daal/publisher/deploy/provider"
)

// The reply the box really sends (cmd/daal-relay-mgmt/identity.go),
// as bytes: this struct is the TRANSPORT to the signer, and a field
// missing from it is silently dropped on decode.
const realIdentityBody = `{"identity_version":1,
 "reality_public_key":"Ck9nvVEcYnAlUUlBl9dqfKvyEpqTFDTjHmwPmLnKvVM",
 "tls_cert_sha256":"q83vEjRWeJCrze8SNFZ4kKvN7xI0VniQq83vEjRWeJA=",
 "cover_sni":"mirror.init7.net",
 "ss_method":"2022-blake3-aes-128-gcm",
 "ss_server_key_sha256":"fcdbdca159bd5651a33cf17ba64d6bcda8b6fb65929529933faf309ab580eae2",
 "families":[{"family":"hysteria2","port":443,"listening":true},
             {"family":"shadowsocks","port":8446,"listening":true},
             {"family":"vless-reality","port":443,"listening":true}],
 "pending_families":[],
 "generated_at_unix":1780000000}`

func identityBox(t *testing.T, pub ed25519.PublicKey, status int, body string) (*Client, *provider.OperatorRecord) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/identity", func(w http.ResponseWriter, r *http.Request) {
		if op, ok := boxVerifies(pub, r); !ok || op != OpIdentity || r.Method != "GET" {
			http.Error(w, "bad token", 401)
			return
		}
		if status != 200 {
			http.Error(w, body, status)
			return
		}
		_, _ = w.Write([]byte(body))
	})
	ts, fp := startTLSServer(t, mux)
	t.Cleanup(ts.Close)
	port, host := splitURL(t, ts.URL)
	rec := mkRec(t, fp, port)
	rec.PublicIP = net.ParseIP(host)
	cli, err := NewClient(rec)
	if err != nil {
		t.Fatal(err)
	}
	return cli, rec
}

func TestClient_Identity_DecodesEveryFieldTheSignerReads(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	cli, r := identityBox(t, pub, 200, realIdentityBody)
	id, err := cli.Identity(context.Background(), r, priv)
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	if id.RealityPublicKey != "Ck9nvVEcYnAlUUlBl9dqfKvyEpqTFDTjHmwPmLnKvVM" ||
		id.TLSCertSHA256 != "q83vEjRWeJCrze8SNFZ4kKvN7xI0VniQq83vEjRWeJA=" ||
		id.CoverSNI != "mirror.init7.net" ||
		id.SSMethod != "2022-blake3-aes-128-gcm" ||
		id.SSServerKeySHA256 != "fcdbdca159bd5651a33cf17ba64d6bcda8b6fb65929529933faf309ab580eae2" {
		t.Errorf("a field was lost in transit: %+v", id)
	}
	if id.PortFor("shadowsocks") != 8446 || id.PortFor("vless-reality") != 443 || id.PortFor("tuic") != 0 {
		t.Errorf("families lost in transit: %+v", id.Families)
	}
}

// An older relay answers 404. That is an answer — "I cannot say" — and
// the caller must be able to tell it from a failure, because the two
// have different remedies (fall back vs. try again).
func TestClient_Identity_AnOlderRelayIsNotAFailure(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	for _, status := range []int{404, 405} {
		cli, r := identityBox(t, pub, status, "404 page not found")
		_, err := cli.Identity(context.Background(), r, priv)
		if !errors.Is(err, ErrIdentityUnsupported) {
			t.Errorf("status %d: err = %v, want ErrIdentityUnsupported", status, err)
		}
	}
}

// A relay that refuses the token, or breaks, is NOT "older": falling
// back there would sign from a stale source while the real problem —
// the wrong key, a broken box — went unreported.
func TestClient_Identity_ARefusalIsNotAnOlderRelay(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	cli, r := identityBox(t, pub, 200, realIdentityBody)
	if _, err := cli.Identity(context.Background(), r, otherPriv); err == nil || errors.Is(err, ErrIdentityUnsupported) {
		t.Errorf("wrong key: err = %v, want a hard failure", err)
	}
	cli, r = identityBox(t, pub, 500, "identity: family set unreadable")
	if _, err := cli.Identity(context.Background(), r, priv); err == nil || errors.Is(err, ErrIdentityUnsupported) {
		t.Errorf("500: err = %v, want a hard failure", err)
	}
}

// What comes back is about to be signed. A document this client cannot
// read exactly is refused, never guessed at.
func TestParseRelayIdentity_RefusesWhatItCannotReadExactly(t *testing.T) {
	cases := map[string]string{
		"not json":            `<html>`,
		"unknown version":     `{"identity_version":2,"families":[],"pending_families":[]}`,
		"no version":          `{"reality_public_key":"x"}`,
		"ss method alone":     `{"identity_version":1,"ss_method":"2022-blake3-aes-128-gcm"}`,
		"ss key digest alone": `{"identity_version":1,"ss_server_key_sha256":"ab"}`,
	}
	for name, body := range cases {
		if _, err := ParseRelayIdentity([]byte(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	id, err := ParseRelayIdentity([]byte(`{"identity_version":1,"families":[],"pending_families":["shadowsocks"]}`))
	if err != nil || !id.Pending("shadowsocks") || id.Pending("naive") {
		t.Errorf("pending: id=%+v err=%v", id, err)
	}
}

func TestMintToken_AcceptsIdentityOp(t *testing.T) {
	method, path, ok := RouteForOp(OpIdentity)
	if !ok || method != "GET" || path != "/identity" {
		t.Fatalf("RouteForOp(identity) = %q %q %v", method, path, ok)
	}
	if !strings.HasPrefix(path, "/") {
		t.Fatal("unreachable")
	}
}
