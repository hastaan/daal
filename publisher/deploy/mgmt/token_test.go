package mgmt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// testRelayFP is a relay's management TLS fingerprint for the tests that
// mint a token without a box to send it to; otherRelayFP is a sibling's.
const (
	testRelayFP  = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
	otherRelayFP = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"
)

// boxVerifies is what a relay does with an authenticated request, minus
// the clock and the nonce set: the token must be signed for THIS relay,
// THIS method, THIS path and THESE body bytes. Every fake box in this
// package goes through it, so a client call that signs one thing and
// sends another fails here as it would on a relay. The body is put back
// for the handler.
//
// The fake box names itself the way a relay does: by the SHA-256 of the
// certificate its own listener serves (never by anything the request
// says: startTLSServer records it by listening address), so a client that signed for a fingerprint other than the one it
// pinned is refused.
func boxVerifies(pub ed25519.PublicKey, r *http.Request) (op string, ok bool) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Daal-Mgmt-Token ")
	body, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(body))
	local, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if local == nil {
		return "", false
	}
	own, _ := fakeBoxFingerprints.Load(local.String())
	fp, _ := own.(string)
	op, err := VerifyToken(pub, fp, tok, r.Method, r.URL.Path, body)
	return op, err == nil
}

// fakeBoxFingerprints is each fake box's own certificate fingerprint,
// by the address it listens on (startTLSServer fills it in).
var fakeBoxFingerprints sync.Map

// TestToken_NamesTheRelay: one publisher key can be trusted by more than
// one relay (an imported key; the old and the new box around a rebuild).
// A token minted for one does not verify on another, and a token cannot
// be minted for no relay at all. Before the relay was under the
// signature the same token and body were honoured by both.
func TestToken_NamesTheRelay(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	body := []byte(`{"name":"r43"}`)
	tok, err := MintToken(priv, testRelayFP, "users-revoke", body, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyToken(pub, testRelayFP, tok, "POST", "/users/revoke", body); err != nil {
		t.Fatalf("the relay it was minted for must accept it: %v", err)
	}
	if _, err := VerifyToken(pub, otherRelayFP, tok, "POST", "/users/revoke", body); err == nil {
		t.Error("a token minted for one relay verified on another that trusts the same key")
	}
	// The recorded fingerprint's spelling is not part of the name: the
	// box computes lower-case hex for itself.
	spelled, err := MintToken(priv, "  "+strings.ToUpper(testRelayFP)+"\n", "users-list", nil, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyToken(pub, testRelayFP, spelled, "GET", "/users/list", nil); err != nil {
		t.Errorf("an upper-case, padded fingerprint names another relay: %v", err)
	}
	for name, fp := range map[string]string{
		"no relay":           "",
		"not hex":            strings.Repeat("zz", 32),
		"a truncated digest": testRelayFP[:40],
		"two lines":          testRelayFP[:32] + "\n" + testRelayFP[:31],
	} {
		if tok, err := MintToken(priv, fp, "users-list", nil, time.Now()); err == nil {
			t.Errorf("%s: minted %q", name, tok)
		}
	}
}

// TestClient_SignsForTheRelayItPinned: the client names the relay by the
// fingerprint in the record it was given - the one the TLS session is
// pinned on - so the box it reaches accepts the token and a sibling that
// trusts the same key would not.
func TestClient_SignsForTheRelayItPinned(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	rec := mkRec(t, strings.ToUpper(testRelayFP), 48443)
	c, err := NewClient(rec)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"name":"r1"}`)
	req, err := c.signedRequest(t.Context(), rec, priv, "users-revoke", body)
	if err != nil {
		t.Fatal(err)
	}
	tok := strings.TrimPrefix(req.Header.Get("Authorization"), "Daal-Mgmt-Token ")
	if _, err := VerifyToken(pub, testRelayFP, tok, "POST", "/users/revoke", body); err != nil {
		t.Errorf("the pinned relay refuses the client's token: %v", err)
	}
	if _, err := VerifyToken(pub, otherRelayFP, tok, "POST", "/users/revoke", body); err == nil {
		t.Error("the client's token verified on a relay it was not sent to")
	}
	rec.MgmtTLSFingerprint = ""
	if _, err := c.signedRequest(t.Context(), rec, priv, "users-revoke", body); err == nil {
		t.Error("a request was signed for a record that names no relay")
	}
}

// TestToken_SignsTheRequestNotJustTheOp is the body-binding itself: a
// token minted for one body does not verify for another, for another
// method, or for another path. Before the v2 format a token signed
// "nonce:ts:op" and every one of these verified.
func TestToken_SignsTheRequestNotJustTheOp(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	body := []byte(`{"name":"r43"}`)
	tok, err := MintToken(priv, testRelayFP, "users-revoke", body, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyToken(pub, testRelayFP, tok, "POST", "/users/revoke", body); err != nil {
		t.Fatalf("the request it was minted for must verify: %v", err)
	}
	for name, c := range map[string]struct {
		method, path string
		body         []byte
	}{
		"another recipient in the body": {"POST", "/users/revoke", []byte(`{"name":"r42"}`)},
		"an empty body":                 {"POST", "/users/revoke", nil},
		"one byte of whitespace added":  {"POST", "/users/revoke", []byte(`{"name":"r43"} `)},
		"another method":                {"GET", "/users/revoke", body},
		"another path":                  {"POST", "/rotate-credentials", body},
	} {
		if _, err := VerifyToken(pub, testRelayFP, tok, c.method, c.path, c.body); err == nil {
			t.Errorf("%s: a token minted for POST /users/revoke %s verified", name, body)
		}
	}
}

// TestToken_V1ShapeIsNotMinted: nothing in this package can produce the
// format that did not sign the request.
func TestToken_V1ShapeIsNotMinted(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	for op := range opRoutes {
		tok, err := MintToken(priv, testRelayFP, op, nil, time.Now())
		if err != nil {
			t.Fatalf("MintToken(%s): %v", op, err)
		}
		if parts := strings.Split(tok, ":"); len(parts) != 5 || parts[0] != "v2" {
			t.Errorf("%s: token %q is not v2:nonce:ts:op:sig", op, tok)
		}
	}
	if _, _, _, _, err := ParseToken("abcd:1700000000:users-list:c2ln"); err == nil {
		t.Error("the unversioned v1 token shape parsed")
	}
}

// TestToken_EveryOpHasOneRoute: the op → (method, path) table is the
// only place a request shape is chosen. whoami is in it — it was served
// by the box and unmintable here (the end-to-end rig's finding LC-O2).
func TestToken_EveryOpHasOneRoute(t *testing.T) {
	want := map[string][2]string{
		"rotate-credentials": {"POST", "/rotate-credentials"},
		"rotate-tls":         {"POST", "/rotate-tls"},
		"users-provision":    {"POST", "/users/provision"},
		"users-revoke":       {"POST", "/users/revoke"},
		"users-list":         {"GET", "/users/list"},
		"whoami":             {"GET", "/whoami"},
		"identity":           {"GET", "/identity"},
		"bind-address":       {"POST", "/bind-address"},
		"unbind-address":     {"POST", "/unbind-address"},
	}
	if len(opRoutes) != len(want) {
		t.Errorf("opRoutes has %d ops, want %d", len(opRoutes), len(want))
	}
	for op, w := range want {
		m, p, ok := RouteForOp(op)
		if !ok || m != w[0] || p != w[1] {
			t.Errorf("RouteForOp(%s) = %s %s %v, want %s %s", op, m, p, ok, w[0], w[1])
		}
	}
}

// tokenVector is the cross-module fixture: this package signs it, the
// box (cmd/daal-relay-mgmt, a separate Go module that shares no symbol
// with this one) verifies the same file in
// TestTokenV2Vector_BoxAcceptsWhatThePublisherSigns.
type tokenVector struct {
	Comment      string `json:"comment"`
	SeedHex      string `json:"seed_hex"`
	PublicKeyHex string `json:"public_key_hex"`
	Relay        string `json:"relay_mgmt_tls_fingerprint_hex"`
	Nonce        string `json:"nonce"`
	TS           int64  `json:"ts"`
	Op           string `json:"op"`
	Method       string `json:"method"`
	Path         string `json:"path"`
	Body         string `json:"body"`
	SigningInput string `json:"signing_input"`
	Token        string `json:"token"`
}

const tokenVectorFile = "testdata/token_v2_vector.json"

func TestTokenV2Vector_PublisherProducesTheFixture(t *testing.T) {
	raw, err := os.ReadFile(tokenVectorFile)
	if err != nil {
		t.Fatal(err)
	}
	var vs []tokenVector
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatal(err)
	}
	if len(vs) < 2 {
		t.Fatalf("fixture has %d vectors, want a POST with a body and a GET without", len(vs))
	}
	for _, v := range vs {
		seed, _ := hex.DecodeString(v.SeedHex)
		priv := ed25519.NewKeyFromSeed(seed)
		if got := hex.EncodeToString(priv.Public().(ed25519.PublicKey)); got != v.PublicKeyHex {
			t.Fatalf("%s: public key %s, fixture says %s", v.Op, got, v.PublicKeyHex)
		}
		if a, err := tokenAudience(v.Relay); err != nil || a != v.Relay {
			t.Fatalf("%s: fixture relay %q is not a canonical fingerprint", v.Op, v.Relay)
		}
		method, path, ok := RouteForOp(v.Op)
		if !ok || method != v.Method || path != v.Path {
			t.Fatalf("%s: route %s %s, fixture says %s %s", v.Op, method, path, v.Method, v.Path)
		}
		var body []byte
		if v.Body != "" {
			body = []byte(v.Body)
		}
		ts := time.Unix(v.TS, 0)
		if got := string(signingInput(v.Relay, v.Nonce, strconv.FormatInt(v.TS, 10), v.Op, method, path, body)); got != v.SigningInput {
			t.Errorf("%s: signing input\n got %q\nwant %q", v.Op, got, v.SigningInput)
		}
		// Ed25519 is deterministic, so the whole token is reproducible.
		if got := mintTokenWithNonce(priv, v.Relay, v.Nonce, v.Op, opRoutes[v.Op], body, ts); got != v.Token {
			t.Errorf("%s: token\n got %s\nwant %s", v.Op, got, v.Token)
		}
		sigB64 := v.Token[strings.LastIndex(v.Token, ":")+1:]
		if _, err := base64.StdEncoding.DecodeString(sigB64); err != nil {
			t.Errorf("%s: signature is not standard base64: %v", v.Op, err)
		}
	}
}
