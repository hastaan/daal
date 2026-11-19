package main

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const testRealityPub = "Ck9nvVEcYnAlUUlBl9dqfKvyEpqTFDTjHmwPmLnKvVM"

// identityServer is a relay provisioned for `families` with its
// first-boot material on disk and NO recipient.
func identityServer(t *testing.T, families ...string) (*server, ed25519.PrivateKey, string, *int) {
	t.Helper()
	srv, priv, configPath, reloads := familyServer(t, true, families...)
	if err := os.WriteFile(srv.realityPubPath, []byte(testRealityPub+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(srv.tlsCertPath)
	if _, err := ensureSelfSignedCert(srv.tlsCertPath, filepath.Join(dir, "tls-key.pem"), filepath.Join(dir, "fpr")); err != nil {
		t.Fatal(err)
	}
	return srv, priv, configPath, reloads
}

func getIdentity(t *testing.T, ts *httptest.Server, priv ed25519.PrivateKey) relayIdentity {
	t.Helper()
	resp := getURL(t, ts.URL+"/identity", priv, identityOp)
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := readAll(resp.Body)
		t.Fatalf("GET /identity: status %d body %s", resp.StatusCode, body)
	}
	var id relayIdentity
	if err := json.NewDecoder(resp.Body).Decode(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// The point of the route: a relay with NO recipient says everything a
// publisher needs to sign its endpoints, and saying it changes nothing.
func TestIdentity_BeforeAnyRecipient(t *testing.T) {
	srv, priv, configPath, reloads := identityServer(t,
		famVLESSReality, famHysteria2, famNaive, famWebSocketTLS, famShadowsocks, famAnyTLS)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()
	before, _ := os.ReadFile(configPath)

	id := getIdentity(t, ts, priv)

	if id.IdentityVersion != identityVersion {
		t.Errorf("identity_version = %d, want %d", id.IdentityVersion, identityVersion)
	}
	if id.RealityPublicKey != testRealityPub {
		t.Errorf("reality_public_key = %q, want %q", id.RealityPublicKey, testRealityPub)
	}
	if want := srv.readTLSCertSHA256(); want == "" || id.TLSCertSHA256 != want {
		t.Errorf("tls_cert_sha256 = %q, want the data-plane SPKI pin %q", id.TLSCertSHA256, want)
	}
	if id.CoverSNI == "" || id.CoverSNI != readCoverSNI(configPath) {
		t.Errorf("cover_sni = %q, want the live config's %q", id.CoverSNI, readCoverSNI(configPath))
	}
	// shadowsocks is served, but its box-wide key is minted with the
	// first recipient: no digest yet, and the reply must SAY so.
	if id.SSServerKeySHA256 != "" || id.SSMethod != "" {
		t.Errorf("shadowsocks material present before the key exists: %q %q", id.SSMethod, id.SSServerKeySHA256)
	}
	if !reflect.DeepEqual(id.PendingFamilies, []string{famShadowsocks}) {
		t.Errorf("pending_families = %v, want [shadowsocks]", id.PendingFamilies)
	}
	got := map[string]identityFamily{}
	for _, f := range id.Families {
		got[f.Family] = f
	}
	want := map[string]identityFamily{
		famVLESSReality: {famVLESSReality, 443, true},
		famHysteria2:    {famHysteria2, 443, true},
		famNaive:        {famNaive, naiveListenPort, false},
		famWebSocketTLS: {famWebSocketTLS, wsListenPort, false},
		famShadowsocks:  {famShadowsocks, ssListenPort, false},
		famAnyTLS:       {famAnyTLS, anytlsListenPort, false},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("families = %+v\nwant       %+v", got, want)
	}

	// Read-only: the config is byte-identical and nothing was reloaded.
	after, _ := os.ReadFile(configPath)
	if string(before) != string(after) {
		t.Error("GET /identity rewrote the sing-box config")
	}
	if *reloads != 0 {
		t.Errorf("GET /identity reloaded sing-box %d time(s)", *reloads)
	}
}

// What the relay says about itself is what a recipient's reply says
// about it: one relay, one identity, whichever route it was read by.
func TestIdentity_AgreesWithProvisionReply(t *testing.T) {
	srv, priv, _, _ := identityServer(t,
		famVLESSReality, famHysteria2, famNaive, famWebSocketTLS, famShadowsocks, famAnyTLS)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	resp := postJSON(t, ts.URL+"/users/provision", priv, "users-provision", provisionReq{Name: "r1"})
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := readAll(resp.Body)
		t.Fatalf("provision: status %d body %s", resp.StatusCode, body)
	}
	var creds userCreds
	if err := json.NewDecoder(resp.Body).Decode(&creds); err != nil {
		t.Fatal(err)
	}

	id := getIdentity(t, ts, priv)
	if id.RealityPublicKey != creds.RealityPublicKey || id.TLSCertSHA256 != creds.TLSCertSHA256 || id.CoverSNI != creds.CoverSNI {
		t.Errorf("identity %+v disagrees with the provision reply (%q, %q, %q)",
			id, creds.RealityPublicKey, creds.TLSCertSHA256, creds.CoverSNI)
	}
	if len(id.PendingFamilies) != 0 {
		t.Errorf("pending_families = %v after the first recipient, want none", id.PendingFamilies)
	}
	if id.SSMethod != creds.SSMethod || creds.SSMethod == "" {
		t.Errorf("ss_method = %q, provision reply says %q", id.SSMethod, creds.SSMethod)
	}
	serverKey, _, ok := strings.Cut(creds.SSPassword, ":")
	if !ok || serverKey == "" {
		t.Fatalf("provision reply's ss_password is not <server key>:<user key>: %q", creds.SSPassword)
	}
	if id.SSServerKeySHA256 != ssServerKeyDigest(serverKey) {
		t.Errorf("ss_server_key_sha256 = %q, want the digest of the reply's server key", id.SSServerKeySHA256)
	}
	// The key itself is never in this reply — not under any name.
	raw, _ := json.Marshal(id)
	if strings.Contains(string(raw), serverKey) {
		t.Error("the /identity reply carries the shadowsocks server key in the clear")
	}
	for _, f := range id.Families {
		if !f.Listening {
			t.Errorf("%s is not listening after the first recipient", f.Family)
		}
	}
}

// The digest is a wire contract with bundle.SSServerKeyDigest in
// another module (TestSSServerKeyDigestVector there pins the same
// vector). If either side drifts, a relay's identity and the endpoint a
// recipient recomputes stop agreeing and shadowsocks is refused at
// import.
func TestIdentitySSDigestMatchesTheSignedEndpointRule(t *testing.T) {
	const key = "AAECAwQFBgcICQoLDA0ODw=="
	const want = "fcdbdca159bd5651a33cf17ba64d6bcda8b6fb65929529933faf309ab580eae2"
	if got := ssServerKeyDigest(key); got != want {
		t.Fatalf("ssServerKeyDigest(%q) = %s, want %s", key, got, want)
	}
}

// A relay that serves only shadowsocks has no REALITY key and no TLS
// pin to state, and must not invent either from files left on disk.
func TestIdentity_StatesOnlyWhatTheRelayServes(t *testing.T) {
	srv, priv, _, _ := identityServer(t, famShadowsocks)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()
	id := getIdentity(t, ts, priv)
	if id.RealityPublicKey != "" || id.TLSCertSHA256 != "" || id.CoverSNI != "" {
		t.Errorf("a shadowsocks-only relay stated material for families it does not serve: %+v", id)
	}
	if len(id.Families) != 1 || id.Families[0].Family != famShadowsocks {
		t.Errorf("families = %+v, want shadowsocks only", id.Families)
	}
}

// After /rotate-tls the identity names the NEW cover host: it is read,
// not remembered. This is what the publisher re-signs from.
func TestIdentity_FollowsRotateTLS(t *testing.T) {
	srv, priv, _, _ := identityServer(t, famVLESSReality, famHysteria2)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()
	before := getIdentity(t, ts, priv)

	resp := postJSON(t, ts.URL+"/rotate-tls", priv, "rotate-tls", map[string]any{
		"new_sni": "www.example.org", "new_dests": []string{"www.example.org:443"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := readAll(resp.Body)
		t.Fatalf("rotate-tls: status %d body %s", resp.StatusCode, body)
	}
	after := getIdentity(t, ts, priv)
	if after.CoverSNI != "www.example.org" || after.CoverSNI == before.CoverSNI {
		t.Errorf("cover_sni after rotate-tls = %q (was %q), want www.example.org", after.CoverSNI, before.CoverSNI)
	}
	if after.RealityPublicKey != before.RealityPublicKey || after.TLSCertSHA256 != before.TLSCertSHA256 {
		t.Error("rotate-tls moved key material in the identity; it must move the cover host only")
	}
}

func TestIdentity_RequiresAnIdentityToken(t *testing.T) {
	srv, priv, _, _ := identityServer(t, famVLESSReality)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	// No token.
	resp, err := http.Get(ts.URL + "/identity")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no token: status %d, want 401", resp.StatusCode)
	}
	// A valid token for a different op.
	resp = getURL(t, ts.URL+"/identity", priv, "users-list")
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("users-list token: status %d, want 401", resp.StatusCode)
	}
	// The right token, the wrong method.
	resp = postJSON(t, ts.URL+"/identity", priv, identityOp, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST: status %d, want 405", resp.StatusCode)
	}
}

// A relay that was told its family set and cannot read it must not
// answer with a guess: the publisher would sign the guess.
func TestIdentity_FailsClosedOnAnUnreadableFamilySet(t *testing.T) {
	srv, priv, _, _ := identityServer(t, famVLESSReality)
	if err := os.WriteFile(srv.familiesPath, []byte("\n# nothing\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()
	resp := getURL(t, ts.URL+"/identity", priv, identityOp)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status %d, want 500", resp.StatusCode)
	}
}
