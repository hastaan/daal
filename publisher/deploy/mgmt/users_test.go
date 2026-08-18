package mgmt

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestClient_ProvisionUser_Round_Trips boots a TLS test server that
// validates the signed token, decodes the request body, and returns
// a UserCreds payload. The client must decode it back faithfully.
func TestClient_ProvisionUser_RoundTrips(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	var sawName string
	mux := http.NewServeMux()
	mux.HandleFunc("/users/provision", func(w http.ResponseWriter, r *http.Request) {
		hdr := r.Header.Get("Authorization")
		tok := strings.TrimPrefix(hdr, "Daal-Mgmt-Token ")
		nonce, tsStr, op, sig, err := ParseToken(tok)
		if err != nil || op != "users-provision" {
			http.Error(w, "bad token", 401)
			return
		}
		if !ed25519.Verify(pub, []byte(nonce+":"+tsStr+":"+op), sig) {
			http.Error(w, "sig", 401)
			return
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		sawName = body["name"]
		_ = json.NewEncoder(w).Encode(UserCreds{
			Name:              body["name"],
			VLESSUUID:         "00000000-0000-0000-0000-000000000000",
			RealityShortID:    "deadbeef",
			Hy2Password:       "aGVsbG93b3JsZGFwYXNzd2Q",
			NaivePassword:     "bmFpdmVwYXNzd29yZGFiY2Q",
			WSPath:            "/r1/cafebabe",
			ProvisionedAtUnix: 1700000000,
		})
	})
	ts, fp := startTLSServer(t, mux)
	defer ts.Close()

	port, host := splitURL(t, ts.URL)
	rec := mkRec(t, fp, port)
	rec.PublicIP = net.ParseIP(host)
	cli, err := NewClient(rec)
	if err != nil {
		t.Fatal(err)
	}
	creds, err := cli.ProvisionUser(context.Background(), rec, priv, "r1")
	if err != nil {
		t.Fatalf("ProvisionUser: %v", err)
	}
	if sawName != "r1" {
		t.Errorf("server saw name = %q", sawName)
	}
	if creds.Name != "r1" {
		t.Errorf("Name = %q", creds.Name)
	}
	if creds.RealityShortID != "deadbeef" {
		t.Errorf("RealityShortID round-trip lost: %q", creds.RealityShortID)
	}
	if creds.WSPath != "/r1/cafebabe" {
		t.Errorf("WSPath round-trip lost: %q", creds.WSPath)
	}
}

func TestClient_RevokeUser_RoundTrips(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	mux := http.NewServeMux()
	mux.HandleFunc("/users/revoke", func(w http.ResponseWriter, r *http.Request) {
		hdr := r.Header.Get("Authorization")
		tok := strings.TrimPrefix(hdr, "Daal-Mgmt-Token ")
		nonce, tsStr, op, sig, err := ParseToken(tok)
		if err != nil || op != "users-revoke" {
			http.Error(w, "bad token", 401)
			return
		}
		if !ed25519.Verify(pub, []byte(nonce+":"+tsStr+":"+op), sig) {
			http.Error(w, "sig", 401)
			return
		}
		_ = json.NewEncoder(w).Encode(RevokeResp{RevokedAtUnix: 1700000123})
	})
	ts, fp := startTLSServer(t, mux)
	defer ts.Close()

	port, host := splitURL(t, ts.URL)
	rec := mkRec(t, fp, port)
	rec.PublicIP = net.ParseIP(host)
	cli, err := NewClient(rec)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cli.RevokeUser(context.Background(), rec, priv, "r17")
	if err != nil {
		t.Fatalf("RevokeUser: %v", err)
	}
	if resp.RevokedAtUnix != 1700000123 {
		t.Errorf("RevokedAtUnix = %d", resp.RevokedAtUnix)
	}
}

func TestClient_ListUsers_RoundTrips(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	mux := http.NewServeMux()
	mux.HandleFunc("/users/list", func(w http.ResponseWriter, r *http.Request) {
		hdr := r.Header.Get("Authorization")
		tok := strings.TrimPrefix(hdr, "Daal-Mgmt-Token ")
		nonce, tsStr, op, sig, err := ParseToken(tok)
		if err != nil || op != "users-list" {
			http.Error(w, "bad token", 401)
			return
		}
		if !ed25519.Verify(pub, []byte(nonce+":"+tsStr+":"+op), sig) {
			http.Error(w, "sig", 401)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"users": []UserMeta{{Name: "r1"}, {Name: "r3"}, {Name: "r17"}},
		})
	})
	ts, fp := startTLSServer(t, mux)
	defer ts.Close()

	port, host := splitURL(t, ts.URL)
	rec := mkRec(t, fp, port)
	rec.PublicIP = net.ParseIP(host)
	cli, err := NewClient(rec)
	if err != nil {
		t.Fatal(err)
	}
	users, err := cli.ListUsers(context.Background(), rec, priv)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 3 {
		t.Fatalf("len = %d want 3", len(users))
	}
	names := map[string]bool{}
	for _, u := range users {
		names[u.Name] = true
	}
	for _, want := range []string{"r1", "r3", "r17"} {
		if !names[want] {
			t.Errorf("missing %q", want)
		}
	}
}

// TestMintToken_AcceptsUsersOps pins that the token minter now
// allows the three FRP-14 ops.
func TestMintToken_AcceptsUsersOps(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	for _, op := range []string{"users-provision", "users-revoke", "users-list"} {
		if _, err := MintToken(priv, op, time.Now()); err != nil {
			t.Errorf("MintToken(%q) = %v", op, err)
		}
	}
}

// TestTUICCredsWireContract pins both halves of the tuic hop across the
// box→publisher boundary: the JSON key names (the box writes them, this
// struct reads them, and encoding/json drops what is not declared) and
// the capability token literal.
//
// This project has shipped an inert feature exactly this way once
// already — cover_sni and mux_inbound were echoed by the box and
// swallowed here — so the keys are asserted from raw JSON rather than
// from a round trip through the same struct, which would pass even if
// both sides were wrong together.
func TestTUICCredsWireContract(t *testing.T) {
	raw := []byte(`{"name":"r1","vless_uuid":"v","reality_short_id":"s",
	  "hy2_password":"h","naive_password":"n","ws_path":"/r1/ab","provisioned_at_unix":7,
	  "tuic_uuid":"99999999-8888-7777-6666-555555555555","tuic_password":"tuicpw"}`)
	var got UserCreds
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.TUICUUID != "99999999-8888-7777-6666-555555555555" {
		t.Errorf("tuic_uuid did not survive the hop: %+v", got)
	}
	if got.TUICPassword != "tuicpw" {
		t.Errorf("tuic_password did not survive the hop: %+v", got)
	}
	// A relay that does not serve the family sends neither key. That
	// absence — not an error, not a flag — is what makes the pack
	// renderer refuse, so it must decode cleanly to empty.
	var silent UserCreds
	if err := json.Unmarshal([]byte(`{"name":"r1"}`), &silent); err != nil {
		t.Fatalf("a box that says nothing about tuic must still decode: %v", err)
	}
	if silent.TUICUUID != "" || silent.TUICPassword != "" {
		t.Errorf("expected empty tuic creds, got %+v", silent)
	}

	// Wire contract with cmd/daal-relay-mgmt's capTUICUsers, which is in
	// a different module and cannot be imported here.
	if CapTUICUsers != "tuic-users" {
		t.Fatalf("token = %q, want tuic-users", CapTUICUsers)
	}
}
