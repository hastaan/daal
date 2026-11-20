package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

// cdnDoorUUIDs returns uuid by name for every row of ws-cdn-in, or nil
// when the door is closed.
func cdnDoorUUIDs(t *testing.T, cfg string) map[string]string {
	t.Helper()
	doc, err := loadSingboxDoc(cfg)
	if err != nil {
		t.Fatal(err)
	}
	in := findInboundByTag(doc, tagCDN)
	if in == nil {
		return nil
	}
	out := map[string]string{}
	for _, raw := range asSlice(in["users"]) {
		u, _ := raw.(map[string]any)
		n, _ := u["name"].(string)
		id, _ := u["uuid"].(string)
		out[n] = id
	}
	return out
}

// Revocation reaches the Cloudflare door. Through the real routes and
// signed tokens: open the door with two recipients, revoke one, and the
// revoked recipient's UUID is gone from ws-cdn-in while the other's
// stays. A recipient added afterwards gets a row on the open door, and
// the last one leaving closes it. Before the hooks were wired, a
// recipient revoked after the door opened kept a way in through
// Cloudflare.
func TestRevokedRecipientLosesTheCDNDoor(t *testing.T) {
	srv, priv, cfg, _ := newUsersTestServer(t)
	old := cdnDir
	cdnDir = filepath.Join(t.TempDir(), "cdn")
	t.Cleanup(func() { cdnDir = old })
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	creds := map[string]userCreds{}
	for _, name := range []string{"r1", "r2"} {
		resp := postJSON(t, ts.URL+"/users/provision", priv, "users-provision", provisionReq{Name: name})
		var c userCreds
		_ = json.NewDecoder(resp.Body).Decode(&c)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || c.VLESSUUID == "" {
			t.Fatalf("provision %s: %d %+v", name, resp.StatusCode, c)
		}
		creds[name] = c
	}

	m := makeCDNMaterial(t, srv.now())
	resp := postJSON(t, ts.URL+"/cdn", priv, cdnOp, enableReq(m))
	if resp.StatusCode != http.StatusOK {
		body, _ := readAll(resp.Body)
		t.Fatalf("POST /cdn enable: %d %s", resp.StatusCode, body)
	}
	resp.Body.Close()
	door := cdnDoorUUIDs(t, cfg)
	if door["r1"] != creds["r1"].VLESSUUID || door["r2"] != creds["r2"].VLESSUUID {
		t.Fatalf("door after enable = %v", door)
	}

	resp = postJSON(t, ts.URL+"/users/revoke", priv, "users-revoke", revokeReq{Name: "r1"})
	if resp.StatusCode != http.StatusOK {
		body, _ := readAll(resp.Body)
		t.Fatalf("revoke r1: %d %s", resp.StatusCode, body)
	}
	resp.Body.Close()
	door = cdnDoorUUIDs(t, cfg)
	if _, ok := door["r1"]; ok {
		t.Fatalf("r1 was revoked and still holds a row on ws-cdn-in: %v", door)
	}
	for n, id := range door {
		if id == creds["r1"].VLESSUUID {
			t.Fatalf("r1's UUID is still on ws-cdn-in under %q", n)
		}
	}
	if door["r2"] != creds["r2"].VLESSUUID {
		t.Fatalf("r2 lost the door when r1 was revoked: %v", door)
	}

	resp = postJSON(t, ts.URL+"/users/provision", priv, "users-provision", provisionReq{Name: "r3"})
	var c3 userCreds
	_ = json.NewDecoder(resp.Body).Decode(&c3)
	resp.Body.Close()
	if door = cdnDoorUUIDs(t, cfg); door["r3"] != c3.VLESSUUID || c3.VLESSUUID == "" {
		t.Fatalf("a recipient added while the door is open has no row on it: %v", door)
	}

	for _, name := range []string{"r2", "r3"} {
		resp = postJSON(t, ts.URL+"/users/revoke", priv, "users-revoke", revokeReq{Name: name})
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("revoke %s: %d", name, resp.StatusCode)
		}
	}
	if door = cdnDoorUUIDs(t, cfg); door != nil {
		t.Fatalf("the last recipient left and the door is still open: %v", door)
	}
}

// A recipient who holds a row only on the door is still a recipient:
// revoke finds them (found=true, 200) rather than answering 404 and
// leaving the row.
func TestRevokeFindsARecipientOnlyOnTheDoor(t *testing.T) {
	srv, priv, cfg, _ := newUsersTestServer(t)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()
	doc, err := loadSingboxDoc(cfg)
	if err != nil {
		t.Fatal(err)
	}
	setCDNInbound(doc, cdnInbound("/0123456789abcdef", []any{map[string]any{"uuid": "uuid-x", "name": "r77"}}))
	if err := writeSingboxDoc(cfg, doc, nil); err != nil {
		t.Fatal(err)
	}
	resp := postJSON(t, ts.URL+"/users/revoke", priv, "users-revoke", revokeReq{Name: "r77"})
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke of a door-only recipient: %d, want 200", resp.StatusCode)
	}
	if cdnDoorUUIDs(t, cfg) != nil {
		t.Fatal("door-only recipient still on ws-cdn-in")
	}
}

// /cdn is a signed, single-use route and /health says the binary has it.
func TestCDNRouteIsSignedSingleUseAndAdvertised(t *testing.T) {
	if opFromPath("/cdn") != cdnOp || !singleUseOp(cdnOp) {
		t.Fatalf("opFromPath(/cdn)=%q singleUse=%v", opFromPath("/cdn"), singleUseOp(cdnOp))
	}
	srv, _, _, _ := newUsersTestServer(t)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/cdn", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned POST /cdn: %d, want 401", resp.StatusCode)
	}
	resp, err = http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var h struct {
		Capabilities []string `json:"capabilities"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&h)
	found := false
	for _, c := range h.Capabilities {
		if c == "cdn" {
			found = true
		}
	}
	if !found {
		t.Fatalf("/health capabilities %v lack \"cdn\"", h.Capabilities)
	}
}
