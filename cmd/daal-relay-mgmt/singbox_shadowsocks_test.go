package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func ssDoc() map[string]any {
	return map[string]any{
		"inbounds": []any{
			map[string]any{
				"type": "vless", "tag": tagVLESS, "listen_port": float64(443),
				"users": []any{},
				"tls": map[string]any{"enabled": true, "server_name": "ftp.plusline.net",
					"reality": map[string]any{"enabled": true, "short_id": []any{}}},
			},
		},
	}
}

func ssInbound(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()
	in := findInboundByTag(doc, tagSS)
	if in == nil {
		t.Fatalf("no %q inbound", tagSS)
	}
	return in
}

// TestAppendSSUserSharedInbound is the shape assertion: ONE inbound on
// the canonical port, per-recipient rows on it, and the box-wide iPSK
// minted exactly once — the ws-in lesson applied to a second family
// (per-user inbounds on one port crash sing-box).
func TestAppendSSUserSharedInbound(t *testing.T) {
	doc := ssDoc()
	if err := appendSSUser(doc, userCreds{Name: "r7", SSUserPSK: "AAAAAAAAAAAAAAAAAAAAAA=="}); err != nil {
		t.Fatalf("appendSSUser r7: %v", err)
	}
	in := ssInbound(t, doc)
	if ssListenPort != 8446 {
		t.Fatalf("ssListenPort = %d, want 8446 (canonical relayports value)", ssListenPort)
	}
	if p, _ := in["listen_port"].(int); p != ssListenPort {
		t.Errorf("listen_port = %v, want %d", in["listen_port"], ssListenPort)
	}
	if got, _ := in["type"].(string); got != "shadowsocks" {
		t.Errorf("type = %q, want shadowsocks", got)
	}
	if got, _ := in["method"].(string); got != "2022-blake3-aes-128-gcm" {
		t.Errorf("method = %q, want 2022-blake3-aes-128-gcm", got)
	}
	// TCP only: the firewall opens 8446/tcp and nothing else, so a UDP
	// listener here would bind a socket no packet can reach. UDP rides
	// the client's udp_over_tcp instead.
	if got, _ := in["network"].(string); got != "tcp" {
		t.Errorf("network = %q, want tcp", got)
	}
	// The iPSK must decode with StdEncoding to exactly the method's key
	// length; RawURLEncoding (what hy2/naive use) does not, and a PSK
	// that does not decode is a FATAL at sing-box start.
	ipsk := ssInboundPSK(doc)
	raw, err := base64.StdEncoding.DecodeString(ipsk)
	if err != nil {
		t.Fatalf("box iPSK is not base64-std: %v", err)
	}
	if len(raw) != ssKeyBytes {
		t.Fatalf("box iPSK decodes to %d bytes, want %d", len(raw), ssKeyBytes)
	}

	// Second recipient joins the SAME inbound and does not re-mint the
	// box key.
	if err := appendSSUser(doc, userCreds{Name: "r8", SSUserPSK: "BBBBBBBBBBBBBBBBBBBBBB=="}); err != nil {
		t.Fatalf("appendSSUser r8: %v", err)
	}
	if n := len(asSlice(doc["inbounds"])); n != 2 {
		t.Fatalf("inbound count = %d, want 2 (vless-in + one shared ss-in)", n)
	}
	if got := ssInboundPSK(doc); got != ipsk {
		t.Fatalf("box iPSK changed when a second recipient was added: a re-mint would break every already-distributed shadowsocks route")
	}
	if n := len(asSlice(ssInbound(t, doc)["users"])); n != 2 {
		t.Fatalf("ss users = %d, want 2", n)
	}
	// Idempotent.
	if err := appendSSUser(doc, userCreds{Name: "r8", SSUserPSK: "CCCCCCCCCCCCCCCCCCCCCC=="}); err != nil {
		t.Fatalf("re-append r8: %v", err)
	}
	if n := len(asSlice(ssInbound(t, doc)["users"])); n != 2 {
		t.Fatalf("re-adding r8 changed the user count to %d", n)
	}
}

// TestSSCredentialsArePerRecipient is the "distinct credentials"
// assertion. Two recipients on one relay must not be able to present
// each other's key, and the client password each gets must differ while
// sharing the box half.
func TestSSCredentialsArePerRecipient(t *testing.T) {
	a, err := mintCreds("r1", 1)
	if err != nil {
		t.Fatalf("mintCreds r1: %v", err)
	}
	b, err := mintCreds("r2", 1)
	if err != nil {
		t.Fatalf("mintCreds r2: %v", err)
	}
	if a.SSUserPSK == "" || b.SSUserPSK == "" {
		t.Fatalf("mintCreds produced no shadowsocks uPSK")
	}
	if a.SSUserPSK == b.SSUserPSK {
		t.Fatalf("two recipients minted the SAME shadowsocks uPSK")
	}
	for _, c := range []userCreds{a, b} {
		raw, err := base64.StdEncoding.DecodeString(c.SSUserPSK)
		if err != nil {
			t.Fatalf("%s uPSK is not base64-std: %v", c.Name, err)
		}
		if len(raw) != ssKeyBytes {
			t.Fatalf("%s uPSK decodes to %d bytes, want %d", c.Name, len(raw), ssKeyBytes)
		}
	}
	// The uPSK must never be serialised on its own: it is half a key,
	// and shipping it invites the publisher to re-derive the join.
	blob, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal creds: %v", err)
	}
	if strings.Contains(string(blob), a.SSUserPSK) {
		t.Fatalf("userCreds JSON leaks the bare uPSK; it must travel only inside ss_password")
	}

	doc := ssDoc()
	if err := appendSSUser(doc, a); err != nil {
		t.Fatalf("append a: %v", err)
	}
	if err := appendSSUser(doc, b); err != nil {
		t.Fatalf("append b: %v", err)
	}
	pwA, pwB := ssClientPassword(doc, "r1"), ssClientPassword(doc, "r2")
	if pwA == "" || pwB == "" {
		t.Fatalf("assembled client password empty: %q / %q", pwA, pwB)
	}
	if pwA == pwB {
		t.Fatalf("both recipients got the same client password")
	}
	// "<iPSK>:<uPSK>" — the exact shape sing-shadowsocks2 splits on.
	for name, pw := range map[string]string{"r1": pwA, "r2": pwB} {
		parts := strings.Split(pw, ":")
		if len(parts) != 2 {
			t.Fatalf("%s password %q is not two colon-joined halves", name, pw)
		}
		if parts[0] != ssInboundPSK(doc) {
			t.Errorf("%s first half is not the box iPSK", name)
		}
		for _, half := range parts {
			raw, err := base64.StdEncoding.DecodeString(half)
			if err != nil || len(raw) != ssKeyBytes {
				t.Errorf("%s half %q does not base64-std-decode to %d bytes", name, half, ssKeyBytes)
			}
		}
	}
	if got := ssUserPSK(doc, "r1"); got != a.SSUserPSK {
		t.Errorf("r1 row holds %q, want its own uPSK", got)
	}
}

// TestRemoveSSUserDropsInboundWithLastUser guards the worst failure this
// family can have: an ss inbound with an empty users[] does not stop
// serving, it silently degrades to the SINGLE-user service keyed on the
// box iPSK — the half of the password every pack this relay ever minted
// already carries. Revoking the last recipient would then OPEN the relay
// to everyone previously revoked.
func TestRemoveSSUserDropsInboundWithLastUser(t *testing.T) {
	doc := ssDoc()
	if err := appendSSUser(doc, userCreds{Name: "r1", SSUserPSK: "AAAAAAAAAAAAAAAAAAAAAA=="}); err != nil {
		t.Fatalf("append r1: %v", err)
	}
	if err := appendSSUser(doc, userCreds{Name: "r2", SSUserPSK: "BBBBBBBBBBBBBBBBBBBBBB=="}); err != nil {
		t.Fatalf("append r2: %v", err)
	}
	if !removeSSUser(doc, "r1") {
		t.Fatalf("removeSSUser r1 reported nothing removed")
	}
	in := ssInbound(t, doc)
	users := asSlice(in["users"])
	if len(users) != 1 {
		t.Fatalf("users after removing r1 = %d, want 1", len(users))
	}
	if u, _ := users[0].(map[string]any); u["name"] != "r2" {
		t.Fatalf("the WRONG recipient was removed: %v", users[0])
	}
	if !removeSSUser(doc, "r2") {
		t.Fatalf("removeSSUser r2 reported nothing removed")
	}
	if findInboundByTag(doc, tagSS) != nil {
		t.Fatalf("ss-in survived its last user: an empty users[] makes sing-box fall back to the single-user service keyed on the box iPSK, i.e. an open relay for every revoked recipient")
	}
	if removeSSUser(doc, "r2") {
		t.Fatalf("removeSSUser is not idempotent")
	}
}

// TestAddUserToSingboxServesShadowsocks walks the real provision path
// end to end on disk, which is what the /users/provision handler does.
func TestAddUserToSingboxServesShadowsocks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	creds, err := mintCreds("r1", 1)
	if err != nil {
		t.Fatalf("mintCreds: %v", err)
	}
	if _, err := addUserToSingbox(path, creds, nil); err != nil {
		t.Fatalf("addUserToSingbox: %v", err)
	}
	pw := readSSClientPassword(path, "r1")
	if pw == "" {
		t.Fatalf("provision produced no shadowsocks client password")
	}
	if !strings.HasSuffix(pw, ":"+creds.SSUserPSK) {
		t.Fatalf("assembled password %q does not end in the minted uPSK", pw)
	}
	if !ssUserPresent(path, "r1") {
		t.Fatalf("ssUserPresent says no after a successful provision")
	}
	if ssUserPresent(path, "r2") {
		t.Fatalf("ssUserPresent says yes for a recipient that was never provisioned")
	}
	if !ssMethodValid(ssMethod) {
		t.Fatalf("ssMethodValid rejects the method this box writes")
	}
	if ssMethodValid("aes-128-gcm") {
		t.Fatalf("ssMethodValid accepted a legacy AEAD method; only 2022-blake3-aes-128-gcm may be served")
	}

	// Revocation reaches shadowsocks too.
	found, err := removeUserFromSingbox(path, "r1", nil)
	if err != nil || !found {
		t.Fatalf("removeUserFromSingbox: found=%v err=%v", found, err)
	}
	if readSSClientPassword(path, "r1") != "" {
		t.Fatalf("revoked recipient still has a live shadowsocks credential")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if strings.Contains(string(body), creds.SSUserPSK) {
		t.Fatalf("the revoked recipient's uPSK is still present in the config")
	}
}

// TestRotationKeepsShadowsocksUsers is the rotation assertion the brief
// asks for, in both halves: a surgical per-recipient rotation must move
// the uPSK (so the leaked one stops working), must NOT move the box
// iPSK (which would revoke everyone else's shadowsocks route), and must
// leave every other recipient's row untouched.
func TestRotationKeepsShadowsocksUsers(t *testing.T) {
	doc := ssDoc()
	r1, _ := mintCreds("r1", 1)
	r2, _ := mintCreds("r2", 1)
	for _, c := range []userCreds{r1, r2} {
		if err := appendVLESSUser(doc, c); err != nil {
			t.Fatalf("appendVLESSUser: %v", err)
		}
		if err := appendSSUser(doc, c); err != nil {
			t.Fatalf("appendSSUser: %v", err)
		}
	}
	ipskBefore := ssInboundPSK(doc)
	otherBefore := ssUserPSK(doc, "r2")

	fresh, _ := mintCreds("r1", 2)
	res, err := rotateRecipientCreds(doc, "r1", fresh)
	if err != nil {
		t.Fatalf("rotateRecipientCreds: %v", err)
	}
	var sawSS bool
	for _, tag := range res.Inbounds {
		if tag == tagSS {
			sawSS = true
		}
	}
	if !sawSS {
		t.Fatalf("rotation did not report the %q inbound: %v", tagSS, res.Inbounds)
	}
	if got := ssUserPSK(doc, "r1"); got != fresh.SSUserPSK {
		t.Fatalf("r1's uPSK was not rotated (got %q)", got)
	}
	if got := ssUserPSK(doc, "r2"); got != otherBefore {
		t.Fatalf("rotating r1 changed r2's shadowsocks credential")
	}
	if got := ssInboundPSK(doc); got != ipskBefore {
		t.Fatalf("rotation re-minted the BOX iPSK; that would break the shadowsocks route of every other recipient on this relay")
	}
	if res.Creds.SSMethod != ssMethod {
		t.Fatalf("rotation echoed method %q, want %q", res.Creds.SSMethod, ssMethod)
	}
	want := ipskBefore + ":" + fresh.SSUserPSK
	if res.Creds.SSPassword != want {
		t.Fatalf("rotation echoed password %q, want the live iPSK joined to the fresh uPSK", res.Creds.SSPassword)
	}
	// The retired credential must be gone from the whole document — the
	// same fail-closed rule every other family's rotation obeys.
	if err := assertRetiredAbsent(doc, res.retired); err != nil {
		t.Fatalf("assertRetiredAbsent: %v", err)
	}
	if !ssRetired(res.retired, r1.SSUserPSK) {
		t.Fatalf("the old uPSK was not recorded as retired, so nothing checks it is gone")
	}
}

func ssRetired(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// TestHealthAdvertisesShadowsocks pins the capability token as RAW TEXT
// on the wire, not as a constant name. It is a cross-module contract
// with publisher/deploy/mgmt.CapShadowsocks2022, the two modules share
// no symbol, and the publisher fails CLOSED — so a drift here does not
// break a build, it silently tells every publisher that no relay can
// serve the family.
func TestHealthAdvertisesShadowsocks(t *testing.T) {
	srv, _, _, _ := newTestServer(t)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got struct {
		OK           bool     `json:"ok"`
		Capabilities []string `json:"capabilities"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, c := range got.Capabilities {
		if c == "shadowsocks-2022" {
			found = true
		}
	}
	if !found {
		t.Fatalf("/health does not advertise \"shadowsocks-2022\": %v", got.Capabilities)
	}
	// Asserted unconditionally, unlike bind-address: this token
	// describes what the BINARY does, not what the host grants it. The
	// box needs no privilege and no cloud-init field to create ss-in.
	if capShadowsocks2022 != "shadowsocks-2022" {
		t.Fatalf("capability token const = %q", capShadowsocks2022)
	}
}
