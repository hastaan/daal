package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// tuicScaffold is a config in the shape cloud-init writes for a relay
// whose toolbox profile enabled tuic: vless-in + hy2-in as always, plus
// a tuic-in with an empty users[] (sing-box's tuic inbound has no
// "missing users" fatal, unlike naive).
func tuicScaffold(t *testing.T, withTUIC bool) string {
	t.Helper()
	inbounds := []any{
		map[string]any{
			"type": "vless", "tag": tagVLESS, "listen_port": float64(443),
			"users": []any{},
			"tls": map[string]any{"enabled": true, "server_name": "cdn.example.net",
				"reality": map[string]any{"enabled": true, "short_id": []any{}}},
		},
		map[string]any{"type": "hysteria2", "tag": tagHy2, "listen_port": float64(443), "users": []any{}},
	}
	if withTUIC {
		inbounds = append(inbounds, map[string]any{
			"type": "tuic", "tag": tagTUIC, "listen_port": float64(tuicListenPort),
			"users":              []any{},
			"congestion_control": "bbr",
			"tls": map[string]any{"enabled": true, "alpn": []any{"h3"},
				"certificate_path": tlsCertPath, "key_path": tlsKeyPath},
		})
	}
	body, err := json.Marshal(map[string]any{
		"log":       map[string]any{"level": "info"},
		"inbounds":  inbounds,
		"outbounds": []any{map[string]any{"type": "direct"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestTUICUsersAreAppendedOnlyWhenTheInboundExists is the whole
// provision-time contract in one test.
//
// The two halves are not symmetric. On a relay that serves tuic the row
// must appear, or the pack ships a credential the box will not honour.
// On a relay that does not, the appender must be a silent no-op AND
// tuicUserPresent must report false, because that false is the only
// signal the publisher gets — it blanks the creds, and the pack minter
// then refuses to render a tuic route at all.
func TestTUICUsersAreAppendedOnlyWhenTheInboundExists(t *testing.T) {
	creds := userCreds{
		Name: "r1", VLESSUUID: "11111111-2222-3333-4444-555555555555",
		RealityShortID: "deadbeef", WSPath: "/r1/cafebabe",
		TUICUUID: "99999999-8888-7777-6666-555555555555", TUICPassword: "tuicpw",
	}

	// Served.
	path := tuicScaffold(t, true)
	if _, err := addUserToSingbox(path, creds, nil); err != nil {
		t.Fatalf("addUserToSingbox: %v", err)
	}
	if !tuicUserPresent(path, "r1") {
		t.Fatal("tuic row missing on a relay that serves the family")
	}
	doc, err := loadSingboxDoc(path)
	if err != nil {
		t.Fatal(err)
	}
	in := findInboundByTag(doc, tagTUIC)
	users, _ := in["users"].([]any)
	if len(users) != 1 {
		t.Fatalf("users = %v", users)
	}
	u := users[0].(map[string]any)
	// tuic authenticates on the PAIR; a row with only one half is a row
	// that never authenticates.
	if u["uuid"] != creds.TUICUUID || u["password"] != creds.TUICPassword || u["name"] != "r1" {
		t.Errorf("tuic user row = %v", u)
	}
	// Idempotent: a repeated provision must not duplicate the row.
	doc2, _ := loadSingboxDoc(path)
	appendTUICUser(doc2, creds)
	in2 := findInboundByTag(doc2, tagTUIC)
	if got, _ := in2["users"].([]any); len(got) != 1 {
		t.Errorf("appendTUICUser is not idempotent: %v", got)
	}

	// Not served.
	bare := tuicScaffold(t, false)
	if _, err := addUserToSingbox(bare, creds, nil); err != nil {
		t.Fatalf("addUserToSingbox on a tuic-less relay must succeed: %v", err)
	}
	if tuicUserPresent(bare, "r1") {
		t.Fatal("tuicUserPresent must be false when the relay does not serve tuic")
	}
	bareDoc, _ := loadSingboxDoc(bare)
	if findInboundByTag(bareDoc, tagTUIC) != nil {
		t.Error("the mgmt service must never CREATE a tuic inbound: binding 8443/udp is a " +
			"provision-time decision that the cloud-init ufw rules have to match")
	}
}

// TestTUICPortDriftIsRefused covers the drift guard. relayports decides
// the port and cloud-init writes it; this binary only mirrors the
// number. If they ever disagree, the publisher would render a client
// outbound dialling a port nothing listens on, so the row is refused and
// the publisher fails closed instead.
func TestTUICPortDriftIsRefused(t *testing.T) {
	doc := map[string]any{"inbounds": []any{
		map[string]any{"type": "tuic", "tag": tagTUIC, "listen_port": float64(9999), "users": []any{}},
	}}
	if appendTUICUser(doc, userCreds{Name: "r1", TUICUUID: "u", TUICPassword: "p"}) {
		t.Error("a tuic-in on the wrong port must not accept users")
	}
	in := findInboundByTag(doc, tagTUIC)
	if users, _ := in["users"].([]any); len(users) != 0 {
		t.Errorf("users = %v, want none", users)
	}
}

// TestTUICCredentialsArePerRecipientAndIndependent pins two separate
// properties that both matter under a leak.
//
// Distinct per recipient: two recipients must never share a tuic
// credential, or revoking one revokes both and a leak from one opens
// the other's route.
//
// Independent of the VLESS uuid: reusing one identifier across tiers
// means a single leaked pack links the recipient on the REALITY tier
// too, and a rotation of one leaves the leaked value live on the other.
func TestTUICCredentialsArePerRecipientAndIndependent(t *testing.T) {
	a, err := mintCreds("r1", 1)
	if err != nil {
		t.Fatal(err)
	}
	b, err := mintCreds("r2", 2)
	if err != nil {
		t.Fatal(err)
	}
	if a.TUICUUID == "" || a.TUICPassword == "" {
		t.Fatalf("mintCreds produced no tuic pair: %+v", a)
	}
	if a.TUICUUID == b.TUICUUID {
		t.Error("two recipients share a tuic uuid")
	}
	if a.TUICPassword == b.TUICPassword {
		t.Error("two recipients share a tuic password")
	}
	if a.TUICUUID == a.VLESSUUID {
		t.Error("tuic uuid must be independent of the VLESS uuid")
	}
	for _, other := range []string{a.Hy2Password, a.NaivePassword, a.RealityShortID} {
		if a.TUICPassword == other {
			t.Errorf("tuic password collides with another tier's secret (%q)", other)
		}
	}
}

// TestRotateCredentialsCoversTUIC. Rotation exists to make a leaked
// credential dead. A tier the rotator skips keeps the leaked value live
// on the wire while reporting success — the exact failure the naive
// `username` vs `name` note in rotate.go records.
func TestRotateCredentialsCoversTUIC(t *testing.T) {
	doc := map[string]any{"inbounds": []any{
		map[string]any{"type": "vless", "tag": tagVLESS, "users": []any{
			map[string]any{"name": "r1", "uuid": "old-vless"},
		}},
		map[string]any{"type": "tuic", "tag": tagTUIC, "users": []any{
			map[string]any{"name": "r1", "uuid": "old-tuic-uuid", "password": "old-tuic-pw"},
			map[string]any{"name": "r2", "uuid": "keep-uuid", "password": "keep-pw"},
		}},
	}}
	fresh := userCreds{
		Name: "r1", VLESSUUID: "new-vless",
		TUICUUID: "new-tuic-uuid", TUICPassword: "new-tuic-pw",
	}
	res, err := rotateRecipientCreds(doc, "r1", fresh)
	if err != nil {
		t.Fatalf("rotateRecipientCreds: %v", err)
	}
	in := findInboundByTag(doc, tagTUIC)
	users, _ := in["users"].([]any)
	got := users[0].(map[string]any)
	if got["uuid"] != "new-tuic-uuid" || got["password"] != "new-tuic-pw" {
		t.Errorf("tuic row not rotated: %v", got)
	}
	// BOTH halves move: tuic authenticates on the pair, so leaving the
	// uuid behind keeps half a leaked credential live.
	other := users[1].(map[string]any)
	if other["uuid"] != "keep-uuid" || other["password"] != "keep-pw" {
		t.Errorf("rotating r1 disturbed r2: %v", other)
	}
	if res.Creds.TUICUUID != "new-tuic-uuid" || res.Creds.TUICPassword != "new-tuic-pw" {
		t.Errorf("rotation must echo the new tuic pair: %+v", res.Creds)
	}
	// The old values must be recorded as retired, and the structural
	// sweep must agree they are gone. That sweep is what turns "we
	// rotated" into "the leaked value is not in the config any more".
	retired := map[string]bool{}
	for _, r := range res.retired {
		retired[r] = true
	}
	for _, want := range []string{"old-tuic-uuid", "old-tuic-pw"} {
		if !retired[want] {
			t.Errorf("retired set %v does not name %q", res.retired, want)
		}
	}
	if err := assertRetiredAbsent(doc, res.retired); err != nil {
		t.Errorf("rotation left a retired credential in the config: %v", err)
	}
}

// TestRotateOnTUICLessRelayEchoesNoTUICCreds: a relay that does not
// serve tuic must not hand back a pair the publisher would mint into an
// undialable route. Same fail-closed contract as /users/provision.
func TestRotateOnTUICLessRelayEchoesNoTUICCreds(t *testing.T) {
	doc := map[string]any{"inbounds": []any{
		map[string]any{"type": "vless", "tag": tagVLESS, "users": []any{
			map[string]any{"name": "r1", "uuid": "old-vless"},
		}},
	}}
	res, err := rotateRecipientCreds(doc, "r1", userCreds{
		Name: "r1", VLESSUUID: "new-vless",
		TUICUUID: "should-not-escape", TUICPassword: "should-not-escape",
	})
	if err != nil {
		t.Fatalf("rotateRecipientCreds: %v", err)
	}
	if res.Creds.TUICUUID != "" || res.Creds.TUICPassword != "" {
		t.Errorf("tuic creds leaked from a relay that does not serve tuic: %+v", res.Creds)
	}
}

// TestHealthAdvertisesTUICUsers pins the wire literal shared with
// publisher/deploy/mgmt.CapTUICUsers. The two constants live in
// different Go modules that cannot import each other, so a rename on one
// side is silent: the publisher stops seeing the token, decides the box
// is too old, and refuses a family the relay serves perfectly well.
//
// Advertised unconditionally, and note what it does NOT claim: not
// "this relay serves tuic" — the inbound comes from cloud-init and only
// when the toolbox profile selected it — but "this binary knows how to
// put a recipient into a tuic-in inbound if one is there". Those are
// separately pinned artifacts, and their mismatch is the whole reason
// the token exists.
func TestHealthAdvertisesTUICUsers(t *testing.T) {
	srv, _, _, _ := newTestServer(t)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got struct {
		Capabilities []string `json:"capabilities"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range got.Capabilities {
		if c == "tuic-users" {
			found = true
		}
	}
	if !found {
		t.Fatalf("/health does not advertise \"tuic-users\": %v", got.Capabilities)
	}
	if capTUICUsers != "tuic-users" {
		t.Fatalf("capability token const = %q", capTUICUsers)
	}
}
