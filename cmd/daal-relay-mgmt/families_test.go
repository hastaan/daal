package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// The config cloud-init bakes for a relay, by family set — what
// publisher/deploy/relayconf.SingBoxConfigForFamilies renders: vless-in
// iff vless-reality, hy2-in iff hysteria2, tuic-in iff tuic, and nothing
// for the families whose inbound is created on first use.
func bakedConfig(families ...string) string {
	var ins []string
	for _, f := range families {
		switch f {
		case famVLESSReality:
			ins = append(ins, `{"type":"vless","tag":"vless-in","listen":"0.0.0.0","listen_port":443,"users":[],
  "tls":{"enabled":true,"server_name":"sni.example.com","reality":{"enabled":true,"private_key":"00","short_id":[],
         "handshake":{"server":"sni.example.com","server_port":443}}}}`)
		case famHysteria2:
			ins = append(ins, `{"type":"hysteria2","tag":"hy2-in","listen":"0.0.0.0","listen_port":443,"users":[]}`)
		case famTUIC:
			ins = append(ins, `{"type":"tuic","tag":"tuic-in","listen":"0.0.0.0","listen_port":8443,"users":[]}`)
		}
	}
	return `{"log":{"level":"info"},"inbounds":[` + strings.Join(ins, ",") + `],"outbounds":[{"type":"direct"}]}`
}

// familyServer is a mgmt server on a box provisioned for `families`:
// the baked config, and /etc/daal/families naming the set (or no file
// when declared is false — a box built by an older cloud-init).
func familyServer(t *testing.T, declared bool, families ...string) (*server, ed25519.PrivateKey, string, *int) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config.json")
	if err := os.WriteFile(configPath, []byte(bakedConfig(families...)), 0o644); err != nil {
		t.Fatal(err)
	}
	srv := newServer(pub, configPath)
	srv.audience = testAudience
	srv.familiesPath = filepath.Join(tmp, "families")
	if declared {
		if err := os.WriteFile(srv.familiesPath, []byte(strings.Join(families, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	reloads := 0
	srv.singboxControl = func(action string) error {
		if action == "reload" {
			reloads++
		}
		return nil
	}
	srv.singboxCheck = func(string) error { return nil }
	srv.realityPubPath = filepath.Join(tmp, "reality.pub")
	srv.tlsCertPath = filepath.Join(tmp, "tls-cert.pem")
	srv.coverSNIPath = filepath.Join(tmp, "cover-sni")
	srv.now = func() time.Time { return time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC) }
	return srv, priv, configPath, &reloads
}

// inboundTags returns the sorted tags of every inbound in the config
// file — i.e. what sing-box would bind on its next start.
func inboundTags(t *testing.T, configPath string) []string {
	t.Helper()
	doc, err := loadSingboxDoc(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, raw := range asSlice(doc["inbounds"]) {
		in, _ := raw.(map[string]any)
		tag, _ := in["tag"].(string)
		out = append(out, tag)
	}
	sort.Strings(out)
	return out
}

func provisionOK(t *testing.T, ts *httptest.Server, priv ed25519.PrivateKey, name string) userCreds {
	t.Helper()
	resp := postJSON(t, ts.URL+"/users/provision", priv, "users-provision", provisionReq{Name: name})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := readAll(resp.Body)
		t.Fatalf("provision %s: %d %s", name, resp.StatusCode, body)
	}
	var c userCreds
	if err := json.NewDecoder(resp.Body).Decode(&c); err != nil {
		t.Fatal(err)
	}
	return c
}

// FAM-4, the reproduction: a relay provisioned with `--families
// shadowsocks,anytls`. The box must end up with ss-in and anytls-in and
// NOTHING else — it used to create naive-in and ws-in as well (and
// vless-in/hy2-in were baked unconditionally), four listening,
// credentialled inbounds no pack of this relay mentions.
func TestProvision_NarrowRelayBindsOnlyItsFamilies(t *testing.T) {
	srv, priv, configPath, _ := familyServer(t, true, famShadowsocks, famAnyTLS)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	c := provisionOK(t, ts, priv, "r1")
	if got, want := strings.Join(inboundTags(t, configPath), ","), "anytls-in,ss-in"; got != want {
		t.Fatalf("inbounds after the first recipient = %s, want exactly %s", got, want)
	}
	if c.SSPassword == "" || c.SSMethod == "" || c.AnyTLSPassword == "" {
		t.Errorf("served families came back without credentials: ss=%q/%q anytls=%q", c.SSPassword, c.SSMethod, c.AnyTLSPassword)
	}
	// No credential for a family the box does not serve: the publisher
	// must never be handed a secret nothing on the box will check.
	for field, v := range map[string]string{
		"vless_uuid": c.VLESSUUID, "reality_short_id": c.RealityShortID, "hy2_password": c.Hy2Password,
		"naive_password": c.NaivePassword, "ws_path": c.WSPath, "tuic_uuid": c.TUICUUID, "tuic_password": c.TUICPassword,
	} {
		if v != "" {
			t.Errorf("%s = %q on a relay that serves neither that family nor its inbound", field, v)
		}
	}

	// The registry works without a vless-in to hang it on: the same name
	// again is a conflict, the list names the recipient, and the count
	// (the recipient cap) sees them.
	resp := postJSON(t, ts.URL+"/users/provision", priv, "users-provision", provisionReq{Name: "r1"})
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("second provision of r1 = %d, want 409: the duplicate check must not depend on vless-in existing", resp.StatusCode)
	}
	provisionOK(t, ts, priv, "r2")
	users, err := listUsers(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 || users[0].Name != "r1" || users[1].Name != "r2" {
		t.Errorf("listUsers = %+v, want r1 and r2", users)
	}
	if n, _ := countUsers(configPath); n != 2 {
		t.Errorf("countUsers = %d, want 2", n)
	}

	// Revoking both leaves a config with no inbound at all — never an
	// empty ss-in (an open relay) or an inbound of another family.
	for _, name := range []string{"r1", "r2"} {
		resp := postJSON(t, ts.URL+"/users/revoke", priv, "users-revoke", revokeReq{Name: name})
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("revoke %s = %d", name, resp.StatusCode)
		}
	}
	if tags := inboundTags(t, configPath); len(tags) != 0 {
		t.Errorf("inbounds after revoking everyone = %v, want none", tags)
	}
}

// O-3 / backlog W5-1: a DEFAULT relay must not bind ss-in and anytls-in.
// Both were created for every recipient on every relay; behind shut
// firewalls, but listening and holding credentials.
func TestProvision_DefaultRelayDoesNotCreateOptInInbounds(t *testing.T) {
	srv, priv, configPath, _ := familyServer(t, true, famVLESSReality, famHysteria2, famNaive, famWebSocketTLS)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	c := provisionOK(t, ts, priv, "r1")
	if got, want := strings.Join(inboundTags(t, configPath), ","), "hy2-in,naive-in,vless-in,ws-in"; got != want {
		t.Fatalf("inbounds = %s, want exactly %s", got, want)
	}
	if c.VLESSUUID == "" || c.RealityShortID == "" || c.Hy2Password == "" || c.NaivePassword == "" || c.WSPath == "" {
		t.Errorf("a served default family came back without its credential: %+v", c)
	}
	if c.SSPassword != "" || c.SSMethod != "" || c.AnyTLSPassword != "" || c.TUICUUID != "" {
		t.Errorf("credentials for families this relay does not serve: ss=%q anytls=%q tuic=%q", c.SSPassword, c.AnyTLSPassword, c.TUICUUID)
	}
}

// Each default family can be left out on its own, and each opt-in one
// added on its own: the box follows the declared set exactly.
func TestProvision_InboundsFollowTheDeclaredSet(t *testing.T) {
	inboundFor := map[string]string{
		famVLESSReality: "vless-in", famHysteria2: "hy2-in", famNaive: "naive-in", famWebSocketTLS: "ws-in",
		famTUIC: "tuic-in", famShadowsocks: "ss-in", famAnyTLS: "anytls-in",
	}
	all := []string{famVLESSReality, famHysteria2, famNaive, famWebSocketTLS, famTUIC, famShadowsocks, famAnyTLS}
	for _, off := range all {
		var fams, want []string
		for _, f := range all {
			if f != off {
				fams = append(fams, f)
				want = append(want, inboundFor[f])
			}
		}
		sort.Strings(want)
		srv, priv, configPath, _ := familyServer(t, true, fams...)
		ts := httptest.NewServer(srv.routes())
		provisionOK(t, ts, priv, "r1")
		ts.Close()
		if got := strings.Join(inboundTags(t, configPath), ","); got != strings.Join(want, ",") {
			t.Errorf("relay without %s: inbounds = %s, want %s", off, got, strings.Join(want, ","))
		}
	}
}

// A box built by a cloud-init that predates /etc/daal/families has
// nothing to obey and behaves as it always did: every on-first-use
// family is created. Narrowing it by guesswork would take tiers away
// from a relay whose packs already carry them.
func TestProvision_UndeclaredBoxBehavesAsBefore(t *testing.T) {
	srv, priv, configPath, _ := familyServer(t, false, famVLESSReality, famHysteria2)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()
	provisionOK(t, ts, priv, "r1")
	if got, want := strings.Join(inboundTags(t, configPath), ","), "anytls-in,hy2-in,naive-in,ss-in,vless-in,ws-in"; got != want {
		t.Errorf("undeclared box inbounds = %s, want %s", got, want)
	}
}

// A box that WAS told its family set and cannot read it must refuse,
// not fall back to "everything" — that is the over-exposure the file
// exists to prevent, reached through a truncated write.
func TestProvision_UnreadableFamilySetIsRefused(t *testing.T) {
	srv, priv, configPath, reloads := familyServer(t, true, famVLESSReality, famHysteria2)
	if err := os.WriteFile(srv.familiesPath, []byte("\n  \n# nothing\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(configPath)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()
	resp := postJSON(t, ts.URL+"/users/provision", priv, "users-provision", provisionReq{Name: "r1"})
	resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("provision with an empty family set = %d, want 500", resp.StatusCode)
	}
	after, _ := os.ReadFile(configPath)
	if string(before) != string(after) {
		t.Error("the config was rewritten although the family set could not be read")
	}
	if *reloads != 0 {
		t.Errorf("sing-box was reloaded %d time(s) for a refused provision", *reloads)
	}
}

// A declared set naming only families this binary cannot serve must not
// answer 200 with a recipient who has no row anywhere.
func TestProvision_NoServableFamilyIsAnError(t *testing.T) {
	srv, priv, _, _ := familyServer(t, true, "a-family-from-the-future")
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()
	resp := postJSON(t, ts.URL+"/users/provision", priv, "users-provision", provisionReq{Name: "r1"})
	resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("provision on a relay with no servable family = %d, want 500", resp.StatusCode)
	}
}

// A rotation on a narrow relay echoes credentials for the rows it
// rewrote and nothing else. The four older families were echoed
// unconditionally — a fresh hy2 password for a relay with no hy2-in.
func TestRotateCreds_NarrowRelayEchoesOnlyWhatItRotated(t *testing.T) {
	srv, priv, _, reloads := familyServer(t, true, famShadowsocks, famAnyTLS)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()
	old := provisionOK(t, ts, priv, "r1")
	*reloads = 0
	// The rotate helper signs its token at the rotate tests' fixed clock.
	srv.now = func() time.Time { return time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC) }

	resp := rotateCreds(t, ts, priv, `{"name":"r1"}`, 200)
	if *reloads != 1 {
		t.Errorf("rotation cost %d reloads, want 1", *reloads)
	}
	if resp.SSPassword == "" || resp.SSPassword == old.SSPassword || resp.AnyTLSPassword == "" || resp.AnyTLSPassword == old.AnyTLSPassword {
		t.Errorf("served credentials did not rotate: ss %q→%q anytls %q→%q", old.SSPassword, resp.SSPassword, old.AnyTLSPassword, resp.AnyTLSPassword)
	}
	for field, v := range map[string]string{
		"vless_uuid": resp.VLESSUUID, "reality_short_id": resp.RealityShortID, "hy2_password": resp.Hy2Password,
		"naive_password": resp.NaivePassword, "tuic_uuid": resp.TUICUUID,
	} {
		if v != "" {
			t.Errorf("rotation echoed %s = %q for a family with no row on this box", field, v)
		}
	}
}

func TestReadFamilySet(t *testing.T) {
	dir := t.TempDir()
	if fs, err := readFamilySet(filepath.Join(dir, "absent")); err != nil || fs != nil {
		t.Errorf("absent file = (%v, %v), want the nil (undeclared) set and no error", fs, err)
	}
	if fs, err := readFamilySet(""); err != nil || fs != nil {
		t.Errorf("empty path = (%v, %v), want undeclared", fs, err)
	}
	var undeclared familySet
	for _, f := range []string{famVLESSReality, famShadowsocks, "anything"} {
		if !undeclared.serves(f) {
			t.Errorf("the undeclared set must serve %q (pre-file behaviour)", f)
		}
	}
	p := filepath.Join(dir, "families")
	if err := os.WriteFile(p, []byte("shadowsocks\n\n  anytls  \n# comment\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fs, err := readFamilySet(p)
	if err != nil {
		t.Fatal(err)
	}
	if !fs.serves(famShadowsocks) || !fs.serves(famAnyTLS) || fs.serves(famVLESSReality) || fs.serves(famNaive) || len(fs) != 2 {
		t.Errorf("parsed set = %v, want exactly shadowsocks and anytls", fs)
	}
	if err := os.WriteFile(p, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readFamilySet(p); err == nil {
		t.Error("an empty family file was accepted; it must not mean \"serve everything\"")
	}
	if _, err := readFamilySet(dir); err == nil {
		t.Error("an unreadable family file (a directory) was accepted")
	}
}

// The family names in /etc/daal/families are written by the publisher
// (relayconf.ServedFamilies) and matched here against local constants,
// across a module boundary nothing imports over. A constant that drifted
// from the publisher's spelling would never match, and a served family
// would silently get no inbound. The publisher's family matrix is the
// one file both halves share (see box_client_agreement_test.go).
func TestFamilyNamesMatchThePublishers(t *testing.T) {
	matrix := loadFamilyMatrix(t)
	mine := []string{famVLESSReality, famHysteria2, famNaive, famWebSocketTLS, famTUIC, famShadowsocks, famAnyTLS}
	have := map[string]bool{}
	for _, f := range mine {
		have[f] = true
		if _, ok := matrix.Families[f]; !ok {
			t.Errorf("this binary calls a family %q; the publisher's matrix has no such family, so /etc/daal/families will never name it", f)
		}
	}
	for f := range matrix.Families {
		if !have[f] {
			t.Errorf("the publisher serves %q and this binary has no name for it: listing it in /etc/daal/families would create nothing", f)
		}
	}
	// Every managed inbound belongs to exactly one family and is in the
	// registry walk, or its users would be invisible to /users/list.
	if len(recipientInbounds) != len(mine) {
		t.Errorf("recipientInbounds has %d entries for %d families", len(recipientInbounds), len(mine))
	}
}
