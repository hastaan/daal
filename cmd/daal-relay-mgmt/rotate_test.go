// Step 7 tests — THREE recipients, on purpose.
//
// A two-recipient fixture cannot tell "rotated the one I named" apart from
// "rotated everyone": with two rows, rotating both and rotating the named one
// look identical from the named row's point of view, and the surviving row is
// at an edge of the list. Three rows put the target in the MIDDLE, so an
// off-by-one, a truncation, or a fan-out all show up as a byte-level change
// to a neighbour that must not have moved.
//
// That is not a hypothetical shape of bug in this file. removeVLESSUser once
// truncated reality.short_id[] and thereby revoked the wrong recipient, and
// surgicalSetUUID once rewrote inbounds[0].users[0] and thereby revoked
// nobody. Both survived their single-recipient tests.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// threeRecipientServer builds the real four-inbound shape a provisioned box
// has, with r1/r2/r3 present in every one of them and multiplex stamped on
// the vless family (Wave 2). Distinct, realistic credential values so a
// leak of any one of them is unambiguous when it shows up somewhere it
// should not.
func threeRecipientServer(t *testing.T) (*server, ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config.json")
	if err := os.WriteFile(configPath, []byte(`{
  "log": {"level":"info"},
  "inbounds": [
    {"type":"vless","tag":"vless-in","listen":"0.0.0.0","listen_port":443,
     "users":[{"uuid":"11111111-1111-4111-8111-111111111111","name":"r1","flow":"xtls-rprx-vision"},
              {"uuid":"22222222-2222-4222-8222-222222222222","name":"r2","flow":"xtls-rprx-vision"},
              {"uuid":"33333333-3333-4333-8333-333333333333","name":"r3","flow":"xtls-rprx-vision"}],
     "multiplex":{"enabled":true,"padding":true},
     "tls":{"enabled":true,"server_name":"mirror.init7.net",
            "reality":{"enabled":true,"private_key":"YAoRLRs2r1PUyGZmSMOoGuFo9UbnrxWiCPMEjZoQdmc",
                       "short_id":["a1a1a1a1","b2b2b2b2","c3c3c3c3"],
                       "handshake":{"server":"mirror.init7.net","server_port":443}}}},
    {"type":"hysteria2","tag":"hy2-in","listen":"0.0.0.0","listen_port":443,
     "users":[{"name":"r1","password":"hy2-pw-one"},
              {"name":"r2","password":"hy2-pw-two"},
              {"name":"r3","password":"hy2-pw-three"}],
     "tls":{"enabled":true,"certificate_path":"/etc/daal/tls-cert.pem","key_path":"/etc/daal/tls-key.pem"}},
    {"type":"vless","tag":"ws-in","listen":"0.0.0.0","listen_port":8445,
     "users":[{"uuid":"11111111-1111-4111-8111-111111111111","name":"r1"},
              {"uuid":"22222222-2222-4222-8222-222222222222","name":"r2"},
              {"uuid":"33333333-3333-4333-8333-333333333333","name":"r3"}],
     "multiplex":{"enabled":true,"padding":true},
     "transport":{"type":"ws","path":"/r1/0badcafe"},
     "tls":{"enabled":true,"server_name":"mirror.init7.net",
            "certificate_path":"/etc/daal/tls-cert.pem","key_path":"/etc/daal/tls-key.pem"}},
    {"type":"naive","tag":"naive-in","listen":"0.0.0.0","listen_port":8444,
     "users":[{"username":"r1","password":"naive-pw-one"},
              {"username":"r2","password":"naive-pw-two"},
              {"username":"r3","password":"naive-pw-three"}],
     "tls":{"enabled":true,"certificate_path":"/etc/daal/tls-cert.pem","key_path":"/etc/daal/tls-key.pem"}}
  ],
  "outbounds":[{"type":"direct"}]
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	srv := newServer(pub, configPath)
	srv.singboxControl = func(string) error { return nil }
	srv.singboxKick = func() error { return nil }
	srv.singboxCheck = func(string) error { return nil }
	srv.realityPubPath = filepath.Join(tmp, "reality.pub")
	srv.tlsCertPath = filepath.Join(tmp, "tls-cert.pem")
	srv.coverSNIPath = filepath.Join(tmp, "cover-sni")
	srv.now = func() time.Time { return time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC) }
	return srv, priv, configPath
}

// userRows returns every user row for `name`, keyed by inbound tag, as
// canonical JSON. Comparing these before and after is the byte-level
// "this recipient did not move" assertion.
func userRows(t *testing.T, doc map[string]any, name string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, raw := range asSlice(doc["inbounds"]) {
		in, _ := raw.(map[string]any)
		tag, _ := in["tag"].(string)
		for _, ur := range asSlice(in["users"]) {
			u, _ := ur.(map[string]any)
			n, _ := u["name"].(string)
			if n == "" {
				n, _ = u["username"].(string)
			}
			if n != name {
				continue
			}
			b, err := json.Marshal(u)
			if err != nil {
				t.Fatal(err)
			}
			out[tag] = string(b)
		}
	}
	return out
}

// shortIDs returns the vless-in REALITY short_id list.
func shortIDs(doc map[string]any) []string {
	in := findInboundByTag(doc, tagVLESS)
	tb, _ := in["tls"].(map[string]any)
	r, _ := tb["reality"].(map[string]any)
	out := []string{}
	for _, raw := range asSlice(r["short_id"]) {
		s, _ := raw.(string)
		out = append(out, s)
	}
	return out
}

// TestRotateCreds_TargetsExactlyOneRecipient is the heart of Step 7.
//
// Rotate the MIDDLE recipient of three and assert, in this order of
// importance:
//
//  1. the neighbours are byte-unchanged in every inbound — a rotation whose
//     blast radius exceeds the recipient it names is a targeted revocation
//     that severs the family;
//  2. every one of r2's retired secrets is gone from the whole config — a
//     rotation that misses one inbound leaves the leaked credential live on
//     that tier, and "half revoked" reads as success to the operator;
//  3. r2 was updated in ALL FOUR inbounds, with one consistent UUID across
//     the vless family (the client dials vless-in and ws-in with the same
//     UUID) and the response reporting exactly that.
func TestRotateCreds_TargetsExactlyOneRecipient(t *testing.T) {
	srv, priv, configPath := threeRecipientServer(t)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	before := readDoc(t, configPath)
	r1Before, r3Before := userRows(t, before, "r1"), userRows(t, before, "r3")
	sidsBefore := shortIDs(before)

	got := rotateCreds(t, ts, priv, `{"name":"r2"}`, 200)
	after := readDoc(t, configPath)

	// 1. The bystanders.
	if r1After := userRows(t, after, "r1"); !reflect.DeepEqual(r1Before, r1After) {
		t.Errorf("r1 changed during r2's rotation:\n before %v\n after  %v", r1Before, r1After)
	}
	if r3After := userRows(t, after, "r3"); !reflect.DeepEqual(r3Before, r3After) {
		t.Errorf("r3 changed during r2's rotation:\n before %v\n after  %v", r3Before, r3After)
	}
	sidsAfter := shortIDs(after)
	if len(sidsAfter) != len(sidsBefore) {
		t.Fatalf("short_id list length changed %d → %d; users[i] owns short_id[i] and that pairing is the whole mechanism", len(sidsBefore), len(sidsAfter))
	}
	if sidsAfter[0] != sidsBefore[0] || sidsAfter[2] != sidsBefore[2] {
		t.Errorf("short_id neighbours moved: %v → %v (this is exactly how removeVLESSUser once revoked the wrong recipient)", sidsBefore, sidsAfter)
	}
	if sidsAfter[1] == sidsBefore[1] {
		t.Errorf("r2's short_id was not rotated: %v", sidsAfter)
	}
	if sidsAfter[1] != got.RealityShortID {
		t.Errorf("reported reality_short_id %q != the value the box now accepts %q", got.RealityShortID, sidsAfter[1])
	}

	// 2. Nothing retired survives, anywhere in the document.
	for _, retired := range []string{
		"22222222-2222-4222-8222-222222222222", // vless-in AND ws-in
		"hy2-pw-two",
		"naive-pw-two",
		"b2b2b2b2",
	} {
		if docContainsString(after, retired) {
			t.Errorf("retired credential %q still present in the config — the leak is not closed", retired)
		}
	}

	// 3. Every tier updated, consistently.
	sort.Strings(got.UpdatedInbounds)
	if want := []string{"hy2-in", "naive-in", "vless-in", "ws-in"}; !reflect.DeepEqual(got.UpdatedInbounds, want) {
		t.Errorf("updated_inbounds = %v, want %v", got.UpdatedInbounds, want)
	}
	if len(got.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", got.Warnings)
	}
	for _, tag := range []string{tagVLESS, tagWS} {
		in := findInboundByTag(after, tag)
		u := findUserRow(in, "name", "r2")
		if u == nil {
			t.Fatalf("inbound %q lost r2", tag)
		}
		if uuid, _ := u["uuid"].(string); uuid != got.VLESSUUID {
			t.Errorf("%s r2 uuid = %q, want the rotated %q — the client dials both with one UUID", tag, uuid, got.VLESSUUID)
		}
	}
	if u := findUserRow(findInboundByTag(after, tagHy2), "name", "r2"); u == nil {
		t.Fatal("hy2-in lost r2")
	} else if pw, _ := u["password"].(string); pw != got.Hy2Password {
		t.Errorf("hy2-in r2 password = %q, want the rotated one", pw)
	}
	if u := findUserRow(findInboundByTag(after, tagNaive), "username", "r2"); u == nil {
		t.Fatal("naive-in lost r2")
	} else if pw, _ := u["password"].(string); pw != got.NaivePassword {
		t.Errorf("naive-in r2 password = %q, want the rotated one", pw)
	}

	// Wave 2 must not regress: mux where it was, and the two REALITY names
	// still agreeing.
	assertWave2Invariants(t, after)
}

// TestRotateCreds_DoesNotTouchBoxWideMaterial pins the split itself. The
// operation with the one-recipient blast radius must leave everything with a
// fleet-wide blast radius exactly where it found it.
func TestRotateCreds_DoesNotTouchBoxWideMaterial(t *testing.T) {
	srv, priv, configPath := threeRecipientServer(t)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	before := readDoc(t, configPath)
	rotateCreds(t, ts, priv, `{"name":"r2"}`, 200)
	after := readDoc(t, configPath)

	beforeTLS, _ := findInboundByTag(before, tagVLESS)["tls"].(map[string]any)
	afterTLS, _ := findInboundByTag(after, tagVLESS)["tls"].(map[string]any)
	beforeReality, _ := beforeTLS["reality"].(map[string]any)
	afterReality, _ := afterTLS["reality"].(map[string]any)

	// The REALITY private key is the pinned public key in every pack this box
	// ever emitted. Rotating it as a side effect of a per-recipient
	// revocation would disconnect every recipient, permanently, until each
	// one is hand-delivered a new file.
	if beforeReality["private_key"] != afterReality["private_key"] {
		t.Error("/rotate-credentials rotated the box REALITY private key — that is a third operation with a fleet-wide blast radius")
	}
	if beforeTLS["server_name"] != afterTLS["server_name"] {
		t.Error("/rotate-credentials moved the cover SNI — that is /rotate-tls")
	}
	if wsInboundPath(before) != wsInboundPath(after) {
		t.Error("/rotate-credentials moved the SHARED ws path — every other recipient's ws tier just died")
	}
	// And the on-disk advertised public key must not have been rewritten,
	// because the key it describes did not change.
	if _, err := os.Stat(srv.realityPubPath); err == nil {
		t.Error("reality.pub rewritten by a per-recipient rotation")
	}
}

// TestRotateTLS_LeavesEveryCredentialAlone is the mirror assertion: the
// box-wide operation must not revoke anybody. Recipients keep their
// identities and need only new connection parameters — which is what makes a
// TLS rotation recoverable at all.
func TestRotateTLS_LeavesEveryCredentialAlone(t *testing.T) {
	srv, priv, configPath := threeRecipientServer(t)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	before := readDoc(t, configPath)
	rowsBefore := map[string]map[string]string{}
	for _, n := range []string{"r1", "r2", "r3"} {
		rowsBefore[n] = userRows(t, before, n)
	}
	sidsBefore := shortIDs(before)
	beforeReality, _ := findInboundByTag(before, tagVLESS)["tls"].(map[string]any)["reality"].(map[string]any)

	got := rotateTLS(t, ts, priv, `{"new_sni":"ftp.plusline.net","new_dests":["ftp.plusline.net:443"]}`, 200)
	after := readDoc(t, configPath)

	for _, n := range []string{"r1", "r2", "r3"} {
		if rowsAfter := userRows(t, after, n); !reflect.DeepEqual(rowsBefore[n], rowsAfter) {
			t.Errorf("%s's credentials changed during a TLS rotation:\n before %v\n after  %v", n, rowsBefore[n], rowsAfter)
		}
	}
	if !reflect.DeepEqual(sidsBefore, shortIDs(after)) {
		t.Errorf("short_id list changed during a TLS rotation: %v → %v", sidsBefore, shortIDs(after))
	}
	afterReality, _ := findInboundByTag(after, tagVLESS)["tls"].(map[string]any)["reality"].(map[string]any)
	if beforeReality["private_key"] != afterReality["private_key"] {
		t.Error("/rotate-tls rotated the REALITY keypair — it must move the cover identity and nothing else")
	}
	if !reflect.DeepEqual(got.Changed, []string{"cover_sni", "reality_handshake"}) {
		t.Errorf("changed = %v, want the cover host and its handshake dest, together", got.Changed)
	}
	if got.AppliedSNI != "ftp.plusline.net" || got.AppliedHandshake != "ftp.plusline.net:443" {
		t.Errorf("applied = %q / %q, want both on ftp.plusline.net", got.AppliedSNI, got.AppliedHandshake)
	}
	assertWave2Invariants(t, after)
}

// TestRotateShortIDs_MisalignedListIsNotGuessedAt covers the config shape
// where users[] and short_id[] have drifted out of correspondence (a
// hand-edited config, or a box predating the paired append).
//
// Two things must hold at once, and they pull in opposite directions. No
// EXISTING entry may be touched or handed out: overwriting one revokes a
// bystander, and returning one (this used to return sids[0]) couples the
// rotated recipient's lifetime to somebody else's revocation — their tier
// dies later, with nothing linking the two events. But the recipient still
// has to be given a short_id that works, or their rebuilt pack cannot use
// the vless-reality tier at all. Appending satisfies both: short_id is a set
// on the wire, so an added entry works for its owner and takes nothing from
// anyone.
func TestRotateShortIDs_MisalignedListIsNotGuessedAt(t *testing.T) {
	srv, priv, configPath := threeRecipientServer(t)
	doc := readDoc(t, configPath)
	tb, _ := findInboundByTag(doc, tagVLESS)["tls"].(map[string]any)
	r, _ := tb["reality"].(map[string]any)
	r["short_id"] = []any{"a1a1a1a1", "b2b2b2b2"} // 2 entries, 3 users
	if err := writeSingboxDoc(configPath, doc, nil); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	got := rotateCreds(t, ts, priv, `{"name":"r2"}`, 200)
	after := readDoc(t, configPath)

	sids := shortIDs(after)
	if want := []string{"a1a1a1a1", "b2b2b2b2"}; !reflect.DeepEqual(sids[:len(want)], want) {
		t.Errorf("short_id = %v; the pre-existing entries must survive untouched (%v)", sids, want)
	}
	if len(sids) != 3 {
		t.Fatalf("short_id = %v, want the recipient's own entry appended", sids)
	}
	if got.RealityShortID == "" {
		t.Error("reality_short_id is empty; the caller must be handed a short_id that works, or the rebuilt pack loses the vless-reality tier")
	}
	if got.RealityShortID != sids[2] {
		t.Errorf("reality_short_id = %q but the appended entry is %q; the value handed back must be the one that was added", got.RealityShortID, sids[2])
	}
	for _, old := range []string{"a1a1a1a1", "b2b2b2b2"} {
		if got.RealityShortID == old {
			t.Errorf("reality_short_id = %q — that entry may belong to another recipient, whose revocation would then silently take this one's REALITY tier away", old)
		}
	}
	if len(got.Warnings) != 1 {
		t.Errorf("warnings = %v, want one explaining why short_id was not rotated", got.Warnings)
	}
	u := findUserRow(findInboundByTag(after, tagVLESS), "name", "r2")
	if uuid, _ := u["uuid"].(string); uuid == "22222222-2222-4222-8222-222222222222" {
		t.Error("r2's UUID was not rotated; the short_id complication must not block the credential that authenticates")
	}
}

// assertWave2Invariants pins what a rotation must never regress: the strict
// parser accepts the document, multiplex survives on the vless family (it is
// the mitigation the nested-TLS detection literature measures as effective,
// and a rotation that silently drops it makes the fleet fingerprintable
// again), and the two REALITY names still agree.
func assertWave2Invariants(t *testing.T, doc map[string]any) {
	t.Helper()
	if !muxInboundEnabled(doc) {
		t.Error("multiplex lost from a vless-family inbound by a rotation")
	}
	for _, in := range vlessFamilyInbounds(doc) {
		tb, _ := in["tls"].(map[string]any)
		if tb == nil {
			continue
		}
		reality, _ := tb["reality"].(map[string]any)
		if reality == nil {
			continue
		}
		if _, present := reality["server_names"]; present {
			t.Error("reality.server_names present: not a field in sing-box 1.13; the box will not boot")
		}
		hs, _ := reality["handshake"].(map[string]any)
		sni, _ := tb["server_name"].(string)
		if host, _ := hs["server"].(string); host != sni {
			t.Errorf("reality.handshake.server = %q but tls.server_name = %q — the IP-to-SNI mismatch REALITY exists to prevent", host, sni)
		}
	}
}

// findUserRow returns the first user row in `in` whose `key` equals name.
func findUserRow(in map[string]any, key, name string) map[string]any {
	if in == nil {
		return nil
	}
	for _, raw := range asSlice(in["users"]) {
		u, _ := raw.(map[string]any)
		if u == nil {
			continue
		}
		if n, _ := u[key].(string); n == name {
			return u
		}
	}
	return nil
}

// TestRotationConfigsLoadInRealSingBox runs the shipped 1.13.12 binary over
// every config the Step-7 endpoints produce, on the three-recipient shape.
//
// A unit test cannot catch what actually breaks these boxes. Every failure in
// this service's history was a document Go marshalled happily and sing-box
// then refused at startup: an unknown field, a key in the wrong encoding, a
// block on an inbound that does not define it. `check` is the only oracle for
// that, and a rotation is precisely when a box has no second chance — the
// operator is already reaching for it because something went wrong, and there
// is no SSH path back in. Skips when the artifact is not in the tree.
func TestRotationConfigsLoadInRealSingBox(t *testing.T) {
	bin := singboxBinaryForTest(t)
	if bin == "" {
		t.Skip("dist-release sing-box artifact not present; skipping real-parser check")
	}
	srv, priv, configPath := threeRecipientServer(t)
	tmp := filepath.Dir(configPath)
	certPath := filepath.Join(tmp, "tls-cert.pem")
	keyPath := filepath.Join(tmp, "tls-key.pem")
	if _, err := ensureSelfSignedCert(certPath, keyPath, filepath.Join(tmp, "fpr")); err != nil {
		t.Fatal(err)
	}
	// The fixture's cert paths are the compile-time /etc/daal ones; point
	// them at the temp leaf so the real parser can load them here.
	retargetCertPaths(t, configPath, certPath, keyPath)
	// The real validator, in the position the handlers call it from: a
	// rejected candidate must never reach the live file.
	srv.singboxCheck = func(p string) error {
		out, err := exec.Command(bin, "check", "-c", p).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s", out)
		}
		return nil
	}
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	check := func(stage string) {
		t.Helper()
		out, err := exec.Command(bin, "check", "-c", configPath).CombinedOutput()
		t.Logf("%s check -c %s → %q (err=%v)", filepath.Base(bin), configPath, out, err)
		if err != nil {
			t.Fatalf("[%s] config rejected by sing-box 1.13.12: %s", stage, out)
		}
	}
	check("provisioned fixture")

	rotateCreds(t, ts, priv, `{"name":"r2"}`, 200)
	check("after per-recipient credential rotation")
	assertWave2Invariants(t, readDoc(t, configPath))

	rotateTLS(t, ts, priv, `{"new_sni":"ftp.plusline.net","new_dests":["ftp.plusline.net:443"]}`, 200)
	check("after cover-identity rotation")
	assertWave2Invariants(t, readDoc(t, configPath))

	rotateTLS(t, ts, priv, `{}`, 200)
	check("after empty-body (ws path) rotation")
	assertWave2Invariants(t, readDoc(t, configPath))

	// Rotating a second recipient after all of that must still land a
	// loadable config — the box's real lifetime is many rotations deep.
	rotateCreds(t, ts, priv, `{"name":"r3"}`, 200)
	check("after a second credential rotation")
	assertWave2Invariants(t, readDoc(t, configPath))
}

// TestAssertRetiredAbsent_NoSubstringFalsePositive pins the structural scan.
// A substring scan of the marshalled bytes would see "uuid-1" inside
// "uuid-12" and abort a correct rotation — a guard that fails closed on
// correct input is a guard that gets removed.
func TestAssertRetiredAbsent_NoSubstringFalsePositive(t *testing.T) {
	doc := map[string]any{"inbounds": []any{
		map[string]any{"users": []any{map[string]any{"uuid": "uuid-12"}}},
	}}
	if err := assertRetiredAbsent(doc, []string{"uuid-1"}); err != nil {
		t.Errorf("false positive on a substring: %v", err)
	}
	if err := assertRetiredAbsent(doc, []string{"uuid-12"}); err == nil {
		t.Error("a surviving retired credential must abort the rotation")
	}
}

// TestRotateCreds_ReloadFailureLeavesNothingBehind pins the commit/reload
// boundary, which is the one place a rotation can hurt the box hours after
// the operator was told it failed.
//
// commitSingboxDoc renames the new config over the live one and the reload
// happens after it, so between the two the box holds a config it is not
// running. Without a rollback a reload failure returns 500 with the rotation
// still on disk: the publisher records "nothing was applied" and keeps the
// old credentials, and then the next unrelated reload — most plausibly the
// operator adding a recipient — activates the orphaned rotation and cuts the
// recipient off with credentials that exist nowhere else, since this
// response is the only time they leave the box.
func TestRotateCreds_ReloadFailureLeavesNothingBehind(t *testing.T) {
	srv, priv, configPath := threeRecipientServer(t)
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	srv.singboxControl = func(action string) error {
		if action == "reload" {
			return fmt.Errorf("Job type reload is not applicable for unit sing-box.service")
		}
		return nil
	}
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	rotateCreds(t, ts, priv, `{"name":"r2"}`, 500)

	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("the rotation is still on disk after a failed reload; the box will activate it at the next unrelated reload, cutting off a recipient whose new credentials were never returned")
	}
	if _, err := os.Stat(configPath + ".rollback"); err == nil {
		t.Error("rollback temp file left behind")
	}
}

// TestRotateTLS_ReloadFailureLeavesNothingBehind is the same boundary on the
// heavier verb, where the consequence is relay-wide. runRotateTLS treats a
// nil response as "nothing was applied" and keeps the burned cover host in
// the record, so an orphaned config would put the box on a name no pack will
// ever carry — a delayed, unattributable outage of the primary tier.
func TestRotateTLS_ReloadFailureLeavesNothingBehind(t *testing.T) {
	srv, priv, configPath := threeRecipientServer(t)
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	srv.singboxControl = func(string) error { return fmt.Errorf("systemd said no") }
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	tok := mintToken(priv, "rotate-tls", srv.now().Unix())
	body, _ := json.Marshal(rotateTLSReq{NewSNI: "ftp.plusline.net", NewDests: []string{"ftp.plusline.net:443"}})
	req, _ := http.NewRequest("POST", ts.URL+"/rotate-tls", bytes.NewReader(body))
	req.Header.Set("Authorization", "Daal-Mgmt-Token "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 500 {
		t.Fatalf("rotate-tls with a failing reload = %d, want 500", resp.StatusCode)
	}
	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("the new cover identity survived a failed reload; the box would start advertising %q at the next reload while the publisher's record still says %q", coverSNI(readDoc(t, configPath)), "mirror.init7.net")
	}
	// The declared-cover-SNI file must not have moved either: it is written
	// only after a reload the box confirmed.
	if b, err := os.ReadFile(srv.coverSNIPath); err == nil && strings.Contains(string(b), "ftp.plusline.net") {
		t.Error("/etc/daal/cover-sni names a host the box never started serving")
	}
}

// TestMutatingEndpointsSerializeOnTheConfig is the read-modify-write race.
//
// All four mutating endpoints do load → mutate → rename over ONE file, and
// net/http gives each request its own goroutine. Unserialized, two calls
// both read the pre-call document and the second rename discards the first
// wholesale — and a discarded ROTATION is a revocation the publisher has
// already filed as complete, with the leaked credential still live in the
// file the box serves. Neither assertRetiredAbsent nor `sing-box check` can
// see it: both validate the in-memory candidate, not the file being
// replaced.
//
// Runs a rotation concurrently with provisions and revocations of other
// recipients, then asserts every operation that reported success is present
// in the final config.
func TestMutatingEndpointsSerializeOnTheConfig(t *testing.T) {
	srv, priv, configPath := threeRecipientServer(t)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	post := func(verb, path, body string) int {
		tok := mintToken(priv, verb, srv.now().Unix())
		req, _ := http.NewRequest("POST", ts.URL+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Daal-Mgmt-Token "+tok)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return 0
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}

	var wg sync.WaitGroup
	newNames := []string{"r10", "r11", "r12", "r13"}
	for _, n := range newNames {
		wg.Add(1)
		go func(n string) {
			defer wg.Done()
			if code := post("users-provision", "/users/provision", `{"name":"`+n+`"}`); code != 200 {
				t.Errorf("provision %s = %d", n, code)
			}
		}(n)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if code := post("rotate-credentials", "/rotate-credentials", `{"name":"r2"}`); code != 200 {
			t.Errorf("rotate-credentials r2 = %d", code)
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		if code := post("users-revoke", "/users/revoke", `{"name":"r3"}`); code != 200 {
			t.Errorf("revoke r3 = %d", code)
		}
	}()
	wg.Wait()

	after := readDoc(t, configPath)
	for _, n := range append([]string{"r1", "r2"}, newNames...) {
		if findUserRow(findInboundByTag(after, tagVLESS), "name", n) == nil {
			t.Errorf("%s is missing from vless-in: a concurrent write discarded an operation that reported success", n)
		}
	}
	if findUserRow(findInboundByTag(after, tagVLESS), "name", "r3") != nil {
		t.Error("r3's revocation was discarded by a concurrent write")
	}
	if docContainsString(after, "22222222-2222-4222-8222-222222222222") {
		t.Error("r2's retired UUID is still live: the rotation was discarded by a concurrent write, but the publisher has already recorded it as a completed revocation")
	}
}
