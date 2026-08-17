package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestEnsureMultiplexInbounds_OnlyVlessFamily is the load-bearing guard
// for the mux change. sing-box 1.13's parser is strict and `multiplex`
// is defined ONLY on the protocols whose options embed
// InboundMultiplexOptions — vless among them, hysteria2 and naive not.
// Stamping the block onto hy2-in or naive-in produces
// `json: unknown field "multiplex"`, which is a boot-time FATAL on a
// relay nobody can SSH into.
func TestEnsureMultiplexInbounds_OnlyVlessFamily(t *testing.T) {
	doc := map[string]any{"inbounds": []any{
		map[string]any{"type": "vless", "tag": tagVLESS},
		map[string]any{"type": "hysteria2", "tag": tagHy2},
		map[string]any{"type": "vless", "tag": tagWS},
		map[string]any{"type": "naive", "tag": tagNaive},
	}}
	ensureMultiplexInbounds(doc)
	for _, tag := range []string{tagVLESS, tagWS} {
		in := findInboundByTag(doc, tag)
		mux, _ := in["multiplex"].(map[string]any)
		if mux == nil {
			t.Fatalf("inbound %q has no multiplex block", tag)
		}
		if mux["enabled"] != true {
			t.Errorf("inbound %q multiplex.enabled = %v", tag, mux["enabled"])
		}
		// Padding is an ENFORCEMENT flag on the inbound: with it set the
		// box rejects a mux client that did not pad ("non-padded
		// connection rejected"). It must stay in lockstep with the client
		// outbound renderer's "padding": true.
		if mux["padding"] != true {
			t.Errorf("inbound %q multiplex.padding = %v", tag, mux["padding"])
		}
	}
	for _, tag := range []string{tagHy2, tagNaive} {
		if in := findInboundByTag(doc, tag); in["multiplex"] != nil {
			t.Errorf("inbound %q must NOT carry multiplex (unknown field → FATAL at boot)", tag)
		}
	}
}

// TestEnsureMultiplexInbounds_Idempotent: it runs on every provision so
// that relays built before multiplex existed pick it up, which means it
// runs many times over a box's life.
func TestEnsureMultiplexInbounds_Idempotent(t *testing.T) {
	doc := map[string]any{"inbounds": []any{
		map[string]any{"type": "vless", "tag": tagVLESS,
			"multiplex": map[string]any{"enabled": true, "padding": true}},
	}}
	before, _ := json.Marshal(doc)
	ensureMultiplexInbounds(doc)
	after, _ := json.Marshal(doc)
	if string(before) != string(after) {
		t.Errorf("second pass mutated the config:\n%s\n%s", before, after)
	}
}

// TestAddUserToSingbox_StampsMuxOnExistingRelay covers the upgrade path:
// a relay provisioned before this change has no multiplex block, and
// /users/provision is the only routine write path to its config.
func TestAddUserToSingbox_StampsMuxOnExistingRelay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	legacy := `{"inbounds":[
      {"type":"vless","tag":"vless-in","listen_port":443,"users":[],
       "tls":{"enabled":true,"server_name":"news.example.org",
              "reality":{"enabled":true,"private_key":"k","short_id":[],
                         "handshake":{"server":"news.example.org","server_port":443}}}},
      {"type":"hysteria2","tag":"hy2-in","listen_port":443,"users":[],"tls":{"enabled":true}}]}`
	if err := os.WriteFile(path, []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := addUserToSingbox(path, userCreds{
		Name: "r1", VLESSUUID: "u1", RealityShortID: "aabbccdd", WSPath: "/r1/deadbeef",
	}, nil); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(path)
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	for _, tag := range []string{tagVLESS, tagWS} {
		in := findInboundByTag(doc, tag)
		if in == nil {
			t.Fatalf("inbound %q missing", tag)
		}
		if in["multiplex"] == nil {
			t.Errorf("inbound %q did not acquire multiplex on provision", tag)
		}
	}
	if findInboundByTag(doc, tagHy2)["multiplex"] != nil {
		t.Error("hy2-in acquired multiplex")
	}
	if findInboundByTag(doc, tagNaive)["multiplex"] != nil {
		t.Error("naive-in acquired multiplex")
	}
	// The cover host is the box's to report; the publisher must take it
	// from here rather than from a compile-time constant.
	if got := readCoverSNI(path); got != "news.example.org" {
		t.Errorf("readCoverSNI = %q, want news.example.org", got)
	}
	// ws-in mirrors it at creation time.
	wsTLS, _ := findInboundByTag(doc, tagWS)["tls"].(map[string]any)
	if sni, _ := wsTLS["server_name"].(string); sni != "news.example.org" {
		t.Errorf("ws-in server_name = %q, want the mirrored cover host", sni)
	}
}

// singboxBinaryForTest returns the checked-in relay artifact, or "" when
// it is not present (a clean checkout without dist-release, CI).
func singboxBinaryForTest(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "dist-release", "relay-v1.5.0", "sing-box-1.13.12-linux-amd64"))
	if err != nil {
		return ""
	}
	if _, err := os.Stat(p); err != nil {
		return ""
	}
	return p
}

// TestGeneratedConfigLoadsInRealSingBox runs the shipped 1.13.12 binary
// over a config this service actually produces — provision two
// recipients, then rotate the cover identity — and asserts it loads.
//
// A unit test cannot catch what breaks these boxes. Every failure in
// this file's history was a config that Go was perfectly happy to
// marshal and that sing-box then refused at startup: an unknown field,
// a key in the wrong encoding, a block on an inbound that does not
// define it. `check` is the only oracle for that, so it is worth the
// dependency; the test skips when the artifact is not in the tree.
func TestGeneratedConfigLoadsInRealSingBox(t *testing.T) {
	bin := singboxBinaryForTest(t)
	if bin == "" {
		t.Skip("dist-release sing-box artifact not present; skipping real-parser check")
	}
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.json")
	certPath := filepath.Join(tmp, "tls-cert.pem")
	keyPath := filepath.Join(tmp, "tls-key.pem")
	if _, err := ensureSelfSignedCert(certPath, keyPath, filepath.Join(tmp, "fpr")); err != nil {
		t.Fatal(err)
	}

	// A real box's starting point: cloud-init's scaffold with a genuine
	// REALITY key (base64url, as `sing-box generate reality-keypair`
	// emits) and the box's data-plane leaf.
	scaffold := `{
  "log": {"level":"info"},
  "inbounds": [
    {"type":"vless","tag":"vless-in","listen":"0.0.0.0","listen_port":443,"users":[],
     "tls":{"enabled":true,"server_name":"news.example.org",
            "reality":{"enabled":true,"private_key":"YAoRLRs2r1PUyGZmSMOoGuFo9UbnrxWiCPMEjZoQdmc",
                       "short_id":[],"handshake":{"server":"news.example.org","server_port":443}}}},
    {"type":"hysteria2","tag":"hy2-in","listen":"0.0.0.0","listen_port":443,"users":[],
     "tls":{"enabled":true,"certificate_path":"` + certPath + `","key_path":"` + keyPath + `"}}
  ],
  "outbounds":[{"type":"direct"}]
}`
	if err := os.WriteFile(path, []byte(scaffold), 0o644); err != nil {
		t.Fatal(err)
	}
	// The data-plane cert paths are compile-time constants pointing at
	// /etc/daal; rewrite them to the temp leaf so the parser can load
	// them here.
	provision := func(name, uuid, shortID string) {
		t.Helper()
		if _, err := addUserToSingbox(path, userCreds{
			Name: name, VLESSUUID: uuid, RealityShortID: shortID,
			Hy2Password: "p-" + name, NaivePassword: "n-" + name, WSPath: "/" + name + "/deadbeef",
		}, nil); err != nil {
			t.Fatal(err)
		}
		retargetCertPaths(t, path, certPath, keyPath)
	}
	provision("r1", "11111111-2222-3333-4444-555555555555", "aabbccdd")
	provision("r2", "66666666-7777-8888-9999-000000000000", "11223344")

	srv := newServer(nil, path)
	srv.singboxCheck = func(p string) error {
		out, err := exec.Command(bin, "check", "-c", p).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s", out)
		}
		return nil
	}
	if _, _, err := srv.rewriteSingboxTLS(path, rotateTLSReq{
		NewSNI: "cdn.example.net", NewDests: []string{"cdn.example.net:443"}, NewWSPath: "/r1/cafef00d",
	}); err != nil {
		t.Fatalf("rotate-tls produced a config sing-box rejects: %v", err)
	}
	if out, err := exec.Command(bin, "check", "-c", path).CombinedOutput(); err != nil {
		t.Fatalf("final config rejected by sing-box: %s", out)
	}

	// And a per-recipient credential rotation on top of it — the config the
	// box actually ends up serving after both Step-7 operations have run.
	// This is the only oracle that catches the failures this file's history
	// is made of: a document Go marshals happily that the strict 1.13 parser
	// then FATALs on, on a box with no SSH path back in.
	doc, err := loadSingboxDoc(path)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := mintCreds("r2", 0)
	if err != nil {
		t.Fatal(err)
	}
	res, err := rotateRecipientCreds(doc, "r2", fresh)
	if err != nil {
		t.Fatalf("rotate-credentials: %v", err)
	}
	if err := assertRetiredAbsent(doc, res.retired); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.commitSingboxDoc(path, doc); err != nil {
		t.Fatalf("rotate-credentials produced a config sing-box rejects: %v", err)
	}
	if out, err := exec.Command(bin, "check", "-c", path).CombinedOutput(); err != nil {
		t.Fatalf("post-credential-rotation config rejected by sing-box: %s", out)
	}
	// A rotation must leave the multiplex block where it found it: it is the
	// mitigation the nested-TLS detection work measures as effective, and a
	// silent drop makes the relay fingerprintable again.
	rotated, err := loadSingboxDoc(path)
	if err != nil {
		t.Fatal(err)
	}
	if !muxInboundEnabled(rotated) {
		t.Error("multiplex lost across the rotation pair")
	}
}

// retargetCertPaths rewrites the hardcoded /etc/daal data-plane cert
// paths to the test's temp leaf, so the real parser can load them.
func retargetCertPaths(t *testing.T, path, certPath, keyPath string) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	inbounds, _ := doc["inbounds"].([]any)
	for _, raw := range inbounds {
		in, _ := raw.(map[string]any)
		tb, _ := in["tls"].(map[string]any)
		if tb == nil {
			continue
		}
		if _, ok := tb["certificate_path"]; ok {
			tb["certificate_path"] = certPath
			tb["key_path"] = keyPath
		}
	}
	if err := writeSingboxDoc(path, doc, nil); err != nil {
		t.Fatal(err)
	}
}

// The capability signal the publisher gates pack emission on. It is
// deliberately an AND across the vless-family inbounds: the publisher
// gets one boolean and mints one pack covering both the vless-reality
// and websocket-tls routes, so "one of the two has mux" must read as
// false — a true there would put a mux outbound on a route the box
// cannot serve, and that route fails hard rather than degrading.
func TestMuxInboundEnabled_AllOrNothing(t *testing.T) {
	mux := func() map[string]any { return map[string]any{"enabled": true, "padding": true} }
	cases := []struct {
		name string
		doc  map[string]any
		want bool
	}{
		{"both vless inbounds have it", map[string]any{"inbounds": []any{
			map[string]any{"type": "vless", "tag": "vless-in", "multiplex": mux()},
			map[string]any{"type": "vless", "tag": "ws-in", "multiplex": mux()},
			map[string]any{"type": "hysteria2", "tag": "hy2-in"},
		}}, true},
		{"ws-in missing it", map[string]any{"inbounds": []any{
			map[string]any{"type": "vless", "tag": "vless-in", "multiplex": mux()},
			map[string]any{"type": "vless", "tag": "ws-in"},
		}}, false},
		{"present but disabled", map[string]any{"inbounds": []any{
			map[string]any{"type": "vless", "tag": "vless-in",
				"multiplex": map[string]any{"enabled": false}},
		}}, false},
		{"pre-Wave-2 box", map[string]any{"inbounds": []any{
			map[string]any{"type": "vless", "tag": "vless-in"},
		}}, false},
		{"no vless inbounds at all", map[string]any{"inbounds": []any{
			map[string]any{"type": "hysteria2", "tag": "hy2-in"},
		}}, false},
	}
	for _, tc := range cases {
		if got := muxInboundEnabled(tc.doc); got != tc.want {
			t.Errorf("%s: muxInboundEnabled = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// After a provision the box must report the capability it just wrote:
// ensureMultiplexInbounds runs on every /users/provision, so a relay
// built before multiplex existed acquires it on the next recipient and
// starts advertising it in the same response.
func TestAddUserToSingbox_ReportsMuxCapability(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/config.json"
	if err := os.WriteFile(path, []byte(`{
  "inbounds": [
    {"type":"vless","tag":"vless-in","listen_port":443,"users":[],
     "tls":{"enabled":true,"server_name":"news.example.org",
            "reality":{"enabled":true,"private_key":"","short_id":[],
                       "handshake":{"server":"news.example.org","server_port":443}}}}
  ]
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if readMuxInbound(path) {
		t.Fatal("a pre-Wave-2 config must not claim mux capability")
	}
	if _, err := addUserToSingbox(path, userCreds{
		Name: "r1", VLESSUUID: "u1", RealityShortID: "aabbccdd",
		Hy2Password: "h", NaivePassword: "n", WSPath: "/r1/deadbeef",
	}, nil); err != nil {
		t.Fatal(err)
	}
	if !readMuxInbound(path) {
		t.Error("after a provision the box must report the mux block it just wrote")
	}
}
