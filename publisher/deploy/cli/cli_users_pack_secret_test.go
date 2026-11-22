package cli

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"

	"daal/bundle-go/bundle"
	"daal/bundle-go/envelope"
)

// The update secret reaches a file through the creds JSON only, lands in
// the per-recipient half (sealed to the person in a .sbpx), is never
// printed, and a person's secret is refused for the Everyone file.
func TestUsersPack_UpdateSecretTravelsInTheCredsFileOnly(t *testing.T) {
	recPath, privPath, _, _ := mkBindFixture(t)
	body, _ := os.ReadFile(recPath)
	var rec map[string]any
	_ = json.Unmarshal(body, &rec)
	server, _ := rec["public_ip"].(string)

	dir := t.TempDir()
	sbp := filepath.Join(dir, "rp.sbp")
	var stdout, stderr bytes.Buffer
	if rc := Run([]string{"bind-and-sign", "--operator-record", recPath, "--priv-key", privPath,
		"--output", sbp, "--phase", testPhase}, &stdout, &stderr); rc != 0 {
		t.Fatalf("bind-and-sign rc=%d %s", rc, stderr.String())
	}

	people := bundle.DeriveUpdateSecret([]byte("root"), "rp-x", bundle.AudiencePeople)
	everyone := bundle.DeriveUpdateSecret([]byte("root"), "rp-x", bundle.AudienceEveryone)
	creds := func(secret [32]byte, audience string) string {
		c := map[string]any{
			"name": "r1", "vless_uuid": "11111111-2222-3333-4444-555555555555", "reality_short_id": "deadbeef",
			"hy2_password": "hy2secretpassword22ch", "reality_public_key": fixtureRealityPub,
			"tls_cert_sha256": fixtureTLSPin, "cover_sni": rec["cover_sni"],
		}
		if audience != "" {
			c["update_secret"] = base64.StdEncoding.EncodeToString(secret[:])
			c["update_audience"] = audience
		}
		b, _ := json.Marshal(c)
		p := filepath.Join(t.TempDir(), "creds.json")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	run := func(args ...string) (int, string, string) {
		var o, e bytes.Buffer
		rc := Run(args, &o, &e)
		return rc, o.String(), e.String()
	}
	b64 := func(s [32]byte) string { return base64.StdEncoding.EncodeToString(s[:]) }

	// A person's file.
	var xpriv [32]byte
	_, _ = rand.Read(xpriv[:])
	xpub, _ := curve25519.X25519(xpriv[:], curve25519.Basepoint)
	sbpx := filepath.Join(dir, "p.sbpx")
	rc, out, errs := run("users-pack-sbpx", "--in", sbp, "--recipient-pub-hex", hex.EncodeToString(xpub),
		"--out", sbpx, "--creds-file", creds(people, bundle.AudiencePeople), "--server", server)
	if rc != 0 {
		t.Fatalf("users-pack-sbpx rc=%d %s", rc, errs)
	}
	if strings.Contains(out+errs, b64(people)) || !strings.Contains(out, `"update_secret":true`) {
		t.Fatalf("stdout/stderr: %s %s", out, errs)
	}
	sealed, _ := os.ReadFile(sbpx)
	if bytes.Contains(sealed, []byte(b64(people))) {
		t.Fatal("the secret is readable outside the envelope")
	}
	inner, err := envelope.Decrypt(sealed, xpriv)
	if err != nil {
		t.Fatal(err)
	}
	got, err := bundle.ReadUpdateSecret(inner)
	if err != nil || got.Audience != bundle.AudiencePeople || got.Secret != people {
		t.Fatalf("inner member: %v", err)
	}

	// The Everyone file: its own audience only.
	shared := filepath.Join(dir, "shared.sbp")
	if rc, _, errs := run("users-pack-sbp", "--in", sbp, "--out", shared,
		"--creds-file", creds(people, bundle.AudiencePeople), "--server", server); rc != 2 ||
		!strings.Contains(errs, "Everyone") || strings.Contains(errs, b64(people)) {
		t.Fatalf("a person's secret for the Everyone file: rc=%d %s", rc, errs)
	}
	if _, err := os.Stat(shared); err == nil {
		t.Fatal("the refused Everyone file was written")
	}
	if rc, _, errs := run("users-pack-sbp", "--in", sbp, "--out", shared,
		"--creds-file", creds(everyone, bundle.AudienceEveryone), "--server", server); rc != 0 {
		t.Fatalf("Everyone file: rc=%d %s", rc, errs)
	}
	plain, _ := os.ReadFile(shared)
	if got, err := bundle.ReadUpdateSecret(plain); err != nil || got.Audience != bundle.AudienceEveryone {
		t.Fatalf("Everyone member: %v", err)
	}

	// Without --creds-file the input is enveloped untouched, so an input
	// that already carries a secret (here the Everyone file) is refused.
	if rc, _, errs := run("users-pack-sbpx", "--in", shared, "--recipient-pub-hex", hex.EncodeToString(xpub),
		"--out", filepath.Join(dir, "legacy.sbpx")); rc != 2 || !strings.Contains(errs, "already carries") {
		t.Fatalf("an input with a secret, no creds: rc=%d %s", rc, errs)
	}
	if rc, _, errs := run("users-pack-sbpx", "--in", sbp, "--recipient-pub-hex", hex.EncodeToString(xpub),
		"--out", filepath.Join(dir, "legacy.sbpx")); rc != 0 {
		t.Fatalf("the signed pack, no creds: rc=%d %s", rc, errs)
	}

	// No members: exactly as before.
	rc, out, errs = run("users-pack-sbp", "--in", sbp, "--out", shared,
		"--creds-file", creds([32]byte{}, ""), "--server", server)
	if rc != 0 || !strings.Contains(out, `"update_secret":false`) {
		t.Fatalf("no secret: rc=%d %s %s", rc, out, errs)
	}
	plain, _ = os.ReadFile(shared)
	if _, err := bundle.ReadUpdateSecret(plain); err != bundle.ErrNoUpdateSecret {
		t.Fatalf("a file without a secret carries one: %v", err)
	}

	// A malformed secret is refused, and not echoed.
	bad := filepath.Join(t.TempDir(), "bad.json")
	_ = os.WriteFile(bad, []byte(`{"name":"r1","update_secret":"c2VjcmV0","update_audience":"people"}`), 0o600)
	if rc, _, errs := run("users-pack-sbpx", "--in", sbp, "--recipient-pub-hex", hex.EncodeToString(xpub),
		"--out", sbpx, "--creds-file", bad, "--server", server); rc != 2 || strings.Contains(errs, "c2VjcmV0") {
		t.Fatalf("malformed: rc=%d %s", rc, errs)
	}
}
