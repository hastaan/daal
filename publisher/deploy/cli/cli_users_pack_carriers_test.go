package cli

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"

	"daal/bundle-go/bundle"
	"daal/bundle-go/envelope"
)

// The carriers member reaches a person's file through the creds JSON
// only, is sealed with the rest, is never printed, needs a person's
// secret, and is refused for the Everyone file.
func TestUsersPack_CarriersTravelInTheCredsFileOnly(t *testing.T) {
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
	const carriers = `{"v":1,"gittag":{"owner":"quiet-owner","repo":"notes"},"dns":{"zone":"n.example.org"}}`
	creds := func(secret *[32]byte, audience string, car string) string {
		c := map[string]any{
			"name": "r1", "vless_uuid": "11111111-2222-3333-4444-555555555555", "reality_short_id": "deadbeef",
			"hy2_password": "hy2secretpassword22ch", "reality_public_key": fixtureRealityPub,
			"tls_cert_sha256": fixtureTLSPin, "cover_sni": rec["cover_sni"],
		}
		if secret != nil {
			c["update_secret"] = base64.StdEncoding.EncodeToString(secret[:])
			c["update_audience"] = audience
		}
		if car != "" {
			c["update_carriers"] = json.RawMessage(car)
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
	var xpriv [32]byte
	_, _ = rand.Read(xpriv[:])
	xpub, _ := curve25519.X25519(xpriv[:], curve25519.Basepoint)
	pubHex := hex.EncodeToString(xpub)
	sbpx := filepath.Join(dir, "p.sbpx")

	rc, out, errs := run("users-pack-sbpx", "--in", sbp, "--recipient-pub-hex", pubHex,
		"--out", sbpx, "--creds-file", creds(&people, bundle.AudiencePeople, carriers), "--server", server)
	if rc != 0 {
		t.Fatalf("users-pack-sbpx rc=%d %s", rc, errs)
	}
	if strings.Contains(out+errs, "quiet-owner") || strings.Contains(out+errs, "n.example.org") ||
		!strings.Contains(out, `"update_carriers":true`) {
		t.Fatalf("stdout/stderr: %s %s", out, errs)
	}
	sealed, _ := os.ReadFile(sbpx)
	if bytes.Contains(sealed, []byte("quiet-owner")) {
		t.Fatal("the carriers are readable outside the envelope")
	}
	inner, err := envelope.Decrypt(sealed, xpriv)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := bundle.ReadUpdateCarriers(inner); err != nil || got.GitTag.Repo != "notes" || got.DNS.Zone != "n.example.org" {
		t.Fatalf("inner member: %v", err)
	}

	// No secret, or the Everyone secret: refused.
	for name, c := range map[string]string{
		"no secret": creds(nil, "", carriers),
		"everyone":  creds(&everyone, bundle.AudienceEveryone, carriers),
	} {
		if rc, _, errs := run("users-pack-sbpx", "--in", sbp, "--recipient-pub-hex", pubHex,
			"--out", filepath.Join(dir, "x.sbpx"), "--creds-file", c, "--server", server); rc != 2 ||
			!strings.Contains(errs, "update_secret") {
			t.Fatalf("%s: rc=%d %s", name, rc, errs)
		}
	}
	// Malformed: refused, not echoed.
	if rc, _, errs := run("users-pack-sbpx", "--in", sbp, "--recipient-pub-hex", pubHex,
		"--out", filepath.Join(dir, "x.sbpx"), "--creds-file",
		creds(&people, bundle.AudiencePeople, `{"v":1,"dns":{"zone":"evil zone.example"}}`), "--server", server); rc != 2 ||
		strings.Contains(errs, "evil") {
		t.Fatalf("malformed: rc=%d %s", rc, errs)
	}
	// The Everyone file: refused.
	shared := filepath.Join(dir, "shared.sbp")
	if rc, _, errs := run("users-pack-sbp", "--in", sbp, "--out", shared,
		"--creds-file", creds(&everyone, bundle.AudienceEveryone, carriers), "--server", server); rc != 2 ||
		!strings.Contains(errs, "Everyone") || strings.Contains(errs, "quiet-owner") {
		t.Fatalf("Everyone file with carriers: rc=%d %s", rc, errs)
	}
	if _, err := os.Stat(shared); err == nil {
		t.Fatal("the refused Everyone file was written")
	}
	rc, out, errs = run("users-pack-sbp", "--in", sbp, "--out", shared,
		"--creds-file", creds(&everyone, bundle.AudienceEveryone, ""), "--server", server)
	if rc != 0 || !strings.Contains(out, `"update_carriers":false`) {
		t.Fatalf("Everyone file: rc=%d %s %s", rc, out, errs)
	}

	// Without --creds-file: an input that carries the member is refused.
	withCar := filepath.Join(dir, "with.sbp")
	raw, _ := os.ReadFile(sbp)
	if err := os.WriteFile(withCar, addZipMember(t, raw, bundle.UpdateCarriersPath, []byte(carriers)), 0o600); err != nil {
		t.Fatal(err)
	}
	if rc, _, errs := run("users-pack-sbpx", "--in", withCar, "--recipient-pub-hex", pubHex,
		"--out", filepath.Join(dir, "legacy.sbpx")); rc != 2 || !strings.Contains(errs, "already carries update carriers") {
		t.Fatalf("an input with carriers, no creds: rc=%d %s", rc, errs)
	}
}

// addZipMember re-zips body with one more member.
func addZipMember(t *testing.T, body []byte, name string, data []byte) []byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(rc)
		rc.Close()
		w, _ := zw.Create(f.Name)
		w.Write(b)
	}
	w, _ := zw.Create(name)
	w.Write(data)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
