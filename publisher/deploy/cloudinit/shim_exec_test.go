package cloudinit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// shimWorld stages what the box has when daal-fetch-verify runs: the
// shim itself, a release public key, and a manifest whose one artefact
// is served by a local mirror. It RUNS the embedded shim bytes — the
// same bytes cloud-init writes to /usr/local/bin/daal-fetch-verify.
type shimWorld struct {
	shim, pub, manifest, target string
}

func newShimWorld(t *testing.T, mirrors func(good string) []string, tamperSig bool) shimWorld {
	t.Helper()
	for _, tool := range []string{"bash", "python3", "openssl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed", tool)
		}
	}
	dir := t.TempDir()
	pubKey, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		t.Fatal(err)
	}
	w := shimWorld{
		shim:     filepath.Join(dir, "daal-fetch-verify"),
		pub:      filepath.Join(dir, "release.pub"),
		manifest: filepath.Join(dir, "artifacts.json"),
		target:   filepath.Join(dir, "bin"),
	}
	if err := os.Mkdir(w.target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(w.pub, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(w.shim, VerifierShimSource(), 0o755); err != nil {
		t.Fatal(err)
	}
	body := []byte("#!/bin/sh\necho artefact\n")
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/good" {
			http.NotFound(rw, r)
			return
		}
		_, _ = rw.Write(body)
	}))
	t.Cleanup(srv.Close)
	sum := sha256.Sum256(body)
	sig := ed25519.Sign(priv, body)
	if tamperSig {
		sig[0] ^= 0xff
	}
	m := ArtifactManifest{Version: "test", Artefacts: []Artifact{{
		Name:      "thing-1.0-linux-amd64",
		InstallAs: "thing",
		Sha256:    hex.EncodeToString(sum[:]),
		SigHex:    hex.EncodeToString(sig),
		Mirrors:   mirrors(srv.URL + "/good"),
	}}}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(w.manifest, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return w
}

func (w shimWorld) run(t *testing.T, tmpdir string) (string, error) {
	t.Helper()
	cmd := exec.Command("bash", w.shim, w.manifest, w.pub, w.target+"/")
	cmd.Env = append(os.Environ(), "TMPDIR="+tmpdir)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

// otherMount returns a writable directory on a different filesystem
// than `ref`, or "" when this machine has none to offer.
func otherMount(t *testing.T, ref string) string {
	t.Helper()
	var rs syscall.Stat_t
	if err := syscall.Stat(ref, &rs); err != nil {
		t.Fatal(err)
	}
	home, _ := os.UserHomeDir()
	wd, _ := os.Getwd()
	for _, base := range []string{"/dev/shm", "/var/tmp", home, wd, "/run/user/" + strings.TrimSpace(os.Getenv("UID"))} {
		if base == "" {
			continue
		}
		var bs syscall.Stat_t
		if err := syscall.Stat(base, &bs); err != nil || bs.Dev == rs.Dev {
			continue
		}
		d, err := os.MkdirTemp(base, "daal-shim-test-")
		if err != nil {
			continue
		}
		t.Cleanup(func() { _ = os.RemoveAll(d) })
		return d
	}
	return ""
}

// TestVerifierShim_InstallsAcrossMounts is F-001: the default temp
// directory and the install directory on different mounts (a tmpfs
// /tmp, which is systemd's default, or /usr/local as its own volume).
// The old shim downloaded to $TMPDIR and rename(2)d into place, which is
// EXDEV — reported as "no mirror passed verification" after the hash
// and the signature had both passed.
func TestVerifierShim_InstallsAcrossMounts(t *testing.T) {
	w := newShimWorld(t, func(good string) []string { return []string{good} }, false)
	tmp := otherMount(t, w.target)
	if tmp == "" {
		t.Skip("no second writable filesystem on this machine")
	}
	out, err := w.run(t, tmp)
	if err != nil {
		t.Fatalf("shim failed with TMPDIR on another mount: %v\n%s", err, out)
	}
	dst := filepath.Join(w.target, "thing")
	st, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o755 {
		t.Errorf("installed mode = %v, want 0755", st.Mode().Perm())
	}
	left, _ := os.ReadDir(w.target)
	if len(left) != 1 {
		t.Errorf("install dir holds %d entries, want only the artefact (temp files left behind)", len(left))
	}
	strays, _ := os.ReadDir(tmp)
	if len(strays) != 0 {
		t.Errorf("shim wrote %d file(s) to TMPDIR; it must stage beside the destination", len(strays))
	}
}

// TestVerifierShim_SaysWhyAMirrorFailed: the per-mirror reason reaches
// stderr. Swallowing it is what made F-001 read like a signature
// problem.
func TestVerifierShim_SaysWhyAMirrorFailed(t *testing.T) {
	w := newShimWorld(t, func(good string) []string {
		return []string{strings.TrimSuffix(good, "/good") + "/missing"}
	}, false)
	out, err := w.run(t, t.TempDir())
	if err == nil {
		t.Fatalf("shim succeeded with no working mirror:\n%s", out)
	}
	for _, want := range []string{"FAIL: no mirror passed verification for thing-1.0-linux-amd64", "/missing", "404"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

// TestVerifierShim_RefusesBadSignature: the fix must not have loosened
// the gate. A right-hash, wrong-signature artefact is not installed and
// nothing is left in the install directory.
func TestVerifierShim_RefusesBadSignature(t *testing.T) {
	w := newShimWorld(t, func(good string) []string { return []string{good} }, true)
	out, err := w.run(t, t.TempDir())
	if err == nil {
		t.Fatalf("shim installed an artefact whose signature does not verify:\n%s", out)
	}
	if !strings.Contains(out, "signature did not verify") {
		t.Errorf("output does not name the signature failure:\n%s", out)
	}
	left, _ := os.ReadDir(w.target)
	if len(left) != 0 {
		t.Errorf("install dir not empty after a refused artefact: %d entries", len(left))
	}
}

// TestVerifierShim_FallsBackToSecondMirror: a dead first mirror must not
// stop a good second one.
func TestVerifierShim_FallsBackToSecondMirror(t *testing.T) {
	w := newShimWorld(t, func(good string) []string {
		return []string{strings.TrimSuffix(good, "/good") + "/missing", good}
	}, false)
	if out, err := w.run(t, t.TempDir()); err != nil {
		t.Fatalf("shim did not fall back: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(w.target, "thing")); err != nil {
		t.Fatal(err)
	}
}
