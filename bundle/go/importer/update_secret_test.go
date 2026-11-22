package importer_test

// The update secret (specs/update-ladder-v2.md §2) in a person's file:
// carried by this build to the store beside each commitment, and invisible
// to the rules phones in the field already run (internal/oldrules, frozen
// from 079ef96) and to this build's own signature and RelayPack checks.

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"testing"
	"time"

	"daal/bundle-go/bundle"
	"daal/bundle-go/importer/internal/oldrules"
)

// withMember re-zips body with one more archive member.
func withMember(t *testing.T, body []byte, name string, data []byte) []byte {
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

func peopleSecret(t *testing.T) []byte {
	t.Helper()
	u := bundle.UpdateSecret{Audience: bundle.AudiencePeople,
		Secret: bundle.DeriveUpdateSecret([]byte("root"), "rp-addons-001", bundle.AudiencePeople)}
	raw, err := bundle.MarshalUpdateSecret(u)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// An old build imports a file that carries the secret exactly as one
// without it: same routes, nothing refused, and the secret is nowhere in
// what it stores.
func TestOldBuild_IgnoresTheUpdateSecret(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := newTestRoot(t)
	secret := peopleSecret(t)
	body := withMember(t, defaultAddonPack(t, pub, priv, root), bundle.UpdateSecretPath, secret)

	_, out := oldImport(t, body, &oldDevice{routes: map[string]oldrules.DeviceRoute{}}, false)
	if out.Refused {
		t.Fatalf("the old rules refused a file with an update secret: %s %v", out.Reason, out.Err)
	}
	if len(out.Stored) != 2 || out.Stored[0].RouteID != "rA" || out.Stored[1].RouteID != "rB" {
		t.Fatalf("the direct routes must import: %+v", out.Stored)
	}
	for _, r := range out.Stored {
		if bytes.Contains(r.Profile, secret) || bytes.Contains(r.Endpoint, secret) ||
			bytes.Contains([]byte(r.EngineConfig), []byte("secret")) {
			t.Fatalf("%s: the secret reached an old build's store", r.RouteID)
		}
	}
	// The member is outside the signed manifest: the signature is the
	// one the publisher made, unchanged.
	parsed, err := bundle.ParseSBP(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	if err := bundle.VerifyBundleAt(parsed, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
}

func TestImport_CarriesTheUpdateSecretBesideTheCommitment(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := newTestRoot(t)
	secret := peopleSecret(t)
	st := newDeviceState()
	mustImport(t, st, withMember(t, defaultAddonPack(t, pub, priv, root), bundle.UpdateSecretPath, secret))
	got := savedByID(t, st)
	for _, id := range []string{"rA", "rB", "rC"} {
		if string(got[id].UpdateSecret) != string(secret) {
			t.Fatalf("%s: update secret %q", id, got[id].UpdateSecret)
		}
	}
}

// An older file without a secret, and a file with a malformed one, import
// as before and carry none: their codes work in the plain form only.
func TestImport_NoOrMalformedUpdateSecretIsAbsent(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := newTestRoot(t)
	plain := defaultAddonPack(t, pub, priv, root)
	for name, body := range map[string][]byte{
		"older file": plain,
		"malformed":  withMember(t, plain, bundle.UpdateSecretPath, []byte(`{"v":2,"audience":"people","secret":"x"}`)),
	} {
		st := newDeviceState()
		mustImport(t, st, body)
		for id, r := range savedByID(t, st) {
			if r.UpdateSecret != nil {
				t.Fatalf("%s/%s: carried %q", name, id, r.UpdateSecret)
			}
		}
	}
}
