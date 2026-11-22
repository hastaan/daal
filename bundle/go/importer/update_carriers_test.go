package importer_test

// The carriers member (specs/update-ladder-v2.md §4.5) in a person's
// file: carried by this build to the store beside each commitment, and
// invisible to the rules phones in the field already run
// (internal/oldrules, frozen from 079ef96) and to this build's own
// signature and RelayPack checks.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"daal/bundle-go/bundle"
	"daal/bundle-go/importer/internal/oldrules"
)

const testCarriers = `{"v":1,"gittag":{"owner":"quiet-owner","repo":"notes"},"dns":{"zone":"n.example.org"}}`

func TestOldBuild_IgnoresTheCarriersMember(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := newTestRoot(t)
	body := withMember(t, defaultAddonPack(t, pub, priv, root), bundle.UpdateSecretPath, peopleSecret(t))
	body = withMember(t, body, bundle.UpdateCarriersPath, []byte(testCarriers))

	_, out := oldImport(t, body, &oldDevice{routes: map[string]oldrules.DeviceRoute{}}, false)
	if out.Refused {
		t.Fatalf("the old rules refused a file with a carriers member: %s %v", out.Reason, out.Err)
	}
	if len(out.Stored) != 2 || out.Stored[0].RouteID != "rA" || out.Stored[1].RouteID != "rB" {
		t.Fatalf("the direct routes must import: %+v", out.Stored)
	}
	for _, r := range out.Stored {
		for _, s := range []string{"quiet-owner", "n.example.org", "gittag"} {
			if bytes.Contains(r.Profile, []byte(s)) || bytes.Contains(r.Endpoint, []byte(s)) ||
				bytes.Contains([]byte(r.EngineConfig), []byte(s)) {
				t.Fatalf("%s: the carriers reached an old build's store", r.RouteID)
			}
		}
	}
	parsed, err := bundle.ParseSBP(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	if err := bundle.VerifyBundleAt(parsed, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
}

func TestImport_CarriesTheCarriersBesideTheCommitment(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := newTestRoot(t)
	st := newDeviceState()
	// Not canonical on the wire (spacing): the store gets the canonical form.
	loose := []byte(`{ "dns": {"zone":"n.example.org"}, "v": 1, "gittag": {"repo":"notes","owner":"quiet-owner"} }`)
	mustImport(t, st, withMember(t, defaultAddonPack(t, pub, priv, root), bundle.UpdateCarriersPath, loose))
	got := savedByID(t, st)
	for _, id := range []string{"rA", "rB", "rC"} {
		if string(got[id].UpdateCarriers) != testCarriers {
			t.Fatalf("%s: carriers %q", id, got[id].UpdateCarriers)
		}
	}
}

func TestImport_NoOrMalformedCarriersAreAbsent(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := newTestRoot(t)
	plain := defaultAddonPack(t, pub, priv, root)
	for name, body := range map[string][]byte{
		"older file": plain,
		"malformed":  withMember(t, plain, bundle.UpdateCarriersPath, []byte(`{"v":1,"gittag":{"owner":"a/b","repo":"x"}}`)),
		"unknown v":  withMember(t, plain, bundle.UpdateCarriersPath, []byte(`{"v":2}`)),
	} {
		st := newDeviceState()
		mustImport(t, st, body)
		for id, r := range savedByID(t, st) {
			if r.UpdateCarriers != nil {
				t.Fatalf("%s/%s: carried %q", name, id, r.UpdateCarriers)
			}
		}
	}
}
