package abi

import (
	"encoding/hex"
	"testing"

	"daal/bundle-go/bundle"
)

// The wrapped standby code (specs/update-ladder-v2.md §3): the engine
// tries the code as typed, then unwrapped with the update secret of each
// route's file; the signed commitment decides. Vectors: the Python ones
// of bundle/go/bundle/standby_wrap_test.go.
const (
	sbWrappedText = "DW08XN Z6SE1 KJD95 57SAY MT9M8"
	sbPeopleHex   = "92b41abddf99cd530b5f2603f924f47059d1614d763b9aa012b71e39870ca072"
)

func putUpdateSecret(t *testing.T, c *Core, id, audience string, secretHex string) {
	t.Helper()
	u := bundle.UpdateSecret{Audience: audience}
	b, err := hex.DecodeString(secretHex)
	if err != nil || copy(u.Secret[:], b) != len(u.Secret) {
		t.Fatal("bad secret hex")
	}
	raw, err := bundle.MarshalUpdateSecret(u)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.store.PutSecret(bundle.UpdateSecretStoreKey(id), raw); err != nil {
		t.Fatal(err)
	}
}

func TestStandbyKey_AcceptsTheWrappedCodeWithThePersonsFile(t *testing.T) {
	rig := newAutoRig(t, [][3]string{
		{"r1", "vless-reality", sbPrimaryREALITY},
		{"r3", "vless-reality", sbOtherREALITY},
	})
	c := rig.c
	for _, id := range []string{"r1", "r3"} {
		packRoute(t, c, id, "p1")
		putStandby(t, c, id, sbSealed)
	}

	// No secret held (an older file): the wrapped code opens nothing,
	// the plain one still works.
	if got := standbyKeyCall(t, "p1", sbWrappedText); got.Outcome != StandbyKeyNoMatch {
		t.Fatalf("wrapped without a secret: %+v", got)
	}

	// Only the Everyone file's secret: the plain form only.
	putUpdateSecret(t, c, "r1", bundle.AudienceEveryone, sbPeopleHex)
	if got := standbyKeyCall(t, "p1", sbWrappedText); got.Outcome != StandbyKeyNoMatch {
		t.Fatalf("wrapped with an Everyone secret: %+v", got)
	}

	// The person's file: the wrapped code unwraps to the key on r1 only
	// (r3's file holds no secret), and the key kept is the PLAIN one.
	putUpdateSecret(t, c, "r1", bundle.AudiencePeople, sbPeopleHex)
	if got := standbyKeyCall(t, "p1", sbWrappedText); got.Outcome != StandbyKeyAccepted || got.Routes != 1 {
		t.Fatalf("wrapped with the person's secret: %+v", got)
	}
	kb, err := c.store.GetSecret(bundle.StandbyKeyStoreKey("r1"))
	if err != nil {
		t.Fatal(err)
	}
	k, _ := bundle.StandbyKeyFromBytes(kb)
	if k.Text() != sbKeyText {
		t.Fatal("the stored key is not the unwrapped plain key")
	}
	row, _ := c.store.GetRoute("r1")
	if addr, ok := routeStandbyAddress(c.store, row); !ok || addr != sbAddr {
		t.Fatalf("standby address after the wrapped code: %q %v", addr, ok)
	}

	// The plain code still works beside a held secret.
	if got := standbyKeyCall(t, "p1", sbKeyText); got.Outcome != StandbyKeyAccepted || got.Routes != 2 {
		t.Fatalf("plain beside a secret: %+v", got)
	}

	// A code wrapped under another secret opens nothing.
	other := bundle.WrapStandbyKey(k, bundle.DeriveUpdateSecret([]byte("another root"), "p1", bundle.AudiencePeople))
	if got := standbyKeyCall(t, "p1", other.Text()); got.Outcome != StandbyKeyNoMatch {
		t.Fatalf("wrapped under another secret: %+v", got)
	}
}

// A code wrapped under the second-newest secret held for a route (an
// older copy of one's file imported after the newer one, or a planted
// member in front) is still accepted: every held secret is tried.
func TestStandbyKey_TriesEverySecretHeldForTheRoute(t *testing.T) {
	rig := newAutoRig(t, [][3]string{{"r1", "vless-reality", sbPrimaryREALITY}})
	c := rig.c
	packRoute(t, c, "r1", "p1")
	putStandby(t, c, "r1", sbSealed)

	mk := func(audience, secretHex string) []byte {
		u := bundle.UpdateSecret{Audience: audience}
		b, _ := hex.DecodeString(secretHex)
		copy(u.Secret[:], b)
		raw, err := bundle.MarshalUpdateSecret(u)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	held := mk(bundle.AudiencePeople, sbPeopleHex)
	newer, ok := bundle.MergeHeldUpdateSecrets(held, mk(bundle.UpdateAudiencePeople(9), "11"+sbPeopleHex[2:]))
	if !ok {
		t.Fatal("merge refused")
	}
	if err := c.store.PutSecret(bundle.UpdateSecretStoreKey("r1"), newer); err != nil {
		t.Fatal(err)
	}
	if n := len(bundle.ParseHeldUpdateSecrets(mustGet(t, c, "r1"))); n != 2 {
		t.Fatalf("held %d secrets, want 2", n)
	}
	if got := standbyKeyCall(t, "p1", sbWrappedText); got.Outcome != StandbyKeyAccepted || got.Routes != 1 {
		t.Fatalf("wrapped under the second-newest secret: %+v", got)
	}
}

func mustGet(t *testing.T, c *Core, id string) []byte {
	t.Helper()
	b, err := c.store.GetSecret(bundle.UpdateSecretStoreKey(id))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
