package trust_test

import (
	"testing"

	"daal/bundle-go/bundle"
	"daal/bundle-go/importer"
	"daal/core/trust"
)

func secretJSON(t *testing.T, audience string, b byte) []byte {
	t.Helper()
	u := bundle.UpdateSecret{Audience: audience}
	for i := range u.Secret {
		u.Secret[i] = b
	}
	raw, err := bundle.MarshalUpdateSecret(u)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// heldSecrets is the list of secret first bytes held for the route,
// newest first (each test secret is one byte repeated).
func heldSecrets(t *testing.T, a *trust.StoreAdapter, routeID string) []byte {
	t.Helper()
	got, err := a.S.GetSecret(bundle.UpdateSecretStoreKey(routeID))
	if err != nil {
		return nil
	}
	var out []byte
	for _, u := range bundle.ParseHeldUpdateSecrets(got) {
		out = append(out, u.Secret[0])
	}
	return out
}

// SaveImport keeps the file's update secrets beside the commitment
// (specs/update-ladder-v2.md §2, "On the device"): a person's secret goes
// first in a short list and never costs the phone one it holds, an
// Everyone secret never replaces a person's, and a save that carries
// none (a refresh, an older file) keeps them.
func TestStoreAdapter_KeepsTheUpdateSecretBesideTheCommitment(t *testing.T) {
	a := &trust.StoreAdapter{S: openStore(t)}
	r := testRouteInputWithModifiers("")
	r.Endpoint = []byte(`{"v":1,"server":"203.0.113.9","port":443}`)
	r.SignedAt = "2026-11-20T10:00:00Z"
	save := func(sec []byte) {
		t.Helper()
		r.Profile = []byte("profile")
		r.UpdateSecret = sec
		if err := a.SaveImport(testPublisherInput(), []importer.RouteInput{r}); err != nil {
			t.Fatal(err)
		}
	}
	held := func() string { return string(heldSecrets(t, a, r.RouteID)) }

	everyone := secretJSON(t, bundle.AudienceEveryone, 1)
	people := secretJSON(t, bundle.AudiencePeople, 2)
	people2 := secretJSON(t, bundle.UpdateAudiencePeople(2), 3)

	save(everyone)
	if held() != "\x01" {
		t.Fatal("the Everyone secret was not kept where none was held")
	}
	save(people)
	if held() != "\x02" {
		t.Fatalf("a person's secret did not replace the Everyone one: %x", held())
	}
	save(everyone)
	if held() != "\x02" {
		t.Fatal("the Everyone file replaced the person's secret")
	}
	save(nil)
	if held() != "\x02" {
		t.Fatal("a save without a secret (a refresh, an older file) dropped it")
	}
	save([]byte(`{"v":9}`))
	if held() != "\x02" {
		t.Fatal("a malformed secret replaced a good one")
	}
	save(people2)
	if held() != "\x03\x02" {
		t.Fatalf("a newer generation did not go first, keeping the old: %x", held())
	}
	// An older copy of one's own file (or a planted member) re-imported
	// after a newer one: both are kept, the one just seen first.
	save(people)
	if held() != "\x02\x03" {
		t.Fatalf("an older file after a newer one lost a secret: %x", held())
	}
	// A fifth distinct secret lets the oldest go.
	for _, b := range []byte{4, 5, 6} {
		save(secretJSON(t, bundle.UpdateAudiencePeople(int(b)), b))
	}
	if held() != "\x06\x05\x04\x02" {
		t.Fatalf("the list is not newest first, four long: %x", held())
	}

	// Saved with no commitment: nothing of the old route stays.
	r.Endpoint, r.SignedAt, r.UpdateSecret = nil, "", nil
	if err := a.S.DeleteRoute(r.RouteID); err != nil {
		t.Fatal(err)
	}
	if err := a.SaveImport(testPublisherInput(), []importer.RouteInput{r}); err != nil {
		t.Fatal(err)
	}
	if held() != "" {
		t.Fatal("a route saved without a commitment kept the update secret")
	}
}

// What the first build that kept a secret stored (one member, not a
// list) is still read, and a new secret goes in front of it.
func TestStoreAdapter_ReadsTheOldSingleSecretForm(t *testing.T) {
	a := &trust.StoreAdapter{S: openStore(t)}
	r := testRouteInputWithModifiers("")
	r.Endpoint = []byte(`{"v":1,"server":"203.0.113.9","port":443}`)
	r.SignedAt = "2026-11-20T10:00:00Z"
	r.Profile = []byte("profile")
	if err := a.SaveImport(testPublisherInput(), []importer.RouteInput{r}); err != nil {
		t.Fatal(err)
	}
	if err := a.S.PutSecret(bundle.UpdateSecretStoreKey(r.RouteID), secretJSON(t, bundle.AudiencePeople, 7)); err != nil {
		t.Fatal(err)
	}
	if got := string(heldSecrets(t, a, r.RouteID)); got != "\x07" {
		t.Fatalf("old form not read: %x", got)
	}
	r.Profile = []byte("profile")
	r.UpdateSecret = secretJSON(t, bundle.UpdateAudiencePeople(2), 8)
	if err := a.SaveImport(testPublisherInput(), []importer.RouteInput{r}); err != nil {
		t.Fatal(err)
	}
	if got := string(heldSecrets(t, a, r.RouteID)); got != "\x08\x07" {
		t.Fatalf("new secret not put in front of the old form: %x", got)
	}
}
