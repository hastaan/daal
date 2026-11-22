package trust_test

import (
	"testing"

	"daal/bundle-go/bundle"
	"daal/bundle-go/importer"
	"daal/core/trust"
)

// SaveImport keeps the file's carriers member beside the commitment
// (specs/update-ladder-v2.md §4.5): a newer valid member replaces the
// held one, a save without one (a refresh, an older file) keeps it, and a
// route saved without a commitment holds none.
func TestStoreAdapter_KeepsTheCarriersBesideTheCommitment(t *testing.T) {
	a := &trust.StoreAdapter{S: openStore(t)}
	r := testRouteInputWithModifiers("")
	r.Endpoint = []byte(`{"v":1,"server":"203.0.113.9","port":443}`)
	r.SignedAt = "2026-11-20T10:00:00Z"
	save := func(c []byte) {
		t.Helper()
		r.Profile = []byte("profile")
		r.UpdateCarriers = c
		if err := a.SaveImport(testPublisherInput(), []importer.RouteInput{r}); err != nil {
			t.Fatal(err)
		}
	}
	held := func() string {
		got, err := a.S.GetSecret(bundle.UpdateCarriersStoreKey(r.RouteID))
		if err != nil {
			return ""
		}
		return string(got)
	}

	first := `{"v":1,"gittag":{"owner":"a","repo":"b"}}`
	save([]byte(first))
	if held() != first {
		t.Fatalf("not kept: %q", held())
	}
	save(nil) // a refresh, an older file
	if held() != first {
		t.Fatalf("a save without carriers cleared them: %q", held())
	}
	save([]byte(`{"v":1,"gittag":{"owner":"a/../x","repo":"b"}}`)) // malformed: absent
	if held() != first {
		t.Fatalf("a malformed member replaced the held one: %q", held())
	}
	moved := `{"v":1,"gittag":{"owner":"c","repo":"d"},"dns":{"zone":"n.example.org"}}`
	save([]byte(moved))
	if held() != moved {
		t.Fatalf("a newer member did not replace: %q", held())
	}
	save([]byte(`{"v":1}`)) // the publisher switched every carrier off
	if held() != `{"v":1}` {
		t.Fatalf("an empty member did not replace: %q", held())
	}

	save([]byte(first))
	r.Endpoint, r.SignedAt, r.UpdateCarriers = nil, "", nil
	if err := a.S.DeleteRoute(r.RouteID); err != nil {
		t.Fatal(err)
	}
	if err := a.SaveImport(testPublisherInput(), []importer.RouteInput{r}); err != nil {
		t.Fatal(err)
	}
	if held() != "" {
		t.Fatal("a route saved without a commitment kept the carriers")
	}
}
