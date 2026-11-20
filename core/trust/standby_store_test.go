package trust_test

import (
	"testing"

	"daal/bundle-go/bundle"
	"daal/bundle-go/importer"
	"daal/core/trust"
)

// SaveImport keeps a route's signed `_standby` beside its commitment
// (specs/relaypack-v1.md "`_standby` key", "On the device"): written
// with it, rewritten on every save, and removed — with any accepted
// standby key — when a newer commitment carries none or the route is
// saved without a commitment at all.
func TestStoreAdapter_KeepsTheStandbyWithTheCommitment(t *testing.T) {
	a := &trust.StoreAdapter{S: openStore(t)}
	r := testRouteInputWithModifiers("")
	const sealed = `{"v":1,"mode":"sealed","commit":"oLKATgHpOx6iddfCqnGCuDAi1XSE7ysXDZ1tUmE5HHY="}`
	const open = `{"v":1,"mode":"open","server":"203.0.113.20"}`
	r.Endpoint = []byte(`{"v":1,"server":"203.0.113.9","port":443}`)
	r.SignedAt = "2026-11-20T10:00:00Z"
	r.Standby = []byte(sealed)
	if err := a.SaveImport(testPublisherInput(), []importer.RouteInput{r}); err != nil {
		t.Fatal(err)
	}
	if got, err := a.S.GetSecret(bundle.StandbyStoreKey(r.RouteID)); err != nil || string(got) != sealed {
		t.Fatalf("standby not stored as signed: %q %v", got, err)
	}

	// A key accepted later (engine_standby_key) survives a refresh that
	// still carries a standby: it only ever opens the commitment it
	// hashes to.
	if err := a.S.PutSecret(bundle.StandbyKeyStoreKey(r.RouteID), make([]byte, bundle.StandbyKeyLen)); err != nil {
		t.Fatal(err)
	}
	r.Endpoint = []byte(`{"v":1,"server":"203.0.113.9","port":443}`)
	r.Profile = []byte("profile")
	r.Standby = []byte(open)
	if err := a.SaveImport(testPublisherInput(), []importer.RouteInput{r}); err != nil {
		t.Fatal(err)
	}
	if got, _ := a.S.GetSecret(bundle.StandbyStoreKey(r.RouteID)); string(got) != open {
		t.Fatalf("a refresh did not rewrite the standby: %q", got)
	}
	if got, err := a.S.GetSecret(bundle.StandbyKeyStoreKey(r.RouteID)); err != nil || len(got) != bundle.StandbyKeyLen {
		t.Fatalf("the key went with a refresh that still carries a standby: %v", err)
	}

	// A newer commitment without `_standby`: both go.
	r.Endpoint = []byte(`{"v":1,"server":"203.0.113.9","port":443}`)
	r.Profile = []byte("profile")
	r.Standby = nil
	if err := a.SaveImport(testPublisherInput(), []importer.RouteInput{r}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.S.GetSecret(bundle.StandbyStoreKey(r.RouteID)); err == nil {
		t.Fatal("a commitment without _standby left the old standby behind")
	}
	if _, err := a.S.GetSecret(bundle.StandbyKeyStoreKey(r.RouteID)); err == nil {
		t.Fatal("a commitment without _standby left the standby key behind")
	}
}

// A route saved with no commitment (one the user removed, re-imported
// from a file that is not a RelayPack) keeps no standby of the route
// that held the id before.
func TestStoreAdapter_NoCommitmentNoStandby(t *testing.T) {
	a := &trust.StoreAdapter{S: openStore(t)}
	r := testRouteInputWithModifiers("")
	r.Endpoint = []byte(`{"v":1,"server":"203.0.113.9","port":443}`)
	r.SignedAt = "2026-11-20T10:00:00Z"
	r.Standby = []byte(`{"v":1,"mode":"open","server":"203.0.113.20"}`)
	if err := a.SaveImport(testPublisherInput(), []importer.RouteInput{r}); err != nil {
		t.Fatal(err)
	}
	if err := a.S.PutSecret(bundle.StandbyKeyStoreKey(r.RouteID), make([]byte, bundle.StandbyKeyLen)); err != nil {
		t.Fatal(err)
	}
	if err := a.S.DeleteRoute(r.RouteID); err != nil {
		t.Fatal(err)
	}
	bare := r
	bare.Endpoint, bare.SignedAt, bare.Standby, bare.RelayPack = nil, "", nil, nil
	bare.Profile = []byte("profile")
	if err := a.SaveImport(testPublisherInput(), []importer.RouteInput{bare}); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{bundle.StandbyStoreKey(r.RouteID), bundle.StandbyKeyStoreKey(r.RouteID)} {
		if _, err := a.S.GetSecret(k); err == nil {
			t.Fatalf("%s outlived its commitment", k)
		}
	}
}
