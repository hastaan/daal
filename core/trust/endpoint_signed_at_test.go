package trust_test

import (
	"errors"
	"testing"

	"daal/bundle-go/importer"
	"daal/core/trust"
)

// The importer refuses to merge a signed skeleton that is older than
// what a route holds (bundle/go/importer planRoutes, rule 4). That rule
// reads the route's commitment and the date it was signed back from
// THIS store, so the store has to keep them, keep them together, and
// drop them together.
func TestStoreAdapter_KeepsWhenARouteEndpointWasSigned(t *testing.T) {
	a := &trust.StoreAdapter{S: openStore(t)}
	r := testRouteInputWithModifiers("")
	// (PutSecret wipes the plaintext it is handed, so the expected
	// commitment is kept as a string.)
	first := `{"v":1,"server":"203.0.113.9","port":443}`
	r.Endpoint = []byte(first)
	r.SignedAt = "2026-05-05T10:00:00Z"
	if err := a.SaveImport(testPublisherInput(), []importer.RouteInput{r}); err != nil {
		t.Fatal(err)
	}
	got, ok, err := a.DeviceRoute(r.RouteID)
	if err != nil || !ok {
		t.Fatalf("DeviceRoute: ok=%v err=%v", ok, err)
	}
	if got.SignedAt != r.SignedAt || string(got.Endpoint) != first {
		t.Fatalf("the store did not hand back what the endpoint was signed with: %+v", got)
	}

	// A later signing replaces the date along with the commitment.
	second := `{"v":1,"server":"203.0.113.9","port":8443}`
	r.Endpoint = []byte(second)
	r.SignedAt = "2026-06-01T10:00:00Z"
	r.Profile = []byte("profile")
	if err := a.SaveImport(testPublisherInput(), []importer.RouteInput{r}); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := a.DeviceRoute(r.RouteID); got.SignedAt != r.SignedAt || string(got.Endpoint) != second {
		t.Fatalf("after a re-import: %+v", got)
	}

	// A route that is held to a commitment is not replaced by one with
	// none (rule 5): the save is refused and the commitment, its date
	// and the profile stay exactly as they were.
	bare := r
	bare.Endpoint, bare.SignedAt, bare.Profile, bare.RelayPack = nil, "", []byte("attacker"), nil
	if err := a.SaveImport(testPublisherInput(), []importer.RouteInput{bare}); !errors.Is(err, importer.ErrEndpointDowngrade) {
		t.Fatalf("an uncommitted replacement of a committed route: err=%v", err)
	}
	if got, _, _ := a.DeviceRoute(r.RouteID); got.SignedAt != r.SignedAt || string(got.Endpoint) != second || string(got.Profile) != "profile" {
		t.Fatalf("a refused save changed the route: %+v", got)
	}

	// Once the user has removed the route, what it left behind does not
	// bind a new route under the same id — and a route saved with no
	// commitment leaves no date behind either: a stale one would be
	// compared against a commitment that is gone.
	if err := a.S.DeleteRoute(r.RouteID); err != nil {
		t.Fatal(err)
	}
	if err := a.SaveImport(testPublisherInput(), []importer.RouteInput{bare}); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := a.DeviceRoute(r.RouteID); got.SignedAt != "" || len(got.Endpoint) != 0 {
		t.Fatalf("a date outlived its commitment: %+v", got)
	}
}

// The same rule for a route that is committed only by belonging to a
// RelayPack (relay_pack_id set), and for one that has since expired or
// been revoked: neither may be overwritten by an uncommitted route, and
// relay_pack_id must not be blanked.
func TestStoreAdapter_CommitmentIsSticky(t *testing.T) {
	a := &trust.StoreAdapter{S: openStore(t)}
	r := testRouteInputWithModifiers("")
	r.Endpoint = []byte(`{"v":1,"server":"203.0.113.9","port":443}`)
	r.SignedAt = "2026-05-05T10:00:00Z"
	if err := a.SaveImport(testPublisherInput(), []importer.RouteInput{r}); err != nil {
		t.Fatal(err)
	}
	before, err := a.S.GetRoute(r.RouteID)
	if err != nil || before.RelayPackID == "" {
		t.Fatalf("fixture route is not a RelayPack route: %+v %v", before, err)
	}
	if err := a.S.MarkRouteRevoked(r.RouteID); err != nil {
		t.Fatal(err)
	}
	if held, err := a.RouteCommitted(r.RouteID); err != nil || !held {
		t.Fatalf("a revoked committed route must still count: held=%v err=%v", held, err)
	}
	// Even with the commitment secret gone, the pack id alone binds.
	if err := a.S.DeleteSecret(trust.RouteEndpointKey(r.RouteID)); err != nil {
		t.Fatal(err)
	}
	bare := r
	bare.Endpoint, bare.SignedAt, bare.RelayPack, bare.Profile = nil, "", nil, []byte("attacker")
	if err := a.SaveImport(testPublisherInput(), []importer.RouteInput{bare}); !errors.Is(err, importer.ErrEndpointDowngrade) {
		t.Fatalf("err=%v", err)
	}
	after, err := a.S.GetRoute(r.RouteID)
	if err != nil || after.RelayPackID != before.RelayPackID {
		t.Fatalf("relay_pack_id changed: %q -> %q (%v)", before.RelayPackID, after.RelayPackID, err)
	}
	if held, _ := a.RouteCommitted("no-such-route"); held {
		t.Fatal("a route the device does not hold is not committed")
	}
}
