package rotation

// THE FAILURE PATHS OF AN ADDRESS SWAP
//
// A rotation that strands the relay is worse than a burned IP: a burned
// address is a route the operator knows is dead, while a stranded one is
// a route every recipient believes in. So the tests that matter for L3
// are not the happy path (executor_test.go has that) but the ones where
// something fails in the middle, and the question each asks is the same:
// after this failure, does rec.PublicIP still name an address that is
// routed to this server?

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"daal/publisher/deploy/provider"
)

func l3Fixture(t *testing.T, prov provider.Provider, b *mockBinder) (*Executor, *memStore, *provider.OperatorRecord) {
	t.Helper()
	st := &memStore{}
	clk := &fakeClock{t: time.Unix(1700000000, 0).UTC()}
	return newExecutor(prov, b, st, clk), st, newRecord("fip-old")
}

func rotateL3(t *testing.T, exec *Executor, rec *provider.OperatorRecord, fipID string) (*RotateResult, error) {
	t.Helper()
	return exec.Rotate(context.Background(), &RotateRequest{
		OperatorID:      7,
		Record:          rec,
		PrivKey:         newPriv(t),
		Recommendation:  RotationRecommendation{Level: L3},
		NewFloatingIPID: fipID,
	})
}

// An adapter that attaches the address and leaves the record naming the
// old one is the pre-Step-9 Hetzner adapter and the Vultr/Stark adapters
// today. It must fail, loudly, rather than let the binder sign a pack
// aimed at the address the operator is rotating away from.
func TestL3_LegacyAdapterThatMovesNothingIsRejected(t *testing.T) {
	prov := &mockProvider{legacyAssign: true}
	b := &mockBinder{res: okBinderRes()}
	exec, st, rec := l3Fixture(t, prov, b)
	before := rec.PublicIP.String()

	_, err := rotateL3(t, exec, rec, "fip-new")
	if !errors.Is(err, ErrL3AddressUnchanged) {
		t.Fatalf("err = %v, want ErrL3AddressUnchanged", err)
	}
	if b.calls != 0 {
		t.Errorf("Bind ran %d times; a pack must never be signed against a record whose address did not move", b.calls)
	}
	if st.committed != 0 {
		t.Errorf("committed %d rows; want 0", st.committed)
	}
	if rec.PublicIP.String() != before {
		t.Errorf("record left on %s, want the pre-swap %s", rec.PublicIP, before)
	}
}

// The record keeps TWO copies of the dialled address. An adapter that
// moves PublicIP and forgets the candidate tags signs a pack that dials
// one address and declares another.
func TestL3_HalfAppliedRecordIsRejected(t *testing.T) {
	prov := &halfApplyProvider{mockProvider: &mockProvider{}}
	b := &mockBinder{res: okBinderRes()}
	exec, st, rec := l3Fixture(t, prov, b)

	_, err := rotateL3(t, exec, rec, "fip-new")
	if !errors.Is(err, ErrRecordAddressInconsistent) {
		t.Fatalf("err = %v, want ErrRecordAddressInconsistent", err)
	}
	if b.calls != 0 || st.committed != 0 {
		t.Errorf("bind=%d commit=%d; want 0/0", b.calls, st.committed)
	}
	// Rolled back onto the address it came from, tags included.
	if err := CheckRecordAddressConsistent(rec); err != nil {
		t.Errorf("rollback left the record inconsistent: %v", err)
	}
	if got := rec.PublicIP.String(); got != "198.51.100.10" {
		t.Errorf("record.PublicIP = %s, want the pre-swap 198.51.100.10", got)
	}
	if rec.FloatingIPID != "fip-old" {
		t.Errorf("record.FloatingIPID = %q, want the pre-swap fip-old", rec.FloatingIPID)
	}
}

// halfApplyProvider moves rec.PublicIP but not the candidates' tags.
type halfApplyProvider struct{ *mockProvider }

func (h *halfApplyProvider) AssignFloatingIP(_ context.Context, rec *provider.OperatorRecord, fipID string) error {
	h.assignFloatingCalls++
	rec.FloatingIPID = fipID
	rec.PublicIP = h.addressOf(fipID)
	return nil
}

// A bind failure is the canonical "fails midway" case: the address is
// attached, nothing is signed. The relay must end up back on the address
// its distributed packs name, and the address we took must be given
// back rather than left billing.
func TestL3_BindFailureRollsBackTheSwap(t *testing.T) {
	prov := &mockProvider{}
	b := &mockBinder{err: errors.New("signing key unavailable")}
	exec, st, rec := l3Fixture(t, prov, b)

	if _, err := rotateL3(t, exec, rec, "fip-new"); err == nil {
		t.Fatal("expected the bind failure to surface")
	}
	if st.committed != 0 {
		t.Errorf("committed %d rows after a failed bind", st.committed)
	}
	if got := rec.PublicIP.String(); got != "198.51.100.10" {
		t.Errorf("record.PublicIP = %s, want the pre-swap 198.51.100.10 — a failed rotation must not leave the relay on an address no pack names", got)
	}
	if rec.FloatingIPID != "fip-old" {
		t.Errorf("record.FloatingIPID = %q, want fip-old", rec.FloatingIPID)
	}
	if err := CheckRecordAddressConsistent(rec); err != nil {
		t.Errorf("rollback left the record inconsistent: %v", err)
	}
	// fip-old is NOT released: the rotation failed, so the relay is
	// still living on it.
	for _, id := range prov.releasedIDs {
		if id == "fip-old" {
			t.Error("rollback released the address the relay is still using")
		}
	}
}

// Same shape, one step later: the transaction is what fails. The pack
// exists on disk but was never made active, so the swap must unwind for
// the same reason.
func TestL3_StoreFailureRollsBackTheSwap(t *testing.T) {
	prov := &mockProvider{}
	b := &mockBinder{res: okBinderRes()}
	st := &memStore{insertFails: true}
	clk := &fakeClock{t: time.Unix(1700000000, 0).UTC()}
	exec := newExecutor(prov, b, st, clk)
	rec := newRecord("fip-old")

	if _, err := rotateL3(t, exec, rec, "fip-new"); err == nil {
		t.Fatal("expected the store failure to surface")
	}
	if got := rec.PublicIP.String(); got != "198.51.100.10" {
		t.Errorf("record.PublicIP = %s, want the pre-swap 198.51.100.10", got)
	}
	if rec.FloatingIPID != "fip-old" {
		t.Errorf("record.FloatingIPID = %q, want fip-old", rec.FloatingIPID)
	}
}

// An address the executor minted and could not use is a billing
// resource with no purpose — the same leak class as the orphaned
// provisioning server. It must be handed back on every failure path.
func TestL3_ReservedAddressIsNotLeakedOnFailure(t *testing.T) {
	prov := &mockProvider{releaseOwned: true}
	b := &mockBinder{err: errors.New("nope")}
	st := &memStore{}
	clk := &fakeClock{t: time.Unix(1700000000, 0).UTC()}
	exec := newExecutor(prov, b, st, clk)

	if _, err := rotateL3(t, exec, newRecord(""), ""); err == nil {
		t.Fatal("expected the bind failure to surface")
	}
	if prov.createCalls != 1 {
		t.Fatalf("CreateFloatingIP calls = %d, want 1", prov.createCalls)
	}
	found := false
	for _, id := range prov.releasedIDs {
		if id == "fip-reserved" {
			found = true
		}
	}
	if !found {
		t.Errorf("reserved address was never released; released=%v", prov.releasedIDs)
	}
}

// An assign that fails outright must leave the record untouched — there
// is nothing to unwind on the record, and the relay is still on the
// address its packs name.
func TestL3_AssignFailureLeavesRecordAlone(t *testing.T) {
	prov := &mockProvider{assignFloatErr: errors.New("cloud says no")}
	b := &mockBinder{res: okBinderRes()}
	exec, _, rec := l3Fixture(t, prov, b)

	if _, err := rotateL3(t, exec, rec, "fip-new"); err == nil {
		t.Fatal("expected the assign failure to surface")
	}
	if got := rec.PublicIP.String(); got != "198.51.100.10" {
		t.Errorf("record.PublicIP = %s, want 198.51.100.10", got)
	}
	if rec.FloatingIPID != "fip-old" {
		t.Errorf("record.FloatingIPID = %q, want fip-old", rec.FloatingIPID)
	}
}

// A verifier that says the new address does not answer must abort the
// rotation, not merely warn: signing a pack for an address that does not
// serve is the outage this whole rung exists to avoid.
func TestL3_VerifyReachableFailureAborts(t *testing.T) {
	prov := &mockProvider{}
	b := &mockBinder{res: okBinderRes()}
	exec, st, rec := l3Fixture(t, prov, b)
	exec.VerifyReachable = func(context.Context, *provider.OperatorRecord) error {
		return errors.New("no TCP on 443")
	}

	if _, err := rotateL3(t, exec, rec, "fip-new"); err == nil {
		t.Fatal("expected the reachability failure to surface")
	}
	if b.calls != 0 || st.committed != 0 {
		t.Errorf("bind=%d commit=%d after a failed reachability check; want 0/0", b.calls, st.committed)
	}
	if got := rec.PublicIP.String(); got != "198.51.100.10" {
		t.Errorf("record.PublicIP = %s, want the pre-swap 198.51.100.10", got)
	}
}

// The old address is released only AFTER the history transaction
// commits. Ordering is the whole safety property: until the new pack is
// stored, every already-distributed pack must keep working.
func TestL3_OldAddressReleasedOnlyAfterCommit(t *testing.T) {
	prov := &orderedProvider{mockProvider: &mockProvider{releaseOwned: true}}
	b := &mockBinder{res: okBinderRes()}
	st := &memStore{}
	clk := &fakeClock{t: time.Unix(1700000000, 0).UTC()}
	prov.store = st
	exec := newExecutor(prov, b, st, clk)

	res, err := rotateL3(t, exec, newRecord("fip-old"), "fip-new")
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if !prov.releaseSawCommit {
		t.Error("the previous address was released before the transaction committed — that window strands every distributed pack if the commit then fails")
	}
	if !res.L3.PriorReleased {
		t.Error("L3 outcome does not report the prior address as released")
	}
	if len(res.L3.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", res.L3.Warnings)
	}
}

type orderedProvider struct {
	*mockProvider
	store            *memStore
	releaseSawCommit bool
}

func (o *orderedProvider) ReleaseFloatingIP(ctx context.Context, rec *provider.OperatorRecord, id string) (bool, error) {
	if o.store.committed > 0 {
		o.releaseSawCommit = true
	}
	return o.mockProvider.ReleaseFloatingIP(ctx, rec, id)
}

// An address daal-deploy did not create is detached, not deleted — and
// the operator is told, because it is still on their bill. Silence here
// is how a rotation quietly doubles somebody's address costs.
func TestL3_UnownedPriorAddressIsReportedNotDeleted(t *testing.T) {
	prov := &mockProvider{releaseOwned: false}
	b := &mockBinder{res: okBinderRes()}
	exec, _, rec := l3Fixture(t, prov, b)

	res, err := rotateL3(t, exec, rec, "fip-new")
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if res.L3.PriorReleased {
		t.Error("claimed the prior address was released when the adapter did not delete it")
	}
	if len(res.L3.Warnings) == 0 {
		t.Error("an address left reserved and billing must be reported, not passed over in silence")
	}
}

// checkRecordAddressConsistent is the invariant the swap maintains;
// pin the two ways a record can break it.
func TestCheckRecordAddressConsistent(t *testing.T) {
	rec := newRecord("")
	if err := CheckRecordAddressConsistent(rec); err != nil {
		t.Fatalf("a freshly built record should be consistent: %v", err)
	}
	rec.PublicIP = net.ParseIP("203.0.113.9")
	if err := CheckRecordAddressConsistent(rec); !errors.Is(err, ErrRecordAddressInconsistent) {
		t.Errorf("moving PublicIP alone: err = %v, want ErrRecordAddressInconsistent", err)
	}

	rec = newRecord("")
	rec.Candidates[0].PublicRiskTags = []string{"public_port:tcp443"}
	if err := CheckRecordAddressConsistent(rec); !errors.Is(err, ErrRecordAddressInconsistent) {
		t.Errorf("candidate with no public_ip tag: err = %v, want ErrRecordAddressInconsistent", err)
	}
}
