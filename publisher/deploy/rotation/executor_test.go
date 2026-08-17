package rotation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"testing"
	"time"

	"daal/publisher/deploy/provider"
)

// --- Mocks ----------------------------------------------------------

type mockProvider struct {
	provisionCalls        int
	reprovisionCalls      int
	assignFloatingCalls   int
	unassignFloatingCalls int
	decommissionCalls     int
	pricingCalls          int

	lastReprovisionOpts provider.ReprovisionOpts
	lastAssignedFipID   string

	provisionErr     error
	reprovisionErr   error
	assignFloatErr   error
	unassignFloatErr error

	// addressFor maps a floating-IP id to the address it carries, the
	// way the real cloud API does. A mock that skipped this could not
	// exercise the one thing L3 is for.
	addressFor map[string]net.IP

	// legacyAssign models the PRE-Step-9 adapter (and the Vultr/Stark
	// adapters today): set FloatingIPID, move nothing else. The
	// executor's post-condition must reject it.
	legacyAssign bool

	// reserve/release plumbing for the FloatingIPProvisioner half.
	createCalls  int
	createErr    error
	releaseCalls int
	releasedIDs  []string
	releaseErr   error
	releaseOwned bool
}

func (m *mockProvider) Provision(_ context.Context, _ provider.ProvisionOpts) (*provider.OperatorRecord, error) {
	m.provisionCalls++
	return nil, m.provisionErr
}

func (m *mockProvider) Reprovision(_ context.Context, rec *provider.OperatorRecord, opts provider.ReprovisionOpts) error {
	m.reprovisionCalls++
	m.lastReprovisionOpts = opts
	if m.reprovisionErr == nil && rec != nil {
		// Simulate a successful reprovision touching the record's
		// LastReprovisionedAt slot (the production path mutates this).
		now := time.Now().UTC()
		rec.LastReprovisionedAt = &now
	}
	return m.reprovisionErr
}

func (m *mockProvider) Decommission(_ context.Context, rec *provider.OperatorRecord) (*provider.DecommissionReport, error) {
	m.decommissionCalls++
	rep := provider.NewDecommissionReport("mock", "")
	if rec != nil {
		rep.ServerID = rec.ServerID
	}
	rep.ServerDeleted, rep.SSHKeyDeleted, rep.FirewallDeleted = true, true, true
	return rep, nil
}

// AssignFloatingIP models the FIXED adapter contract: attach, and move
// every copy of the dialled address onto the new one (rec.PublicIP plus
// each candidate's public_ip:* tag). Set legacyAssign to get the broken
// pre-Step-9 behaviour instead.
func (m *mockProvider) AssignFloatingIP(_ context.Context, rec *provider.OperatorRecord, fipID string) error {
	m.assignFloatingCalls++
	m.lastAssignedFipID = fipID
	if m.assignFloatErr != nil || rec == nil {
		return m.assignFloatErr
	}
	rec.FloatingIPID = fipID
	if m.legacyAssign {
		return nil
	}
	ip := m.addressOf(fipID)
	rec.PublicIP = ip
	for i := range rec.Candidates {
		tags := []string{}
		for _, t := range rec.Candidates[i].PublicRiskTags {
			if !hasPublicIPPrefix(t) {
				tags = append(tags, t)
			}
		}
		rec.Candidates[i].PublicRiskTags = append(tags, "public_ip:"+ip.String())
	}
	return nil
}

func (m *mockProvider) addressOf(fipID string) net.IP {
	if ip, ok := m.addressFor[fipID]; ok {
		return ip
	}
	// Deterministic synthetic address so every id maps to a distinct,
	// stable value without every test having to populate the map.
	sum := 0
	for _, b := range []byte(fipID) {
		sum = (sum + int(b)) % 250
	}
	return net.IPv4(203, 0, 113, byte(sum+1))
}

func hasPublicIPPrefix(t string) bool {
	return len(t) >= len("public_ip:") && t[:len("public_ip:")] == "public_ip:"
}

func (m *mockProvider) UnassignFloatingIP(_ context.Context, rec *provider.OperatorRecord) error {
	m.unassignFloatingCalls++
	if m.unassignFloatErr == nil && rec != nil {
		rec.FloatingIPID = ""
	}
	return m.unassignFloatErr
}

// CreateFloatingIP / ReleaseFloatingIP make the mock a
// FloatingIPProvisioner, which is what lets an L3 run without the
// operator having reserved an address by hand.
func (m *mockProvider) CreateFloatingIP(_ context.Context, _ *provider.OperatorRecord) (string, net.IP, error) {
	m.createCalls++
	if m.createErr != nil {
		return "", nil, m.createErr
	}
	id := "fip-reserved"
	return id, m.addressOf(id), nil
}

func (m *mockProvider) ReleaseFloatingIP(_ context.Context, _ *provider.OperatorRecord, id string) (bool, error) {
	m.releaseCalls++
	m.releasedIDs = append(m.releasedIDs, id)
	if m.releaseErr != nil {
		return false, m.releaseErr
	}
	return m.releaseOwned, nil
}

func (m *mockProvider) Pricing(_ context.Context, _ *provider.OperatorRecord) (provider.Pricing, error) {
	m.pricingCalls++
	return provider.Pricing{}, nil
}

// FRP-10: SetEphemeralFirewallRule / RemoveEphemeralFirewallRule
// are no-ops on this V1.5/V1.6 rotation-test mock; the rotation
// executor only invokes them on the V2 fast path.
func (m *mockProvider) SetEphemeralFirewallRule(_ context.Context, serverID, callerIP string, port int, durationSec int) (*provider.EphemeralFirewallRule, error) {
	return &provider.EphemeralFirewallRule{ID: "mock-eph-rule", ServerID: serverID, CallerIP: callerIP, Port: port}, nil
}

func (m *mockProvider) RemoveEphemeralFirewallRule(_ context.Context, _ *provider.EphemeralFirewallRule) error {
	return nil
}

// mockBinder captures inputs and returns canned bytes.
type mockBinder struct {
	calls   int
	lastNow time.Time
	err     error
	res     BinderResult
}

func (m *mockBinder) Bind(_ *provider.OperatorRecord, _ ed25519.PrivateKey, now time.Time) (BinderResult, error) {
	m.calls++
	m.lastNow = now
	if m.err != nil {
		return BinderResult{}, m.err
	}
	return m.res, nil
}

// memTx + memStore are an in-memory implementation of the
// SBPStore/SBPTx contract suitable for unit tests.
type memStore struct {
	rows        []SignedSBP
	beginErr    error
	beginCalls  int
	commitFails bool
	insertFails bool
	markFails   bool
	updateFails bool
	rolledBack  int
	committed   int
}

func (s *memStore) Begin() (SBPTx, error) {
	s.beginCalls++
	if s.beginErr != nil {
		return nil, s.beginErr
	}
	return &memTx{store: s}, nil
}

type memTx struct {
	store    *memStore
	pending  []SignedSBP
	priorOps []int64
	closed   bool
}

func (t *memTx) MarkPriorInactive(operatorID int64) error {
	if t.store.markFails {
		return errors.New("inject mark fail")
	}
	t.priorOps = append(t.priorOps, operatorID)
	return nil
}

func (t *memTx) InsertActive(row SignedSBP) error {
	if t.store.insertFails {
		return errors.New("inject insert fail")
	}
	t.pending = append(t.pending, row)
	return nil
}

func (t *memTx) UpdateOperatorActiveProjection(_ int64, _ SignedSBP) error {
	if t.store.updateFails {
		return errors.New("inject update fail")
	}
	return nil
}

func (t *memTx) Commit() error {
	if t.closed {
		return errors.New("double commit")
	}
	if t.store.commitFails {
		// SQLite: a failed Commit leaves the tx open so Rollback
		// can be called. Mirror that behaviour here.
		return errors.New("inject commit fail")
	}
	t.closed = true
	for i := range t.store.rows {
		for _, op := range t.priorOps {
			if t.store.rows[i].OperatorID == op {
				t.store.rows[i].Active = false
			}
		}
	}
	t.store.rows = append(t.store.rows, t.pending...)
	t.store.committed++
	return nil
}

func (t *memTx) Rollback() error {
	if t.closed {
		return nil
	}
	t.closed = true
	t.store.rolledBack++
	return nil
}

// fakeClock advances by stepping on .Tick() — used to pin L3 budget.
type fakeClock struct {
	t time.Time
}

func (c *fakeClock) Now() time.Time                  { return c.t }
func (c *fakeClock) Since(t time.Time) time.Duration { return c.t.Sub(t) }
func (c *fakeClock) Tick(d time.Duration)            { c.t = c.t.Add(d) }

// --- helpers --------------------------------------------------------

func newPriv(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func newExecutor(prov provider.Provider, b *mockBinder, st *memStore, clk Clock) *Executor {
	return &Executor{
		Provider: prov,
		Binder:   b,
		Store:    st,
		WriteSBP: func(_ *provider.OperatorRecord, _ []byte, _ time.Time) (string, error) {
			return "/tmp/test/relay.sbp", nil
		},
		Clock: clk,
	}
}

func newRecord(withFipID string) *provider.OperatorRecord {
	rec := &provider.OperatorRecord{
		Provider:        "hetzner",
		ServerID:        "srv-1",
		ServerType:      "cpx21",
		Region:          "fsn1",
		PublicIP:        net.ParseIP("198.51.100.10"),
		PublisherPubKey: []byte("placeholder"),
		// Candidates carry the SECOND copy of the dialled address.
		// Every L3 test needs them present, because a swap that moves
		// rec.PublicIP and leaves these behind is exactly the
		// half-applied state that signs a self-contradicting pack.
		Candidates: []provider.CandidateMeta{
			{Family: "vless-reality", Port: 443,
				PublicRiskTags: []string{"public_ip:198.51.100.10", "public_port:tcp443"}},
			{Family: "hysteria2", Port: 443,
				PublicRiskTags: []string{"public_ip:198.51.100.10", "public_port:udp443"}},
		},
	}
	if withFipID != "" {
		rec.FloatingIPID = withFipID
	}
	return rec
}

func okBinderRes() BinderResult {
	return BinderResult{
		SBPBytes:     []byte("signed bytes"),
		BundleSHA256: "deadbeef",
		RelayPackID:  "rp-1",
		RouteCount:   3,
	}
}

// --- Tests: happy paths --------------------------------------------

func TestRotate_L3_FastPath_Succeeds(t *testing.T) {
	prov := &mockProvider{}
	b := &mockBinder{res: okBinderRes()}
	st := &memStore{}
	clk := &fakeClock{t: time.Unix(1700000000, 0).UTC()}

	exec := newExecutor(prov, b, st, clk)
	rec := newRecord("fip-old")

	res, err := exec.Rotate(context.Background(), &RotateRequest{
		OperatorID:      42,
		Record:          rec,
		PrivKey:         newPriv(t),
		Recommendation:  RotationRecommendation{Level: L3, EstWallClock: "~10s"},
		NewFloatingIPID: "fip-new",
	})
	if err != nil {
		t.Fatalf("Rotate L3: %v", err)
	}
	if prov.assignFloatingCalls != 1 {
		t.Errorf("AssignFloatingIP calls = %d, want 1", prov.assignFloatingCalls)
	}
	// The prior address is given back exactly once, and only through
	// the post-commit release leg. A pre-swap UnassignFloatingIP would
	// take the relay off the address every distributed pack names
	// BEFORE the replacement is proven — the window this ordering
	// exists to close.
	if prov.unassignFloatingCalls != 0 {
		t.Errorf("UnassignFloatingIP calls = %d, want 0 (the old address is released after the commit, not detached before the swap)", prov.unassignFloatingCalls)
	}
	if len(prov.releasedIDs) != 1 || prov.releasedIDs[0] != "fip-old" {
		t.Errorf("released = %v, want exactly [fip-old]", prov.releasedIDs)
	}
	if prov.reprovisionCalls != 0 {
		t.Errorf("Reprovision calls = %d, want 0 (L3 must NOT call Reprovision)", prov.reprovisionCalls)
	}
	if b.calls != 1 {
		t.Errorf("Bind calls = %d, want 1", b.calls)
	}
	if st.committed != 1 {
		t.Errorf("commits = %d, want 1", st.committed)
	}
	if len(st.rows) != 1 {
		t.Errorf("rows = %d, want 1", len(st.rows))
	}
	if !st.rows[0].Active {
		t.Errorf("inserted row Active=false; want true")
	}
	if res.SignedSBP.OperatorID != 42 {
		t.Errorf("res.OperatorID = %d, want 42", res.SignedSBP.OperatorID)
	}
	if st.rows[0].OperatorID != 42 {
		t.Errorf("stored OperatorID = %d, want 42", st.rows[0].OperatorID)
	}
	if res.SignedSBP.RelayPackID != "rp-1" {
		t.Errorf("res.RelayPackID = %s, want rp-1", res.SignedSBP.RelayPackID)
	}
	if rec.FloatingIPID != "fip-new" {
		t.Errorf("record.FloatingIPID = %s, want fip-new", rec.FloatingIPID)
	}
	// THE POINT OF THE WHOLE RUNG: the address recipients dial moved,
	// in both places the record keeps it.
	want := prov.addressOf("fip-new").String()
	if rec.PublicIP.String() != want {
		t.Errorf("record.PublicIP = %s, want %s — an L3 that leaves the burned address in place is a rotation that rotates nothing", rec.PublicIP, want)
	}
	if err := CheckRecordAddressConsistent(rec); err != nil {
		t.Errorf("record left inconsistent after L3: %v", err)
	}
	if res.L3.NewFloatingIPID != "fip-new" || res.L3.PriorFloatingIPID != "fip-old" {
		t.Errorf("L3 outcome = %+v", res.L3)
	}
}

func TestRotate_L1_CallsReprovisionWithRegenCredentials(t *testing.T) {
	prov := &mockProvider{}
	b := &mockBinder{res: okBinderRes()}
	st := &memStore{}
	clk := &fakeClock{t: time.Unix(1700000000, 0).UTC()}

	exec := newExecutor(prov, b, st, clk)

	_, err := exec.Rotate(context.Background(), &RotateRequest{
		Record:          newRecord(""),
		PrivKey:         newPriv(t),
		Recommendation:  RotationRecommendation{Level: L1},
		ReprovisionOpts: provider.ReprovisionOpts{RegenCredentials: true},
	})
	if err != nil {
		t.Fatalf("Rotate L1: %v", err)
	}
	if prov.reprovisionCalls != 1 {
		t.Errorf("Reprovision calls = %d, want 1", prov.reprovisionCalls)
	}
	if !prov.lastReprovisionOpts.RegenCredentials {
		t.Errorf("ReprovisionOpts.RegenCredentials = false, want true")
	}
	if prov.assignFloatingCalls != 0 {
		t.Errorf("L1 must not touch floating IP; calls = %d", prov.assignFloatingCalls)
	}
}

func TestRotate_L2_PassesNewSNIAndWSPath(t *testing.T) {
	prov := &mockProvider{}
	b := &mockBinder{res: okBinderRes()}
	st := &memStore{}
	clk := &fakeClock{t: time.Unix(1700000000, 0).UTC()}

	exec := newExecutor(prov, b, st, clk)

	_, err := exec.Rotate(context.Background(), &RotateRequest{
		Record:         newRecord(""),
		PrivKey:        newPriv(t),
		Recommendation: RotationRecommendation{Level: L2},
		ReprovisionOpts: provider.ReprovisionOpts{
			NewSNI:    "discuss.gnome.org",
			NewWSPath: "/api/v1/socket",
		},
	})
	if err != nil {
		t.Fatalf("Rotate L2: %v", err)
	}
	if prov.lastReprovisionOpts.NewSNI != "discuss.gnome.org" {
		t.Errorf("NewSNI = %q", prov.lastReprovisionOpts.NewSNI)
	}
	if prov.lastReprovisionOpts.NewWSPath != "/api/v1/socket" {
		t.Errorf("NewWSPath = %q", prov.lastReprovisionOpts.NewWSPath)
	}
}

func TestRotate_L4_L5_L6_AllUseReprovision(t *testing.T) {
	for _, level := range []Level{L4, L5, L6} {
		level := level
		t.Run(string(level), func(t *testing.T) {
			prov := &mockProvider{}
			b := &mockBinder{res: okBinderRes()}
			st := &memStore{}
			clk := &fakeClock{t: time.Unix(1700000000, 0).UTC()}
			exec := newExecutor(prov, b, st, clk)

			_, err := exec.Rotate(context.Background(), &RotateRequest{
				Record:         newRecord(""),
				PrivKey:        newPriv(t),
				Recommendation: RotationRecommendation{Level: level},
				ReprovisionOpts: provider.ReprovisionOpts{
					NewToolboxProfile: "tcp-only-vps-native",
				},
			})
			if err != nil {
				t.Fatalf("Rotate %s: %v", level, err)
			}
			if prov.reprovisionCalls != 1 {
				t.Errorf("%s reprovision calls = %d, want 1", level, prov.reprovisionCalls)
			}
			if prov.lastReprovisionOpts.NewToolboxProfile != "tcp-only-vps-native" {
				t.Errorf("%s NewToolboxProfile lost: %q", level, prov.lastReprovisionOpts.NewToolboxProfile)
			}
		})
	}
}

// --- Tests: error paths --------------------------------------------

func TestRotate_ProviderFailure_NoTransactionOpened(t *testing.T) {
	prov := &mockProvider{reprovisionErr: errors.New("hetzner 503")}
	b := &mockBinder{}
	st := &memStore{}
	clk := &fakeClock{t: time.Unix(1700000000, 0).UTC()}
	exec := newExecutor(prov, b, st, clk)

	_, err := exec.Rotate(context.Background(), &RotateRequest{
		Record:         newRecord(""),
		PrivKey:        newPriv(t),
		Recommendation: RotationRecommendation{Level: L4},
	})
	if err == nil {
		t.Fatal("expected provider error")
	}
	if st.beginCalls != 0 {
		t.Errorf("Store.Begin called despite provider failure: %d", st.beginCalls)
	}
	if b.calls != 0 {
		t.Errorf("Bind called despite provider failure: %d", b.calls)
	}
}

func TestRotate_BinderFailure_NoTransactionOpened(t *testing.T) {
	prov := &mockProvider{}
	b := &mockBinder{err: errors.New("validate RP018")}
	st := &memStore{}
	clk := &fakeClock{t: time.Unix(1700000000, 0).UTC()}
	exec := newExecutor(prov, b, st, clk)

	_, err := exec.Rotate(context.Background(), &RotateRequest{
		Record:         newRecord(""),
		PrivKey:        newPriv(t),
		Recommendation: RotationRecommendation{Level: L4},
	})
	if err == nil {
		t.Fatal("expected binder error")
	}
	if st.beginCalls != 0 {
		t.Errorf("Store.Begin called despite binder failure: %d", st.beginCalls)
	}
}

func TestRotate_StoreCommitFailure_RollsBack(t *testing.T) {
	prov := &mockProvider{}
	b := &mockBinder{res: okBinderRes()}
	st := &memStore{commitFails: true}
	clk := &fakeClock{t: time.Unix(1700000000, 0).UTC()}
	exec := newExecutor(prov, b, st, clk)

	_, err := exec.Rotate(context.Background(), &RotateRequest{
		Record:         newRecord(""),
		PrivKey:        newPriv(t),
		Recommendation: RotationRecommendation{Level: L4},
	})
	if err == nil {
		t.Fatal("expected commit error")
	}
	if st.rolledBack != 1 {
		t.Errorf("rollbacks = %d, want 1", st.rolledBack)
	}
	if len(st.rows) != 0 {
		t.Errorf("rows persisted despite commit failure: %d", len(st.rows))
	}
}

func TestRotate_StoreInsertFailure_RollsBack(t *testing.T) {
	prov := &mockProvider{}
	b := &mockBinder{res: okBinderRes()}
	st := &memStore{insertFails: true}
	clk := &fakeClock{t: time.Unix(1700000000, 0).UTC()}
	exec := newExecutor(prov, b, st, clk)

	_, err := exec.Rotate(context.Background(), &RotateRequest{
		Record:         newRecord(""),
		PrivKey:        newPriv(t),
		Recommendation: RotationRecommendation{Level: L4},
	})
	if err == nil {
		t.Fatal("expected insert error")
	}
	if st.rolledBack != 1 {
		t.Errorf("rollbacks = %d, want 1", st.rolledBack)
	}
}

// An empty NewFloatingIPID used to be a hard error, which meant the
// rung could only be climbed by an operator who had reserved an address
// by hand in the provider console and knew its numeric id. Now the
// executor reserves one.
func TestRotate_L3_WithoutFipIDReservesOne(t *testing.T) {
	prov := &mockProvider{}
	b := &mockBinder{res: okBinderRes()}
	st := &memStore{}
	clk := &fakeClock{t: time.Unix(1700000000, 0).UTC()}
	exec := newExecutor(prov, b, st, clk)
	rec := newRecord("")

	res, err := exec.Rotate(context.Background(), &RotateRequest{
		Record:         rec,
		PrivKey:        newPriv(t),
		Recommendation: RotationRecommendation{Level: L3},
		// NewFloatingIPID empty
	})
	if err != nil {
		t.Fatalf("Rotate L3 without a supplied address: %v", err)
	}
	if prov.createCalls != 1 {
		t.Errorf("CreateFloatingIP calls = %d, want 1", prov.createCalls)
	}
	if rec.FloatingIPID != "fip-reserved" {
		t.Errorf("record.FloatingIPID = %q, want fip-reserved", rec.FloatingIPID)
	}
	if !res.L3.ReservedHere {
		t.Error("L3 outcome does not record that the executor reserved the address")
	}
	// The relay was on its server's primary address, so there is no
	// prior floating IP to hand back.
	if len(prov.releasedIDs) != 0 {
		t.Errorf("released = %v, want nothing", prov.releasedIDs)
	}
}

// A provider that cannot mint an address must say so, not fail with a
// message about a missing input the operator has no way to produce.
func TestRotate_L3_NoAddressSourceIsNamed(t *testing.T) {
	prov := &noReserveProvider{mockProvider: &mockProvider{}}
	b := &mockBinder{res: okBinderRes()}
	st := &memStore{}
	clk := &fakeClock{t: time.Unix(1700000000, 0).UTC()}
	exec := newExecutor(prov, b, st, clk)

	_, err := exec.Rotate(context.Background(), &RotateRequest{
		Record:         newRecord(""),
		PrivKey:        newPriv(t),
		Recommendation: RotationRecommendation{Level: L3},
	})
	if !errors.Is(err, ErrL3NoAddressSource) {
		t.Fatalf("err = %v, want ErrL3NoAddressSource", err)
	}
	if prov.assignFloatingCalls != 0 {
		t.Errorf("AssignFloatingIP called: %d", prov.assignFloatingCalls)
	}
}

// noReserveProvider is a provider.Provider that is NOT a
// FloatingIPProvisioner — the Vultr/Stark shape. Embedding by value
// (not by pointer to a type that has the methods) is what keeps the
// optional interface unsatisfied.
type noReserveProvider struct {
	*mockProvider
}

// CreateFloatingIP deliberately has the WRONG signature, so
// noReserveProvider does not satisfy FloatingIPProvisioner even though
// it embeds a type that does.
func (n *noReserveProvider) CreateFloatingIP() {}

// ReleaseFloatingIP likewise.
func (n *noReserveProvider) ReleaseFloatingIP() {}

func TestRotate_NilRequestRejected(t *testing.T) {
	prov := &mockProvider{}
	b := &mockBinder{}
	st := &memStore{}
	clk := &fakeClock{t: time.Unix(1700000000, 0).UTC()}
	exec := newExecutor(prov, b, st, clk)
	if _, err := exec.Rotate(context.Background(), nil); err == nil {
		t.Fatal("expected ErrNilRequest")
	}
}

func TestRotate_IncompleteExecutorRejected(t *testing.T) {
	exec := &Executor{} // all zero
	_, err := exec.Rotate(context.Background(), &RotateRequest{
		Record:         newRecord(""),
		PrivKey:        newPriv(t),
		Recommendation: RotationRecommendation{Level: L4},
	})
	if err == nil {
		t.Fatal("expected ErrExecutorIncomplete")
	}
}

// --- L3 wall-clock pin (the soak rig invariant) --------------------

func TestRotate_L3_WallClockBudgetPin(t *testing.T) {
	prov := &mockProvider{}
	b := &mockBinder{res: okBinderRes()}
	st := &memStore{}

	t0 := time.Unix(1700000000, 0).UTC()
	clk := &fakeClock{t: t0}

	// We need the clock to advance during the call. Wrap the
	// AssignFloatingIP mock to tick the clock past the budget.
	prov.assignFloatErr = nil

	// Replace the Provider mock with one that ticks the clock.
	tickingProv := &tickingProvider{base: prov, clock: clk, tick: 16 * time.Second}

	exec := newExecutor(prov, b, st, clk)
	exec.Provider = tickingProv
	rec := newRecord("fip-old")

	_, err := exec.Rotate(context.Background(), &RotateRequest{
		Record:          rec,
		PrivKey:         newPriv(t),
		Recommendation:  RotationRecommendation{Level: L3},
		NewFloatingIPID: "fip-new",
	})
	if err == nil {
		t.Fatal("expected ErrL3WallClockBudget")
	}
	if !errors.Is(err, ErrL3WallClockBudget) {
		t.Errorf("err = %v, want ErrL3WallClockBudget", err)
	}
	// A budget miss is a FAILED rotation, so it unwinds like every
	// other pre-commit failure. Leaving the relay on an address that
	// no committed pack names would turn a slow rotation into an
	// outage.
	if got := rec.PublicIP.String(); got != "198.51.100.10" {
		t.Errorf("record.PublicIP = %s, want the pre-swap 198.51.100.10 after a budget miss", got)
	}
	if rec.FloatingIPID != "fip-old" {
		t.Errorf("record.FloatingIPID = %q, want the pre-swap fip-old after a budget miss", rec.FloatingIPID)
	}
	if st.committed != 0 {
		t.Errorf("commits = %d, want 0 on budget failure", st.committed)
	}
	if len(st.rows) != 0 {
		t.Errorf("rows persisted despite L3 budget failure: %d", len(st.rows))
	}
}

func TestRotate_L3_FastPathWithinBudget(t *testing.T) {
	prov := &mockProvider{}
	b := &mockBinder{res: okBinderRes()}
	st := &memStore{}

	t0 := time.Unix(1700000000, 0).UTC()
	clk := &fakeClock{t: t0}
	// L3 calls Unassign + Assign, so 2× tick. 5s × 2 = 10s < 15s.
	tickingProv := &tickingProvider{base: prov, clock: clk, tick: 5 * time.Second}

	exec := newExecutor(prov, b, st, clk)
	exec.Provider = tickingProv

	res, err := exec.Rotate(context.Background(), &RotateRequest{
		Record:          newRecord("fip-old"),
		PrivKey:         newPriv(t),
		Recommendation:  RotationRecommendation{Level: L3},
		NewFloatingIPID: "fip-new",
	})
	if err != nil {
		t.Fatalf("L3 within budget: %v", err)
	}
	if res.WallClock >= L3FastPathBudget {
		t.Errorf("wallclock = %s, want < %s", res.WallClock, L3FastPathBudget)
	}
}

// tickingProvider wraps a mockProvider and advances the fakeClock
// once per Provider call, simulating real wall-clock progress.
type tickingProvider struct {
	base  *mockProvider
	clock *fakeClock
	tick  time.Duration
}

func (p *tickingProvider) Provision(ctx context.Context, opts provider.ProvisionOpts) (*provider.OperatorRecord, error) {
	p.clock.Tick(p.tick)
	return p.base.Provision(ctx, opts)
}

func (p *tickingProvider) Reprovision(ctx context.Context, rec *provider.OperatorRecord, opts provider.ReprovisionOpts) error {
	p.clock.Tick(p.tick)
	return p.base.Reprovision(ctx, rec, opts)
}

func (p *tickingProvider) Decommission(ctx context.Context, rec *provider.OperatorRecord) (*provider.DecommissionReport, error) {
	p.clock.Tick(p.tick)
	return p.base.Decommission(ctx, rec)
}

func (p *tickingProvider) AssignFloatingIP(ctx context.Context, rec *provider.OperatorRecord, fipID string) error {
	p.clock.Tick(p.tick)
	return p.base.AssignFloatingIP(ctx, rec, fipID)
}

func (p *tickingProvider) UnassignFloatingIP(ctx context.Context, rec *provider.OperatorRecord) error {
	p.clock.Tick(p.tick)
	return p.base.UnassignFloatingIP(ctx, rec)
}

func (p *tickingProvider) Pricing(ctx context.Context, rec *provider.OperatorRecord) (provider.Pricing, error) {
	return p.base.Pricing(ctx, rec)
}

// FRP-10: ephemeral firewall rule pass-through (no tick — these
// methods are V2 mgmt-plane only and not exercised by the V1.5
// rotation executor tests).
func (p *tickingProvider) SetEphemeralFirewallRule(ctx context.Context, serverID, callerIP string, port int, durationSec int) (*provider.EphemeralFirewallRule, error) {
	return p.base.SetEphemeralFirewallRule(ctx, serverID, callerIP, port, durationSec)
}

func (p *tickingProvider) RemoveEphemeralFirewallRule(ctx context.Context, rule *provider.EphemeralFirewallRule) error {
	return p.base.RemoveEphemeralFirewallRule(ctx, rule)
}

// --- Revert --------------------------------------------------------

func TestRevert_RestoresPreviousRow(t *testing.T) {
	st := &memStore{}
	clk := &fakeClock{t: time.Unix(1700000000, 0).UTC()}
	exec := newExecutor(&mockProvider{}, &mockBinder{}, st, clk)

	prior := SignedSBP{
		OperatorID:   42,
		SignedAtUnix: 1690000000,
		SBPPath:      "/staging/sbp-old.sbp",
		SBPSHA256:    "cafef00d",
		RelayPackID:  "rp-old",
		RouteCount:   2,
	}
	if err := exec.Revert(context.Background(), prior); err != nil {
		t.Fatalf("Revert: %v", err)
	}
	if st.committed != 1 {
		t.Errorf("commits = %d, want 1", st.committed)
	}
	if len(st.rows) != 1 || !st.rows[0].Active || st.rows[0].RelayPackID != "rp-old" {
		t.Errorf("revert state mismatch: %+v", st.rows)
	}
}

// --- Recommender → executor end-to-end (smoke) ---------------------

func TestRecommendThenRotate_E2E(t *testing.T) {
	exp := Explanation{
		Pick: ExplPicked{ExposureMode: "direct_vps"},
		Failures: []ExplFailure{
			{Classification: "tcp_reset", Tag: "public_ip:198.51.100.10"},
		},
		ActiveCooldowns: []ExplCooldown{
			{Tag: "public_ip:198.51.100.10", Reason: "tcp_reset"},
		},
		Phase: currentPhase,
	}
	rec := newRecord("fip-old")
	r := FromExplanation(exp, rec)
	if r.Level != L3 {
		t.Fatalf("recommender = %s, want L3", r.Level)
	}

	prov := &mockProvider{}
	b := &mockBinder{res: okBinderRes()}
	st := &memStore{}
	clk := &fakeClock{t: time.Unix(1700000000, 0).UTC()}
	exec := newExecutor(prov, b, st, clk)

	res, err := exec.Rotate(context.Background(), &RotateRequest{
		Record:          rec,
		PrivKey:         newPriv(t),
		Recommendation:  r,
		NewFloatingIPID: "fip-new",
	})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if !res.SignedSBP.Active {
		t.Errorf("post-rotate row not Active")
	}
}
