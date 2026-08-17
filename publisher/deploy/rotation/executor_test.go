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

func (m *mockProvider) AssignFloatingIP(_ context.Context, rec *provider.OperatorRecord, fipID string) error {
	m.assignFloatingCalls++
	m.lastAssignedFipID = fipID
	if m.assignFloatErr == nil && rec != nil {
		rec.FloatingIPID = fipID
	}
	return m.assignFloatErr
}

func (m *mockProvider) UnassignFloatingIP(_ context.Context, rec *provider.OperatorRecord) error {
	m.unassignFloatingCalls++
	if m.unassignFloatErr == nil && rec != nil {
		rec.FloatingIPID = ""
	}
	return m.unassignFloatErr
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

func newExecutor(prov *mockProvider, b *mockBinder, st *memStore, clk Clock) *Executor {
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
	if prov.unassignFloatingCalls != 1 {
		t.Errorf("UnassignFloatingIP calls = %d, want 1", prov.unassignFloatingCalls)
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

func TestRotate_L3_RequiresFipID(t *testing.T) {
	prov := &mockProvider{}
	b := &mockBinder{res: okBinderRes()}
	st := &memStore{}
	clk := &fakeClock{t: time.Unix(1700000000, 0).UTC()}
	exec := newExecutor(prov, b, st, clk)

	_, err := exec.Rotate(context.Background(), &RotateRequest{
		Record:         newRecord(""),
		PrivKey:        newPriv(t),
		Recommendation: RotationRecommendation{Level: L3},
		// NewFloatingIPID empty
	})
	if err == nil {
		t.Fatal("expected ErrL3MissingFipID")
	}
	if prov.assignFloatingCalls != 0 {
		t.Errorf("AssignFloatingIP called: %d", prov.assignFloatingCalls)
	}
}

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

	_, err := exec.Rotate(context.Background(), &RotateRequest{
		Record:          newRecord("fip-old"),
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
		Phase: "V1.5",
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
