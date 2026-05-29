package vultr

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"daal/publisher/deploy/provider"
)

// fakeClient is an in-memory vultrClient for unit tests.
type fakeClient struct {
	mu             sync.Mutex
	instances      map[string]*InstanceInfo
	sshKeys        map[string][]byte
	idCount        int64
	priceM         map[string]struct{ hourly, monthly float64 }
	floating       map[string]string
	ephemeralRules map[string]ephemeralRuleEntry
}

type ephemeralRuleEntry struct {
	InstanceID string
	CallerIP   string
	Port       int
	ExpiresAt  time.Time
}

func newFake() *fakeClient {
	return &fakeClient{
		instances: map[string]*InstanceInfo{},
		sshKeys:   map[string][]byte{},
		priceM:    map[string]struct{ hourly, monthly float64 }{"fra/vc2-1c-1gb": {0.007, 5.00}},
		floating:  map[string]string{},
	}
}

func (f *fakeClient) InstanceCreate(_ context.Context, opts InstanceCreateOpts) (*InstanceInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.instances {
		if s.Label == opts.Label {
			return nil, errors.New("instance with same label already exists")
		}
	}
	f.idCount++
	id := strconv.FormatInt(f.idCount, 10)
	s := &InstanceInfo{
		ID: id, Label: opts.Label, Status: "active",
		Plan: opts.Plan, Region: opts.Region,
		MainIP: net.ParseIP("78.141.0." + id),
		Tags:   opts.Tags,
	}
	f.instances[id] = s
	return s, nil
}

func (f *fakeClient) InstanceByID(_ context.Context, id string) (*InstanceInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.instances[id]; ok {
		return s, nil
	}
	return nil, errInstanceNotFound
}

func (f *fakeClient) InstanceByLabel(_ context.Context, label string) (*InstanceInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.instances {
		if s.Label == label {
			return s, nil
		}
	}
	return nil, errInstanceNotFound
}

func (f *fakeClient) InstanceDelete(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.instances, id)
	return nil
}

func (f *fakeClient) PlanPrice(_ context.Context, region, plan string) (float64, float64, error) {
	if p, ok := f.priceM[region+"/"+plan]; ok {
		return p.hourly, p.monthly, nil
	}
	return 0, 0, errors.New("no pricing")
}

func (f *fakeClient) SSHKeyCreate(_ context.Context, name string, publicKey []byte) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.idCount++
	id := strconv.FormatInt(f.idCount, 10)
	f.sshKeys[id] = publicKey
	_ = name
	return id, nil
}

func (f *fakeClient) SSHKeyDelete(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.sshKeys, id)
	return nil
}

func (f *fakeClient) ReservedIPAttach(_ context.Context, ipID, instanceID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.floating[ipID] = instanceID
	return nil
}

func (f *fakeClient) ReservedIPDetach(_ context.Context, ipID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.floating, ipID)
	return nil
}

func (f *fakeClient) FirewallAddEphemeralRule(_ context.Context, instanceID, callerIP string, port int, expiresAt time.Time) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ephemeralRules == nil {
		f.ephemeralRules = map[string]ephemeralRuleEntry{}
	}
	id := "vultr-eph-" + instanceID + "-" + callerIP + "-" + strconv.Itoa(port) + "-" + strconv.FormatInt(expiresAt.Unix(), 10)
	f.ephemeralRules[id] = ephemeralRuleEntry{InstanceID: instanceID, CallerIP: callerIP, Port: port, ExpiresAt: expiresAt}
	return id, nil
}

func (f *fakeClient) FirewallRemoveEphemeralRule(_ context.Context, ruleID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.ephemeralRules, ruleID)
	return nil
}

// --- helpers ---

func mkOpts() provider.ProvisionOpts {
	pub, priv, _ := ed25519.GenerateKey(nil)
	return provider.ProvisionOpts{
		PublisherPubKey: pub,
		Region:          "fra",
		ServerType:      "vc2-1c-1gb",
		ToolboxProfile:  "iran-default",
		HelperIP:        net.ParseIP("1.2.3.4"),
		EphemeralSSHKey: priv,
		DryRun:          true,
	}
}

// --- tests ---

func TestProvision_DryRunReturnsSyntheticRecord(t *testing.T) {
	p := New(newFake())
	rec, err := p.Provision(context.Background(), mkOpts())
	if err != nil {
		t.Fatal(err)
	}
	if rec.Provider != "vultr" {
		t.Errorf("Provider = %q want vultr", rec.Provider)
	}
	if rec.Region != "fra" {
		t.Errorf("Region = %q want fra", rec.Region)
	}
	for _, c := range rec.Candidates {
		if c.ExposureMode != "direct_vps" {
			t.Errorf("V1.5 invariant: candidate %s has exposure_mode=%q", c.Family, c.ExposureMode)
		}
		if len(c.OriginRiskTags) != 0 {
			t.Errorf("V1.5 invariant: candidate %s has origin tags", c.Family)
		}
	}
}

func TestProvision_RejectsMissingFields(t *testing.T) {
	p := New(newFake())
	cases := []struct {
		name string
		mut  func(*provider.ProvisionOpts)
	}{
		{"no-pubkey", func(o *provider.ProvisionOpts) { o.PublisherPubKey = nil }},
		{"no-region", func(o *provider.ProvisionOpts) { o.Region = "" }},
		{"no-server-type", func(o *provider.ProvisionOpts) { o.ServerType = "" }},
		{"no-toolbox", func(o *provider.ProvisionOpts) { o.ToolboxProfile = "" }},
		{"no-helper-ip", func(o *provider.ProvisionOpts) { o.HelperIP = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := mkOpts()
			tc.mut(&opts)
			if _, err := p.Provision(context.Background(), opts); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}

func TestProvision_TwiceIsIdempotent(t *testing.T) {
	p := New(newFake())
	opts := mkOpts()
	r1, err := p.Provision(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := p.Provision(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if r1.ServerID != r2.ServerID {
		t.Errorf("dry-run Provision must be deterministic; got %s vs %s", r1.ServerID, r2.ServerID)
	}
}

func TestProvision_ExistingInstanceRequiresPersistedMgmtPort(t *testing.T) {
	p := New(newFake())
	opts := mkOpts()
	opts.DryRun = false
	opts.MgmtPort = 42424
	if _, err := p.Provision(context.Background(), opts); err != nil {
		t.Fatalf("initial Provision: %v", err)
	}

	retry := opts
	retry.MgmtPort = 0
	if _, err := p.Provision(context.Background(), retry); err == nil {
		t.Fatal("expected existing instance retry without persisted MgmtPort to fail")
	}

	retry.MgmtPort = 42424
	rec, err := p.Provision(context.Background(), retry)
	if err != nil {
		t.Fatalf("retry with persisted MgmtPort: %v", err)
	}
	if rec.MgmtPort != 42424 {
		t.Fatalf("MgmtPort = %d, want 42424", rec.MgmtPort)
	}
}

func TestDecommission_AbsentIsNoOp(t *testing.T) {
	p := New(newFake())
	if err := p.Decommission(context.Background(), &provider.OperatorRecord{ServerID: "9999"}); err != nil {
		t.Errorf("Decommission of absent must be nil; got %v", err)
	}
	if err := p.Decommission(context.Background(), nil); err != nil {
		t.Errorf("Decommission(nil) must be nil; got %v", err)
	}
}

func TestAssignFloatingIP_SameIDIsNoOp(t *testing.T) {
	f := newFake()
	p := New(f)
	rec := &provider.OperatorRecord{ServerID: "1", FloatingIPID: "rip-100"}
	if err := p.AssignFloatingIP(context.Background(), rec, "rip-100"); err != nil {
		t.Errorf("idempotent assign must be nil; got %v", err)
	}
	if len(f.floating) != 0 {
		t.Errorf("idempotent path must not call API")
	}
}

func TestAssignFloatingIP_NewIDUpdatesRecord(t *testing.T) {
	f := newFake()
	p := New(f)
	rec := &provider.OperatorRecord{ServerID: "1"}
	if err := p.AssignFloatingIP(context.Background(), rec, "rip-200"); err != nil {
		t.Fatal(err)
	}
	if rec.FloatingIPID != "rip-200" || f.floating["rip-200"] != "1" {
		t.Errorf("attach not recorded")
	}
}

func TestPricing_ReturnsHourlyAndMonthly(t *testing.T) {
	p := New(newFake())
	rec := &provider.OperatorRecord{Region: "fra", ServerType: "vc2-1c-1gb"}
	pr, err := p.Pricing(context.Background(), rec)
	if err != nil {
		t.Fatal(err)
	}
	if pr.HourlyEUR != 0.007 || pr.MonthlyEUR != 5.00 {
		t.Errorf("pricing wrong: %+v", pr)
	}
	if pr.Provider != "vultr" {
		t.Errorf("Provider field missing in Pricing: %q", pr.Provider)
	}
}

func TestSetEphemeralFirewallRule_OpensCorrectTuple(t *testing.T) {
	f := newFake()
	p := New(f)
	pin := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	p.SetClock(func() time.Time { return pin })

	rule, err := p.SetEphemeralFirewallRule(context.Background(), "1", "2.3.4.5", 12345, 300)
	if err != nil {
		t.Fatalf("SetEphemeralFirewallRule: %v", err)
	}
	if rule.Port != 12345 || rule.CallerIP != "2.3.4.5" {
		t.Errorf("(port, IP) tuple wrong: %+v", rule)
	}
	if !rule.ExpiresAt.Equal(pin.Add(300 * time.Second).UTC()) {
		t.Errorf("ExpiresAt drift")
	}
	if len(f.ephemeralRules) != 1 {
		t.Errorf("rule not recorded")
	}
}

func TestSetEphemeralFirewallRule_RejectsBadInputs(t *testing.T) {
	p := New(newFake())
	if _, err := p.SetEphemeralFirewallRule(context.Background(), "", "2.3.4.5", 12345, 300); err == nil {
		t.Errorf("missing serverID must error")
	}
	if _, err := p.SetEphemeralFirewallRule(context.Background(), "1", "", 12345, 300); err == nil {
		t.Errorf("missing callerIP must error")
	}
	if _, err := p.SetEphemeralFirewallRule(context.Background(), "1", "2.3.4.5", 0, 300); err == nil {
		t.Errorf("port=0 must error")
	}
	if _, err := p.SetEphemeralFirewallRule(context.Background(), "1", "2.3.4.5", 8443, 300); err == nil {
		t.Errorf("fixed low port 8443 must error")
	}
	if _, err := p.SetEphemeralFirewallRule(context.Background(), "1", "2.3.4.5", 65001, 300); err == nil {
		t.Errorf("port > 65000 must error")
	}
	if _, err := p.SetEphemeralFirewallRule(context.Background(), "1", "2.3.4.5", 12345, 0); err == nil {
		t.Errorf("durationSec=0 must error")
	}
}

func TestRemoveEphemeralFirewallRule_Idempotent(t *testing.T) {
	f := newFake()
	p := New(f)
	if err := p.RemoveEphemeralFirewallRule(context.Background(), nil); err != nil {
		t.Errorf("nil rule must be nil; got %v", err)
	}
	rule, _ := p.SetEphemeralFirewallRule(context.Background(), "1", "2.3.4.5", 12345, 300)
	if err := p.RemoveEphemeralFirewallRule(context.Background(), rule); err != nil {
		t.Fatal(err)
	}
	if len(f.ephemeralRules) != 0 {
		t.Errorf("rule not removed")
	}
	// Second remove: idempotent.
	if err := p.RemoveEphemeralFirewallRule(context.Background(), rule); err != nil {
		t.Errorf("second remove must be nil; got %v", err)
	}
}

func TestPricing_MonthlyToHourlyHelper(t *testing.T) {
	if got := monthlyToHourly(7.30); got < 0.0099 || got > 0.0101 {
		t.Errorf("monthlyToHourly(7.30) = %v want ~0.01", got)
	}
	if got := monthlyToHourly(0); got != 0 {
		t.Errorf("monthlyToHourly(0) must be 0; got %v", got)
	}
}

func TestRegions_IsSupported(t *testing.T) {
	if !IsSupportedRegion(DefaultRegion) {
		t.Errorf("DefaultRegion %q not in SupportedRegions", DefaultRegion)
	}
	if IsSupportedRegion("nowhere") {
		t.Errorf("unknown region should not be reported supported")
	}
}

func TestNewLiveClient_ReturnsErrLiveNotImplemented(t *testing.T) {
	c := NewLiveClient("dummy-token")
	if _, err := c.InstanceByID(context.Background(), "1"); err != ErrLiveNotImplemented {
		t.Errorf("live client must return ErrLiveNotImplemented; got %v", err)
	}
}
