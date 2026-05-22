package hetzner

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

// fakeClient is an in-memory hcloudClient for unit tests.
type fakeClient struct {
	mu             sync.Mutex
	servers        map[string]*ServerInfo
	sshKeys        map[string][]byte
	idCount        int64
	priceM         map[string]struct{ hourly, monthly float64 }
	floating       map[string]string                    // fipID -> serverID
	firewalls      map[string]struct{ V4, V6 []string } // firewallID -> rule sources
	ephemeralRules map[string]ephemeralRuleEntry        // ruleID -> entry (FRP-10)
}

// ephemeralRuleEntry mirrors what FirewallAddEphemeralRule
// recorded; tests assert against the (Port, IP, ExpiresAt) tuple.
type ephemeralRuleEntry struct {
	ServerID  string
	CallerIP  string
	Port      int
	ExpiresAt time.Time
}

func newFake() *fakeClient {
	return &fakeClient{
		servers:  map[string]*ServerInfo{},
		sshKeys:  map[string][]byte{},
		priceM:   map[string]struct{ hourly, monthly float64 }{"fsn1/cx22": {0.005, 3.85}},
		floating: map[string]string{},
	}
}

func (f *fakeClient) ServerCreate(ctx context.Context, opts ServerCreateOpts) (*ServerInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.servers {
		if s.Name == opts.Name {
			return nil, errors.New("server with same name already exists")
		}
	}
	f.idCount++
	id := strconv.FormatInt(f.idCount, 10)
	s := &ServerInfo{
		ID: id, Name: opts.Name, Status: "running",
		ServerType: opts.ServerType, Region: opts.Region,
		PublicIP: net.ParseIP("5.75.0." + id),
		Labels:   opts.Labels,
	}
	f.servers[id] = s
	return s, nil
}

func (f *fakeClient) ServerByID(ctx context.Context, id string) (*ServerInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.servers[id]; ok {
		return s, nil
	}
	return nil, errServerNotFound
}

func (f *fakeClient) ServerByName(ctx context.Context, name string) (*ServerInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.servers {
		if s.Name == name {
			return s, nil
		}
	}
	return nil, errServerNotFound
}

func (f *fakeClient) ServerDelete(ctx context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.servers, id) // idempotent
	return nil
}

func (f *fakeClient) ServerTypePrice(ctx context.Context, region, serverType string) (float64, float64, error) {
	if p, ok := f.priceM[region+"/"+serverType]; ok {
		return p.hourly, p.monthly, nil
	}
	return 0, 0, errors.New("no pricing")
}

func (f *fakeClient) SSHKeyCreate(ctx context.Context, name string, publicKey []byte) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.idCount++
	id := strconv.FormatInt(f.idCount, 10)
	f.sshKeys[id] = publicKey
	return id, nil
}

func (f *fakeClient) SSHKeyDelete(ctx context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.sshKeys, id)
	return nil
}

func (f *fakeClient) FloatingIPAssign(ctx context.Context, fipID, serverID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.floating[fipID] = serverID
	return nil
}

func (f *fakeClient) FloatingIPUnassign(ctx context.Context, fipID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.floating, fipID)
	return nil
}

// fakeFirewalls and FirewallApplyCloudflareRule track the
// FRP-8 §11.7 origin firewall rule. firewallID == "" creates
// a fresh rule; non-empty updates in place.
func (f *fakeClient) FirewallApplyCloudflareRule(_ context.Context, firewallID string, ipv4, ipv6 []string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if firewallID == "" {
		f.idCount++
		firewallID = "fw-" + strconv.FormatInt(f.idCount, 10)
	}
	if f.firewalls == nil {
		f.firewalls = map[string]struct{ V4, V6 []string }{}
	}
	f.firewalls[firewallID] = struct{ V4, V6 []string }{V4: ipv4, V6: ipv6}
	return firewallID, nil
}

// FRP-10: ephemeral firewall rules. The fake records each
// add and clears each remove; tests inspect ephemeralRules to
// verify the (port, IP, expiresAt) tuple is opened/closed.
func (f *fakeClient) FirewallAddEphemeralRule(_ context.Context, serverID, callerIP string, port int, expiresAt time.Time) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ephemeralRules == nil {
		f.ephemeralRules = map[string]ephemeralRuleEntry{}
	}
	f.idCount++
	id := "daal-eph-" + serverID + "-" + callerIP + "-" + strconv.Itoa(port) + "-" + strconv.FormatInt(expiresAt.Unix(), 10)
	f.ephemeralRules[id] = ephemeralRuleEntry{ServerID: serverID, CallerIP: callerIP, Port: port, ExpiresAt: expiresAt}
	return id, nil
}

func (f *fakeClient) FirewallRemoveEphemeralRule(_ context.Context, ruleID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.ephemeralRules, ruleID)
	return nil
}

// fakeEphemeralKey returns an ed25519.PrivateKey whose .Public()
// returns a []byte (matching the live wrapper's expectation).
type fakeEphemeralKey []byte

func (k fakeEphemeralKey) Public() any                             { return []byte("ssh-ed25519 AAAAFAKE daal-deploy") }
func (k fakeEphemeralKey) Sign(_, _ []byte, _ any) ([]byte, error) { return nil, nil }
func (k fakeEphemeralKey) Equal(_ any) bool                        { return false }
func (k fakeEphemeralKey) Seed() []byte                            { return nil }

// We use an actual ed25519 private key for the EphemeralSSHKey
// field; the adapter calls .Public() and casts to []byte. Pin the
// expected behaviour by wrapping the byte-form public key into a
// type that satisfies the contract.
//
// Easier: generate a real ed25519 keypair and encode the public
// half as the "public key" the adapter passes to SSHKeyCreate. The
// adapter expects a []byte from Public() — here we satisfy that by
// using the public-key bytes directly via a custom key type below.

func mkOpts() provider.ProvisionOpts {
	pub, priv, _ := ed25519.GenerateKey(nil)
	return provider.ProvisionOpts{
		PublisherPubKey: pub,
		Region:          "fsn1",
		ServerType:      "cx22",
		ToolboxProfile:  "iran-default",
		HelperIP:        net.ParseIP("1.2.3.4"),
		EphemeralSSHKey: priv,
		DryRun:          true, // keep tests pure-function; no userData rendering required
	}
}

func TestProvision_DryRunReturnsSyntheticRecord(t *testing.T) {
	p := New(newFake())
	rec, err := p.Provision(context.Background(), mkOpts())
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if rec.Provider != "hetzner" {
		t.Errorf("Provider = %q want hetzner", rec.Provider)
	}
	if rec.Region != "fsn1" {
		t.Errorf("Region = %q want fsn1", rec.Region)
	}
	if len(rec.Candidates) == 0 {
		t.Errorf("Candidates empty; iran-default has 4 default-enabled families")
	}
	for _, c := range rec.Candidates {
		if c.ExposureMode != "direct_vps" {
			t.Errorf("V1.5 invariant: candidate %s has exposure_mode=%q; want direct_vps", c.Family, c.ExposureMode)
		}
		if len(c.OriginRiskTags) != 0 {
			t.Errorf("V1.5 invariant: candidate %s has %d origin tags; want 0", c.Family, len(c.OriginRiskTags))
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
	// Use a fake-client live path (dry-run path skips the cloud
	// client entirely; we want to exercise the ServerByName lookup
	// idempotency check). To do this without rendering cloud-init,
	// we set DryRun=true and check that the dry-run record is
	// stable across two calls (the derived name is a function of
	// pubkey+region, so the *record* is identical even though the
	// fake-client never sees a server).
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

func TestProvision_ExistingServerRequiresPersistedMgmtPort(t *testing.T) {
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
		t.Fatal("expected existing server retry without persisted MgmtPort to fail")
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

func TestDecommission_AbsentServerSucceeds(t *testing.T) {
	p := New(newFake())
	rec := &provider.OperatorRecord{ServerID: "9999"} // doesn't exist in fake
	if err := p.Decommission(context.Background(), rec); err != nil {
		t.Errorf("Decommission of absent server must be nil; got %v", err)
	}
}

func TestDecommission_NilRecordIsNoOp(t *testing.T) {
	p := New(newFake())
	if err := p.Decommission(context.Background(), nil); err != nil {
		t.Errorf("Decommission(nil) must be nil; got %v", err)
	}
}

func TestAssignFloatingIP_SameIDIsNoOp(t *testing.T) {
	f := newFake()
	p := New(f)
	rec := &provider.OperatorRecord{ServerID: "1", FloatingIPID: "fip-100"}
	if err := p.AssignFloatingIP(context.Background(), rec, "fip-100"); err != nil {
		t.Errorf("idempotent assign must be nil; got %v", err)
	}
	if len(f.floating) != 0 {
		t.Errorf("idempotent path must not call cloud API; got %d floating entries", len(f.floating))
	}
}

func TestAssignFloatingIP_NewIDUpdatesRecord(t *testing.T) {
	f := newFake()
	p := New(f)
	rec := &provider.OperatorRecord{ServerID: "1"}
	if err := p.AssignFloatingIP(context.Background(), rec, "fip-200"); err != nil {
		t.Fatal(err)
	}
	if rec.FloatingIPID != "fip-200" {
		t.Errorf("FloatingIPID not updated on record")
	}
	if f.floating["fip-200"] != "1" {
		t.Errorf("fake-client did not see assign call")
	}
}

func TestUnassignFloatingIP_UpdatesRecord(t *testing.T) {
	f := newFake()
	p := New(f)
	rec := &provider.OperatorRecord{ServerID: "1", FloatingIPID: "fip-200"}
	f.floating["fip-200"] = "1"
	if err := p.UnassignFloatingIP(context.Background(), rec); err != nil {
		t.Fatal(err)
	}
	if rec.FloatingIPID != "" {
		t.Errorf("FloatingIPID not cleared")
	}
	if _, ok := f.floating["fip-200"]; ok {
		t.Errorf("fake-client did not see unassign call")
	}
}

func TestProvision_EnabledFamiliesFilterProfile(t *testing.T) {
	p := New(newFake())
	opts := mkOpts()
	opts.EnabledFamilies = []string{"vless-reality", "hysteria2"}
	rec, err := p.Provision(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Candidates) != 2 {
		t.Fatalf("candidate count = %d want 2", len(rec.Candidates))
	}
	got := map[string]bool{}
	for _, c := range rec.Candidates {
		got[c.Family] = true
	}
	for _, want := range opts.EnabledFamilies {
		if !got[want] {
			t.Errorf("missing selected family %s", want)
		}
	}
}

func TestPricing_ReturnsHourlyAndMonthly(t *testing.T) {
	p := New(newFake())
	rec := &provider.OperatorRecord{Region: "fsn1", ServerType: "cx22"}
	pr, err := p.Pricing(context.Background(), rec)
	if err != nil {
		t.Fatal(err)
	}
	if pr.HourlyEUR != 0.005 || pr.MonthlyEUR != 3.85 {
		t.Errorf("pricing wrong: %+v", pr)
	}
	if pr.Provider != "hetzner" {
		t.Errorf("Provider field missing in Pricing")
	}
}

func TestDerivedServerName_DeterministicSamePubkeyRegion(t *testing.T) {
	pub := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A}
	a := derivedServerName(pub, "fsn1")
	b := derivedServerName(pub, "fsn1")
	if a != b {
		t.Errorf("derivedServerName non-deterministic: %s vs %s", a, b)
	}
	c := derivedServerName(pub, "ash")
	if a == c {
		t.Errorf("region change must change derived name")
	}
}

// TestClock_Injectable pins that SetClock works (deterministic
// tests downstream).
func TestClock_Injectable(t *testing.T) {
	p := New(newFake())
	pin := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	p.SetClock(func() time.Time { return pin })
	rec, err := p.Provision(context.Background(), mkOpts())
	if err != nil {
		t.Fatal(err)
	}
	if !rec.ProvisionedAt.Equal(pin) {
		t.Errorf("clock injection failed; got %v want %v", rec.ProvisionedAt, pin)
	}
}

// FRP-10 commit 2: ephemeral firewall rule semantics.

func TestSetEphemeralFirewallRule_OpensCorrectTuple(t *testing.T) {
	f := newFake()
	p := New(f)
	pin := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	p.SetClock(func() time.Time { return pin })

	rule, err := p.SetEphemeralFirewallRule(context.Background(), "1", "2.3.4.5", 12345, 300)
	if err != nil {
		t.Fatalf("SetEphemeralFirewallRule: %v", err)
	}
	if rule.Port != 12345 {
		t.Errorf("Port lost; got %d", rule.Port)
	}
	if rule.CallerIP != "2.3.4.5" {
		t.Errorf("CallerIP lost; got %q", rule.CallerIP)
	}
	if !rule.ExpiresAt.Equal(pin.Add(300 * time.Second).UTC()) {
		t.Errorf("ExpiresAt drift; got %v", rule.ExpiresAt)
	}
	if len(f.ephemeralRules) != 1 {
		t.Fatalf("fake-client did not record rule; got %d", len(f.ephemeralRules))
	}
	for _, e := range f.ephemeralRules {
		if e.Port != 12345 || e.CallerIP != "2.3.4.5" {
			t.Errorf("(port, IP) tuple wrong: %+v", e)
		}
	}
}

func TestSetEphemeralFirewallRule_RejectsZeroPort(t *testing.T) {
	p := New(newFake())
	if _, err := p.SetEphemeralFirewallRule(context.Background(), "1", "2.3.4.5", 0, 300); err == nil {
		t.Errorf("expected error for port=0 (invariant 28: port required)")
	}
	if _, err := p.SetEphemeralFirewallRule(context.Background(), "1", "2.3.4.5", 8443, 300); err == nil {
		t.Errorf("expected error for fixed low port 8443 (invariant 27: random per-deploy range)")
	}
	if _, err := p.SetEphemeralFirewallRule(context.Background(), "1", "2.3.4.5", 65001, 300); err == nil {
		t.Errorf("expected error for port > 65000")
	}
}

func TestSetEphemeralFirewallRule_RejectsZeroDuration(t *testing.T) {
	p := New(newFake())
	if _, err := p.SetEphemeralFirewallRule(context.Background(), "1", "2.3.4.5", 12345, 0); err == nil {
		t.Errorf("expected error for durationSec=0")
	}
}

func TestRemoveEphemeralFirewallRule_Idempotent(t *testing.T) {
	f := newFake()
	p := New(f)

	// Remove with nil rule: nil.
	if err := p.RemoveEphemeralFirewallRule(context.Background(), nil); err != nil {
		t.Errorf("RemoveEphemeralFirewallRule(nil) must be nil; got %v", err)
	}
	// Remove with empty ID: nil.
	empty := &provider.EphemeralFirewallRule{}
	if err := p.RemoveEphemeralFirewallRule(context.Background(), empty); err != nil {
		t.Errorf("RemoveEphemeralFirewallRule(empty ID) must be nil; got %v", err)
	}
	// Add then remove: rule is gone.
	rule, err := p.SetEphemeralFirewallRule(context.Background(), "1", "2.3.4.5", 12345, 300)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.RemoveEphemeralFirewallRule(context.Background(), rule); err != nil {
		t.Fatal(err)
	}
	if len(f.ephemeralRules) != 0 {
		t.Errorf("rule not removed; %d remain", len(f.ephemeralRules))
	}
	// Remove again: idempotent.
	if err := p.RemoveEphemeralFirewallRule(context.Background(), rule); err != nil {
		t.Errorf("second RemoveEphemeralFirewallRule must be nil; got %v", err)
	}
}
