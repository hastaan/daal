package hetzner

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"daal/publisher/deploy/provider"
	"daal/publisher/deploy/sni"
)

// fakeClient is an in-memory hcloudClient for unit tests.
type fakeClient struct {
	mu               sync.Mutex
	servers          map[string]*ServerInfo
	sshKeys          map[string]*fakeSSHKey // id -> key
	idCount          int64
	priceM           map[string]struct{ hourly, monthly float64 }
	floating         map[string]string                    // fipID -> serverID
	firewalls        map[string]struct{ V4, V6 []string } // firewallID -> rule sources
	ephemeralRules   map[string]ephemeralRuleEntry        // ruleID -> entry (FRP-10)
	ensuredFirewalls map[string]string                    // serverID -> firewallID (FRP-14)
	fwAppliedTo      map[string][]string                  // firewallID -> server IDs behind it

	// Failure injection for the teardown/rollback tables. Each one
	// fails exactly the named call so a test can assert that one
	// resource failing does not abort the others.
	failServerCreate   error
	failServerDelete   error
	failServerByName   error
	failSSHKeyList     error
	failSSHKeyDelete   error
	failFirewallDelete error

	// lastUserData is the cloud-init the most recent create/rebuild
	// was handed. cover_sni_test.go parses it to prove the per-relay
	// REALITY cover host actually reaches the box's sing-box config.
	lastUserData string
}

// fakeSSHKey mirrors what Hetzner stores for an SSH key. Name is
// modelled explicitly because name-uniqueness is the whole point of
// the retry-after-failure regression test.
type fakeSSHKey struct {
	Name      string
	Labels    map[string]string
	PublicKey []byte
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
		servers:          map[string]*ServerInfo{},
		sshKeys:          map[string]*fakeSSHKey{},
		priceM:           map[string]struct{ hourly, monthly float64 }{"fsn1/cx22": {0.005, 3.85}},
		floating:         map[string]string{},
		ensuredFirewalls: map[string]string{},
		fwAppliedTo:      map[string][]string{},
	}
}

// seedSSHKey plants a key on the account, as a killed provisioning
// run or a pre-fix build would have left behind.
func (f *fakeClient) seedSSHKey(name string, labels map[string]string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.idCount++
	id := strconv.FormatInt(f.idCount, 10)
	f.sshKeys[id] = &fakeSSHKey{Name: name, Labels: labels, PublicKey: []byte("ssh-ed25519 SEED")}
	return id
}

func (f *fakeClient) ServerCreate(ctx context.Context, opts ServerCreateOpts) (*ServerInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failServerCreate != nil {
		return nil, f.failServerCreate
	}
	for _, s := range f.servers {
		if s.Name == opts.Name {
			return nil, errors.New("server with same name already exists")
		}
	}
	f.idCount++
	id := strconv.FormatInt(f.idCount, 10)
	f.lastUserData = opts.UserData
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
	if f.failServerByName != nil {
		return nil, f.failServerByName
	}
	for _, s := range f.servers {
		if s.Name == name {
			return s, nil
		}
	}
	return nil, errServerNotFound
}

func (f *fakeClient) ServerRebuild(ctx context.Context, id string, image string, userData string) (*ServerInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.servers[id]
	if !ok {
		return nil, errServerNotFound
	}
	s.Status = "rebuilding"
	return s, nil
}

func (f *fakeClient) ServerList(ctx context.Context) ([]*ServerInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var result []*ServerInfo
	for _, s := range f.servers {
		result = append(result, s)
	}
	return result, nil
}

func (f *fakeClient) ServerDelete(ctx context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failServerDelete != nil {
		return f.failServerDelete
	}
	delete(f.servers, id) // idempotent
	return nil
}

func (f *fakeClient) ServerTypePrice(ctx context.Context, region, serverType string) (float64, float64, error) {
	if p, ok := f.priceM[region+"/"+serverType]; ok {
		return p.hourly, p.monthly, nil
	}
	return 0, 0, errors.New("no pricing")
}

// SSHKeyCreate models Hetzner's name-uniqueness constraint verbatim
// — including the error string. That constraint is what used to make
// a single orphaned key wedge an account permanently, so the fake has
// to reproduce it or the retry-after-failure test proves nothing.
func (f *fakeClient) SSHKeyCreate(ctx context.Context, name string, publicKey []byte, labels map[string]string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, k := range f.sshKeys {
		if k.Name == name {
			return "", errors.New("SSH key not unique (uniqueness_error, ssh key with the same name already exists)")
		}
	}
	f.idCount++
	id := strconv.FormatInt(f.idCount, 10)
	f.sshKeys[id] = &fakeSSHKey{Name: name, Labels: labels, PublicKey: publicKey}
	return id, nil
}

func (f *fakeClient) SSHKeyDelete(ctx context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failSSHKeyDelete != nil {
		return f.failSSHKeyDelete
	}
	delete(f.sshKeys, id)
	return nil
}

func (f *fakeClient) SSHKeyList(ctx context.Context) ([]SSHKeyInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failSSHKeyList != nil {
		return nil, f.failSSHKeyList
	}
	out := make([]SSHKeyInfo, 0, len(f.sshKeys))
	for id, k := range f.sshKeys {
		out = append(out, SSHKeyInfo{ID: id, Name: k.Name, Labels: k.Labels})
	}
	return out, nil
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

// FirewallEnsureForServer in the fake records that the per-server
// firewall was ensured, so tests can assert provisioning ran the
// step. Returns a deterministic ID per serverID and tracks which
// servers sit behind it (fwAppliedTo), which is what makes the
// shared-firewall case testable.
func (f *fakeClient) FirewallEnsureForServer(_ context.Context, serverID string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ensuredFirewalls == nil {
		f.ensuredFirewalls = map[string]string{}
	}
	if f.fwAppliedTo == nil {
		f.fwAppliedTo = map[string][]string{}
	}
	if id, ok := f.ensuredFirewalls[serverID]; ok {
		return id, nil
	}
	id := "fw-" + serverID
	f.ensuredFirewalls[serverID] = id
	f.fwAppliedTo[id] = append(f.fwAppliedTo[id], serverID)
	return id, nil
}

// FirewallDeleteForServer mirrors the live client: the firewall for
// serverID is deleted only when no OTHER server is still behind it.
func (f *fakeClient) FirewallDeleteForServer(_ context.Context, serverID string) (FirewallTeardownResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var res FirewallTeardownResult
	if f.failFirewallDelete != nil {
		return res, f.failFirewallDelete
	}
	fwID, ok := f.ensuredFirewalls[serverID]
	if !ok {
		return res, nil // never existed; nothing of ours left behind
	}
	res.Found = true
	res.FirewallID = fwID
	for _, s := range f.fwAppliedTo[fwID] {
		if s != serverID {
			res.SharedWith = append(res.SharedWith, s)
		}
	}
	if len(res.SharedWith) > 0 {
		return res, nil // preserved on purpose
	}
	delete(f.ensuredFirewalls, serverID)
	delete(f.fwAppliedTo, fwID)
	res.Deleted = true
	return res, nil
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
	// The adopt path also refuses to invent a cover host; state the one
	// the first Provision wrote.
	retry.CoverSNI = sni.Pick(derivedServerName(opts.PublisherPubKey, opts.Region), opts.Region)
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
	rep, err := p.Decommission(context.Background(), rec)
	if err != nil {
		t.Errorf("Decommission of absent server must be nil; got %v", err)
	}
	if !rep.ServerDeleted || !rep.FirewallDeleted {
		t.Errorf("absent server must report nothing left behind; got %+v", rep)
	}
}

func TestDecommission_NilRecordIsNoOp(t *testing.T) {
	p := New(newFake())
	rep, err := p.Decommission(context.Background(), nil)
	if err != nil {
		t.Errorf("Decommission(nil) must be nil; got %v", err)
	}
	if !rep.Clean() {
		t.Errorf("Decommission(nil) must report a clean teardown; got %+v", rep)
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

func TestSSHCloudInitTailCommand_SurfacesProvisionFailFile(t *testing.T) {
	cmd := sshCloudInitTailCommand()
	for _, want := range []string{
		"/var/log/daal-provision.fail",
		"--- daal-provision.fail ---",
		"exit 42",
	} {
		if !strings.Contains(cmd, want) {
			t.Fatalf("ssh tail command missing %q: %s", want, cmd)
		}
	}
}

func TestProvisionFatalErrorSummary_TrimsLongLog(t *testing.T) {
	err := &provisionFatalError{Log: strings.Repeat("x", 800)}
	if len(err.Summary()) != 500 {
		t.Fatalf("summary len = %d, want 500", len(err.Summary()))
	}
}

// ---------------------------------------------------------------
// Teardown + rollback (the "Remove server" feature and the failed-
// provision money bug). The fake models Hetzner's SSH-key name
// uniqueness and firewall attachment set, so these tests fail if
// either invariant is broken.
// ---------------------------------------------------------------

// liveOpts is mkOpts with the dry-run short circuit off, so the
// provision actually walks the cloud-client path against the fake.
func liveOpts() provider.ProvisionOpts {
	o := mkOpts()
	o.DryRun = false
	return o
}

// provisionLive runs one real provision against the fake and returns
// the record plus the opts it was built from (tests need the pubkey +
// region to re-derive resource names, exactly as teardown does).
func provisionLive(t *testing.T, p *Provider) (*provider.OperatorRecord, provider.ProvisionOpts) {
	t.Helper()
	opts := liveOpts()
	rec, err := p.Provision(context.Background(), opts)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	return rec, opts
}

func TestDecommission_CompleteTeardown(t *testing.T) {
	f := newFake()
	p := New(f)
	rec, opts := provisionLive(t, p)
	relay := derivedServerName(opts.PublisherPubKey, opts.Region)

	// Provision removes its own one-shot key on the way out, so seed
	// the two orphan shapes teardown is expected to sweep: a pre-fix
	// build's unsuffixed key, and a labelled key from a run that was
	// killed before its cleanup ran.
	f.seedSSHKey(relay+"-ephemeral", nil)
	f.seedSSHKey(relay+"-ephemeral-deadbeef", map[string]string{
		labelManagedBy: labelManagedByValue,
		labelRelay:     relay,
	})

	rep, err := p.Decommission(context.Background(), rec)
	if err != nil {
		t.Fatalf("Decommission: %v", err)
	}
	if !rep.Clean() {
		t.Errorf("teardown not clean: %+v", rep)
	}
	if len(rep.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", rep.Warnings)
	}
	if len(rep.DeletedSSHKeyIDs) != 2 {
		t.Errorf("deleted ssh keys = %v, want both orphans", rep.DeletedSSHKeyIDs)
	}
	if _, ok := f.servers[rec.ServerID]; ok {
		t.Errorf("server %s survived teardown", rec.ServerID)
	}
	if _, ok := f.ensuredFirewalls[rec.ServerID]; ok {
		t.Errorf("firewall for %s survived teardown", rec.ServerID)
	}
	if len(f.sshKeys) != 0 {
		t.Errorf("ssh keys survived teardown: %d left", len(f.sshKeys))
	}
	if rep.Provider != "hetzner" {
		t.Errorf("report provider = %q", rep.Provider)
	}
}

func TestDecommission_PartialFailuresAreBestEffort(t *testing.T) {
	boom := errors.New("cloud API 503")
	cases := []struct {
		name         string
		inject       func(*fakeClient)
		wantErr      bool
		wantServer   bool
		wantSSHKey   bool
		wantFirewall bool
		wantWarn     string
		wantKeyAlive bool // the seeded orphan key still on the account
	}{
		{
			name:         "firewall delete fails but the key sweep still runs",
			inject:       func(f *fakeClient) { f.failFirewallDelete = boom },
			wantServer:   true,
			wantSSHKey:   true,
			wantFirewall: false,
			wantWarn:     "could not delete firewall",
		},
		{
			name:         "ssh key delete fails but the server and firewall still go",
			inject:       func(f *fakeClient) { f.failSSHKeyDelete = boom },
			wantServer:   true,
			wantSSHKey:   false,
			wantFirewall: true,
			wantWarn:     "could not delete SSH key",
			wantKeyAlive: true,
		},
		{
			name:         "ssh key list fails: reported, not guessed at",
			inject:       func(f *fakeClient) { f.failSSHKeyList = boom },
			wantServer:   true,
			wantSSHKey:   false,
			wantFirewall: true,
			wantWarn:     "could not list SSH keys",
			wantKeyAlive: true,
		},
		{
			name:         "server delete fails: fatal, and nothing else is touched",
			inject:       func(f *fakeClient) { f.failServerDelete = boom },
			wantErr:      true,
			wantServer:   false,
			wantSSHKey:   false,
			wantFirewall: false,
			wantWarn:     "could not delete server",
			wantKeyAlive: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			p := New(f)
			rec, opts := provisionLive(t, p)
			relay := derivedServerName(opts.PublisherPubKey, opts.Region)
			keyID := f.seedSSHKey(relay+"-ephemeral", nil)
			tc.inject(f)

			rep, err := p.Decommission(context.Background(), rec)
			if tc.wantErr != (err != nil) {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if rep == nil {
				t.Fatal("report must never be nil, even on error")
			}
			if rep.ServerDeleted != tc.wantServer {
				t.Errorf("ServerDeleted = %v want %v", rep.ServerDeleted, tc.wantServer)
			}
			if rep.SSHKeyDeleted != tc.wantSSHKey {
				t.Errorf("SSHKeyDeleted = %v want %v", rep.SSHKeyDeleted, tc.wantSSHKey)
			}
			if rep.FirewallDeleted != tc.wantFirewall {
				t.Errorf("FirewallDeleted = %v want %v", rep.FirewallDeleted, tc.wantFirewall)
			}
			if !warnsContain(rep.Warnings, tc.wantWarn) {
				t.Errorf("warnings %v do not mention %q", rep.Warnings, tc.wantWarn)
			}
			if len(rep.Preserved) == 0 {
				t.Errorf("a survivor must be listed in Preserved; got none")
			}
			_, alive := f.sshKeys[keyID]
			if alive != tc.wantKeyAlive {
				t.Errorf("seeded key alive = %v want %v", alive, tc.wantKeyAlive)
			}
		})
	}
}

func TestDecommission_SharedFirewallIsPreserved(t *testing.T) {
	f := newFake()
	p := New(f)
	rec, _ := provisionLive(t, p)

	// A second relay was attached to the same firewall out-of-band.
	// Deleting it would strip that relay's only protection for its
	// random mgmt port.
	fwID := f.ensuredFirewalls[rec.ServerID]
	f.fwAppliedTo[fwID] = append(f.fwAppliedTo[fwID], "other-server-77")

	rep, err := p.Decommission(context.Background(), rec)
	if err != nil {
		t.Fatalf("Decommission: %v", err)
	}
	if !rep.ServerDeleted {
		t.Errorf("server should still have been deleted")
	}
	if rep.FirewallDeleted {
		t.Errorf("shared firewall must NOT be reported deleted")
	}
	if _, ok := f.ensuredFirewalls[rec.ServerID]; !ok {
		t.Errorf("shared firewall was destroyed; the other relay lost its firewall")
	}
	if !warnsContain(rep.Warnings, "other-server-77") {
		t.Errorf("warnings must name the sharing server; got %v", rep.Warnings)
	}
	if !preservedContains(rep.Preserved, "firewall:") {
		t.Errorf("shared firewall must appear in Preserved; got %v", rep.Preserved)
	}
}

func TestDecommission_LeavesForeignAndUnprovenKeysAlone(t *testing.T) {
	f := newFake()
	p := New(f)
	rec, opts := provisionLive(t, p)
	relay := derivedServerName(opts.PublisherPubKey, opts.Region)

	// None of these belong to this operator's relay, and none may be
	// deleted on a loose "daal-" prefix match.
	foreign := map[string]string{
		"another operator, same region": f.seedSSHKey("daal-fsn1-ffffffffffffffff-ephemeral", nil),
		"the user's own laptop key":     f.seedSSHKey("my-laptop", nil),
		"same relay, different region":  f.seedSSHKey(derivedServerName(opts.PublisherPubKey, "hel1")+"-ephemeral", nil),
		"our name shape, no ownership label": f.seedSSHKey(relay+"-ephemeral-cafebabe", map[string]string{
			labelManagedBy: "someone-else",
		}),
	}
	ours := f.seedSSHKey(relay+"-ephemeral", nil)

	rep, err := p.Decommission(context.Background(), rec)
	if err != nil {
		t.Fatalf("Decommission: %v", err)
	}
	if !rep.SSHKeyDeleted {
		t.Errorf("our own key should have been swept: %+v", rep)
	}
	if _, alive := f.sshKeys[ours]; alive {
		t.Errorf("our one-shot key survived")
	}
	for what, id := range foreign {
		if _, alive := f.sshKeys[id]; !alive {
			t.Errorf("teardown deleted a key it does not own (%s)", what)
		}
	}
}

// A record with no server id is the SHAPE A FAILED PROVISION LEAVES:
// the wizard only writes the OperatorRecord back on success, so a run
// that created the box and then failed its health wait persists
// `server_id: ""` while a real, billing VPS runs under the derived
// name. Teardown must find it by that name and delete it. Reporting
// ServerDeleted without looking told the user "the server is gone and
// the billing has stopped" and then erased the token and the row that
// were the only way back to it.
func TestDecommission_FindsAndDeletesOrphanServerByDerivedName(t *testing.T) {
	f := newFake()
	p := New(f)
	_, opts := provisionLive(t, p)
	relay := derivedServerName(opts.PublisherPubKey, opts.Region)
	orphanKey := f.seedSSHKey(relay+"-ephemeral", nil)

	before, err := f.ServerByName(context.Background(), relay)
	if err != nil || before == nil {
		t.Fatalf("fixture: no server named %q to orphan", relay)
	}

	stale := &provider.OperatorRecord{
		Provider:        "hetzner",
		Region:          opts.Region,
		PublisherPubKey: opts.PublisherPubKey,
	}
	rep, err := p.Decommission(context.Background(), stale)
	if err != nil {
		t.Fatalf("Decommission: %v", err)
	}
	if !rep.ServerDeleted {
		t.Errorf("orphan server must be reported deleted: %+v", rep)
	}
	if _, alive := f.servers[before.ID]; alive {
		t.Errorf("the billing orphan %s survived a teardown that claimed %v", before.ID, rep.ServerDeleted)
	}
	if rep.ServerID != before.ID {
		t.Errorf("report must name the server it found: ServerID = %q, want %q", rep.ServerID, before.ID)
	}
	// With the box gone the one-shot key is ours to remove again.
	if !rep.SSHKeyDeleted {
		t.Errorf("key sweep must run once the server is gone: %+v", rep)
	}
	if _, alive := f.sshKeys[orphanKey]; alive {
		t.Errorf("orphaned one-shot key survived")
	}
}

// The other half of the same contract: an unverifiable lookup must NOT
// be rounded down to "there is nothing there". `ServerDeleted` stays
// false and the call errors, so relay_destroy keeps the local record —
// the only remaining handle on a possibly-live box.
func TestDecommission_LookupFailureNeverClaimsDeleted(t *testing.T) {
	f := newFake()
	p := New(f)
	_, opts := provisionLive(t, p)
	f.failServerByName = errors.New("hcloud: 503 service unavailable")

	stale := &provider.OperatorRecord{
		Provider:        "hetzner",
		Region:          opts.Region,
		PublisherPubKey: opts.PublisherPubKey,
	}
	rep, err := p.Decommission(context.Background(), stale)
	if err == nil {
		t.Fatalf("an unverifiable server lookup must be an error, got report %+v", rep)
	}
	if rep.ServerDeleted {
		t.Errorf("must not claim a deletion it could not perform: %+v", rep)
	}
	if len(f.servers) == 0 {
		t.Error("nothing should have been deleted")
	}
	if !warnsContain(rep.Warnings, "could not confirm") {
		t.Errorf("warnings must say what could not be proved; got %v", rep.Warnings)
	}
}

// The key sweep's own liveness guard, exercised directly: if a server
// still carries the derived name when the sweep runs — Hetzner's delete
// is asynchronous, so this can happen even after a successful delete —
// the one-shot key is not ours to remove.
func TestSweepEphemeralKeys_PreservedWhileItsServerIsAlive(t *testing.T) {
	f := newFake()
	p := New(f)
	_, opts := provisionLive(t, p)
	relay := derivedServerName(opts.PublisherPubKey, opts.Region)
	orphan := f.seedSSHKey(relay+"-ephemeral", nil)

	rep := provider.NewDecommissionReport("hetzner", "")
	p.sweepEphemeralKeys(context.Background(), &provider.OperatorRecord{
		Provider:        "hetzner",
		Region:          opts.Region,
		PublisherPubKey: opts.PublisherPubKey,
	}, rep)

	if rep.SSHKeyDeleted {
		t.Errorf("must not claim the key is gone while its server runs: %+v", rep)
	}
	if _, alive := f.sshKeys[orphan]; !alive {
		t.Errorf("deleted the ssh key of a live relay")
	}
	if !warnsContain(rep.Warnings, "still running") {
		t.Errorf("warnings must explain the preservation; got %v", rep.Warnings)
	}
}

func TestDecommission_ReportsFloatingIPItDoesNotOwn(t *testing.T) {
	f := newFake()
	p := New(f)
	rec, _ := provisionLive(t, p)
	rec.FloatingIPID = "fip-9"

	rep, err := p.Decommission(context.Background(), rec)
	if err != nil {
		t.Fatalf("Decommission: %v", err)
	}
	if !warnsContain(rep.Warnings, "fip-9") {
		t.Errorf("floating IP must be reported, not silently left: %v", rep.Warnings)
	}
	if !preservedContains(rep.Preserved, "floating-ip:fip-9") {
		t.Errorf("floating IP missing from Preserved: %v", rep.Preserved)
	}
}

// TestProvision_RetryAfterFailureSucceeds is the regression test for
// the worst defect this work fixes: a failed attempt used to leave an
// SSH key whose name was a pure function of (publisher key, region),
// and Hetzner then rejected every later attempt with
// "SSH key not unique" — permanently, with no in-app way out.
func TestProvision_RetryAfterFailureSucceeds(t *testing.T) {
	t.Run("after a failed attempt", func(t *testing.T) {
		f := newFake()
		p := New(f)
		opts := liveOpts()

		f.failServerCreate = errors.New("hetzner: transient 500")
		if _, err := p.Provision(context.Background(), opts); err == nil {
			t.Fatal("attempt 1 was supposed to fail")
		}
		if len(f.sshKeys) != 0 {
			t.Errorf("failed attempt leaked %d ssh key(s); that is what bricks retries", len(f.sshKeys))
		}

		f.failServerCreate = nil
		if _, err := p.Provision(context.Background(), opts); err != nil {
			t.Fatalf("attempt 2 must succeed without manual cleanup; got %v", err)
		}
	})

	t.Run("with a pre-fix orphan already on the account", func(t *testing.T) {
		f := newFake()
		p := New(f)
		opts := liveOpts()
		relay := derivedServerName(opts.PublisherPubKey, opts.Region)
		// Exactly the state a pre-fix build left behind.
		f.seedSSHKey(relay+"-ephemeral", nil)

		if _, err := p.Provision(context.Background(), opts); err != nil {
			t.Fatalf("provision must survive a legacy orphan key; got %v", err)
		}
	})
}

func TestProvision_RemovesOneShotKeyOnEveryPath(t *testing.T) {
	cases := []struct {
		name   string
		inject func(*fakeClient)
		wantOK bool
	}{
		{"success", func(*fakeClient) {}, true},
		{"server create fails", func(f *fakeClient) { f.failServerCreate = errors.New("boom") }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			p := New(f)
			tc.inject(f)
			_, err := p.Provision(context.Background(), liveOpts())
			if tc.wantOK != (err == nil) {
				t.Fatalf("err = %v, wantOK = %v", err, tc.wantOK)
			}
			// The private half never left this process, so the cloud
			// side of the keypair is dead weight either way.
			if len(f.sshKeys) != 0 {
				t.Errorf("one-shot ssh key left on the account: %d", len(f.sshKeys))
			}
		})
	}
}

func TestEphemeralSSHKeyName_UniquePerAttempt(t *testing.T) {
	a, err := ephemeralSSHKeyName("daal-fsn1-0011223344556677")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ephemeralSSHKeyName("daal-fsn1-0011223344556677")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatalf("two attempts produced the same key name (%q); that is the uniqueness_error bug", a)
	}
	if !strings.HasPrefix(a, "daal-fsn1-0011223344556677-ephemeral-") {
		t.Errorf("key name %q lost the derived-relay anchor teardown matches on", a)
	}
}

// TestProvision_FailureAfterServerCreated pins the money bug: once a
// billing server exists, a later failure must either roll it back or
// say out loud that it is still running.
func TestProvision_FailureAfterServerCreated(t *testing.T) {
	cases := []struct {
		name             string
		rollback         bool
		wantServerAlive  bool
		wantErrContains  string
		wantProgressStep string
	}{
		{
			name:             "default keeps the box but names it",
			rollback:         false,
			wantServerAlive:  true,
			wantErrContains:  "still running and still billing",
			wantProgressStep: "provision_orphan",
		},
		{
			name:             "rollback destroys what it created",
			rollback:         true,
			wantServerAlive:  false,
			wantErrContains:  "rolled back",
			wantProgressStep: "provision_rollback",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			p := New(f)
			p.setHealthWaiter(func(context.Context, *provider.OperatorRecord, *ServerInfo, string, provider.ProvisionOpts, func(string, string)) error {
				return errors.New("hetzner: health check timed out after 60 attempts")
			})

			var steps []string
			var messages []string
			opts := liveOpts()
			opts.WaitForHealth = true
			opts.RollbackOnFailure = tc.rollback
			opts.OnProgress = func(step, msg string) {
				steps = append(steps, step)
				messages = append(messages, msg)
			}

			_, err := p.Provision(context.Background(), opts)
			if err == nil {
				t.Fatal("expected the health failure to surface")
			}
			if !strings.Contains(err.Error(), tc.wantErrContains) {
				t.Errorf("error %q does not contain %q", err, tc.wantErrContains)
			}
			if !contains(steps, tc.wantProgressStep) {
				t.Errorf("progress steps %v missing %q", steps, tc.wantProgressStep)
			}
			if len(f.servers) != 0 && !tc.wantServerAlive {
				t.Errorf("rollback left %d server(s) billing", len(f.servers))
			}
			if len(f.servers) == 0 && tc.wantServerAlive {
				t.Errorf("server was deleted although rollback was off")
			}
			if tc.wantServerAlive {
				// The whole point: the caller can identify the box.
				for id := range f.servers {
					if !strings.Contains(err.Error(), id) {
						t.Errorf("error %q does not name the surviving server id %q", err, id)
					}
					if !anyContains(messages, id) {
						t.Errorf("progress messages %v do not name the surviving server id %q", messages, id)
					}
				}
			}
			if len(f.sshKeys) != 0 {
				t.Errorf("one-shot ssh key leaked on the failure path: %d", len(f.sshKeys))
			}
			if tc.rollback {
				if len(f.ensuredFirewalls) != 0 {
					t.Errorf("rollback left the firewall behind")
				}
			}
		})
	}
}

func TestOwnsEphemeralKey(t *testing.T) {
	const relay = "daal-fsn1-0011223344556677"
	ourLabels := map[string]string{labelManagedBy: labelManagedByValue, labelRelay: relay}
	cases := []struct {
		name string
		key  SSHKeyInfo
		want bool
	}{
		{"pre-fix unsuffixed name", SSHKeyInfo{Name: relay + "-ephemeral"}, true},
		{"current name + labels", SSHKeyInfo{Name: relay + "-ephemeral-a1b2c3d4", Labels: ourLabels}, true},
		{"right name shape, no labels", SSHKeyInfo{Name: relay + "-ephemeral-a1b2c3d4"}, false},
		{"right name shape, foreign labels", SSHKeyInfo{
			Name:   relay + "-ephemeral-a1b2c3d4",
			Labels: map[string]string{labelManagedBy: labelManagedByValue, labelRelay: "daal-fsn1-ffffffffffffffff"},
		}, false},
		{"loose daal prefix", SSHKeyInfo{Name: "daal-something-else", Labels: ourLabels}, false},
		{"another relay", SSHKeyInfo{Name: "daal-fsn1-ffffffffffffffff-ephemeral"}, false},
		{"unrelated key", SSHKeyInfo{Name: "my-laptop"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ownsEphemeralKey(tc.key, relay); got != tc.want {
				t.Errorf("ownsEphemeralKey(%q) = %v want %v", tc.key.Name, got, tc.want)
			}
		})
	}
}

func warnsContain(warnings []string, want string) bool { return anyContains(warnings, want) }

func preservedContains(preserved []string, want string) bool { return anyContains(preserved, want) }

func anyContains(hay []string, want string) bool {
	for _, h := range hay {
		if strings.Contains(h, want) {
			return true
		}
	}
	return false
}

func contains(hay []string, want string) bool {
	for _, h := range hay {
		if h == want {
			return true
		}
	}
	return false
}

// TestProvision_RollbackNeverDeletesTheCallersOwnServer: on the
// rebuild path the box belongs to the user (they asked us to re-image
// an existing machine), so a failed provision must report it, never
// destroy it — even with RollbackOnFailure on.
func TestProvision_RollbackNeverDeletesTheCallersOwnServer(t *testing.T) {
	f := newFake()
	p := New(f)
	// A server the user already owns.
	existing, err := f.ServerCreate(context.Background(), ServerCreateOpts{
		Name: "my-own-box", ServerType: "cx22", Region: "fsn1",
	})
	if err != nil {
		t.Fatal(err)
	}
	p.setHealthWaiter(func(context.Context, *provider.OperatorRecord, *ServerInfo, string, provider.ProvisionOpts, func(string, string)) error {
		return errors.New("hetzner: health check timed out after 60 attempts")
	})
	opts := liveOpts()
	opts.WaitForHealth = true
	opts.RollbackOnFailure = true
	opts.ExistingServerID = existing.ID

	if _, err := p.Provision(context.Background(), opts); err == nil {
		t.Fatal("expected the health failure to surface")
	}
	if _, alive := f.servers[existing.ID]; !alive {
		t.Fatalf("rollback destroyed the user's own server %s", existing.ID)
	}
}
