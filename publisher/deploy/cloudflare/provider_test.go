package cloudflare

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"daal/publisher/deploy/relayports"
)

const testToken = "cf-secret-token-value-0123456789"

func mkOpts(dir string) CloudflareOpts {
	return CloudflareOpts{
		Hostname:      "momsroute.example.com",
		OriginIP:      "5.75.1.2",
		OriginIPv6:    "2a01:4f8::1",
		CFTokenSecret: []byte(testToken),
		OutDir:        dir,
	}
}

// snapshot is the mock's whole Cloudflare state, for "nothing changed"
// assertions.
type snapshot struct {
	Settings    map[string]map[string]string
	AOPOn       map[string]bool
	AOPCerts    map[string]map[string]string
	Records     map[string][]DNSRecord
	OriginRules map[string][]MockOriginRule
	OriginCerts map[string][]string
}

func snap(m *MockCFClient) snapshot {
	m.init()
	cp := snapshot{
		Settings: map[string]map[string]string{}, AOPOn: map[string]bool{}, AOPCerts: map[string]map[string]string{},
		Records: map[string][]DNSRecord{}, OriginRules: map[string][]MockOriginRule{}, OriginCerts: map[string][]string{},
	}
	for z, s := range m.Settings {
		cp.Settings[z] = map[string]string{}
		for k, v := range s {
			cp.Settings[z][k] = v
		}
	}
	for z, v := range m.AOPOn {
		if v {
			cp.AOPOn[z] = v
		}
	}
	for z, c := range m.AOPCerts {
		if len(c) > 0 {
			cp.AOPCerts[z] = map[string]string{}
			for k, v := range c {
				cp.AOPCerts[z][k] = v
			}
		}
	}
	for z, r := range m.Records {
		if len(r) > 0 {
			cp.Records[z] = append([]DNSRecord(nil), r...)
		}
	}
	for z, r := range m.OriginRules {
		if len(r) > 0 {
			cp.OriginRules[z] = append([]MockOriginRule(nil), r...)
		}
	}
	for k, v := range m.OriginCerts {
		cp.OriginCerts[k] = v
	}
	return cp
}

func TestProvisionFront_HappyPath(t *testing.T) {
	m := NewMockCFClient("example.com")
	p := NewProvider(m)
	dir := t.TempDir()
	opts := mkOpts(dir)
	opts.ECH = &MockECHFetcher{ConfigList: testECHConfigList(t, "cloudflare-ech.com")}
	rec, err := p.ProvisionFront(context.Background(), opts)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	z := "zone-example.com"
	if rec.Hostname != "momsroute.example.com" || rec.ZoneID != z || rec.Zone != "example.com" {
		t.Errorf("record = %+v", rec)
	}
	if rec.OriginPort != relayports.CDNOrigin.Port {
		t.Errorf("origin port = %d", rec.OriginPort)
	}
	if !ValidWSPath(rec.OriginPath) || len(rec.OriginPath) != 33 || rec.PublicPath != rec.OriginPath {
		t.Errorf("path = %q / %q", rec.OriginPath, rec.PublicPath)
	}
	if rec.WorkerRouteID != "" {
		t.Error("a Worker route id in a record with no Worker")
	}
	// Origin CA covers the zone and its wildcard.
	if got := m.OriginCerts[rec.OriginCertID]; !reflect.DeepEqual(got, []string{"example.com", "*.example.com"}) {
		t.Errorf("origin cert hostnames = %v", got)
	}
	// Origin pull: our own certificate uploaded, setting on.
	if !m.AOPOn[z] || len(m.AOPCerts[z]) != 1 || m.AOPCerts[z][rec.AOPCertID] == "" {
		t.Errorf("aop: on=%v certs=%v", m.AOPOn[z], m.AOPCerts[z])
	}
	if m.Settings[z]["ssl"] != "strict" || m.Settings[z]["websockets"] != "on" {
		t.Errorf("settings = %v", m.Settings[z])
	}
	if rec.PriorSettings["ssl"] != "flexible" || rec.PriorSettings["websockets"] != "off" || rec.PriorSettings["aop"] != "off" {
		t.Errorf("prior settings = %v", rec.PriorSettings)
	}
	if len(rec.DNSRecordIDs) != 2 || len(m.Records[z]) != 2 {
		t.Errorf("dns: ids=%v records=%v", rec.DNSRecordIDs, m.Records[z])
	}
	rules := m.OriginRules[z]
	if len(rules) != 1 || rules[0].Hostname != rec.Hostname || rules[0].Port != relayports.CDNOrigin.Port || rules[0].Ref != rec.OriginRuleRef {
		t.Errorf("origin rules = %+v", rules)
	}
	// ECH already on: read, not changed.
	if rec.ECH.ZoneSetting != "on" || !rec.ECH.Published || rec.ECH.PublicName != "cloudflare-ech.com" || !rec.ECH.NameHidden(rec.Hostname) {
		t.Errorf("ech = %+v", rec.ECH)
	}
	for _, c := range m.Calls {
		if strings.Contains(c, "SetZoneSetting") && strings.Contains(c, "ech") {
			t.Errorf("ProvisionFront changed ECH: %s", c)
		}
		if strings.Contains(c, testToken) {
			t.Errorf("token in a call record: %s", c)
		}
	}
	// Files: cert, key and origin-pull CA at 0600; no client key on disk.
	for _, f := range []string{rec.OriginCACertPath, rec.OriginCAPrivPath, rec.AOPCACertPath} {
		st, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %o", f, st.Mode().Perm())
		}
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 3 {
		t.Errorf("out dir holds %d files, want 3 (no origin-pull client key)", len(ents))
	}
}

func TestProvisionFront_LeavesSettingsAlreadyRight(t *testing.T) {
	m := NewMockCFClient("example.com")
	m.Settings["zone-example.com"]["ssl"] = "strict"
	m.Settings["zone-example.com"]["websockets"] = "on"
	m.AOPOn = map[string]bool{"zone-example.com": true}
	if _, err := NewProvider(m).ProvisionFront(context.Background(), mkOpts(t.TempDir())); err != nil {
		t.Fatal(err)
	}
	for _, c := range m.Calls {
		if strings.HasPrefix(c, "SetZoneSetting") || strings.HasPrefix(c, "SetAOPEnabled") {
			t.Errorf("unneeded write %s", c)
		}
	}
}

func TestProvisionFront_RandomLabelInZone(t *testing.T) {
	m := NewMockCFClient("example.com")
	opts := mkOpts(t.TempDir())
	opts.Hostname, opts.Zone = "", "example.com"
	rec, err := NewProvider(m).ProvisionFront(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	label := strings.TrimSuffix(rec.Hostname, ".example.com")
	if len(label) != 10 || strings.Contains(label, ".") || label[0] < 'a' || label[0] > 'z' {
		t.Errorf("hostname = %q", rec.Hostname)
	}
}

// The apexOf bug: `x.eu.org` and `.co.uk` names used to resolve to the
// public suffix.
func TestFindZone_WalksLabels(t *testing.T) {
	m := &MockCFClient{Zones: []Zone{
		{ID: "z1", Name: "example.co.uk", Status: "active"},
		{ID: "z2", Name: "me.eu.org", Status: "active"},
		{ID: "z3", Name: "pending.com", Status: "pending"},
	}}
	cases := map[string]string{
		"relay.example.co.uk":   "z1",
		"a.b.example.co.uk":     "z1",
		"example.co.uk":         "z1",
		"abc.me.eu.org":         "z2",
		"ABC.Me.EU.org.":        "z2",
		"deep.x.y.me.eu.org":    "z2",
		"nothing.example.org":   "",
		"relay.pending.com":     "",
		"relay.co.uk":           "",
		"not a host.example.uk": "",
	}
	for host, want := range cases {
		z, err := FindZone(context.Background(), m, []byte(testToken), host)
		if want == "" {
			if err == nil {
				t.Errorf("%s: found %s, want none", host, z.ID)
			}
			continue
		}
		if err != nil || z.ID != want {
			t.Errorf("%s: got %q %v, want %s", host, z.ID, err, want)
		}
	}
	// Most specific first, and never shorter than two labels.
	m.Calls = nil
	_, _ = FindZone(context.Background(), m, []byte(testToken), "a.b.example.co.uk")
	want := []string{"LookupZone(a.b.example.co.uk)", "LookupZone(b.example.co.uk)", "LookupZone(example.co.uk)"}
	if !reflect.DeepEqual(m.Calls, want) {
		t.Errorf("lookups = %v", m.Calls)
	}
}

func TestProvisionFront_Validation(t *testing.T) {
	bad := map[string]func(*CloudflareOpts){
		"no token":       func(o *CloudflareOpts) { o.CFTokenSecret = nil },
		"no out dir":     func(o *CloudflareOpts) { o.OutDir = "" },
		"no origin":      func(o *CloudflareOpts) { o.OriginIP = "" },
		"v6 as v4":       func(o *CloudflareOpts) { o.OriginIP = "2a01::1" },
		"v4 as v6":       func(o *CloudflareOpts) { o.OriginIPv6 = "1.2.3.4" },
		"no host/zone":   func(o *CloudflareOpts) { o.Hostname = "" },
		"bad host":       func(o *CloudflareOpts) { o.Hostname = `x".example.com` },
		"wildcard":       func(o *CloudflareOpts) { o.Hostname = "*.example.com" },
		"bad path":       func(o *CloudflareOpts) { o.OriginPath = "ws" },
		"REALITY port":   func(o *CloudflareOpts) { o.OriginPort = 443 },
		"ws-in port":     func(o *CloudflareOpts) { o.OriginPort = relayports.For("websocket-tls").Port },
		"port too large": func(o *CloudflareOpts) { o.OriginPort = 70000 },
	}
	for name, mutate := range bad {
		m := NewMockCFClient("example.com")
		o := mkOpts(t.TempDir())
		mutate(&o)
		if _, err := NewProvider(m).ProvisionFront(context.Background(), o); err == nil {
			t.Errorf("%s: accepted", name)
		}
		for _, c := range m.Calls {
			if !strings.HasPrefix(c, "LookupZone") {
				t.Errorf("%s: refused input still reached %s", name, c)
			}
		}
	}
}

// Every step that can fail leaves the zone exactly as it was, and the
// out dir empty.
func TestProvisionFront_RollsBackEveryStep(t *testing.T) {
	steps := []string{
		"IssueOriginCert", "UploadAOPCert", "AOPEnabled", "SetAOPEnabled",
		"GetZoneSetting", "SetZoneSetting", "EnsureProxiedRecords", "EnsureOriginRule",
	}
	for _, step := range steps {
		t.Run(step, func(t *testing.T) {
			m := NewMockCFClient("example.com")
			before := snap(m)
			m.FailOn = map[string]error{step: errors.New("boom " + testToken)}
			dir := t.TempDir()
			_, err := NewProvider(m).ProvisionFront(context.Background(), mkOpts(dir))
			var pe *ProvisionError
			if !errors.As(err, &pe) {
				t.Fatalf("want *ProvisionError, got %v", err)
			}
			if len(pe.Left) != 0 {
				t.Errorf("rollback left %v", pe.Left)
			}
			if strings.Contains(err.Error(), testToken) {
				t.Fatalf("token in error: %v", err)
			}
			m.FailOn = nil
			if after := snap(m); !reflect.DeepEqual(before, after) {
				t.Errorf("zone changed:\n before %+v\n after  %+v", before, after)
			}
			if ents, _ := os.ReadDir(dir); len(ents) != 0 {
				t.Errorf("files left: %v", ents)
			}
		})
	}
}

// Only the second setting fails: the first, already changed, goes back.
func TestProvisionFront_RollsBackAChangedSetting(t *testing.T) {
	m := NewMockCFClient("example.com")
	before := snap(m)
	m.FailSetting = map[string]error{"websockets": errors.New("nope")}
	if _, err := NewProvider(m).ProvisionFront(context.Background(), mkOpts(t.TempDir())); err == nil {
		t.Fatal("want failure")
	}
	m.FailSetting = nil
	if after := snap(m); !reflect.DeepEqual(before, after) {
		t.Errorf("ssl not put back: %v", m.Settings)
	}
}

func TestProvisionFront_RefusesRecordsItDidNotMake(t *testing.T) {
	for name, rec := range map[string]DNSRecord{
		"dns-only": {ID: "x", Type: "A", Name: "momsroute.example.com", Content: "5.75.1.2", Proxied: new(bool)},
		"elsewhere": {ID: "y", Type: "A", Name: "momsroute.example.com", Content: "9.9.9.9", Proxied: func() *bool {
			b := true
			return &b
		}()},
	} {
		m := NewMockCFClient("example.com")
		m.Records = map[string][]DNSRecord{"zone-example.com": {rec}}
		_, err := NewProvider(m).ProvisionFront(context.Background(), mkOpts(t.TempDir()))
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
		if len(m.Records["zone-example.com"]) != 1 || m.Records["zone-example.com"][0].ID != rec.ID {
			t.Errorf("%s: the existing record was touched: %v", name, m.Records)
		}
	}
}

func TestProvisionFront_ReusesItsOwnRecord(t *testing.T) {
	m := NewMockCFClient("example.com")
	p := NewProvider(m)
	o := mkOpts(t.TempDir())
	if _, err := p.ProvisionFront(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	rec, err := p.ProvisionFront(context.Background(), o)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if len(rec.DNSRecordIDs) != 0 || len(m.Records["zone-example.com"]) != 2 {
		t.Errorf("second run created records: %v", rec.DNSRecordIDs)
	}
	if len(m.OriginRules["zone-example.com"]) != 1 {
		t.Errorf("origin rules = %v", m.OriginRules)
	}
}

// The publisher's own origin rules are never touched.
func TestOriginRule_KeepsOtherRules(t *testing.T) {
	m := NewMockCFClient("example.com")
	m.OriginRules = map[string][]MockOriginRule{"zone-example.com": {{Ref: "theirs", Hostname: "www.example.com", Port: 8080}}}
	p := NewProvider(m)
	rec, err := p.ProvisionFront(context.Background(), mkOpts(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Remove(context.Background(), []byte(testToken), rec); err != nil {
		t.Fatal(err)
	}
	if got := m.OriginRules["zone-example.com"]; len(got) != 1 || got[0].Ref != "theirs" {
		t.Errorf("rules after removal = %v", got)
	}
}

func TestRemove_TakesEverythingDownAndRestoresSettings(t *testing.T) {
	m := NewMockCFClient("example.com")
	before := snap(m)
	p := NewProvider(m)
	rec, err := p.ProvisionFront(context.Background(), mkOpts(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	rep, err := p.Remove(context.Background(), []byte(testToken), rec)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Complete {
		t.Fatalf("report = %+v", rep)
	}
	if after := snap(m); !reflect.DeepEqual(before, after) {
		t.Errorf("zone not back to start:\n before %+v\n after  %+v", before, after)
	}
	for _, f := range []string{rec.OriginCACertPath, rec.OriginCAPrivPath, rec.AOPCACertPath} {
		if _, err := os.Stat(f); err == nil {
			t.Errorf("%s left", f)
		}
	}
}

// A zone with ECH off: Daal turns it on, records that it did, waits
// for the HTTPS record to carry the config, and Remove turns it off
// again.
func TestProvisionFront_TurnsECHOnAndWaitsForTheRecord(t *testing.T) {
	defer shrinkECHWait(t)()
	m := NewMockCFClient("example.com")
	z := "zone-example.com"
	m.Settings[z]["ech"] = "off"
	before := snap(m)
	p := NewProvider(m)
	opts := mkOpts(t.TempDir())
	f := &MockECHFetcher{ConfigList: testECHConfigList(t, "cloudflare-ech.com"), Zone: m, ZoneID: z, LagCalls: 2}
	opts.ECH = f
	rec, err := p.ProvisionFront(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if m.Settings[z]["ech"] != "on" || rec.PriorSettings["ech"] != "off" {
		t.Errorf("ech setting = %q, prior = %v", m.Settings[z]["ech"], rec.PriorSettings)
	}
	if len(f.Calls) != 3 {
		t.Errorf("DoH reads = %d, want 3 (two lagging, then the record)", len(f.Calls))
	}
	if !rec.ECH.Published || rec.ECH.ConfigListB64 == "" || rec.ECH.ZoneSetting != "on" || rec.ECH.Error != "" {
		t.Errorf("ech = %+v", rec.ECH)
	}
	if _, err := p.Remove(context.Background(), []byte(testToken), rec); err != nil {
		t.Fatal(err)
	}
	if after := snap(m); !reflect.DeepEqual(before, after) {
		t.Errorf("zone not back to start:\n before %+v\n after  %+v", before, after)
	}
}

// The record never comes: a bounded number of reads, then the posture
// says unpublished and provisioning still succeeds (the caller decides).
func TestProvisionFront_ECHNeverPublishedIsBounded(t *testing.T) {
	defer shrinkECHWait(t)()
	m := NewMockCFClient("example.com")
	p := NewProvider(m)
	opts := mkOpts(t.TempDir())
	f := &MockECHFetcher{}
	opts.ECH = f
	rec, err := p.ProvisionFront(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Calls) != ECHPublishTries || rec.ECH.Published {
		t.Errorf("reads = %d (want %d), ech = %+v", len(f.Calls), ECHPublishTries, rec.ECH)
	}
}

// Cloudflare refuses the ECH setting: not fatal, said in the posture,
// and nothing recorded to restore.
func TestProvisionFront_ECHSettingRefused(t *testing.T) {
	defer shrinkECHWait(t)()
	m := NewMockCFClient("example.com")
	z := "zone-example.com"
	m.Settings[z]["ech"] = "off"
	m.FailSetting = map[string]error{"ech": errors.New("403 forbidden")}
	p := NewProvider(m)
	opts := mkOpts(t.TempDir())
	opts.ECH = &MockECHFetcher{ConfigList: testECHConfigList(t, "cloudflare-ech.com"), Zone: m, ZoneID: z}
	rec, err := p.ProvisionFront(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := rec.PriorSettings["ech"]; ok || rec.ECH.Published || rec.ECH.ZoneSetting != "off" {
		t.Errorf("prior = %v, ech = %+v", rec.PriorSettings, rec.ECH)
	}
	if !strings.Contains(rec.ECH.Error, "turn ECH on") {
		t.Errorf("ech error = %q", rec.ECH.Error)
	}
}

func shrinkECHWait(t *testing.T) func() {
	t.Helper()
	d := ECHPublishDelay
	ECHPublishDelay = time.Millisecond
	return func() { ECHPublishDelay = d }
}

// A setting the publisher changed after the build is theirs.
func TestRemove_KeepsASettingThePublisherChanged(t *testing.T) {
	m := NewMockCFClient("example.com")
	p := NewProvider(m)
	rec, err := p.ProvisionFront(context.Background(), mkOpts(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	m.Settings["zone-example.com"]["ssl"] = "full"
	if _, err := p.Remove(context.Background(), []byte(testToken), rec); err != nil {
		t.Fatal(err)
	}
	if got := m.Settings["zone-example.com"]["ssl"]; got != "full" {
		t.Errorf("ssl = %q, want the publisher's full", got)
	}
	if got := m.Settings["zone-example.com"]["websockets"]; got != "off" {
		t.Errorf("websockets = %q, want restored off", got)
	}
}

// One failing step does not stop the others, and is reported.
func TestRemove_ContinuesPastAFailure(t *testing.T) {
	m := NewMockCFClient("example.com")
	p := NewProvider(m)
	rec, err := p.ProvisionFront(context.Background(), mkOpts(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	m.FailOn = map[string]error{"RevokeOriginCert": errors.New("down " + testToken)}
	rep, err := p.Remove(context.Background(), []byte(testToken), rec)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Complete {
		t.Fatal("complete despite a failure")
	}
	states := map[string]string{}
	for _, s := range rep.Steps {
		states[s.Name] = s.State
		if strings.Contains(s.Detail, testToken) {
			t.Errorf("token in report: %s", s.Detail)
		}
	}
	if states["origin_certificate"] != "failed" || states["dns_records"] != "done" || states["origin_rule"] != "done" || states["origin_pull_certificate"] != "done" {
		t.Errorf("states = %v", states)
	}
	// Files stay when the certificate they belong to was not revoked.
	if _, err := os.Stat(rec.OriginCAPrivPath); err != nil {
		t.Errorf("key file removed although the certificate is still live: %v", err)
	}
}

func TestVerifyPosture(t *testing.T) {
	m := NewMockCFClient("example.com")
	p := NewProvider(m)
	opts := mkOpts(t.TempDir())
	rec, err := p.ProvisionFront(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	rec.FirewallID = "777"
	ech := &MockECHFetcher{ConfigList: testECHConfigList(t, "cloudflare-ech.com")}
	r, err := p.VerifyPosture(context.Background(), []byte(testToken), rec, ech)
	if err != nil {
		t.Fatal(err)
	}
	if !r.OriginCAFingerprintMatch || !r.AOPEnabled || !r.SSLStrict || !r.WebSockets || !r.OriginRule || !r.DNSProxiedOnly || !r.NameHidden {
		t.Errorf("posture = %+v", r)
	}
	if r.OnlyCloudflare || r.FirewallChecked {
		t.Error("the Cloudflare side alone must not claim the firewall half")
	}
	// Drift: ECH off, rule gone.
	m.Settings["zone-example.com"]["ech"] = "off"
	m.OriginRules = nil
	r, err = p.VerifyPosture(context.Background(), []byte(testToken), rec, ech)
	if err != nil {
		t.Fatal(err)
	}
	if r.NameHidden || r.OriginRule || !strings.Contains(r.Notes, "drift") {
		t.Errorf("drift not seen: %+v", r)
	}
}

func TestRotateHostname_SameZone(t *testing.T) {
	m := NewMockCFClient("example.com")
	p := NewProvider(m)
	rec, err := p.ProvisionFront(context.Background(), mkOpts(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	oldRef := rec.OriginRuleRef
	zoneID, route, err := p.RotateHostname(context.Background(), []byte(testToken), rec, "fresh.example.com", "5.75.1.2", "2a01:4f8::1")
	if err != nil {
		t.Fatal(err)
	}
	if zoneID != "zone-example.com" || route != "" || rec.Hostname != "fresh.example.com" || rec.OriginRuleRef == oldRef {
		t.Errorf("rotate: zone=%s route=%q rec=%+v", zoneID, route, rec)
	}
	rules := m.OriginRules["zone-example.com"]
	if len(rules) != 1 || rules[0].Hostname != "fresh.example.com" {
		t.Errorf("rules = %+v", rules)
	}
	for _, r := range m.Records["zone-example.com"] {
		if r.Name != "fresh.example.com" {
			t.Errorf("old record left: %+v", r)
		}
	}
}

// The old rotate verb passes only the hostname: records are found by
// content, the rule by its derived ref.
func TestRotateHostname_FromAHostnameOnlyRecord(t *testing.T) {
	m := NewMockCFClient("example.com")
	p := NewProvider(m)
	full, err := p.ProvisionFront(context.Background(), mkOpts(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	bare := &FrontRecord{Hostname: full.Hostname, ZoneID: full.ZoneID}
	if _, _, err := p.RotateHostname(context.Background(), []byte(testToken), bare, "next.example.com", "5.75.1.2", "2a01:4f8::1"); err != nil {
		t.Fatal(err)
	}
	if rules := m.OriginRules["zone-example.com"]; len(rules) != 1 || rules[0].Hostname != "next.example.com" {
		t.Errorf("rules = %+v", rules)
	}
	for _, r := range m.Records["zone-example.com"] {
		if r.Name == full.Hostname {
			t.Errorf("old record left: %+v", r)
		}
	}
}

func TestRotateHostname_RefusesAnotherZone(t *testing.T) {
	m := NewMockCFClient("example.com")
	m.Zones = append(m.Zones, Zone{ID: "zone-other.org", Name: "other.org", Status: "active"})
	p := NewProvider(m)
	rec, err := p.ProvisionFront(context.Background(), mkOpts(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.RotateHostname(context.Background(), []byte(testToken), rec, "x.other.org", "5.75.1.2", ""); !errors.Is(err, ErrCrossZoneRotation) {
		t.Fatalf("want ErrCrossZoneRotation, got %v", err)
	}
}

func TestRotateOrigin_RePointsInPlace(t *testing.T) {
	m := NewMockCFClient("example.com")
	p := NewProvider(m)
	rec, err := p.ProvisionFront(context.Background(), mkOpts(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, r := range m.Records["zone-example.com"] {
		ids[r.ID] = true
	}
	if err := p.RotateOrigin(context.Background(), []byte(testToken), rec, "5.75.9.9", ""); err != nil {
		t.Fatal(err)
	}
	recs := m.Records["zone-example.com"]
	if len(recs) != 1 || recs[0].Type != "A" || recs[0].Content != "5.75.9.9" || !ids[recs[0].ID] {
		t.Errorf("records = %+v (want the same A record re-pointed, AAAA to the old relay gone)", recs)
	}
	if rec.OriginRuleRef != originRuleRef(rec.Hostname) {
		t.Error("origin rule ref changed")
	}
}

func TestRotatePublicPath_IsGoneWithTheWorker(t *testing.T) {
	p := NewProvider(NewMockCFClient("example.com"))
	if _, _, err := p.RotatePublicPath(context.Background(), []byte(testToken), "acct", &FrontRecord{Hostname: "a.example.com"}, ""); !errors.Is(err, ErrWorkerRemoved) {
		t.Fatalf("got %v", err)
	}
}

func TestNoWorkerCodeLeft(t *testing.T) {
	if _, err := os.Stat("worker.go"); err == nil {
		t.Fatal("worker.go is back (decision D-5)")
	}
	ents, _ := os.ReadDir(".")
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), "_test.go") || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		b, _ := os.ReadFile(e.Name())
		for _, bad := range []string{"/workers/scripts/\"+", "UploadWorkerScript", "BindWorkerRoute", "addEventListener"} {
			if strings.Contains(string(b), bad) {
				t.Errorf("%s still calls the Worker API (%s)", e.Name(), bad)
			}
		}
	}
}
