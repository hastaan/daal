package cloudflare

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
)

// MockCFClient is an in-memory Cloudflare: zones, settings, DNS records,
// origin rules, Origin CA and origin-pull certificates. Tests drive the
// real Provider against it and then read its state back, so a rollback
// test can assert that the zone looks exactly as it did before.
//
// It never stores the token. Calls records method names and non-secret
// arguments in order.
type MockCFClient struct {
	mu sync.Mutex

	Calls []string

	// Token
	TokenID     string // default "tok-1"
	TokenState  string // default "active"
	VerifyErr   error
	ProbeAnswer map[string]ProbeResult // path → answer; absent paths are ProbeDenied
	ProbeErr    map[string]error

	// Zones the token can see.
	Zones []Zone

	// Live state, keyed by zone id.
	Settings    map[string]map[string]string
	AOPOn       map[string]bool
	AOPCerts    map[string]map[string]string // zone → cert id → cert PEM
	Records     map[string][]DNSRecord
	OriginRules map[string][]MockOriginRule
	OriginCerts map[string][]string // cert id → hostnames

	// FailOn makes the named method return the error (e.g.
	// "EnsureOriginRule"). FailSetting fails SetZoneSetting for one
	// setting name.
	FailOn      map[string]error
	FailSetting map[string]error

	// IssueCertPEM overrides the certificate the mock issues.
	IssueCertPEM []byte

	next int
}

// MockOriginRule is one rule in a zone's http_request_origin entrypoint.
type MockOriginRule struct {
	Ref      string
	Hostname string
	Port     int
}

// NewMockCFClient returns a mock whose token sees exactly one active
// zone and holds exactly the five permissions: every probe CheckToken
// needs answers allowed, every probe of something more answers denied.
func NewMockCFClient(zoneName string) *MockCFClient {
	m := &MockCFClient{}
	z := Zone{ID: "zone-" + zoneName, Name: zoneName, Status: "active", AccountID: "acct-1"}
	m.Zones = []Zone{z}
	m.ProbeAnswer = map[string]ProbeResult{}
	for _, p := range requiredProbes(z) {
		m.ProbeAnswer[p.Path] = ProbeAllowed
	}
	// No origin ruleset yet on a fresh zone.
	m.ProbeAnswer[originEntrypointPath(z.ID)] = ProbeNotFound
	m.Settings = map[string]map[string]string{z.ID: {"ssl": "flexible", "websockets": "off", "ech": "on"}}
	return m
}

func (m *MockCFClient) record(format string, args ...any) {
	m.Calls = append(m.Calls, fmt.Sprintf(format, args...))
}

func (m *MockCFClient) fail(name string) error {
	if m.FailOn == nil {
		return nil
	}
	return m.FailOn[name]
}

func (m *MockCFClient) id(prefix string) string {
	m.next++
	return fmt.Sprintf("%s-%d", prefix, m.next)
}

func (m *MockCFClient) init() {
	if m.Settings == nil {
		m.Settings = map[string]map[string]string{}
	}
	if m.AOPOn == nil {
		m.AOPOn = map[string]bool{}
	}
	if m.AOPCerts == nil {
		m.AOPCerts = map[string]map[string]string{}
	}
	if m.Records == nil {
		m.Records = map[string][]DNSRecord{}
	}
	if m.OriginRules == nil {
		m.OriginRules = map[string][]MockOriginRule{}
	}
	if m.OriginCerts == nil {
		m.OriginCerts = map[string][]string{}
	}
}

func (m *MockCFClient) VerifyToken(_ context.Context, _ []byte) (TokenStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.record("VerifyToken")
	if m.VerifyErr != nil {
		return TokenStatus{}, m.VerifyErr
	}
	st := TokenStatus{ID: m.TokenID, Status: m.TokenState}
	if st.ID == "" {
		st.ID = "tok-1"
	}
	if st.Status == "" {
		st.Status = "active"
	}
	return st, nil
}

func (m *MockCFClient) ListZones(_ context.Context, _ []byte) ([]Zone, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.record("ListZones")
	if err := m.fail("ListZones"); err != nil {
		return nil, err
	}
	return append([]Zone(nil), m.Zones...), nil
}

func (m *MockCFClient) LookupZone(_ context.Context, _ []byte, name string) (Zone, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.record("LookupZone(%s)", name)
	if err := m.fail("LookupZone"); err != nil {
		return Zone{}, false, err
	}
	for _, z := range m.Zones {
		if z.Name == name {
			return z, true, nil
		}
	}
	return Zone{}, false, nil
}

func (m *MockCFClient) ProbeRead(_ context.Context, _ []byte, path string) (ProbeResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.record("ProbeRead(%s)", path)
	if err := m.ProbeErr[path]; err != nil {
		return ProbeDenied, err
	}
	if r, ok := m.ProbeAnswer[path]; ok {
		return r, nil
	}
	return ProbeDenied, nil
}

func (m *MockCFClient) IssueOriginCert(_ context.Context, _ []byte, hostnames []string, days int) (OriginCert, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.init()
	m.record("IssueOriginCert(%s,%d)", strings.Join(hostnames, " "), days)
	if err := m.fail("IssueOriginCert"); err != nil {
		return OriginCert{}, err
	}
	id := m.id("ocert")
	m.OriginCerts[id] = append([]string(nil), hostnames...)
	cert := m.IssueCertPEM
	if cert == nil {
		cert = []byte("-----BEGIN CERTIFICATE-----\nMOCK " + id + "\n-----END CERTIFICATE-----\n")
	}
	sum := sha256.Sum256(cert)
	return OriginCert{
		ID:             id,
		CertPEM:        cert,
		KeyPEM:         []byte("-----BEGIN EC PRIVATE KEY-----\nMOCK\n-----END EC PRIVATE KEY-----\n"),
		FingerprintHex: hex.EncodeToString(sum[:]),
	}, nil
}

func (m *MockCFClient) RevokeOriginCert(_ context.Context, _ []byte, certID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.init()
	m.record("RevokeOriginCert(%s)", certID)
	if err := m.fail("RevokeOriginCert"); err != nil {
		return err
	}
	delete(m.OriginCerts, certID)
	return nil
}

func (m *MockCFClient) UploadAOPCert(_ context.Context, _ []byte, zoneID string, certPEM, keyPEM []byte) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.init()
	m.record("UploadAOPCert(%s)", zoneID)
	if err := m.fail("UploadAOPCert"); err != nil {
		return "", err
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return "", fmt.Errorf("mock: empty certificate or key")
	}
	id := m.id("aop")
	if m.AOPCerts[zoneID] == nil {
		m.AOPCerts[zoneID] = map[string]string{}
	}
	m.AOPCerts[zoneID][id] = string(certPEM)
	return id, nil
}

func (m *MockCFClient) DeleteAOPCert(_ context.Context, _ []byte, zoneID, certID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.init()
	m.record("DeleteAOPCert(%s,%s)", zoneID, certID)
	if err := m.fail("DeleteAOPCert"); err != nil {
		return err
	}
	delete(m.AOPCerts[zoneID], certID)
	return nil
}

func (m *MockCFClient) SetAOPEnabled(_ context.Context, _ []byte, zoneID string, enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.init()
	m.record("SetAOPEnabled(%s,%v)", zoneID, enabled)
	if err := m.fail("SetAOPEnabled"); err != nil {
		return err
	}
	m.AOPOn[zoneID] = enabled
	return nil
}

func (m *MockCFClient) AOPEnabled(_ context.Context, _ []byte, zoneID string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.init()
	m.record("AOPEnabled(%s)", zoneID)
	if err := m.fail("AOPEnabled"); err != nil {
		return false, err
	}
	return m.AOPOn[zoneID], nil
}

func (m *MockCFClient) GetZoneSetting(_ context.Context, _ []byte, zoneID, name string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.init()
	m.record("GetZoneSetting(%s,%s)", zoneID, name)
	if err := m.fail("GetZoneSetting"); err != nil {
		return "", err
	}
	return m.Settings[zoneID][name], nil
}

func (m *MockCFClient) SetZoneSetting(_ context.Context, _ []byte, zoneID, name, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.init()
	m.record("SetZoneSetting(%s,%s,%s)", zoneID, name, value)
	if err := m.fail("SetZoneSetting"); err != nil {
		return err
	}
	if err := m.FailSetting[name]; err != nil {
		return err
	}
	if m.Settings[zoneID] == nil {
		m.Settings[zoneID] = map[string]string{}
	}
	m.Settings[zoneID][name] = value
	return nil
}

func (m *MockCFClient) ListDNSRecords(_ context.Context, _ []byte, zoneID, hostname string) ([]DNSRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.init()
	m.record("ListDNSRecords(%s,%s)", zoneID, hostname)
	if err := m.fail("ListDNSRecords"); err != nil {
		return nil, err
	}
	var out []DNSRecord
	for _, r := range m.Records[zoneID] {
		if r.Name == hostname {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *MockCFClient) EnsureProxiedRecords(_ context.Context, _ []byte, zoneID, hostname, v4, v6 string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.init()
	m.record("EnsureProxiedRecords(%s,%s,%s,%s)", zoneID, hostname, v4, v6)
	if err := m.fail("EnsureProxiedRecords"); err != nil {
		return nil, err
	}
	want := map[string]string{"A": v4}
	if v6 != "" {
		want["AAAA"] = v6
	}
	for _, r := range m.Records[zoneID] {
		if r.Name != hostname || (r.Type != "A" && r.Type != "AAAA") {
			continue
		}
		if !r.proxied() {
			return nil, ErrDNSOnlyRecordPresent
		}
		if c, ok := want[r.Type]; ok && c != r.Content {
			return nil, ErrHostnameInUse
		}
	}
	var created []string
	for _, typ := range []string{"A", "AAAA"} {
		content, ok := want[typ]
		if !ok {
			continue
		}
		exists := false
		for _, r := range m.Records[zoneID] {
			if r.Name == hostname && r.Type == typ {
				exists = true
			}
		}
		if exists {
			continue
		}
		t := true
		id := m.id("rec")
		m.Records[zoneID] = append(m.Records[zoneID], DNSRecord{ID: id, Type: typ, Name: hostname, Content: content, Proxied: &t})
		created = append(created, id)
	}
	return created, nil
}

func (m *MockCFClient) SetDNSRecordContent(_ context.Context, _ []byte, zoneID, recordID, content string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.init()
	m.record("SetDNSRecordContent(%s,%s,%s)", zoneID, recordID, content)
	if err := m.fail("SetDNSRecordContent"); err != nil {
		return err
	}
	for i, r := range m.Records[zoneID] {
		if r.ID == recordID {
			m.Records[zoneID][i].Content = content
			return nil
		}
	}
	return fmt.Errorf("mock: no record %s", recordID)
}

func (m *MockCFClient) DeleteDNSRecord(_ context.Context, _ []byte, zoneID, recordID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.init()
	m.record("DeleteDNSRecord(%s,%s)", zoneID, recordID)
	if err := m.fail("DeleteDNSRecord"); err != nil {
		return err
	}
	kept := m.Records[zoneID][:0]
	for _, r := range m.Records[zoneID] {
		if r.ID != recordID {
			kept = append(kept, r)
		}
	}
	m.Records[zoneID] = kept
	return nil
}

func (m *MockCFClient) EnsureOriginRule(_ context.Context, _ []byte, zoneID, ref, hostname string, port int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.init()
	m.record("EnsureOriginRule(%s,%s,%s,%d)", zoneID, ref, hostname, port)
	if err := m.fail("EnsureOriginRule"); err != nil {
		return err
	}
	var next []MockOriginRule
	for _, r := range m.OriginRules[zoneID] {
		if r.Ref != ref {
			next = append(next, r)
		}
	}
	m.OriginRules[zoneID] = append(next, MockOriginRule{Ref: ref, Hostname: hostname, Port: port})
	return nil
}

func (m *MockCFClient) RemoveOriginRule(_ context.Context, _ []byte, zoneID, ref string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.init()
	m.record("RemoveOriginRule(%s,%s)", zoneID, ref)
	if err := m.fail("RemoveOriginRule"); err != nil {
		return err
	}
	var next []MockOriginRule
	for _, r := range m.OriginRules[zoneID] {
		if r.Ref != ref {
			next = append(next, r)
		}
	}
	m.OriginRules[zoneID] = next
	return nil
}

func (m *MockCFClient) OriginRule(_ context.Context, _ []byte, zoneID, ref string) (string, int, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.init()
	m.record("OriginRule(%s,%s)", zoneID, ref)
	if err := m.fail("OriginRule"); err != nil {
		return "", 0, false, err
	}
	for _, r := range m.OriginRules[zoneID] {
		if r.Ref == ref {
			return r.Hostname, r.Port, true, nil
		}
	}
	return "", 0, false, nil
}

// MockECHFetcher answers FetchECH from fixed values.
//
// Zone and ZoneID, when set, model Cloudflare: the hostname publishes
// ConfigList only while that zone's `ech` setting is "on". LagCalls
// models the publishing delay: that many reads after the setting first
// reads "on" still find no ech parameter.
type MockECHFetcher struct {
	ConfigList []byte
	Resolver   string
	Err        error
	Calls      []string

	Zone     *MockCFClient
	ZoneID   string
	LagCalls int
}

func (f *MockECHFetcher) FetchECH(_ context.Context, hostname string) ([]byte, string, error) {
	f.Calls = append(f.Calls, hostname)
	if f.Err != nil {
		return nil, "", f.Err
	}
	r := f.Resolver
	if r == "" {
		r = "mock-doh"
	}
	if f.Zone != nil && f.Zone.Settings[f.ZoneID]["ech"] != "on" {
		return nil, r, nil
	}
	if f.LagCalls > 0 {
		f.LagCalls--
		return nil, r, nil
	}
	return f.ConfigList, r, nil
}
