package cloudflare

import (
	"context"
	"fmt"
	"sync"
)

// MockCFClient is a deterministic test implementation of CFClient.
// Every call appends to Calls under a Mutex so concurrent tests
// observe a stable order; behaviour overrides plug in via the
// per-method *Override fields.
type MockCFClient struct {
	mu sync.Mutex

	Calls []string

	// Per-method behaviour. Nil means "happy path".
	IssueErr                error
	IssueCertPEM            []byte
	IssuePrivPEM            []byte
	IssueFingerprint        string
	EnableAOPErr            error
	FetchAOPClientErr       error
	FetchAOPClientPEM       []byte
	EnsureRecordsErr        error
	UploadWorkerErr         error
	UploadWorkerScriptID    string
	BindRouteErr            error
	BindRouteID             string
	LookupZoneErr           error
	LookupZoneIDOverride    string
	LookupAccountIDOverride string
	PostureErr              error
	Posture                 PostureReport

	// FRP-9 rotation surface mocks.
	RotatePathErr           error
	RotatePathRouteID       string
	RotateHostnameErr       error
	RotateHostnameZoneID    string
	RotateHostnameAccountID string
	RotateOriginErr         error
}

func (m *MockCFClient) record(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls = append(m.Calls, name)
}

func (m *MockCFClient) IssueOriginCert(_ context.Context, _ []byte, hostnames []string, _ int) ([]byte, []byte, string, error) {
	m.record(fmt.Sprintf("IssueOriginCert(%v)", hostnames))
	if m.IssueErr != nil {
		return nil, nil, "", m.IssueErr
	}
	cert := m.IssueCertPEM
	if cert == nil {
		cert = []byte("-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----\n")
	}
	priv := m.IssuePrivPEM
	if priv == nil {
		priv = []byte("-----BEGIN PRIVATE KEY-----\nMOCK\n-----END PRIVATE KEY-----\n")
	}
	fp := m.IssueFingerprint
	if fp == "" {
		fp = "ababababababababababababababababababababababababababababababab"
	}
	return cert, priv, fp, nil
}

func (m *MockCFClient) EnableAOP(_ context.Context, _ []byte, zoneID string) error {
	m.record(fmt.Sprintf("EnableAOP(%s)", zoneID))
	return m.EnableAOPErr
}

func (m *MockCFClient) FetchAOPClientCert(_ context.Context, _ []byte, zoneID string) ([]byte, error) {
	m.record(fmt.Sprintf("FetchAOPClientCert(%s)", zoneID))
	if m.FetchAOPClientErr != nil {
		return nil, m.FetchAOPClientErr
	}
	cert := m.FetchAOPClientPEM
	if cert == nil {
		cert = []byte("-----BEGIN CERTIFICATE-----\nMOCK-AOP-CLIENT\n-----END CERTIFICATE-----\n")
	}
	return cert, nil
}

func (m *MockCFClient) EnsureProxiedRecords(_ context.Context, _ []byte, zoneID, hostname, ipv4, ipv6 string) error {
	m.record(fmt.Sprintf("EnsureProxiedRecords(%s,%s,%s,%s)", zoneID, hostname, ipv4, ipv6))
	return m.EnsureRecordsErr
}

func (m *MockCFClient) UploadWorkerScript(_ context.Context, _ []byte, accountID, scriptName string, body []byte) (string, error) {
	m.record(fmt.Sprintf("UploadWorkerScript(%s,%s,len=%d)", accountID, scriptName, len(body)))
	if m.UploadWorkerErr != nil {
		return "", m.UploadWorkerErr
	}
	if m.UploadWorkerScriptID != "" {
		return m.UploadWorkerScriptID, nil
	}
	return scriptName, nil
}

func (m *MockCFClient) BindWorkerRoute(_ context.Context, _ []byte, zoneID, scriptName, pattern string) (string, error) {
	m.record(fmt.Sprintf("BindWorkerRoute(%s,%s,%s)", zoneID, scriptName, pattern))
	if m.BindRouteErr != nil {
		return "", m.BindRouteErr
	}
	if m.BindRouteID != "" {
		return m.BindRouteID, nil
	}
	return "route-" + zoneID + "-" + scriptName, nil
}

func (m *MockCFClient) LookupZoneID(_ context.Context, _ []byte, apex string) (string, string, error) {
	m.record(fmt.Sprintf("LookupZoneID(%s)", apex))
	if m.LookupZoneErr != nil {
		return "", "", m.LookupZoneErr
	}
	zone := m.LookupZoneIDOverride
	if zone == "" {
		zone = "zone-" + apex
	}
	acc := m.LookupAccountIDOverride
	if acc == "" {
		acc = "account-" + apex
	}
	return zone, acc, nil
}

func (m *MockCFClient) RotatePublicPath(_ context.Context, _ []byte, zoneID, oldRouteID, scriptName, hostname, newPublicPath, originPath string) (string, error) {
	m.record(fmt.Sprintf("RotatePublicPath(%s,%s,%s,%s,%s,%s)", zoneID, oldRouteID, scriptName, hostname, newPublicPath, originPath))
	if m.RotatePathErr != nil {
		return "", m.RotatePathErr
	}
	if m.RotatePathRouteID != "" {
		return m.RotatePathRouteID, nil
	}
	return "route-" + zoneID + "-rotated", nil
}

func (m *MockCFClient) RotateHostname(_ context.Context, _ []byte, oldRec *FrontRecord, newHostname, ipv4, ipv6 string) (string, string, error) {
	m.record(fmt.Sprintf("RotateHostname(%s->%s,%s,%s)", oldRec.Hostname, newHostname, ipv4, ipv6))
	if m.RotateHostnameErr != nil {
		return "", "", m.RotateHostnameErr
	}
	zone := m.RotateHostnameZoneID
	if zone == "" {
		zone = "zone-" + newHostname
	}
	acc := m.RotateHostnameAccountID
	if acc == "" {
		acc = "account-" + newHostname
	}
	return zone, acc, nil
}

func (m *MockCFClient) RotateOrigin(_ context.Context, _ []byte, zoneID, hostname, ipv4, ipv6 string) error {
	m.record(fmt.Sprintf("RotateOrigin(%s,%s,%s,%s)", zoneID, hostname, ipv4, ipv6))
	return m.RotateOriginErr
}

func (m *MockCFClient) VerifyPosture(_ context.Context, _ []byte, rec *FrontRecord) (PostureReport, error) {
	m.record(fmt.Sprintf("VerifyPosture(%s)", rec.Hostname))
	if m.PostureErr != nil {
		return PostureReport{}, m.PostureErr
	}
	if (m.Posture != PostureReport{}) {
		return m.Posture, nil
	}
	return PostureReport{
		OriginCAFingerprintMatch: true,
		AOPEnabled:               true,
		FirewallEdgeRangesFresh:  true,
		DNSProxiedOnly:           true,
	}, nil
}
