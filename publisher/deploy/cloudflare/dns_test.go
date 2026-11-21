package cloudflare

import (
	"context"
	"errors"
	"testing"
)

func TestCheckAndEnsureDNS_HappyPath(t *testing.T) {
	m := NewMockCFClient("example.com")
	got, err := CheckAndEnsureDNS(context.Background(), m, []byte(testToken), "zone-example.com", "a.example.com", "5.75.1.2", "2a01::1")
	if err != nil {
		t.Fatal(err)
	}
	if !got.ProxiedRecordsEnsured || got.DNSOnlyPresent || len(got.CreatedIDs) != 2 {
		t.Errorf("got %+v", got)
	}
}

func TestCheckAndEnsureDNS_DNSOnlyRecordRejected(t *testing.T) {
	m := NewMockCFClient("example.com")
	m.Records = map[string][]DNSRecord{"zone-example.com": {{ID: "r", Type: "A", Name: "a.example.com", Content: "1.1.1.1", Proxied: new(bool)}}}
	got, err := CheckAndEnsureDNS(context.Background(), m, []byte(testToken), "zone-example.com", "a.example.com", "5.75.1.2", "")
	if !errors.Is(err, ErrDNSOnlyRecordPresent) || !got.DNSOnlyPresent {
		t.Fatalf("got %+v %v", got, err)
	}
}

func TestCheckAndEnsureDNS_Validation(t *testing.T) {
	m := NewMockCFClient("example.com")
	if _, err := CheckAndEnsureDNS(context.Background(), m, []byte(testToken), "", "a.example.com", "1.1.1.1", ""); err == nil {
		t.Error("empty zone accepted")
	}
}
