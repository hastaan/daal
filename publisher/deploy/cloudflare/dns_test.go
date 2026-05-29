package cloudflare

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestCheckAndEnsureDNS_HappyPathV4Only(t *testing.T) {
	cf := &MockCFClient{}
	chk, err := CheckAndEnsureDNS(context.Background(), cf, []byte("token"), "zone-1", "host.example.com", "5.75.1.2", "")
	if err != nil {
		t.Fatal(err)
	}
	if chk.DNSOnlyPresent {
		t.Error("DNSOnlyPresent should be false")
	}
	if !chk.ProxiedRecordsEnsured {
		t.Error("ProxiedRecordsEnsured should be true")
	}
	if !strings.Contains(chk.Notes, "proxied A") || strings.Contains(chk.Notes, "AAAA") {
		t.Errorf("Notes = %q (should mention A only when no v6)", chk.Notes)
	}
}

func TestCheckAndEnsureDNS_HappyPathV4PlusV6(t *testing.T) {
	cf := &MockCFClient{}
	chk, err := CheckAndEnsureDNS(context.Background(), cf, []byte("token"), "zone-1", "host.example.com", "5.75.1.2", "2a01::1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(chk.Notes, "AAAA") {
		t.Errorf("Notes should mention AAAA when v6 supplied: %q", chk.Notes)
	}
}

func TestCheckAndEnsureDNS_DNSOnlyRecordRejected(t *testing.T) {
	cf := &MockCFClient{EnsureRecordsErr: ErrDNSOnlyRecordPresent}
	chk, err := CheckAndEnsureDNS(context.Background(), cf, []byte("token"), "zone-1", "host.example.com", "5.75.1.2", "")
	if !errors.Is(err, ErrDNSOnlyRecordPresent) {
		t.Fatalf("want ErrDNSOnlyRecordPresent, got %v", err)
	}
	if !chk.DNSOnlyPresent {
		t.Error("DNSOnlyPresent should be true")
	}
	if chk.ProxiedRecordsEnsured {
		t.Error("ProxiedRecordsEnsured should be false on DNS-only refusal")
	}
}

func TestCheckAndEnsureDNS_GenericErrorPropagates(t *testing.T) {
	cf := &MockCFClient{EnsureRecordsErr: errors.New("rate limit")}
	_, err := CheckAndEnsureDNS(context.Background(), cf, []byte("token"), "zone-1", "host.example.com", "5.75.1.2", "")
	if err == nil {
		t.Fatal("want error")
	}
	if errors.Is(err, ErrDNSOnlyRecordPresent) {
		t.Errorf("generic error should NOT be classified as ErrDNSOnlyRecordPresent: %v", err)
	}
}

func TestCheckAndEnsureDNS_Validation(t *testing.T) {
	cf := &MockCFClient{}
	cases := []struct{ zone, host, v4 string }{
		{"", "h.example.com", "5.75.1.2"},
		{"z", "", "5.75.1.2"},
		{"z", "h.example.com", ""},
	}
	for _, c := range cases {
		_, err := CheckAndEnsureDNS(context.Background(), cf, []byte("t"), c.zone, c.host, c.v4, "")
		if err == nil {
			t.Errorf("want validation error for (%q,%q,%q)", c.zone, c.host, c.v4)
		}
	}
}
