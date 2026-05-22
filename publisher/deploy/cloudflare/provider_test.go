package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func mkOpts(dir string) CloudflareOpts {
	return CloudflareOpts{
		Hostname:      "momsroute.example.com",
		OriginIP:      "5.75.1.2",
		OriginIPv6:    "2a01:4f8::1",
		PublicPath:    "/r/abcdefab",
		OriginPath:    "/ws",
		CFTokenSecret: []byte("secret-token"),
		OutDir:        dir,
	}
}

func TestProvisionFront_HappyPath(t *testing.T) {
	cf := &MockCFClient{}
	p := NewProvider(cf)
	rec, err := p.ProvisionFront(context.Background(), mkOpts(t.TempDir()))
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if rec.Hostname != "momsroute.example.com" {
		t.Errorf("hostname = %q", rec.Hostname)
	}
	if rec.ZoneID != "zone-example.com" {
		t.Errorf("zone = %q (mock returns zone-<apex>)", rec.ZoneID)
	}
	if rec.PublicPath != "/r/abcdefab" {
		t.Errorf("public path = %q", rec.PublicPath)
	}
	if rec.OriginPath != "/ws" {
		t.Errorf("origin path = %q", rec.OriginPath)
	}
	if rec.OriginCAFingerprint == "" {
		t.Error("origin CA fingerprint empty")
	}
	if !rec.AOPEnabled {
		t.Error("AOPEnabled should be true after happy path")
	}
	if rec.WorkerRouteID == "" {
		t.Error("worker route ID empty")
	}

	// Verify the orchestration order: zone lookup → cert →
	// AOP → AOP fetch → DNS → worker upload → route bind.
	wantOrder := []string{
		"LookupZoneID(",
		"IssueOriginCert(",
		"EnableAOP(",
		"FetchAOPClientCert(",
		"EnsureProxiedRecords(",
		"UploadWorkerScript(",
		"BindWorkerRoute(",
	}
	if len(cf.Calls) < len(wantOrder) {
		t.Fatalf("Calls = %v (too few)", cf.Calls)
	}
	for i, prefix := range wantOrder {
		if !strings.HasPrefix(cf.Calls[i], prefix) {
			t.Errorf("Calls[%d] = %q, want prefix %q", i, cf.Calls[i], prefix)
		}
	}
}

func TestProvisionFront_GeneratesRandomPath(t *testing.T) {
	cf := &MockCFClient{}
	p := NewProvider(cf)
	opts := mkOpts(t.TempDir())
	opts.PublicPath = ""
	rec, err := p.ProvisionFront(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(rec.PublicPath, "/r/") || len(rec.PublicPath) <= len("/r/") {
		t.Errorf("expected /r/<hex>, got %q", rec.PublicPath)
	}
}

func TestProvisionFront_RejectsEmptyHostname(t *testing.T) {
	p := NewProvider(&MockCFClient{})
	opts := mkOpts(t.TempDir())
	opts.Hostname = ""
	if _, err := p.ProvisionFront(context.Background(), opts); err == nil {
		t.Fatal("want error")
	}
}

func TestProvisionFront_RejectsEmptyOriginIP(t *testing.T) {
	p := NewProvider(&MockCFClient{})
	opts := mkOpts(t.TempDir())
	opts.OriginIP = ""
	if _, err := p.ProvisionFront(context.Background(), opts); err == nil {
		t.Fatal("want error")
	}
}

func TestProvisionFront_RejectsEmptyOriginPath(t *testing.T) {
	p := NewProvider(&MockCFClient{})
	opts := mkOpts(t.TempDir())
	opts.OriginPath = ""
	if _, err := p.ProvisionFront(context.Background(), opts); err == nil {
		t.Fatal("want error")
	}
}

func TestProvisionFront_RejectsEmptyToken(t *testing.T) {
	p := NewProvider(&MockCFClient{})
	opts := mkOpts(t.TempDir())
	opts.CFTokenSecret = nil
	if _, err := p.ProvisionFront(context.Background(), opts); err == nil {
		t.Fatal("want error")
	}
}

func TestProvisionFront_PropagatesDNSOnlyRecordError(t *testing.T) {
	cf := &MockCFClient{EnsureRecordsErr: ErrDNSOnlyRecordPresent}
	p := NewProvider(cf)
	_, err := p.ProvisionFront(context.Background(), mkOpts(t.TempDir()))
	if err == nil || !errors.Is(err, ErrDNSOnlyRecordPresent) {
		t.Fatalf("want wrapped ErrDNSOnlyRecordPresent, got %v", err)
	}
}

func TestApexOf(t *testing.T) {
	cases := []struct{ in, want string }{
		{"momsroute.example.com", "example.com"},
		{"example.com", "example.com"},
		{"a.b.c.d.example.com", "example.com"},
		{"co.uk", "co.uk"}, // single label edge; FRP-8 doesn't handle PSL
	}
	for _, c := range cases {
		if got := apexOf(c.in); got != c.want {
			t.Errorf("apexOf(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestProvider_VerifyPosture_Plumbing(t *testing.T) {
	cf := &MockCFClient{}
	p := NewProvider(cf)
	rec := &FrontRecord{Hostname: "momsroute.example.com"}
	rep, err := p.VerifyPosture(context.Background(), []byte("token"), rec)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OriginCAFingerprintMatch || !rep.AOPEnabled || !rep.FirewallEdgeRangesFresh || !rep.DNSProxiedOnly {
		t.Errorf("default mock posture should be all-PASS, got %+v", rep)
	}
}

func TestProvider_SetFirewallID(t *testing.T) {
	p := NewProvider(&MockCFClient{})
	rec := &FrontRecord{}
	p.SetFirewallID(rec, "fw-1234")
	if rec.FirewallID != "fw-1234" {
		t.Errorf("firewall id = %q", rec.FirewallID)
	}
}

func TestRewriteWorkerScript_MentionsBothPaths(t *testing.T) {
	src := string(RewriteWorkerScript("/r/abcdef", "/ws"))
	if !strings.Contains(src, "/r/abcdef") || !strings.Contains(src, "/ws") {
		t.Errorf("script should reference both paths verbatim:\n%s", src)
	}
	if !strings.Contains(src, "addEventListener(\"fetch\"") {
		t.Errorf("script should be a fetch handler:\n%s", src)
	}
}

func TestLiveCFClient_ZoneAndDNS(t *testing.T) {
	var sawAuth bool
	proxied := true
	mux := http.NewServeMux()
	mux.HandleFunc("/zones", func(w http.ResponseWriter, r *http.Request) {
		sawAuth = strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ")
		writeCF(w, []map[string]any{{"id": "zone-1", "account": map[string]string{"id": "acct-1"}}})
	})
	mux.HandleFunc("/zones/zone-1/dns_records", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeCF(w, []map[string]any{{"id": "rec-1", "type": "A", "name": "momsroute.example.com", "content": "1.1.1.1", "proxied": true}})
		case http.MethodPut, http.MethodPost:
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["proxied"] != true {
				t.Errorf("proxied = %v", body["proxied"])
			}
			writeCF(w, map[string]any{"id": "rec-1", "proxied": proxied})
		default:
			t.Errorf("unexpected method %s", r.Method)
		}
	})
	mux.HandleFunc("/zones/zone-1/dns_records/rec-1", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("method = %s", r.Method)
		}
		writeCF(w, map[string]any{"id": "rec-1", "proxied": true})
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	cf := newLiveCFClient(ts.URL, ts.Client())
	zone, acct, err := cf.LookupZoneID(context.Background(), []byte("tok"), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if zone != "zone-1" || acct != "acct-1" {
		t.Fatalf("zone/acct = %s/%s", zone, acct)
	}
	if err := cf.EnsureProxiedRecords(context.Background(), []byte("tok"), zone, "momsroute.example.com", "5.75.1.2", ""); err != nil {
		t.Fatal(err)
	}
	if !sawAuth {
		t.Error("live client did not send bearer token")
	}
}

func TestLiveCFClient_DNSOnlyRecordRejected(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/zones/zone-1/dns_records", func(w http.ResponseWriter, r *http.Request) {
		proxied := false
		writeCF(w, []dnsRecord{{ID: "rec-1", Type: "A", Name: "momsroute.example.com", Content: "1.1.1.1", Proxied: &proxied}})
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	cf := newLiveCFClient(ts.URL, ts.Client())
	err := cf.EnsureProxiedRecords(context.Background(), []byte("tok"), "zone-1", "momsroute.example.com", "5.75.1.2", "")
	if !errors.Is(err, ErrDNSOnlyRecordPresent) {
		t.Fatalf("want ErrDNSOnlyRecordPresent, got %v", err)
	}
}

func writeCF(w http.ResponseWriter, result any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"errors":  []any{},
		"result":  result,
	})
}
