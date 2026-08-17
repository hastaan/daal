package stark

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"daal/publisher/deploy/provider"
)

// fakeStarkServer is a minimal in-memory REST endpoint that serves
// the subset of Stark's API the adapter exercises.
type fakeStarkServer struct {
	mu          sync.Mutex
	idCount     int64
	vpses       map[string]*VPSResp       // id -> resp
	rules       map[string]map[string]any // ruleID -> input
	sshKeys     map[string]string         // keyID -> name
	authHeaders []string                  // every Authorization header observed
	expectToken string                    // tests set this; server 401s on mismatch
}

func newFakeServer(token string) (*fakeStarkServer, *httptest.Server) {
	f := &fakeStarkServer{
		vpses:       map[string]*VPSResp{},
		rules:       map[string]map[string]any{},
		sshKeys:     map[string]string{},
		expectToken: token,
	}
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/ssh-keys", func(w http.ResponseWriter, r *http.Request) {
		if !f.checkAuth(w, r) {
			return
		}
		if r.Method != "POST" {
			http.Error(w, "method", 405)
			return
		}
		var req SSHKeyReq
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		f.idCount++
		id := "ssh-" + strconvI(f.idCount)
		f.sshKeys[id] = req.Name
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(SSHKeyResp{KeyID: id})
	})

	// DELETE /ssh-keys/<id> — the leg the adapter now calls on every
	// exit path so a one-shot key never outlives its provision.
	mux.HandleFunc("/v1/ssh-keys/", func(w http.ResponseWriter, r *http.Request) {
		if !f.checkAuth(w, r) {
			return
		}
		if r.Method != "DELETE" {
			http.Error(w, "method", 405)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/v1/ssh-keys/")
		f.mu.Lock()
		defer f.mu.Unlock()
		if _, ok := f.sshKeys[id]; !ok {
			http.Error(w, "not found", 404)
			return
		}
		delete(f.sshKeys, id)
		w.WriteHeader(204)
	})

	mux.HandleFunc("/v1/vps", func(w http.ResponseWriter, r *http.Request) {
		if !f.checkAuth(w, r) {
			return
		}
		switch r.Method {
		case "POST":
			var req VPSCreateReq
			_ = json.NewDecoder(r.Body).Decode(&req)
			f.mu.Lock()
			f.idCount++
			id := "vps-" + strconvI(f.idCount)
			resp := &VPSResp{
				ID: id, Hostname: req.Hostname, Status: "active",
				Plan: req.Plan, Region: req.Region, IPv4: "92.118.0." + strconvI(f.idCount),
				Tags: req.Tags,
			}
			f.vpses[id] = resp
			f.mu.Unlock()
			_ = json.NewEncoder(w).Encode(resp)
		case "GET":
			hostname := r.URL.Query().Get("hostname")
			f.mu.Lock()
			defer f.mu.Unlock()
			out := []*VPSResp{}
			for _, v := range f.vpses {
				if v.Hostname == hostname {
					out = append(out, v)
				}
			}
			_ = json.NewEncoder(w).Encode(out)
		default:
			http.Error(w, "method", 405)
		}
	})

	mux.HandleFunc("/v1/vps/", func(w http.ResponseWriter, r *http.Request) {
		if !f.checkAuth(w, r) {
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/v1/vps/")
		switch r.Method {
		case "DELETE":
			f.mu.Lock()
			defer f.mu.Unlock()
			if _, ok := f.vpses[id]; !ok {
				http.Error(w, "not found", 404)
				return
			}
			delete(f.vpses, id)
			w.WriteHeader(204)
		default:
			http.Error(w, "method", 405)
		}
	})

	mux.HandleFunc("/v1/firewall/rules", func(w http.ResponseWriter, r *http.Request) {
		if !f.checkAuth(w, r) {
			return
		}
		if r.Method != "POST" {
			http.Error(w, "method", 405)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.idCount++
		id := "rule-" + strconvI(f.idCount)
		f.rules[id] = body
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(FirewallRuleResp{RuleID: id})
	})

	mux.HandleFunc("/v1/firewall/rules/", func(w http.ResponseWriter, r *http.Request) {
		if !f.checkAuth(w, r) {
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/v1/firewall/rules/")
		if r.Method != "DELETE" {
			http.Error(w, "method", 405)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if _, ok := f.rules[id]; !ok {
			http.Error(w, "not found", 404)
			return
		}
		delete(f.rules, id)
		w.WriteHeader(204)
	})

	mux.HandleFunc("/v1/pricing/", func(w http.ResponseWriter, r *http.Request) {
		if !f.checkAuth(w, r) {
			return
		}
		_ = json.NewEncoder(w).Encode(PriceResp{
			Plan:       strings.TrimPrefix(r.URL.Path, "/v1/pricing/"),
			Region:     r.URL.Query().Get("region"),
			MonthlyEUR: 7.30,
		})
	})

	mux.HandleFunc("/v1/reserved-ips/", func(w http.ResponseWriter, r *http.Request) {
		if !f.checkAuth(w, r) {
			return
		}
		w.WriteHeader(204)
	})

	srv := httptest.NewServer(mux)
	return f, srv
}

func (f *fakeStarkServer) checkAuth(w http.ResponseWriter, r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	f.mu.Lock()
	f.authHeaders = append(f.authHeaders, auth)
	expect := f.expectToken
	f.mu.Unlock()
	if auth != "Bearer "+expect {
		http.Error(w, "unauthorized", 401)
		return false
	}
	return true
}

func strconvI(n int64) string {
	const digits = "0123456789"
	if n == 0 {
		return "0"
	}
	out := []byte{}
	for n > 0 {
		out = append([]byte{digits[n%10]}, out...)
		n /= 10
	}
	return string(out)
}

// --- test helpers ---

func mkOpts() provider.ProvisionOpts {
	pub, priv, _ := ed25519.GenerateKey(nil)
	return provider.ProvisionOpts{
		PublisherPubKey: pub,
		Region:          "vno",
		ServerType:      "stark-1c-1gb",
		ToolboxProfile:  "iran-default",
		HelperIP:        net.ParseIP("1.2.3.4"),
		EphemeralSSHKey: priv,
		DryRun:          true,
	}
}

func mkProvider(t *testing.T, token string) (*Provider, *fakeStarkServer, func()) {
	t.Helper()
	srv, ts := newFakeServer(token)
	c := NewClient(WithEndpoint(ts.URL+"/v1"), WithHTTPClient(&http.Client{Timeout: 5 * time.Second}))
	p := New(c, func() string { return token })
	return p, srv, ts.Close
}

// --- tests ---

func TestProvision_DryRunReturnsSyntheticRecord(t *testing.T) {
	p, _, cleanup := mkProvider(t, "tok")
	defer cleanup()
	rec, err := p.Provision(context.Background(), mkOpts())
	if err != nil {
		t.Fatal(err)
	}
	if rec.Provider != "stark" {
		t.Errorf("Provider = %q want stark", rec.Provider)
	}
	for _, c := range rec.Candidates {
		if c.ExposureMode != "direct_vps" {
			t.Errorf("V1.5 invariant: %s exposure_mode=%q", c.Family, c.ExposureMode)
		}
	}
}

func TestProvision_ExistingVPSRequiresPersistedMgmtPort(t *testing.T) {
	p, _, cleanup := mkProvider(t, "tok")
	defer cleanup()
	opts := mkOpts()
	opts.DryRun = false
	opts.MgmtPort = 42424
	if _, err := p.Provision(context.Background(), opts); err != nil {
		t.Fatalf("initial Provision: %v", err)
	}

	retry := opts
	retry.MgmtPort = 0
	if _, err := p.Provision(context.Background(), retry); err == nil {
		t.Fatal("expected existing vps retry without persisted MgmtPort to fail")
	}

	retry.MgmtPort = 42424
	// The adopt path refuses to invent a cover host for a box it cannot
	// inspect, so state one. Same shape as MgmtPort two lines up.
	retry.CoverSNI = "mirror.init7.net"
	rec, err := p.Provision(context.Background(), retry)
	if err != nil {
		t.Fatalf("retry with persisted MgmtPort: %v", err)
	}
	if rec.MgmtPort != 42424 {
		t.Fatalf("MgmtPort = %d, want 42424", rec.MgmtPort)
	}
	if rec.CoverSNI != "mirror.init7.net" {
		t.Fatalf("CoverSNI = %q, want the persisted value verbatim", rec.CoverSNI)
	}
}

func TestProvision_RejectsMissingFields(t *testing.T) {
	p, _, cleanup := mkProvider(t, "tok")
	defer cleanup()
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

func TestPricing_MonthlyOver730_GivesHourly(t *testing.T) {
	p, _, cleanup := mkProvider(t, "tok")
	defer cleanup()
	rec := &provider.OperatorRecord{Region: "vno", ServerType: "stark-1c-1gb"}
	pr, err := p.Pricing(context.Background(), rec)
	if err != nil {
		t.Fatal(err)
	}
	if pr.MonthlyEUR != 7.30 {
		t.Errorf("MonthlyEUR = %v want 7.30", pr.MonthlyEUR)
	}
	want := 7.30 / 730.0
	if pr.HourlyEUR < want-0.0001 || pr.HourlyEUR > want+0.0001 {
		t.Errorf("HourlyEUR = %v want ~%v", pr.HourlyEUR, want)
	}
	if pr.Provider != "stark" {
		t.Errorf("Provider field missing in Pricing: %q", pr.Provider)
	}
}

func TestSetEphemeralFirewallRule_OpensCorrectTuple(t *testing.T) {
	p, srv, cleanup := mkProvider(t, "tok")
	defer cleanup()
	pin := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	p.SetClock(func() time.Time { return pin })

	rule, err := p.SetEphemeralFirewallRule(context.Background(), "vps-1", "2.3.4.5", 12345, 300)
	if err != nil {
		t.Fatalf("SetEphemeralFirewallRule: %v", err)
	}
	if rule.Port != 12345 {
		t.Errorf("Port lost; got %d", rule.Port)
	}
	if !rule.ExpiresAt.Equal(pin.Add(300 * time.Second).UTC()) {
		t.Errorf("ExpiresAt drift")
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.rules) != 1 {
		t.Errorf("server saw %d rules, want 1", len(srv.rules))
	}
	for _, body := range srv.rules {
		if body["port"].(float64) != 12345 {
			t.Errorf("server saw wrong port: %+v", body)
		}
		if body["src_ip"].(string) != "2.3.4.5" {
			t.Errorf("server saw wrong src_ip: %+v", body)
		}
	}
}

func TestSetEphemeralFirewallRule_RejectsBadInputs(t *testing.T) {
	p, _, cleanup := mkProvider(t, "tok")
	defer cleanup()
	if _, err := p.SetEphemeralFirewallRule(context.Background(), "", "1.2.3.4", 12345, 300); err == nil {
		t.Errorf("missing serverID must error")
	}
	if _, err := p.SetEphemeralFirewallRule(context.Background(), "v", "", 12345, 300); err == nil {
		t.Errorf("missing callerIP must error")
	}
	if _, err := p.SetEphemeralFirewallRule(context.Background(), "v", "1.2.3.4", 0, 300); err == nil {
		t.Errorf("port=0 must error")
	}
	if _, err := p.SetEphemeralFirewallRule(context.Background(), "v", "1.2.3.4", 8443, 300); err == nil {
		t.Errorf("fixed low port 8443 must error")
	}
	if _, err := p.SetEphemeralFirewallRule(context.Background(), "v", "1.2.3.4", 65001, 300); err == nil {
		t.Errorf("port > 65000 must error")
	}
	if _, err := p.SetEphemeralFirewallRule(context.Background(), "v", "1.2.3.4", 12345, 0); err == nil {
		t.Errorf("durationSec=0 must error")
	}
}

func TestRemoveEphemeralFirewallRule_Idempotent(t *testing.T) {
	p, srv, cleanup := mkProvider(t, "tok")
	defer cleanup()
	if err := p.RemoveEphemeralFirewallRule(context.Background(), nil); err != nil {
		t.Errorf("nil rule must be nil; got %v", err)
	}
	rule, _ := p.SetEphemeralFirewallRule(context.Background(), "vps-1", "1.2.3.4", 12345, 300)
	if err := p.RemoveEphemeralFirewallRule(context.Background(), rule); err != nil {
		t.Fatal(err)
	}
	srv.mu.Lock()
	if len(srv.rules) != 0 {
		t.Errorf("server still has %d rules", len(srv.rules))
	}
	srv.mu.Unlock()
	if err := p.RemoveEphemeralFirewallRule(context.Background(), rule); err != nil {
		t.Errorf("second remove must be nil; got %v", err)
	}
}

func TestBearer_FailsClosedOnEmptyToken(t *testing.T) {
	c := NewClient(WithEndpoint("http://localhost:0"))
	p := New(c, func() string { return "" })
	if _, err := p.SetEphemeralFirewallRule(context.Background(), "v", "1.2.3.4", 12345, 300); err == nil {
		t.Errorf("expected error for empty token")
	}
}

func TestBearer_WrongTokenReturns401Path(t *testing.T) {
	p, _, cleanup := mkProvider(t, "expected-tok")
	defer cleanup()
	// Override the token source to send a wrong token.
	p.tokenSource = func() string { return "wrong-tok" }
	if _, err := p.SetEphemeralFirewallRule(context.Background(), "v", "1.2.3.4", 12345, 300); err == nil {
		t.Errorf("expected 401 propagation; got nil error")
	}
}

func TestBearer_HeaderShape(t *testing.T) {
	p, srv, cleanup := mkProvider(t, "tok")
	defer cleanup()
	rec := &provider.OperatorRecord{Region: "vno", ServerType: "stark-1c-1gb"}
	if _, err := p.Pricing(context.Background(), rec); err != nil {
		t.Fatal(err)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.authHeaders) == 0 {
		t.Fatalf("server saw no Authorization headers")
	}
	for _, h := range srv.authHeaders {
		if !strings.HasPrefix(h, "Bearer ") {
			t.Errorf("expected Bearer prefix; got %q", h)
		}
	}
}

func TestRegions_IsSupported(t *testing.T) {
	if !IsSupportedRegion(DefaultRegion) {
		t.Errorf("DefaultRegion %q not supported", DefaultRegion)
	}
	if IsSupportedRegion("nowhere") {
		t.Errorf("unknown region should not be supported")
	}
}

func TestDecommission_AbsentIsNoOp(t *testing.T) {
	p, _, cleanup := mkProvider(t, "tok")
	defer cleanup()
	rep, err := p.Decommission(context.Background(), nil)
	if err != nil {
		t.Errorf("nil rec must be nil; got %v", err)
	}
	if !rep.Clean() {
		t.Errorf("Decommission(nil) must report a clean teardown; got %+v", rep)
	}
	if _, err := p.Decommission(context.Background(), &provider.OperatorRecord{ServerID: "absent"}); err != nil {
		t.Errorf("absent server must be nil; got %v", err)
	}
}

// TestProvision_RemovesOneShotKey pins the leak this adapter used to
// have: the ephemeral key was created and then never deleted on ANY
// path, success included.
func TestProvision_RemovesOneShotKey(t *testing.T) {
	p, srv, cleanup := mkProvider(t, "tok")
	defer cleanup()
	opts := mkOpts()
	opts.DryRun = false
	if _, err := p.Provision(context.Background(), opts); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.sshKeys) != 0 {
		t.Errorf("one-shot ssh key left on the account: %v", srv.sshKeys)
	}
}

// TestDecommission_ReportsWhatItCannotProve pins the honesty
// contract: the VPS goes, firewall rules are vps-scoped with a
// server-side TTL, and the one-shot key is deleted by id at the end of
// every provision — so all three legs report gone, and the only
// warning left is the reserved IP the operator owns.
func TestDecommission_ReportsWhatItCannotProve(t *testing.T) {
	p, srv, cleanup := mkProvider(t, "tok")
	defer cleanup()
	opts := mkOpts()
	opts.DryRun = false
	rec, err := p.Provision(context.Background(), opts)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	rec.FloatingIPID = "rip-3"

	rep, err := p.Decommission(context.Background(), rec)
	if err != nil {
		t.Fatalf("Decommission: %v", err)
	}
	if !rep.ServerDeleted || !rep.FirewallDeleted {
		t.Errorf("vps + vps-scoped rules must be reported gone; got %+v", rep)
	}
	if !rep.SSHKeyDeleted {
		t.Errorf("one-shot key is deleted by id at the end of every provision: %+v", rep)
	}
	srv.mu.Lock()
	left := len(srv.vpses)
	srv.mu.Unlock()
	if left != 0 {
		t.Errorf("vps survived teardown")
	}
	for _, want := range []string{
		"rip-3",
	} {
		found := false
		for _, w := range rep.Warnings {
			if strings.Contains(w, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("warnings %v do not mention %q", rep.Warnings, want)
		}
	}
}

// A record with no ServerID is the shape a failed provision leaves —
// the wizard only writes the OperatorRecord back on success — so an
// empty id must not be read as "nothing to delete" while a real,
// billing VPS runs under the derived hostname.
func TestDecommission_FindsOrphanVPSByDerivedHostname(t *testing.T) {
	p, srv, cleanup := mkProvider(t, "tok")
	defer cleanup()
	opts := mkOpts()
	opts.DryRun = false
	if _, err := p.Provision(context.Background(), opts); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	stale := &provider.OperatorRecord{
		Provider:        "stark",
		Region:          opts.Region,
		PublisherPubKey: opts.PublisherPubKey,
	}
	rep, err := p.Decommission(context.Background(), stale)
	if err != nil {
		t.Fatalf("Decommission: %v", err)
	}
	if !rep.ServerDeleted {
		t.Errorf("orphan vps must be reported deleted: %+v", rep)
	}
	srv.mu.Lock()
	left := len(srv.vpses)
	srv.mu.Unlock()
	if left != 0 {
		t.Errorf("the billing orphan survived a teardown that claimed server_deleted=%v", rep.ServerDeleted)
	}
}

func TestEphemeralSSHKeyName_UniquePerAttempt(t *testing.T) {
	a, err := ephemeralSSHKeyName("daal-vno-0011223344556677")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ephemeralSSHKeyName("daal-vno-0011223344556677")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatalf("two attempts produced the same key name (%q)", a)
	}
}

func TestNewClient_DefaultEndpointRespected(t *testing.T) {
	c := NewClient()
	if c.endpoint != DefaultEndpoint {
		t.Errorf("default endpoint not set; got %q", c.endpoint)
	}
	c2 := NewClient(WithEndpoint("https://custom.example/v2"))
	if c2.endpoint != "https://custom.example/v2" {
		t.Errorf("WithEndpoint not honored")
	}
}
