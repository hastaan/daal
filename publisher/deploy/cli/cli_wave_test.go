package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"daal/publisher/deploy/health"
	"daal/publisher/deploy/mgmt"
	"daal/publisher/deploy/provider"
)

// --- D4: decommission --release-addresses ---

type fakeReleasingProvider struct {
	providerFace
	report       *provider.DecommissionReport
	err          error
	addrs        []provider.AddressOutcome
	releaseCalls int
}

func (f *fakeReleasingProvider) Decommission(_ context.Context, _ *provider.OperatorRecord) (*provider.DecommissionReport, error) {
	return f.report, f.err
}

func (f *fakeReleasingProvider) ReleaseRelayAddresses(_ context.Context, _ *provider.OperatorRecord, _ string) []provider.AddressOutcome {
	f.releaseCalls++
	return f.addrs
}

func goneReportWithAddressWarning() *provider.DecommissionReport {
	rep := provider.NewDecommissionReport("hetzner", "12345")
	rep.ServerDeleted, rep.SSHKeyDeleted, rep.FirewallDeleted = true, true, true
	rep.Warnf("floating IP fip-1 stays reserved on your account and keeps billing — daal-deploy reserved it, so run " +
		"`daal-deploy floating-ip release --fip-id fip-1 --skip-unbind` to stop paying for it")
	rep.Warnf("could not delete one-shot SSH key %q (id 9): boom — remove it with: %s", "k",
		`curl -s -X DELETE -H "Authorization: Bearer $VULTR_API_KEY" https://api.vultr.com/v2/ssh-keys/9`)
	rep.Preserve("floating-ip:fip-1")
	return rep
}

func writeRecordWithFIP(t *testing.T, fip string) (string, string) {
	t.Helper()
	recordFile, tokenFile := writeDecommissionFixture(t)
	rec, err := readRecord(recordFile)
	if err != nil {
		t.Fatal(err)
	}
	rec.FloatingIPID = fip
	body, _ := json.Marshal(rec)
	if err := os.WriteFile(recordFile, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return recordFile, tokenFile
}

func TestDecommissionReleaseAddresses_ReleasesAndSpeaksNoCommands(t *testing.T) {
	fake := &fakeReleasingProvider{report: goneReportWithAddressWarning(), addrs: []provider.AddressOutcome{
		{ID: "fip-1", IP: "198.51.100.9", Released: true, Code: provider.AddrReleased},
		{ID: "fip-9", IP: "198.51.100.10", Code: provider.AddrNotDaal},
	}}
	withFakeProvider(t, fake)
	recordFile, tokenFile := writeRecordWithFIP(t, "fip-1")
	var stdout, stderr bytes.Buffer
	rc := Run([]string{"decommission", "--record-file", recordFile, "--token-file", tokenFile, "--json", "--release-addresses"}, &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("rc=%d stderr=%s", rc, stderr.String())
	}
	var rep provider.DecommissionReport
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Addresses == nil || len(*rep.Addresses) != 2 || (*rep.Addresses)[0].Code != provider.AddrReleased {
		t.Fatalf("addresses = %+v", rep.Addresses)
	}
	for _, w := range rep.Warnings {
		if strings.ContainsAny(w, "`$") || strings.Contains(w, "curl") || strings.Contains(w, "daal-deploy ") {
			t.Errorf("a warning still carries a command line: %q", w)
		}
		if strings.Contains(w, "fip-1") {
			t.Errorf("a released address is still described as billing: %q", w)
		}
	}
	for _, p := range rep.Preserved {
		if p == "floating-ip:fip-1" {
			t.Error("a released address is still listed as preserved")
		}
	}
}

func TestDecommissionReleaseAddresses_AFailedReleaseExits6(t *testing.T) {
	fake := &fakeReleasingProvider{report: goneReportWithAddressWarning(), addrs: []provider.AddressOutcome{
		{ID: "fip-1", IP: "198.51.100.9", Code: provider.AddrReleaseFailed, Error: "503"},
	}}
	withFakeProvider(t, fake)
	recordFile, tokenFile := writeRecordWithFIP(t, "fip-1")
	var stdout, stderr bytes.Buffer
	if rc := Run([]string{"decommission", "--record-file", recordFile, "--token-file", tokenFile, "--release-addresses"}, &stdout, &stderr); rc != 6 {
		t.Fatalf("rc=%d, want 6; stderr=%s", rc, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"release_failed"`) {
		t.Fatalf("report does not name the failed release: %s", stdout.String())
	}
}

func TestDecommissionReleaseAddresses_NothingIsReleasedWhileTheServerSurvives(t *testing.T) {
	rep := provider.NewDecommissionReport("hetzner", "12345")
	fake := &fakeReleasingProvider{report: rep, err: errors.New("delete server: 500")}
	withFakeProvider(t, fake)
	recordFile, tokenFile := writeRecordWithFIP(t, "fip-1")
	var stdout, stderr bytes.Buffer
	if rc := Run([]string{"decommission", "--record-file", recordFile, "--token-file", tokenFile, "--release-addresses"}, &stdout, &stderr); rc != 1 {
		t.Fatalf("rc=%d, want 1", rc)
	}
	if fake.releaseCalls != 0 {
		t.Fatal("released an address while its server is still running")
	}
}

func TestDecommission_WithoutTheFlagTheReportIsUnchanged(t *testing.T) {
	fake := &fakeReleasingProvider{report: goneReportWithAddressWarning()}
	withFakeProvider(t, fake)
	recordFile, tokenFile := writeRecordWithFIP(t, "fip-1")
	var stdout, stderr bytes.Buffer
	if rc := Run([]string{"decommission", "--record-file", recordFile, "--token-file", tokenFile}, &stdout, &stderr); rc != 0 {
		t.Fatalf("rc=%d", rc)
	}
	if strings.Contains(stdout.String(), `"addresses"`) || fake.releaseCalls != 0 {
		t.Fatalf("an older shell's report changed: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "floating-ip release") {
		t.Fatal("the legacy warning was rewritten without the flag")
	}
}

func TestPlainWarning_DropsCommandsKeepsTheStatement(t *testing.T) {
	cases := map[string]string{
		"could not delete firewall group 7: boom — remove it with: curl -s -X DELETE -H \"Authorization: Bearer $VULTR_API_KEY\" https://x/7": "could not delete firewall group 7: boom",
		"server 9 is still running, so its one-shot SSH key was left in place":                                                                "server 9 is still running, so its one-shot SSH key was left in place",
		"could not list SSH keys (503) — a key may still be there. To see exactly what is left on your cloud account — and what can safely be removed — run `daal-deploy account-audit --token-file <token>`; it needs no record and never deletes anything.": "could not list SSH keys (503) — a key may still be there",
	}
	for in, want := range cases {
		if got := provider.PlainWarning(in); got != want {
			t.Errorf("PlainWarning(%q)\n got %q\nwant %q", in, got, want)
		}
	}
}

// --- D2: users-renew ---

// cliBox is a minimal management service for CLI tests: a roster, the
// users routes and /identity. Tokens are not verified here (mgmt's own
// tests do that); the TLS pin is, by the real client.
type cliBox struct {
	mu       sync.Mutex
	users    map[string]bool
	writes   []string
	noList   bool
	identity bool
}

func (b *cliBox) handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("/users/list", func(w http.ResponseWriter, r *http.Request) {
		if b.noList {
			http.NotFound(w, r)
			return
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		out := []mgmt.UserMeta{}
		for n := range b.users {
			out = append(out, mgmt.UserMeta{Name: n})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"users": out})
	})
	m.HandleFunc("/users/provision", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Name string }
		_ = json.NewDecoder(r.Body).Decode(&req)
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.users[req.Name] {
			http.Error(w, "user already exists", http.StatusConflict)
			return
		}
		b.users[req.Name] = true
		b.writes = append(b.writes, "provision "+req.Name)
		_ = json.NewEncoder(w).Encode(mgmt.UserCreds{Name: req.Name, VLESSUUID: "SECRET-UUID-" + req.Name})
	})
	m.HandleFunc("/users/revoke", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Name string }
		_ = json.NewDecoder(r.Body).Decode(&req)
		b.mu.Lock()
		defer b.mu.Unlock()
		if !b.users[req.Name] {
			http.NotFound(w, r)
			return
		}
		delete(b.users, req.Name)
		b.writes = append(b.writes, "revoke "+req.Name)
		_ = json.NewEncoder(w).Encode(mgmt.RevokeResp{RevokedAtUnix: 1})
	})
	m.HandleFunc("/identity", func(w http.ResponseWriter, r *http.Request) {
		if !b.identity {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(mgmt.RelayIdentity{IdentityVersion: mgmt.IdentityVersion, CoverSNI: "cover.example.org",
			TLSCertSHA256: "PIN-FROM-IDENTITY",
			Families:      []mgmt.RelayIdentityFamily{{Family: "vless-reality", Port: 443}, {Family: "naive", Port: 8444}, {Family: "hysteria2", Port: 443}}})
	})
	return m
}

// windowProvider counts firewall windows and optionally reports a
// server state.
type windowProvider struct {
	providerFace
	mu      sync.Mutex
	opened  int
	closed  int
	openErr error
	state   string
}

func (w *windowProvider) SetEphemeralFirewallRule(_ context.Context, serverID, callerIP string, port, _ int) (*provider.EphemeralFirewallRule, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.openErr != nil {
		return nil, w.openErr
	}
	w.opened++
	return &provider.EphemeralFirewallRule{ID: "r", ServerID: serverID, CallerIP: callerIP, Port: port}, nil
}

func (w *windowProvider) RemoveEphemeralFirewallRule(context.Context, *provider.EphemeralFirewallRule) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed++
	return nil
}

func (w *windowProvider) ServerState(context.Context, *provider.OperatorRecord) (string, error) {
	return w.state, nil
}

// boxFixture starts box over TLS and writes a record pinned to it plus
// a private key and a token file. Returns the argv prefix shared by
// users-renew and relay-health.
func boxFixture(t *testing.T, box http.Handler) (args []string, rec *provider.OperatorRecord) {
	t.Helper()
	ts := httptest.NewTLSServer(box)
	t.Cleanup(ts.Close)
	sum := sha256.Sum256(ts.Certificate().Raw)
	host, portS, _ := net.SplitHostPort(strings.TrimPrefix(ts.URL, "https://"))
	port, _ := strconv.Atoi(portS)
	if port < provider.MinMgmtPort {
		t.Skip("ephemeral port below the management port range")
	}
	pub, priv, _ := ed25519.GenerateKey(nil)
	rec = &provider.OperatorRecord{Provider: "hetzner", ServerID: "12345", Region: "fsn1", PublisherPubKey: pub,
		PublicIP: net.ParseIP(host), MgmtPort: port, MgmtTLSFingerprint: hex.EncodeToString(sum[:]),
		CoverSNI: "record-cover.example.org", TLSCertSHA256: "PIN-FROM-RECORD",
		Candidates: []provider.CandidateMeta{{Family: "vless-reality", ExposureMode: "direct_vps"}, {Family: "shadowsocks", ExposureMode: "direct_vps"}, {Family: "websocket-tls", ExposureMode: "cdn_fronted"}}}
	dir := t.TempDir()
	recFile := filepath.Join(dir, "rec.json")
	body, _ := json.Marshal(rec)
	keyFile := filepath.Join(dir, "key")
	tokFile := filepath.Join(dir, "tok")
	for p, b := range map[string][]byte{recFile: body, keyFile: priv, tokFile: []byte("TOKEN-NEVER-PRINTED")} {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return []string{"--record-file", recFile, "--priv-key", keyFile, "--helper-ip", "198.51.100.7", "--token-file", tokFile}, rec
}

func TestUsersRenewCLI_ArgvOrderOneWindowCredsOnStdoutOnly(t *testing.T) {
	box := &cliBox{users: map[string]bool{"r1": true, "r2": true, "r4": true}}
	common, _ := boxFixture(t, box.handler())
	wp := &windowProvider{}
	withFakeProvider(t, wp)
	var stdout, stderr bytes.Buffer
	argv := append([]string{"users-renew"}, common...)
	argv = append(argv, "--progress-json", "--replace", "r2", "--ensure", "r1", "--revoke", "r4", "--ensure", "r0", "--revoke", "r6")
	if rc := Run(argv, &stdout, &stderr); rc != 0 {
		t.Fatalf("rc=%d stderr=%s", rc, stderr.String())
	}
	if wp.opened != 1 || wp.closed != 1 {
		t.Fatalf("windows opened=%d closed=%d, want one", wp.opened, wp.closed)
	}
	var rep mgmt.RenewReport
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
		t.Fatalf("%v\n%s", err, stdout.String())
	}
	var order []string
	for _, r := range rep.Results {
		order = append(order, r.Name+":"+r.Action)
	}
	if got := strings.Join(order, " "); got != "r2:provisioned r1:kept r4:revoked r0:provisioned r6:absent" {
		t.Fatalf("results = %s", got)
	}
	if got := strings.Join(box.writes, "|"); got != "revoke r2|provision r2|revoke r4|provision r0" {
		t.Errorf("box writes = %s", got)
	}
	if strings.Contains(stderr.String(), "SECRET-UUID") || strings.Contains(stderr.String(), "TOKEN-NEVER-PRINTED") {
		t.Fatalf("a secret reached stderr: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), `"step":"renew_user"`) {
		t.Errorf("no progress lines: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), `"creds":null`) || !strings.Contains(stdout.String(), `"error_code":""`) {
		t.Errorf("stdout shape: %s", stdout.String())
	}
}

func TestUsersRenewCLI_ExitCodes(t *testing.T) {
	t.Run("a revoked person listed for anything else is usage", func(t *testing.T) {
		box := &cliBox{users: map[string]bool{}}
		common, _ := boxFixture(t, box.handler())
		wp := &windowProvider{}
		withFakeProvider(t, wp)
		var out, errb bytes.Buffer
		argv := append(append([]string{"users-renew"}, common...), "--revoke", "r3", "--ensure", "r3")
		if rc := Run(argv, &out, &errb); rc != 2 {
			t.Fatalf("rc=%d", rc)
		}
		if wp.opened != 0 || len(box.writes) != 0 {
			t.Fatal("a refused request reached the relay")
		}
	})
	t.Run("relay too old to list its people is 3", func(t *testing.T) {
		box := &cliBox{users: map[string]bool{}, noList: true}
		common, _ := boxFixture(t, box.handler())
		withFakeProvider(t, &windowProvider{})
		var out, errb bytes.Buffer
		if rc := Run(append(append([]string{"users-renew"}, common...), "--ensure", "r1"), &out, &errb); rc != 3 {
			t.Fatalf("rc=%d stderr=%s", rc, errb.String())
		}
		if len(box.writes) != 0 {
			t.Fatal("wrote to a relay whose roster could not be read")
		}
	})
	t.Run("no window is 1", func(t *testing.T) {
		box := &cliBox{users: map[string]bool{}}
		common, _ := boxFixture(t, box.handler())
		withFakeProvider(t, &windowProvider{openErr: errors.New("cloud 503")})
		var out, errb bytes.Buffer
		if rc := Run(append(append([]string{"users-renew"}, common...), "--ensure", "r1"), &out, &errb); rc != 1 {
			t.Fatalf("rc=%d", rc)
		}
	})
}

// --- D3: relay-health ---

type probeCall struct {
	ways []health.Way
	opts health.WayProbeOpts
}

func stubProbe(t *testing.T) *probeCall {
	t.Helper()
	call := &probeCall{}
	prev := healthProbeWays
	healthProbeWays = func(_ context.Context, _ net.IP, ways []health.Way, opts health.WayProbeOpts) []health.WayResult {
		call.ways, call.opts = ways, opts
		out := []health.WayResult{}
		for _, w := range ways {
			st := health.WayAnswers
			if w.UDP {
				st = health.WayNotTestableHere
			}
			out = append(out, health.WayResult{Family: w.Family, Port: w.Port, UDP: w.UDP, State: st})
		}
		return out
	}
	t.Cleanup(func() { healthProbeWays = prev })
	return call
}

func runHealth(t *testing.T, argv []string) map[string]any {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if rc := Run(argv, &stdout, &stderr); rc != 0 {
		t.Fatalf("rc=%d stderr=%s", rc, stderr.String())
	}
	if strings.Contains(stdout.String()+stderr.String(), "TOKEN-NEVER-PRINTED") {
		t.Fatal("the token was printed")
	}
	var out map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("%v\n%s", err, stdout.String())
	}
	return out
}

func TestRelayHealthCLI_ServerManagementAndWaysFromIdentity(t *testing.T) {
	box := &cliBox{users: map[string]bool{"r0": true, "r1": true}, identity: true}
	common, _ := boxFixture(t, box.handler())
	wp := &windowProvider{state: provider.ServerRunning}
	withFakeProvider(t, wp)
	call := stubProbe(t)
	out := runHealth(t, append([]string{"relay-health"}, common...))

	if s := out["server"].(map[string]any)["state"]; s != "running" {
		t.Errorf("server = %v", s)
	}
	m := out["management"].(map[string]any)
	if m["state"] != "answers" || m["identity"] == nil || len(m["users"].([]any)) != 2 {
		t.Errorf("management = %v", m)
	}
	if wp.opened != 1 || wp.closed != 1 {
		t.Errorf("windows opened=%d closed=%d", wp.opened, wp.closed)
	}
	if fmt.Sprint(call.ways) != "[{vless-reality 443 false} {naive 8444 false} {hysteria2 443 true}]" {
		t.Errorf("ways = %v (want the relay's own list)", call.ways)
	}
	if call.opts.CoverSNI != "cover.example.org" || call.opts.CertPin != "PIN-FROM-IDENTITY" {
		t.Errorf("probe opts = %+v (the relay's identity wins over the record)", call.opts)
	}
	limits := fmt.Sprint(out["limits"])
	if !strings.Contains(limits, "inside_country_unknown") || !strings.Contains(limits, "udp_not_tested") {
		t.Errorf("limits = %s", limits)
	}
	if out["v"] != float64(1) || out["checked_at"] == "" {
		t.Errorf("header = %v %v", out["v"], out["checked_at"])
	}
}

func TestRelayHealthCLI_WithoutATokenOnlyTheWaysAreChecked(t *testing.T) {
	box := &cliBox{users: map[string]bool{}}
	common, _ := boxFixture(t, box.handler())
	withFakeProvider(t, nil) // must not be built
	prev := buildProviderFn
	buildProviderFn = func(string, string, bool) (providerFace, error) {
		t.Fatal("built a provider without a token")
		return nil, nil
	}
	t.Cleanup(func() { buildProviderFn = prev })
	call := stubProbe(t)
	out := runHealth(t, append([]string{"relay-health"}, common[:4]...)) // record + key only

	if out["server"].(map[string]any)["state"] != "not_checked" || out["management"].(map[string]any)["state"] != "not_checked" {
		t.Errorf("server/management = %v / %v", out["server"], out["management"])
	}
	// The record's DIRECT candidates on their canonical ports; the CDN
	// one is not at the relay's address.
	if fmt.Sprint(call.ways) != "[{vless-reality 443 false} {shadowsocks 8446 false}]" {
		t.Errorf("ways = %v", call.ways)
	}
	if call.opts.CoverSNI != "record-cover.example.org" || call.opts.CertPin != "PIN-FROM-RECORD" {
		t.Errorf("probe opts = %+v", call.opts)
	}
}

func TestRelayHealthCLI_AMissingServerIsNotAskedAnything(t *testing.T) {
	box := &cliBox{users: map[string]bool{}}
	common, _ := boxFixture(t, box.handler())
	wp := &windowProvider{state: provider.ServerMissing}
	withFakeProvider(t, wp)
	stubProbe(t)
	out := runHealth(t, append([]string{"relay-health"}, common...))
	if out["server"].(map[string]any)["state"] != "missing" || out["management"].(map[string]any)["state"] != "not_checked" {
		t.Errorf("server/management = %v / %v", out["server"], out["management"])
	}
	if wp.opened != 0 {
		t.Error("opened a firewall window for a server that does not exist")
	}
}

// --- D1: account-reclaim --include-unclaimed-servers reaches the adapter ---

type fakeServerReclaimer struct {
	fakeAuditProvider
	opts []provider.ReclaimOpts
}

func (f *fakeServerReclaimer) ReclaimOrphansWithOpts(_ context.Context, _ []*provider.OperatorRecord, only []provider.ResourceRef, opts provider.ReclaimOpts) (*provider.ReclaimReport, error) {
	f.opts = append(f.opts, opts)
	f.lastOnly = only
	rep := provider.NewReclaimReport("hetzner")
	rep.Add(provider.ReclaimOutcome{Kind: provider.KindServer, ID: "9", Deleted: opts.IncludeUnclaimedServers,
		Reason: map[bool]string{true: "deleted; it is no longer billing", false: "refused (unclaimed): x"}[opts.IncludeUnclaimedServers]})
	return rep, nil
}

func TestAccountReclaimCLI_IncludeUnclaimedServersIsPassedAndCoded(t *testing.T) {
	f := &fakeServerReclaimer{fakeAuditProvider: fakeAuditProvider{audit: auditWithOneOrphan()}}
	withFakeProvider(t, f)
	for _, withFlag := range []bool{false, true} {
		argv := []string{"account-reclaim", "--token-file", tokenFileFor(t), "--yes", "--json", "--only", "server:9"}
		if withFlag {
			argv = append(argv, "--include-unclaimed-servers")
		}
		var stdout, stderr bytes.Buffer
		if rc := Run(argv, &stdout, &stderr); rc != 0 {
			t.Fatalf("rc=%d %s", rc, stderr.String())
		}
		var rep provider.ReclaimReport
		if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
			t.Fatal(err)
		}
		want := map[bool]string{false: provider.ReclaimKeptUnproven, true: provider.ReclaimDeleted}[withFlag]
		if len(rep.Outcomes) != 1 || rep.Outcomes[0].Code != want {
			t.Errorf("flag=%v outcomes=%+v, want code %s", withFlag, rep.Outcomes, want)
		}
	}
	if len(f.opts) != 2 || f.opts[0].IncludeUnclaimedServers || !f.opts[1].IncludeUnclaimedServers {
		t.Fatalf("opts passed = %+v", f.opts)
	}
}
