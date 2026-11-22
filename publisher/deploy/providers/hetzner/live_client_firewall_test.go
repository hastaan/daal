package hetzner

// Tests for the live client's firewall rule edits, against a fake
// Hetzner Cloud API (httptest) rather than the hcloudClient fake,
// because the bug being pinned lives in what liveClient sends to
// set_rules. Regression: FirewallApplyCloudflareRule used to call
// set_rules with its one rule alone, wiping 80/tcp, every data-plane
// port and any open mgmt hole on the firewall it was given.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"daal/publisher/deploy/relayports"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"github.com/hetznercloud/hcloud-go/v2/hcloud/schema"
)

const (
	fakeServerID   = 4242
	fakeFirewallID = 777
)

// fakeHcloudAPI is the minimum of the Hetzner Cloud API the firewall
// verbs touch: GET /servers/{id}, GET /firewalls/{id},
// POST /firewalls/{id}/actions/set_rules, POST /firewalls.
type fakeHcloudAPI struct {
	mu       sync.Mutex
	rules    []schema.FirewallRule
	setCalls int
	created  []schema.FirewallCreateRequest

	// afterSet, when set, runs after each set_rules is stored, with
	// the lock held; it may rewrite f.rules to simulate another
	// writer landing after ours.
	afterSet func(f *fakeHcloudAPI)
	// getDelay widens the read-modify-write window so a
	// missing lock shows up as a lost update.
	getDelay time.Duration
	// detached: the server lists no firewall, while the firewall
	// named daal-relay-4242 still exists (FirewallEnsureForServer's
	// reuse path).
	detached bool
	applied  int
}

func ruleDesc(r schema.FirewallRule) string {
	if r.Description == nil {
		return ""
	}
	return *r.Description
}

func (f *fakeHcloudAPI) descriptions() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, r := range f.rules {
		out = append(out, fmt.Sprintf("%s/%s/%s", r.Protocol, deref(r.Port), ruleDesc(r)))
	}
	return out
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func (f *fakeHcloudAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	write := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	switch {
	case r.Method == http.MethodGet && r.URL.Path == fmt.Sprintf("/servers/%d", fakeServerID):
		fws := []map[string]any{{"id": fakeFirewallID, "status": "applied"}}
		if f.detached {
			fws = []map[string]any{}
		}
		write(map[string]any{"server": map[string]any{
			"id":         fakeServerID,
			"name":       "relay",
			"public_net": map[string]any{"firewalls": fws},
		}})
	case r.Method == http.MethodGet && r.URL.Path == "/firewalls":
		write(map[string]any{
			"firewalls": []map[string]any{{"id": fakeFirewallID, "name": "daal-relay-4242"}},
			"meta":      map[string]any{"pagination": map[string]any{"page": 1, "per_page": 50, "total_entries": 1}},
		})
	case r.Method == http.MethodPost && r.URL.Path == fmt.Sprintf("/firewalls/%d/actions/apply_to_resources", fakeFirewallID):
		f.mu.Lock()
		f.applied++
		f.mu.Unlock()
		write(map[string]any{"actions": []any{}})
	case r.Method == http.MethodGet && r.URL.Path == fmt.Sprintf("/firewalls/%d", fakeFirewallID):
		if f.getDelay > 0 {
			time.Sleep(f.getDelay)
		}
		f.mu.Lock()
		fw := schema.Firewall{ID: fakeFirewallID, Name: "daal-relay-4242", Rules: append([]schema.FirewallRule(nil), f.rules...)}
		f.mu.Unlock()
		write(schema.FirewallGetResponse{Firewall: fw})
	case r.Method == http.MethodPost && r.URL.Path == fmt.Sprintf("/firewalls/%d/actions/set_rules", fakeFirewallID):
		var req schema.FirewallActionSetRulesRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.setCalls++
		f.rules = f.rules[:0:0]
		for _, rr := range req.Rules {
			f.rules = append(f.rules, schema.FirewallRule{
				Direction: rr.Direction, SourceIPs: rr.SourceIPs, DestinationIPs: rr.DestinationIPs,
				Protocol: rr.Protocol, Port: rr.Port, Description: rr.Description,
			})
		}
		if f.afterSet != nil {
			f.afterSet(f)
		}
		f.mu.Unlock()
		write(schema.FirewallActionSetRulesResponse{Actions: []schema.Action{}})
	case r.Method == http.MethodPost && r.URL.Path == "/firewalls":
		var req schema.FirewallCreateRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		f.created = append(f.created, req)
		f.mu.Unlock()
		write(map[string]any{"firewall": map[string]any{"id": 9001, "name": req.Name}, "actions": []any{}})
	default:
		w.WriteHeader(http.StatusNotFound)
		write(map[string]any{"error": map[string]any{"code": "not_found", "message": r.Method + " " + r.URL.Path}})
	}
}

func newFakeLive(t *testing.T, f *fakeHcloudAPI) *liveClient {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return &liveClient{c: hcloud.NewClient(
		hcloud.WithEndpoint(srv.URL),
		hcloud.WithToken("fake-test-token"),
		hcloud.WithRetryOpts(hcloud.RetryOpts{MaxRetries: 0}),
	)}
}

// relayBaseline is what FirewallEnsureForServer leaves on a relay
// plus one open mgmt hole: the rules the old code deleted.
func relayBaseline() []schema.FirewallRule {
	srcAny := []string{"0.0.0.0/0", "::/0"}
	p := func(s string) *string { return &s }
	return []schema.FirewallRule{
		{Direction: "in", Protocol: "tcp", Port: p("80"), SourceIPs: srcAny},
		{Direction: "in", Protocol: "tcp", Port: p("443"), SourceIPs: srcAny},
		{Direction: "in", Protocol: "udp", Port: p("443"), SourceIPs: srcAny},
		{Direction: "in", Protocol: "tcp", Port: p("8444"), SourceIPs: srcAny},
		{Direction: "in", Protocol: "tcp", Port: p("8445"), SourceIPs: srcAny},
		// Still in date (2096): an expired one would be swept by the
		// next add or remove (TestLiveFirewall_EveryAddSweepsExpiredWindows).
		{Direction: "in", Protocol: "tcp", Port: p("31337"), SourceIPs: []string{"192.0.2.10/32"}, Description: p("daal-eph-4242-192.0.2.10-31337-4000000000")},
	}
}

// THE EXPIRY SWEEP: a window left by a process that was killed before
// its defer ran (port 22 or the health port open to the helper's
// address, which on mobile can be a carrier NAT shared by many) is
// dropped by the next add or remove on that firewall, in the same
// write. A window still in date, the Cloudflare rule and the baseline
// stay.
func TestLiveFirewall_EveryAddSweepsExpiredWindows(t *testing.T) {
	p := func(s string) *string { return &s }
	expired := "daal-eph-4242-192.0.2.11-22-1700000000"
	inDate := fmt.Sprintf("daal-eph-4242-192.0.2.12-9876-%d", time.Now().Add(time.Hour).Unix())
	f := &fakeHcloudAPI{rules: append(relayBaseline(),
		schema.FirewallRule{Direction: "in", Protocol: "tcp", Port: p("22"), SourceIPs: []string{"192.0.2.11/32"}, Description: p(expired)},
		schema.FirewallRule{Direction: "in", Protocol: "tcp", Port: p("9876"), SourceIPs: []string{"192.0.2.12/32"}, Description: p(inDate)},
		schema.FirewallRule{Direction: "in", Protocol: "tcp", Port: p(cdnOriginPort), SourceIPs: []string{"173.245.48.0/20"}, Description: p(cdnRuleDescription)},
	)}
	l := newFakeLive(t, f)
	ctx := context.Background()
	id, err := l.FirewallAddEphemeralRule(ctx, strconv.Itoa(fakeServerID), "198.51.100.7", 40001, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(f.descriptions(), " ")
	if strings.Contains(got, expired) {
		t.Errorf("an expired window survived an unrelated add: %s", got)
	}
	for _, want := range []string{inDate, cdnRuleDescription, id, "daal-eph-4242-192.0.2.10-31337-4000000000", "tcp/80/"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q after the sweep: %s", want, got)
		}
	}
	if f.setCalls != 1 {
		t.Errorf("the sweep cost an extra write: %d set_rules", f.setCalls)
	}

	// A remove sweeps too, and an add of a rule already there that
	// finds an expired window writes once to drop it.
	f.mu.Lock()
	f.rules = append(f.rules, schema.FirewallRule{Direction: "in", Protocol: "tcp", Port: p("22"), SourceIPs: []string{"192.0.2.11/32"}, Description: p(expired)})
	f.mu.Unlock()
	if err := l.FirewallRemoveEphemeralRule(ctx, "daal-eph-4242-203.0.113.1-1-4000000000"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.descriptions(), " "); strings.Contains(got, expired) || !strings.Contains(got, id) {
		t.Errorf("remove did not sweep, or swept too much: %s", got)
	}
}

func TestLiveFirewallApplyCloudflareRule_KeepsEveryOtherRule(t *testing.T) {
	f := &fakeHcloudAPI{rules: relayBaseline()}
	l := newFakeLive(t, f)
	id, err := l.FirewallApplyCloudflareRule(context.Background(), strconv.Itoa(fakeFirewallID),
		[]string{"173.245.48.0/20", "103.21.244.0/22"}, []string{"2400:cb00::/32"})
	if err != nil {
		t.Fatal(err)
	}
	if id != strconv.Itoa(fakeFirewallID) {
		t.Errorf("id = %q", id)
	}
	got := f.descriptions()
	want := []string{"tcp/80/", "tcp/443/", "udp/443/", "tcp/8444/", "tcp/8445/",
		"tcp/31337/daal-eph-4242-192.0.2.10-31337-4000000000", "tcp/" + cdnOriginPort + "/" + cdnRuleDescription}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("rules after apply:\n got  %v\n want %v", got, want)
	}
	cf := f.rules[len(f.rules)-1]
	if strings.Join(cf.SourceIPs, ",") != "173.245.48.0/20,103.21.244.0/22,2400:cb00::/32" {
		t.Errorf("cdn rule sources = %v", cf.SourceIPs)
	}
}

func TestLiveFirewallApplyCloudflareRule_RefreshReplacesOnlyItsOwnRule(t *testing.T) {
	f := &fakeHcloudAPI{rules: relayBaseline()}
	l := newFakeLive(t, f)
	ctx := context.Background()
	fw := strconv.Itoa(fakeFirewallID)
	if _, err := l.FirewallApplyCloudflareRule(ctx, fw, []string{"1.0.0.0/24"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := l.FirewallApplyCloudflareRule(ctx, fw, []string{"2.0.0.0/24"}, []string{"2400:cb00::/32"}); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range f.rules {
		if ruleDesc(r) == cdnRuleDescription {
			n++
			if strings.Join(r.SourceIPs, ",") != "2.0.0.0/24,2400:cb00::/32" {
				t.Errorf("refreshed sources = %v", r.SourceIPs)
			}
		}
	}
	if n != 1 {
		t.Errorf("want exactly one cdn rule, got %d", n)
	}
	if len(f.rules) != len(relayBaseline())+1 {
		t.Errorf("rule count = %d, want %d", len(f.rules), len(relayBaseline())+1)
	}

	// Same ranges again: no write at all.
	before := f.setCalls
	if _, err := l.FirewallApplyCloudflareRule(ctx, fw, []string{"2.0.0.0/24"}, []string{"2400:cb00::/32"}); err != nil {
		t.Fatal(err)
	}
	if f.setCalls != before {
		t.Errorf("identical re-apply wrote set_rules (%d -> %d)", before, f.setCalls)
	}
}

func TestLiveFirewallApplyCloudflareRule_RetriesWhenOverwrittenAfterWrite(t *testing.T) {
	f := &fakeHcloudAPI{rules: relayBaseline()}
	// Another writer replaces the set right after our first write,
	// dropping our rule and adding one of its own.
	fired := false
	f.afterSet = func(f *fakeHcloudAPI) {
		if fired {
			return
		}
		fired = true
		p := "9999"
		f.rules = append(relayBaseline(), schema.FirewallRule{Direction: "in", Protocol: "tcp", Port: &p, SourceIPs: []string{"0.0.0.0/0"}})
	}
	l := newFakeLive(t, f)
	if _, err := l.FirewallApplyCloudflareRule(context.Background(), strconv.Itoa(fakeFirewallID), []string{"1.0.0.0/24"}, nil); err != nil {
		t.Fatal(err)
	}
	if f.setCalls != 2 {
		t.Errorf("set_rules calls = %d, want 2 (one retry)", f.setCalls)
	}
	got := strings.Join(f.descriptions(), " ")
	if !strings.Contains(got, "tcp/9999/") || !strings.Contains(got, "tcp/"+cdnOriginPort+"/"+cdnRuleDescription) {
		t.Errorf("retry must keep the other writer's rule and land ours: %v", got)
	}
}

func TestLiveFirewallApplyCloudflareRule_GivesUpWhenNeverLands(t *testing.T) {
	f := &fakeHcloudAPI{rules: relayBaseline()}
	f.afterSet = func(f *fakeHcloudAPI) { f.rules = relayBaseline() }
	l := newFakeLive(t, f)
	_, err := l.FirewallApplyCloudflareRule(context.Background(), strconv.Itoa(fakeFirewallID), []string{"1.0.0.0/24"}, nil)
	if !errors.Is(err, errFirewallConcurrentChange) {
		t.Fatalf("want errFirewallConcurrentChange, got %v", err)
	}
	if f.setCalls != firewallWriteAttempts {
		t.Errorf("set_rules calls = %d, want %d", f.setCalls, firewallWriteAttempts)
	}
}

func TestLiveFirewallApplyCloudflareRule_RejectsBadOrEmptyRanges(t *testing.T) {
	f := &fakeHcloudAPI{rules: relayBaseline()}
	l := newFakeLive(t, f)
	ctx := context.Background()
	fw := strconv.Itoa(fakeFirewallID)
	if _, err := l.FirewallApplyCloudflareRule(ctx, fw, nil, nil); !errors.Is(err, errEmptyRanges) {
		t.Errorf("empty ranges: got %v", err)
	}
	if _, err := l.FirewallApplyCloudflareRule(ctx, fw, []string{"2400:cb00::/32"}, nil); err == nil {
		t.Error("v6 range in the v4 list must be refused")
	}
	if _, err := l.FirewallApplyCloudflareRule(ctx, fw, []string{"nope"}, nil); err == nil {
		t.Error("garbage cidr must be refused")
	}
	if f.setCalls != 0 {
		t.Errorf("a refused call wrote set_rules %d times", f.setCalls)
	}
}

// Defect 3: an empty firewall id used to create a fresh firewall holding
// only this rule and attached to nothing. It is refused now, before any
// API call.
func TestLiveFirewallApplyCloudflareRule_RefusesNoFirewall(t *testing.T) {
	f := &fakeHcloudAPI{}
	l := newFakeLive(t, f)
	_, err := l.FirewallApplyCloudflareRule(context.Background(), "", []string{"1.0.0.0/24"}, nil)
	if !errors.Is(err, errNoRelayFirewall) {
		t.Fatalf("want errNoRelayFirewall, got %v", err)
	}
	if len(f.created) != 0 || f.setCalls != 0 {
		t.Errorf("refused call reached the API: created=%d set=%d", len(f.created), f.setCalls)
	}
}

// The default port is the CDN door's, never 443 (REALITY, world-open).
func TestLiveFirewallApplyCloudflareRule_DefaultsToTheCDNDoor(t *testing.T) {
	if cdnOriginPort != strconv.Itoa(relayports.CDNOrigin.Port) || cdnOriginPort == "443" {
		t.Fatalf("cdnOriginPort = %s", cdnOriginPort)
	}
}

// A port the firewall already opens to everyone is refused: the rule
// would narrow nothing while the posture said "only Cloudflare".
func TestLiveFirewallApplyCloudflareRuleOnPort_RefusesWorldOpenPort(t *testing.T) {
	f := &fakeHcloudAPI{rules: relayBaseline()}
	l := newFakeLive(t, f)
	_, err := l.FirewallApplyCloudflareRuleOnPort(context.Background(), strconv.Itoa(fakeFirewallID), 443, []string{"1.0.0.0/24"}, nil)
	if !errors.Is(err, errCDNPortWorldOpen) {
		t.Fatalf("want errCDNPortWorldOpen, got %v", err)
	}
	if f.setCalls != 0 {
		t.Errorf("refused call wrote set_rules %d times", f.setCalls)
	}
}

func TestLiveFirewallApplyCloudflareRule_RefusesEveryoneAsARange(t *testing.T) {
	f := &fakeHcloudAPI{rules: relayBaseline()}
	l := newFakeLive(t, f)
	if _, err := l.FirewallApplyCloudflareRule(context.Background(), strconv.Itoa(fakeFirewallID), []string{"0.0.0.0/0"}, nil); err == nil {
		t.Fatal("0.0.0.0/0 is not a Cloudflare range")
	}
}

// In-process writers must not lose one another's rules. The GET
// delay makes every unlocked read-modify-write overlap.
func TestLiveFirewall_ConcurrentWritersKeepEveryRule(t *testing.T) {
	f := &fakeHcloudAPI{rules: relayBaseline(), getDelay: 5 * time.Millisecond}
	l := newFakeLive(t, f)
	ctx := context.Background()
	exp := time.Unix(1_900_000_000, 0)
	const n = 6
	var wg sync.WaitGroup
	errs := make(chan error, n+1)
	ids := make([]string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id, err := l.FirewallAddEphemeralRule(ctx, strconv.Itoa(fakeServerID), fmt.Sprintf("198.51.100.%d", i+1), 40000+i, exp)
			ids[i] = id
			errs <- err
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := l.FirewallApplyCloudflareRule(ctx, strconv.Itoa(fakeFirewallID), []string{"1.0.0.0/24"}, nil)
		errs <- err
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	have := map[string]bool{}
	for _, r := range f.rules {
		have[ruleDesc(r)] = true
	}
	for _, id := range ids {
		if !have[id] {
			t.Errorf("lost ephemeral rule %q", id)
		}
	}
	if !have[cdnRuleDescription] {
		t.Error("lost cdn rule")
	}
	if len(f.rules) != len(relayBaseline())+n+1 {
		t.Errorf("rule count = %d, want %d", len(f.rules), len(relayBaseline())+n+1)
	}

	// Removal keeps everything else too.
	if err := l.FirewallRemoveEphemeralRule(ctx, ids[0]); err != nil {
		t.Fatal(err)
	}
	have = map[string]bool{}
	for _, r := range f.rules {
		have[ruleDesc(r)] = true
	}
	if have[ids[0]] || !have[ids[1]] || !have[cdnRuleDescription] || len(f.rules) != len(relayBaseline())+n {
		t.Errorf("remove dropped the wrong rules: %v", f.descriptions())
	}
	// Removing again is a no-op, not a write.
	before := f.setCalls
	if err := l.FirewallRemoveEphemeralRule(ctx, ids[0]); err != nil {
		t.Fatal(err)
	}
	if f.setCalls != before {
		t.Error("removing an absent rule wrote set_rules")
	}
}

func TestLiveFirewallAddEphemeralRule_IdempotentAndNoRawIPInError(t *testing.T) {
	f := &fakeHcloudAPI{rules: relayBaseline()}
	l := newFakeLive(t, f)
	ctx := context.Background()
	exp := time.Unix(1_900_000_000, 0)
	id1, err := l.FirewallAddEphemeralRule(ctx, strconv.Itoa(fakeServerID), "198.51.100.7", 40001, exp)
	if err != nil {
		t.Fatal(err)
	}
	id2, err := l.FirewallAddEphemeralRule(ctx, strconv.Itoa(fakeServerID), "198.51.100.7", 40001, exp)
	if err != nil || id2 != id1 {
		t.Fatalf("second add: id=%q err=%v", id2, err)
	}
	if f.setCalls != 1 || len(f.rules) != len(relayBaseline())+1 {
		t.Errorf("duplicate add wrote again: set=%d rules=%d", f.setCalls, len(f.rules))
	}
	_, err = l.FirewallAddEphemeralRule(ctx, strconv.Itoa(fakeServerID), "not-an-ip-198.51.100.9", 40001, exp)
	if err == nil || strings.Contains(err.Error(), "198.51.100.9") {
		t.Errorf("bad ip error must not echo the input: %v", err)
	}
}

func TestWithCloudflareRule_Pure(t *testing.T) {
	d := cdnRuleDescription
	other := "x"
	_, n1, _ := net.ParseCIDR("1.0.0.0/24")
	cur := []hcloud.FirewallRule{
		{Description: &other},
		{Description: &d},
		{},
		{Description: &d},
	}
	next := withCloudflareRule(cur, hcloud.FirewallRule{Description: &d, SourceIPs: []net.IPNet{*n1}})
	if len(next) != 3 || ruleHasDescription(next[0], d) || next[1].Description != nil || !ruleHasDescription(next[2], d) {
		t.Errorf("merge = %+v", next)
	}
	if len(cur) != 4 {
		t.Error("input mutated")
	}
}

// set_rules lands but the rule never reads back (another writer keeps
// replacing the set): the add fails, and its id still comes back so
// the caller can close what may be open.
func TestLiveFirewallAddEphemeralRule_ReturnsTheIDWithAPostWriteError(t *testing.T) {
	f := &fakeHcloudAPI{rules: relayBaseline()}
	f.afterSet = func(f *fakeHcloudAPI) { f.rules = relayBaseline() }
	l := newFakeLive(t, f)
	id, err := l.FirewallAddEphemeralRule(context.Background(), strconv.Itoa(fakeServerID), "198.51.100.7", 40001, time.Unix(1_900_000_000, 0))
	if !errors.Is(err, errFirewallConcurrentChange) || id == "" {
		t.Fatalf("id=%q err=%v; want the id with errFirewallConcurrentChange", id, err)
	}
	// Before any write (bad server id) there is nothing to close.
	if id, err := l.FirewallAddEphemeralRule(context.Background(), "x", "198.51.100.7", 40001, time.Unix(1_900_000_000, 0)); err == nil || id != "" {
		t.Errorf("pre-write failure: id=%q err=%v", id, err)
	}
}

// W1-D: FirewallEnsureForServer reusing a detached firewall used to
// call set_rules with the baseline alone, deleting Daal's Cloudflare
// rule and any mgmt window still in date. It now resets only the
// untagged rules.
func TestLiveFirewallEnsureForServer_ReuseKeepsDaalRules(t *testing.T) {
	p := func(s string) *string { return &s }
	future := time.Now().Add(time.Hour).Unix()
	live := fmt.Sprintf("daal-eph-4242-192.0.2.10-31337-%d", future)
	stale := "daal-eph-4242-192.0.2.11-31338-1"
	f := &fakeHcloudAPI{detached: true, rules: []schema.FirewallRule{
		{Direction: "in", Protocol: "tcp", Port: p("80"), SourceIPs: []string{"0.0.0.0/0", "::/0"}},
		// drift: someone opened 3389 to the world in the console
		{Direction: "in", Protocol: "tcp", Port: p("3389"), SourceIPs: []string{"0.0.0.0/0"}},
		{Direction: "in", Protocol: "tcp", Port: p(cdnOriginPort), SourceIPs: []string{"173.245.48.0/20"}, Description: p(cdnRuleDescription)},
		{Direction: "in", Protocol: "tcp", Port: p("31337"), SourceIPs: []string{"192.0.2.10/32"}, Description: p(live)},
		{Direction: "in", Protocol: "tcp", Port: p("31338"), SourceIPs: []string{"192.0.2.11/32"}, Description: p(stale)},
	}}
	l := newFakeLive(t, f)
	ports := []relayports.Endpoint{{Port: 443}, {Port: 443, UDP: true}}
	id, err := l.FirewallEnsureForServer(context.Background(), strconv.Itoa(fakeServerID), ports)
	if err != nil {
		t.Fatal(err)
	}
	if id != strconv.Itoa(fakeFirewallID) || f.applied != 1 {
		t.Fatalf("id=%q applied=%d", id, f.applied)
	}
	got := strings.Join(f.descriptions(), " ")
	for _, want := range []string{"tcp/80/", "tcp/443/", "udp/443/", "tcp/" + cdnOriginPort + "/" + cdnRuleDescription, "tcp/31337/" + live} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %s", want, got)
		}
	}
	for _, gone := range []string{"tcp/3389/", stale} {
		if strings.Contains(got, gone) {
			t.Errorf("kept %q: %s", gone, got)
		}
	}
	if len(f.rules) != 5 {
		t.Errorf("rules = %s, want 5", got)
	}

	// Already right: a second ensure writes nothing.
	before := f.setCalls
	if _, err := l.FirewallEnsureForServer(context.Background(), strconv.Itoa(fakeServerID), ports); err != nil {
		t.Fatal(err)
	}
	if f.setCalls != before {
		t.Errorf("an unchanged firewall was rewritten (%d -> %d)", before, f.setCalls)
	}
}

func TestEphemeralRuleExpiry(t *testing.T) {
	for desc, want := range map[string]int64{
		"daal-eph-4242-192.0.2.10-31337-1900000000": 1_900_000_000,
		"daal-eph-4242-2001:db8::1-22-1900000000":   1_900_000_000,
	} {
		got, ok := ephemeralRuleExpiry(desc)
		if !ok || got.Unix() != want {
			t.Errorf("%s: %v %v", desc, got, ok)
		}
	}
	for _, desc := range []string{"", cdnRuleDescription, "daal-eph-x-y-z-notanumber"} {
		if _, ok := ephemeralRuleExpiry(desc); ok {
			t.Errorf("%q parsed as ephemeral", desc)
		}
	}
}
