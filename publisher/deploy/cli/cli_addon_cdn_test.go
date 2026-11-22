package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"daal/publisher/deploy/cloudflare"
	"daal/publisher/deploy/providers/hetzner"
)

const (
	cdnTestCFToken = "cf-token-must-never-appear-0001"
	cdnTestHZToken = "hz-token-must-never-appear-0002"
)

type fakeCDNFirewall struct {
	rules   map[string]*cloudflare.EdgeRanges
	failErr error
	removed []string
}

func (f *fakeCDNFirewall) ApplyCloudflareRule(_ context.Context, id string, r *cloudflare.EdgeRanges) (string, error) {
	if f.failErr != nil {
		return "", f.failErr
	}
	if id == "" {
		return "", errors.New("no firewall")
	}
	f.rules[id] = r
	return id, nil
}

func (f *fakeCDNFirewall) RemoveCloudflareRule(_ context.Context, id string) error {
	delete(f.rules, id)
	f.removed = append(f.removed, id)
	return nil
}

func (f *fakeCDNFirewall) CloudflareRule(_ context.Context, id string) (hetzner.CloudflareRuleState, error) {
	r, ok := f.rules[id]
	if !ok {
		return hetzner.CloudflareRuleState{}, nil
	}
	return hetzner.CloudflareRuleState{Present: true, Port: "8448", Sources: len(r.V4) + len(r.V6)}, nil
}

func (f *fakeCDNFirewall) DoorPortOpenToCloudflareOnly(st hetzner.CloudflareRuleState) bool {
	return st.Present && st.Sources > 0 && st.Port == "8448"
}

type fakeEdgeFetcher struct{}

func (fakeEdgeFetcher) FetchV4(context.Context) ([]string, error) { return []string{"173.245.48.0/20"}, nil }
func (fakeEdgeFetcher) FetchV6(context.Context) ([]string, error) { return []string{"2400:cb00::/32"}, nil }

// withCDNFakes points every seam at a fake and returns them.
func withCDNFakes(t *testing.T) (*cloudflare.MockCFClient, *fakeCDNFirewall, string) {
	t.Helper()
	m := cloudflare.NewMockCFClient("example.com")
	fw := &fakeCDNFirewall{rules: map[string]*cloudflare.EdgeRanges{}}
	oldCF, oldEdge, oldECH, oldFW, oldTest := newCFClient, newEdgeFetcher, newECHFetcher, newCDNFirewall, frontTest
	newCFClient = func() cloudflare.CFClient { return m }
	newEdgeFetcher = func() cloudflare.EdgeRangeFetcher { return fakeEdgeFetcher{} }
	newECHFetcher = func() cloudflare.ECHFetcher { return &cloudflare.MockECHFetcher{} }
	newCDNFirewall = func(token string) cdnFirewall {
		if token != cdnTestHZToken {
			t.Errorf("firewall built with the wrong token")
		}
		return fw
	}
	t.Cleanup(func() {
		newCFClient, newEdgeFetcher, newECHFetcher, newCDNFirewall, frontTest = oldCF, oldEdge, oldECH, oldFW, oldTest
	})
	dir := t.TempDir()
	for name, tok := range map[string]string{"cf": cdnTestCFToken, "hz": cdnTestHZToken} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(tok+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return m, fw, dir
}

func cdnRunCLI(t *testing.T, argv ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	rc := Run(argv, &out, &errb)
	for _, tok := range []string{cdnTestCFToken, cdnTestHZToken} {
		if strings.Contains(out.String(), tok) || strings.Contains(errb.String(), tok) {
			t.Fatalf("%v printed a token:\nstdout %s\nstderr %s", argv, out.String(), errb.String())
		}
	}
	return rc, out.String(), errb.String()
}

func cdnProvisionArgs(dir string, extra ...string) []string {
	return append([]string{"cdn-provision",
		"--hostname", "relay.example.com", "--origin-ip", "5.75.1.2",
		"--out-dir", filepath.Join(dir, "out"),
		"--cf-token-file", filepath.Join(dir, "cf"), "--token-file", filepath.Join(dir, "hz"),
		"--firewall-id", "777", "--progress-json"}, extra...)
}

func TestCDNTokenCheckVerb(t *testing.T) {
	m, _, dir := withCDNFakes(t)
	rc, out, _ := cdnRunCLI(t, "cdn-token-check", "--token-file", filepath.Join(dir, "cf"), "--zone", "example.com")
	if rc != 0 {
		t.Fatalf("rc=%d out=%s", rc, out)
	}
	var res cloudflare.TokenCheck
	if err := json.Unmarshal([]byte(out), &res); err != nil || res.Verdict != cloudflare.VerdictOK {
		t.Fatalf("out = %s", out)
	}
	if res.Zone != "example.com" {
		t.Fatalf("zone = %q", res.Zone)
	}
	// More than the five: it works, and the extra is named.
	m.ProbeAnswer["/accounts/acct-1/workers/scripts"] = cloudflare.ProbeAllowed
	rc, out, _ = cdnRunCLI(t, "cdn-token-check", "--token-file", filepath.Join(dir, "cf"))
	if rc != 0 || !strings.Contains(out, `"ok_broad"`) || !strings.Contains(out, "Workers Scripts") {
		t.Fatalf("broad: rc=%d out=%s", rc, out)
	}
	// Several zones and none picked: the list, not usable yet.
	m.Zones = append(m.Zones, cloudflare.Zone{ID: "zone-b.org", Name: "b.org", Status: "active", AccountID: "acct-1"})
	rc, out, _ = cdnRunCLI(t, "cdn-token-check", "--token-file", filepath.Join(dir, "cf"))
	if rc != exitCDNRefused || !strings.Contains(out, `"pick_zone"`) || !strings.Contains(out, "b.org") {
		t.Fatalf("two zones: rc=%d out=%s", rc, out)
	}
	// The zone picked is the one checked.
	rc, out, _ = cdnRunCLI(t, "cdn-token-check", "--token-file", filepath.Join(dir, "cf"), "--zone", "example.com")
	if rc != 0 || !strings.Contains(out, `"zone": "example.com"`) {
		t.Fatalf("picked: rc=%d out=%s", rc, out)
	}
	// Short of one of the five: refused, and the missing one is named.
	delete(m.ProbeAnswer, "/zones/zone-example.com/dns_records?per_page=1")
	rc, out, _ = cdnRunCLI(t, "cdn-token-check", "--token-file", filepath.Join(dir, "cf"), "--zone", "example.com")
	if rc != exitCDNRefused || !strings.Contains(out, `"missing_permission"`) || !strings.Contains(out, "Zone — DNS") {
		t.Fatalf("short: rc=%d out=%s", rc, out)
	}
	if rc, _, _ := cdnRunCLI(t, "cdn-token-check"); rc != 2 {
		t.Errorf("no flags: rc=%d", rc)
	}
}

func TestCDNProvisionVerb(t *testing.T) {
	m, fw, dir := withCDNFakes(t)
	rc, out, errOut := cdnRunCLI(t, cdnProvisionArgs(dir)...)
	if rc != 0 {
		t.Fatalf("rc=%d stderr=%s", rc, errOut)
	}
	var rec cloudflare.FrontRecord
	if err := json.Unmarshal([]byte(out), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.FirewallID != "777" || rec.OriginPort != 8448 || rec.LastEdgeRefreshUnix == 0 || rec.WorkerRouteID != "" {
		t.Errorf("record = %+v", rec)
	}
	if r := fw.rules["777"]; r == nil || len(r.V4) != 1 || len(r.V6) != 1 {
		t.Errorf("firewall rules = %+v", fw.rules)
	}
	if len(m.OriginRules["zone-example.com"]) != 1 {
		t.Errorf("origin rules = %v", m.OriginRules)
	}
	// Old wizard keys still decode (CdnFrontResult).
	var old map[string]any
	_ = json.Unmarshal([]byte(out), &old)
	for _, k := range []string{"hostname", "zone_id", "public_path", "origin_path", "worker_route_id", "firewall_id",
		"origin_ca_fingerprint", "origin_ca_cert_path", "origin_ca_priv_path", "aop_client_cert_path", "aop_enabled"} {
		if _, ok := old[k]; !ok {
			t.Errorf("record lost key %q", k)
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(errOut), "\n") {
		if !json.Valid([]byte(line)) {
			t.Errorf("progress line not JSON: %q", line)
		}
	}
}

func TestCDNProvisionVerb_Usage(t *testing.T) {
	_, _, dir := withCDNFakes(t)
	args := cdnProvisionArgs(dir)
	var noFW []string
	for i := 0; i < len(args); i++ {
		if args[i] == "--firewall-id" {
			i++
			continue
		}
		noFW = append(noFW, args[i])
	}
	if rc, _, _ := cdnRunCLI(t, noFW...); rc != 2 {
		t.Errorf("no --firewall-id: rc=%d (the rule must go on the relay's own firewall)", rc)
	}
	if rc, _, _ := cdnRunCLI(t, cdnProvisionArgs(dir, "--origin-path", "/a", "--public-path", "/b")...); rc != 2 {
		t.Errorf("worker-style public path accepted: rc=%d", rc)
	}
}

// The firewall step failing takes the Cloudflare side down again.
func TestCDNProvisionVerb_FirewallFailureRollsBack(t *testing.T) {
	m, fw, dir := withCDNFakes(t)
	fw.failErr = errors.New("hetzner said no " + cdnTestHZToken)
	rc, out, errOut := cdnRunCLI(t, cdnProvisionArgs(dir)...)
	if rc != 1 || out != "" {
		t.Fatalf("rc=%d out=%s", rc, out)
	}
	if !strings.Contains(errOut, "removed again") {
		t.Errorf("stderr = %s", errOut)
	}
	z := "zone-example.com"
	if len(m.Records[z]) != 0 || len(m.OriginRules[z]) != 0 || len(m.OriginCerts) != 0 || len(m.AOPCerts[z]) != 0 || m.AOPOn[z] {
		t.Errorf("cloudflare left: records=%v rules=%v certs=%v aop=%v/%v", m.Records[z], m.OriginRules[z], m.OriginCerts, m.AOPCerts[z], m.AOPOn[z])
	}
	if m.Settings[z]["ssl"] != "flexible" || m.Settings[z]["websockets"] != "off" {
		t.Errorf("settings not restored: %v", m.Settings[z])
	}
}

func provisionRecordFile(t *testing.T, dir string) string {
	t.Helper()
	rc, out, errOut := cdnRunCLI(t, cdnProvisionArgs(dir)...)
	if rc != 0 {
		t.Fatalf("provision: %s", errOut)
	}
	p := filepath.Join(dir, "front.json")
	if err := os.WriteFile(p, []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCDNPostureVerb(t *testing.T) {
	_, _, dir := withCDNFakes(t)
	recFile := provisionRecordFile(t, dir)
	rc, out, errOut := cdnRunCLI(t, "cdn-posture", "--record-file", recFile, "--token-file", filepath.Join(dir, "cf"),
		"--hetzner-token-file", filepath.Join(dir, "hz"))
	if rc != 0 {
		t.Fatalf("rc=%d %s", rc, errOut)
	}
	var rep cloudflare.PostureReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	if !rep.FirewallChecked || !rep.OnlyCloudflare || !rep.SSLStrict || !rep.OriginRule || rep.NameHidden {
		t.Errorf("posture = %+v (the mock DoH publishes no ECH, so the name is not hidden)", rep)
	}
}

func TestCDNRemoveVerb(t *testing.T) {
	m, fw, dir := withCDNFakes(t)
	recFile := provisionRecordFile(t, dir)
	rc, out, errOut := cdnRunCLI(t, "cdn-remove", "--record-file", recFile, "--token-file", filepath.Join(dir, "cf"),
		"--hetzner-token-file", filepath.Join(dir, "hz"))
	if rc != 0 {
		t.Fatalf("rc=%d %s %s", rc, out, errOut)
	}
	var res cdnRemoveResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatal(err)
	}
	states := map[string]string{}
	for _, s := range res.Steps {
		states[s.Name] = s.State
	}
	if states["firewall_rule"] != "done" || states["dns_records"] != "done" || states["relay_door"] != "skipped" {
		t.Errorf("steps = %v", states)
	}
	if len(fw.rules) != 0 || len(m.Records["zone-example.com"]) != 0 {
		t.Errorf("left: fw=%v records=%v", fw.rules, m.Records)
	}
	if len(res.Tell) != 2 {
		t.Errorf("tell = %v", res.Tell)
	}
}

func TestCDNTestVerb(t *testing.T) {
	_, _, dir := withCDNFakes(t)
	recFile := provisionRecordFile(t, dir)
	// The record carries no ECH config (mock DoH): requiring ECH refuses
	// before dialling.
	called := false
	frontTest = func(_ context.Context, o cloudflare.FrontTestOpts) cloudflare.FrontTestResult {
		called = true
		return cloudflare.FrontTestResult{OK: true, Edge: o.Edge, HTTPStatus: 101}
	}
	if rc, out, _ := cdnRunCLI(t, "cdn-test", "--record-file", recFile); rc != exitCDNRefused || called || !strings.Contains(out, "no ECH config") {
		t.Fatalf("rc=%d called=%v out=%s", rc, called, out)
	}
	rc, out, _ := cdnRunCLI(t, "cdn-test", "--record-file", recFile, "--require-ech=false", "--edge", "104.16.0.1:443", "--timeout", (2 * time.Second).String())
	if rc != 0 || !called || !strings.Contains(out, "104.16.0.1:443") {
		t.Fatalf("rc=%d out=%s", rc, out)
	}
}
