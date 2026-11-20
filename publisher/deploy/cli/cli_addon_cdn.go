package cli

// Add-on 2, way in through Cloudflare (docs/optional-addons-plan.md §2,
// items B-2, B-3, B-5; specs/optional-addons-v1.md §4 and §6.3).
//
//	cdn-token-check --token-file F [--zone Z]
//	        verify the token, list the zones it sees, refuse one that sees
//	        more than one zone or can do more than the five zone
//	        permissions (verdict too_broad), or lacks one of them
//	cdn-test        --record-file R [--edge ip:port] [--require-ech=false]
//	                [--refresh-ech] [--timeout 15s]
//	        one real TLS + WebSocket handshake through the front, with ECH
//	cdn-posture     --record-file R --token-file F [--hetzner-token-file H]
//	                [--no-doh]
//	        read-only: SSL strict, WebSockets, origin rule, origin pull,
//	        proxied-only DNS, ECH (zone setting and the published config),
//	        and with H the relay firewall rule
//	cdn-remove      --record-file R --token-file F [--hetzner-token-file H]
//	        delete the DNS records and the origin rule, revoke the origin
//	        certificate, delete the origin-pull certificate, put back the
//	        zone settings Daal changed, and with H close the firewall rule
//
// cdn-provision (cli.go) builds it; see runCDNProvision.
//
// Tokens are read from files (the wizard writes them 0600 and deletes
// them), zeroed after use, and never printed: not on stdout, not on
// stderr, not inside an error. Exit codes: 0 done; 1 an error (nothing
// was decided); 2 usage; 4 a refusal or a failed check, with the JSON
// that says why on stdout.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"daal/publisher/deploy/cloudflare"
	"daal/publisher/deploy/providers/hetzner"
)

const exitCDNRefused = 4

// Seams, so the verbs run against MockCFClient and fakes in tests.
// Production leaves them pointing at the live implementations.
var (
	newCFClient    = cloudflare.NewLiveCFClient
	newEdgeFetcher = func() cloudflare.EdgeRangeFetcher { return cloudflare.NewHTTPSEdgeRangeFetcher() }
	newECHFetcher  = func() cloudflare.ECHFetcher { return cloudflare.NewDoHECHFetcher() }
	newCDNFirewall = func(token string) cdnFirewall {
		return hetzner.NewCloudflareFirewallApplier(hetzner.NewLiveClient(token))
	}
	frontTest = cloudflare.FrontTest
)

// cdnFirewall is the relay-firewall half of the add-on (B-2).
type cdnFirewall interface {
	ApplyCloudflareRule(ctx context.Context, firewallID string, ranges *cloudflare.EdgeRanges) (string, error)
	RemoveCloudflareRule(ctx context.Context, firewallID string) error
	CloudflareRule(ctx context.Context, firewallID string) (hetzner.CloudflareRuleState, error)
	DoorPortOpenToCloudflareOnly(st hetzner.CloudflareRuleState) bool
}

// readSecretFile reads a token file. The bytes are the caller's to zero.
func cdnReadSecret(path, flagName string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", flagName, err)
	}
	t := []byte(strings.TrimSpace(string(b)))
	zeroBytes(b)
	if len(t) == 0 {
		return nil, fmt.Errorf("%s is empty", flagName)
	}
	return t, nil
}

func cdnReadRecord(path string) (*cloudflare.FrontRecord, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read --record-file: %w", err)
	}
	var rec cloudflare.FrontRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return nil, fmt.Errorf("--record-file is not a front record: %w", err)
	}
	if rec.Hostname == "" || rec.ZoneID == "" {
		return nil, errors.New("--record-file has no hostname or zone")
	}
	return &rec, nil
}

func cdnWriteJSON(stdout io.Writer, v any) error {
	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, string(body))
	return err
}

// secretSafe returns err's text with the token removed, for stderr.
func cdnSecretSafe(err error, secrets ...[]byte) string {
	msg := err.Error()
	for _, s := range secrets {
		if len(s) > 0 {
			msg = strings.ReplaceAll(msg, string(s), "[token]")
		}
	}
	return msg
}

func runCDNTokenCheck(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cdn-token-check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	tokenFile := fs.String("token-file", "", "Cloudflare API token file")
	zone := fs.String("zone", "", "the zone the publisher picked (optional)")
	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if err := requireAll(stderr, map[string]string{"--token-file": *tokenFile}); err != nil {
		return 2
	}
	tok, err := cdnReadSecret(*tokenFile, "--token-file")
	if err != nil {
		fmt.Fprintf(stderr, "cdn-token-check: %v\n", err)
		return 1
	}
	defer zeroBytes(tok)
	res, err := cloudflare.CheckToken(ctx, newCFClient(), tok, *zone)
	if err != nil {
		fmt.Fprintf(stderr, "cdn-token-check: %s\n", cdnSecretSafe(err, tok))
		return 1
	}
	if err := cdnWriteJSON(stdout, res); err != nil {
		fmt.Fprintf(stderr, "cdn-token-check: %v\n", err)
		return 1
	}
	if res.Verdict != cloudflare.VerdictOK {
		return exitCDNRefused
	}
	return 0
}

func runCDNTest(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cdn-test", flag.ContinueOnError)
	fs.SetOutput(stderr)
	recordFile := fs.String("record-file", "", "front record JSON (cdn-provision output)")
	edge := fs.String("edge", "", "Cloudflare edge ip:port to dial (default: the hostname on 443)")
	requireECH := fs.Bool("require-ech", true, "fail unless the edge accepts ECH")
	refreshECH := fs.Bool("refresh-ech", false, "read the ECH config over DoH now instead of using the record's")
	timeout := fs.Duration("timeout", 15*time.Second, "whole-test timeout")
	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if err := requireAll(stderr, map[string]string{"--record-file": *recordFile}); err != nil {
		return 2
	}
	rec, err := cdnReadRecord(*recordFile)
	if err != nil {
		fmt.Fprintf(stderr, "cdn-test: %v\n", err)
		return 1
	}
	var list []byte
	if *refreshECH {
		p := cloudflare.ReadECHPosture(ctx, newECHFetcher(), rec.Hostname, time.Now().Unix())
		if p.Error != "" {
			fmt.Fprintf(stderr, "cdn-test: ech: %s\n", p.Error)
		}
		rec.ECH.ConfigListB64 = p.ConfigListB64
	}
	if rec.ECH.ConfigListB64 != "" {
		if list, err = base64.StdEncoding.DecodeString(rec.ECH.ConfigListB64); err != nil {
			fmt.Fprintf(stderr, "cdn-test: record ech config: %v\n", err)
			return 1
		}
	}
	if *requireECH && len(list) == 0 {
		_ = cdnWriteJSON(stdout, cloudflare.FrontTestResult{Edge: *edge, Detail: "no ECH config for this hostname; the zone may have ECH off (run cdn-posture), or pass --require-ech=false to test without it"})
		return exitCDNRefused
	}
	res := frontTest(ctx, cloudflare.FrontTestOpts{
		Hostname:      rec.Hostname,
		Path:          rec.OriginPath,
		Edge:          *edge,
		ECHConfigList: list,
		RequireECH:    *requireECH,
		Timeout:       *timeout,
	})
	if err := cdnWriteJSON(stdout, res); err != nil {
		fmt.Fprintf(stderr, "cdn-test: %v\n", err)
		return 1
	}
	if !res.OK {
		return exitCDNRefused
	}
	return 0
}

func runCDNPosture(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cdn-posture", flag.ContinueOnError)
	fs.SetOutput(stderr)
	recordFile := fs.String("record-file", "", "front record JSON (cdn-provision output)")
	tokenFile := fs.String("token-file", "", "Cloudflare API token file")
	hzTokenFile := fs.String("hetzner-token-file", "", "Hetzner API token file (optional: reads the relay firewall rule)")
	noDoH := fs.Bool("no-doh", false, "do not read the published ECH config over DoH")
	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if err := requireAll(stderr, map[string]string{"--record-file": *recordFile, "--token-file": *tokenFile}); err != nil {
		return 2
	}
	rec, err := cdnReadRecord(*recordFile)
	if err != nil {
		fmt.Fprintf(stderr, "cdn-posture: %v\n", err)
		return 1
	}
	tok, err := cdnReadSecret(*tokenFile, "--token-file")
	if err != nil {
		fmt.Fprintf(stderr, "cdn-posture: %v\n", err)
		return 1
	}
	defer zeroBytes(tok)
	var ech cloudflare.ECHFetcher
	if !*noDoH {
		ech = newECHFetcher()
	}
	rep, err := cloudflare.NewProvider(newCFClient()).VerifyPosture(ctx, tok, rec, ech)
	if err != nil {
		fmt.Fprintf(stderr, "cdn-posture: %s\n", cdnSecretSafe(err, tok))
		return 1
	}
	if *hzTokenFile != "" && rec.FirewallID != "" {
		hz, err := cdnReadSecret(*hzTokenFile, "--hetzner-token-file")
		if err != nil {
			fmt.Fprintf(stderr, "cdn-posture: %v\n", err)
			return 1
		}
		fw := newCDNFirewall(string(hz))
		st, err := fw.CloudflareRule(ctx, rec.FirewallID)
		if err != nil {
			rep.Notes += "; firewall: " + cdnSecretSafe(err, tok, hz)
		} else {
			rep.FirewallChecked = true
			rep.FirewallEdgeRangesFresh = fw.DoorPortOpenToCloudflareOnly(st)
			rep.OnlyCloudflare = rep.AOPEnabled && rep.FirewallEdgeRangesFresh
		}
		zeroBytes(hz)
	}
	if err := cdnWriteJSON(stdout, rep); err != nil {
		fmt.Fprintf(stderr, "cdn-posture: %v\n", err)
		return 1
	}
	return 0
}

// cdnRemoveResult is cdn-remove's stdout.
type cdnRemoveResult struct {
	cloudflare.RemoveReport
	// Tell is what the card must say after removal: the token and the
	// domain are the publisher's to end, Daal cannot.
	Tell []string `json:"tell"`
}

func runCDNRemove(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cdn-remove", flag.ContinueOnError)
	fs.SetOutput(stderr)
	recordFile := fs.String("record-file", "", "front record JSON (cdn-provision output)")
	tokenFile := fs.String("token-file", "", "Cloudflare API token file")
	hzTokenFile := fs.String("hetzner-token-file", "", "Hetzner API token file (closes the relay firewall rule)")
	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if err := requireAll(stderr, map[string]string{"--record-file": *recordFile, "--token-file": *tokenFile}); err != nil {
		return 2
	}
	rec, err := cdnReadRecord(*recordFile)
	if err != nil {
		fmt.Fprintf(stderr, "cdn-remove: %v\n", err)
		return 1
	}
	tok, err := cdnReadSecret(*tokenFile, "--token-file")
	if err != nil {
		fmt.Fprintf(stderr, "cdn-remove: %v\n", err)
		return 1
	}
	defer zeroBytes(tok)
	rep, err := cloudflare.NewProvider(newCFClient()).Remove(ctx, tok, rec)
	if err != nil {
		fmt.Fprintf(stderr, "cdn-remove: %s\n", cdnSecretSafe(err, tok))
		return 1
	}
	fwStep := cloudflare.RemoveStep{Name: "firewall_rule", State: "skipped", Detail: "no --hetzner-token-file"}
	if *hzTokenFile != "" && rec.FirewallID != "" {
		hz, err := cdnReadSecret(*hzTokenFile, "--hetzner-token-file")
		if err != nil {
			fmt.Fprintf(stderr, "cdn-remove: %v\n", err)
			return 1
		}
		if err := newCDNFirewall(string(hz)).RemoveCloudflareRule(ctx, rec.FirewallID); err != nil {
			fwStep = cloudflare.RemoveStep{Name: "firewall_rule", State: "failed", Detail: cdnSecretSafe(err, tok, hz)}
			rep.Complete = false
		} else {
			fwStep = cloudflare.RemoveStep{Name: "firewall_rule", State: "done"}
		}
		zeroBytes(hz)
	}
	rep.Steps = append(rep.Steps, fwStep,
		// The door on the relay is closed through daal-relay-mgmt
		// (POST /cdn {"action":"disable"}), which this verb cannot
		// reach: the publisher's mgmt client has no /cdn call yet.
		cloudflare.RemoveStep{Name: "relay_door", State: "skipped", Detail: "close ws-cdn-in through daal-relay-mgmt /cdn (action disable)"})
	out := cdnRemoveResult{RemoveReport: rep, Tell: []string{
		"delete the API token in Cloudflare (My Profile → API Tokens)",
		"the domain keeps billing until it is cancelled at the registrar",
	}}
	if err := cdnWriteJSON(stdout, out); err != nil {
		fmt.Fprintf(stderr, "cdn-remove: %v\n", err)
		return 1
	}
	if !rep.Complete {
		return exitCDNRefused
	}
	return 0
}

// provisionCDN is cdn-provision's body (cli.go keeps only flag parsing):
// the Cloudflare side through cloudflare.ProvisionFront, then the relay
// firewall rule from freshly fetched Cloudflare ranges. A firewall
// failure takes the Cloudflare side down again, so a failed run leaves
// nothing behind.
func provisionCDN(ctx context.Context, opts cloudflare.CloudflareOpts, hzToken []byte, firewallID string, progress bool, stdout, stderr io.Writer) int {
	tok := opts.CFTokenSecret
	cf := newCFClient()
	p := cloudflare.NewProvider(cf)
	emitProgress(progress, stderr, "cloudflare", "certificate, origin pull, zone settings, DNS record, origin rule", map[string]any{"state": "running"})
	rec, err := p.ProvisionFront(ctx, opts)
	if err != nil {
		emitProgress(progress, stderr, "cloudflare", cdnSecretSafe(err, tok, hzToken), map[string]any{"state": "failed"})
		fmt.Fprintf(stderr, "cdn-provision: %s\n", cdnSecretSafe(err, tok, hzToken))
		return 1
	}
	emitProgress(progress, stderr, "cloudflare", "done", map[string]any{"state": "ok"})

	emitProgress(progress, stderr, "firewall", "relay firewall: the CDN door to Cloudflare's ranges only", map[string]any{"state": "running"})
	fw := newCDNFirewall(string(hzToken))
	fwID, ranges, err := cloudflare.RefreshFirewall(ctx, newEdgeFetcher(), fw, firewallID, time.Now)
	if err != nil {
		msg := cdnSecretSafe(err, tok, hzToken)
		emitProgress(progress, stderr, "firewall", msg, map[string]any{"state": "failed"})
		rep, rerr := p.Remove(ctx, tok, rec)
		left := []string{}
		for _, s := range rep.Steps {
			if s.State == "failed" {
				left = append(left, s.Name+": "+s.Detail)
			}
		}
		if rerr != nil {
			left = append(left, cdnSecretSafe(rerr, tok, hzToken))
		}
		if len(left) == 0 {
			fmt.Fprintf(stderr, "cdn-provision firewall: %s (the Cloudflare side was removed again)\n", msg)
		} else {
			fmt.Fprintf(stderr, "cdn-provision firewall: %s; could not remove: %s\n", msg, strings.Join(left, "; "))
		}
		return 1
	}
	p.SetFirewallID(rec, fwID)
	rec.LastEdgeRefreshUnix = ranges.FetchedAt.Unix()
	emitProgress(progress, stderr, "firewall", "done", map[string]any{"state": "ok"})
	if err := cdnWriteJSON(stdout, rec); err != nil {
		fmt.Fprintf(stderr, "marshal front record: %v\n", err)
		return 1
	}
	return 0
}
