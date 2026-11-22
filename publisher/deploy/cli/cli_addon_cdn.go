package cli

// Add-on 2, way in through Cloudflare (docs/optional-addons-plan.md §2,
// items B-2, B-3, B-5; specs/optional-addons-v1.md §4 and §6.3).
//
//	cdn-token-check --token-file F [--zone Z]
//	        verify the token and list the zones it sees; refuse one that
//	        does not work, sees no zone or lacks one of the five zone
//	        permissions (missing names which). One that can do more
//	        works (verdict ok_broad, extra names what). One that sees
//	        several zones with no --zone answers pick_zone: run again
//	        with the zone picked, which is then the one checked and used
//	cdn-test        --record-file R [--edge ip:port] [--require-ech=false]
//	                [--refresh-ech] [--timeout 15s]
//	        one real TLS + WebSocket handshake through the front, with ECH
//	cdn-posture     --record-file R --token-file F [--hetzner-token-file H]
//	                [--no-doh]
//	        read-only: SSL strict, WebSockets, origin rule, origin pull,
//	        proxied-only DNS, ECH (zone setting and the published config),
//	        and with H the relay firewall rule
//	cdn-door        --record-file R --operator-record O --token-file H
//	                --action enable|disable --priv-key -|P --helper-ip IP
//	        the relay's door through its management (daal-relay-mgmt
//	        POST /cdn, mgmt.CDNDoorEnable / CDNDoorDisable): enable sends
//	        the origin certificate, its key, the origin-pull CA and
//	        Cloudflare's ranges (the relay opens its box firewall to them);
//	        disable closes the inbound and those rules
//	cdn-remove      --record-file R --token-file F [--hetzner-token-file H]
//	                [--operator-record O --priv-key -|P --helper-ip IP]
//	        with O, P and IP (and H for the management window) close the
//	        relay's door first; then delete the DNS records and the origin
//	        rule, revoke the origin certificate, delete the origin-pull
//	        certificate, put back the zone settings Daal changed, and with
//	        H close the firewall rule
//
// cdn-provision (cli.go) builds the Cloudflare side and the provider
// firewall rule; see runCDNProvision. The door is cdn-door's: the app
// runs cdn-provision, cdn-door --action enable, cdn-test, then signs.
//
// Tokens are read from files (the wizard writes them 0600 and deletes
// them), zeroed after use, and never printed: not on stdout, not on
// stderr, not inside an error. Exit codes: 0 done (for cdn-token-check:
// the token is usable, ok or ok_broad); 1 an error (nothing was
// decided); 2 usage; 4 a refusal or a failed check (for cdn-token-check
// also pick_zone: not usable until a zone is picked), with the JSON
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

	"daal/bundle-go/bundle"
	"daal/publisher/deploy/cloudflare"
	"daal/publisher/deploy/mgmt"
	"daal/publisher/deploy/provider"
	"daal/publisher/deploy/providers/hetzner"
	"daal/publisher/deploy/relaypack"
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
	// The relay's door, each inside an ephemeral management window.
	cdnDoorEnable  = mgmt.CDNDoorEnableWithFW
	cdnDoorDisable = mgmt.CDNDoorDisableWithFW
)

// cdnFirewall is the relay-firewall half of the add-on (B-2). The id
// may be the firewall's name (daal-relay-<server id>): the applier
// resolves it.
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
	if !res.Usable() {
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

func runCDNRemove(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cdn-remove", flag.ContinueOnError)
	fs.SetOutput(stderr)
	recordFile := fs.String("record-file", "", "front record JSON (cdn-provision output)")
	tokenFile := fs.String("token-file", "", "Cloudflare API token file")
	hzTokenFile := fs.String("hetzner-token-file", "", "Hetzner API token file (closes the relay firewall rule)")
	opRecord := fs.String("operator-record", "", "the relay's OperatorRecord JSON (with --priv-key and --helper-ip: close the relay's door first)")
	privKeyFlag := fs.String("priv-key", "", "publisher Ed25519 private key (path | '-' for stdin), for the relay's door")
	helperIP := fs.String("helper-ip", "", "this device's outbound public IP (management window), for the relay's door")
	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if err := requireAll(stderr, map[string]string{"--record-file": *recordFile, "--token-file": *tokenFile}); err != nil {
		return 2
	}
	door := *opRecord != "" || *privKeyFlag != "" || *helperIP != ""
	if door {
		if err := requireAll(stderr, map[string]string{"--operator-record": *opRecord, "--priv-key": *privKeyFlag,
			"--helper-ip": *helperIP, "--hetzner-token-file": *hzTokenFile}); err != nil {
			return 2
		}
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
	// The door first: a name Cloudflare still routes to a closed door
	// answers nothing, never a stranger.
	doorStep := cloudflare.RemoveStep{Name: "relay_door", State: "skipped", Detail: "no --operator-record: close it with cdn-door --action disable"}
	if door {
		doorStep = cdnCloseDoor(ctx, *opRecord, *privKeyFlag, *helperIP, *hzTokenFile, stdin, tok)
	}
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
	if doorStep.State == "failed" {
		rep.Complete = false
	}
	rep.Steps = append(rep.Steps, fwStep, doorStep)
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
// nothing behind. firewallID may be the firewall's name
// (daal-relay-<server id>); the record carries the numeric id after.
// The relay's door is not opened here (cdn-door does that, with the
// publisher's key).
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
	// The same list goes to the relay with the door (cdn-door), which
	// opens its box firewall to it, and its v4 half gives the signed
	// edge seeds.
	rec.EdgeRanges = append(append([]string{}, ranges.V4...), ranges.V6...)
	emitProgress(progress, stderr, "firewall", "done", map[string]any{"state": "ok"})
	if err := cdnWriteJSON(stdout, rec); err != nil {
		fmt.Fprintf(stderr, "marshal front record: %v\n", err)
		return 1
	}
	return 0
}

// cdnBoxEnv is what a door call needs: the relay's record and provider
// (for the management window) and the publisher's key.
type cdnBoxEnv struct {
	rec  *provider.OperatorRecord
	prov provider.Provider
	priv []byte
}

func (e *cdnBoxEnv) wipe() {
	if e != nil {
		zeroBytes(e.priv)
	}
}

func cdnReadBox(opRecord, privKeyFlag, hzTokenFile string, stdin io.Reader) (*cdnBoxEnv, error) {
	rec, err := readRecord(opRecord)
	if err != nil {
		return nil, fmt.Errorf("read --operator-record: %w", err)
	}
	if rec.MgmtPort == 0 || rec.MgmtTLSFingerprint == "" {
		return nil, errors.New("--operator-record has no management endpoint (mgmt_port, mgmt_tls_fingerprint)")
	}
	priv, err := readPrivKey(privKeyFlag, stdin)
	if err != nil {
		return nil, fmt.Errorf("read --priv-key: %w", err)
	}
	p, err := buildProviderFn(rec.Provider, hzTokenFile, false)
	if err != nil {
		zeroBytes(priv)
		return nil, fmt.Errorf("build provider: %w", err)
	}
	return &cdnBoxEnv{rec: rec, prov: p, priv: priv}, nil
}

// cdnCloseDoor is cdn-remove's relay_door step.
func cdnCloseDoor(ctx context.Context, opRecord, privKeyFlag, helperIP, hzTokenFile string, stdin io.Reader, secrets ...[]byte) cloudflare.RemoveStep {
	env, err := cdnReadBox(opRecord, privKeyFlag, hzTokenFile, stdin)
	if err != nil {
		return cloudflare.RemoveStep{Name: "relay_door", State: "failed", Detail: cdnSecretSafe(err, secrets...)}
	}
	defer env.wipe()
	got, err := cdnDoorDisable(ctx, env.prov, env.rec, env.priv, helperIP)
	switch {
	case errors.Is(err, mgmt.ErrCDNDoorUnsupported):
		// The relay's management has no door: there is none to close.
		return cloudflare.RemoveStep{Name: "relay_door", State: "done", Detail: "this relay has no door to close"}
	case err != nil:
		return cloudflare.RemoveStep{Name: "relay_door", State: "failed", Detail: cdnSecretSafe(err, secrets...)}
	case got.BoxFirewallRules > 0:
		return cloudflare.RemoveStep{Name: "relay_door", State: "done",
			Detail: fmt.Sprintf("door closed; %d box-firewall rule(s) would not go (nothing listens behind them)", got.BoxFirewallRules)}
	}
	return cloudflare.RemoveStep{Name: "relay_door", State: "done"}
}

// cdnDoorResult is cdn-door's stdout. It never carries key material.
type cdnDoorResult struct {
	Action           string `json:"action"`
	Enabled          bool   `json:"enabled"`
	Changed          bool   `json:"changed"`
	Port             int    `json:"port,omitempty"`
	WSPath           string `json:"ws_path,omitempty"`
	Users            int    `json:"users"`
	BoxFirewallRules int    `json:"box_firewall_rules"`
}

// runCDNDoor opens or closes the relay's ws-cdn-in door through its
// management. Exit 3: the relay's management has no door (built before
// the add-on: it needs a rebuild); 1: any other failure.
func runCDNDoor(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cdn-door", flag.ContinueOnError)
	fs.SetOutput(stderr)
	recordFile := fs.String("record-file", "", "front record JSON (cdn-provision output)")
	opRecord := fs.String("operator-record", "", "the relay's OperatorRecord JSON")
	hzTokenFile := fs.String("token-file", "", "Hetzner API token file (the management window)")
	action := fs.String("action", "", "enable | disable")
	privKeyFlag := fs.String("priv-key", "", "publisher Ed25519 private key (path | '-' for stdin)")
	helperIP := fs.String("helper-ip", "", "this device's outbound public IP (management window)")
	_ = fs.Bool("progress-json", false, "accepted for symmetry with the other verbs")
	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if err := requireAll(stderr, map[string]string{"--record-file": *recordFile, "--operator-record": *opRecord,
		"--token-file": *hzTokenFile, "--action": *action, "--priv-key": *privKeyFlag, "--helper-ip": *helperIP}); err != nil {
		return 2
	}
	if *action != "enable" && *action != "disable" {
		fmt.Fprintln(stderr, "cdn-door: --action must be enable or disable")
		return 2
	}
	front, err := cdnReadRecord(*recordFile)
	if err != nil {
		fmt.Fprintf(stderr, "cdn-door: %v\n", err)
		return 1
	}
	env, err := cdnReadBox(*opRecord, *privKeyFlag, *hzTokenFile, stdin)
	if err != nil {
		fmt.Fprintf(stderr, "cdn-door: %v\n", err)
		return 1
	}
	defer env.wipe()
	var got *mgmt.CDNDoorResp
	if *action == "enable" {
		got, err = cdnDoorEnable(ctx, env.prov, env.rec, env.priv, *helperIP, front)
	} else {
		got, err = cdnDoorDisable(ctx, env.prov, env.rec, env.priv, *helperIP)
	}
	if errors.Is(err, mgmt.ErrCDNDoorUnsupported) {
		fmt.Fprintf(stderr, "cdn-door: %v\n", err)
		return 3
	}
	if err != nil {
		fmt.Fprintf(stderr, "cdn-door: %v\n", err)
		return 1
	}
	out := cdnDoorResult{Action: *action, Enabled: got.Enabled, Changed: got.Changed, Port: got.Port,
		WSPath: got.WSPath, Users: got.Users, BoxFirewallRules: got.BoxFirewallRules}
	if err := cdnWriteJSON(stdout, out); err != nil {
		fmt.Fprintf(stderr, "cdn-door: %v\n", err)
		return 1
	}
	return 0
}

// cdnFrontFromRecordFile reads the operator record's `cdn_front` member
// (the front record plus the signed plain_fallback flag), which the app
// writes while the way in through Cloudflare is live, as the binder's
// CDN input: seeds from the ranges cdn-provision read. Roots are the
// caller's. nil: the record has no such member.
func cdnFrontFromRecordFile(path string) (*relaypack.CDNFront, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var outer struct {
		CDNFront json.RawMessage `json:"cdn_front"`
	}
	if err := json.Unmarshal(b, &outer); err != nil {
		return nil, err
	}
	raw := strings.TrimSpace(string(outer.CDNFront))
	if raw == "" || raw == "null" {
		return nil, nil
	}
	var front cloudflare.FrontRecord
	if err := json.Unmarshal(outer.CDNFront, &front); err != nil {
		return nil, fmt.Errorf("cdn_front is not a front record: %w", err)
	}
	if front.Hostname == "" || front.ZoneID == "" {
		return nil, errors.New("cdn_front has no hostname or zone")
	}
	var flags struct {
		PlainFallback bool `json:"plain_fallback"`
	}
	_ = json.Unmarshal(outer.CDNFront, &flags)
	return &relaypack.CDNFront{
		Front:         &front,
		EdgeSeeds:     cloudflare.EdgeSeedsFromRanges(front.EdgeRanges, bundle.MaxEdgeSeeds),
		PlainFallback: flags.PlainFallback,
	}, nil
}
