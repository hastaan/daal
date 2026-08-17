// Package cli is the FRP-4a deploy-side CLI dispatcher. It reads
// argv, dispatches to the appropriate provider method, and prints
// human + JSON output. FRP-5 uses this layer for read-only pricing;
// FRP-4b wires the live deploy path. The same surface lets Helper
// operators drive deployment from the command line during development
// and field operation.
//
// Subcommands:
//
//	provision      create a new VPS, return OperatorRecord JSON.
//	reprovision    delete-and-recreate an existing record's box.
//	decommission   destroy the VPS + the firewall and one-shot SSH key
//	               provisioning created, and print a per-resource JSON
//	               report.
//	pricing        fetch live per-hour cost for a record's server type.
//	assign-fip     attach a floating IP to a record's server.
//	floating-ip    assign or unassign a floating IP.
//	verify         validate OperatorRecord JSON.
//	bind-and-sign  bind an OperatorRecord into a signed RelayPack .sbp (FRP-4b).
//	qr-fountain    stream LT-fountain frames for a .sbp as JSON lines (FRP-4b).
//	version        print CLI version.
//
// Mutating cloud subcommands accept --record-file (OperatorRecord
// JSON) and --token-file (Hetzner API token). The provision
// subcommand accepts --pubkey-file / --pubkey (publisher Ed25519
// public key, raw 32-byte file), --region, --server-type,
// --toolbox-profile / --toolbox, --families, --helper-ip, --dry-run.
package cli

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"daal/bundle-go/fountain"
	"daal/bundle-go/phase"
	"daal/bundle-go/relaypackvalidate"
	"daal/publisher/deploy/cloudflare"
	"daal/publisher/deploy/freshness"
	"daal/publisher/deploy/provider"
	"daal/publisher/deploy/providers/hetzner"
	"daal/publisher/deploy/providers/stark"
	"daal/publisher/deploy/providers/vultr"
	"daal/publisher/deploy/relaypack"
	"daal/publisher/deploy/rotation"
)

// Run is the package entry point invoked by cmd/daal-deploy/main.
// Returns process exit code (0 on success, non-zero on error).
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		fmt.Fprintln(stderr, usage())
		return 2
	}
	sub := args[0]
	rest := args[1:]
	ctx := context.Background()

	switch sub {
	case "provision":
		return runProvision(ctx, rest, stdout, stderr)
	case "reprovision":
		return runReprovision(ctx, rest, stdout, stderr)
	case "decommission":
		return runDecommission(ctx, rest, stdout, stderr)
	case "pricing":
		return runPricing(ctx, rest, stdout, stderr)
	case "assign-fip":
		return runAssignFIP(ctx, rest, stdout, stderr)
	case "floating-ip":
		return runFloatingIP(ctx, rest, stdout, stderr)
	case "verify":
		return runVerify(rest, stdout, stderr)
	case "bind-and-sign":
		return runBindAndSign(rest, os.Stdin, stdout, stderr)
	case "qr-fountain":
		return runQRFountain(rest, stdout, stderr)
	case "rotate-recommend":
		return runRotateRecommend(rest, os.Stdin, stdout, stderr)
	case "cdn-provision":
		return runCDNProvision(ctx, rest, stdout, stderr)
	case "cdn-rotate-path":
		return runCDNRotatePath(ctx, rest, stdout, stderr)
	case "cdn-rotate-hostname":
		return runCDNRotateHostname(ctx, rest, stdout, stderr)
	case "cdn-rotate-origin":
		return runCDNRotateOrigin(ctx, rest, stdout, stderr)
	case "publish-freshness":
		return runPublishFreshness(ctx, rest, stdout, stderr)
	case "cell-create":
		return runCellCreate(ctx, rest, stdout, stderr)
	case "cell-invite":
		return runCellInvite(ctx, rest, stdout, stderr)
	case "cell-sign":
		return runCellSign(ctx, rest, stdout, stderr)
	case "cell-verify":
		return runCellVerify(ctx, rest, stdout, stderr)
	case "cell-status":
		return runCellStatus(ctx, rest, stdout, stderr)
	case "list-server-types":
		return runListServerTypes(ctx, rest, stdout, stderr)
	case "list-servers":
		return runListServers(ctx, rest, stdout, stderr)
	case "users-provision":
		return runUsersProvision(ctx, rest, os.Stdin, stdout, stderr)
	case "users-revoke":
		return runUsersRevoke(ctx, rest, os.Stdin, stdout, stderr)
	case "users-list":
		return runUsersList(ctx, rest, os.Stdin, stdout, stderr)
	case "users-pack-sbp":
		return runUsersPackSbp(ctx, rest, os.Stdin, stdout, stderr)
	case "users-pack-sbpx":
		return runUsersPackSbpx(ctx, rest, os.Stdin, stdout, stderr)
	case "users-unpack-sbpx":
		return runUsersUnpackSbpx(ctx, rest, os.Stdin, stdout, stderr)
	case "version":
		fmt.Fprintln(stdout, Version)
		return 0
	case "-h", "--help", "help":
		fmt.Fprintln(stdout, usage())
		return 0
	default:
		fmt.Fprintf(stderr, "unknown subcommand %q\n%s\n", sub, usage())
		return 2
	}
}

func usage() string {
	return strings.TrimSpace(`
daal-deploy — Helper-side VPS deployment driver (FRP-4a)

Usage:
  daal-deploy <subcommand> [flags]

Subcommands:
  provision     Create a new VPS and emit OperatorRecord JSON to stdout.
  reprovision   Delete the VPS and re-Provision (full rotation).
  decommission  Destroy the cloud resources behind an OperatorRecord: the VPS,
                its per-server firewall, and the one-shot provisioning SSH key.
                Emits a per-resource JSON report on stdout (server_deleted /
                ssh_key_deleted / firewall_deleted / preserved / warnings).
                Exit 1 means the billing server survived — keep the record.
  pricing       Print live per-hour cost for a record's server type.
  assign-fip    Attach a floating IP to a record's server.
  floating-ip   Assign or unassign a floating IP.
  verify        Validate OperatorRecord JSON.
  bind-and-sign Bind OperatorRecord -> signed RelayPack .sbp (FRP-4b).
  qr-fountain   Stream LT-fountain frames for a .sbp (FRP-4b).
  rotate-recommend
                Read an Explanation JSON on stdin (or a context flag set)
                and emit a RotationRecommendation JSON on stdout (FRP-7).
  cdn-provision Provision Cloudflare fronting + firewall and emit FrontRecord JSON (FRP-8).
  cdn-rotate-path
                Rotate the visible /r/<hex> path on a CDN-fronted candidate
                (re-uploads worker, rebinds route). Emits CdnRotateResult JSON.
                Caller MUST re-sign RelayPack + re-publish freshness afterwards (FRP-9).
  cdn-rotate-hostname
                Migrate proxied DNS to a new hostname, rebind worker on the new
                zone. Emits CdnRotateResult JSON. Caller MUST re-sign RelayPack +
                re-publish freshness afterwards (FRP-9).
  cdn-rotate-origin
                Re-point proxied A / AAAA at a new origin IP. Hostname + public
                path unchanged. Emits CdnRotateResult JSON. Caller MUST NOT
                re-sign RelayPack — origin-only is invisible to the family (FRP-9).
  publish-freshness
                Build + sign a freshness JSON document for the current SBP and
                emit it to stdout (or --out-file). Wizard calls this on L7/L8
                public-surface rotations after the RelayPack is re-signed.
                MUST NOT be called on L9 origin-only rotations (FRP-9).
  cell-create   Generate a fresh per-admin Ed25519 keypair (FRP-11). Emits
                JSON with both halves; operator persists to encrypted keystore.
  cell-invite   Wrap an admin-quorum-signed membership doc into a .cell-join
                envelope an operator can share with a prospective member.
  cell-sign     Produce one CellAdminSignature over a membership or delegation
                doc's canonical bytes. Reads admin private key from --priv-file,
                never argv. Used to collect M-of-N signatures.
  cell-verify   Run M-of-N admin-quorum + cell_id-match checks on a membership
                + delegation doc pair (operator sanity check before publishing).
  cell-status   Print summary of a cell's admin set, quorum, and membership.
  version       Print CLI version.

Run 'daal-deploy <subcommand> --help' for subcommand flags.
`)
}

func parseFlags(fs *flag.FlagSet, args []string) int {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	return -1
}

const Version = "daal-deploy 0.2.0+frp-4b"

//	runProvision: daal-deploy provision --pubkey-file ... --region ... \
//	  --server-type ... --toolbox-profile ... --helper-ip ... [--dry-run]
//	  [--token-file ... ] -o record.json
func runProvision(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("provision", flag.ContinueOnError)
	fs.SetOutput(stderr)
	pubkeyFile := fs.String("pubkey-file", "", "path to publisher Ed25519 public key (32 raw bytes)")
	pubkeyAlias := fs.String("pubkey", "", "alias for --pubkey-file")
	providerName := fs.String("provider", "hetzner", "cloud provider (hetzner | vultr | stark)")
	region := fs.String("region", "", "cloud region (e.g. fsn1)")
	serverType := fs.String("server-type", "cx22", "server type (e.g. cx22)")
	toolboxProfile := fs.String("toolbox-profile", "iran-default", "toolbox profile (V1.5: iran-default)")
	toolboxAlias := fs.String("toolbox", "", "alias for --toolbox-profile")
	families := fs.String("families", "", "comma-separated enabled transport families; empty uses profile defaults")
	helperIP := fs.String("helper-ip", "", "Helper machine's public IPv4 (for ufw allowlist)")
	mgmtPort := fs.Int("mgmt-port", 0, "V2 mgmt-plane port in [10000,65000]; 0 generates a random per-deploy port")
	dryRun := fs.Bool("dry-run", false, "skip cloud calls; emit synthetic OperatorRecord")
	tokenFile := fs.String("token-file", "", "Hetzner API token file (omit for --dry-run)")
	existingServerID := fs.String("existing-server-id", "", "rebuild this existing server instead of creating new")
	rollbackOnFailure := fs.Bool("rollback-on-failure", false, "destroy the server if provisioning fails after it was created (default: keep it and name it in the error, so a slow boot stays recoverable)")
	outFile := fs.String("o", "", "write OperatorRecord JSON here (default: stdout)")
	progressJSON := fs.Bool("progress-json", false, "emit one JSON line per provisioning step on stderr (FRP-4b)")

	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if *pubkeyFile == "" && *pubkeyAlias != "" {
		*pubkeyFile = *pubkeyAlias
	}
	if *toolboxAlias != "" {
		*toolboxProfile = *toolboxAlias
	}
	if err := requireAll(stderr, map[string]string{
		"--pubkey-file":     *pubkeyFile,
		"--region":          *region,
		"--toolbox-profile": *toolboxProfile,
		"--helper-ip":       *helperIP,
	}); err != nil {
		return 2
	}

	pub, err := os.ReadFile(*pubkeyFile)
	if err != nil {
		fmt.Fprintf(stderr, "read pubkey-file: %v\n", err)
		return 1
	}
	if len(pub) != ed25519.PublicKeySize {
		fmt.Fprintf(stderr, "pubkey-file: want %d bytes, got %d\n", ed25519.PublicKeySize, len(pub))
		return 1
	}

	hip := net.ParseIP(*helperIP)
	if hip == nil {
		fmt.Fprintf(stderr, "invalid --helper-ip: %s\n", *helperIP)
		return 1
	}

	var ephem ed25519.PrivateKey
	if !*dryRun {
		_, ephem, err = ed25519.GenerateKey(nil)
		if err != nil {
			fmt.Fprintf(stderr, "generate ephemeral ssh key: %v\n", err)
			return 1
		}
	}

	p, err := buildProvider(*providerName, *tokenFile, *dryRun)
	if err != nil {
		fmt.Fprintf(stderr, "build provider: %v\n", err)
		return 1
	}

	emitProgress(*progressJSON, stderr, "provision_start", "starting provisioning", nil)
	emitProgress(*progressJSON, stderr, "provision_cloud_call", "calling cloud provider", map[string]any{"provider": *providerName, "region": *region})

	rec, err := p.Provision(ctx, provider.ProvisionOpts{
		PublisherPubKey:   pub,
		Region:            *region,
		ServerType:        *serverType,
		ToolboxProfile:    *toolboxProfile,
		EnabledFamilies:   splitCSV(*families),
		HelperIP:          hip,
		MgmtPort:          *mgmtPort,
		WaitForHealth:     !*dryRun,
		EphemeralSSHKey:   ephem,
		DryRun:            *dryRun,
		ExistingServerID:  *existingServerID,
		RollbackOnFailure: *rollbackOnFailure,
		OnProgress: func(step, msg string) {
			emitProgress(*progressJSON, stderr, step, msg, nil)
		},
	})
	if err != nil {
		emitProgress(*progressJSON, stderr, "provision_error", err.Error(), nil)
		fmt.Fprintf(stderr, "provision: %v\n", err)
		return 1
	}
	emitProgress(*progressJSON, stderr, "provision_done", "OperatorRecord ready", map[string]any{
		"server_id": rec.ServerID, "public_ip": rec.PublicIP.String(), "candidates": len(rec.Candidates),
	})
	return emitRecord(rec, *outFile, stdout, stderr)
}

// emitProgress writes one JSON-line step event to stderr when
// --progress-json is on. Schema (FRP-4b spec §6):
//
//	{"step":"<id>", "message":"<human>", "ts":"<rfc3339>", ...extra}
//
// The Tauri shim forwards these to the wizard via app.emit() events.
func emitProgress(on bool, stderr io.Writer, step, message string, extra map[string]any) {
	if !on {
		return
	}
	payload := map[string]any{
		"step":    step,
		"message": message,
		"ts":      time.Now().UTC().Format(time.RFC3339),
	}
	for k, v := range extra {
		payload[k] = v
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return // never break the run because progress encoding failed.
	}
	fmt.Fprintln(stderr, string(body))
}

func runReprovision(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("reprovision", flag.ContinueOnError)
	fs.SetOutput(stderr)
	recordFile := fs.String("record-file", "", "OperatorRecord JSON path")
	tokenFile := fs.String("token-file", "", "Hetzner API token file")
	// FRP-7: ReprovisionOpts flags so the wizard's rotate path can
	// drive L1 (regen-creds), L2 (sni/ws-path), L4/L5/L6 (new
	// toolbox profile) over the existing CLI surface.
	regenCreds := fs.Bool("regen-credentials", false, "FRP-7 L1: regenerate credentials")
	newSNI := fs.String("new-sni", "", "FRP-7 L2: new TLS SNI")
	newWSPath := fs.String("new-ws-path", "", "FRP-7 L2: new WebSocket path")
	newToolboxProfile := fs.String("new-toolbox-profile", "", "FRP-7 L4/L5/L6: new toolbox profile")
	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if err := requireAll(stderr, map[string]string{
		"--record-file": *recordFile,
		"--token-file":  *tokenFile,
	}); err != nil {
		return 2
	}
	rec, err := readRecord(*recordFile)
	if err != nil {
		fmt.Fprintf(stderr, "read record-file: %v\n", err)
		return 1
	}
	p, err := buildProvider(rec.Provider, *tokenFile, false)
	if err != nil {
		fmt.Fprintf(stderr, "build provider: %v\n", err)
		return 1
	}
	opts := provider.ReprovisionOpts{
		NewToolboxProfile: *newToolboxProfile,
		NewSNI:            *newSNI,
		NewWSPath:         *newWSPath,
		RegenCredentials:  *regenCreds,
	}
	if err := p.Reprovision(ctx, rec, opts); err != nil {
		fmt.Fprintf(stderr, "reprovision: %v\n", err)
		return 1
	}
	return emitRecord(rec, *recordFile, stdout, stderr)
}

// runDecommission tears down the cloud side of an OperatorRecord and
// prints a per-resource JSON report on stdout:
//
//	{
//	  "provider": "hetzner",
//	  "server_id": "12345",
//	  "server_deleted": true,
//	  "ssh_key_deleted": true,
//	  "firewall_deleted": true,
//	  "deleted_ssh_key_ids": ["678"],
//	  "firewall_id": "910",
//	  "preserved": ["floating-ip:42"],
//	  "warnings": ["floating IP 42 stays reserved on your account …"]
//	}
//
// Each boolean means "nothing of that kind from this deploy is left
// behind" — see provider.DecommissionReport for the full semantics.
// `warnings` is always present (possibly empty) and is meant to be
// shown to the user verbatim.
//
// The JSON is printed on BOTH exit paths so a partial teardown is
// still legible. Exit 0 means the billing server is gone (warnings
// may still describe preserved resources); exit 1 means it is not,
// and the caller must keep its local record — that record is the
// only remaining way to reach the surviving server.
//
// (Before this commit the command printed the bare line
// "decommissioned" and deleted only the server. Nothing consumed
// that line.)
//
// `--json` is accepted and ignored: the report is unconditional. The
// Rust bridge asks for it explicitly because the app and this binary
// are not the same vintage — on Android the deploy engine is a pinned
// `libdaal_deploy.so` that can lag the shell — so it sends `--json`,
// treats a flag-parse exit (2) as "old binary" and retries without it.
// Accepting the flag here is what keeps the first attempt the one that
// works; without it every teardown would run the verb twice and land
// in the legacy-compat branch. Do not remove it to "clean up an unused
// flag" — an older shell in the field still sends it.
func runDecommission(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("decommission", flag.ContinueOnError)
	fs.SetOutput(stderr)
	recordFile := fs.String("record-file", "", "OperatorRecord JSON path")
	tokenFile := fs.String("token-file", "", "Hetzner API token file")
	_ = fs.Bool("json", false, "emit the report as JSON (always on; accepted for compatibility)")
	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if err := requireAll(stderr, map[string]string{
		"--record-file": *recordFile,
		"--token-file":  *tokenFile,
	}); err != nil {
		return 2
	}
	rec, err := readRecord(*recordFile)
	if err != nil {
		fmt.Fprintf(stderr, "read record-file: %v\n", err)
		return 1
	}
	p, err := buildProviderFn(rec.Provider, *tokenFile, false)
	if err != nil {
		fmt.Fprintf(stderr, "build provider: %v\n", err)
		return 1
	}
	rep, decErr := p.Decommission(ctx, rec)
	if rep == nil {
		// Defensive: the interface promises a non-nil report, but a
		// silent teardown is the one outcome we refuse to produce.
		rep = provider.NewDecommissionReport(rec.Provider, rec.ServerID)
		if decErr != nil {
			rep.Warnf("%v", decErr)
		}
	}
	body, mErr := json.MarshalIndent(rep, "", "  ")
	if mErr != nil {
		fmt.Fprintf(stderr, "marshal decommission report: %v\n", mErr)
		return 1
	}
	fmt.Fprintln(stdout, string(body))
	if decErr != nil {
		fmt.Fprintf(stderr, "decommission: %v\n", decErr)
		return 1
	}
	for _, w := range rep.Warnings {
		fmt.Fprintf(stderr, "decommission warning: %s\n", w)
	}
	return 0
}

func runPricing(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("pricing", flag.ContinueOnError)
	fs.SetOutput(stderr)
	providerName := fs.String("provider", "hetzner", "cloud provider (hetzner | vultr | stark)")
	region := fs.String("region", "", "cloud region (e.g. fsn1)")
	serverType := fs.String("server-type", "", "server type (e.g. cx22)")
	recordFile := fs.String("record-file", "", "optional OperatorRecord JSON path")
	tokenFile := fs.String("token-file", "", "Hetzner API token file")
	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if err := requireAll(stderr, map[string]string{"--token-file": *tokenFile}); err != nil {
		return 2
	}
	rec := &provider.OperatorRecord{Provider: *providerName, Region: *region, ServerType: *serverType}
	if *recordFile != "" {
		var err error
		rec, err = readRecord(*recordFile)
		if err != nil {
			fmt.Fprintf(stderr, "read record-file: %v\n", err)
			return 1
		}
	}
	if rec.Region == "" || rec.ServerType == "" {
		if err := requireAll(stderr, map[string]string{"--region": rec.Region, "--server-type": rec.ServerType}); err != nil {
			return 2
		}
	}
	p, err := buildProvider(rec.Provider, *tokenFile, false)
	if err != nil {
		fmt.Fprintf(stderr, "build provider: %v\n", err)
		return 1
	}
	pr, err := p.Pricing(ctx, rec)
	if err != nil {
		fmt.Fprintf(stderr, "pricing: %v\n", err)
		return 1
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(pr); err != nil {
		fmt.Fprintf(stderr, "marshal: %v\n", err)
		return 1
	}
	return 0
}

func runAssignFIP(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("assign-fip", flag.ContinueOnError)
	fs.SetOutput(stderr)
	recordFile := fs.String("record-file", "", "OperatorRecord JSON path")
	tokenFile := fs.String("token-file", "", "Hetzner API token file")
	fipID := fs.String("fip-id", "", "Hetzner floating-IP ID")
	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if err := requireAll(stderr, map[string]string{
		"--record-file": *recordFile,
		"--token-file":  *tokenFile,
		"--fip-id":      *fipID,
	}); err != nil {
		return 2
	}
	rec, err := readRecord(*recordFile)
	if err != nil {
		fmt.Fprintf(stderr, "read record-file: %v\n", err)
		return 1
	}
	p, err := buildProvider(rec.Provider, *tokenFile, false)
	if err != nil {
		fmt.Fprintf(stderr, "build provider: %v\n", err)
		return 1
	}
	if err := p.AssignFloatingIP(ctx, rec, *fipID); err != nil {
		fmt.Fprintf(stderr, "assign-fip: %v\n", err)
		return 1
	}
	return emitRecord(rec, *recordFile, stdout, stderr)
}

func runFloatingIP(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		fmt.Fprintln(stderr, "missing floating-ip action: assign | unassign")
		return 2
	}
	action := args[0]
	switch action {
	case "assign":
		return runAssignFIP(ctx, args[1:], stdout, stderr)
	case "unassign":
		return runUnassignFIP(ctx, args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown floating-ip action %q (want assign or unassign)\n", action)
		return 2
	}
}

func runUnassignFIP(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("floating-ip unassign", flag.ContinueOnError)
	fs.SetOutput(stderr)
	recordFile := fs.String("record-file", "", "OperatorRecord JSON path")
	tokenFile := fs.String("token-file", "", "Hetzner API token file")
	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if err := requireAll(stderr, map[string]string{
		"--record-file": *recordFile,
		"--token-file":  *tokenFile,
	}); err != nil {
		return 2
	}
	rec, err := readRecord(*recordFile)
	if err != nil {
		fmt.Fprintf(stderr, "read record-file: %v\n", err)
		return 1
	}
	p, err := buildProvider(rec.Provider, *tokenFile, false)
	if err != nil {
		fmt.Fprintf(stderr, "build provider: %v\n", err)
		return 1
	}
	if err := p.UnassignFloatingIP(ctx, rec); err != nil {
		fmt.Fprintf(stderr, "floating-ip unassign: %v\n", err)
		return 1
	}
	return emitRecord(rec, *recordFile, stdout, stderr)
}

func runVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	recordFile := fs.String("record-file", "", "OperatorRecord JSON path")
	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if err := requireAll(stderr, map[string]string{"--record-file": *recordFile}); err != nil {
		return 2
	}
	rec, err := readRecord(*recordFile)
	if err != nil {
		fmt.Fprintf(stderr, "read record-file: %v\n", err)
		return 1
	}
	if err := validateRecord(rec); err != nil {
		fmt.Fprintf(stderr, "verify: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, `{"ok":true}`)
	return 0
}

// providerFace is the surface the CLI consumes from the
// provider package. Defined locally so test code can substitute a
// fake without pulling in hcloud-go.
type providerFace interface {
	provider.Provider
}

// ServerTypeInfo is a single entry in the list-server-types output.
type ServerTypeInfo struct {
	ID          string  `json:"id"`
	Description string  `json:"description"`
	CPUs        int     `json:"cpus"`
	MemoryGB    float64 `json:"memory_gb"`
	DiskGB      int     `json:"disk_gb"`
	MonthlyEUR  float64 `json:"monthly_eur"`
	HourlyEUR   float64 `json:"hourly_eur"`
	Location    string  `json:"location"`
	Arch        string  `json:"arch"`
}

func runListServerTypes(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("list-server-types", flag.ContinueOnError)
	fs.SetOutput(stderr)
	providerName := fs.String("provider", "hetzner", "cloud provider (hetzner)")
	tokenFile := fs.String("token-file", "", "API token file")
	region := fs.String("region", "fsn1", "region for pricing lookup")
	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if err := requireAll(stderr, map[string]string{"--token-file": *tokenFile}); err != nil {
		return 2
	}
	tokenBytes, err := os.ReadFile(*tokenFile)
	if err != nil {
		fmt.Fprintf(stderr, "read token-file: %v\n", err)
		return 1
	}
	token := strings.TrimSpace(string(tokenBytes))
	if token == "" {
		fmt.Fprintln(stderr, "token-file is empty")
		return 1
	}

	switch *providerName {
	case "hetzner":
		return listHetznerServerTypes(ctx, token, *region, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "list-server-types not yet supported for %q\n", *providerName)
		return 1
	}
}

func listHetznerServerTypes(ctx context.Context, token, region string, stdout, stderr io.Writer) int {
	client := hetzner.NewLiveClientForListing(token)
	types, err := client.ListServerTypes(ctx, region)
	if err != nil {
		fmt.Fprintf(stderr, "list server types: %v\n", err)
		return 1
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(types); err != nil {
		fmt.Fprintf(stderr, "marshal: %v\n", err)
		return 1
	}
	return 0
}

func runListServers(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("list-servers", flag.ContinueOnError)
	fs.SetOutput(stderr)
	providerName := fs.String("provider", "hetzner", "cloud provider (hetzner)")
	tokenFile := fs.String("token-file", "", "API token file")
	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if err := requireAll(stderr, map[string]string{"--token-file": *tokenFile}); err != nil {
		return 2
	}
	tokenBytes, err := os.ReadFile(*tokenFile)
	if err != nil {
		fmt.Fprintf(stderr, "read token-file: %v\n", err)
		return 1
	}
	token := strings.TrimSpace(string(tokenBytes))
	if token == "" {
		fmt.Fprintln(stderr, "token-file is empty")
		return 1
	}

	switch *providerName {
	case "hetzner":
		client := hetzner.NewLiveClientForListing(token)
		servers, err := client.ListServers(ctx)
		if err != nil {
			fmt.Fprintf(stderr, "list servers: %v\n", err)
			return 1
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(servers); err != nil {
			fmt.Fprintf(stderr, "marshal: %v\n", err)
			return 1
		}
		return 0
	default:
		fmt.Fprintf(stderr, "list-servers not yet supported for %q\n", *providerName)
		return 1
	}
}

// buildProviderFn is the seam runDecommission builds its adapter
// through, so cli_test.go can assert the decommission JSON contract
// against an in-memory provider instead of a live cloud token.
// Production always leaves it pointing at buildProvider.
var buildProviderFn = buildProvider

// buildProvider returns the selected FRP provider adapter. When
// dryRun is true and tokenFile is empty, each adapter is constructed
// with a client/token path that Provision's DryRun branch never
// reaches.
func buildProvider(providerName, tokenFile string, dryRun bool) (providerFace, error) {
	if dryRun && tokenFile == "" {
		switch providerName {
		case "hetzner":
			return hetzner.New(hetzner.NewDryRunClient()), nil
		case "vultr":
			return vultr.New(vultr.NewLiveClient("")), nil
		case "stark":
			return stark.New(stark.NewClient(), func() string { return "" }), nil
		default:
			return nil, fmt.Errorf("unsupported --provider %q", providerName)
		}
	}
	if tokenFile == "" {
		return nil, errors.New("--token-file required (omit only with --dry-run)")
	}
	tokenBytes, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, fmt.Errorf("read token-file: %w", err)
	}
	token := strings.TrimSpace(string(tokenBytes))
	if token == "" {
		return nil, errors.New("token-file is empty")
	}
	switch providerName {
	case "hetzner":
		return hetzner.New(hetzner.NewLiveClient(token)), nil
	case "vultr":
		return vultr.New(vultr.NewLiveClient(token)), nil
	case "stark":
		return stark.New(stark.NewClient(), func() string { return token }), nil
	default:
		return nil, fmt.Errorf("unsupported --provider %q", providerName)
	}
}

// runCDNProvision provisions the Cloudflare side of a cdn_fronted
// candidate and emits publisher/deploy/cloudflare.FrontRecord JSON.
func runCDNProvision(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cdn-provision", flag.ContinueOnError)
	fs.SetOutput(stderr)
	hostname := fs.String("hostname", "", "public CDN hostname, e.g. relay.example.com")
	originIP := fs.String("origin-ip", "", "origin VPS IPv4")
	originIPv6 := fs.String("origin-ipv6", "", "origin VPS IPv6 (optional)")
	originPath := fs.String("origin-path", "", "stable origin path, e.g. /ws")
	publicPath := fs.String("public-path", "", "public random path; empty generates one")
	outDir := fs.String("out-dir", "", "directory for origin CA / AOP cert files")
	tokenFile := fs.String("cf-token-file", "", "Cloudflare API token file")
	cloudTokenFile := fs.String("token-file", "", "Hetzner API token file for Cloudflare-edge firewall")
	firewallID := fs.String("firewall-id", "", "existing Hetzner firewall ID to update (optional)")

	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if err := requireAll(stderr, map[string]string{
		"--hostname":      *hostname,
		"--origin-ip":     *originIP,
		"--origin-path":   *originPath,
		"--out-dir":       *outDir,
		"--cf-token-file": *tokenFile,
		"--token-file":    *cloudTokenFile,
	}); err != nil {
		return 2
	}
	tokenBytes, err := os.ReadFile(*tokenFile)
	if err != nil {
		fmt.Fprintf(stderr, "read cf-token-file: %v\n", err)
		return 1
	}
	token := []byte(strings.TrimSpace(string(tokenBytes)))
	if len(token) == 0 {
		fmt.Fprintln(stderr, "cf-token-file is empty")
		return 1
	}
	defer zeroBytes(token)

	p := cloudflare.NewProvider(cloudflare.NewLiveCFClient())
	rec, err := p.ProvisionFront(ctx, cloudflare.CloudflareOpts{
		Hostname:      *hostname,
		OriginIP:      *originIP,
		OriginIPv6:    *originIPv6,
		PublicPath:    *publicPath,
		OriginPath:    *originPath,
		CFTokenSecret: token,
		OutDir:        *outDir,
	})
	if err != nil {
		fmt.Fprintf(stderr, "cdn-provision: %v\n", err)
		return 1
	}
	cloudTokenBytes, err := os.ReadFile(*cloudTokenFile)
	if err != nil {
		fmt.Fprintf(stderr, "read token-file: %v\n", err)
		return 1
	}
	cloudToken := []byte(strings.TrimSpace(string(cloudTokenBytes)))
	if len(cloudToken) == 0 {
		fmt.Fprintln(stderr, "token-file is empty")
		return 1
	}
	defer zeroBytes(cloudToken)
	applier := hetzner.NewCloudflareFirewallApplier(hetzner.NewLiveClient(string(cloudToken)))
	fwID, _, err := cloudflare.RefreshFirewall(ctx, cloudflare.NewHTTPSEdgeRangeFetcher(), applier, *firewallID, time.Now)
	if err != nil {
		fmt.Fprintf(stderr, "cdn-provision firewall: %v\n", err)
		return 1
	}
	p.SetFirewallID(rec, fwID)
	body, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "marshal front record: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, string(body))
	return 0
}

// cdnRotateResult mirrors the wizard cli_bridge.CdnRotateResult
// JSON shape so wizard ↔ CLI stays a single contract surface.
// Fields not relevant to a particular rotation kind are emitted
// as their JSON-zero value.
type cdnRotateResult struct {
	Hostname      string `json:"hostname"`
	ZoneID        string `json:"zone_id"`
	PublicPath    string `json:"public_path"`
	WorkerRouteID string `json:"worker_route_id"`
	OriginIPv4    string `json:"origin_ipv4"`
	OriginIPv6    string `json:"origin_ipv6"`
}

// runCDNRotatePath drives the supplement §14.4 public-path
// rotation. The visible /r/<hex> path changes; hostname and
// origin path are unchanged. The caller (wizard) is responsible
// for re-signing the RelayPack + re-publishing the freshness JSON
// document afterwards because a public_risk_tag value (the path)
// changed. The CLI itself does NOT re-sign or re-publish — those
// are wizard-orchestrated steps.
func runCDNRotatePath(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cdn-rotate-path", flag.ContinueOnError)
	fs.SetOutput(stderr)
	hostname := fs.String("hostname", "", "current public CDN hostname")
	zoneID := fs.String("zone-id", "", "Cloudflare zone ID for hostname")
	accountID := fs.String("account-id", "", "Cloudflare account ID hosting the worker script")
	oldRouteID := fs.String("old-route-id", "", "current worker route ID; will be replaced")
	originPath := fs.String("origin-path", "", "stable origin path (unchanged)")
	newPublicPath := fs.String("new-public-path", "", "new public random path; empty generates one")
	tokenFile := fs.String("cf-token-file", "", "Cloudflare API token file")

	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if err := requireAll(stderr, map[string]string{
		"--hostname":      *hostname,
		"--zone-id":       *zoneID,
		"--account-id":    *accountID,
		"--origin-path":   *originPath,
		"--cf-token-file": *tokenFile,
	}); err != nil {
		return 2
	}
	tokenBytes, err := os.ReadFile(*tokenFile)
	if err != nil {
		fmt.Fprintf(stderr, "read cf-token-file: %v\n", err)
		return 1
	}
	token := []byte(strings.TrimSpace(string(tokenBytes)))
	if len(token) == 0 {
		fmt.Fprintln(stderr, "cf-token-file is empty")
		return 1
	}
	defer zeroBytes(token)

	p := cloudflare.NewProvider(cloudflare.NewLiveCFClient())
	rec := &cloudflare.FrontRecord{
		Hostname:      *hostname,
		ZoneID:        *zoneID,
		OriginPath:    *originPath,
		WorkerRouteID: *oldRouteID,
	}
	newPath, newRouteID, err := p.RotatePublicPath(ctx, token, *accountID, rec, *newPublicPath)
	if err != nil {
		fmt.Fprintf(stderr, "cdn-rotate-path: %v\n", err)
		return 1
	}
	body, err := json.MarshalIndent(cdnRotateResult{
		Hostname:      rec.Hostname,
		ZoneID:        rec.ZoneID,
		PublicPath:    newPath,
		WorkerRouteID: newRouteID,
	}, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "marshal rotate result: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, string(body))
	return 0
}

// runCDNRotateHostname drives the supplement §14.4 hostname
// rotation. The hostname (and likely the zone) changes; public
// path and origin path are unchanged. Caller re-signs the
// RelayPack afterwards.
func runCDNRotateHostname(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cdn-rotate-hostname", flag.ContinueOnError)
	fs.SetOutput(stderr)
	oldHostname := fs.String("old-hostname", "", "current public CDN hostname")
	oldZoneID := fs.String("old-zone-id", "", "current Cloudflare zone ID")
	publicPath := fs.String("public-path", "", "current public random path (unchanged)")
	originPath := fs.String("origin-path", "", "stable origin path (unchanged)")
	newHostname := fs.String("new-hostname", "", "new public CDN hostname")
	originIPv4 := fs.String("origin-ipv4", "", "origin IPv4 to attach to new hostname")
	originIPv6 := fs.String("origin-ipv6", "", "origin IPv6 (optional)")
	tokenFile := fs.String("cf-token-file", "", "Cloudflare API token file")

	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if err := requireAll(stderr, map[string]string{
		"--old-hostname":  *oldHostname,
		"--old-zone-id":   *oldZoneID,
		"--public-path":   *publicPath,
		"--origin-path":   *originPath,
		"--new-hostname":  *newHostname,
		"--origin-ipv4":   *originIPv4,
		"--cf-token-file": *tokenFile,
	}); err != nil {
		return 2
	}
	tokenBytes, err := os.ReadFile(*tokenFile)
	if err != nil {
		fmt.Fprintf(stderr, "read cf-token-file: %v\n", err)
		return 1
	}
	token := []byte(strings.TrimSpace(string(tokenBytes)))
	if len(token) == 0 {
		fmt.Fprintln(stderr, "cf-token-file is empty")
		return 1
	}
	defer zeroBytes(token)

	p := cloudflare.NewProvider(cloudflare.NewLiveCFClient())
	rec := &cloudflare.FrontRecord{
		Hostname:   *oldHostname,
		ZoneID:     *oldZoneID,
		PublicPath: *publicPath,
		OriginPath: *originPath,
	}
	_, newRouteID, err := p.RotateHostname(ctx, token, rec, *newHostname, *originIPv4, *originIPv6)
	if err != nil {
		fmt.Fprintf(stderr, "cdn-rotate-hostname: %v\n", err)
		return 1
	}
	body, err := json.MarshalIndent(cdnRotateResult{
		Hostname:      rec.Hostname,
		ZoneID:        rec.ZoneID,
		PublicPath:    rec.PublicPath,
		WorkerRouteID: newRouteID,
		OriginIPv4:    *originIPv4,
		OriginIPv6:    *originIPv6,
	}, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "marshal rotate result: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, string(body))
	return 0
}

// runCDNRotateOrigin drives the supplement §14.4 origin-only
// rotation. Hostname, public path, origin path are byte-identical
// before and after; only the proxied A / AAAA records move. Per
// §14.5 the caller MUST NOT re-sign the RelayPack — the public
// surface is unchanged from the censor's vantage.
func runCDNRotateOrigin(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cdn-rotate-origin", flag.ContinueOnError)
	fs.SetOutput(stderr)
	hostname := fs.String("hostname", "", "current public CDN hostname (unchanged)")
	zoneID := fs.String("zone-id", "", "current Cloudflare zone ID (unchanged)")
	newOriginIPv4 := fs.String("new-origin-ipv4", "", "new origin IPv4")
	newOriginIPv6 := fs.String("new-origin-ipv6", "", "new origin IPv6 (optional)")
	tokenFile := fs.String("cf-token-file", "", "Cloudflare API token file")

	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if err := requireAll(stderr, map[string]string{
		"--hostname":        *hostname,
		"--zone-id":         *zoneID,
		"--new-origin-ipv4": *newOriginIPv4,
		"--cf-token-file":   *tokenFile,
	}); err != nil {
		return 2
	}
	tokenBytes, err := os.ReadFile(*tokenFile)
	if err != nil {
		fmt.Fprintf(stderr, "read cf-token-file: %v\n", err)
		return 1
	}
	token := []byte(strings.TrimSpace(string(tokenBytes)))
	if len(token) == 0 {
		fmt.Fprintln(stderr, "cf-token-file is empty")
		return 1
	}
	defer zeroBytes(token)

	p := cloudflare.NewProvider(cloudflare.NewLiveCFClient())
	rec := &cloudflare.FrontRecord{
		Hostname: *hostname,
		ZoneID:   *zoneID,
	}
	if err := p.RotateOrigin(ctx, token, rec, *newOriginIPv4, *newOriginIPv6); err != nil {
		fmt.Fprintf(stderr, "cdn-rotate-origin: %v\n", err)
		return 1
	}
	body, err := json.MarshalIndent(cdnRotateResult{
		Hostname:   rec.Hostname,
		ZoneID:     rec.ZoneID,
		OriginIPv4: *newOriginIPv4,
		OriginIPv6: *newOriginIPv6,
	}, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "marshal rotate result: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, string(body))
	return 0
}

// publishFreshnessResult is the wizard ↔ CLI contract shape for
// publish-freshness. The signed_doc_path is empty when the wizard
// did not pass --out-file; signed_doc_b64 always carries the
// signed JSON so the wizard can stash it without a tempfile.
type publishFreshnessResult struct {
	SignedDocB64    string `json:"signed_doc_b64"`
	SignedDocPath   string `json:"signed_doc_path"`
	RelayPackID     string `json:"relay_pack_id"`
	BundleSHA256Hex string `json:"current_bundle_sha256"`
	PublishedURL    string `json:"published_url"`
}

// runPublishFreshness builds and signs a freshness JSON document
// for the supplied RelayPack metadata. The wizard calls this
// after re-signing the RelayPack on L7 / L8 rotations so the
// recipient's freshness fetcher (core/refresh/relaypack.go) can
// re-walk the sub-key chain on the new bundle. **Must not be
// called on L9 origin-only rotations** — the bundle is unchanged
// and the existing freshness document is still valid.
//
// This commit ships build + sign only; live backend Put (R2 /
// GH Pages) is gated behind freshness.ErrBackendNotImplemented
// and will be wired alongside the SDK in a follow-up. The wizard
// stores the signed bytes in the operator's staging directory so
// a manual `gh-pages push` (or equivalent) can publish them in the
// interim.
func runPublishFreshness(_ context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("publish-freshness", flag.ContinueOnError)
	fs.SetOutput(stderr)
	relayPackID := fs.String("relay-pack-id", "", "RelayPack.RelayPackID for the current bundle")
	currentBundleSHA := fs.String("current-bundle-sha256", "", "SHA-256 hex digest of the .sbp body")
	currentSignedURL := fs.String("current-signed-url", "", "https URL the .sbp is published at")
	publisherPubHex := fs.String("publisher-pub-hex", "", "publisher root pubkey, hex")
	rootPrivFile := fs.String("root-priv-file", "", "publisher root privkey file (Ed25519, 64-byte raw)")
	subkeyPrivFile := fs.String("subkey-priv-file", "", "subkey privkey file (overrides root-priv-file)")
	subkeyCertFile := fs.String("subkey-cert-file", "", "subkey cert JSON file; required when subkey-priv-file set")
	outFile := fs.String("out-file", "", "write signed JSON to this path (else stdout-only)")
	nowOverride := fs.Int64("now-unix", 0, "freshness LastModified override; 0 = wall clock")

	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if err := requireAll(stderr, map[string]string{
		"--relay-pack-id":         *relayPackID,
		"--current-bundle-sha256": *currentBundleSHA,
		"--current-signed-url":    *currentSignedURL,
		"--publisher-pub-hex":     *publisherPubHex,
	}); err != nil {
		return 2
	}
	if *rootPrivFile == "" && *subkeyPrivFile == "" {
		fmt.Fprintln(stderr, "publish-freshness: either --root-priv-file or --subkey-priv-file is required")
		return 2
	}
	if *subkeyPrivFile != "" && *subkeyCertFile == "" {
		fmt.Fprintln(stderr, "publish-freshness: --subkey-priv-file requires --subkey-cert-file")
		return 2
	}
	var lastModified time.Time
	if *nowOverride != 0 {
		lastModified = time.Unix(*nowOverride, 0).UTC()
	}
	doc, err := freshness.Build(freshness.BuildOpts{
		RelayPackID:         *relayPackID,
		CurrentBundleSHA256: *currentBundleSHA,
		CurrentSignedURL:    *currentSignedURL,
		PublisherPubHex:     *publisherPubHex,
		LastModified:        lastModified,
	})
	if err != nil {
		fmt.Fprintf(stderr, "publish-freshness: build: %v\n", err)
		return 1
	}
	var signed []byte
	if *subkeyPrivFile != "" {
		subPriv, err := os.ReadFile(*subkeyPrivFile)
		if err != nil {
			fmt.Fprintf(stderr, "publish-freshness: read subkey-priv-file: %v\n", err)
			return 1
		}
		defer zeroBytes(subPriv)
		if len(subPriv) != ed25519.PrivateKeySize {
			fmt.Fprintln(stderr, "publish-freshness: subkey-priv-file must be 64 bytes raw Ed25519")
			return 1
		}
		certBytes, err := os.ReadFile(*subkeyCertFile)
		if err != nil {
			fmt.Fprintf(stderr, "publish-freshness: read subkey-cert-file: %v\n", err)
			return 1
		}
		signed, err = freshness.SignWithSubkey(doc, ed25519.PrivateKey(subPriv), certBytes)
		if err != nil {
			fmt.Fprintf(stderr, "publish-freshness: sign-with-subkey: %v\n", err)
			return 1
		}
	} else {
		rootPriv, err := os.ReadFile(*rootPrivFile)
		if err != nil {
			fmt.Fprintf(stderr, "publish-freshness: read root-priv-file: %v\n", err)
			return 1
		}
		defer zeroBytes(rootPriv)
		if len(rootPriv) != ed25519.PrivateKeySize {
			fmt.Fprintln(stderr, "publish-freshness: root-priv-file must be 64 bytes raw Ed25519")
			return 1
		}
		signed, err = freshness.Sign(doc, ed25519.PrivateKey(rootPriv))
		if err != nil {
			fmt.Fprintf(stderr, "publish-freshness: sign: %v\n", err)
			return 1
		}
	}
	if *outFile != "" {
		if err := os.WriteFile(*outFile, signed, 0o600); err != nil {
			fmt.Fprintf(stderr, "publish-freshness: write %q: %v\n", *outFile, err)
			return 1
		}
	}
	res := publishFreshnessResult{
		SignedDocB64:    base64.StdEncoding.EncodeToString(signed),
		SignedDocPath:   *outFile,
		RelayPackID:     *relayPackID,
		BundleSHA256Hex: *currentBundleSHA,
		// PublishedURL is left empty: live backend Put is stubbed
		// at this commit; a follow-up FRP-9 patch wires R2 / GH
		// Pages SDKs and fills this in.
	}
	body, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "publish-freshness: marshal: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, string(body))
	return 0
}

func readRecord(path string) (*provider.OperatorRecord, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rec provider.OperatorRecord
	if err := json.Unmarshal(body, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

func emitRecord(rec *provider.OperatorRecord, outFile string, stdout, stderr io.Writer) int {
	body, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "marshal: %v\n", err)
		return 1
	}
	body = append(body, '\n')
	if outFile == "" {
		_, _ = stdout.Write(body)
		return 0
	}
	if err := os.WriteFile(outFile, body, 0o600); err != nil {
		fmt.Fprintf(stderr, "write %s: %v\n", outFile, err)
		return 1
	}
	return 0
}

func requireAll(stderr io.Writer, m map[string]string) error {
	missing := []string{}
	for k, v := range m {
		if v == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		fmt.Fprintf(stderr, "missing required flags: %s\n", strings.Join(missing, ", "))
		return errors.New("missing flags")
	}
	return nil
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// runBindAndSign: daal-deploy bind-and-sign --operator-record path \
//
//	--priv-key <path|-> --output rp.sbp [--phase <phase>] [--now-unix N]
//	[--expiry-days 30] [--publisher-name "Family Relay Publisher"]
//	[--subkey-cert trust/subkey-cert.json] [--progress-json]
//
// Privkey transport: by default the privkey file is read from disk.
// Pass --priv-key=- to read it from stdin instead (the wizard pipes
// the decrypted privkey via stdin so it never touches disk).
//
// stdin must be exactly ed25519.PrivateKeySize bytes (64 raw). The
// CLI zero-fills its buffer immediately after passing the bytes to
// BindAndSign so the privkey doesn't linger in CLI process memory
// once signing is done.
func runBindAndSign(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("bind-and-sign", flag.ContinueOnError)
	fs.SetOutput(stderr)
	recordFile := fs.String("operator-record", "", "OperatorRecord JSON path")
	privKeyFlag := fs.String("priv-key", "", "publisher Ed25519 private key (path | '-' for stdin)")
	outFile := fs.String("output", "", "write signed .sbp here (default: stdout)")
	// Default = the one canonical constant. Nothing in this file may
	// spell a phase literal; see bundle/go/phase.
	phaseFlag := fs.String("phase", string(relaypackvalidate.CurrentPhase),
		fmt.Sprintf("validator phase (%s | %s | %s)",
			relaypackvalidate.PhaseV15, relaypackvalidate.PhaseV16, relaypackvalidate.PhasePostV2))
	nowUnix := fs.Int64("now-unix", 0, "override CreatedAt to this unix time (deterministic builds; 0 = time.Now())")
	expiryDays := fs.Int("expiry-days", 30, "bundle validity window in days")
	publisherName := fs.String("publisher-name", "", "human-readable publisher name (default: Family Relay Publisher)")
	subkeyCert := fs.String("subkey-cert", "", "FRP-7.5 trust/subkey-cert.json path when --priv-key is a certified sub-key")
	freshnessURL := fs.String("freshness-url", "", "FRP-8 V1.6 freshness endpoint URL (https://); empty for V1.5")
	progressJSON := fs.Bool("progress-json", false, "emit one JSON line per step on stderr")

	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if err := requireAll(stderr, map[string]string{
		"--operator-record": *recordFile,
		"--priv-key":        *privKeyFlag,
		"--output":          *outFile,
	}); err != nil {
		return 2
	}

	emitProgress(*progressJSON, stderr, "bind_start", "starting bind", nil)

	rec, err := readRecord(*recordFile)
	if err != nil {
		fmt.Fprintf(stderr, "read operator-record: %v\n", err)
		return 1
	}

	priv, err := readPrivKey(*privKeyFlag, stdin)
	if err != nil {
		fmt.Fprintf(stderr, "read priv-key: %v\n", err)
		return 1
	}
	defer zeroBytes(priv)
	var subkeyCertJSON []byte
	if *subkeyCert != "" {
		subkeyCertJSON, err = os.ReadFile(*subkeyCert)
		if err != nil {
			fmt.Fprintf(stderr, "read subkey-cert: %v\n", err)
			return 1
		}
		if len(subkeyCertJSON) == 0 {
			fmt.Fprintln(stderr, "read subkey-cert: empty file")
			return 1
		}
	}

	emitProgress(*progressJSON, stderr, "bind_validate", "running RelayPack validator", nil)

	// phase.Parse is the single parser: it maps "" to the shipped
	// phase and rejects anything it does not recognise, so a typo in
	// --phase can never silently select a different gate set.
	ph, err := phase.Parse(*phaseFlag)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 2
	}

	now := time.Now().UTC()
	if *nowUnix > 0 {
		now = time.Unix(*nowUnix, 0).UTC()
	}

	res, err := relaypack.BindAndSign(rec, priv, relaypack.BindOpts{
		Now:                  now,
		Expiry:               time.Duration(*expiryDays) * 24 * time.Hour,
		Phase:                ph,
		PublisherDisplayName: *publisherName,
		SubkeyCertJSON:       subkeyCertJSON,
		FreshnessURL:         *freshnessURL,
	})
	if err != nil {
		emitProgress(*progressJSON, stderr, "bind_error", err.Error(), nil)
		fmt.Fprintf(stderr, "bind-and-sign: %v\n", err)
		return 1
	}

	emitProgress(*progressJSON, stderr, "bind_sign", "signing bundle", nil)

	if err := os.WriteFile(*outFile, res.SBPBytes, 0o600); err != nil {
		fmt.Fprintf(stderr, "write output: %v\n", err)
		return 1
	}

	// Stdout: a small JSON summary the wizard parses for the
	// fingerprint screen. Keep it stable; the Rust shim assumes
	// these field names.
	summary := map[string]any{
		"sbp_path":          *outFile,
		"sbp_sha256":        res.BundleSHA256,
		"relay_pack_id":     res.RelayPackID,
		"fingerprint_hex":   res.FingerprintHex,
		"fingerprint_en":    res.FingerprintEN,
		"fingerprint_fa":    res.FingerprintFA,
		"lint_warnings":     res.LintReport.Warnings,
		"shared_risk_edges": len(res.SharedRiskGraph),
	}
	body, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "marshal summary: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, string(body))
	emitProgress(*progressJSON, stderr, "bind_done", "bundle signed", map[string]any{
		"sbp_sha256": res.BundleSHA256, "relay_pack_id": res.RelayPackID,
	})
	return 0
}

// runQRFountain: daal-deploy qr-fountain --sbp <path> [--block-size 256] [--frames 0]
//
// Writes JSON-line frames to stdout, one per line:
//
//	{"i":<index>,"k":<src_blocks>,"frame_b64":"<base64url>"}
//
// --frames 0 (default) means stream forever (Helper UI throttles
// the read loop based on its render FPS); --frames N caps the
// stream to N frames (used by tests).
//
// Block-size default 256 bytes — empirically the sweet spot for
// txqr-grade animated QR scanning on 1080p phone cameras at
// 5–10 FPS.
func runQRFountain(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("qr-fountain", flag.ContinueOnError)
	fs.SetOutput(stderr)
	sbpFile := fs.String("sbp", "", "signed RelayPack .sbp path")
	blockSize := fs.Int("block-size", 256, "fountain block size (bytes)")
	maxFrames := fs.Int("frames", 0, "max frames to emit (0 = unbounded)")
	seed := fs.Int64("seed", 0, "seed for the LT degree+block selector (deterministic streams for tests)")
	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if err := requireAll(stderr, map[string]string{"--sbp": *sbpFile}); err != nil {
		return 2
	}
	body, err := os.ReadFile(*sbpFile)
	if err != nil {
		fmt.Fprintf(stderr, "read sbp: %v\n", err)
		return 1
	}
	enc := fountain.NewEncoder(body, *blockSize, *seed)
	w := bufio.NewWriter(stdout)
	defer w.Flush()
	for i := 0; *maxFrames == 0 || i < *maxFrames; i++ {
		frame := enc.NextFrame()
		line := map[string]any{
			"i":         i,
			"k":         enc.SourceBlocks(),
			"frame_b64": base64.RawURLEncoding.EncodeToString(frame),
		}
		out, _ := json.Marshal(line)
		if _, err := w.Write(append(out, '\n')); err != nil {
			fmt.Fprintf(stderr, "write frame: %v\n", err)
			return 1
		}
	}
	return 0
}

// readPrivKey reads a 64-byte ed25519 private key from disk or
// stdin (when path is "-"). The returned slice is the caller's to
// zero after use.
func readPrivKey(path string, stdin io.Reader) (ed25519.PrivateKey, error) {
	var raw []byte
	var err error
	if path == "-" {
		raw, err = io.ReadAll(stdin)
		if err != nil {
			return nil, fmt.Errorf("stdin: %w", err)
		}
	} else {
		raw, err = os.ReadFile(path)
		if err != nil {
			return nil, err
		}
	}
	if len(raw) != ed25519.PrivateKeySize {
		// best-effort zero of the partial buffer before returning
		zeroBytes(raw)
		return nil, fmt.Errorf("priv-key: want %d bytes, got %d", ed25519.PrivateKeySize, len(raw))
	}
	return ed25519.PrivateKey(raw), nil
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func validateRecord(rec *provider.OperatorRecord) error {
	if rec == nil {
		return errors.New("nil OperatorRecord")
	}
	if rec.Provider == "" {
		return errors.New("missing provider")
	}
	if rec.Region == "" {
		return errors.New("missing region")
	}
	if rec.ServerType == "" {
		return errors.New("missing server_type")
	}
	if len(rec.PublisherPubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("publisher_pub_key length = %d want %d", len(rec.PublisherPubKey), ed25519.PublicKeySize)
	}
	if len(rec.Candidates) == 0 {
		return errors.New("missing candidates")
	}
	return nil
}

// runRotateRecommend is the FRP-7 rotation recommender CLI surface.
//
// Two paths:
//
//  1. With --explanation - (or no flag), reads a JSON-encoded
//     selection.Explanation from stdin and an OperatorRecord from
//     --record-file; emits the resulting RotationRecommendation as
//     JSON on stdout. This is the wizard's "I have the family's
//     diagnostics" path.
//
//  2. With --context-only, takes failure classifications and
//     network signals via repeated flags + --record-file and
//     emits the medium/low-confidence recommendation. Used when
//     the FRP cannot exfiltrate the recipient's Explanation.
//
// Position B: stdin/stdout/file I/O only; no network.
func runRotateRecommend(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rotate-recommend", flag.ContinueOnError)
	fs.SetOutput(stderr)
	recordFile := fs.String("record-file", "", "OperatorRecord JSON path (required)")
	contextOnly := fs.Bool("context-only", false, "use --classification + --signal flags instead of stdin Explanation")
	classifications := commaListFlag(fs, "classification", "comma-separated failure classifications (with --context-only)")
	signals := commaListFlag(fs, "signal", "comma-separated network signals (with --context-only)")
	credLeak := fs.Bool("credential-leak", false, "operator-asserted credential leak (with --context-only)")
	exposureMode := fs.String("exposure-mode", "direct_vps", "candidate exposure mode (direct_vps at V1.5)")
	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if err := requireAll(stderr, map[string]string{"--record-file": *recordFile}); err != nil {
		return 2
	}
	rec, err := readRecord(*recordFile)
	if err != nil {
		fmt.Fprintf(stderr, "read record-file: %v\n", err)
		return 1
	}

	var recommendation rotation.RotationRecommendation
	if *contextOnly {
		recommendation = rotation.FromContext(rotation.RotationContext{
			FailureClassifications:  *classifications,
			NetworkSignals:          *signals,
			ExposureMode:            *exposureMode,
			OperatorRecord:          rec,
			CredentialLeakSuspected: *credLeak,
		})
	} else {
		raw, err := io.ReadAll(stdin)
		if err != nil {
			fmt.Fprintf(stderr, "read stdin: %v\n", err)
			return 1
		}
		var exp rotation.Explanation
		if len(strings.TrimSpace(string(raw))) > 0 {
			if err := json.Unmarshal(raw, &exp); err != nil {
				fmt.Fprintf(stderr, "parse Explanation JSON: %v\n", err)
				return 1
			}
		}
		recommendation = rotation.FromExplanation(exp, rec)
	}

	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(recommendation); err != nil {
		fmt.Fprintf(stderr, "marshal: %v\n", err)
		return 1
	}
	return 0
}

// commaListFlag is a small helper that wires a repeatable string
// flag into a *[]string. Each occurrence may carry a comma-
// separated value; the flag accumulates across occurrences.
func commaListFlag(fs *flag.FlagSet, name, usage string) *[]string {
	out := &[]string{}
	fs.Var(commaListValue{out: out}, name, usage)
	return out
}

type commaListValue struct {
	out *[]string
}

func (v commaListValue) String() string {
	if v.out == nil {
		return ""
	}
	return strings.Join(*v.out, ",")
}

func (v commaListValue) Set(s string) error {
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			*v.out = append(*v.out, p)
		}
	}
	return nil
}
