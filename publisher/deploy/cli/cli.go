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
//	assign-fip     attach a floating IP to a record's server, reserving
//	               a fresh one when --fip-id is omitted, and tell the relay
//	               to configure it on its interface (--priv-key/--helper-ip)
//	               — the provider only ROUTES the address; the guest OS does
//	               not answer on it until it is bound.
//	floating-ip    assign | unassign | release a floating IP. unassign
//	               detaches (the address stays reserved and billing);
//	               release unbinds it on the relay, detaches, AND gives the
//	               address back, but only when daal-deploy reserved it.
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
	"bytes"
	"context"
	"crypto/ed25519"
	"daal/publisher/deploy/health"
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
	"daal/publisher/deploy/freshness/backends/ghpages"
	"daal/publisher/deploy/freshness/backends/r2"
	"daal/publisher/deploy/mgmt"
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
		return runAssignFIP(ctx, rest, os.Stdin, stdout, stderr)
	case "floating-ip":
		return runFloatingIP(ctx, rest, os.Stdin, stdout, stderr)
	case "verify":
		return runVerify(rest, stdout, stderr)
	case "bind-and-sign":
		return runBindAndSign(rest, os.Stdin, stdout, stderr)
	case "qr-fountain":
		return runQRFountain(rest, stdout, stderr)
	case "rotate-recommend":
		return runRotateRecommend(rest, os.Stdin, stdout, stderr)
	case "rotate-credentials":
		return runRotateCredentials(ctx, rest, os.Stdin, stdout, stderr)
	case "rotate-tls":
		return runRotateTLS(ctx, rest, os.Stdin, stdout, stderr)
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
                --cover-sni pins the REALITY cover host; omit it and the relay
                gets its own from the pool (publisher/deploy/sni).
  reprovision   Delete the VPS and re-Provision (full rotation). The record
                comes back with a NEW cover host unless --new-sni pins one.
  decommission  Destroy the cloud resources behind an OperatorRecord: the VPS,
                its per-server firewall, and the one-shot provisioning SSH key.
                Emits a per-resource JSON report on stdout (server_deleted /
                ssh_key_deleted / firewall_deleted / preserved / warnings).
                Exit 1 means the billing server survived — keep the record.
  pricing       Print live per-hour cost for a record's server type.
  assign-fip    Attach a floating IP to a record's server AND bind it on the
                relay so the box actually answers there. Needs --priv-key and
                --helper-ip; refuses (exit 3) on a relay whose mgmt binary
                cannot bind an address, before anything is reserved.
  floating-ip   Assign, unassign or release a floating IP. release unbinds the
                address on the relay before handing it back to the provider.
  verify        Validate OperatorRecord JSON.
  bind-and-sign Bind OperatorRecord -> signed RelayPack .sbp (FRP-4b).
                --freshness-mirror provider=url (REPEAT, min 2, distinct
                providers) attaches the pack's freshness endpoint SET: the
                signed trust/freshness-mirrors.json entry plus the legacy
                scalar slot. A single freshness host is not a supported pack
                shape — it is one block away from no recovery path — so the
                old --freshness-url is retired and errors.
                --revocation-url + --revocation-pub-hex set the publisher's
                revocation endpoint. Without them recipients never poll a
                revocation list and a leaked pack can never be withdrawn.
  qr-fountain   Stream LT-fountain frames for a .sbp (FRP-4b).
  rotate-recommend
                Read an Explanation JSON on stdin (or a context flag set)
                and emit a RotationRecommendation JSON on stdout (FRP-7).
  rotate-credentials
                L1 in place: rotate ONE recipient's per-user credentials across
                every inbound on a live relay (~90s, server survives). --name is
                required; there is no rotate-all. Emits the new creds as JSON in
                users-provision shape — persist them, they exist nowhere else.
                Other recipients are unaffected and their packs stay valid.
  rotate-tls    L2 in place: rotate the relay's cover SNI / TLS parameters on a
                live relay (~90s, server survives). REALITY keypairs and every
                recipient's credentials are untouched. Omit --new-sni to draw a
                fresh admissible host from the relay's zone. REWRITES the
                OperatorRecord (--record-out to redirect) because the record's
                cover host is what the pack minter reads. Every distributed pack
                pins the old host and must be re-minted afterwards.
                Exit 3 from either verb means the relay's daal-relay-mgmt is too
                old for in-place rotation — reprovision or re-release.
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
                Build, sign and PUBLISH the freshness document for the current
                SBP; emits it to stdout (or --out-file). Wizard calls this on
                L7/L8 public-surface rotations after the RelayPack is re-signed.
                MUST NOT be called on L9 origin-only rotations (FRP-9).
                The document carries a monotonic --sequence (default: the
                publish timestamp) and a --ttl-hours expiry: together they are
                what stops a censor replaying an older signed document to
                freeze a recipient or walk it back onto revoked credentials.
                Supply --r2-* and/or --gh-* credentials to upload; the upload
                is an error unless at least 2 mirrors accept it. With no
                credentials the verb signs only and says so on stderr.
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
//	  [--token-file ... ] [--cover-sni ...] -o record.json
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
	// Wave 2: the per-relay REALITY cover host. Empty is the normal
	// case — the provider picks one from publisher/deploy/sni, seeded on
	// this relay's identity. Pass the persisted value when re-running
	// provisioning for an existing record (a rebuild, a retry, or the
	// second half of a reprovision), or the box comes back advertising a
	// different name than the packs already in recipients' hands.
	coverSNI := fs.String("cover-sni", "", "REALITY cover hostname; empty picks a per-relay host from the sni pool")
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
		CoverSNI:          *coverSNI,
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
		// Surfaced so the wizard can show which cover host this relay
		// got, and so two back-to-back provisions are visibly different
		// without reading the record file.
		"cover_sni": rec.CoverSNI,
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
	// Empty does NOT mean "keep the current SNI": the provider picks a
	// fresh host from the sni pool, excluding the one this relay is
	// advertising today. Set this only to force a specific name.
	newSNI := fs.String("new-sni", "", "FRP-7 L2: new TLS SNI; empty picks a fresh pool host, excluding the current one")
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

// floatingIPReserver is the optional half of the provider contract that
// can mint an address rather than only attach one the operator already
// owns. Mirrors rotation.FloatingIPProvisioner; declared locally for the
// same reason providerFace is.
type floatingIPReserver interface {
	CreateFloatingIP(ctx context.Context, rec *provider.OperatorRecord) (string, net.IP, error)
	ReleaseFloatingIP(ctx context.Context, rec *provider.OperatorRecord, fipID string) (bool, error)
}

// l3ProbePort/l3ProbeTimeout bound the post-swap reachability probe. 443 is
// the port every profile serves vless-reality on (relayports.For), and the
// timeout is short because a working address answers immediately — a slow
// answer here means something is wrong, not that we should wait longer.
const (
	l3ProbePort    = 443
	l3ProbeTimeout = 8 * time.Second
)

// printUnbindWarnings renders the box's own words about a removal.
//
// The bind path already did this (it is how "persisted=false" reaches an
// operator), and every unbind site threw the response away — including
// the one that goes on to hand the address back to the provider. The
// hard cases are errors now (mgmt.UnbindAddress refuses a 200 that says
// the address is still configured), so what is left here is genuinely
// advisory: a persistence record removed while the live half was already
// gone, a stale record skipped, a delegated apply. All of it is about a
// relay nobody can SSH into, so none of it is summarised.
func printUnbindWarnings(stderr io.Writer, un *mgmt.UnbindAddressResp) {
	if un == nil {
		return
	}
	for _, w := range un.Warnings {
		fmt.Fprintf(stderr, "warning: %s\n", w)
	}
}

// l3AddressServes is the reachability post-condition, injectable so tests
// can exercise both outcomes without waiting on a real network timeout —
// and so a test cannot accidentally pass by dialling something real.
var l3AddressServes = health.AddressServes

// The three mgmt-plane seams the L3 verbs drive, injectable for the same
// reason l3AddressServes is: each one opens a cloud firewall window and
// dials a TLS-pinned box, so a test that did not stub them would either
// hit the network or panic on a fake provider.
var (
	l3BoxCapabilities = mgmt.CapabilitiesWithFW
	l3BindAddress     = mgmt.BindAddressWithFW
	l3UnbindAddress   = mgmt.UnbindAddressWithFW
)

// THE ORDER OF AN L3 SWAP, AND WHY IT IS THIS ORDER.
//
//  0. ASK THE BOX WHAT IT CAN DO      — before anything is reserved or
//     attached. A relay whose pinned
//     mgmt binary cannot bind an
//     address can never answer on a
//     floating IP, so attaching one
//     would produce a billing
//     resource and a dead relay. The
//     refusal costs nothing and
//     changes nothing.
//  1. RESERVE (if no --fip-id)        — failure: nothing to undo.
//  2. ATTACH at the provider          — failure: give the reserved
//     address back.
//  3. RECORD POST-CONDITIONS          — the record's two copies of the
//     dialled address moved and
//     agree. Failure: give it back.
//  4. BIND ON THE BOX                 — the guest OS puts the address
//     on its interface. Delivered
//     over the PRE-SWAP address,
//     because that is the only one
//     the box answers on yet.
//     Failure: give it back.
//  5. PROBE                           — health.AddressServes proves the
//     bind actually worked. This is
//     the difference between
//     believing the box and knowing.
//     Failure: unbind, then give it
//     back.
//  6. COMMIT                          — write the record. Only now does
//     anything downstream re-sign a
//     pack against the new address.
//
// Step 5 stays even though step 4 reports success. The box's answer is a
// claim about a syscall; the probe is a connection from outside the box
// to the port recipients dial. The 2026-08-17 finding was exactly a case
// where every layer above reported success and the address was dead.
//
// On every failing path the record is NOT written, so nothing downstream
// can persist or re-sign a half-applied swap.
func runAssignFIP(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("assign-fip", flag.ContinueOnError)
	fs.SetOutput(stderr)
	recordFile := fs.String("record-file", "", "OperatorRecord JSON path")
	tokenFile := fs.String("token-file", "", "Hetzner API token file")
	// REQUIRED SINCE THIS WAVE. The swap is not a pure cloud-API
	// operation any more: the box has to be told to configure the
	// address, and that call is Ed25519-signed and runs inside an
	// ephemeral firewall window opened for this caller's IP. Without
	// these two the verb cannot finish, and it says so before it
	// reserves anything rather than after it has attached an address the
	// box will never answer on.
	privKeyFlag := fs.String("priv-key", "", "publisher Ed25519 private key (path | '-' for stdin) — required: the relay must be told to bind the new address")
	helperIP := fs.String("helper-ip", "", "Helper's outbound public IP (firewall allowlist) — required, see --priv-key")
	// OPTIONAL SINCE STEP 9. It used to be mandatory, which made the
	// whole L3 rung reachable only by an operator who had reserved an
	// address by hand in the provider console and knew its numeric id.
	// Empty now means "reserve a fresh one for this relay".
	fipID := fs.String("fip-id", "", "floating-IP ID to attach; empty reserves a new address in the relay's region")
	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if err := requireAll(stderr, map[string]string{
		"--record-file": *recordFile,
		"--token-file":  *tokenFile,
		"--priv-key":    *privKeyFlag,
		"--helper-ip":   *helperIP,
	}); err != nil {
		fmt.Fprintln(stderr, "assign-fip: attaching a floating IP is only half the swap — the relay has to configure the "+
			"address on its interface or it will never answer on it, and that call is signed. Pass --priv-key and --helper-ip.")
		return 2
	}
	rec, err := readRecord(*recordFile)
	if err != nil {
		fmt.Fprintf(stderr, "read record-file: %v\n", err)
		return 1
	}
	priv, err := readPrivKey(*privKeyFlag, stdin)
	if err != nil {
		fmt.Fprintf(stderr, "read priv-key: %v\n", err)
		return 1
	}
	defer zeroBytes(priv)
	p, err := buildProviderFn(rec.Provider, *tokenFile, false)
	if err != nil {
		fmt.Fprintf(stderr, "build provider: %v\n", err)
		return 1
	}

	// STEP 0. Never attach an address the box cannot answer on.
	//
	// This is the Step-7 interlock applied one operation earlier than
	// usual. Everywhere else the capability probe fires inside the same
	// firewall window as the call it guards; here it has to fire before
	// the CLOUD is touched at all, because by the time the bind would
	// refuse, an address has been reserved (billing) and attached
	// (routing to a box that ignores it). The probe is non-mutating and
	// costs one short window.
	caps, err := l3BoxCapabilities(ctx, p, rec, *helperIP)
	if err != nil {
		fmt.Fprintf(stderr, "assign-fip: capability probe failed (refusing to swap the address of a relay whose software we cannot identify): %v\n", err)
		return 1
	}
	if !caps.Has(mgmt.CapBindAddress) {
		fmt.Fprintf(stderr, "assign-fip: %v\n", mgmt.UnsupportedCapabilityError(caps, mgmt.CapBindAddress))
		return exitCapabilityUnsupported
	}

	id := *fipID
	reservedHere := false
	if id == "" {
		res, ok := p.(floatingIPReserver)
		if !ok {
			fmt.Fprintf(stderr, "assign-fip: the %s adapter cannot reserve an address — pass --fip-id with one you reserved in the provider console\n", rec.Provider)
			return 2
		}
		newID, addr, err := res.CreateFloatingIP(ctx, rec)
		if err != nil {
			fmt.Fprintf(stderr, "assign-fip: reserve address: %v\n", err)
			return 1
		}
		id, reservedHere = newID, true
		fmt.Fprintf(stderr, "reserved floating IP %s (%s)\n", newID, addr)
	}

	// Snapshot the address BEFORE the swap. rec.PublicIP is a net.IP
	// (a slice), and adoptPublicIP replaces the header rather than
	// writing through it — but a copy costs nothing and a post-
	// condition that aliases the thing it is checking is not a
	// post-condition.
	priorIP := append(net.IP(nil), rec.PublicIP...)
	priorFIPID := rec.FloatingIPID

	giveBack := func() {
		if !reservedHere {
			return
		}
		res, ok := p.(floatingIPReserver)
		if !ok {
			return
		}
		if deleted, rerr := res.ReleaseFloatingIP(ctx, rec, id); rerr != nil || !deleted {
			fmt.Fprintf(stderr, "warning: reserved floating IP %s could not be released (%v) and is still billing\n", id, rerr)
		}
	}

	if err := p.AssignFloatingIP(ctx, rec, id); err != nil {
		// An address we minted seconds ago and could not attach is a
		// billing resource with no purpose. Give it back rather than
		// leave the operator to find it in the console — the same
		// leak-on-failure the provisioning path was fixed for.
		giveBack()
		fmt.Fprintf(stderr, "assign-fip: %v\n", err)
		return 1
	}

	// THE POST-CONDITION, AND WHY IT LIVES HERE RATHER THAN IN THE
	// GO ROTATION EXECUTOR.
	//
	// rotation.Executor has exactly this check (checkAddressMoved,
	// checkRecordAddressConsistent) and it is correct — and it has no
	// production caller. The shipped rotation path is the wizard's
	// Rust re-implementation, and the ONLY provider mutation it makes
	// for L3 is this subprocess. So a guard that is not on this seam
	// is not on any seam a user can reach.
	//
	// What it catches is the bug Step 9 exists to end, in its two live
	// forms. (1) An adapter that records the floating-IP id and stops:
	// Vultr and Stark both do exactly that today, by their own
	// comments, so an L3 there re-signs a pack still naming the burned
	// address. (2) An operator who re-attaches the address the relay
	// is already on — the UI used to pre-fill that value — which
	// completes, reports success, publishes a freshness document and
	// changes nothing a censor can see. Both used to exit 0.
	//
	// The record is NOT emitted on failure, so nothing downstream
	// persists or re-signs against a half-applied swap.
	if err := rotation.CheckAddressMoved(priorIP, rec.PublicIP); err != nil {
		giveBack()
		fmt.Fprintf(stderr, "assign-fip: %v\n", err)
		return 1
	}
	if err := rotation.CheckRecordAddressConsistent(rec); err != nil {
		giveBack()
		fmt.Fprintf(stderr, "assign-fip: %v\n", err)
		return 1
	}
	// STEP 4. THE GUEST-OS HALF. Everything above happened in the cloud
	// API; a Hetzner floating IP is routed to the server there, but the
	// box does not reply on it until the address is on its interface.
	// This is the call that puts it there.
	//
	// It is delivered over priorIP — the address the relay is still
	// answering on — and NOT over rec.PublicIP, which the adapter has
	// already moved onto the new address. Dialling the new one would
	// deadlock the swap on itself: the request that brings the address
	// up cannot be delivered over the address it is bringing up.
	if len(priorIP) == 0 {
		giveBack()
		fmt.Fprintln(stderr, "assign-fip: the record carries no current public IP, so there is no working address to deliver the bind over; "+
			"repair the record (or reprovision) before swapping its address")
		return 1
	}
	bound, err := l3BindAddress(ctx, p, rec, priv, *helperIP, priorIP, rec.PublicIP)
	if err != nil {
		giveBack()
		fmt.Fprintf(stderr, "assign-fip: bind %s on the relay: %v\n", rec.PublicIP, err)
		if errors.Is(err, mgmt.ErrCapabilityUnsupported) {
			return exitCapabilityUnsupported
		}
		return 1
	}
	// The box's own words, verbatim and before the probe — a bind that
	// worked but did not persist is a relay that comes back after its
	// next reboot on an address no pack names, and the operator must see
	// that even on the success path.
	for _, w := range bound.Warnings {
		fmt.Fprintf(stderr, "warning: %s\n", w)
	}

	// STEP 5. And prove the relay actually ANSWERS there. The record
	// checks above ask whether the record moved; the bind above is the
	// box's own claim about what it did; this asks whether the move
	// WORKS, from outside, on the port recipients dial. On real hardware
	// (2026-08-17) an assign reported success at every layer above this
	// one and the box never replied. Committing that swap would re-sign
	// every pack onto a dead address: worse than the no-op this rung
	// used to be.
	if err := l3AddressServes(rec.PublicIP, l3ProbePort, l3ProbeTimeout); err != nil {
		// The bind DID happen, so undo it: leaving an address configured
		// on a box that is not going to serve on it means the relay may
		// source its own outbound traffic from an address the record no
		// longer names.
		//
		// AND THE UNDO DECIDES WHETHER THE ADDRESS MAY BE HANDED BACK.
		// giveBack() does not merely detach — it DELETES the reservation,
		// putting the address into the provider's pool for another
		// customer. Doing that while this relay may still hold it on its
		// interface is the same harm the release path refuses to commit,
		// so a failed unbind keeps the address reserved (costing money,
		// visibly, with the id printed) instead of giving it away.
		unbindFailed := false
		if un, uerr := l3UnbindAddress(ctx, p, rec, priv, *helperIP, priorIP, rec.PublicIP); uerr != nil {
			unbindFailed = true
			fmt.Fprintf(stderr, "warning: could not unbind %s from the relay after the failed probe (%v); "+
				"the address may still be configured on its interface\n", rec.PublicIP, uerr)
		} else {
			printUnbindWarnings(stderr, un)
		}
		switch {
		case unbindFailed && reservedHere:
			fmt.Fprintf(stderr, "floating IP %s (%s) was NOT released: handing it back to the provider pool while this relay "+
				"may still have it configured would give another customer an address this box still claims. "+
				"It is still reserved and still billing — release it with "+
				"`daal-deploy floating-ip release --fip-id %s --fip-address %s` once the relay is reachable, "+
				"or with --skip-unbind if the relay is gone\n", id, rec.PublicIP, id, rec.PublicIP)
		case unbindFailed:
			// Not ours to release (the operator supplied --fip-id), so
			// there was never anything to give back — but the address
			// is attached to this server AND may still be on its
			// interface, and nothing else will say so.
			fmt.Fprintf(stderr, "floating IP %s (%s) is still attached to this relay and may still be configured on its "+
				"interface; detach it with `daal-deploy floating-ip unassign` once the relay is reachable\n", id, rec.PublicIP)
		default:
			giveBack()
		}
		fmt.Fprintf(stderr, "assign-fip: %v\n", err)
		return 1
	}
	// The address the relay just moved OFF is still attached and still
	// billing — AssignFloatingIP deliberately does not detach it, so
	// that every already-distributed pack keeps working until the new
	// one is signed. Say so on stderr with the id the operator needs,
	// because "the old one no longer serves" is what the wizard tells
	// them and it is not true until someone releases it.
	if priorFIPID != "" && priorFIPID != id {
		// --fip-address is part of the instruction, not decoration: the
		// record this verb just wrote names the NEW address, so by the
		// time anyone runs the release the prior address exists nowhere
		// the CLI can find it, and a release that cannot name the
		// address cannot tell the relay to drop it.
		fmt.Fprintf(stderr, "note: floating IP %s (%s) is still attached to this relay and still billing; "+
			"release it with `daal-deploy floating-ip release --fip-id %s --fip-address %s` once the new pack is signed and distributed\n",
			priorFIPID, priorIP, priorFIPID, priorIP)
	}
	return emitRecord(rec, *recordFile, stdout, stderr)
}

// runReleaseFIP gives an address back. Separate from `unassign`, which
// only detaches: an address that is merely detached is still reserved
// and still billing, and until Step 9 there was no way at all to stop
// paying for one from inside the app.
//
// THE ORDER, which is the mirror of the assign path's:
//
//  1. remember the ADDRESS   — the record carries an id and an address;
//     after the detach the address is gone
//     from the record, and the box needs the
//     address, not the id. When the id being
//     released is NOT the one the record
//     names — which is every rotation, since
//     the record has already been replaced
//     with the swap's output — the caller
//     supplies it with --fip-address, and a
//     release that cannot resolve it REFUSES
//     rather than proceeding unbound.
//  2. DETACH at the provider — the record falls back to the server's own
//     primary address, so the mgmt call in step
//     3 has a working address to travel over.
//  3. UNBIND on the box      — remove it from the interface and from the
//     reboot-time config.
//  4. RELEASE                — and only now hand it back to the provider.
//
// Steps 3 and 4 are in that order for a reason worth stating: a released
// address goes back into the provider's pool and may be issued to
// another customer's server tomorrow. A box that still has it configured
// will keep choosing it as a source address for its own outbound
// traffic, from an address that is now routed to somebody else. So an
// unbind that FAILS stops the release rather than being logged and
// stepped over — the address stays reserved (costing money) instead of
// being handed away while a live box still claims it.
func runReleaseFIP(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("floating-ip release", flag.ContinueOnError)
	fs.SetOutput(stderr)
	recordFile := fs.String("record-file", "", "OperatorRecord JSON path")
	tokenFile := fs.String("token-file", "", "Hetzner API token file")
	fipID := fs.String("fip-id", "", "floating-IP ID to release; empty releases the one on the record")
	// --fip-address exists because of the ONLY shipping L3 path.
	//
	// The provider speaks ids; the box speaks addresses. When the id
	// being released is the one on the record, the record supplies the
	// address. The rotation flow never has that shape: the wizard
	// updates the stored record with the swap's OUTPUT (the new id and
	// the new address) and only then releases the PRIOR id, so the id
	// and the record disagree by construction, the address could not be
	// resolved, and the release proceeded with a warning — unbinding
	// nothing. Every second-and-later L3 therefore left the old address
	// configured on eth0 with a live persistence record, re-asserted at
	// every reboot, while the provider was free to issue it to someone
	// else; four of those and `maxBoundAddresses` kills L3 on that relay
	// for good.
	fipAddress := fs.String("fip-address", "",
		"the ADDRESS being released, for the relay's unbind, when it is not the one on the record (rotations release the PRIOR id)")
	privKeyFlag := fs.String("priv-key", "", "publisher Ed25519 private key (path | '-' for stdin) — required unless --skip-unbind")
	helperIP := fs.String("helper-ip", "", "Helper's outbound public IP (firewall allowlist) — required unless --skip-unbind")
	// THE ESCAPE HATCH, and it is narrow. The unbind needs a box that
	// answers; a relay that has already been destroyed cannot answer,
	// and refusing to release its address would leave the operator
	// paying for it with no way out of the app. --skip-unbind is that
	// case and only that case: on a LIVE box it hands an address back to
	// the provider pool while the box still claims it locally.
	skipUnbind := fs.Bool("skip-unbind", false,
		"release without telling the relay to drop the address; only for a relay that is already destroyed or permanently unreachable")
	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	needed := map[string]string{
		"--record-file": *recordFile,
		"--token-file":  *tokenFile,
	}
	if !*skipUnbind {
		needed["--priv-key"] = *privKeyFlag
		needed["--helper-ip"] = *helperIP
	}
	if err := requireAll(stderr, needed); err != nil {
		if !*skipUnbind {
			fmt.Fprintln(stderr, "floating-ip release: the relay has to be told to drop the address before it goes back to the "+
				"provider pool, and that call is signed. Pass --priv-key and --helper-ip, or --skip-unbind if the relay is already gone.")
		}
		return 2
	}
	rec, err := readRecord(*recordFile)
	if err != nil {
		fmt.Fprintf(stderr, "read record-file: %v\n", err)
		return 1
	}
	var priv ed25519.PrivateKey
	if !*skipUnbind {
		priv, err = readPrivKey(*privKeyFlag, stdin)
		if err != nil {
			fmt.Fprintf(stderr, "read priv-key: %v\n", err)
			return 1
		}
		defer zeroBytes(priv)
	}
	p, err := buildProviderFn(rec.Provider, *tokenFile, false)
	if err != nil {
		fmt.Fprintf(stderr, "build provider: %v\n", err)
		return 1
	}
	res, ok := p.(floatingIPReserver)
	if !ok {
		fmt.Fprintf(stderr, "floating-ip release: the %s adapter cannot release addresses — remove it in the provider console\n", rec.Provider)
		return 2
	}
	id := *fipID
	if id == "" {
		id = rec.FloatingIPID
	}
	if id == "" {
		fmt.Fprintln(stderr, "floating-ip release: no --fip-id and the record carries none")
		return 2
	}
	// STEP 1. The box speaks addresses; the provider speaks ids. This is
	// the only moment both are in hand, because the detach below clears
	// the record's address.
	//
	// Two ways to learn the address, in this order of authority:
	//
	//	--fip-address   the caller knows it. This is what a rotation
	//	                passes: it released the PRIOR id, whose address
	//	                the stored record no longer names.
	//	the record      when the id being released IS the record's
	//	                current one.
	//
	// If neither answers, the address cannot be resolved from here (no
	// adapter exposes id→address on the Provider interface) and the
	// release REFUSES rather than proceeding unbound. Proceeding is what
	// hands a live box's address to another customer, and a warning on
	// stderr is not a control. --skip-unbind remains the way through for
	// a relay that is genuinely gone.
	var releasedAddr net.IP
	switch {
	case strings.TrimSpace(*fipAddress) != "":
		releasedAddr = net.ParseIP(strings.TrimSpace(*fipAddress))
		if releasedAddr == nil {
			fmt.Fprintf(stderr, "floating-ip release: --fip-address %q is not an IP address\n", *fipAddress)
			return 2
		}
		// A caller that supplies both must agree with the record, or one
		// of the two is about to be acted on wrongly.
		if id == rec.FloatingIPID && len(rec.PublicIP) > 0 && !rec.PublicIP.Equal(releasedAddr) {
			fmt.Fprintf(stderr, "floating-ip release: --fip-address %s does not match the address the record gives for floating IP %s (%s); "+
				"refusing to guess which one the relay is holding\n", releasedAddr, id, rec.PublicIP)
			return 2
		}
	case id == rec.FloatingIPID:
		releasedAddr = append(net.IP(nil), rec.PublicIP...)
	}
	if len(releasedAddr) == 0 && !*skipUnbind {
		fmt.Fprintf(stderr, "floating-ip release: floating IP %s is not the address this record names, so its address is not "+
			"known here and the relay cannot be told to drop it. Pass --fip-address <addr> (a rotation releasing the PRIOR "+
			"address knows it), or --skip-unbind if that relay no longer exists. Releasing an address a live box still has "+
			"configured hands another customer an address this relay still claims\n", id)
		return 2
	}

	// STEP 2. Releasing the address the record is CURRENTLY on would
	// leave the record naming an unrouted address, which is the exact
	// failure the L3 work exists to prevent. Detach through the provider
	// first so the record falls back to the server's own primary
	// address — which is also what gives the unbind below a working
	// address to travel over.
	if id == rec.FloatingIPID {
		if err := p.UnassignFloatingIP(ctx, rec); err != nil {
			fmt.Fprintf(stderr, "floating-ip release: detach: %v\n", err)
			return 1
		}
	}

	// STEP 3.
	switch {
	case *skipUnbind:
		fmt.Fprintf(stderr, "warning: --skip-unbind: the relay was not told to drop %s. "+
			"If that box is still alive it will keep the address configured on its interface after the provider re-issues it to somebody else\n", id)
	default:
		// releasedAddr is non-empty here: the resolution above refuses
		// the run outright when the address is unknown and --skip-unbind
		// was not given, so there is no third branch that quietly
		// releases without telling the relay.
		un, err := l3UnbindAddress(ctx, p, rec, priv, *helperIP, rec.PublicIP, releasedAddr)
		printUnbindWarnings(stderr, un)
		switch {
		case errors.Is(err, mgmt.ErrCapabilityUnsupported):
			// A relay too old to bind never bound anything, so there is
			// nothing to remove and the release is safe. Refusing here
			// would strand an address on every pre-this-wave relay.
			fmt.Fprintf(stderr, "note: this relay's software predates address binding, so it never configured %s itself; releasing\n", releasedAddr)
		case err != nil:
			// Detached but NOT released. The record is written so it
			// matches the cloud (the address is off this server), and
			// the address stays reserved rather than being handed to
			// another customer while this box still claims it.
			_ = emitRecord(rec, *recordFile, stdout, stderr)
			fmt.Fprintf(stderr, "floating-ip release: unbind %s on the relay: %v\n", releasedAddr, err)
			fmt.Fprintf(stderr, "the address is DETACHED but NOT released: it is still reserved and still billing. "+
				"Releasing it now would hand an address back to the provider pool while this relay still has it configured, "+
				"so fix the relay and re-run, or re-run with --skip-unbind if the relay is gone\n")
			return 1
		}
	}

	// STEP 4.
	deleted, err := res.ReleaseFloatingIP(ctx, rec, id)
	if err != nil {
		fmt.Fprintf(stderr, "floating-ip release: %v\n", err)
		return 1
	}
	if !deleted {
		fmt.Fprintf(stderr, "floating IP %s was detached but left reserved (daal-deploy did not create it) — it is still on your account and still billing\n", id)
	}
	return emitRecord(rec, *recordFile, stdout, stderr)
}

func runFloatingIP(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		fmt.Fprintln(stderr, "missing floating-ip action: assign | unassign")
		return 2
	}
	action := args[0]
	switch action {
	case "assign":
		return runAssignFIP(ctx, args[1:], stdin, stdout, stderr)
	case "unassign":
		return runUnassignFIP(ctx, args[1:], stdin, stdout, stderr)
	case "release":
		return runReleaseFIP(ctx, args[1:], stdin, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown floating-ip action %q (want assign, unassign or release)\n", action)
		return 2
	}
}

// runUnassignFIP detaches the address at the provider and leaves it
// reserved.
//
// The box half is OPTIONAL here, unlike on release, and the difference
// is the blast radius. Release hands the address back to the provider's
// pool, where another customer may be issued it while this box still
// claims it locally — so release refuses rather than proceed unbound.
// Unassign leaves the address reserved to this operator, so nobody else
// can receive it; the only cost of a leftover binding is that this relay
// may keep choosing a no-longer-routed address as its outbound source.
// That is worth fixing when the caller supplies the signing material and
// worth SAYING when it does not — but not worth making a third verb
// unusable without it.
func runUnassignFIP(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("floating-ip unassign", flag.ContinueOnError)
	fs.SetOutput(stderr)
	recordFile := fs.String("record-file", "", "OperatorRecord JSON path")
	tokenFile := fs.String("token-file", "", "Hetzner API token file")
	privKeyFlag := fs.String("priv-key", "", "publisher Ed25519 private key (path | '-' for stdin); supply it to also drop the address on the relay")
	helperIP := fs.String("helper-ip", "", "Helper's outbound public IP (firewall allowlist); needed with --priv-key")
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
	// The address, captured before the detach clears it from the record.
	detached := append(net.IP(nil), rec.PublicIP...)
	hadFIP := rec.FloatingIPID != ""
	if err := p.UnassignFloatingIP(ctx, rec); err != nil {
		fmt.Fprintf(stderr, "floating-ip unassign: %v\n", err)
		return 1
	}
	switch {
	case !hadFIP || len(detached) == 0:
		// Nothing was attached; nothing to drop.
	case *privKeyFlag == "" || *helperIP == "":
		fmt.Fprintf(stderr, "warning: %s is detached at the provider but the relay was not told to drop it, so it is still "+
			"configured on the box's interface and may still be used as an outbound source address. "+
			"Re-run with --priv-key and --helper-ip, or unbind it on the relay\n", detached)
	default:
		priv, err := readPrivKey(*privKeyFlag, stdin)
		if err != nil {
			fmt.Fprintf(stderr, "read priv-key: %v\n", err)
			return 1
		}
		defer zeroBytes(priv)
		un, err := l3UnbindAddress(ctx, p, rec, priv, *helperIP, rec.PublicIP, detached)
		printUnbindWarnings(stderr, un)
		if err != nil && !errors.Is(err, mgmt.ErrCapabilityUnsupported) {
			fmt.Fprintf(stderr, "warning: could not tell the relay to drop %s (%v); it may still be configured on its interface\n", detached, err)
		}
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

// buildProviderFn is the seam the teardown and floating-IP paths build
// their adapter through, so cli_test.go can assert their contracts —
// the decommission JSON report, and the address-swap behaviour L3
// depends on — against an in-memory provider instead of a live cloud
// token. Production always leaves it pointing at buildProvider.
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
	// PublishedURL is the first mirror that accepted the write.
	// Retained because the Rust bridge's PublishFreshnessResult
	// deserialises it by name and would fail on a missing field;
	// Published[] is the field that actually describes the outcome.
	PublishedURL string `json:"published_url"`
	// Sequence is the monotonic counter stamped into the document.
	// Surfaced so the caller can persist it and pass a strictly
	// greater value next time.
	Sequence uint64 `json:"sequence"`
	NotAfter string `json:"not_after"`
	// Published carries one row per configured mirror, including
	// the failures — a publish that only reached one provider is
	// reported as an error, but the operator still needs to see
	// which one refused.
	Published []freshness.PublishResult `json:"published"`
}

// runPublishFreshness builds and signs a freshness JSON document
// for the supplied RelayPack metadata. The wizard calls this
// after re-signing the RelayPack on L7 / L8 rotations so the
// recipient's freshness fetcher (core/refresh/relaypack.go) can
// re-walk the sub-key chain on the new bundle. **Must not be
// called on L9 origin-only rotations** — the bundle is unchanged
// and the existing freshness document is still valid.
//
// Publishing is live: with --r2-* / --gh-* credentials supplied
// the signed bytes are PUT to every configured mirror and the
// per-mirror outcome is reported. With none supplied the verb
// builds and signs only (the pre-Wave-3 behaviour), so the wizard
// path that stashes the bytes in the staging directory keeps
// working.
func runPublishFreshness(ctx context.Context, args []string, stdout, stderr io.Writer) int {
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
	sequence := fs.Uint64("sequence", 0, "monotonic document counter; 0 = derive from the publish timestamp")
	minSequence := fs.Uint64("min-sequence", 0,
		"refuse to publish unless the document's sequence is strictly greater than this (the caller's last published value)")
	supersedes := commaListFlag(fs, "supersedes",
		"a relay_pack_id this pack replaces; repeat once per prior id, newest first")
	ttlHours := fs.Int("ttl-hours", 0, "document validity window in hours (0 = 72h default)")
	advertise := commaListFlag(fs, "mirror",
		"advertise this endpoint set in the document as provider=https://url; repeat (min 2)")
	// Live-upload credentials. Absent ⇒ build+sign only.
	r2Account := fs.String("r2-account", "", "Cloudflare account ID for the R2 mirror")
	r2Bucket := fs.String("r2-bucket", "", "R2 bucket")
	r2Key := fs.String("r2-object-key", "", "R2 object key, e.g. freshness/<relay_pack_id>.json")
	r2PublicURL := fs.String("r2-public-url", "", "recipient-facing https URL of the R2 object")
	r2AccessKeyID := fs.String("r2-access-key-id", "", "R2 S3-compatible access key id")
	r2SecretFile := fs.String("r2-secret-file", "", "file holding the R2 secret access key")
	ghOwner := fs.String("gh-owner", "", "GitHub Pages owner")
	ghRepo := fs.String("gh-repo", "", "GitHub Pages repo")
	ghPath := fs.String("gh-path", "", "path inside the repo, e.g. freshness/<relay_pack_id>.json")
	ghBranch := fs.String("gh-branch", "", "branch (default main)")
	ghPublicURL := fs.String("gh-public-url", "", "recipient-facing https://owner.github.io/repo/path URL")
	ghPATFile := fs.String("gh-pat-file", "", "file holding the fine-grained PAT (Contents: RW)")

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
	lastModified := time.Now().UTC()
	if *nowOverride != 0 {
		lastModified = time.Unix(*nowOverride, 0).UTC()
	}
	// THE SEQUENCE, AND WHY THE CLOCK IS NOT ENOUGH ON ITS OWN.
	//
	// The sequence is what makes a replayed document harmless. It has
	// to move forward on every publish, forever, per relay_pack_id.
	// Deriving it from the publish timestamp gets that for free while
	// a clock only moves forward — and a clock is not a counter. An
	// NTP correction after a dead RTC, a restored VM snapshot, or
	// simply publishing from a second laptop whose clock lags, all
	// produce a document with a LOWER sequence than one recipients
	// have already accepted and persisted as their high-water mark.
	// Those recipients then reject every document until wall clock
	// catches up, for hours or days, while this command exits 0 and
	// the panel goes green. Nothing on either side would notice.
	//
	// So the counter has an owner: the caller. --min-sequence is the
	// caller's statement of the last value it published, and a
	// document that does not strictly exceed it is refused HERE,
	// loudly, instead of being uploaded and silently ignored by the
	// fleet. The wizard passes max(last+1, now) as --sequence, so in
	// normal operation this never fires; when it does, it means the
	// publishing machine's clock went backwards and the operator
	// needs to know that before it costs them a recovery.
	seq := *sequence
	if seq == 0 {
		seq = uint64(lastModified.Unix())
		if *minSequence >= seq {
			// Clock behind the counter: keep publishing, but on the
			// counter's terms rather than the clock's. Refusing here
			// would leave an operator with a backwards clock unable
			// to recover a relay at all, which is a worse failure
			// than a sequence that has run ahead of wall time.
			seq = *minSequence + 1
			fmt.Fprintf(stderr, "publish-freshness: this machine's clock (%d) is at or behind the last published sequence (%d); "+
				"using %d instead — check the clock, because every OTHER thing that derives a timestamp here is also wrong\n",
				lastModified.Unix(), *minSequence, seq)
		}
	}
	if *minSequence > 0 && seq <= *minSequence {
		fmt.Fprintf(stderr, "publish-freshness: refusing to publish sequence %d — it is not greater than the last published value (%d), "+
			"so every recipient that already accepted %d would reject this document as a rollback and keep serving the previous one\n",
			seq, *minSequence, *minSequence)
		return 2
	}
	advertised, err := parseFreshnessMirrors(*advertise)
	if err != nil {
		fmt.Fprintf(stderr, "publish-freshness: %v\n", err)
		return 2
	}
	warnSharedDomains(stderr, "publish-freshness", advertised)
	doc, err := freshness.Build(freshness.BuildOpts{
		RelayPackID: *relayPackID,
		// The ids this pack replaces. Without them the document is
		// addressed to a name no existing recipient answers to: the
		// pack id is a hash of the very attributes L3/L4/L5/L6
		// change, so the rung that rotates a relay also renames it.
		Supersedes:          *supersedes,
		Sequence:            seq,
		CurrentBundleSHA256: *currentBundleSHA,
		CurrentSignedURL:    *currentSignedURL,
		PublisherPubHex:     *publisherPubHex,
		Mirrors:             advertised,
		LastModified:        lastModified,
		TTL:                 time.Duration(*ttlHours) * time.Hour,
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
		Sequence:        doc.Sequence,
		NotAfter:        doc.NotAfter,
	}

	targets, err := freshnessTargets(freshnessTargetArgs{
		r2Account: *r2Account, r2Bucket: *r2Bucket, r2Key: *r2Key,
		r2PublicURL: *r2PublicURL, r2AccessKeyID: *r2AccessKeyID, r2SecretFile: *r2SecretFile,
		ghOwner: *ghOwner, ghRepo: *ghRepo, ghPath: *ghPath, ghBranch: *ghBranch,
		ghPublicURL: *ghPublicURL, ghPATFile: *ghPATFile,
	})
	if err != nil {
		fmt.Fprintf(stderr, "publish-freshness: %v\n", err)
		return 2
	}
	publishFailed := false
	if len(targets) > 0 {
		results, perr := freshness.PublishAll(ctx, signed, targets)
		res.Published = results
		for _, r := range results {
			if r.OK && res.PublishedURL == "" {
				res.PublishedURL = r.URL
			}
			if !r.OK {
				// The failure is printed on stderr as well as
				// carried in the JSON: an operator watching a
				// terminal must not have to parse stdout to learn
				// that half their mirrors are down.
				fmt.Fprintf(stderr, "publish-freshness: mirror %s FAILED: %s\n", r.Provider, r.Error)
			}
		}
		if perr != nil {
			fmt.Fprintf(stderr, "publish-freshness: %v\n", perr)
			publishFailed = true
		}
	} else {
		fmt.Fprintln(stderr, "publish-freshness: no mirror credentials supplied — "+
			"document signed but NOT published; recipients will keep serving the previous document until it expires")
	}

	body, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "publish-freshness: marshal: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, string(body))
	if publishFailed {
		return 1
	}
	return 0
}

// freshnessTargetArgs groups the per-backend upload credentials so
// freshnessTargets stays readable.
type freshnessTargetArgs struct {
	r2Account, r2Bucket, r2Key, r2PublicURL, r2AccessKeyID, r2SecretFile string
	ghOwner, ghRepo, ghPath, ghBranch, ghPublicURL, ghPATFile            string
}

// freshnessTargets builds the upload targets from whichever
// credential groups the operator supplied. A group is "supplied"
// if any of its flags is set; a partially-supplied group is an
// error rather than a silently-skipped mirror, because a silently
// skipped mirror is a pack that promises two endpoints and has
// one.
//
// Secrets are read into byte slices and zeroized by the caller's
// deferred wipe; they are never placed in argv (which is world-
// readable on Linux) — hence --r2-secret-file / --gh-pat-file
// rather than --r2-secret / --gh-pat.
func freshnessTargets(a freshnessTargetArgs) ([]freshness.Target, error) {
	var targets []freshness.Target

	r2Set := a.r2Account != "" || a.r2Bucket != "" || a.r2Key != "" ||
		a.r2PublicURL != "" || a.r2AccessKeyID != "" || a.r2SecretFile != ""
	if r2Set {
		if a.r2Account == "" || a.r2Bucket == "" || a.r2Key == "" ||
			a.r2PublicURL == "" || a.r2AccessKeyID == "" || a.r2SecretFile == "" {
			return nil, errors.New("r2 mirror: --r2-account, --r2-bucket, --r2-object-key, " +
				"--r2-public-url, --r2-access-key-id and --r2-secret-file are all required")
		}
		secret, err := os.ReadFile(a.r2SecretFile)
		if err != nil {
			return nil, fmt.Errorf("read r2-secret-file: %w", err)
		}
		be, err := r2.New(r2.Config{
			AccountID:       a.r2Account,
			Bucket:          a.r2Bucket,
			ObjectKey:       a.r2Key,
			AccessKeyID:     a.r2AccessKeyID,
			SecretAccessKey: bytes.TrimSpace(secret),
			PublicReadURL:   a.r2PublicURL,
		})
		if err != nil {
			return nil, err
		}
		targets = append(targets, freshness.Target{Provider: freshness.ProviderR2, Backend: be})
	}

	ghSet := a.ghOwner != "" || a.ghRepo != "" || a.ghPath != "" ||
		a.ghPublicURL != "" || a.ghPATFile != ""
	if ghSet {
		if a.ghOwner == "" || a.ghRepo == "" || a.ghPath == "" ||
			a.ghPublicURL == "" || a.ghPATFile == "" {
			return nil, errors.New("ghpages mirror: --gh-owner, --gh-repo, --gh-path, " +
				"--gh-public-url and --gh-pat-file are all required")
		}
		pat, err := os.ReadFile(a.ghPATFile)
		if err != nil {
			return nil, fmt.Errorf("read gh-pat-file: %w", err)
		}
		be, err := ghpages.New(ghpages.Config{
			Owner:         a.ghOwner,
			Repo:          a.ghRepo,
			Path:          a.ghPath,
			Branch:        a.ghBranch,
			PAT:           bytes.TrimSpace(pat),
			PublicReadURL: a.ghPublicURL,
		})
		if err != nil {
			return nil, err
		}
		targets = append(targets, freshness.Target{Provider: freshness.ProviderGHPages, Backend: be})
	}
	return targets, nil
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
	// Repeatable: --freshness-mirror r2=https://… --freshness-mirror ghpages=https://…
	// One pair per storage account the publisher actually holds.
	// Fewer than freshness.MinMirrors is refused by NewMirrorSet.
	freshnessMirrors := commaListFlag(fs, "freshness-mirror",
		"FRP-8 freshness endpoint as provider=https://url; repeat for each provider (min 2, distinct providers)")
	// Retired. Kept as a recognised flag so a caller that still
	// passes it fails loudly instead of silently minting a pack
	// with no freshness path at all.
	freshnessURLRetired := fs.String("freshness-url", "",
		"RETIRED — use --freshness-mirror provider=url (repeat); a single freshness host is not a supported pack shape")
	revocationURL := fs.String("revocation-url", "", "publisher revocation list URL (https://); requires --revocation-pub-hex")
	revocationPubHex := fs.String("revocation-pub-hex", "", "revocation list SIGNING public key, 64 hex chars (not a fingerprint)")
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
	if *freshnessURLRetired != "" {
		fmt.Fprintln(stderr, "bind-and-sign: --freshness-url is retired.")
		fmt.Fprintln(stderr, "  A freshness endpoint is a fixed URL inside a signed pack: it is itself a")
		fmt.Fprintln(stderr, "  censorship target, and one host means one block away from no recovery path.")
		fmt.Fprintf(stderr, "  Pass %d or more: --freshness-mirror r2=https://… --freshness-mirror ghpages=https://…\n",
			freshness.MinMirrors)
		return 2
	}
	mirrorSet, err := parseFreshnessMirrors(*freshnessMirrors)
	if err != nil {
		fmt.Fprintf(stderr, "bind-and-sign: %v\n", err)
		return 2
	}
	warnSharedDomains(stderr, "bind-and-sign", mirrorSet)
	// Non-blocking, but said out loud: a pack with no revocation
	// endpoint cannot ever be revoked, and the recipient-side
	// machinery that would act on one selects on this field being
	// non-empty.
	if *revocationURL == "" {
		fmt.Fprintln(stderr, "bind-and-sign: warning: no --revocation-url; recipients of this pack "+
			"will never poll a revocation list and a leaked pack cannot be withdrawn")
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
		Freshness:            mirrorSet,
		RevocationURL:        *revocationURL,
		RevocationPubHex:     *revocationPubHex,
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
		"freshness_mirrors": mirrorSet.Len(),
		"revocation_url":    *revocationURL,
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
	// Step 7: what this relay's in-box mgmt binary can actually do.
	// PRESENCE of the flag means "probed" — even with an empty value,
	// which is the honest way to say "probed, and it can do neither".
	// Absence means unprobed, and the emitted Action says so rather
	// than claiming a one-tap rotation that may not exist. This verb
	// stays offline (Position B), so the probe belongs to the caller:
	// `daal-deploy rotate-tls`/`rotate-credentials` do it themselves,
	// and the wizard gets it from mgmt.CapabilitiesWithFW.
	relayCaps := fs.String("relay-capabilities", "",
		"comma list of verbs this relay advertises (rotate-credentials,rotate-tls,bind-address); "+
			"passing the flag at all means 'probed', omitting it means 'unknown'")
	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	caps := rotation.RelayCapabilities{}
	fs.Visit(func(f *flag.Flag) {
		if f.Name != "relay-capabilities" {
			return
		}
		caps.Known = true
		for _, v := range splitCSV(*relayCaps) {
			switch strings.TrimSpace(v) {
			case "rotate-credentials":
				caps.RotateCredentialsInPlace = true
			case "rotate-tls":
				caps.RotateTLSInPlace = true
			case mgmt.CapBindAddress:
				// L3's rung depends on this one: a relay that cannot
				// bind an address cannot be swapped onto one.
				caps.BindAddress = true
			}
		}
	})
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
			RelayCapabilities:       caps,
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
		recommendation = rotation.FromExplanationWithCapabilities(exp, rec, caps)
	}

	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(recommendation); err != nil {
		fmt.Fprintf(stderr, "marshal: %v\n", err)
		return 1
	}
	return 0
}

// warnSharedDomains says out loud when two "distinct providers" share a
// registrable domain.
//
// The distinctness the type enforces is label + host, and neither is a
// failure domain. Two subdomains of one zone is one registration, one
// account and one takedown — and every honesty surface downstream (the
// panel's provider count, the MIN_MIRRORS gate, the recipient's
// Providers) would report it as redundancy. This is not a refusal
// because the configuration can be legitimate; it is the one place the
// operator is told what they actually bought.
func warnSharedDomains(stderr io.Writer, verb string, set *freshness.MirrorSet) {
	for _, group := range set.SharedDomains() {
		labels := make([]string, 0, len(group))
		for _, m := range group {
			labels = append(labels, fmt.Sprintf("%s=%s", m.Provider, m.URL))
		}
		fmt.Fprintf(stderr, "%s: warning: these mirrors share one domain and will very likely fail together, "+
			"so they count as ONE provider however they are labelled: %s\n", verb, strings.Join(labels, ", "))
	}
}

// parseFreshnessMirrors turns repeated `provider=https://url`
// flag values into a validated MirrorSet. An empty list yields a
// nil set (a pack with no freshness path, which is still a legal
// pack — it just cannot be healed remotely).
//
// The provider label is split on the FIRST '=' only: the URL may
// itself contain one in a query string.
func parseFreshnessMirrors(pairs []string) (*freshness.MirrorSet, error) {
	if len(pairs) == 0 {
		return nil, nil
	}
	mirrors := make([]freshness.Mirror, 0, len(pairs))
	for _, p := range pairs {
		name, rawURL, ok := strings.Cut(p, "=")
		if !ok || name == "" || rawURL == "" {
			return nil, fmt.Errorf("--freshness-mirror %q: want provider=https://url", p)
		}
		mirrors = append(mirrors, freshness.Mirror{
			Provider: freshness.Provider(strings.ToLower(strings.TrimSpace(name))),
			URL:      strings.TrimSpace(rawURL),
		})
	}
	set, err := freshness.NewMirrorSet(mirrors)
	if err != nil {
		return nil, fmt.Errorf("--freshness-mirror: %w", err)
	}
	return set, nil
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
