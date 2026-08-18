// FRP-14: daal-deploy users-{provision,revoke,list} sub-commands.
//
// These shells invoke the V2 mgmt-plane /users/* routes through
// publisher/deploy/mgmt and emit JSON on stdout. The wizard's Rust
// `cli_bridge` shells out to them with stdout-JSON capture.
//
// All three accept --record-file (OperatorRecord JSON) and
// --priv-key (publisher Ed25519 private key path or "-"). All three
// open an ephemeral cloud-firewall window via the provider adapter
// for the duration of the call and remove it on exit.
package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"daal/publisher/deploy/mgmt"
)

func runUsersProvision(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("users-provision", flag.ContinueOnError)
	fs.SetOutput(stderr)
	recordFile := fs.String("record-file", "", "OperatorRecord JSON path")
	privKeyFlag := fs.String("priv-key", "", "publisher Ed25519 private key (path | '-' for stdin)")
	helperIP := fs.String("helper-ip", "", "Helper's outbound public IP (firewall allowlist)")
	tokenFile := fs.String("token-file", "", "cloud-provider API token file")
	name := fs.String("name", "", "recipient name (r<digits>)")
	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if err := requireAll(stderr, map[string]string{
		"--record-file": *recordFile,
		"--priv-key":    *privKeyFlag,
		"--helper-ip":   *helperIP,
		"--name":        *name,
	}); err != nil {
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
	prov, err := buildProvider(rec.Provider, *tokenFile, false)
	if err != nil {
		fmt.Fprintf(stderr, "build provider: %v\n", err)
		return 1
	}
	creds, err := mgmt.ProvisionUserWithFW(ctx, prov, rec, priv, *helperIP, *name)
	if err != nil {
		fmt.Fprintf(stderr, "users/provision: %v\n", err)
		return 1
	}
	// The early warning the capability tokens promised and nothing
	// delivered. A family this relay was provisioned to OFFER, whose
	// credential came back empty, is a route the operator is about to
	// discover missing at pack time — or, before the repair pass, a
	// route that killed the whole pack. Say it here, once, next to the
	// action that fixes it. STDERR: stdout is the creds JSON.
	if missing := mgmt.MissingFamilyCredentials(rec, creds); len(missing) > 0 {
		for _, f := range missing {
			fmt.Fprintf(stderr,
				"warning: this relay offers %q but reported no credential for it — %s\n",
				f, mgmt.StaleArtifactHint)
		}
	}
	if err := json.NewEncoder(stdout).Encode(creds); err != nil {
		fmt.Fprintf(stderr, "encode: %v\n", err)
		return 1
	}
	return 0
}

func runUsersRevoke(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("users-revoke", flag.ContinueOnError)
	fs.SetOutput(stderr)
	recordFile := fs.String("record-file", "", "OperatorRecord JSON path")
	privKeyFlag := fs.String("priv-key", "", "publisher Ed25519 private key (path | '-' for stdin)")
	helperIP := fs.String("helper-ip", "", "Helper's outbound public IP")
	tokenFile := fs.String("token-file", "", "cloud-provider API token file")
	name := fs.String("name", "", "recipient name (r<digits>)")
	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if err := requireAll(stderr, map[string]string{
		"--record-file": *recordFile,
		"--priv-key":    *privKeyFlag,
		"--helper-ip":   *helperIP,
		"--name":        *name,
	}); err != nil {
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
	prov, err := buildProvider(rec.Provider, *tokenFile, false)
	if err != nil {
		fmt.Fprintf(stderr, "build provider: %v\n", err)
		return 1
	}
	resp, err := mgmt.RevokeUserWithFW(ctx, prov, rec, priv, *helperIP, *name)
	if err != nil {
		fmt.Fprintf(stderr, "users/revoke: %v\n", err)
		return 1
	}
	if err := json.NewEncoder(stdout).Encode(resp); err != nil {
		fmt.Fprintf(stderr, "encode: %v\n", err)
		return 1
	}
	return 0
}

func runUsersList(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("users-list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	recordFile := fs.String("record-file", "", "OperatorRecord JSON path")
	privKeyFlag := fs.String("priv-key", "", "publisher Ed25519 private key (path | '-' for stdin)")
	helperIP := fs.String("helper-ip", "", "Helper's outbound public IP")
	tokenFile := fs.String("token-file", "", "cloud-provider API token file")
	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if err := requireAll(stderr, map[string]string{
		"--record-file": *recordFile,
		"--priv-key":    *privKeyFlag,
		"--helper-ip":   *helperIP,
	}); err != nil {
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
	prov, err := buildProvider(rec.Provider, *tokenFile, false)
	if err != nil {
		fmt.Fprintf(stderr, "build provider: %v\n", err)
		return 1
	}
	users, err := mgmt.ListUsersWithFW(ctx, prov, rec, priv, *helperIP)
	if err != nil {
		fmt.Fprintf(stderr, "users/list: %v\n", err)
		return 1
	}
	if err := json.NewEncoder(stdout).Encode(map[string]any{"users": users}); err != nil {
		fmt.Fprintf(stderr, "encode: %v\n", err)
		return 1
	}
	return 0
}

// Silence unused-import warning when os is not directly used by
// this file but is needed for the os.File-based readers.
var _ = os.Stdin
