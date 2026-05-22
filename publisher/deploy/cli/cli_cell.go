package cli

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	bundle "daal/bundle-go/bundle"
	"daal/publisher/cell"
)

// FRP-11 cell subcommands. The CLI surfaces:
//
//	cell-create      Generate fresh admin keypair + emit JSON.
//	cell-invite      Build a .cell-join invite for a member publisher.
//	cell-aggregate   Aggregate member RelayPacks into a cell .sbp.
//	cell-publish     Publish cell directory + membership/delegation.
//	cell-verify      Verify a cell .sbp recipient-side.
//	cell-status      Print cell membership + delegation status.
//
// Locked answers from the FRP-11 spec:
//   #1 fresh per-admin Ed25519 keypair (cell-create generates one);
//   #2 cell-admin signing is desktop-only (cmd/daal-deploy is
//      Helper-side desktop; Android has cell-join only).
//
// FRP-11 invariant 31: M-of-N independent Ed25519 (no threshold).
// FRP-11 invariant 33: this CLI imports daal/publisher/cell and
// daal/bundle-go; not daal/core (which would loop the dependency
// the wrong way for cmd/daal-deploy).

// cellAdminKeyJSON is the on-disk persisted shape for a single
// cell admin keypair the wizard / CLI emits at cell-create. The
// private key bytes live ONLY in this file (operator persists to
// the wizard's encrypted keystore at FRP-11 commit 8); the public
// key is what gets baked into the membership doc.
type cellAdminKeyJSON struct {
	CellID      string `json:"cell_id"`
	AdminIdx    int    `json:"admin_idx"`
	PubB64      string `json:"pub_b64"`
	PrivB64     string `json:"priv_b64"`
	GeneratedAt string `json:"generated_at"`
}

// cellInviteJSON is the .cell-join envelope shape per supplement
// §16.4 — small signed file (~1 KB) the operator pastes into the
// recipient wizard. Carries the membership doc, current directory
// URL hint, and an optional trust-label suggestion. Per FRP-11
// locked answer #4 the recipient may override the trust label
// locally; the hint is advisory.
type cellInviteJSON struct {
	CellID              string                   `json:"cell_id"`
	MembershipDoc       bundle.CellMembershipDoc `json:"membership_doc"`
	CurrentDirectoryURL string                   `json:"current_directory_url"`
	TrustLabelHint      string                   `json:"trust_label_hint"`
}

//	runCellCreate: daal-deploy cell-create --cell-id ... --admin-idx N \
//	  [-o admin-key.json]
//
// Generates a FRESH Ed25519 admin keypair (FRP-11 locked answer #1)
// and emits JSON containing both halves to --out / stdout. The
// operator persists the JSON to the wizard's encrypted keystore.
func runCellCreate(_ context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cell-create", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cellID := fs.String("cell-id", "", "cell identifier (non-empty)")
	adminIdx := fs.Int("admin-idx", 0, "this admin's index in the membership doc admin_pubkeys[]")
	outFile := fs.String("out", "", "write to file instead of stdout")
	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if *cellID == "" {
		fmt.Fprintln(stderr, "cell-create: --cell-id required")
		return 2
	}
	if *adminIdx < 0 || *adminIdx >= bundle.MaxCellAdminN {
		fmt.Fprintf(stderr, "cell-create: --admin-idx must be in [0,%d)\n", bundle.MaxCellAdminN)
		return 2
	}
	kp, err := cell.NewAdminKeypair()
	if err != nil {
		fmt.Fprintf(stderr, "cell-create: keygen: %v\n", err)
		return 1
	}
	out := cellAdminKeyJSON{
		CellID:      *cellID,
		AdminIdx:    *adminIdx,
		PubB64:      kp.PubB64(),
		PrivB64:     base64.RawStdEncoding.EncodeToString(kp.Priv),
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}
	bytes, _ := json.MarshalIndent(out, "", "  ")
	bytes = append(bytes, '\n')
	if *outFile != "" {
		if err := os.WriteFile(*outFile, bytes, 0o600); err != nil {
			fmt.Fprintf(stderr, "cell-create: write: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "wrote admin keypair to %s\n", *outFile)
		return 0
	}
	stdout.Write(bytes)
	return 0
}

//	runCellInvite: daal-deploy cell-invite --membership-file member.json \
//	  --directory-url URL [--trust-label-hint family]
//
// Reads a finalised membership-doc JSON file (admin-quorum-signed)
// and emits a .cell-join envelope on stdout the operator can share
// with a prospective member. The recipient verifies the embedded
// membership doc's quorum before joining.
func runCellInvite(_ context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cell-invite", flag.ContinueOnError)
	fs.SetOutput(stderr)
	memFile := fs.String("membership-file", "", "path to admin-quorum-signed membership doc JSON")
	dirURL := fs.String("directory-url", "", "current cell directory URL")
	labelHint := fs.String("trust-label-hint", "", "advisory trust label for recipient (empty for none)")
	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if *memFile == "" || *dirURL == "" {
		fmt.Fprintln(stderr, "cell-invite: --membership-file + --directory-url required")
		return 2
	}
	memBytes, err := os.ReadFile(*memFile)
	if err != nil {
		fmt.Fprintf(stderr, "cell-invite: read membership: %v\n", err)
		return 1
	}
	var memb bundle.CellMembershipDoc
	if err := json.Unmarshal(memBytes, &memb); err != nil {
		fmt.Fprintf(stderr, "cell-invite: parse membership: %v\n", err)
		return 1
	}
	if err := bundle.VerifyCellMembershipQuorum(memb); err != nil {
		fmt.Fprintf(stderr, "cell-invite: refuses to wrap a non-quorum membership doc: %v\n", err)
		return 1
	}
	if !strings.HasPrefix(*dirURL, "https://") {
		fmt.Fprintln(stderr, "cell-invite: --directory-url must be HTTPS")
		return 2
	}
	out := cellInviteJSON{
		CellID:              memb.CellID,
		MembershipDoc:       memb,
		CurrentDirectoryURL: *dirURL,
		TrustLabelHint:      *labelHint,
	}
	bytes, _ := json.MarshalIndent(out, "", "  ")
	bytes = append(bytes, '\n')
	stdout.Write(bytes)
	return 0
}

// runCellSign: daal-deploy cell-sign --doc-file ... --priv-file ... --idx N
//
//	[--type membership|delegation]
//
// Produces one admin signature over the canonical bytes of the
// supplied doc. Emits a CellAdminSignature JSON. Used by operator
// CLI workflows to collect M-of-N signatures one admin at a time.
// The long-lived admin private key is read from a mode-0600 file,
// never argv, so it does not leak through shell history or the
// process table.
func runCellSign(_ context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cell-sign", flag.ContinueOnError)
	fs.SetOutput(stderr)
	docFile := fs.String("doc-file", "", "path to membership or delegation doc JSON")
	privFile := fs.String("priv-file", "", "mode-0600 file containing base64-rawstd Ed25519 private key (64 bytes)")
	idx := fs.Int("idx", 0, "this admin's index in admin_pubkeys[]")
	docType := fs.String("type", "membership", "doc type: membership | delegation")
	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if *docFile == "" || *privFile == "" {
		fmt.Fprintln(stderr, "cell-sign: --doc-file + --priv-file required")
		return 2
	}
	priv, err := readCellAdminPrivateKeyFile(*privFile)
	if err != nil {
		fmt.Fprintf(stderr, "cell-sign: %v\n", err)
		return 2
	}
	docBytes, err := os.ReadFile(*docFile)
	if err != nil {
		fmt.Fprintf(stderr, "cell-sign: read doc: %v\n", err)
		return 1
	}
	var sig bundle.CellAdminSignature
	switch *docType {
	case "membership":
		var d bundle.CellMembershipDoc
		if err := json.Unmarshal(docBytes, &d); err != nil {
			fmt.Fprintf(stderr, "cell-sign: parse membership: %v\n", err)
			return 1
		}
		sig, err = bundle.SignCellMembership(d, *idx, ed25519.PrivateKey(priv))
	case "delegation":
		var d bundle.CellDelegationDoc
		if err := json.Unmarshal(docBytes, &d); err != nil {
			fmt.Fprintf(stderr, "cell-sign: parse delegation: %v\n", err)
			return 1
		}
		sig, err = bundle.SignCellDelegation(d, *idx, ed25519.PrivateKey(priv))
	default:
		fmt.Fprintf(stderr, "cell-sign: unknown --type %q\n", *docType)
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "cell-sign: %v\n", err)
		return 1
	}
	bytes, _ := json.MarshalIndent(sig, "", "  ")
	bytes = append(bytes, '\n')
	stdout.Write(bytes)
	return 0
}

func readCellAdminPrivateKeyFile(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("read --priv-file: %w", err)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("--priv-file must be a regular file")
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("--priv-file must be mode 0600 or stricter")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read --priv-file: %w", err)
	}
	priv, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("--priv-file must base64-rawstd-decode to 64 bytes")
	}
	return priv, nil
}

// runCellVerify: daal-deploy cell-verify --membership-file ... --delegation-file ...
//
// Recipient-side smoke test: parses both docs and runs the M-of-N
// quorum + cell_id matching checks. Useful for operators sanity-
// checking a cell config before publishing the .sbp aggregate.
func runCellVerify(_ context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cell-verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	memFile := fs.String("membership-file", "", "path to membership doc JSON")
	delFile := fs.String("delegation-file", "", "path to delegation doc JSON")
	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if *memFile == "" || *delFile == "" {
		fmt.Fprintln(stderr, "cell-verify: --membership-file + --delegation-file required")
		return 2
	}
	mb, err := os.ReadFile(*memFile)
	if err != nil {
		fmt.Fprintf(stderr, "cell-verify: read membership: %v\n", err)
		return 1
	}
	db, err := os.ReadFile(*delFile)
	if err != nil {
		fmt.Fprintf(stderr, "cell-verify: read delegation: %v\n", err)
		return 1
	}
	var memb bundle.CellMembershipDoc
	var deleg bundle.CellDelegationDoc
	if err := json.Unmarshal(mb, &memb); err != nil {
		fmt.Fprintf(stderr, "cell-verify: parse membership: %v\n", err)
		return 1
	}
	if err := json.Unmarshal(db, &deleg); err != nil {
		fmt.Fprintf(stderr, "cell-verify: parse delegation: %v\n", err)
		return 1
	}
	if err := bundle.VerifyCellMembershipQuorum(memb); err != nil {
		fmt.Fprintf(stderr, "cell-verify: membership quorum invalid: %v\n", err)
		return 1
	}
	if err := bundle.VerifyCellDelegationQuorum(memb, deleg); err != nil {
		fmt.Fprintf(stderr, "cell-verify: delegation quorum invalid: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "cell %s OK: %d-of-%d admin quorum verified for membership and delegation\n",
		memb.CellID, memb.QuorumM, len(memb.AdminPubkeys))
	return 0
}

// runCellStatus: print summary of a cell's membership + delegation.
func runCellStatus(_ context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cell-status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	memFile := fs.String("membership-file", "", "path to membership doc JSON")
	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if *memFile == "" {
		fmt.Fprintln(stderr, "cell-status: --membership-file required")
		return 2
	}
	mb, err := os.ReadFile(*memFile)
	if err != nil {
		fmt.Fprintf(stderr, "cell-status: read: %v\n", err)
		return 1
	}
	var memb bundle.CellMembershipDoc
	if err := json.Unmarshal(mb, &memb); err != nil {
		fmt.Fprintf(stderr, "cell-status: parse: %v\n", err)
		return 1
	}
	out := struct {
		CellID         string `json:"cell_id"`
		AdminCount     int    `json:"admin_count"`
		QuorumM        int    `json:"quorum_m"`
		MemberCount    int    `json:"member_count"`
		ValidUntilUnix int64  `json:"valid_until_unix"`
		Quorate        bool   `json:"quorate"`
	}{
		CellID:         memb.CellID,
		AdminCount:     len(memb.AdminPubkeys),
		QuorumM:        memb.QuorumM,
		MemberCount:    len(memb.Members),
		ValidUntilUnix: memb.RuleSet.ValidUntilUnix,
		Quorate:        bundle.VerifyCellMembershipQuorum(memb) == nil,
	}
	bytes, _ := json.MarshalIndent(out, "", "  ")
	bytes = append(bytes, '\n')
	stdout.Write(bytes)
	return 0
}
