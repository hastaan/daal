// Step 7: daal-deploy rotate-credentials / rotate-tls — the two
// in-place rotation verbs.
//
// These are the L1 and L2 rungs of the supplement §14.1 ladder made
// executable. Before them the ladder's cheapest two rungs were
// reachable only by `reprovision`, i.e. by destroying the server and
// building a new one: ~3 minutes, a new IP, a new mgmt TLS pin, and
// every recipient needing a fresh pack — to change a password.
//
// Both verbs follow the users-* conventions exactly (--record-file,
// --priv-key, --helper-ip, --token-file; JSON on stdout for the Rust
// bridge to capture) and both go through mgmt's WithFW orchestration,
// so the cloud firewall opens for the call and closes after it on every
// path.
//
// EXIT CODES
//
//	0  rotated
//	1  failed
//	2  bad flags
//	3  this relay's software predates the operation (see
//	   mgmt.ErrCapabilityUnsupported). Distinct on purpose: it is not a
//	   transient failure and retrying will never fix it, so the wizard
//	   must render "reprovision or re-release", not "try again".
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"daal/publisher/deploy/mgmt"
)

// exitCapabilityUnsupported is returned when the relay cannot do this
// in place. See the package comment.
const exitCapabilityUnsupported = 3

// rotateExit maps a mgmt error onto the exit code, so both verbs report
// "too old" identically.
func rotateExit(stderr io.Writer, label string, err error) int {
	fmt.Fprintf(stderr, "%s: %v\n", label, err)
	if errors.Is(err, mgmt.ErrCapabilityUnsupported) {
		return exitCapabilityUnsupported
	}
	return 1
}

// runRotateCredentials rotates ONE recipient's per-user credentials
// across every inbound on the relay — a targeted revocation.
//
// --name is required and there is no "rotate all" spelling. Omitting it
// is an error at three layers (here, in mgmt.RotateCredentialsWithFW,
// and on the box), because on a pre-Step-7 box an empty name is not a
// no-op: that box ignores the body and rotates the box-wide REALITY
// keypair, killing every pack in the field.
func runRotateCredentials(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rotate-credentials", flag.ContinueOnError)
	fs.SetOutput(stderr)
	recordFile := fs.String("record-file", "", "OperatorRecord JSON path")
	privKeyFlag := fs.String("priv-key", "", "publisher Ed25519 private key (path | '-' for stdin)")
	helperIP := fs.String("helper-ip", "", "Helper's outbound public IP (firewall allowlist)")
	tokenFile := fs.String("token-file", "", "cloud-provider API token file")
	name := fs.String("name", "", "recipient to rotate (r<digits>) — required; there is no rotate-all")
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
	creds, err := mgmt.RotateCredentialsWithFW(ctx, prov, rec, priv, *helperIP, *name)
	if err != nil {
		return rotateExit(stderr, "rotate-credentials", err)
	}
	// Same shape as users-provision output, so the pack minter
	// (users-pack-sbp) consumes a rotation exactly as it consumes a
	// provision. This is the ONLY time the new secrets exist outside the
	// box: the caller must persist them before doing anything else.
	body, err := json.Marshal(creds)
	if err != nil {
		fmt.Fprintf(stderr, "encode: %v\n", err)
		return 1
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		fmt.Fprintf(stderr, "encode: %v\n", err)
		return 1
	}
	// Always present, possibly empty, rendered verbatim by the wizard.
	// The box's own warnings come first: it saw the config, we did not.
	warnings := append([]string{}, creds.Warnings...)
	// A revocation that reached three of four inbounds leaves the leaked
	// credential live on the fourth, and a 200 looks identical either
	// way. If the relay would not name what it rewrote, nothing verified
	// that the revocation was complete — and that has to be said, not
	// inferred from an absent field.
	if len(creds.UpdatedInbounds) == 0 {
		warnings = append(warnings, "relay did not report which inbounds it rewrote; the revocation's completeness is unverified")
	}
	// A relay that does not echo its own connection material is not an
	// error — it is an older relay — but the pack mint will then fall
	// back to the OperatorRecord, which records what was REQUESTED
	// rather than what the box is actually serving. Say so; a
	// mint-from-stale-record failure is invisible until recipients
	// cannot connect.
	if creds.CoverSNI == "" {
		warnings = append(warnings, "relay did not echo its cover host; the pack mint will fall back to the OperatorRecord")
	}
	if creds.RealityPublicKey == "" {
		warnings = append(warnings, "relay did not echo its REALITY public key; the pack mint will fall back to the OperatorRecord")
	}
	out["warnings"] = warnings
	if err := json.NewEncoder(stdout).Encode(out); err != nil {
		fmt.Fprintf(stderr, "encode: %v\n", err)
		return 1
	}
	return 0
}

// runRotateTLS rotates the relay's cover SNI / TLS parameters in place.
// It touches no REALITY keypair and no recipient's credentials.
//
// --new-sni is OPTIONAL and omitting it is the normal case: the
// publisher picks a fresh admissible host from the relay's zone,
// excluding the one it is advertising today. Passing the flag pins a
// specific host (the pool rule still validates it).
//
// The OperatorRecord is REWRITTEN on success. That is not a
// convenience: the record's CoverSNI is what the pack minter reads, so
// a rotation that changed the box but not the record would mint packs
// for the burned host, and the failure would show up only as recipients
// who cannot connect. --record-out redirects the write; the path
// actually written is echoed in the JSON.
func runRotateTLS(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rotate-tls", flag.ContinueOnError)
	fs.SetOutput(stderr)
	recordFile := fs.String("record-file", "", "OperatorRecord JSON path")
	privKeyFlag := fs.String("priv-key", "", "publisher Ed25519 private key (path | '-' for stdin)")
	helperIP := fs.String("helper-ip", "", "Helper's outbound public IP (firewall allowlist)")
	tokenFile := fs.String("token-file", "", "cloud-provider API token file")
	newSNI := fs.String("new-sni", "", "pin a specific cover host; empty picks a fresh pool host, excluding the current one")
	newWSPath := fs.String("new-ws-path", "", "new WebSocket path (optional)")
	recordOut := fs.String("record-out", "", "where to write the updated OperatorRecord (default: --record-file, in place)")
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
	previousCoverSNI := rec.CoverSNI
	resp, rotErr := mgmt.RotateTLSWithFW(ctx, prov, rec, priv, *helperIP, mgmt.TLSProfile{
		NewSNI:    *newSNI,
		NewWSPath: *newWSPath,
	})
	if rotErr != nil && resp == nil {
		// Nothing was applied: leave the record exactly as it was.
		return rotateExit(stderr, "rotate-tls", rotErr)
	}

	// Something was applied. Persist the record FIRST — an operator who
	// loses the new cover host has a relay they can no longer mint packs
	// for — then report, then propagate the error if there was one.
	outPath := *recordOut
	if outPath == "" {
		outPath = *recordFile
	}
	writeRC := emitRecord(rec, outPath, stdout, stderr)

	// `warnings` is always present, possibly empty, and rendered
	// verbatim by the wizard — same contract as the decommission report.
	// The standing one is the honest tail of this operation: the relay
	// has moved and every already-distributed pack still pins the old
	// cover host. Step 8 (freshness delivery) is what will make that
	// redistribution automatic; until it lands it is manual, and the
	// operator must not learn it from silence.
	warnings := []string{
		"relay now advertises " + rec.CoverSNI + "; every recipient needs a re-minted pack before it will connect again",
	}
	if resp.AppliedSNI == "" {
		warnings = append(warnings,
			"relay did not echo the cover host it applied — the value recorded is what was requested, not what was verified")
	}
	if rotErr != nil {
		warnings = append(warnings, rotErr.Error())
	}
	// Follow the box, not the request. The shared ws path belongs to the
	// WHOLE relay (one ws-in inbound, every recipient dialling the same
	// path), and the box is the only place a rotated one exists: the
	// contract's `POST /rotate-tls {}` rotates the ws path and nothing
	// else, and the box then echoes applied_ws_path. Reporting the
	// REQUESTED value — as this used to, on the since-falsified belief
	// that the box echoes none — means a moved path is recorded nowhere,
	// and ws is the tier a blocked relay is most likely to be recovered
	// on. Fall back to what was asked for only when nothing is echoed.
	wsPath := resp.AppliedWSPath
	if wsPath == "" {
		wsPath = *newWSPath
	}
	out := map[string]any{
		"applied_at_unix": resp.AppliedAtUnix,
		// cover_sni / previous_cover_sni are the pair the wizard reads;
		// applied_* are the box's raw echo, kept for diagnosis.
		"cover_sni":          rec.CoverSNI,
		"previous_cover_sni": previousCoverSNI,
		"ws_path":            wsPath,
		"applied_sni":        resp.AppliedSNI,
		"applied_handshake":  resp.AppliedHandshake,
		"record_written":     outPath,
		"warnings":           warnings,
	}
	if err := json.NewEncoder(stdout).Encode(out); err != nil {
		fmt.Fprintf(stderr, "encode: %v\n", err)
		return 1
	}
	if rotErr != nil {
		return rotateExit(stderr, "rotate-tls", rotErr)
	}
	if writeRC != 0 {
		return writeRC
	}
	fmt.Fprintf(stderr, "rotate-tls: %s\n", warnings[0])
	return 0
}

var _ = os.Stdin
