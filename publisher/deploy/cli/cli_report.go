// Network-test reports (specs/field-probe-v2.md, specs/sealed-report-v1.md):
//
//	daal-deploy report-keygen --out <key file>
//	    makes the publisher's report key: the private half (64 hex, mode
//	    0600) goes to --out, the `daal1…` report address is printed. The
//	    address is what the Test pack carries as family_specific_config
//	    ._report_to on the Test relay's routes; the app seals every
//	    network-test result to it.
//
//	daal-deploy report-open --in <net-xxxxxxxx.dat> [--key <key file>] [--findings]
//	    decrypts one sealed report (the key from --key, or 64 hex on
//	    stdin), validates it strictly against schema v2 and prints it as
//	    JSON — or, with --findings, one line per finding.
//
// A report is UNTRUSTED INPUT: age does not say who made it, anyone who
// has the report address can make one that opens. The opener refuses
// anything outside the schema and never interprets free text.
package cli

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"daal/bundle-go/envelope"
	"daal/bundle-go/fieldreport"
)

func runReportKeygen(_ context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("report-keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	outPath := fs.String("out", "", "file to write the report private key to (64 hex, mode 0600); must not exist. "+
		"\"-\" prints it in the JSON instead (\"private_key_hex\"), for the app, which keeps it in its own key store")
	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if err := requireAll(stderr, map[string]string{"--out": *outPath}); err != nil {
		return 2
	}
	pub, priv, err := envelope.NewReportKey()
	if err != nil {
		fmt.Fprintf(stderr, "keygen: %v\n", err)
		return 1
	}
	defer func() {
		for i := range priv {
			priv[i] = 0
		}
	}()
	if *outPath == "-" {
		// The app's path: the key never touches a file. Stdout is a
		// pipe to the parent, which seals it into device custody.
		privHex := []byte(hex.EncodeToString(priv[:]))
		defer zeroBytes(privHex)
		if err := json.NewEncoder(stdout).Encode(map[string]any{
			"report_to":       fieldreport.EncodeAddress(pub),
			"private_key_hex": string(privHex),
		}); err != nil {
			return 1
		}
		return 0
	}
	f, err := os.OpenFile(*outPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		fmt.Fprintf(stderr, "write key: %v\n", err)
		return 1
	}
	if _, err := f.WriteString(hex.EncodeToString(priv[:]) + "\n"); err != nil {
		_ = f.Close()
		fmt.Fprintf(stderr, "write key: %v\n", err)
		return 1
	}
	if err := f.Close(); err != nil {
		fmt.Fprintf(stderr, "write key: %v\n", err)
		return 1
	}
	if err := json.NewEncoder(stdout).Encode(map[string]any{
		"report_to": fieldreport.EncodeAddress(pub),
		"key_path":  *outPath,
	}); err != nil {
		return 1
	}
	return 0
}

func runReportOpen(_ context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("report-open", flag.ContinueOnError)
	fs.SetOutput(stderr)
	inPath := fs.String("in", "", "sealed report file (net-xxxxxxxx.dat)")
	keyPath := fs.String("key", "", "report private key file (64 hex); stdin when empty")
	findings := fs.Bool("findings", false, "print one line per finding instead of the JSON")
	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if err := requireAll(stderr, map[string]string{"--in": *inPath}); err != nil {
		return 2
	}
	var keyBuf []byte
	var err error
	if *keyPath != "" {
		keyBuf, err = os.ReadFile(*keyPath)
	} else {
		keyBuf, err = io.ReadAll(io.LimitReader(stdin, 256))
	}
	if err != nil {
		fmt.Fprintf(stderr, "read key: %v\n", err)
		return 1
	}
	defer zeroBytes(keyBuf)
	privHex := trimAscii(string(keyBuf))
	if len(privHex) != 64 {
		fmt.Fprintf(stderr, "the key must be 64 hex chars (got %d)\n", len(privHex))
		return 2
	}
	raw, err := hex.DecodeString(privHex)
	if err != nil {
		fmt.Fprintf(stderr, "decode key: %v\n", err)
		return 2
	}
	var priv [32]byte
	copy(priv[:], raw)
	zeroBytes(raw)
	defer func() {
		for i := range priv {
			priv[i] = 0
		}
	}()
	sealed, err := os.ReadFile(*inPath)
	if err != nil {
		fmt.Fprintf(stderr, "read report: %v\n", err)
		return 1
	}
	if !envelope.SniffReportMagic(sealed) {
		fmt.Fprintln(stderr, "not a sealed network-test report (bad magic)")
		return 1
	}
	r, err := fieldreport.Open(sealed, priv)
	if err != nil {
		fmt.Fprintf(stderr, "open: %v\n", err)
		return 1
	}
	if *findings {
		fmt.Fprintf(stdout, "report %s  %s  %s/%s  label=%s  complete=%t\n",
			r.ReportID, r.GeneratedHourBucket, r.Platform, r.Net.Kind, r.NetworkLabel, r.Run.Complete)
		for _, f := range r.Findings {
			q := f.Question
			if f.Variant != "" {
				q += "[" + f.Variant + "]"
			}
			fmt.Fprintf(stdout, "  %-40s %-8s %s\n", q, f.Answer, strings.Join(f.Basis, ","))
		}
		return 0
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return 1
	}
	return 0
}
