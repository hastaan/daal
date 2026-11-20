package cli

// Add-on 3, update channel through Google (docs/optional-addons-plan.md
// §3, items G1, G2; specs/optional-addons-v1.md §5).
//
//	appsscript-script  --write-key-file F --path-token T
//	                   Code.gs and appsscript.json with the write key and
//	                   path token in them: {"code_gs","manifest_json"}.
//	appsscript-deploy  --write-key-file F --path-token T [--script-id ID]
//	                   [--title T] [--progress-json]
//	                   Path A. stdin is one JSON object: {"access_token"}
//	                   (Android, from Play services) or the desktop
//	                   sign-in's {"code","code_verifier","redirect_uri",
//	                   "client_id","client_secret"}. Creates the project
//	                   (or, with --script-id, resumes into one an earlier
//	                   attempt made), uploads the content, makes a version
//	                   and a web-app deployment, then revokes the token.
//	                   Prints {"script_id","deployment_id","version","url"}.
//	appsscript-check   --url U [--write-key-file F (--freshness-file D
//	                   [--pack-file P] [--standby-key-file S] | --seq N)]
//	                   [--expect-sha256 H]
//	                   With a write key: POST the container (the signed
//	                   document, the pack it names, a standby key; or the
//	                   empty container numbered --seq), then fetch it back
//	                   the way a recipient does. Without: fetch only and
//	                   compare with --expect-sha256. Prints a CheckResult;
//	                   exit 0 whenever the check ran, whatever it found.
//	appsscript-clear   --url U --write-key-file F --seq N
//	                   POST the empty container (removal) and fetch back.
//
// Secrets: the write key comes only from a file (64 hex characters),
// the access token or authorization code only on stdin; neither is ever
// printed, and the token is revoked and zeroed after the deploy.
//
// Publishing an update rides on publish-freshness as one more backend
// (appsscript.Backend, built by appsScriptFreshnessTarget below). The
// flags that select it live in cli.go, which this lane does not edit;
// until they are wired, the app publishes to the channel with
// appsscript-check right after publish-freshness, which sends the same
// bytes.

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"daal/publisher/deploy/freshness"
	"daal/publisher/deploy/freshness/backends/appsscript"
)

// Where the verbs reach Google. Tests point both at a fake.
var (
	appsScriptNetwork   = appsscript.Network{}
	appsScriptEndpoints = appsscript.DefaultEndpoints
)

// readWriteKeyFile reads a write key file: 64 hex characters.
func readWriteKeyFile(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read write-key-file: %w", err)
	}
	defer zeroBytes(raw)
	k, err := hex.DecodeString(string(bytes.TrimSpace(raw)))
	if err != nil || len(k) != appsscript.WriteKeySize {
		zeroBytes(k)
		return nil, errors.New("write-key-file must hold 64 hex characters (32 bytes)")
	}
	return k, nil
}

func printJSON(stdout, stderr io.Writer, verb string, v any) int {
	body, err := json.Marshal(v)
	if err != nil {
		fmt.Fprintf(stderr, "%s: marshal: %v\n", verb, err)
		return 1
	}
	fmt.Fprintln(stdout, string(body))
	return 0
}

func runAppsScriptScript(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	_ = ctx
	fs := flag.NewFlagSet("appsscript-script", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keyFile := fs.String("write-key-file", "", "file holding the write key (64 hex)")
	token := fs.String("path-token", "", "the k of the /exec URL (22 base64url characters)")
	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if err := requireAll(stderr, map[string]string{"--write-key-file": *keyFile, "--path-token": *token}); err != nil {
		return 2
	}
	key, err := readWriteKeyFile(*keyFile)
	if err != nil {
		fmt.Fprintf(stderr, "appsscript-script: %v\n", err)
		return 2
	}
	defer zeroBytes(key)
	code, manifest, err := appsscript.Script(key, *token)
	if err != nil {
		fmt.Fprintf(stderr, "appsscript-script: %v\n", err)
		return 2
	}
	return printJSON(stdout, stderr, "appsscript-script", map[string]string{"code_gs": code, "manifest_json": manifest})
}

// deployAuth is the stdin of appsscript-deploy.
type deployAuth struct {
	AccessToken string `json:"access_token"`
	appsscript.AuthCode
}

func runAppsScriptDeploy(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("appsscript-deploy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keyFile := fs.String("write-key-file", "", "file holding the write key (64 hex)")
	token := fs.String("path-token", "", "the k of the /exec URL")
	scriptID := fs.String("script-id", "", "resume into the project an earlier attempt created")
	title := fs.String("title", "Notes", "project title (shown in the publisher's Google Drive)")
	progress := fs.Bool("progress-json", false, "emit one JSON line per step on stderr")
	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if err := requireAll(stderr, map[string]string{"--write-key-file": *keyFile, "--path-token": *token}); err != nil {
		return 2
	}
	key, err := readWriteKeyFile(*keyFile)
	if err != nil {
		fmt.Fprintf(stderr, "appsscript-deploy: %v\n", err)
		return 2
	}
	defer zeroBytes(key)
	code, manifest, err := appsscript.Script(key, *token)
	if err != nil {
		fmt.Fprintf(stderr, "appsscript-deploy: %v\n", err)
		return 2
	}

	raw, err := io.ReadAll(io.LimitReader(stdin, 16<<10))
	defer zeroBytes(raw)
	if err != nil {
		fmt.Fprintln(stderr, "appsscript-deploy: could not read the sign-in from stdin")
		return 2
	}
	var auth deployAuth
	if err := json.Unmarshal(raw, &auth); err != nil {
		fmt.Fprintln(stderr, "appsscript-deploy: stdin is not the sign-in JSON")
		return 2
	}
	ep := appsScriptEndpoints()
	var access []byte
	if auth.AccessToken != "" {
		access = []byte(auth.AccessToken)
	} else {
		emitProgress(*progress, stderr, "signing_in", "exchanging the sign-in code", nil)
		access, err = ep.ExchangeCode(ctx, auth.AuthCode)
		if err != nil {
			return deployFailed(stderr, err)
		}
	}
	auth = deployAuth{}
	defer func() {
		// The token's life ends here, whatever happened: revoke, then
		// zero. Revocation is best effort; it expires within the hour.
		_ = ep.RevokeToken(context.Background(), access)
		zeroBytes(access)
	}()

	emitProgress(*progress, stderr, "deploying", "creating and deploying the script", nil)
	res, err := ep.Deploy(ctx, access, appsscript.DeployOpts{
		Title: *title, Code: code, Manifest: manifest, ScriptID: *scriptID,
	})
	if err != nil {
		return deployFailed(stderr, err)
	}
	url, err := appsscript.NormalizeExecURL(res.ExecURL, *token)
	if err != nil {
		fmt.Fprintf(stderr, "E_GOOGLE_PARTIAL: script_id=%s stage=deployment: %v\n", res.ScriptID, err)
		return 1
	}
	emitProgress(*progress, stderr, "deployed", "the script is deployed", nil)
	return printJSON(stdout, stderr, "appsscript-deploy", map[string]any{
		"script_id": res.ScriptID, "deployment_id": res.DeploymentID,
		"version": res.Version, "url": url,
	})
}

// deployFailed prints the first stderr line the app branches on.
func deployFailed(stderr io.Writer, err error) int {
	var ae *appsscript.APIError
	if !errors.As(err, &ae) {
		fmt.Fprintf(stderr, "E_GOOGLE_API: %v\n", err)
		return 1
	}
	switch {
	case ae.Reason == appsscript.APIReasonNotEnabled:
		fmt.Fprintf(stderr, "E_GOOGLE_API_NOT_ENABLED: turn on the Apps Script API at script.google.com/home/usersettings, then try again\n")
	case ae.ScriptID != "":
		fmt.Fprintf(stderr, "E_GOOGLE_PARTIAL: script_id=%s stage=%s: %s\n", ae.ScriptID, ae.Stage, ae.Error())
	case ae.Reason == appsscript.APIReasonUnauthorized:
		fmt.Fprintf(stderr, "E_GOOGLE_UNAUTHORIZED: %s\n", ae.Error())
	default:
		fmt.Fprintf(stderr, "E_GOOGLE_API: %s\n", ae.Error())
	}
	return 1
}

func runAppsScriptCheck(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("appsscript-check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	url := fs.String("url", "", "the mirror URL, ?k= included")
	keyFile := fs.String("write-key-file", "", "file holding the write key; absent: fetch only")
	docFile := fs.String("freshness-file", "", "the signed freshness document to send")
	packFile := fs.String("pack-file", "", "the signed credential-less pack the document names")
	standbyFile := fs.String("standby-key-file", "", "file holding a standby key to carry")
	seq := fs.Uint64("seq", 0, "update number for the empty container (no --freshness-file)")
	expect := fs.String("expect-sha256", "", "fetch only: the container's expected SHA-256")
	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if err := requireAll(stderr, map[string]string{"--url": *url}); err != nil {
		return 2
	}
	if *keyFile == "" {
		r := appsScriptNetwork.FetchAndCompare(ctx, *url, strings.ToLower(strings.TrimSpace(*expect)))
		return printJSON(stdout, stderr, "appsscript-check", r)
	}
	key, err := readWriteKeyFile(*keyFile)
	if err != nil {
		fmt.Fprintf(stderr, "appsscript-check: %v\n", err)
		return 2
	}
	defer zeroBytes(key)
	blob, n, packIncluded, err := checkContainer(*docFile, *packFile, *standbyFile, *seq)
	if err != nil {
		fmt.Fprintf(stderr, "appsscript-check: %v\n", err)
		return 2
	}
	r := appScriptSend(ctx, *url, key, n, blob)
	return printJSON(stdout, stderr, "appsscript-check", struct {
		appsscript.CheckResult
		PackIncluded bool `json:"pack_included"`
	}{r, packIncluded})
}

// checkContainer builds what appsscript-check sends.
func checkContainer(docFile, packFile, standbyFile string, seq uint64) (blob []byte, n uint64, packIncluded bool, err error) {
	if docFile == "" {
		if packFile != "" || standbyFile != "" {
			return nil, 0, false, errors.New("--pack-file and --standby-key-file need --freshness-file")
		}
		if seq == 0 {
			return nil, 0, false, errors.New("--seq is required without --freshness-file")
		}
		return appsscript.Empty(), seq, false, nil
	}
	doc, err := os.ReadFile(docFile)
	if err != nil {
		return nil, 0, false, fmt.Errorf("read freshness-file: %w", err)
	}
	var pack []byte
	if packFile != "" {
		if pack, err = os.ReadFile(packFile); err != nil {
			return nil, 0, false, fmt.Errorf("read pack-file: %w", err)
		}
	}
	standby := ""
	if standbyFile != "" {
		raw, err := os.ReadFile(standbyFile)
		if err != nil {
			return nil, 0, false, fmt.Errorf("read standby-key-file: %w", err)
		}
		standby = strings.TrimSpace(string(raw))
		zeroBytes(raw)
	}
	n, err = appsscript.DocSequence(doc)
	if err != nil {
		return nil, 0, false, err
	}
	blob, err = appsscript.Build(doc, pack, standby)
	if errors.Is(err, appsscript.ErrPackTooLarge) {
		// The pack does not fit: send the document alone, and
		// recipients fetch the pack from its own URL.
		blob, err = appsscript.Build(doc, nil, standby)
		return blob, n, false, err
	}
	return blob, n, len(pack) > 0 && err == nil, err
}

func appScriptSend(ctx context.Context, url string, key []byte, seq uint64, blob []byte) appsscript.CheckResult {
	return appsScriptNetwork.SendAndCheck(ctx, url, key, seq, blob)
}

func runAppsScriptClear(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("appsscript-clear", flag.ContinueOnError)
	fs.SetOutput(stderr)
	url := fs.String("url", "", "the mirror URL, ?k= included")
	keyFile := fs.String("write-key-file", "", "file holding the write key")
	seq := fs.Uint64("seq", 0, "update number, greater than any sent before")
	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if err := requireAll(stderr, map[string]string{"--url": *url, "--write-key-file": *keyFile}); err != nil {
		return 2
	}
	if *seq == 0 {
		fmt.Fprintln(stderr, "appsscript-clear: --seq is required")
		return 2
	}
	key, err := readWriteKeyFile(*keyFile)
	if err != nil {
		fmt.Fprintf(stderr, "appsscript-clear: %v\n", err)
		return 2
	}
	defer zeroBytes(key)
	return printJSON(stdout, stderr, "appsscript-clear", appScriptSend(ctx, *url, key, *seq, appsscript.Empty()))
}

// appsScriptFreshnessTarget is the publish-freshness backend for one
// channel, for when cli.go grows its flags (--appsscript-url,
// --appsscript-write-key-file, --appsscript-pack-file,
// --appsscript-standby-key-file). The returned wipe zeroes the key.
func appsScriptFreshnessTarget(url, writeKeyFile, packFile, standbyKeyFile string) (freshness.Target, func(), error) {
	key, err := readWriteKeyFile(writeKeyFile)
	if err != nil {
		return freshness.Target{}, func() {}, err
	}
	wipe := func() { zeroBytes(key) }
	var pack []byte
	if packFile != "" {
		if pack, err = os.ReadFile(packFile); err != nil {
			wipe()
			return freshness.Target{}, func() {}, fmt.Errorf("read appsscript pack file: %w", err)
		}
	}
	standby := ""
	if standbyKeyFile != "" {
		raw, err := os.ReadFile(standbyKeyFile)
		if err != nil {
			wipe()
			return freshness.Target{}, func() {}, fmt.Errorf("read appsscript standby key file: %w", err)
		}
		standby = strings.TrimSpace(string(raw))
		zeroBytes(raw)
	}
	be, err := appsscript.New(appsscript.Config{
		ExecURL: url, WriteKey: key, Pack: pack, StandbyKey: standby, Network: appsScriptNetwork,
	})
	if err != nil {
		wipe()
		return freshness.Target{}, func() {}, err
	}
	return freshness.Target{Provider: freshness.ProviderAppsScript, Backend: be}, wipe, nil
}
