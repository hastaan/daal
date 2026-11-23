package cli

// The DNS micro-note (docs/update-ladder-v2.md §4.3; the write side is
// publisher/deploy/cloudflare/dns_note.go).
//
//	note-dns publish --creds-file F|- [--dry-run]
//	        write this week's six records: filler, or the sealed standby
//	        key when the creds carry one; remove notes two or more weeks
//	        old. --dry-run reads the zone and prints the plan, writing
//	        nothing.
//	note-dns remove  --creds-file F|- [--dry-run]
//	        remove every note of this secret (the DNS switch turned off).
//
// Every input is in the creds JSON, read from a 0600 file the app
// deletes after the call, or from stdin with "-". Never argv.
//
//	{
//	  "cf_token":        "<Cloudflare API token>",
//	  "update_secret":   "<standard base64 of 32 bytes>",
//	  "update_audience": "people" | "people/<g>",
//	  "zone":            "<note zone: the carriers member's dns.zone>",
//	  "standby_key":     "<the standby key's 26-symbol text>"   (publish, optional)
//	}
//
// standby_key present: reveal; absent: filler. The Everyone audience is
// refused (exit 4) before any call to Cloudflare.
//
// Stdout, one JSON object (no name, zone, address or secret in it):
//
//	{"ok":true,"verb":"publish","dry_run":false,"epoch":2968,"mode":"filler"|"reveal"|"remove",
//	 "created":6,"replaced":0,"kept":0,"removed":6,"foreign_kept":0,
//	 "ops":[{"op":"create","index":0,"epoch_offset":0}, ...]}
//
// On a refusal, {"ok":false,"verb":..,"code":"<code>"} on stdout as well,
// with code one of everyone_refused, name_taken, zone_not_found,
// not_authorised. Exit status: 0 done; 1 an error (network, API);
// 2 usage or a bad creds file (its values are never echoed); 4 a refusal.

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
)

// Seams for tests.
var (
	newNoteDNSClient = cloudflare.NewLiveNoteDNSClient
	noteDNSNow       = time.Now
)

// noteDNSCredsMax bounds the creds JSON.
const noteDNSCredsMax = 16 << 10

type noteDNSCreds struct {
	CFToken        string `json:"cf_token"`
	UpdateSecret   string `json:"update_secret"`
	UpdateAudience string `json:"update_audience"`
	Zone           string `json:"zone"`
	StandbyKey     string `json:"standby_key"`
}

type noteDNSOut struct {
	OK     bool   `json:"ok"`
	Verb   string `json:"verb"`
	DryRun bool   `json:"dry_run"`
	Code   string `json:"code,omitempty"`
	*cloudflare.NotePlanSummary
}

func runNoteDNS(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) < 1 || (args[0] != "publish" && args[0] != "remove") {
		fmt.Fprintln(stderr, "usage: daal-deploy note-dns publish|remove --creds-file F|- [--dry-run]")
		return 2
	}
	verb := args[0]
	fs := flag.NewFlagSet("note-dns "+verb, flag.ContinueOnError)
	fs.SetOutput(stderr)
	credsFile := fs.String("creds-file", "", "creds JSON file (cf_token, update_secret, update_audience, zone[, standby_key]); - for stdin")
	dryRun := fs.Bool("dry-run", false, "read the zone and print the plan; write nothing")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "note-dns: unexpected arguments (every input goes in --creds-file)")
		return 2
	}
	if err := requireAll(stderr, map[string]string{"--creds-file": *credsFile}); err != nil {
		return 2
	}

	in, tok, err := readNoteDNSCreds(*credsFile, stdin, verb)
	defer zeroBytes(tok)
	if err != nil {
		fmt.Fprintf(stderr, "note-dns: %v\n", err)
		return 2
	}
	defer func() { in.Secret.Secret = [bundle.UpdateSecretLen]byte{} }()
	in.Now = noteDNSNow()

	refuse := func(code string, err error) int {
		fmt.Fprintf(stderr, "note-dns: %s\n", cdnSecretSafe(err, tok))
		cdnWriteJSON(stdout, noteDNSOut{OK: false, Verb: verb, DryRun: *dryRun, Code: code})
		return exitCDNRefused
	}
	if in.Secret.Audience == bundle.AudienceEveryone {
		return refuse("everyone_refused", cloudflare.ErrNoteAudience)
	}

	api := newNoteDNSClient()
	var plan *cloudflare.NotePlan
	if verb == "publish" {
		plan, err = cloudflare.PlanNoteDNS(ctx, api, tok, in)
	} else {
		plan, err = cloudflare.PlanNoteDNSRemove(ctx, api, tok, in)
	}
	if err == nil && !*dryRun {
		err = cloudflare.ApplyNoteDNS(ctx, api, tok, plan)
	}
	switch {
	case err == nil:
	case errors.Is(err, cloudflare.ErrNoteAudience):
		return refuse("everyone_refused", err)
	case errors.Is(err, cloudflare.ErrNoteNameTaken):
		return refuse("name_taken", err)
	case errors.Is(err, cloudflare.ErrNoteZoneNotFound):
		return refuse("zone_not_found", err)
	case cloudflare.IsNoteAuthError(err):
		return refuse("not_authorised", err)
	case errors.Is(err, cloudflare.ErrNoteInput):
		fmt.Fprintf(stderr, "note-dns: %v\n", err)
		return 2
	default:
		fmt.Fprintf(stderr, "note-dns: %s\n", cdnSecretSafe(err, tok))
		return 1
	}
	s := plan.Summary()
	if err := cdnWriteJSON(stdout, noteDNSOut{OK: true, Verb: verb, DryRun: *dryRun, NotePlanSummary: &s}); err != nil {
		return 1
	}
	return 0
}

// readNoteDNSCreds reads and checks the creds JSON. No value from it is
// ever put into an error.
func readNoteDNSCreds(path string, stdin io.Reader, verb string) (cloudflare.NoteDNSInput, []byte, error) {
	var in cloudflare.NoteDNSInput
	var body []byte
	var err error
	if path == "-" {
		body, err = io.ReadAll(io.LimitReader(stdin, noteDNSCredsMax+1))
	} else {
		body, err = os.ReadFile(path)
	}
	defer zeroBytes(body)
	if err != nil {
		return in, nil, errors.New("cannot read --creds-file")
	}
	if len(body) > noteDNSCredsMax {
		return in, nil, errors.New("--creds-file is too large")
	}
	var c noteDNSCreds
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return in, nil, errors.New("--creds-file is not the note-dns creds JSON")
	}
	tok := []byte(strings.TrimSpace(c.CFToken))
	c.CFToken = ""
	if len(tok) == 0 {
		return in, nil, errors.New("cf_token is missing")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(c.UpdateSecret)
	defer zeroBytes(raw)
	if err != nil || len(raw) != bundle.UpdateSecretLen {
		return in, tok, errors.New("update_secret is not standard base64 of 32 bytes")
	}
	if !bundle.UpdateAudienceOK(c.UpdateAudience) {
		return in, tok, errors.New("update_audience is not an audience")
	}
	in.Secret.Audience = c.UpdateAudience
	copy(in.Secret.Secret[:], raw)
	if !bundle.DNSNoteZoneOK(c.Zone) {
		return in, tok, errors.New("zone is not a note zone")
	}
	in.Zone = c.Zone
	if c.StandbyKey != "" {
		if verb != "publish" {
			return in, tok, errors.New("standby_key is for publish only")
		}
		k, err := bundle.ParseStandbyKeyText(c.StandbyKey)
		if err != nil || !bundle.StandbyAddressOK(k.Address()) {
			return in, tok, errors.New("standby_key is not a standby key")
		}
		in.StandbyKey = &k
	}
	return in, tok, nil
}
