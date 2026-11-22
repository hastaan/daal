package cli

// The git-tag note write (docs/update-ladder-v2.md §4.1; the write is
// publisher/deploy/freshness/backends/gittag).
//
//	note-gittag check   --creds-file F|-
//	        one call to GitHub: who the token is and whether it can
//	        create a public repository and write to it.
//	note-gittag publish --creds-file F|-
//	        make sure the repository exists (public, with a go.mod),
//	        then write this publish: n and go.mod carrying the full note
//	        (or filler), and the tag v0.<seq>.0-<sealed micro note>.
//	        Run twice, it changes nothing.
//
// Every input is in the creds JSON, read from a 0600 file the app
// deletes after the call, or from stdin with "-". Never argv. Unknown
// members are refused (a typo must not turn a reveal into filler).
//
//	check:
//	{
//	  "token": "<GitHub personal access token>",
//	  "owner": "<account the repository lives under>"            (optional)
//	}
//
//	publish:
//	{
//	  "token":           "<GitHub personal access token>",
//	  "owner":           "<carriers member gittag.owner>",
//	  "repo":            "<carriers member gittag.repo>",
//	  "update_secret":   "<standard base64 of 32 bytes>",
//	  "update_audience": "people" | "people/<g>" | "everyone",
//	  "relay_pack_id":   "<the relay's pack id>"                  (optional; never sent)
//	  "standby_commit":  "<_standby.commit, base64 of 32 bytes>"  (required with standby_key)
//	  "standby_key":     "<26-symbol standby key>"                (optional: reveal; absent: filler)
//	  "container_path":  "<file holding a daal-refresh-v2 container>" (optional: reveal; absent: filler)
//	  "seq":             <tag sequence, ≥ 1, above every seq in the repository>,
//	  "now":             "<RFC 3339 time>"                        (optional; default the clock)
//	  "filler_bucket":   4096 | 16384 | 65536                     (optional; size of full filler)
//	}
//
// The container's slot is set here to the note's name, so the app may
// build it with any slot. Its parts are carried unchanged.
//
// Stdout, one JSON object, naming no tag, name, repository or secret:
//
//	check:   {"ok":true,"verb":"check","verdict":"ok"|"ok_broad"|"invalid"|"missing_permission"|"owner_mismatch",
//	          "login":"..","token_kind":"classic"|"fine_grained"|"other","missing":[..],"extra":[..],
//	          "unproven":[..],"expires_at":"..","notes":"..","suggested_repo":".."}
//	publish: {"ok":true,"verb":"publish","changed":true,"reason":""|"already_published"|"epoch_written",
//	          "created_repo":false,"seq":7,"highest_seq":7,"epoch":2969,
//	          "micro":"reveal"|"filler","full":"reveal"|"filler","full_bucket":16384}
//
// On a failure, {"ok":false,"verb":..,"code":"<code>", ...} on stdout as
// well, with code one of
//
//	bad_input, invalid_token, missing_permission (+ "missing":[..]),
//	rate_limited (+ "retry_after_s"), seq_behind (+ "highest_seq"),
//	repo_private, repo_archived, repo_not_ours, repo_unseen,
//	other_account, tag_taken, github, network.
//
// Exit status: 0 done (check: whatever the verdict); 1 GitHub or the
// network failed (github, network, tag_taken); 2 usage or bad creds (the
// values are never echoed); 3 invalid_token; 4 a refusal about the
// account or repository (missing_permission, repo_*, other_account);
// 5 rate_limited; 6 seq_behind.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base32"
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
	"daal/publisher/deploy/freshness/backends/gittag"
)

// Seams for tests: the client (a fake GitHub) and the clock.
var (
	newNoteGitTagClient = func(token []byte) (*gittag.Client, error) {
		return gittag.New(gittag.Config{Token: token})
	}
	noteGitTagNow = time.Now
)

const noteGitTagCredsMax = 16 << 10

const (
	exitNoteGitTagToken   = 3
	exitNoteGitTagRefused = 4
	exitNoteGitTagRate    = 5
	exitNoteGitTagSeq     = 6
)

type noteGitTagCreds struct {
	Token          string `json:"token"`
	Owner          string `json:"owner"`
	Repo           string `json:"repo"`
	UpdateSecret   string `json:"update_secret"`
	UpdateAudience string `json:"update_audience"`
	RelayPackID    string `json:"relay_pack_id"`
	StandbyCommit  string `json:"standby_commit"`
	StandbyKey     string `json:"standby_key"`
	ContainerPath  string `json:"container_path"`
	Seq            uint64 `json:"seq"`
	Now            string `json:"now"`
	FillerBucket   int    `json:"filler_bucket"`
}

type noteGitTagFail struct {
	OK          bool     `json:"ok"`
	Verb        string   `json:"verb"`
	Code        string   `json:"code"`
	Missing     []string `json:"missing,omitempty"`
	RetryAfterS int      `json:"retry_after_s,omitempty"`
	HighestSeq  uint64   `json:"highest_seq,omitempty"`
}

type noteGitTagCheckOut struct {
	OK   bool   `json:"ok"`
	Verb string `json:"verb"`
	gittag.TokenCheck
	SuggestedRepo string `json:"suggested_repo,omitempty"`
}

type noteGitTagPublishOut struct {
	OK   bool   `json:"ok"`
	Verb string `json:"verb"`
	gittag.PublishResult
}

func runNoteGitTag(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) < 1 || (args[0] != "check" && args[0] != "publish") {
		fmt.Fprintln(stderr, "usage: daal-deploy note-gittag check|publish --creds-file F|-")
		return 2
	}
	verb := args[0]
	fs := flag.NewFlagSet("note-gittag "+verb, flag.ContinueOnError)
	fs.SetOutput(stderr)
	credsFile := fs.String("creds-file", "", "creds JSON file; - for stdin")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "note-gittag: unexpected arguments (every input goes in --creds-file)")
		return 2
	}
	if err := requireAll(stderr, map[string]string{"--creds-file": *credsFile}); err != nil {
		return 2
	}
	creds, err := readNoteGitTagCreds(*credsFile, stdin)
	tok := []byte(creds.Token)
	creds.Token = ""
	defer zeroBytes(tok)
	badInput := func(err error) int {
		fmt.Fprintf(stderr, "note-gittag: %s\n", cdnSecretSafe(err, tok))
		cdnWriteJSON(stdout, noteGitTagFail{Verb: verb, Code: "bad_input"})
		return 2
	}
	if err != nil {
		return badInput(err)
	}
	if len(tok) == 0 {
		return badInput(errors.New("token is missing"))
	}
	client, err := newNoteGitTagClient(tok)
	if err != nil {
		return badInput(err)
	}

	if verb == "check" {
		if creds.Owner != "" && !bundle.GitOwnerOK(creds.Owner) {
			return badInput(errors.New("owner is not a GitHub account name"))
		}
		res, err := client.CheckToken(ctx, creds.Owner)
		if err != nil {
			return noteGitTagFailed(stdout, stderr, verb, err, tok)
		}
		out := noteGitTagCheckOut{OK: true, Verb: verb, TokenCheck: res}
		if res.Usable() {
			out.SuggestedRepo = suggestNoteRepo()
		}
		cdnWriteJSON(stdout, out)
		return 0
	}

	in, err := noteGitTagPublishInput(&creds)
	defer func() { in.Secret.Secret = [bundle.UpdateSecretLen]byte{} }()
	if err != nil {
		return badInput(err)
	}
	res, err := client.Publish(ctx, in)
	if err != nil {
		if errors.Is(err, gittag.ErrInput) || errors.Is(err, gittag.ErrContainer) || errors.Is(err, gittag.ErrBadName) {
			return badInput(err)
		}
		return noteGitTagFailed(stdout, stderr, verb, err, tok)
	}
	cdnWriteJSON(stdout, noteGitTagPublishOut{OK: true, Verb: verb, PublishResult: res})
	return 0
}

// noteGitTagFailed prints the failure and picks the exit status.
func noteGitTagFailed(stdout, stderr io.Writer, verb string, err error, tok []byte) int {
	out := noteGitTagFail{Verb: verb}
	rc := 1
	var ae *gittag.APIError
	var sb *gittag.SeqBehindError
	switch {
	case errors.As(err, &sb):
		out.Code, out.HighestSeq, rc = "seq_behind", sb.Highest, exitNoteGitTagSeq
	case errors.Is(err, gittag.ErrRepoPrivate):
		out.Code, rc = "repo_private", exitNoteGitTagRefused
	case errors.Is(err, gittag.ErrRepoArchived):
		out.Code, rc = "repo_archived", exitNoteGitTagRefused
	case errors.Is(err, gittag.ErrRepoNotOurs):
		out.Code, rc = "repo_not_ours", exitNoteGitTagRefused
	case errors.Is(err, gittag.ErrRepoUnseen):
		out.Code, rc = "repo_unseen", exitNoteGitTagRefused
	case errors.Is(err, gittag.ErrOtherAccount):
		out.Code, rc = "other_account", exitNoteGitTagRefused
	case errors.Is(err, gittag.ErrTagTaken):
		out.Code = "tag_taken"
	case errors.As(err, &ae):
		switch ae.Kind {
		case gittag.KindInvalidToken:
			out.Code, rc = "invalid_token", exitNoteGitTagToken
		case gittag.KindMissingPermission:
			out.Code, out.Missing, rc = "missing_permission", []string{ae.Permission}, exitNoteGitTagRefused
		case gittag.KindRateLimited:
			out.Code, out.RetryAfterS, rc = "rate_limited", int(ae.RetryAfter.Seconds()), exitNoteGitTagRate
		case gittag.KindNetwork:
			out.Code = "network"
		default:
			out.Code = "github"
		}
	default:
		out.Code = "github"
	}
	fmt.Fprintf(stderr, "note-gittag: %s\n", cdnSecretSafe(err, tok))
	cdnWriteJSON(stdout, out)
	return rc
}

func readNoteGitTagCreds(path string, stdin io.Reader) (noteGitTagCreds, error) {
	var c noteGitTagCreds
	var r io.Reader
	if path == "-" {
		r = stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return c, errors.New("cannot read the creds file")
		}
		defer f.Close()
		r = f
	}
	body, err := io.ReadAll(io.LimitReader(r, noteGitTagCredsMax+1))
	defer zeroBytes(body)
	if err != nil || len(body) > noteGitTagCredsMax {
		return c, errors.New("the creds are unreadable or too large")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil || dec.More() {
		// The values are never echoed.
		return noteGitTagCreds{}, errors.New("the creds are not the note-gittag JSON")
	}
	c.Token = strings.TrimSpace(c.Token)
	return c, nil
}

func noteGitTagPublishInput(c *noteGitTagCreds) (gittag.PublishInput, error) {
	in := gittag.PublishInput{Owner: c.Owner, Repo: c.Repo, StandbyCommit: c.StandbyCommit, Seq: c.Seq, FillerBucket: c.FillerBucket}
	if !bundle.GitOwnerOK(c.Owner) || !bundle.GitRepoOK(c.Repo) {
		return in, errors.New("owner or repo is not a GitHub name")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(c.UpdateSecret)
	defer zeroBytes(raw)
	if err != nil || len(raw) != bundle.UpdateSecretLen {
		return in, errors.New("update_secret is not standard base64 of 32 bytes")
	}
	if !bundle.UpdateAudienceOK(c.UpdateAudience) {
		return in, errors.New("update_audience is not an audience")
	}
	in.Secret.Audience = c.UpdateAudience
	copy(in.Secret.Secret[:], raw)
	c.UpdateSecret = ""
	if len(c.RelayPackID) > 256 {
		return in, errors.New("relay_pack_id is too long")
	}
	if c.StandbyKey != "" {
		k, err := bundle.ParseStandbyKeyText(c.StandbyKey)
		if err != nil {
			return in, errors.New("standby_key is not a standby key")
		}
		in.StandbyKey = &k
		c.StandbyKey = ""
	}
	if c.ContainerPath != "" {
		f, err := os.Open(c.ContainerPath)
		if err != nil {
			return in, errors.New("cannot read the container file")
		}
		defer f.Close()
		b, err := io.ReadAll(io.LimitReader(f, bundle.MaxFullNoteContainer+1))
		if err != nil || len(b) == 0 || len(b) > bundle.MaxFullNoteContainer {
			return in, errors.New("the container file is empty, unreadable or too large")
		}
		in.Container = b
	}
	in.Now = noteGitTagNow()
	if c.Now != "" {
		t, err := time.Parse(time.RFC3339, c.Now)
		if err != nil {
			return in, errors.New("now is not an RFC 3339 time")
		}
		in.Now = t
	}
	return in, nil
}

// suggestNoteRepo is a repository name with nothing of the relay in it:
// 12 random lowercase base32 symbols. The app may use it or its own.
func suggestNoteRepo() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return strings.ToLower(base32.StdEncoding.EncodeToString(b[:]))[:12]
}
