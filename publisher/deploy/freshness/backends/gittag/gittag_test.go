package gittag

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"daal/bundle-go/bundle"
	"daal/bundle-go/fullnote"
	"daal/publisher/deploy/freshness/backends/gittag/gittagtest"
)

const (
	testToken = "ghp_testtoken0123456789"
	fgToken   = "github_pat_testtoken0123456789"
	owner     = "notes-acct"
	repo      = "q7cm2kd9xfr4"
	packID    = "rp-0f3a9c2e7b1d4455"
	relayName = "Tehran-Home-Relay"
	relayIP   = "203.0.113.77"
)

var testNow = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

func newFake(t *testing.T) *gittagtest.Fake {
	t.Helper()
	f := gittagtest.New()
	t.Cleanup(f.Close)
	f.AddToken(testToken, &gittagtest.Account{Login: owner, Scopes: []string{"public_repo"}})
	return f
}

func client(t *testing.T, f *gittagtest.Fake, token string) *Client {
	t.Helper()
	c, err := New(Config{Token: []byte(token), BaseURL: f.URL(), HTTPClient: f.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func secret(t *testing.T) bundle.UpdateSecret {
	t.Helper()
	u := bundle.UpdateSecret{Audience: bundle.UpdateAudiencePeople(0)}
	u.Secret = bundle.DeriveUpdateSecret([]byte("root-0123456789abcdef0123456789ab"), packID, u.Audience)
	return u
}

func standbyKey(t *testing.T) bundle.StandbyKeyBytes {
	t.Helper()
	k, err := bundle.NewStandbyKey(relayIP, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func container(t *testing.T, k *bundle.StandbyKeyBytes) []byte {
	t.Helper()
	doc := `{"kind":"daal-freshness","sequence":9,"relay_pack_id":"` + packID + `","name":"` + relayName + `"}`
	w := `{"kind":"daal-refresh-v2","slot":"placeholder","freshness":"` + base64.StdEncoding.EncodeToString([]byte(doc)) + `"`
	if k != nil {
		w += `,"standby_key":"` + strings.ReplaceAll(k.Text(), " ", "") + `"`
	}
	return []byte(w + "}")
}

func TestGitObjectIDs(t *testing.T) {
	// `git write-tree` of go.mod = "module x\n" and n = "abc\n".
	got := gitTreeSHA(map[string][]byte{"go.mod": []byte("module x\n"), "n": []byte("abc\n")})
	if got != "96f5aa567f40e214e3dc07eb97c46c7df5af8c24" {
		t.Fatalf("tree id %s", got)
	}
	if gittagtest.TreeSHA(map[string][]byte{"go.mod": []byte("module x\n"), "n": []byte("abc\n")}) != got {
		t.Fatal("the fake computes another tree id")
	}
}

func TestCheckToken_Verdicts(t *testing.T) {
	f := newFake(t)
	f.AddToken("ghp_broad", &gittagtest.Account{Login: owner, Scopes: []string{"repo", "delete_repo"}, Expires: "2027-01-01 00:00:00 UTC"})
	f.AddToken("ghp_gist", &gittagtest.Account{Login: owner, Scopes: []string{"gist"}})
	f.AddToken("ghp_none", &gittagtest.Account{Login: owner, Scopes: []string{}})
	f.AddToken(fgToken, &gittagtest.Account{Login: owner})
	f.AddToken("ghp_bot", &gittagtest.Account{Login: "x[bot]", Type: "Bot", Scopes: []string{"public_repo"}})

	cases := []struct {
		token, owner, verdict string
		missing               []string
	}{
		{testToken, "", VerdictOK, nil},
		{testToken, strings.ToUpper(owner), VerdictOK, nil},
		{"ghp_broad", owner, VerdictOKBroad, nil},
		{"ghp_gist", "", VerdictMissingPermission, []string{ScopePublicRepo}},
		{"ghp_none", "", VerdictMissingPermission, []string{ScopePublicRepo}},
		{fgToken, "", VerdictOK, nil},
		{"ghp_unknown", "", VerdictInvalid, nil},
		{"ghp_bot", "", VerdictInvalid, nil},
		{testToken, "someone-else", VerdictOwnerMismatch, nil},
	}
	for _, tc := range cases {
		before := f.CallCount()
		got, err := client(t, f, tc.token).CheckToken(context.Background(), tc.owner)
		if err != nil {
			t.Fatalf("%s: %v", tc.token, err)
		}
		if f.CallCount()-before != 1 {
			t.Fatalf("%s: %d calls, want one", tc.token, f.CallCount()-before)
		}
		if got.Verdict != tc.verdict || strings.Join(got.Missing, ",") != strings.Join(tc.missing, ",") {
			t.Fatalf("%s: %+v", tc.token, got)
		}
		if got.Usable() != (tc.verdict == VerdictOK || tc.verdict == VerdictOKBroad) {
			t.Fatalf("%s: usable %v", tc.token, got.Usable())
		}
	}
	b, _ := client(t, f, "ghp_broad").CheckToken(context.Background(), "")
	if len(b.Extra) != 2 || b.ExpiresAt == "" || b.TokenKind != TokenClassic {
		t.Fatalf("broad: %+v", b)
	}
	fg, _ := client(t, f, fgToken).CheckToken(context.Background(), "")
	if fg.TokenKind != TokenFineGrained || len(fg.Unproven) != 3 {
		t.Fatalf("fine-grained: %+v", fg)
	}
}

func TestCheckToken_RateLimitedAndServerError(t *testing.T) {
	f := newFake(t)
	reset := time.Now().Add(90 * time.Second).Unix()
	f.Fail(gittagtest.Fault{Match: "GET /user", Status: 403, Times: 1,
		Headers: map[string]string{"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": itoa(reset)},
		Body:    `{"message":"API rate limit exceeded"}`})
	_, err := client(t, f, testToken).CheckToken(context.Background(), "")
	var ae *APIError
	if !errors.As(err, &ae) || ae.Kind != KindRateLimited || ae.RetryAfter < 60*time.Second {
		t.Fatalf("want rate_limited with a wait, got %v", err)
	}
	f.Fail(gittagtest.Fault{Match: "GET /user", Status: 429, Times: 1, Headers: map[string]string{"Retry-After": "30"}})
	_, err = client(t, f, testToken).CheckToken(context.Background(), "")
	if !errors.As(err, &ae) || ae.Kind != KindRateLimited || ae.RetryAfter != 30*time.Second {
		t.Fatalf("429: %v", err)
	}
	f.Fail(gittagtest.Fault{Match: "GET /user", Status: 502, Times: 1})
	_, err = client(t, f, testToken).CheckToken(context.Background(), "")
	if !IsKind(err, KindGitHub) || strings.Contains(err.Error(), testToken) {
		t.Fatalf("502: %v", err)
	}
}

func TestEnsureRepo_CreatesIfMissing(t *testing.T) {
	f := newFake(t)
	c := client(t, f, testToken)
	st, err := c.EnsureRepo(context.Background(), owner, repo)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Created || !st.Initialized {
		t.Fatalf("%+v", st)
	}
	r := f.Repo(owner, repo)
	if r == nil || r.Private || r.CreateBody["private"] != false {
		t.Fatalf("repo not created public: %+v", r)
	}
	gm := f.Files(owner, repo, "main")[FileGoMod]
	if !strings.HasPrefix(string(gm), "module github.com/"+owner+"/"+repo+"\n") {
		t.Fatalf("go.mod %q", gm)
	}
	w := f.Writes()
	st, err = c.EnsureRepo(context.Background(), owner, repo)
	if err != nil || st.Created || st.Initialized || f.Writes() != w {
		t.Fatalf("second ensure changed something: %+v %v", st, err)
	}
}

func TestEnsureRepo_Refusals(t *testing.T) {
	f := newFake(t)
	c := client(t, f, testToken)
	f.AddRepo(owner, "private-one", true, nil)
	if _, err := c.EnsureRepo(context.Background(), owner, "private-one"); !errors.Is(err, ErrRepoPrivate) {
		t.Fatalf("private: %v", err)
	}
	f.AddRepo(owner, "project", false, map[string][]byte{"main.go": []byte("package main\n")})
	if _, err := c.EnsureRepo(context.Background(), owner, "project"); !errors.Is(err, ErrRepoNotOurs) {
		t.Fatalf("not ours: %v", err)
	}
	if _, err := c.EnsureRepo(context.Background(), "someone-else", repo); !errors.Is(err, ErrOtherAccount) {
		t.Fatalf("other account: %v", err)
	}
	if _, err := c.EnsureRepo(context.Background(), owner, "bad/name"); !errors.Is(err, ErrBadName) {
		t.Fatalf("bad name: %v", err)
	}
	f.AddToken("github_pat_noadmin", &gittagtest.Account{Login: owner, NoAdmin: true})
	_, err := client(t, f, "github_pat_noadmin").EnsureRepo(context.Background(), owner, "fresh")
	var ae *APIError
	if !errors.As(err, &ae) || ae.Kind != KindMissingPermission || ae.Permission != PermAdministration {
		t.Fatalf("no admin: %v", err)
	}
	f.AddToken("github_pat_nocontents", &gittagtest.Account{Login: owner, NoContents: true})
	f.AddRepo(owner, "ro", false, nil)
	_, err = client(t, f, "github_pat_nocontents").EnsureRepo(context.Background(), owner, "ro")
	if !errors.As(err, &ae) || ae.Kind != KindMissingPermission || ae.Permission != PermContents {
		t.Fatalf("no contents: %v", err)
	}
}

func publishIn(t *testing.T, seq uint64, k *bundle.StandbyKeyBytes, cont []byte, commit string) PublishInput {
	return PublishInput{Owner: owner, Repo: repo, Secret: secret(t), StandbyCommit: commit,
		StandbyKey: k, Container: cont, Seq: seq, Now: testNow}
}

// readNotes opens what a reader would find at a tag: the micro note in
// the tag name, the full note in n and in go.mod's comments.
func readNotes(t *testing.T, f *gittagtest.Fake, tag string, k bundle.StandbyKeyBytes) (bundle.StandbyKeyBytes, bool, *fullnote.Opened) {
	t.Helper()
	u := secret(t)
	_, sealed, ok := bundle.ParseGitNoteTag(tag)
	if !ok {
		t.Fatalf("not a note tag: %s", tag)
	}
	sb := bundle.SealedStandby(k)
	got, _, _, opened := sb.OpenMicroNote(Label, testNow, sealed, []*bundle.UpdateSecret{&u})
	files := f.Files(owner, repo, tag)
	raw, err := bundle.DecodeFullNoteText(string(files[FileNote]))
	if err != nil {
		t.Fatalf("n: %v", err)
	}
	raw2, err := bundle.DecodeFullNoteText(GoModNoteText(files[FileGoMod]))
	if err != nil || !bytes.Equal(raw, raw2) {
		t.Fatalf("go.mod comments do not carry n: %v", err)
	}
	full, err := fullnote.Open(Label, testNow, raw, []*bundle.UpdateSecret{&u})
	if err != nil {
		return got, opened, nil
	}
	return got, opened, full
}

func TestPublish_FillerThenRevealSameShape(t *testing.T) {
	f := newFake(t)
	c := client(t, f, testToken)
	k := standbyKey(t)
	commit := bundle.StandbyCommit(k)

	res, err := c.Publish(context.Background(), publishIn(t, 1, nil, nil, commit))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed || !res.CreatedRepo || res.Micro != NoteFiller || res.Full != NoteFiller || res.Seq != 1 {
		t.Fatalf("%+v", res)
	}
	tags := f.TagNames(owner, repo)
	if len(tags) != 1 {
		t.Fatalf("tags %v", tags)
	}
	_, opened, full := readNotes(t, f, tags[0], k)
	if opened || full != nil {
		t.Fatal("filler opened as a note")
	}
	fillerFiles := f.Files(owner, repo, tags[0])

	cont := container(t, &k)
	res, err = c.Publish(context.Background(), PublishInput{Owner: owner, Repo: repo, Secret: secret(t),
		StandbyCommit: commit, StandbyKey: &k, Container: cont, Seq: 2, Now: testNow, FillerBucket: 4096})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed || res.Micro != NoteReveal || res.Full != NoteReveal || res.Seq != 2 || res.HighestSeq != 2 {
		t.Fatalf("%+v", res)
	}
	tags = f.TagNames(owner, repo)
	var revealTag string
	for _, tg := range tags {
		if strings.HasPrefix(tg, "v0.2.0-") {
			revealTag = tg
		}
	}
	got, opened, full := readNotes(t, f, revealTag, k)
	if !opened || got != k {
		t.Fatal("the reveal's micro note does not open to the standby key")
	}
	if full == nil {
		t.Fatal("the full note does not open")
	}
	slot, _ := bundle.NoteName(secret(t).Secret, Label, bundle.NoteEpochAt(Label, testNow))
	if full.Slot != slot || !bytes.Contains(full.Container, []byte(`"slot":"`+slot+`"`)) {
		t.Fatal("the container does not name the note's slot")
	}
	// Same shape: the same two files, n the same size when the buckets
	// match (the default filler bucket here is 16384, the container's
	// is 4096; a filler run with FillerBucket 4096 matches it).
	revealFiles := f.Files(owner, repo, revealTag)
	if len(revealFiles) != 2 || len(fillerFiles) != 2 {
		t.Fatal("not exactly n and go.mod")
	}
	f2 := newFake(t)
	c2 := client(t, f2, testToken)
	in := publishIn(t, 1, nil, nil, commit)
	in.FillerBucket = res.FullBucket
	if _, err := c2.Publish(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	ff := f2.Files(owner, repo, f2.TagNames(owner, repo)[0])
	if len(ff[FileNote]) != len(revealFiles[FileNote]) || len(ff[FileGoMod]) != len(revealFiles[FileGoMod]) {
		t.Fatalf("filler and note differ in size: n %d/%d go.mod %d/%d",
			len(ff[FileNote]), len(revealFiles[FileNote]), len(ff[FileGoMod]), len(revealFiles[FileGoMod]))
	}
	if len(tags[0]) != len(revealTag) {
		t.Fatal("tags differ in length")
	}
}

func TestPublish_Idempotent(t *testing.T) {
	f := newFake(t)
	c := client(t, f, testToken)
	k := standbyKey(t)
	commit := bundle.StandbyCommit(k)
	if _, err := c.Publish(context.Background(), publishIn(t, 1, nil, nil, commit)); err != nil {
		t.Fatal(err)
	}
	w := f.Writes()
	// The same filler run, and one with a higher seq: nothing changes.
	for _, seq := range []uint64{1, 5} {
		res, err := c.Publish(context.Background(), publishIn(t, seq, nil, nil, commit))
		if err != nil || res.Changed || res.Reason != ReasonEpochWritten || f.Writes() != w {
			t.Fatalf("filler again (seq %d): %+v %v", seq, res, err)
		}
	}
	cont := container(t, &k)
	if _, err := c.Publish(context.Background(), publishIn(t, 2, &k, cont, commit)); err != nil {
		t.Fatal(err)
	}
	w = f.Writes()
	for _, seq := range []uint64{2, 3} {
		res, err := c.Publish(context.Background(), publishIn(t, seq, &k, cont, commit))
		if err != nil || res.Changed || res.Reason != ReasonAlreadyPublished || res.Seq != 2 || f.Writes() != w {
			t.Fatalf("reveal again (seq %d): %+v %v", seq, res, err)
		}
	}
	// Filler after a reveal in the same epoch does not hide it.
	res, err := c.Publish(context.Background(), publishIn(t, 9, nil, nil, commit))
	if err != nil || res.Changed || res.Reason != ReasonEpochWritten || f.Writes() != w {
		t.Fatalf("filler over a reveal: %+v %v", res, err)
	}
	if n := len(f.TagNames(owner, repo)); n != 2 {
		t.Fatalf("%d tags", n)
	}
	// The next epoch's filler is a new write.
	in := publishIn(t, 3, nil, nil, commit)
	in.Now = testNow.Add(bundle.NoteEpochWeek)
	if res, err := c.Publish(context.Background(), in); err != nil || !res.Changed || res.Epoch != bundle.NoteEpochAt(Label, testNow)+1 {
		t.Fatalf("next epoch: %+v %v", res, err)
	}
}

func TestPublish_SeqMonotonic(t *testing.T) {
	f := newFake(t)
	c := client(t, f, testToken)
	k := standbyKey(t)
	commit := bundle.StandbyCommit(k)
	if _, err := c.Publish(context.Background(), publishIn(t, 5, &k, nil, commit)); err != nil {
		t.Fatal(err)
	}
	w := f.Writes()
	cont := container(t, &k)
	for _, seq := range []uint64{4, 5} {
		_, err := c.Publish(context.Background(), publishIn(t, seq, &k, cont, commit))
		var sb *SeqBehindError
		if !errors.Is(err, ErrSeqBehind) || !errors.As(err, &sb) || sb.Highest != 5 {
			t.Fatalf("seq %d: %v", seq, err)
		}
	}
	if f.Writes() != w {
		t.Fatal("a refused seq wrote something")
	}
	if res, err := c.Publish(context.Background(), publishIn(t, 6, &k, cont, commit)); err != nil || res.Seq != 6 {
		t.Fatalf("%+v %v", res, err)
	}
	// A tag that is not a note tag is ignored for seq.
	r := f.Repo(owner, repo)
	r.Tags["v0.99.0"] = r.Branches["main"]
	if _, err := c.Publish(context.Background(), publishIn(t, 7, nil, cont, commit)); err != nil {
		t.Fatal(err)
	}
}

func TestPublish_RateLimitedMidway(t *testing.T) {
	f := newFake(t)
	c := client(t, f, testToken)
	k := standbyKey(t)
	commit := bundle.StandbyCommit(k)
	f.Fail(gittagtest.Fault{Match: "POST /repos/" + owner + "/" + repo + "/git/trees", Status: 403, Times: 1,
		Headers: map[string]string{"Retry-After": "60"}, Body: `{"message":"You have exceeded a secondary rate limit"}`})
	_, err := c.Publish(context.Background(), publishIn(t, 1, &k, nil, commit))
	var ae *APIError
	if !errors.As(err, &ae) || ae.Kind != KindRateLimited || ae.RetryAfter != time.Minute {
		t.Fatalf("want rate_limited, got %v", err)
	}
	if len(f.TagNames(owner, repo)) != 0 {
		t.Fatal("a tag was written")
	}
	if res, err := c.Publish(context.Background(), publishIn(t, 1, &k, nil, commit)); err != nil || !res.Changed {
		t.Fatalf("retry: %+v %v", res, err)
	}
}

func TestPublish_MissingContentsPermission(t *testing.T) {
	f := newFake(t)
	f.AddRepo(owner, repo, false, map[string][]byte{FileGoMod: []byte(baseGoMod(owner, repo))})
	f.Fail(gittagtest.Fault{Match: "POST /repos/" + owner + "/" + repo + "/git/trees", Status: 403,
		Body: `{"message":"Resource not accessible by personal access token"}`})
	k := standbyKey(t)
	_, err := client(t, f, testToken).Publish(context.Background(), publishIn(t, 1, &k, nil, bundle.StandbyCommit(k)))
	var ae *APIError
	if !errors.As(err, &ae) || ae.Kind != KindMissingPermission || ae.Permission != PermContents {
		t.Fatalf("%v", err)
	}
}

func TestPublish_HalfFinishedRetried(t *testing.T) {
	for _, stage := range []string{"POST /repos/" + owner + "/" + repo + "/git/refs", "PATCH /repos/" + owner + "/" + repo + "/git/refs/heads/"} {
		f := newFake(t)
		c := client(t, f, testToken)
		k := standbyKey(t)
		commit := bundle.StandbyCommit(k)
		cont := container(t, &k)
		f.Fail(gittagtest.Fault{Match: stage, Status: 502, Times: 1})
		if _, err := c.Publish(context.Background(), publishIn(t, 1, &k, cont, commit)); !IsKind(err, KindGitHub) {
			t.Fatalf("%s: want the fault, got %v", stage, err)
		}
		if len(f.TagNames(owner, repo)) != 0 {
			t.Fatalf("%s: a tag without a finished commit", stage)
		}
		commitsBefore := len(f.Repo(owner, repo).Commits)
		res, err := c.Publish(context.Background(), publishIn(t, 1, &k, cont, commit))
		if err != nil || !res.Changed || res.Seq != 1 {
			t.Fatalf("%s: retry: %+v %v", stage, res, err)
		}
		tags := f.TagNames(owner, repo)
		if len(tags) != 1 {
			t.Fatalf("%s: tags %v", stage, tags)
		}
		r := f.Repo(owner, repo)
		if r.Tags[tags[0]] != r.Branches["main"] {
			t.Fatalf("%s: the tag is not on the branch head", stage)
		}
		added := len(r.Commits) - commitsBefore
		if strings.HasPrefix(stage, "POST") && added != 0 {
			t.Fatalf("%s: the retry wrote %d more commits", stage, added)
		}
		if got, ok, full := readNotes(t, f, tags[0], k); !ok || got != k || full == nil {
			t.Fatalf("%s: the finished publish does not open", stage)
		}
	}
}

func TestPublish_LostTagAnswer(t *testing.T) {
	f := newFake(t)
	c := client(t, f, testToken)
	k := standbyKey(t)
	commit := bundle.StandbyCommit(k)
	if _, err := c.Publish(context.Background(), publishIn(t, 1, &k, nil, commit)); err != nil {
		t.Fatal(err)
	}
	// createTag on a name that exists on the same commit is accepted.
	r := f.Repo(owner, repo)
	tag := f.TagNames(owner, repo)[0]
	st, _ := c.EnsureRepo(context.Background(), owner, repo)
	if err := c.createTag(context.Background(), owner, repo, tag, r.Tags[tag], st.HeadTree); err != nil {
		t.Fatal(err)
	}
	if err := c.createTag(context.Background(), owner, repo, tag, "0000000000000000000000000000000000000000", "x"); !errors.Is(err, ErrTagTaken) {
		t.Fatalf("%v", err)
	}
}

func TestPublish_NothingInTheClear(t *testing.T) {
	f := newFake(t)
	c := client(t, f, testToken)
	k := standbyKey(t)
	commit := bundle.StandbyCommit(k)
	if _, err := c.Publish(context.Background(), publishIn(t, 1, nil, nil, commit)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Publish(context.Background(), publishIn(t, 2, &k, container(t, &k), commit)); err != nil {
		t.Fatal(err)
	}
	keyText := strings.ReplaceAll(k.Text(), " ", "")
	everything := strings.Join(f.Bodies, "\n") + strings.Join(f.Calls, "\n") + strings.Join(f.TagNames(owner, repo), "\n")
	for _, cm := range f.Repo(owner, repo).Commits {
		everything += cm.Message
	}
	for _, files := range f.Repo(owner, repo).Trees {
		for n, b := range files {
			everything += n + string(b)
		}
	}
	for _, bad := range []string{packID, relayName, relayIP, keyText, testToken,
		base64.StdEncoding.EncodeToString([]byte(packID))[:12]} {
		if strings.Contains(everything, bad) {
			t.Fatalf("%q reached GitHub in the clear", bad)
		}
	}
	for _, cm := range f.Repo(owner, repo).Commits {
		if cm.Message != CommitMessage {
			t.Fatalf("commit message %q", cm.Message)
		}
	}
}

func TestPublish_InputRefusals(t *testing.T) {
	f := newFake(t)
	c := client(t, f, testToken)
	k := standbyKey(t)
	other := standbyKey(t)
	commit := bundle.StandbyCommit(k)
	cases := map[string]PublishInput{
		"seq 0":           publishIn(t, 0, nil, nil, commit),
		"key, no commit":  publishIn(t, 1, &k, nil, ""),
		"key mismatch":    publishIn(t, 1, &other, nil, commit),
		"bad commit":      publishIn(t, 1, nil, nil, "abc"),
		"container key":   publishIn(t, 1, nil, container(t, &other), commit),
		"empty container": publishIn(t, 1, nil, []byte(`{"kind":"daal-refresh-v2","slot":"x"}`), commit),
		"unknown member":  publishIn(t, 1, nil, []byte(`{"kind":"daal-refresh-v2","slot":"x","freshness":"eA==","relay":"y"}`), commit),
		"bad bucket":      {Owner: owner, Repo: repo, Secret: secret(t), Seq: 1, FillerBucket: 5000},
	}
	for name, in := range cases {
		if _, err := c.Publish(context.Background(), in); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if f.Writes() != 0 {
		t.Fatal("a refused input wrote something")
	}
}

func TestFillerIsDeterministicAndPerAudience(t *testing.T) {
	u := secret(t)
	e := bundle.NoteEpochAt(Label, testNow)
	a, _ := fullFiller(u.Secret, e, 4096)
	b, _ := fullFiller(u.Secret, e, 4096)
	if !bytes.Equal(a, b) || !bundle.FullNoteSealedLenOK(len(a)) {
		t.Fatal("full filler")
	}
	v := u
	v.Secret[0] ^= 1
	if MicroFiller(u.Secret, e) == MicroFiller(v.Secret, e) || MicroFiller(u.Secret, e) == MicroFiller(u.Secret, e+1) {
		t.Fatal("micro filler does not depend on u and e")
	}
	if _, err := fullnote.OpenWith(u.Secret, Label, e, a); err == nil {
		t.Fatal("filler opened")
	}
}

func itoa(n int64) string {
	const digits = "0123456789"
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{digits[n%10]}, b...)
		n /= 10
	}
	return string(b)
}

// GitHub pages the tag list: with more than 100 note tags the highest
// seq and an earlier publish are still seen, and a write prunes the
// note tags to the newest KeepNoteTags.
func TestPublish_ManyTagsPaginatedAndPruned(t *testing.T) {
	f := newFake(t)
	c := client(t, f, testToken)
	k := standbyKey(t)
	commit := bundle.StandbyCommit(k)
	cont := container(t, &k)
	if _, err := c.Publish(context.Background(), publishIn(t, 200, &k, cont, commit)); err != nil {
		t.Fatal(err)
	}
	r := f.Repo(owner, repo)
	head := r.Branches["main"]
	for seq := uint64(10); seq < 160; seq++ {
		var sealed [bundle.MicroNoteLen]byte
		_, _ = rand.Read(sealed[:])
		r.Tags[bundle.GitNoteTag(seq, sealed)] = head
	}
	w := f.Writes()
	res, err := c.Publish(context.Background(), publishIn(t, 201, &k, cont, commit))
	if err != nil || res.Changed || res.Reason != ReasonAlreadyPublished || res.Seq != 200 || res.HighestSeq != 200 || f.Writes() != w {
		t.Fatalf("repeat over 151 tags: %+v %v", res, err)
	}
	if _, err := c.Publish(context.Background(), publishIn(t, 150, &k, container(t, nil), commit)); !errors.Is(err, ErrSeqBehind) {
		t.Fatalf("seq behind not seen past page 1: %v", err)
	}
	in := publishIn(t, 202, nil, nil, commit)
	in.Now = testNow.Add(bundle.NoteEpochWeek)
	res, err = c.Publish(context.Background(), in)
	if err != nil || !res.Changed || res.HighestSeq != 202 {
		t.Fatalf("next write: %+v %v", res, err)
	}
	names := f.TagNames(owner, repo)
	if len(names) != KeepNoteTags {
		t.Fatalf("%d tags left", len(names))
	}
	// The newest 40 by seq: 202, 200 and 159 down to 122.
	for _, n := range names {
		if seq, _, ok := bundle.ParseGitNoteTag(n); !ok || seq < 122 {
			t.Fatalf("kept an old tag (seq %d)", seq)
		}
	}
}
