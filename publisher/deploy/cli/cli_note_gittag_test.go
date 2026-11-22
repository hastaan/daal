package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"daal/bundle-go/bundle"
	"daal/publisher/deploy/freshness/backends/gittag"
	"daal/publisher/deploy/freshness/backends/gittag/gittagtest"
)

const (
	ngtToken = "ghp_clitesttoken0123456789"
	ngtOwner = "notes-acct"
	ngtRepo  = "k3vq8m2xw7pa"
	ngtPack  = "rp-77aa55cc33ee1100"
)

func ngtFake(t *testing.T) *gittagtest.Fake {
	t.Helper()
	f := gittagtest.New()
	t.Cleanup(f.Close)
	f.AddToken(ngtToken, &gittagtest.Account{Login: ngtOwner, Scopes: []string{"public_repo"}})
	oldC, oldN := newNoteGitTagClient, noteGitTagNow
	newNoteGitTagClient = func(token []byte) (*gittag.Client, error) {
		return gittag.New(gittag.Config{Token: token, BaseURL: f.URL(), HTTPClient: f.Client()})
	}
	noteGitTagNow = func() time.Time { return time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { newNoteGitTagClient, noteGitTagNow = oldC, oldN })
	return f
}

func ngtRun(t *testing.T, verb string, creds map[string]any) (int, map[string]any, string) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "creds.json")
	b, _ := json.Marshal(creds)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rc := runNoteGitTag(context.Background(), []string{verb, "--creds-file", p}, strings.NewReader(""), &out, &errb)
	var m map[string]any
	if out.Len() > 0 {
		if err := json.Unmarshal(out.Bytes(), &m); err != nil {
			t.Fatalf("stdout is not JSON: %q", out.String())
		}
	}
	return rc, m, out.String() + errb.String()
}

func ngtSecret() (string, [32]byte) {
	u := bundle.DeriveUpdateSecret([]byte("root-for-cli-tests-0123456789abc"), ngtPack, bundle.AudiencePeople)
	return base64.StdEncoding.EncodeToString(u[:]), u
}

func TestNoteGitTag_Check(t *testing.T) {
	f := ngtFake(t)
	f.AddToken("ghp_gistonly", &gittagtest.Account{Login: ngtOwner, Scopes: []string{"gist"}})
	rc, m, all := ngtRun(t, "check", map[string]any{"token": ngtToken})
	if rc != 0 || m["ok"] != true || m["verdict"] != "ok" || m["login"] != ngtOwner {
		t.Fatalf("rc %d %v", rc, m)
	}
	if s, _ := m["suggested_repo"].(string); !bundle.GitRepoOK(s) || len(s) != 12 {
		t.Fatalf("suggested repo %q", s)
	}
	if strings.Contains(all, ngtToken) {
		t.Fatal("the token was printed")
	}
	rc, m, _ = ngtRun(t, "check", map[string]any{"token": "ghp_gistonly"})
	if rc != 0 || m["verdict"] != "missing_permission" || m["suggested_repo"] != nil {
		t.Fatalf("rc %d %v", rc, m)
	}
	rc, m, _ = ngtRun(t, "check", map[string]any{"token": "ghp_nobody"})
	if rc != 0 || m["verdict"] != "invalid" {
		t.Fatalf("rc %d %v", rc, m)
	}
	f.Fail(gittagtest.Fault{Match: "GET /user", Status: 429, Times: 1, Headers: map[string]string{"Retry-After": "12"}})
	rc, m, _ = ngtRun(t, "check", map[string]any{"token": ngtToken})
	if rc != exitNoteGitTagRate || m["ok"] != false || m["code"] != "rate_limited" || m["retry_after_s"] != float64(12) {
		t.Fatalf("rc %d %v", rc, m)
	}
}

func TestNoteGitTag_PublishAndRepeat(t *testing.T) {
	f := ngtFake(t)
	secret, u := ngtSecret()
	k, err := bundle.NewStandbyKey("198.51.100.20", rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	doc := base64.StdEncoding.EncodeToString([]byte(`{"kind":"daal-freshness","sequence":3}`))
	cpath := filepath.Join(t.TempDir(), "container.json")
	if err := os.WriteFile(cpath, []byte(`{"kind":"daal-refresh-v2","slot":"x","freshness":"`+doc+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	creds := map[string]any{
		"token": ngtToken, "owner": ngtOwner, "repo": ngtRepo,
		"update_secret": secret, "update_audience": "people", "relay_pack_id": ngtPack,
		"standby_commit": bundle.StandbyCommit(k), "standby_key": k.Text(),
		"container_path": cpath, "seq": 1,
	}
	rc, m, all := ngtRun(t, "publish", creds)
	if rc != 0 || m["ok"] != true || m["changed"] != true || m["created_repo"] != true ||
		m["micro"] != "reveal" || m["full"] != "reveal" || m["seq"] != float64(1) || m["full_bucket"] != float64(4096) {
		t.Fatalf("rc %d %v\n%s", rc, m, all)
	}
	for _, bad := range []string{ngtToken, secret, ngtRepo, ngtPack, strings.ReplaceAll(k.Text(), " ", "")} {
		if strings.Contains(all, bad) {
			t.Fatalf("%q was printed", bad)
		}
	}
	tags := f.TagNames(ngtOwner, ngtRepo)
	if len(tags) != 1 {
		t.Fatalf("tags %v", tags)
	}
	_, sealed, _ := bundle.ParseGitNoteTag(tags[0])
	sb := bundle.SealedStandby(k)
	us := &bundle.UpdateSecret{Audience: "people", Secret: u}
	got, _, _, ok := sb.OpenMicroNote(bundle.NoteCarrierGitTag, noteGitTagNow(), sealed, []*bundle.UpdateSecret{us})
	if !ok || got != k {
		t.Fatal("the tag does not carry the standby key")
	}

	w := f.Writes()
	rc, m, _ = ngtRun(t, "publish", creds)
	if rc != 0 || m["changed"] != false || m["reason"] != "already_published" || f.Writes() != w {
		t.Fatalf("repeat: rc %d %v", rc, m)
	}
	delete(creds, "standby_key")
	delete(creds, "container_path")
	rc, m, _ = ngtRun(t, "publish", creds)
	if rc != 0 || m["changed"] != false || m["reason"] != "epoch_written" {
		t.Fatalf("filler after reveal: rc %d %v", rc, m)
	}
	creds["now"] = "2026-12-01T00:00:00Z"
	rc, m, _ = ngtRun(t, "publish", creds)
	if rc != exitNoteGitTagSeq || m["code"] != "seq_behind" || m["highest_seq"] != float64(1) {
		t.Fatalf("seq behind: rc %d %v", rc, m)
	}
	creds["seq"] = 2
	rc, m, _ = ngtRun(t, "publish", creds)
	if rc != 0 || m["changed"] != true || m["micro"] != "filler" {
		t.Fatalf("next epoch: rc %d %v", rc, m)
	}
}

func TestNoteGitTag_Refusals(t *testing.T) {
	f := ngtFake(t)
	secret, _ := ngtSecret()
	base := func() map[string]any {
		return map[string]any{"token": ngtToken, "owner": ngtOwner, "repo": ngtRepo,
			"update_secret": secret, "update_audience": "people", "seq": 1}
	}
	cases := []struct {
		name string
		edit func(map[string]any)
		rc   int
		code string
	}{
		{"unknown member", func(m map[string]any) { m["audience"] = "people" }, 2, "bad_input"},
		{"no token", func(m map[string]any) { delete(m, "token") }, 2, "bad_input"},
		{"bad secret", func(m map[string]any) { m["update_secret"] = "abc" }, 2, "bad_input"},
		{"bad audience", func(m map[string]any) { m["update_audience"] = "friends" }, 2, "bad_input"},
		{"bad repo", func(m map[string]any) { m["repo"] = "a/b" }, 2, "bad_input"},
		{"key without commit", func(m map[string]any) { m["standby_key"] = "0000000000000000000000000G" }, 2, "bad_input"},
		{"seq 0", func(m map[string]any) { m["seq"] = 0 }, 2, "bad_input"},
		{"bad token", func(m map[string]any) { m["token"] = "ghp_unknown" }, exitNoteGitTagToken, "invalid_token"},
		{"other account", func(m map[string]any) { m["owner"] = "someone-else" }, exitNoteGitTagRefused, "other_account"},
	}
	for _, tc := range cases {
		c := base()
		tc.edit(c)
		rc, m, all := ngtRun(t, "publish", c)
		if rc != tc.rc || m["code"] != tc.code || m["ok"] != false {
			t.Fatalf("%s: rc %d %v\n%s", tc.name, rc, m, all)
		}
		if strings.Contains(all, secret) {
			t.Fatalf("%s: the secret was printed", tc.name)
		}
	}
	if f.Writes() != 0 {
		t.Fatal("a refused publish wrote something")
	}
	f.Fail(gittagtest.Fault{Match: "POST /user/repos", Status: 403})
	rc, m, _ := ngtRun(t, "publish", base())
	if rc != exitNoteGitTagRefused || m["code"] != "missing_permission" {
		t.Fatalf("rc %d %v", rc, m)
	}
	if ms, _ := m["missing"].([]any); len(ms) != 1 || ms[0] != gittag.PermAdministration {
		t.Fatalf("missing %v", m["missing"])
	}
	// Flags carry nothing: a token on argv is refused as an unknown flag.
	var out, errb bytes.Buffer
	if rc := runNoteGitTag(context.Background(), []string{"publish", "--token", ngtToken}, strings.NewReader(""), &out, &errb); rc != 2 {
		t.Fatalf("argv token: rc %d", rc)
	}
	// Run knows the verb.
	if rc := Run([]string{"note-gittag"}, &out, &errb); rc != 2 || !strings.Contains(errb.String(), "note-gittag check|publish") {
		t.Fatalf("Run: rc %d %q", rc, errb.String())
	}
}
