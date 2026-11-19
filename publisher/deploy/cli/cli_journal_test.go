package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"daal/publisher/deploy/provider"
	"daal/publisher/deploy/provjournal"
)

// fakeProvisioner is a providerFace whose Provision behaves like an
// adapter: it begins the journal, journals a server, and then either
// returns a record or the configured error.
type fakeProvisioner struct {
	providerFace
	called bool
	err    error
}

func (f *fakeProvisioner) Provision(_ context.Context, opts provider.ProvisionOpts) (*provider.OperatorRecord, error) {
	f.called = true
	j := opts.J()
	if err := j.Begin(provider.ModeCreate, "daal-fsn1-0001020304050607", 23456, "www.example.org"); err != nil {
		return nil, provider.Coded(provider.CodeJournalError, err)
	}
	if err := j.Intent(provider.KindServer, "daal-fsn1-0001020304050607", ""); err != nil {
		return nil, provider.Coded(provider.CodeJournalError, err)
	}
	j.Created(provider.KindServer, "123", "daal-fsn1-0001020304050607", nil)
	if f.err != nil {
		return nil, f.err
	}
	return &provider.OperatorRecord{Provider: "hetzner", ServerID: "123", Region: "fsn1",
		MgmtPort: 23456, MgmtTLSFingerprint: strings.Repeat("ab", 32), PublisherPubKey: opts.PublisherPubKey}, nil
}

const journalTestToken = "TOKEN-SHOULD-NEVER-APPEAR-0123456789"

func provisionArgs(t *testing.T, journal string) []string {
	t.Helper()
	dir := t.TempDir()
	pub, _, _ := ed25519.GenerateKey(nil)
	pubFile := filepath.Join(dir, "pub")
	if err := os.WriteFile(pubFile, pub, 0o600); err != nil {
		t.Fatal(err)
	}
	tok := filepath.Join(dir, "tok")
	if err := os.WriteFile(tok, []byte(journalTestToken), 0o600); err != nil {
		t.Fatal(err)
	}
	return []string{"provision", "--pubkey-file", pubFile, "--region", "fsn1", "--toolbox-profile", "iran-default",
		"--helper-ip", "1.2.3.4", "--token-file", tok, "--progress-json", "--journal", journal}
}

// stdoutThatChecksJournal fails the test if anything reaches stdout
// before the journal holds a done line.
type stdoutThatChecksJournal struct {
	t    *testing.T
	path string
	buf  bytes.Buffer
}

func (w *stdoutThatChecksJournal) Write(p []byte) (int, error) {
	body, _ := os.ReadFile(w.path)
	if !strings.Contains(string(body), `"ev":"done"`) {
		w.t.Errorf("stdout written before the journal's done line:\n%s", body)
	}
	return w.buf.Write(p)
}

func TestProvisionCLI_DoneIsJournalledBeforeStdoutAndNoTokenLeaks(t *testing.T) {
	fake := &fakeProvisioner{}
	withFakeProvider(t, fake)
	path := filepath.Join(t.TempDir(), "j.jsonl")
	out := &stdoutThatChecksJournal{t: t, path: path}
	var stderr bytes.Buffer
	if rc := Run(provisionArgs(t, path), out, &stderr); rc != 0 {
		t.Fatalf("rc=%d %s", rc, stderr.String())
	}
	if out.buf.Len() == 0 {
		t.Fatal("no record on stdout")
	}
	body, _ := os.ReadFile(path)
	if strings.Contains(string(body), journalTestToken) {
		t.Fatal("the cloud token reached the journal")
	}
	var begin map[string]any
	_ = json.Unmarshal([]byte(strings.SplitN(string(body), "\n", 2)[0]), &begin)
	if begin["ev"] != "begin" || begin["provider"] != "hetzner" || begin["mode"] != "create" || begin["region"] != "fsn1" {
		t.Fatalf("first line is not a full begin: %v", begin)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("journal mode %v, want 0600", fi.Mode().Perm())
	}
}

func TestProvisionCLI_HeldLockExits5AndCreatesNothing(t *testing.T) {
	fake := &fakeProvisioner{}
	withFakeProvider(t, fake)
	path := filepath.Join(t.TempDir(), "j.jsonl")
	held, err := provjournal.Open(path, provjournal.Static{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	var stdout, stderr bytes.Buffer
	if rc := Run(provisionArgs(t, path), &stdout, &stderr); rc != 5 {
		t.Fatalf("rc=%d, want 5; %s", rc, stderr.String())
	}
	if fake.called {
		t.Fatal("Provision ran although another setup holds the journal")
	}
	if !strings.Contains(stderr.String(), `"code":"journal_busy"`) {
		t.Fatalf("no journal_busy progress line: %s", stderr.String())
	}
}

func TestProvisionCLI_UnwritableJournalExits5BeforeAnyCloudCall(t *testing.T) {
	fake := &fakeProvisioner{}
	withFakeProvider(t, fake)
	path := filepath.Join(t.TempDir(), "no-such-dir", "j.jsonl")
	var stdout, stderr bytes.Buffer
	if rc := Run(provisionArgs(t, path), &stdout, &stderr); rc != 5 {
		t.Fatalf("rc=%d, want 5; %s", rc, stderr.String())
	}
	if fake.called {
		t.Fatal("Provision ran although the journal could not be opened")
	}
	if !strings.Contains(stderr.String(), `"code":"journal_error"`) {
		t.Fatalf("no journal_error progress line: %s", stderr.String())
	}
}

func TestProvisionCLI_ServerExistsExits4WithTheIDAndAFailedLine(t *testing.T) {
	fake := &fakeProvisioner{err: &provider.ProvisionError{Code: provider.CodeServerExists, ServerID: "777", Err: errors.New("exists")}}
	withFakeProvider(t, fake)
	path := filepath.Join(t.TempDir(), "j.jsonl")
	var stdout, stderr bytes.Buffer
	if rc := Run(provisionArgs(t, path), &stdout, &stderr); rc != 4 {
		t.Fatalf("rc=%d, want 4; %s", rc, stderr.String())
	}
	var found bool
	for _, l := range strings.Split(stderr.String(), "\n") {
		var ev map[string]any
		if json.Unmarshal([]byte(l), &ev) == nil && ev["step"] == "provision_error" {
			found = ev["code"] == "server_exists" && ev["server_id"] == "777"
		}
	}
	if !found {
		t.Fatalf("no provision_error line with code+server_id: %s", stderr.String())
	}
	body, _ := os.ReadFile(path)
	if !strings.Contains(string(body), `"ev":"failed"`) || !strings.Contains(string(body), `"code":"server_exists"`) {
		t.Fatalf("journal has no failed line: %s", body)
	}
	if stdout.Len() != 0 {
		t.Fatal("a failed provision printed a record")
	}
}

func TestProvisionCLI_ResumeUnsupportedExits3(t *testing.T) {
	fake := &fakeProvisioner{err: provider.Coded(provider.CodeResumeUnsupported, errors.New("vultr cannot"))}
	withFakeProvider(t, fake)
	var stdout, stderr bytes.Buffer
	if rc := Run(provisionArgs(t, filepath.Join(t.TempDir(), "j.jsonl")), &stdout, &stderr); rc != 3 {
		t.Fatalf("rc=%d, want 3; %s", rc, stderr.String())
	}
}
