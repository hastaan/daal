package abi

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A trust prompt the user never answers must not keep the decoded route
// pack on disk forever. Only ResolveTrustPrompt deletes a pending entry,
// so abandoning the prompt — closing the sheet, being interrupted, or
// deciding not to trust the sender — used to leave plaintext route
// credentials at mode 0600 with nothing to reap them. Step 11 makes that
// the ordinary outcome of both offline lanes, not a rare one.
func TestSweepPendingPromptsRemovesOnlyStaleEntries(t *testing.T) {
	dir := t.TempDir()
	c := &Core{stateDir: dir}
	pend := filepath.Join(dir, "pending")
	if err := os.MkdirAll(pend, 0o700); err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	write := func(name string, age time.Duration) string {
		p := filepath.Join(pend, name)
		if err := os.WriteFile(p, []byte("PK\x03\x04pretend-bundle"), 0o600); err != nil {
			t.Fatal(err)
		}
		mt := now.Add(-age)
		if err := os.Chtimes(p, mt, mt); err != nil {
			t.Fatal(err)
		}
		return p
	}

	fresh := write("aa11.sbp", time.Hour)
	stale := write("bb22.sbp", PendingPromptTTL+time.Hour)
	// A crash between WriteFile and Rename leaves a .tmp nothing claims.
	staleTmp := write("cc33.sbp.tmp", PendingPromptTTL+time.Hour)
	// Anything else in the directory is left alone.
	other := write("notes.txt", PendingPromptTTL+time.Hour)

	got := c.sweepPendingPrompts(PendingPromptTTL, now)
	if got != 2 {
		t.Fatalf("removed %d, want 2", got)
	}
	for _, p := range []string{stale, staleTmp} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("stale entry survived: %s", p)
		}
	}
	for _, p := range []string{fresh, other} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("entry that should have been kept is gone: %s (%v)", p, err)
		}
	}
}

// A pending entry that is still inside the TTL must survive a restart —
// the CLI resolves prompts across process boundaries, so this store is
// deliberately NOT a launch-wipe like the staging directories.
func TestSweepPendingPromptsKeepsPromptsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	c := &Core{stateDir: dir}
	fp := "abcdef0123456789"
	if err := c.persistPendingPrompt(fp, []byte("body")); err != nil {
		t.Fatal(err)
	}
	c.sweepPendingPrompts(PendingPromptTTL, time.Now())
	if _, err := c.loadPendingPrompt(fp); err != nil {
		t.Fatalf("a fresh prompt was swept: %v", err)
	}
}

// The fingerprint crosses the FFI boundary as a bare string and is used
// to build a path. It must not be able to name a file outside the
// pending directory.
func TestPendingPathCannotEscape(t *testing.T) {
	dir := t.TempDir()
	c := &Core{stateDir: dir}
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("do not read or delete me"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, bad := range []string{
		"../secret", "../../etc/passwd", "a/b", "", "..",
		"zz-not-hex", "aa bb",
	} {
		if _, err := c.loadPendingPrompt(bad); err == nil {
			t.Errorf("loadPendingPrompt accepted %q", bad)
		}
		if err := c.persistPendingPrompt(bad, []byte("x")); err == nil {
			t.Errorf("persistPendingPrompt accepted %q", bad)
		}
		_ = c.deletePendingPrompt(bad)
	}
	if _, err := os.Stat(secret); err != nil {
		t.Fatalf("a file outside pending/ was deleted: %v", err)
	}
}
