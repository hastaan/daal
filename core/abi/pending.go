package abi

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// PendingPromptTTL bounds how long an unanswered trust prompt keeps a
// decoded bundle on disk.
//
// The pending store is the one copy of a route pack that NOBODY erases.
// deletePendingPrompt is called from exactly one place — ResolveTrustPrompt
// — so it only runs when the user actually answers. A user who scans a QR,
// sees the word grid, and then closes the sheet (interrupted, or decided
// not to trust the sender) leaves plaintext route credentials at mode 0600
// forever. Step 11 makes that the NORMAL path rather than a rare one: a
// pack arriving offline is by construction from a publisher this device has
// never met, so Kind 1 — trust-prompt-needed — is the ordinary outcome of
// both new lanes.
//
// The TTL is days, not minutes, because unlike the staging directories
// (swept at 10 minutes) this store is REQUIRED to survive a restart — the
// CLI resolves prompts across process boundaries. Seven days is long enough
// that no honest workflow loses a prompt, and short enough that "I decided
// not to trust them" does not mean "keep their routes on my phone until I
// reinstall".
const PendingPromptTTL = 7 * 24 * time.Hour

// persistPendingPrompt stores a pending bundle on disk under
// stateDir/pending/<fingerprint>.sbp. Pending prompts MUST survive process
// restarts; the CLI relies on it.
func (c *Core) persistPendingPrompt(fingerprint string, body []byte) error {
	if !safePendingName(fingerprint) {
		return errors.New("abi: bad fingerprint")
	}
	dir := filepath.Join(c.stateDir, "pending")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	tmp := filepath.Join(dir, fingerprint+".sbp.tmp")
	final := filepath.Join(dir, fingerprint+".sbp")
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, final)
}

func (c *Core) loadPendingPrompt(fingerprint string) ([]byte, error) {
	if c.stateDir == "" {
		return nil, errors.New("abi: state dir not set")
	}
	if !safePendingName(fingerprint) {
		return nil, errors.New("abi: bad fingerprint")
	}
	path := filepath.Join(c.stateDir, "pending", fingerprint+".sbp")
	return os.ReadFile(path)
}

// safePendingName keeps a fingerprint from escaping the pending
// directory. A fingerprint is hex from the engine, so in the normal
// path this can never fail — but it arrives here as a bare string
// across the FFI boundary, and "../../secrets" would otherwise be a
// path to read and delete arbitrary files. The check costs nothing.
func safePendingName(fingerprint string) bool {
	if fingerprint == "" || len(fingerprint) > 128 {
		return false
	}
	for _, r := range fingerprint {
		isHex := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
		if !isHex {
			return false
		}
	}
	return true
}

// sweepPendingPrompts deletes pending bundles older than ttl. Returns the
// number removed. Called from Init, which is the only moment we can be
// sure no prompt is mid-flight in this process.
func (c *Core) sweepPendingPrompts(ttl time.Duration, now time.Time) int {
	if c.stateDir == "" {
		return 0
	}
	dir := filepath.Join(c.stateDir, "pending")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	removed := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// Sweep the temp files too: a crash between WriteFile and
		// Rename leaves a .sbp.tmp that nothing would ever claim.
		if !strings.HasSuffix(name, ".sbp") && !strings.HasSuffix(name, ".sbp.tmp") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if now.Sub(info.ModTime()) < ttl {
			continue
		}
		if err := os.Remove(filepath.Join(dir, name)); err == nil {
			removed++
		}
	}
	return removed
}

func (c *Core) deletePendingPrompt(fingerprint string) error {
	if c.stateDir == "" {
		return nil
	}
	if !safePendingName(fingerprint) {
		return nil
	}
	path := filepath.Join(c.stateDir, "pending", fingerprint+".sbp")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
