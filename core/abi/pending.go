package abi

import (
	"errors"
	"os"
	"path/filepath"
)

// persistPendingPrompt stores a pending bundle on disk under
// stateDir/pending/<fingerprint>.sbp. Pending prompts MUST survive process
// restarts; the CLI relies on it.
func (c *Core) persistPendingPrompt(fingerprint string, body []byte) error {
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
	path := filepath.Join(c.stateDir, "pending", fingerprint+".sbp")
	return os.ReadFile(path)
}

func (c *Core) deletePendingPrompt(fingerprint string) error {
	if c.stateDir == "" {
		return nil
	}
	path := filepath.Join(c.stateDir, "pending", fingerprint+".sbp")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
