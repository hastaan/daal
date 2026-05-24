package cloudflare

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// IssueAndPersistOriginCert provisions a fresh Cloudflare Origin CA
// cert via the supplied CFClient and writes the cert + key to disk
// at mode 0600 under outDir/origin_ca.{pem,key}. Returns the public
// fingerprint hex (the only piece that lives in the FrontRecord
// JSON) plus the on-disk paths.
//
// The cert is valid for 5475 days (15 years, Cloudflare default)
// unless validityDays is supplied >0.
//
// Rule 5 of phase doc §13: this function never embeds the private
// key bytes in any in-memory struct that gets persisted to JSON.
// Callers store only the path.
func IssueAndPersistOriginCert(
	ctx context.Context,
	cf CFClient,
	cfToken []byte,
	hostnames []string,
	outDir string,
	validityDays int,
) (fingerprintHex, certPath, privPath string, err error) {
	if len(hostnames) == 0 {
		return "", "", "", fmt.Errorf("origin_ca: hostnames required")
	}
	if outDir == "" {
		return "", "", "", fmt.Errorf("origin_ca: outDir required")
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return "", "", "", fmt.Errorf("origin_ca: mkdir outDir: %w", err)
	}
	days := validityDays
	if days <= 0 {
		days = 5475
	}

	certPEM, privPEM, fp, err := cf.IssueOriginCert(ctx, cfToken, hostnames, days)
	if err != nil {
		return "", "", "", fmt.Errorf("%w: %v", ErrOriginCAIssueFailed, err)
	}
	if len(certPEM) == 0 || len(privPEM) == 0 {
		return "", "", "", fmt.Errorf("%w: empty cert or priv", ErrOriginCAIssueFailed)
	}

	certPath = filepath.Join(outDir, "origin_ca.pem")
	privPath = filepath.Join(outDir, "origin_ca.key")
	if err := writeMode0600(certPath, certPEM); err != nil {
		return "", "", "", fmt.Errorf("origin_ca: write cert: %w", err)
	}
	if err := writeMode0600(privPath, privPEM); err != nil {
		// Best-effort cleanup so we don't leave a half-state.
		_ = os.Remove(certPath)
		return "", "", "", fmt.Errorf("origin_ca: write priv: %w", err)
	}
	return fp, certPath, privPath, nil
}

// writeMode0600 writes b to path with mode 0600 (POSIX). On
// non-POSIX targets the mode is best-effort.
func writeMode0600(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
