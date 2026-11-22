package cloudflare

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// IssueAndPersistOriginCert issues one Cloudflare Origin CA certificate
// for hostnames and writes it to outDir/origin_ca.{pem,key} at mode
// 0600. Returns the issued certificate's id and fingerprint plus the
// paths; the private key is never kept in any struct that is persisted.
//
// ProvisionFront asks for the zone and `*.<zone>`, so rotating the
// hostname inside the zone needs no new certificate.
//
// The certificate is valid for 5475 days (Cloudflare's default) unless
// validityDays > 0.
func IssueAndPersistOriginCert(
	ctx context.Context,
	cf CFClient,
	cfToken []byte,
	hostnames []string,
	outDir string,
	validityDays int,
) (cert OriginCert, certPath, privPath string, err error) {
	if len(hostnames) == 0 {
		return OriginCert{}, "", "", fmt.Errorf("origin_ca: hostnames required")
	}
	if outDir == "" {
		return OriginCert{}, "", "", fmt.Errorf("origin_ca: outDir required")
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return OriginCert{}, "", "", fmt.Errorf("origin_ca: mkdir outDir: %w", err)
	}
	days := validityDays
	if days <= 0 {
		days = 5475
	}
	cert, err = cf.IssueOriginCert(ctx, cfToken, hostnames, days)
	if err != nil {
		return OriginCert{}, "", "", fmt.Errorf("%w: %v", ErrOriginCAIssueFailed, scrub(err, cfToken))
	}
	if len(cert.CertPEM) == 0 || len(cert.KeyPEM) == 0 {
		return cert, "", "", fmt.Errorf("%w: empty cert or priv", ErrOriginCAIssueFailed)
	}
	defer func() { zero(cert.KeyPEM); cert.KeyPEM = nil }()

	certPath = filepath.Join(outDir, "origin_ca.pem")
	privPath = filepath.Join(outDir, "origin_ca.key")
	if err := writeMode0600(certPath, cert.CertPEM); err != nil {
		return cert, "", "", fmt.Errorf("origin_ca: write cert: %w", err)
	}
	if err := writeMode0600(privPath, cert.KeyPEM); err != nil {
		_ = os.Remove(certPath)
		return cert, "", "", fmt.Errorf("origin_ca: write priv: %w", err)
	}
	return cert, certPath, privPath, nil
}

// writeMode0600 writes b to path with mode 0600 (POSIX). An existing
// file is replaced, and its mode is tightened too.
func writeMode0600(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
