package cloudflare

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// EnableAOPAndPersistClientCert enables Authenticated Origin Pulls
// on the supplied zone, fetches the Cloudflare-signed client cert
// the origin must present back to the edge, and writes it to disk
// at mode 0600 under outDir/aop_client.pem. Returns the on-disk
// path; the cloud-init template reads it at provision time.
//
// Idempotent: re-running on a zone that already has AOP enabled
// is a no-op (the underlying CFClient implementation enforces this).
func EnableAOPAndPersistClientCert(
	ctx context.Context,
	cf CFClient,
	cfToken []byte,
	zoneID string,
	outDir string,
) (clientCertPath string, err error) {
	if zoneID == "" {
		return "", fmt.Errorf("aop: zoneID required")
	}
	if outDir == "" {
		return "", fmt.Errorf("aop: outDir required")
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return "", fmt.Errorf("aop: mkdir outDir: %w", err)
	}

	if err := cf.EnableAOP(ctx, cfToken, zoneID); err != nil {
		return "", fmt.Errorf("%w: %v", ErrAOPEnableFailed, err)
	}
	certPEM, err := cf.FetchAOPClientCert(ctx, cfToken, zoneID)
	if err != nil {
		return "", fmt.Errorf("aop: fetch client cert: %w", err)
	}
	if len(certPEM) == 0 {
		return "", fmt.Errorf("aop: client cert empty")
	}
	clientCertPath = filepath.Join(outDir, "aop_client.pem")
	if err := writeMode0600(clientCertPath, certPEM); err != nil {
		return "", fmt.Errorf("aop: write client cert: %w", err)
	}
	return clientCertPath, nil
}
