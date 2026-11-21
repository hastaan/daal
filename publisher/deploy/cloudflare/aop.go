package cloudflare

// Authenticated Origin Pull, zone level, with a certificate of the
// relay's own.
//
// Why not Cloudflare's shared origin-pull certificate. With the shared
// one, the origin trusts a CA that signs the client certificate EVERY
// Cloudflare zone presents, so any Cloudflare customer can point a
// proxied record at the relay's address and pass the origin's client
// check. Cloudflare's own documentation says the shared certificate
// proves only that the request came through Cloudflare, not through
// this zone. The relay's door should open for this zone alone.
//
// So Daal makes a one-off CA per front, signs one client certificate
// with it, uploads that certificate and its key to the zone
// (POST /zones/{id}/origin_tls_client_auth, the zone-level custom
// certificate), turns origin pull on, and gives the relay the CA
// certificate to verify against (`client_authentication:
// require-and-verify`, `client_certificate_path`). The CA's private key
// is dropped as soon as the client certificate is signed, and the
// client key exists only in memory and at Cloudflare. A renewal is the
// same steps again.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// aopValidity is how long the origin-pull CA and client certificate
// last. Cloudflare's limit for an uploaded zone-level certificate is
// not documented on the pages read on 2026-11-20 (part of GATE C-1).
const aopValidity = 10 * 365 * 24 * time.Hour

// AOPMaterial is one freshly made origin-pull pair. CACertPEM goes to
// the relay; ClientCertPEM and ClientKeyPEM go to Cloudflare.
type AOPMaterial struct {
	CACertPEM     []byte
	ClientCertPEM []byte
	ClientKeyPEM  []byte
}

// NewAOPMaterial makes a CA and one client certificate signed by it.
// The CA key does not survive this function.
func NewAOPMaterial(now time.Time) (AOPMaterial, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return AOPMaterial{}, err
	}
	serial := func() (*big.Int, error) {
		return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	}
	caSerial, err := serial()
	if err != nil {
		return AOPMaterial{}, err
	}
	// Neutral subject names: the zone owner and Cloudflare see these.
	caTmpl := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "origin pull CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(aopValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return AOPMaterial{}, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return AOPMaterial{}, err
	}
	clKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return AOPMaterial{}, err
	}
	clSerial, err := serial()
	if err != nil {
		return AOPMaterial{}, err
	}
	clTmpl := &x509.Certificate{
		SerialNumber: clSerial,
		Subject:      pkix.Name{CommonName: "origin pull"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(aopValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clDER, err := x509.CreateCertificate(rand.Reader, clTmpl, caCert, &clKey.PublicKey, caKey)
	if err != nil {
		return AOPMaterial{}, err
	}
	clKeyDER, err := x509.MarshalECPrivateKey(clKey)
	if err != nil {
		return AOPMaterial{}, err
	}
	return AOPMaterial{
		CACertPEM:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		ClientCertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clDER}),
		ClientKeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: clKeyDER}),
	}, nil
}

// SetupAOP makes the material, uploads the client certificate, writes
// the CA certificate to outDir/aop_ca.pem and returns its path and
// Cloudflare's certificate id. It does NOT turn origin pull on; the
// provider does that as its own undoable step.
func SetupAOP(ctx context.Context, cf CFClient, cfToken []byte, zoneID, outDir string, now time.Time) (caPath, certID string, err error) {
	if zoneID == "" {
		return "", "", fmt.Errorf("aop: zoneID required")
	}
	if outDir == "" {
		return "", "", fmt.Errorf("aop: outDir required")
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return "", "", fmt.Errorf("aop: mkdir outDir: %w", err)
	}
	mat, err := NewAOPMaterial(now)
	if err != nil {
		return "", "", fmt.Errorf("aop: make certificates: %w", err)
	}
	defer zero(mat.ClientKeyPEM)
	certID, err = cf.UploadAOPCert(ctx, cfToken, zoneID, mat.ClientCertPEM, mat.ClientKeyPEM)
	if err != nil {
		return "", "", fmt.Errorf("%w: upload client certificate: %v", ErrAOPEnableFailed, scrub(err, cfToken))
	}
	caPath = filepath.Join(outDir, "aop_ca.pem")
	if err := writeMode0600(caPath, mat.CACertPEM); err != nil {
		return "", certID, fmt.Errorf("aop: write CA certificate: %w", err)
	}
	return caPath, certID, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
