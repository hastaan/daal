package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// MakeLabCA writes a throw-away CA (lab-ca.pem) and one server
// certificate for the given DNS names + IPs (lab-server.pem / .key).
//
// This is the single trust substitution the rig makes for the outside
// world: the unmodified publisher binary and the unmodified box verifier
// reach "api.hetzner.cloud" and "github.com" over real TLS, and the lab
// CA (handed to them through SSL_CERT_FILE) is what makes the lab's
// servers acceptable. No product certificate check is weakened; packs,
// mgmt pins, release signatures and REALITY do not go through this CA.
func MakeLabCA(dir string, dnsNames []string, ips []string) error {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "worldbox lab CA (not a real authority)"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "worldbox lab services"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
	}
	for _, ip := range ips {
		srvTmpl.IPAddresses = append(srvTmpl.IPAddresses, net.ParseIP(ip))
	}
	// Parent must be the PARSED CA so the leaf gets an Authority Key
	// Identifier; strict verifiers (Python ≥ 3.13) reject it otherwise.
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(srvKey)
	if err != nil {
		return err
	}
	write := func(name, typ string, der []byte, mode os.FileMode) error {
		return os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), mode)
	}
	if err := write("lab-ca.pem", "CERTIFICATE", caDER, 0o644); err != nil {
		return err
	}
	caKeyDER, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		return err
	}
	if err := write("lab-ca.key", "EC PRIVATE KEY", caKeyDER, 0o600); err != nil {
		return err
	}
	if err := write("lab-server.pem", "CERTIFICATE", srvDER, 0o644); err != nil {
		return err
	}
	return write("lab-server.key", "EC PRIVATE KEY", keyDER, 0o600)
}
