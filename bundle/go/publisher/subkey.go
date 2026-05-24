package publisher

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"daal/bundle-go/bundle"
)

// SubkeyCert is the canonical-JSON cert binding a subkey to a root key.
type SubkeyCert struct {
	V                  int    `json:"v"`
	Kind               string `json:"kind"`
	RootFingerprintHex string `json:"root_fingerprint_hex"`
	SubkeyPubHex       string `json:"subkey_pub_hex"`
	ValidFrom          string `json:"valid_from"`
	ValidUntil         string `json:"valid_until"`
	Label              string `json:"label"`
	SignatureHex       string `json:"signature_hex"`
}

// SubkeyOptions configures subkey issuance.
type SubkeyOptions struct {
	RootPrivPath string
	OutDir       string
	Validity     time.Duration
	Label        string
}

// SubkeyArtifacts is what Subkey writes to disk and returns to callers.
type SubkeyArtifacts struct {
	SubkeyDir       string
	SubkeyPubPath   string
	SubkeyPrivPath  string
	SubkeyCertPath  string
	SubkeyMetaPath  string
	Cert            SubkeyCert
	SubkeyPubBytes  ed25519.PublicKey
	SubkeyPrivBytes ed25519.PrivateKey
}

// Subkey generates a new Ed25519 subkey, writes it under
// OutDir/subkeys/<fingerprint>/, and produces a root-signed canonical-JSON
// cert.
func Subkey(opts SubkeyOptions) (*SubkeyArtifacts, error) {
	if opts.RootPrivPath == "" || opts.OutDir == "" || opts.Validity <= 0 {
		return nil, fmt.Errorf("--root-priv, --out-dir, and a positive --validity are required")
	}
	rootPriv, err := LoadPriv(opts.RootPrivPath)
	if err != nil {
		return nil, err
	}
	rootPub := ed25519.PublicKey(rootPriv.Public().(ed25519.PublicKey))
	rootFP := bundle.PublisherFingerprint(rootPub).Hex

	subPub, subPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate subkey: %w", err)
	}
	subFP := bundle.PublisherFingerprint(subPub).Hex
	subDir := filepath.Join(opts.OutDir, "subkeys", subFP)
	if err := os.MkdirAll(subDir, keystoreDirMode); err != nil {
		return nil, err
	}
	if err := os.Chmod(subDir, keystoreDirMode); err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	cert := SubkeyCert{
		V:                  1,
		Kind:               "subkey_cert",
		RootFingerprintHex: rootFP,
		SubkeyPubHex:       hex.EncodeToString(subPub),
		ValidFrom:          now.Format(time.RFC3339),
		ValidUntil:         now.Add(opts.Validity).Format(time.RFC3339),
		Label:              opts.Label,
	}
	signed, err := signCanonical(cert, "signature_hex", rootPriv)
	if err != nil {
		return nil, err
	}
	cert.SignatureHex = signed

	certBytes, err := json.MarshalIndent(cert, "", "  ")
	if err != nil {
		return nil, err
	}
	certBytes = append(certBytes, '\n')

	subPubPath := filepath.Join(subDir, "subkey.pub")
	subPrivPath := filepath.Join(subDir, "subkey.priv")
	subCertPath := filepath.Join(subDir, "subkey.cert")
	subMetaPath := filepath.Join(subDir, "subkey.meta.json")

	if err := writeFileAtomic(subPubPath, subPub, pubFileMode); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(subPrivPath, subPriv, privFileMode); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(subCertPath, certBytes, pubFileMode); err != nil {
		return nil, err
	}
	meta := map[string]any{
		"v":                    1,
		"label":                opts.Label,
		"valid_from":           cert.ValidFrom,
		"valid_until":          cert.ValidUntil,
		"root_fingerprint_hex": rootFP,
		"subkey_fingerprint":   subFP,
	}
	metaBytes, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return nil, err
	}
	metaBytes = append(metaBytes, '\n')
	if err := writeFileAtomic(subMetaPath, metaBytes, pubFileMode); err != nil {
		return nil, err
	}

	return &SubkeyArtifacts{
		SubkeyDir:       subDir,
		SubkeyPubPath:   subPubPath,
		SubkeyPrivPath:  subPrivPath,
		SubkeyCertPath:  subCertPath,
		SubkeyMetaPath:  subMetaPath,
		Cert:            cert,
		SubkeyPubBytes:  subPub,
		SubkeyPrivBytes: subPriv,
	}, nil
}

// VerifySubkeyCert returns nil if cert is well-formed, signed by rootPub,
// and currently inside its validity window.
func VerifySubkeyCert(cert SubkeyCert, rootPub ed25519.PublicKey, now time.Time) error {
	if cert.V != 1 || cert.Kind != "subkey_cert" {
		return fmt.Errorf("subkey cert: unsupported version or kind")
	}
	subPub, err := hex.DecodeString(cert.SubkeyPubHex)
	if err != nil || len(subPub) != ed25519.PublicKeySize {
		return fmt.Errorf("subkey cert: invalid subkey_pub_hex")
	}
	if bundle.PublisherFingerprint(rootPub).Hex != cert.RootFingerprintHex {
		return fmt.Errorf("subkey cert: root fingerprint mismatch")
	}
	from, err1 := time.Parse(time.RFC3339, cert.ValidFrom)
	until, err2 := time.Parse(time.RFC3339, cert.ValidUntil)
	if err1 != nil || err2 != nil {
		return fmt.Errorf("subkey cert: invalid validity timestamps")
	}
	if now.Before(from) || !now.Before(until) {
		return fmt.Errorf("subkey cert: outside validity window")
	}
	return verifyCanonical(cert, "signature_hex", cert.SignatureHex, rootPub)
}
