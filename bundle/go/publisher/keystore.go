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

const (
	publisherPubName  = "publisher.pub"
	publisherPrivName = "publisher.priv"
	publisherMetaName = "publisher.meta.json"
	keystoreDirMode   = 0o700
	pubFileMode       = 0o644
	privFileMode      = 0o600
)

// PublisherMeta is the on-disk descriptor for a publisher root key.
type PublisherMeta struct {
	V                 int    `json:"v"`
	Label             string `json:"label"`
	CreatedAt         string `json:"created_at"`
	KeyFingerprintHex string `json:"key_fingerprint_hex"`
	KeyFingerprintEN  string `json:"key_fingerprint_en"`
	KeyFingerprintFA  string `json:"key_fingerprint_fa"`
}

// KeygenOptions configures keygen.
type KeygenOptions struct {
	OutDir string
	Label  string
	Force  bool
}

// Keygen creates a fresh Ed25519 root key in OutDir and writes meta. It
// refuses to overwrite an existing publisher.priv unless Force is set.
func Keygen(opts KeygenOptions) (PublisherMeta, error) {
	if opts.OutDir == "" {
		return PublisherMeta{}, fmt.Errorf("--out-dir is required")
	}
	if err := os.MkdirAll(opts.OutDir, keystoreDirMode); err != nil {
		return PublisherMeta{}, err
	}
	if err := os.Chmod(opts.OutDir, keystoreDirMode); err != nil {
		return PublisherMeta{}, err
	}

	privPath := filepath.Join(opts.OutDir, publisherPrivName)
	if !opts.Force {
		if _, err := os.Stat(privPath); err == nil {
			return PublisherMeta{}, fmt.Errorf("publisher.priv already exists at %s; pass --force to overwrite", privPath)
		}
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return PublisherMeta{}, fmt.Errorf("generate key: %w", err)
	}

	if err := writeFileAtomic(privPath, priv, privFileMode); err != nil {
		return PublisherMeta{}, fmt.Errorf("write private key: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(opts.OutDir, publisherPubName), pub, pubFileMode); err != nil {
		return PublisherMeta{}, fmt.Errorf("write public key: %w", err)
	}

	fp := bundle.PublisherFingerprint(pub)
	rendered, err := bundle.RenderFingerprint(fp, defaultWordlists())
	if err != nil {
		return PublisherMeta{}, err
	}
	meta := PublisherMeta{
		V:                 1,
		Label:             opts.Label,
		CreatedAt:         time.Now().UTC().Format(time.RFC3339),
		KeyFingerprintHex: fp.Hex,
		KeyFingerprintEN:  rendered.EN,
		KeyFingerprintFA:  rendered.FA,
	}
	body, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return PublisherMeta{}, err
	}
	body = append(body, '\n')
	if err := writeFileAtomic(filepath.Join(opts.OutDir, publisherMetaName), body, pubFileMode); err != nil {
		return PublisherMeta{}, err
	}
	return meta, nil
}

// LoadPub reads a publisher public key file and validates its length.
func LoadPub(path string) (ed25519.PublicKey, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read publisher.pub: %w", err)
	}
	if len(body) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("publisher public key must be %d bytes, got %d", ed25519.PublicKeySize, len(body))
	}
	return ed25519.PublicKey(append([]byte(nil), body...)), nil
}

// LoadPriv reads an Ed25519 private key file. Errors never include private
// bytes; only filenames and lengths.
func LoadPriv(path string) (ed25519.PrivateKey, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key %s: %w", path, sanitize(err))
	}
	if len(body) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key %s has wrong length: expected %d", path, ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(append([]byte(nil), body...)), nil
}

// FingerprintHex returns SHA-256 fingerprint of an Ed25519 public key.
func FingerprintHex(pub ed25519.PublicKey) string {
	return bundle.PublisherFingerprint(pub).Hex
}

// HexEncode is a helper exported for tests.
func HexEncode(b []byte) string { return hex.EncodeToString(b) }

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// sanitize ensures error strings never echo raw key bytes by replacing any
// byte that is not printable with a placeholder.
func sanitize(err error) error {
	if err == nil {
		return nil
	}
	s := err.Error()
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7f {
			out = append(out, '?')
			continue
		}
		out = append(out, c)
	}
	return fmt.Errorf("%s", string(out))
}

// DefaultWordlists exposes the placeholder wordlists used to render
// fingerprints. The full BIP-39 and curated Persian lists are V0
// deliverables and remain test-only here.
func DefaultWordlists() bundle.Wordlists { return defaultWordlists() }

// defaultWordlists returns minimal placeholder wordlists.
func defaultWordlists() bundle.Wordlists {
	return bundle.Wordlists{
		English: []string{
			"alpha", "bravo", "charlie", "delta", "echo", "foxtrot",
			"golf", "hotel", "india", "juliet", "kilo", "lima",
			"mike", "november", "oscar", "papa",
		},
		Persian: []string{
			"یک", "دو", "سه", "چهار", "پنج", "شش", "هفت", "هشت",
			"نه", "ده", "یازده", "دوازده", "سیزده", "چهارده", "پانزده", "شانزده",
		},
	}
}
