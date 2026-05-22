// Package fixtures generates Tier-1/2/3 bootstrap material for tests and
// for the embedded build artifact. It is intentionally not a CLI binary;
// production keys are produced by daal-publish under the operator's HSM
// flow. This package only ships placeholder material so the V1 client can
// boot.
package fixtures

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"daal/bundle-go/bundle"
	hbootstrap "daal/core/bootstrap"
)

// Bundle holds everything Generate writes to disk. Tests can also use it
// as a pure in-memory artifact without writing files.
type Bundle struct {
	ProjectRootPub   ed25519.PublicKey
	ProjectRootPriv  ed25519.PrivateKey
	Publishers       []Publisher
	PrimaryPointers  hbootstrap.PointerSet
	FallbackPointers hbootstrap.PointerSet
	Tier2Seeds       [][]byte // raw .sbp bytes
	Directory        []byte   // raw .sbp bytes (signed by Publishers[0])
}

// Publisher is one Tier-1 publisher key + display name.
type Publisher struct {
	Name        string
	Pub         ed25519.PublicKey
	Priv        ed25519.PrivateKey
	Fingerprint string
}

// Options controls Generate.
type Options struct {
	Now              time.Time
	DirectoryURL     string
	FallbackURL      string
	NumPublishers    int  // default 2
	NumTier2Seeds    int  // default 3
	WithDirectorySBP bool // include a directory.sbp signed by Publishers[0]
}

// Generate produces a deterministic-ish (modulo Ed25519 randomness) test
// bundle. Pass into WriteBundle to materialize on disk.
func Generate(opts Options) (*Bundle, error) {
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	if opts.NumPublishers <= 0 {
		opts.NumPublishers = 2
	}
	if opts.NumTier2Seeds <= 0 {
		opts.NumTier2Seeds = 3
	}
	if opts.DirectoryURL == "" {
		opts.DirectoryURL = "https://bootstrap-primary.example.org/dir.sbp"
	}
	if opts.FallbackURL == "" {
		opts.FallbackURL = "https://bootstrap-fallback.example.org/dir.sbp"
	}

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	pubs := make([]Publisher, opts.NumPublishers)
	for i := range pubs {
		pPub, pPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		fp := bundle.PublisherFingerprint(pPub).Hex
		pubs[i] = Publisher{
			Name: fmt.Sprintf("daal-bootstrap-%d", i),
			Pub:  pPub, Priv: pPriv, Fingerprint: fp,
		}
	}

	primary := hbootstrap.PointerSet{
		V: 1, Kind: "bootstrap_pointers", Set: "primary",
		IssuedAt:   opts.Now.Format(time.RFC3339),
		ValidUntil: opts.Now.Add(365 * 24 * time.Hour).Format(time.RFC3339),
		Pointers: []hbootstrap.Pointer{
			{URL: opts.DirectoryURL, ExpectedPublisherFingerprintHex: pubs[0].Fingerprint},
		},
	}
	fallback := hbootstrap.PointerSet{
		V: 1, Kind: "bootstrap_pointers", Set: "fallback",
		IssuedAt:   opts.Now.Format(time.RFC3339),
		ValidUntil: opts.Now.Add(365 * 24 * time.Hour).Format(time.RFC3339),
		Pointers: []hbootstrap.Pointer{
			{URL: opts.FallbackURL, ExpectedPublisherFingerprintHex: pubs[0].Fingerprint},
		},
	}
	primarySigned, err := hbootstrap.SignPointerSet(primary, rootPriv)
	if err != nil {
		return nil, err
	}
	fallbackSigned, err := hbootstrap.SignPointerSet(fallback, rootPriv)
	if err != nil {
		return nil, err
	}

	// Tier-2 seeds: each is a tiny .sbp signed by Publishers[i % len(pubs)],
	// scarcity_class=emergency, valid_until=now+25d (under the 30d cap).
	seeds := make([][]byte, 0, opts.NumTier2Seeds)
	for i := 0; i < opts.NumTier2Seeds; i++ {
		signer := pubs[i%len(pubs)]
		body, err := buildEmergencyBundle(buildArgs{
			BundleType: "emergency",
			BundleID:   fmt.Sprintf("00000000-0000-0000-0000-000000000%03d", i),
			RouteID:    fmt.Sprintf("seed-route-%d", i),
			Signer:     signer,
			Now:        opts.Now,
			ExpiresAt:  opts.Now.Add(25 * 24 * time.Hour),
			Family:     bundle.TransportVLESSReality,
		})
		if err != nil {
			return nil, fmt.Errorf("tier2 seed %d: %w", i, err)
		}
		seeds = append(seeds, body)
	}

	out := &Bundle{
		ProjectRootPub:   rootPub,
		ProjectRootPriv:  rootPriv,
		Publishers:       pubs,
		PrimaryPointers:  primarySigned,
		FallbackPointers: fallbackSigned,
		Tier2Seeds:       seeds,
	}

	if opts.WithDirectorySBP {
		dir, err := buildEmergencyBundle(buildArgs{
			BundleType: hbootstrap.BundleTypeDirectory,
			BundleID:   "11111111-1111-1111-1111-111111111111",
			RouteID:    "directory-route-1",
			Signer:     pubs[0],
			Now:        opts.Now,
			ExpiresAt:  opts.Now.Add(72 * time.Hour),
			Family:     bundle.TransportVLESSReality,
		})
		if err != nil {
			return nil, fmt.Errorf("directory: %w", err)
		}
		out.Directory = dir
	}
	return out, nil
}

type buildArgs struct {
	BundleType string
	BundleID   string
	RouteID    string
	Signer     Publisher
	Now        time.Time
	ExpiresAt  time.Time
	Family     bundle.TransportFamily
}

func buildEmergencyBundle(a buildArgs) ([]byte, error) {
	manifest := bundle.Manifest{
		SpecVersion: 1,
		Publisher: bundle.PublisherInfo{
			Name:              a.Signer.Name,
			KeyFingerprintHex: a.Signer.Fingerprint,
			KeyCreatedAt:      a.Now.Format(time.RFC3339),
			TrustClass:        "official",
		},
		Bundle: bundle.BundleInfo{
			ID:               a.BundleID,
			Type:             a.BundleType,
			CreatedAt:        a.Now.Format(time.RFC3339),
			ExpiresAt:        a.ExpiresAt.Format(time.RFC3339),
			PreviousBundleID: nil,
			SupersedesKeys:   []string{},
		},
		Routes: []bundle.RouteManifestEntry{{
			ID:              a.RouteID,
			ScarcityClass:   string(bundle.ScarcityEmergency),
			TransportFamily: string(a.Family),
			ConfigPath:      "profiles/" + a.RouteID + ".json",
			ValidFrom:       a.Now.Format(time.RFC3339),
			ValidUntil:      a.ExpiresAt.Format(time.RFC3339),
		}},
	}
	profiles := map[string][]byte{
		"profiles/" + a.RouteID + ".json": []byte(`{"type":"placeholder"}`),
	}
	return bundle.BuildSignedBundleDeterministic(manifest, profiles, nil, a.Signer.Pub, a.Signer.Priv)
}

// WriteBundle materializes a Bundle on disk under `dir` in the layout the
// embedded sub-package expects.
func WriteBundle(dir string, b *Bundle) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	// Public material only; never write privates.
	if err := writePEM(filepath.Join(dir, "project-root.pub"), "ED25519 PUBLIC KEY", b.ProjectRootPub); err != nil {
		return err
	}
	for i, p := range b.Publishers {
		if err := writePEM(filepath.Join(dir, fmt.Sprintf("publisher-%d.pub", i)),
			"ED25519 PUBLIC KEY", p.Pub); err != nil {
			return err
		}
	}
	if err := writeJSON(filepath.Join(dir, "pointers-primary.json"), b.PrimaryPointers); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(dir, "pointers-fallback.json"), b.FallbackPointers); err != nil {
		return err
	}
	for i, body := range b.Tier2Seeds {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("tier2-seed-%d.sbp", i)),
			body, 0o644); err != nil {
			return err
		}
	}
	if len(b.Directory) > 0 {
		if err := os.WriteFile(filepath.Join(dir, "directory.sbp"),
			b.Directory, 0o644); err != nil {
			return err
		}
	}
	// publisher-display.json maps fingerprint → friendly name.
	display := map[string]string{}
	for _, p := range b.Publishers {
		display[p.Fingerprint] = p.Name
	}
	return writeJSON(filepath.Join(dir, "publisher-display.json"), display)
}

func writePEM(path, label string, key []byte) error {
	block := &pem.Block{Type: label, Bytes: append([]byte(nil), key...)}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0o644)
}

func writeJSON(path string, v any) error {
	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, body, 0o644)
}
