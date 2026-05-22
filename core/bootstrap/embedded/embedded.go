// Package embedded loads the Tier-1/2 bootstrap material baked into every
// build. The fixtures under fixtures/ are produced by
// `go run daal/core/bootstrap/internal/cmd/genembedded ./fixtures`.
//
// Production builds replace the fixtures directory with operator-signed
// keys before tagging the V1.7 first-publisher release. The on-disk file
// shape is identical, so the swap is a directory-level operation only.
package embedded

import (
	"crypto/ed25519"
	"embed"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"

	"daal/bundle-go/bundle"
	hbootstrap "daal/core/bootstrap"
)

//go:embed fixtures/*.pub fixtures/*.json fixtures/*.sbp
var fixturesFS embed.FS

// LoadManifest reads the embedded fixtures into a Manifest the bootstrap
// Provider can consume. It returns a fresh copy on every call so callers
// can safely mutate the result.
func LoadManifest() (*hbootstrap.Manifest, error) {
	rootPub, err := readPub("fixtures/project-root.pub")
	if err != nil {
		return nil, fmt.Errorf("embedded: project-root.pub: %w", err)
	}
	display, err := readDisplayMap("fixtures/publisher-display.json")
	if err != nil {
		return nil, fmt.Errorf("embedded: publisher-display.json: %w", err)
	}
	pubMap := map[string]ed25519.PublicKey{}
	dirEntries, err := fixturesFS.ReadDir("fixtures")
	if err != nil {
		return nil, err
	}
	for _, e := range dirEntries {
		name := e.Name()
		if !strings.HasPrefix(name, "publisher-") || !strings.HasSuffix(name, ".pub") {
			continue
		}
		pub, err := readPub("fixtures/" + name)
		if err != nil {
			return nil, fmt.Errorf("embedded: %s: %w", name, err)
		}
		fp := bundle.PublisherFingerprint(pub).Hex
		pubMap[fp] = pub
	}
	primary, err := readPointerSet("fixtures/pointers-primary.json")
	if err != nil {
		return nil, fmt.Errorf("embedded: pointers-primary.json: %w", err)
	}
	fallback, err := readPointerSet("fixtures/pointers-fallback.json")
	if err != nil {
		return nil, fmt.Errorf("embedded: pointers-fallback.json: %w", err)
	}
	seeds := [][]byte{}
	for _, e := range dirEntries {
		name := e.Name()
		if !strings.HasPrefix(name, "tier2-seed-") || !strings.HasSuffix(name, ".sbp") {
			continue
		}
		body, err := fixturesFS.ReadFile("fixtures/" + name)
		if err != nil {
			return nil, fmt.Errorf("embedded: %s: %w", name, err)
		}
		seeds = append(seeds, body)
	}
	return &hbootstrap.Manifest{
		ProjectRootPub:        rootPub,
		PublisherRootPubs:     pubMap,
		PublisherDisplayNames: display,
		PrimaryPointers:       primary,
		FallbackPointers:      fallback,
		Tier2Seeds:            seeds,
	}, nil
}

func readPub(path string) (ed25519.PublicKey, error) {
	body, err := fixturesFS.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(body)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	if len(block.Bytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("bad pubkey size in %s: %d", path, len(block.Bytes))
	}
	return ed25519.PublicKey(append([]byte(nil), block.Bytes...)), nil
}

func readPointerSet(path string) (hbootstrap.PointerSet, error) {
	body, err := fixturesFS.ReadFile(path)
	if err != nil {
		return hbootstrap.PointerSet{}, err
	}
	var out hbootstrap.PointerSet
	if err := json.Unmarshal(body, &out); err != nil {
		return hbootstrap.PointerSet{}, err
	}
	return out, nil
}

func readDisplayMap(path string) (map[string]string, error) {
	body, err := fixturesFS.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out map[string]string
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out, nil
}
