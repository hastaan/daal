package bundle

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"sort"
	"time"
)

// BuildSignedBundleDeterministic produces a byte-stable .sbp archive for
// identical inputs. ZIP entries are sorted by name, modification time is
// zeroed, and entries use Store (no compression). This is required by the
// publisher CLI so two runs with the same inputs produce byte-identical
// outputs that can be cross-checked between operators.
func BuildSignedBundleDeterministic(manifest Manifest, profiles map[string][]byte, extras map[string][]byte, pub ed25519.PublicKey, priv ed25519.PrivateKey) ([]byte, error) {
	manifestBytes, err := CanonicalManifestJSON(manifest)
	if err != nil {
		return nil, err
	}
	sig, err := SignManifest(manifest, priv)
	if err != nil {
		return nil, err
	}

	files := map[string][]byte{
		"manifest.json": manifestBytes,
		"manifest.sig":  append([]byte(nil), sig...),
		"publisher.pub": append([]byte(nil), pub...),
	}
	for name, data := range profiles {
		if unsafeArchivePath(name) {
			return nil, ErrUnsafePath
		}
		files[name] = data
	}
	for name, data := range extras {
		if unsafeArchivePath(name) {
			return nil, ErrUnsafePath
		}
		files[name] = data
	}

	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	zeroTime := time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, name := range names {
		header := &zip.FileHeader{
			Name:     name,
			Method:   zip.Store,
			Modified: zeroTime,
		}
		w, err := zw.CreateHeader(header)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(files[name]); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
