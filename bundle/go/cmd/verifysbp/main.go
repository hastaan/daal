package main

import (
	"archive/zip"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"daal/bundle-go/bundle"
)

type bra []byte

func (b bra) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(b)) {
		return 0, io.EOF
	}
	n := copy(p, b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func mustEntry(zr *zip.Reader, name string) []byte {
	for _, f := range zr.File {
		if f.Name == name {
			rc, err := f.Open()
			if err != nil {
				panic(err)
			}
			defer rc.Close()
			b, err := io.ReadAll(rc)
			if err != nil {
				panic(err)
			}
			return b
		}
	}
	panic("missing entry: " + name)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: verifysbp <file.sbp>")
		os.Exit(2)
	}
	path := os.Args[1]
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	zr, err := zip.NewReader(bra(data), int64(len(data)))
	if err != nil {
		panic(err)
	}
	for _, f := range zr.File {
		fmt.Println("entry:", f.Name, "size:", f.UncompressedSize64)
	}
	manB := mustEntry(zr, "manifest.json")
	sigB := mustEntry(zr, "manifest.sig")
	pubB := mustEntry(zr, "publisher.pub")
	fmt.Println("manifest_len:", len(manB), "sig_len:", len(sigB), "pub_len:", len(pubB))

	var m bundle.Manifest
	if err := json.Unmarshal(manB, &m); err != nil {
		panic("unmarshal manifest: " + err.Error())
	}
	canon, err := bundle.CanonicalManifestJSON(m)
	if err != nil {
		panic("canonical: " + err.Error())
	}
	fmt.Println("canonical_len:", len(canon))
	previewLen := 300
	if len(canon) < previewLen {
		previewLen = len(canon)
	}
	fmt.Println("canonical_prefix:", string(canon[:previewLen]))
	if outPath := os.Getenv("DUMP_CANON"); outPath != "" {
		if err := os.WriteFile(outPath, canon, 0o644); err != nil {
			panic(err)
		}
		fmt.Println("dumped go canonical to", outPath)
	}

	if ed25519.Verify(ed25519.PublicKey(pubB), canon, sigB) {
		fmt.Println("[OK] go ed25519 verify against canonical(manifest) passes")
	} else {
		fmt.Println("[FAIL] go ed25519 verify against canonical(manifest) FAILS")
		// Also try verifying against the raw manifest.json bytes — if THAT
		// passes, the publisher signed the raw bytes (not canonical).
		if ed25519.Verify(ed25519.PublicKey(pubB), manB, sigB) {
			fmt.Println("[!!] but verify against RAW manifest.json passes — publisher signs raw, not canonical")
		}
	}
	if err := bundle.VerifyManifest(m, sigB, ed25519.PublicKey(pubB)); err != nil {
		fmt.Println("bundle.VerifyManifest err:", err)
	} else {
		fmt.Println("bundle.VerifyManifest ok")
	}
	fmt.Println("---")
	fmt.Println("manifest_raw_first300:", string(manB[:min(len(manB), 300)]))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
