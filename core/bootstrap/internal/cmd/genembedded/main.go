// Command genembedded writes Tier-1/2 fixtures into core/bootstrap/embedded/fixtures.
// Run via `go run ./core/bootstrap/internal/cmd/genembedded` from repo root.
package main

import (
	"fmt"
	"os"
	"time"

	"daal/core/bootstrap/internal/fixtures"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: genembedded <output-dir>")
		os.Exit(1)
	}
	outDir := os.Args[1]
	now := time.Now().UTC().Truncate(time.Second)

	b, err := fixtures.Generate(fixtures.Options{
		Now:              now,
		DirectoryURL:     "https://bootstrap-primary.daal.example/dir.sbp",
		FallbackURL:      "https://bootstrap-fallback.daal.example/dir.sbp",
		NumPublishers:    2,
		NumTier2Seeds:    3,
		WithDirectorySBP: false, // directory is fetched at runtime, not embedded
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "generate:", err)
		os.Exit(1)
	}
	if err := fixtures.WriteBundle(outDir, b); err != nil {
		fmt.Fprintln(os.Stderr, "write:", err)
		os.Exit(1)
	}
	fmt.Printf("wrote embedded fixtures to %s\n", outDir)
	fmt.Printf("project-root fingerprint: %x\n", []byte(b.ProjectRootPub))
}
