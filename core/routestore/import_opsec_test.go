package routestore_test

// Phase FRP-2 (Phase 30) OPSEC: the bundle import path MUST NOT
// open a network connection. Position B (no telemetry; no engine
// emitting bytes the user did not initiate) is invariant 23 of the
// FRP-2 phase doc; freshness_url is recorded as a string only and
// never fetched at import time. FRP-8 introduces the freshness fetch
// later via the existing tunneled-fetch path.
//
// This test greps the source tree under bundle/go/importer/,
// core/trust/, and core/routestore/ (excluding *_test.go) for
// `net.Dial`, `http.Client`, or `"net/http"` references. Any hit
// is an OPSEC regression.
//
// Mirrors the property the Phase 1A handover established for
// `daal-publish` (no-network at publish time).

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// testRepoRoot resolves the repo root from this test file's location,
// so the test works regardless of where the repo is checked out (CI
// workspaces are not /home/daal).
func testRepoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	// .../core/routestore/import_opsec_test.go → repo root.
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func TestImportPathHasNoNetwork(t *testing.T) {
	// Roots to scan, relative to this test file's package directory
	// (core/routestore/). Use repo-anchored absolute paths so the
	// test is robust against `go test` working-directory quirks.
	repoRoot := testRepoRoot()
	roots := []string{
		filepath.Join(repoRoot, "bundle/go/importer"),
		filepath.Join(repoRoot, "core/trust"),
		filepath.Join(repoRoot, "core/routestore"),
	}
	// Forbidden substrings; these are the entry points an HTTP
	// client or raw socket would use. We grep substrings rather
	// than parse imports because helper functions in third-party
	// packages can also drag in network behavior.
	forbidden := []string{
		`net.Dial`,
		`http.Client`,
		`"net/http"`,
	}

	var hits []string
	for _, root := range roots {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			if !strings.HasSuffix(path, ".go") {
				return nil
			}
			if strings.HasSuffix(path, "_test.go") {
				return nil
			}
			body, rErr := os.ReadFile(path)
			if rErr != nil {
				return rErr
			}
			for _, sub := range forbidden {
				if strings.Contains(string(body), sub) {
					hits = append(hits, path+": contains "+sub)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	if len(hits) > 0 {
		t.Fatalf("Position-B OPSEC violation: import path references network primitives:\n  %s",
			strings.Join(hits, "\n  "))
	}
}
