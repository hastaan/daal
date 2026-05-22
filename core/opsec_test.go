package core_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoNetworkCallSitesInCore enforces the CC.6 zero-telemetry invariant
// across the core/ tree: no Go file outside test files may reference
// net/http or net.Dial. The lone exception is engine/probe.go which
// performs *local* probes — and even there, no http client is used.
func TestNoNetworkCallSitesInCore(t *testing.T) {
	root := repoRoot(t)
	forbidden := []string{
		"net/http",
		"http.Get(",
		"http.Post(",
		"http.Client",
		"http.NewRequest",
	}
	allowed := map[string]bool{
		// No allowed exceptions; share/* speaks raw HTTP/1.1 over
		// tls.Conn and net.Listen, deliberately avoiding net/http.
	}
	err := filepath.Walk(filepath.Join(root, "core"), func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if allowed[filepath.Base(path)] {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		stripped := stripComments(string(body))
		for _, bad := range forbidden {
			if strings.Contains(stripped, bad) {
				t.Errorf("%s contains forbidden token %q", path, bad)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// stripComments removes line and block comments before scanning a Go
// source file for forbidden tokens. Comments document non-use of the
// banned APIs (e.g., "this does NOT use net/http"), and we don't want
// those to trip the OPSEC test.
func stripComments(src string) string {
	var b strings.Builder
	inLineCmt := false
	inBlockCmt := false
	inString := false
	inRawString := false
	prev := byte(0)
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch {
		case inLineCmt:
			if c == '\n' {
				inLineCmt = false
				b.WriteByte(c)
			}
		case inBlockCmt:
			if prev == '*' && c == '/' {
				inBlockCmt = false
			}
		case inString:
			b.WriteByte(c)
			if c == '"' && prev != '\\' {
				inString = false
			}
		case inRawString:
			b.WriteByte(c)
			if c == '`' {
				inRawString = false
			}
		default:
			if c == '/' && i+1 < len(src) && src[i+1] == '/' {
				inLineCmt = true
				i++
				continue
			}
			if c == '/' && i+1 < len(src) && src[i+1] == '*' {
				inBlockCmt = true
				i++
				continue
			}
			if c == '"' {
				inString = true
				b.WriteByte(c)
				continue
			}
			if c == '`' {
				inRawString = true
				b.WriteByte(c)
				continue
			}
			b.WriteByte(c)
		}
		prev = c
	}
	return b.String()
}

// TestNoGroupBasedLabels enforces the V0.1 user-class neutrality rule on
// every code path that crosses an app surface. "ordinary user", "activist",
// "journalist", "high-risk", and "device-seizure" are reserved for the
// threat-model document only.
func TestNoGroupBasedLabels(t *testing.T) {
	root := repoRoot(t)
	forbidden := []string{
		"ordinary user",
		"activist",
		"journalist",
		"high-risk",
		"device-seizure",
		"high risk",
	}
	roots := []string{
		filepath.Join(root, "core"),
		filepath.Join(root, "client-android", "app", "src", "main"),
		filepath.Join(root, "cmd"),
	}
	for _, dir := range roots {
		filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			if !shouldScan(path) {
				return nil
			}
			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			// The OPSEC test file legitimately contains these labels in
			// its denylist constants; skip self-detection.
			if strings.HasSuffix(path, "opsec_test.go") {
				return nil
			}
			lower := strings.ToLower(string(body))
			for _, bad := range forbidden {
				if strings.Contains(lower, bad) {
					t.Errorf("%s contains forbidden group-based label %q", path, bad)
				}
			}
			return nil
		})
	}
}

func shouldScan(path string) bool {
	for _, ext := range []string{".go", ".kt", ".kts", ".xml", ".md"} {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

// TestBootstrapNoNetHTTP enforces that core/bootstrap, the Phase 1D
// directory fetcher, never imports net/http. The fetcher hand-rolls
// HTTP/1.1 over tls.Conn (per specs/bootstrap-pointer-v1.md and
// specs/bootstrap-directory-v1.md) so the OPSEC contract that "no
// net/http in core/" still holds even after we acquired a network-facing
// fetcher.
func TestBootstrapNoNetHTTP(t *testing.T) {
	root := repoRoot(t)
	bad := []string{
		`"net/http"`,
		`"0.0.0.0"`,
		`"::"`,
		`http.Get(`,
		`http.Post(`,
		`http.Client`,
		`http.NewRequest`,
	}
	dir := filepath.Join(root, "core", "bootstrap")
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		stripped := stripComments(string(body))
		for _, b := range bad {
			if strings.Contains(stripped, b) {
				t.Errorf("%s contains forbidden token %q", path, b)
			}
		}
		return nil
	})
}

// TestNoNetHTTPInRefresh enforces the Phase 1.5A invariant that
// core/refresh never reaches for net/http and never logs subscription
// URLs. Subscription bodies are fetched through bootstrap.FetchRaw,
// which hand-rolls HTTP/1.1 over tls.Conn.
func TestNoNetHTTPInRefresh(t *testing.T) {
	root := repoRoot(t)
	bad := []string{
		`"net/http"`,
		`http.Get(`,
		`http.Post(`,
		`http.Client`,
		`http.NewRequest`,
		// the URL must never be log-formatted
		"log.Printf(",
		"fmt.Println(",
	}
	dir := filepath.Join(root, "core", "refresh")
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		stripped := stripComments(string(body))
		for _, b := range bad {
			if strings.Contains(stripped, b) {
				t.Errorf("%s contains forbidden token %q", path, b)
			}
		}
		// Subscription URL strings must never appear in audit ref ids,
		// log lines, or fmt.Errorf messages. We allow `urlBytes` /
		// `string(urlBytes)` since those are passed into bootstrap.FetchRaw,
		// but reject any direct format-with-URL pattern.
		if strings.Contains(stripped, "urlBytes)") &&
			strings.Contains(stripped, "Errorf") &&
			strings.Contains(stripped, "%s") &&
			strings.Contains(stripped, "url=") {
			t.Errorf("%s appears to log a URL via fmt.Errorf", path)
		}
		return nil
	})
}

// TestNoTelemetryInDesktop enforces CC.6 across the client trees
// (`client-ui` for React/TS, `client-shell/tauri` for Rust): no file
// may import a telemetry SDK or open a connection to a
// project-controlled endpoint. We allow `console.error` for genuine
// error surfaces; anything that could be confused with analytics is
// rejected by name.
func TestNoTelemetryInDesktop(t *testing.T) {
	root := repoRoot(t)
	bad := []string{
		"sentry",
		"mixpanel",
		"segment.io",
		"amplitude",
		"posthog",
		"datadog",
		"telemetry",
		"google-analytics",
		"googletagmanager",
		"hotjar",
		"firebase/analytics",
	}
	scanRoots := []string{
		filepath.Join(root, "client-ui"),
		filepath.Join(root, "client-shell"),
	}
	for _, dir := range scanRoots {
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			// Skip target/ build artifacts and node_modules.
			if strings.Contains(path, "/target/") || strings.Contains(path, "/node_modules/") {
				return nil
			}
			// Only scan source files; binaries / fixtures are uninteresting.
			if !shouldScanDesktop(path) {
				return nil
			}
			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			// Strip JS/TS/Rust line + block comments before scanning so a
			// "no telemetry" docstring doesn't trip the test.
			lower := strings.ToLower(stripComments(string(body)))
			for _, b := range bad {
				if strings.Contains(lower, b) {
					t.Errorf("%s contains forbidden token %q (CC.6)", path, b)
				}
			}
			return nil
		})
	}
}

func shouldScanDesktop(p string) bool {
	for _, ext := range []string{".rs", ".ts", ".tsx", ".js", ".jsx", ".json", ".html", ".css"} {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	return false
}

// TestSoakDriverNetworkSurfaceContained enforces that the Phase 1.5C
// blackout-soak rig under `test-rigs/distribution-failure/soak-driver/`
// does not introduce out-of-tree network calls. The rig is allowed to
// import `net/http` only inside `internal/origin/` (its fake-origin
// HTTP server) and `internal/artifacts/` (no, actually that doesn't
// import http; we still allow it for the redact path's URL regex).
//
// Outside those packages, the soak driver must not touch the network.
func TestSoakDriverNetworkSurfaceContained(t *testing.T) {
	root := repoRoot(t)
	dir := filepath.Join(root, "test-rigs", "distribution-failure", "soak-driver")
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("soak-driver tree missing: %v", err)
	}
	allowedPrefixes := []string{
		filepath.Join(dir, "internal", "origin"),
	}
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		for _, p := range allowedPrefixes {
			if strings.HasPrefix(path, p) {
				return nil
			}
		}
		body, _ := os.ReadFile(path)
		stripped := stripComments(string(body))
		if strings.Contains(stripped, `"net/http"`) {
			t.Errorf("%s imports net/http outside the allowed origin/ tree", path)
		}
		return nil
	})
}

// TestShareBindsOnlyPrivate enforces that core/share never contains a
// listen on 0.0.0.0 or :: literals, and never an http.* import. The Phase
// 1C plan requires the LAN listener to bind only to RFC1918/ULA/link-local
// addresses returned by DetectPrivateAddrs.
func TestShareBindsOnlyPrivate(t *testing.T) {
	root := repoRoot(t)
	bad := []string{
		`"0.0.0.0"`,
		`"::"`,
		`net/http"`,
	}
	dir := filepath.Join(root, "core", "share")
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		stripped := stripComments(string(body))
		for _, b := range bad {
			if strings.Contains(stripped, b) {
				t.Errorf("%s contains forbidden token %q", path, b)
			}
		}
		return nil
	})
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// /home/daal/core → /home/daal
	return filepath.Dir(wd)
}
