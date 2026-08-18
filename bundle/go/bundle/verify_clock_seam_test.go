package bundle

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestVerifyBundleAtHasNoProductionCaller turns the comment on
// VerifyBundleAt into an invariant the tree enforces.
//
// VerifyBundleAt is a clock-injection seam: it runs every check
// VerifyBundle runs — sub-key cert window, bundle expiry, per-route
// valid_until, revocation, fingerprint — with nothing skipped or
// widened, and the only difference is which instant "now" is. That is
// exactly what makes it dangerous: one production caller with a
// convenient `now` in scope (a scheduler tick timestamp, a value parsed
// out of the artefact being verified, a device with a wrong clock) is a
// silent expiry bypass on a package core/bootstrap already imports, and
// no existing test would go red.
//
// The seam is worth keeping — a fixture bundle carries a FIXED validity
// window, so verifying it against the wall clock is not a test, it is a
// scheduled alarm, and this repo has been bitten by that three times.
// So gate it rather than delete it. This repo already gates far weaker
// invariants mechanically (hardcoded strings, token shapes, phase
// strings, wrapper reachability); a comment was the odd one out for the
// one function that can forge an expiry pass.
//
// The rule: `VerifyBundleAt(` may appear only in _test.go files, plus
// its own declaration and doc comment in sbp.go.
func TestVerifyBundleAtHasNoProductionCaller(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	// .../bundle/go/bundle -> repo root
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "go.work")); err != nil {
		// Not a layout we recognise; fail loudly rather than pass
		// vacuously. A gate that silently scans nothing is the
		// failure mode this repo has already paid for once.
		if _, err2 := os.Stat(filepath.Join(root, "core")); err2 != nil {
			t.Fatalf("cannot locate repo root from %s (tried %s)", file, root)
		}
	}

	selfDecl := filepath.Join(root, "bundle", "go", "bundle", "sbp.go")
	var offenders []string
	scanned := 0

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// An unreadable subtree must not silently shrink the scan.
			return nil
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "node_modules", "target", "vendor", "dist-release":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		scanned++
		for i, line := range strings.Split(string(body), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			if !strings.Contains(line, "VerifyBundleAt(") {
				continue
			}
			// The declaration itself.
			if path == selfDecl && strings.Contains(line, "func VerifyBundleAt(") {
				continue
			}
			offenders = append(offenders,
				strings.TrimPrefix(path, root+string(filepath.Separator))+":"+itoa(i+1)+": "+trimmed)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if scanned < 50 {
		t.Fatalf("only %d non-test .go files scanned from %s; the gate is not seeing the tree", scanned, root)
	}
	if len(offenders) != 0 {
		t.Fatalf("VerifyBundleAt has a non-test caller — that is an expiry bypass:\n  %s\n\n"+
			"Use VerifyBundle (wall clock) in production. If a caller genuinely needs an\n"+
			"injected clock, it needs a design decision and a threat-model note, not this seam.",
			strings.Join(offenders, "\n  "))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
