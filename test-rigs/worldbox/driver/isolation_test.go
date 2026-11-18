package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The rig contains things that must never reach a user: a binary that
// opens a TUN and reroutes a machine's traffic (labclient), a fake cloud,
// a throw-away CA. The rule that keeps them out of a release is
// structural — nothing in the product may depend on anything under
// test-rigs/ — and these tests are what hold that rule.
//
// They are static and hermetic (no namespaces, no network), so they run
// in `./daal test` and the pre-push hook like any other unit test.

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Clean(filepath.Join(wd, "..", "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "core", "go.mod")); err != nil {
		t.Fatalf("cannot locate repo root from %s: %v", wd, err)
	}
	return root
}

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "dist-release": true, "build": true, "target": true,
	"out": true, "bin": true, "test-rigs": true, "gen": true, ".claude": true,
}

func walkProduct(t *testing.T, root string, visit func(path string)) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		visit(path)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// No product module may require or replace anything under test-rigs/.
func TestNoProductModuleDependsOnTheRig(t *testing.T) {
	root := repoRoot(t)
	n := 0
	walkProduct(t, root, func(path string) {
		if filepath.Base(path) != "go.mod" {
			return
		}
		n++
		body, _ := os.ReadFile(path)
		if strings.Contains(string(body), "test-rigs") {
			t.Errorf("%s references test-rigs: a product module must not depend on a lab binary", path)
		}
	})
	if n < 5 {
		t.Fatalf("only %d product go.mod files found; the walk is not seeing the repo", n)
	}
}

// No product Go file may import the rig, and none may carry the rig's
// lab-only markers.
func TestNoProductSourceReferencesTheRig(t *testing.T) {
	root := repoRoot(t)
	n := 0
	walkProduct(t, root, func(path string) {
		if !strings.HasSuffix(path, ".go") {
			return
		}
		n++
		body, _ := os.ReadFile(path)
		for _, needle := range []string{`"daal/test-rigs`, "worldbox", "wb_protect", "wb-client"} {
			if strings.Contains(string(body), needle) {
				t.Errorf("%s contains %q: lab code or lab hooks must not exist in product source", path, needle)
			}
		}
	})
	if n < 100 {
		t.Fatalf("only %d product Go files scanned; the walk is not seeing the repo", n)
	}
}

// The engine gained NO lab traffic inlet. The rig feeds it through the
// same platform seam the phone uses (abi.SetTunFD), so core/ must not
// contain a build tag or an inbound that exists for the lab.
func TestEngineHasNoLabInlet(t *testing.T) {
	root := repoRoot(t)
	walkProduct(t, filepath.Join(root, "core"), func(path string) {
		if !strings.HasSuffix(path, ".go") {
			return
		}
		body, _ := os.ReadFile(path)
		for _, line := range strings.Split(string(body), "\n") {
			if strings.HasPrefix(line, "//go:build") && (strings.Contains(line, "lab") || strings.Contains(line, "rig")) {
				t.Errorf("%s: build constraint %q looks like a lab-only switch inside the engine", path, line)
			}
		}
	})
}

// Nothing that produces a shippable artefact may build or copy rig code.
func TestReleaseBuildsDoNotTouchTheRig(t *testing.T) {
	root := repoRoot(t)
	scripts := []string{"appveyor.yml"}
	for _, pat := range []string{"tools/build-*.sh", "tools/release/*.sh", "tools/package*.sh"} {
		m, _ := filepath.Glob(filepath.Join(root, pat))
		for _, p := range m {
			rel, _ := filepath.Rel(root, p)
			scripts = append(scripts, rel)
		}
	}
	for _, rel := range scripts {
		body, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			continue
		}
		if strings.Contains(string(body), "worldbox") || strings.Contains(string(body), "wb-client") {
			t.Errorf("%s references the rig: release tooling must not build or package lab binaries", rel)
		}
	}
	// ./daal may name the rig in exactly two places: the driver module in
	// `test` (static tests only) and the e2e verb's entry point. Neither
	// builds anything shippable; build, package and release-check must
	// never mention it.
	body, err := os.ReadFile(filepath.Join(root, "daal"))
	if err != nil {
		t.Fatal(err)
	}
	fn := ""
	for i, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "cmd_") && strings.Contains(line, "()") {
			fn = strings.SplitN(line, "(", 2)[0]
		}
		trim := strings.TrimSpace(line)
		if !strings.Contains(line, "worldbox") || strings.HasPrefix(trim, "#") {
			continue
		}
		okTest := fn == "cmd_test" && trim == `"test-rigs/worldbox/driver"`
		okE2E := fn == "cmd_e2e" && trim == `local e2e="$REPO_ROOT/test-rigs/worldbox/e2e.sh"`
		if !okTest && !okE2E {
			t.Errorf("daal:%d (in %s) mentions the rig outside the test module list and the e2e verb: %s", i+1, fn, trim)
		}
	}
}
