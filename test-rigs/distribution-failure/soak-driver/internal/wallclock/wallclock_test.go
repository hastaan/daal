package wallclock

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"daal/soak-driver/internal/client"
)

// engineBinary returns the path to the soak-engine binary used by the
// 1.5C rig, building it on demand under the test cache. Returns "" if
// the Go toolchain or the source tree is not available.
func engineBinary(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skipf("wallclock test is Linux-only; got %s", runtime.GOOS)
	}
	if path := os.Getenv("DAAL_SOAK_ENGINE"); path != "" {
		return path
	}
	// Build into the per-test temp dir so we are hermetic.
	src := os.Getenv("DAAL_REPO")
	if src == "" {
		// Walk up to find the repo root: look for a directory that
		// contains `cmd/daal-soak-engine/main.go`.
		wd, _ := os.Getwd()
		dir := wd
		for i := 0; i < 8; i++ {
			if _, err := os.Stat(filepath.Join(dir, "cmd", "daal-soak-engine", "main.go")); err == nil {
				src = dir
				break
			}
			dir = filepath.Dir(dir)
		}
	}
	if src == "" {
		t.Skip("could not find repo root containing cmd/daal-soak-engine; set DAAL_REPO")
	}
	out := filepath.Join(t.TempDir(), "daal-soak-engine-test")
	// `cmd/daal-soak-engine` is its own Go module; `cmd.Dir` must be
	// that module's directory.
	cmd := exec.Command("go", "build", "-tags", "soak", "-o", out, ".")
	cmd.Dir = filepath.Join(src, "cmd", "daal-soak-engine")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("could not build soak-engine: %v: %s", err, string(b))
	}
	return out
}

// Run a 2-second wall-clock loop with 200 ms ticks; assert we recorded
// several ticks, the result JSON exists, and the run did not fail.
//
// fd-growth is sample-quality only on the test host; we use a generous
// MaxFDGrowth=200 here because parallel test execution can wobble fd
// counts. The unit test is about end-to-end loop correctness; the
// long-run version is the manual 7-day procedure.
func TestWallclockShortLoop(t *testing.T) {
	bin := engineBinary(t)
	stateDir := t.TempDir()
	outDir := t.TempDir()

	c, err := client.Spawn("wallclock-test", bin, stateDir)
	if err != nil {
		t.Fatalf("spawn: %v", err)
	}
	defer c.Close()

	res, err := Run(Config{
		Client:      c,
		OutDir:      outDir,
		Duration:    2 * time.Second,
		TickEvery:   200 * time.Millisecond,
		MaxFDGrowth: 200,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Failed {
		t.Fatalf("Run failed: %+v", res)
	}
	if res.Ticks < 5 {
		t.Fatalf("expected at least 5 ticks in 2 s, got %d", res.Ticks)
	}
	if res.MaxFD <= 0 {
		t.Fatalf("expected non-zero MaxFD; got %d (read /proc/<pid>/fd failed?)", res.MaxFD)
	}
	resultPath := filepath.Join(outDir, "wallclock_result.json")
	body, err := os.ReadFile(resultPath)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	var got Result
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if got.Ticks != res.Ticks {
		t.Fatalf("artifact ticks=%d != res ticks=%d", got.Ticks, res.Ticks)
	}
	jsonlPath := filepath.Join(outDir, "wallclock_ticks.jsonl")
	if st, err := os.Stat(jsonlPath); err != nil || st.Size() == 0 {
		t.Fatalf("expected non-empty wallclock_ticks.jsonl, err=%v", err)
	}
}
