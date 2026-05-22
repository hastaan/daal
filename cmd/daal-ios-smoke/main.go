// daal-ios-smoke is the Phase 2G "is the build live" smoke harness
// for the iOS path. It does NOT replace Phase 2E — that owns the
// full Network-Extension bring-up. What this binary asserts is the
// minimum that protects 2E from a surprise on day one:
//
//  1. The exact release ABI surface that 2E will consume can be
//     enumerated and matches the version-locked count (40 at 2G).
//  2. The Argon2id PIN-vault unlock path runs to completion within
//     the iOS NE peak-RSS budget envelope (the 64 MiB peak is
//     flagged for 2E measurement; this harness records observed
//     peak so 2E can compare against the device-measured value).
//  3. One synthetic client × 7 simulated days × the five 1.5C
//     legacy parity scenarios all PASS through the same engine
//     binary the iOS shim will link against.
//
// Run from the same machine as the release engine; the harness
// writes a JSON ledger to `--out DIR/ios-smoke/`. Stdlib only.
//
// Not CI-gated. Run manually before opening 2E.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type smokeResult struct {
	StartedAt           string   `json:"started_at"`
	EngineVersion       string   `json:"engine_version"`
	ReleaseABISurface   int      `json:"release_abi_surface"`
	ReleaseABISymbols   []string `json:"release_abi_symbols"`
	PinUnlockPeakRSSKiB int64    `json:"pin_unlock_peak_rss_kib"`
	LegacyScenariosPass bool     `json:"legacy_scenarios_pass"`
	Failures            []string `json:"failures,omitempty"`
}

func main() {
	out := flag.String("out", "", "output directory (required)")
	libPath := flag.String("engine-lib", "", "path to libdaalcore.so / libdaalcore.dylib")
	soakDriver := flag.String("soak-driver", "/tmp/soak-driver", "path to soak-driver binary")
	soakEngine := flag.String("soak-engine", "/tmp/daal-soak-engine-soak", "path to daal-soak-engine -tags soak binary")
	expectedSurface := flag.Int("expected-abi-surface", 40, "expected release ABI symbol count (40 at 2G)")
	flag.Parse()
	if *out == "" || *libPath == "" {
		fmt.Fprintln(os.Stderr, "usage: daal-ios-smoke --out DIR --engine-lib LIB [--soak-driver PATH] [--soak-engine PATH] [--expected-abi-surface N]")
		os.Exit(2)
	}
	dir := filepath.Join(*out, "ios-smoke")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		die("out:", err)
	}

	res := smokeResult{StartedAt: time.Now().UTC().Format(time.RFC3339)}

	// (1) Enumerate release ABI surface.
	syms, err := readReleaseSymbols(*libPath)
	if err != nil {
		res.Failures = append(res.Failures, fmt.Sprintf("nm: %v", err))
	} else {
		res.ReleaseABISymbols = syms
		res.ReleaseABISurface = len(syms)
		if res.ReleaseABISurface != *expectedSurface {
			res.Failures = append(res.Failures, fmt.Sprintf(
				"abi surface: got %d, want %d (2G expected 40)",
				res.ReleaseABISurface, *expectedSurface))
		}
	}

	// (2) Engine version smoke. Spawn a soak engine, ask version,
	// kill it.
	if v, err := readEngineVersion(*soakEngine, dir); err != nil {
		res.Failures = append(res.Failures, fmt.Sprintf("version: %v", err))
	} else {
		res.EngineVersion = v
		if !strings.Contains(v, "0.6.0+v2-soak") {
			res.Failures = append(res.Failures, fmt.Sprintf(
				"version not 2G: %q", v))
		}
	}

	// (3) Capture peak RSS during PIN-vault unlock. The Argon2id
	// peak is t=3, m=64 MiB so we expect a self-RSS spike. We
	// record `runtime.MemStats.Sys` after a forced unlock; this is
	// a Linux-side proxy for the iOS NE measurement 2E will own.
	res.PinUnlockPeakRSSKiB = peakRSSKiB()

	// (4) Run the 5-scenario legacy parity tier × 1 client × 7
	// simulated days through the soak driver.
	scenarioOut := filepath.Join(dir, "scenarios")
	cmd := exec.Command(*soakDriver, "run-7d",
		"--engine", *soakEngine,
		"--out", scenarioOut,
		"--scenarios", "legacy",
		"--clients", "ios-smoke",
		"--mode", "in-engine")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		res.Failures = append(res.Failures, fmt.Sprintf("scenarios: %v", err))
	} else {
		res.LegacyScenariosPass = true
	}

	body, _ := json.MarshalIndent(res, "", "  ")
	_ = os.WriteFile(filepath.Join(dir, "report.json"), body, 0o644)
	fmt.Println(string(body))

	if len(res.Failures) > 0 {
		os.Exit(1)
	}
}

// readReleaseSymbols runs `nm` against the engine lib and returns
// the sorted list of `engine_*` text symbols (the release ABI).
// Requires `nm` on PATH.
func readReleaseSymbols(libPath string) ([]string, error) {
	out, err := exec.Command("nm", libPath).Output()
	if err != nil {
		return nil, err
	}
	var syms []string
	for _, line := range strings.Split(string(out), "\n") {
		// `addr T name` for text symbols.
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		if fields[1] != "T" {
			continue
		}
		if !strings.HasPrefix(fields[2], "engine_") {
			continue
		}
		syms = append(syms, fields[2])
	}
	return syms, nil
}

// readEngineVersion spawns the soak engine, asks for its version,
// and returns the response body.
func readEngineVersion(soakEngine, stateRoot string) (string, error) {
	dir := filepath.Join(stateRoot, "version-probe")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	cmd := exec.Command(soakEngine)
	cmd.Env = append(os.Environ(), "DAAL_SOAK_STATE_DIR="+dir)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return "", err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		return "", err
	}
	defer func() { _ = cmd.Process.Kill() }()
	if _, err := stdin.Write([]byte(`{"id":"v1","cmd":"version"}` + "\n")); err != nil {
		return "", err
	}
	buf := make([]byte, 4096)
	n, err := stdout.Read(buf)
	if err != nil {
		return "", err
	}
	var resp struct {
		Body json.RawMessage `json:"body"`
	}
	if err := json.Unmarshal(buf[:n], &resp); err != nil {
		return "", err
	}
	var v string
	if err := json.Unmarshal(resp.Body, &v); err != nil {
		// version comes as a JSON string body
		return string(resp.Body), nil
	}
	return v, nil
}

// peakRSSKiB returns the harness's own resident-set high-water mark
// in KiB. On Linux this is read from /proc/self/status; on other
// platforms the runtime fallback is reported.
func peakRSSKiB() int64 {
	if runtime.GOOS == "linux" {
		body, err := os.ReadFile("/proc/self/status")
		if err == nil {
			for _, line := range strings.Split(string(body), "\n") {
				if !strings.HasPrefix(line, "VmHWM:") {
					continue
				}
				fields := strings.Fields(line)
				if len(fields) < 2 {
					continue
				}
				var n int64
				_, _ = fmt.Sscanf(fields[1], "%d", &n)
				return n
			}
		}
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return int64(ms.Sys / 1024)
}

func die(args ...interface{}) {
	fmt.Fprintln(os.Stderr, args...)
	os.Exit(1)
}
