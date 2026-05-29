// daal-soak-engine-android is the Android-platform soak-engine stub
// for Phase 3-Soak (V3 success-metric soak). It is a real, separate
// binary that wraps the Linux soak-engine in a platform-shaped
// resource-limited harness:
//
//   - GOMEMLIMIT pinned to 200 MiB (Android dalvik-style ceiling).
//   - DAAL_SOAK_PLATFORM env exported as "android" so the rig's
//     v3verifier can attribute observations per platform.
//   - All other behaviour is byte-identical to the Linux soak-engine
//     (dispatch loop, ABI surface, version string).
//
// The stub fork-execs the Linux soak-engine in-place; the OS sees a
// distinct binary named `daal-soak-engine-android` but the engine
// state machine under test is the same `core/abi` package the
// release CLI uses. This satisfies the 3-Soak locked decision
// "Three real platform stubs" while reusing the proven dispatch
// loop without code duplication.
//
// Build with `-tags soak` to enable the soak-only commands. This
// binary is NEVER shipped to users.
package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"syscall"
)

// platformTag and gomemlimit are locked at 3-Soak per
// `phases of development/27-phase-3-soak-success-metric.md` §5.
const (
	platformTag = "android"
	gomemlimit  = 200 << 20 // 200 MiB
)

func main() {
	// Pin GOMEMLIMIT for this process. The exec'd Linux soak-engine
	// inherits the env var; we set both the Go runtime knob (for
	// allocations made by this wrapper) AND the env var (for the
	// child process).
	debug.SetMemoryLimit(gomemlimit)
	if err := os.Setenv("GOMEMLIMIT", fmt.Sprintf("%d", gomemlimit)); err != nil {
		fmt.Fprintln(os.Stderr, "soak-engine-android: setenv GOMEMLIMIT:", err)
		os.Exit(1)
	}
	if err := os.Setenv("DAAL_SOAK_PLATFORM", platformTag); err != nil {
		fmt.Fprintln(os.Stderr, "soak-engine-android: setenv DAAL_SOAK_PLATFORM:", err)
		os.Exit(1)
	}

	target, err := locateLinuxSoakEngine()
	if err != nil {
		fmt.Fprintln(os.Stderr, "soak-engine-android:", err)
		os.Exit(2)
	}

	// Pass through args + env. We use exec.Cmd (not syscall.Exec)
	// so the wrapper observes the child's exit code; the soak driver
	// reads stdout/stderr line-delimited so a transparent passthrough
	// is sufficient.
	cmd := exec.Command(target, os.Args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			os.Exit(exit.ExitCode())
		}
		fmt.Fprintln(os.Stderr, "soak-engine-android: exec:", err)
		os.Exit(1)
	}
}

// locateLinuxSoakEngine resolves the Linux soak-engine binary. Look-up
// order:
//
//  1. $DAAL_SOAK_ENGINE — explicit override (used by the rig CI).
//  2. <wrapper-dir>/daal-soak-engine — sibling layout (the default
//     when the rig builds both binaries into the same out-dir).
//  3. $PATH — last-resort fallback.
//
// Returns an error rather than os.Exit so the caller controls the
// exit code.
func locateLinuxSoakEngine() (string, error) {
	if env := os.Getenv("DAAL_SOAK_ENGINE"); env != "" {
		if _, err := os.Stat(env); err == nil {
			return env, nil
		}
	}
	exe, err := os.Executable()
	if err == nil {
		sibling := filepath.Join(filepath.Dir(exe), "daal-soak-engine")
		if _, serr := os.Stat(sibling); serr == nil {
			return sibling, nil
		}
	}
	if path, lerr := exec.LookPath("daal-soak-engine"); lerr == nil {
		return path, nil
	}
	return "", &locateError{
		msg: "could not locate daal-soak-engine; set $DAAL_SOAK_ENGINE or place the binary alongside this wrapper",
	}
}

type locateError struct{ msg string }

func (e *locateError) Error() string { return e.msg }

// _ keeps syscall imported for build-tagged platform variants that
// need it; harmless under the default build.
var _ = syscall.Getuid
