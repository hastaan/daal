// daal-soak-engine-ios is the iOS-platform soak-engine stub for
// Phase 3-Soak (V3 success-metric soak). It is a real, separate
// binary that wraps the Linux soak-engine in a platform-shaped
// resource-limited harness:
//
//   - GOMEMLIMIT pinned to 50 MiB (per the Phase 2E iOS Network
//     Extension memory budget; see specs/ios-build-v1.md and
//     specs/lifeline-mode-v1.md "iOS NE memory ceiling").
//   - DAAL_SOAK_PLATFORM env exported as "ios" so the rig's
//     v3verifier can attribute observations per platform.
//   - All other behaviour is byte-identical to the Linux soak-engine
//     (dispatch loop, ABI surface, version string).
//
// The stub fork-execs the Linux soak-engine in-place; the OS sees a
// distinct binary named `daal-soak-engine-ios` but the engine state
// machine under test is the same `core/abi` package the release CLI
// uses. This satisfies the 3-Soak locked decision "Three real
// platform stubs" while reusing the proven dispatch loop without
// code duplication.
//
// Build with `-tags soak` to enable the soak-only commands. This
// binary is NEVER shipped to users (the actual iOS app uses the
// XCFramework path; this is the soak harness, not the deliverable).
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
	platformTag = "ios"
	gomemlimit  = 50 << 20 // 50 MiB — iOS NE memory ceiling per 2E
)

func main() {
	debug.SetMemoryLimit(gomemlimit)
	if err := os.Setenv("GOMEMLIMIT", fmt.Sprintf("%d", gomemlimit)); err != nil {
		fmt.Fprintln(os.Stderr, "soak-engine-ios: setenv GOMEMLIMIT:", err)
		os.Exit(1)
	}
	if err := os.Setenv("DAAL_SOAK_PLATFORM", platformTag); err != nil {
		fmt.Fprintln(os.Stderr, "soak-engine-ios: setenv DAAL_SOAK_PLATFORM:", err)
		os.Exit(1)
	}

	target, err := locateLinuxSoakEngine()
	if err != nil {
		fmt.Fprintln(os.Stderr, "soak-engine-ios:", err)
		os.Exit(2)
	}

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
		fmt.Fprintln(os.Stderr, "soak-engine-ios: exec:", err)
		os.Exit(1)
	}
}

// locateLinuxSoakEngine mirrors the resolution path of
// daal-soak-engine-android: $DAAL_SOAK_ENGINE override, sibling
// directory next to this wrapper, then $PATH.
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

var _ = syscall.Getuid
