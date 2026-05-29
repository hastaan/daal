//go:build soak

package abi

// SetNowUnix is the soak-only ABI export. It overrides the wall-clock
// returned by nowUTC() until cleared (by passing 0) or until the next
// engine_shutdown.
//
// Release builds DO NOT compile this file. Asserted by
// `.github/workflows/desktop.yml` (release-build symbol-grep CI step).
//
// This is intentionally not in the engine-abi-v1.md function count
// because it is not part of the release ABI surface. The phase-1.5C
// rig builds its own `libdaalcore-soak.so` with `-tags soak` for the
// soak run only.
func SetNowUnix(unix int64) {
	clockOverride.Store(unix)
}
