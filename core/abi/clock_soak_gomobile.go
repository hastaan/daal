//go:build gomobile && soak

package abi

// EngineSetNowUnix mirrors engine_set_now_unix for gomobile bindings,
// useful for instrumented Android-emulator soak runs.
func EngineSetNowUnix(unix int64) { SetNowUnix(unix) }
