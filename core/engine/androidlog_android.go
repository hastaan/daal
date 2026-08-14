//go:build android && cgo

package engine

/*
#include <android/log.h>
#include <stdlib.h>
*/
import "C"

import "unsafe"

// androidLog writes an ERROR-level line to logcat under the
// "daalengine" tag so the in-process sing-box driver's failures are
// diagnosable on-device (Go stderr from a c-shared lib does not reach
// logcat on its own). No-op on non-Android builds.
func androidLog(msg string) {
	ctag := C.CString("daalengine")
	cmsg := C.CString(msg)
	C.__android_log_write(C.ANDROID_LOG_ERROR, ctag, cmsg)
	C.free(unsafe.Pointer(ctag))
	C.free(unsafe.Pointer(cmsg))
}
