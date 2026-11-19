//go:build android && cgo

package engine

/*
#include <android/log.h>
#include <stdlib.h>
*/
import "C"

import "unsafe"

// platformLog writes one line to logcat under the "daalengine" tag so
// the engine is diagnosable on-device (Go stderr from a c-shared lib
// does not reach logcat on its own). The line has already been through
// Scrub (log.go).
func platformLog(level int, msg string) {
	ctag := C.CString("daalengine")
	cmsg := C.CString(msg)
	C.__android_log_write(C.int(level), ctag, cmsg)
	C.free(unsafe.Pointer(ctag))
	C.free(unsafe.Pointer(cmsg))
}
