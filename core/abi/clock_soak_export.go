//go:build cshared && soak

package abi

import "C"

//export engine_set_now_unix
func engine_set_now_unix(t C.longlong) {
	SetNowUnix(int64(t))
}
