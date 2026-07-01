//go:build cshared

package abi

// #include <stdint.h>
import "C"

import "unsafe"

// engine_set_tun_fd hands the TUN file descriptor to the in-process
// driver. After a successful return (>=0) the caller MUST NOT close(fd)
// — the engine takes ownership and closes it on
// engine_clear_tun_fd or engine_shutdown.
//
// Returns the number of bytes written to `out` on success, -1 on error.
//
//export engine_set_tun_fd
func engine_set_tun_fd(fd C.int, out unsafe.Pointer, outLen C.int) C.int {
	body, err := SetTunFD(int(fd))
	if err != nil {
		return -1
	}
	return copyOut(body, out, outLen)
}

// engine_clear_tun_fd asks the driver to stop using the fd and closes
// it. Idempotent; safe to call without a prior set.
//
//export engine_clear_tun_fd
func engine_clear_tun_fd(out unsafe.Pointer, outLen C.int) C.int {
	body, err := ClearTunFD()
	if err != nil {
		return -1
	}
	return copyOut(body, out, outLen)
}

// engine_register_protect_callback installs a C function pointer of
// type `int (*)(int fd)` that the in-process driver invokes for every
// upstream socket it opens. Non-zero return means "host successfully
// excluded the socket from the TUN" (Android: VpnService.protect()
// returned true); zero means "protect failed", which the driver may
// treat as fatal for that connection.
//
// Pass cb == 0 to clear the binding.
//
//export engine_register_protect_callback
func engine_register_protect_callback(cb C.uintptr_t, out unsafe.Pointer, outLen C.int) C.int {
	body, err := RegisterProtectCallback(uintptr(cb))
	if err != nil {
		return -1
	}
	return copyOut(body, out, outLen)
}
