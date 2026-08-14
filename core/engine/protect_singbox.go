//go:build singbox && cgo

package engine

/*
#include <stdint.h>

typedef int (*daal_protect_fn)(int fd);

static int daal_invoke_protect(uintptr_t cb, int fd) {
	return ((daal_protect_fn)cb)(fd);
}
*/
import "C"

import "fmt"

// invokeProtect offers fd to the host-registered protect callback
// (core/abi/tun_fd.go contract: `int (*)(int fd)`, non-zero == success).
// No callback registered means no host to protect against (desktop
// tun-helper topology, unit tests) — that is success, not an error.
func invokeProtect(fd int) error {
	cb := CurrentProtectCallback()
	if cb == 0 {
		return nil
	}
	if C.daal_invoke_protect(C.uintptr_t(cb), C.int(fd)) == 0 {
		return fmt.Errorf("engine: host protect(%d) refused the socket", fd)
	}
	return nil
}
