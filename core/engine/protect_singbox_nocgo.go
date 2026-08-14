//go:build singbox && !cgo

package engine

import "errors"

// invokeProtect without cgo cannot dereference the host's C function
// pointer. A registered callback in a CGO_ENABLED=0 build is a build
// configuration error; no callback is the desktop/tun-helper topology
// and needs no protection.
func invokeProtect(fd int) error {
	if CurrentProtectCallback() == 0 {
		return nil
	}
	return errors.New("engine: protect callback registered but binary built without cgo")
}
