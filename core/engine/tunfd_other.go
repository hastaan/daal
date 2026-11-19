//go:build !unix

package engine

import "errors"

// No host hands this build a TUN file descriptor.
var closeFD = func(int) error { return nil }

var dupFD = func(int) (int, error) {
	return -1, errors.New("engine: TUN fd handoff is not supported on this platform")
}
