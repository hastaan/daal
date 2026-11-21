//go:build linux

package desync

import (
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

func noDelay(t *testing.T, c *net.TCPConn) bool {
	t.Helper()
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	v := -1
	if err := raw.Control(func(fd uintptr) {
		v, _ = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NODELAY)
	}); err != nil {
		t.Fatal(err)
	}
	return v != 0
}
