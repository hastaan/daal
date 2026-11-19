//go:build unix

package engine

import "golang.org/x/sys/unix"

// closeFD and dupFD are variables so a test can count closes; nothing
// in production reassigns them.
var closeFD = unix.Close

// dupFD duplicates fd with close-on-exec set, so a child process (tor)
// never inherits a TUN.
var dupFD = func(fd int) (int, error) {
	// Never below 3: sing-tun reads FileDescriptor == 0 as "create a
	// device yourself", and 0–2 can be free in a process that closed
	// its standard streams.
	return unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 3)
}
