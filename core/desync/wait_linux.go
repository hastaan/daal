//go:build linux

package desync

import (
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// tcpInfoOf reads the three TCP_INFO fields the gaps need. ok false when
// there is no socket or the kernel refuses (a closed fd). GOOS=android is
// linux to the build: this is the file a phone runs (source-verified;
// plan T2 "on-device unproven").
func tcpInfoOf(raw syscall.RawConn) (ti tcpInfo) {
	if raw == nil {
		return ti
	}
	var gerr error
	if err := raw.Control(func(fd uintptr) {
		info, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		if err != nil {
			gerr = err
			return
		}
		ti = tcpInfo{
			ok:      true,
			unacked: info.Unacked,
			notsent: info.Notsent_bytes,
			rto:     time.Duration(info.Rto) * time.Microsecond,
		}
	}); err != nil || gerr != nil {
		return tcpInfo{}
	}
	return ti
}

// setNoDelay turns Nagle off for the first flight (so each Write leaves
// as its own segment) and returns how to put the option back as it was.
func setNoDelay(raw syscall.RawConn) (restore func()) {
	if raw == nil {
		return func() {}
	}
	prev := -1
	_ = raw.Control(func(fd uintptr) {
		v, err := unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NODELAY)
		if err != nil {
			return
		}
		prev = v
		if v == 0 {
			_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)
		}
	})
	return func() {
		if prev == 0 {
			_ = raw.Control(func(fd uintptr) {
				_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NODELAY, 0)
			})
		}
	}
}
