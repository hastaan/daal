//go:build linux

package fieldprobe

import (
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// watchHelloAck reports whether the bytes written so far on c (the
// ClientHello) were acknowledged by the far end: TCP_INFO tcpi_unacked
// reaching 0 while the socket is still ESTABLISHED — the mechanism
// core/desync/wait_linux.go uses. GOOS=android is linux to the build.
//
// It polls until the ACK is seen, the socket leaves ESTABLISHED (a RST
// or FIN: the answer is then "not known" unless the ACK came first), or
// `until` passes (then: not acknowledged — the hello was dropped on
// the way). The returned function waits for the verdict.
func watchHelloAck(c net.Conn, until time.Duration) func() (acked, known bool) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return func() (bool, bool) { return false, false }
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return func() (bool, bool) { return false, false }
	}
	type verdict struct{ acked, known bool }
	ch := make(chan verdict, 1)
	go func() {
		deadline := time.Now().Add(until)
		for {
			var unacked uint32
			var state uint8
			var gerr error
			if err := raw.Control(func(fd uintptr) {
				info, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
				if err != nil {
					gerr = err
					return
				}
				unacked, state = info.Unacked, info.State
			}); err != nil || gerr != nil {
				ch <- verdict{}
				return
			}
			const established = 1
			if state != established {
				ch <- verdict{}
				return
			}
			if unacked == 0 {
				ch <- verdict{acked: true, known: true}
				return
			}
			if time.Now().After(deadline) {
				ch <- verdict{acked: false, known: true}
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	var v verdict
	var got bool
	return func() (bool, bool) {
		if !got {
			v, got = <-ch, true
		}
		return v.acked, v.known
	}
}

// kernelRTT is the kernel's smoothed round-trip time of c (TCP_INFO
// tcpi_rtt, microseconds). Read right after connect it is the SYN /
// SYN-ACK sample: the round trip without the protect() hop to the host
// and the scheduling the wall clock around DialTCP also counts.
func kernelRTT(c net.Conn) (time.Duration, bool) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return 0, false
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return 0, false
	}
	var rtt uint32
	var gerr error
	if err := raw.Control(func(fd uintptr) {
		info, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		if err != nil {
			gerr = err
			return
		}
		rtt = info.Rtt
	}); err != nil || gerr != nil || rtt == 0 {
		return 0, false
	}
	return time.Duration(rtt) * time.Microsecond, true
}
