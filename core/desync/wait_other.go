//go:build !linux

package desync

import "syscall"

// tcpInfoOf: no portable TCP_INFO here (Windows, macOS, iOS): no ACK
// wait and no autocork guard; the strategy's delay alone separates
// segments, and that is unmeasured.
func tcpInfoOf(syscall.RawConn) tcpInfo { return tcpInfo{} }

// setNoDelay: Go turns Nagle off on every TCP connection by default; on
// these platforms the option is left as found.
func setNoDelay(syscall.RawConn) func() { return func() {} }
