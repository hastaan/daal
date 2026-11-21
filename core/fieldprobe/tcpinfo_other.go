//go:build !linux

package fieldprobe

import (
	"net"
	"time"
)

// watchHelloAck: TCP_INFO is Linux/Android only; elsewhere the hello's
// ACK is not known and the classifier does without it.
func watchHelloAck(net.Conn, time.Duration) func() (acked, known bool) {
	return func() (bool, bool) { return false, false }
}

// kernelRTT: not known off Linux; the wall-clock measure stands.
func kernelRTT(net.Conn) (time.Duration, bool) { return 0, false }
