//go:build !linux

package desync

import (
	"net"
	"testing"
)

// noDelay: setNoDelay does not touch the option off Linux, so there is
// nothing to restore and nothing to check.
func noDelay(*testing.T, *net.TCPConn) bool { return false }
