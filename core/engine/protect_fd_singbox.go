//go:build singbox

package engine

// ProtectFD offers one socket the engine opens OUTSIDE sing-box to the
// host's protect() callback — the same callback, through the same
// invokeProtect, that sing-box's own outbound sockets go through. The
// network test (core/fieldprobe via core/abi/fieldprobe.go) is the
// caller: every probe socket is protected before it connects.
func ProtectFD(fd int) error { return invokeProtect(fd) }
