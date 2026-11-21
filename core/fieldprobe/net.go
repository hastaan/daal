package fieldprobe

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Net is how the test reaches the network. Every socket it opens goes
// through here, so on Android every one of them is offered to the host's
// protect() callback (the engine's registered one: engine.ProtectFD)
// before it connects — exactly as sing-box's own sockets are. With no
// Daal tunnel up (the test refuses to run beside one, and stops when one
// starts) protect() changes nothing; it is there so that a Daal tunnel
// coming up mid-run can never carry a probe. It cannot take a socket out
// of ANOTHER app's VPN: that case is caught by the host (TRANSPORT_VPN:
// engine_field_probe_cancel("vpn_active")), by the engine's watch of the
// host's network facts, and by pathWatch below.
type Net interface {
	DialTCP(ctx context.Context, to netip.AddrPort) (net.Conn, error)
	DialUDP(ctx context.Context, to netip.AddrPort) (net.Conn, error)
	ListenUDP(ctx context.Context) (net.PacketConn, error)
}

// SysNet is the real Net. Protect may be nil (desktop: no callback).
//
// A Protect error fails the socket before it sends anything, and the
// dial error carries ErrLocal: the probe records local_error, never a
// timeout — a refusal on the device must not read as a censored
// network. Whether a refusal is fatal at all is the caller's call
// (core/abi/fieldprobe.go: with no Daal tunnel up there is nothing to
// bypass, and a host that has dropped its VpnService refuses every
// protect()).
type SysNet struct {
	Protect func(fd int) error
}

// ErrLocal marks a socket the device itself refused (protect() said no,
// or a socket option failed). errKind: "local_error".
var ErrLocal = errors.New("fieldprobe: the device refused the socket")

func (n SysNet) control(_, _ string, c syscall.RawConn) error {
	if n.Protect == nil {
		return nil
	}
	var perr error
	if err := c.Control(func(fd uintptr) { perr = n.Protect(int(fd)) }); err != nil {
		return fmt.Errorf("%w: %v", ErrLocal, err)
	}
	if perr != nil {
		return fmt.Errorf("%w: %v", ErrLocal, perr)
	}
	return nil
}

func (n SysNet) DialTCP(ctx context.Context, to netip.AddrPort) (net.Conn, error) {
	d := net.Dialer{Control: n.control}
	return d.DialContext(ctx, "tcp", to.String())
}

func (n SysNet) DialUDP(ctx context.Context, to netip.AddrPort) (net.Conn, error) {
	d := net.Dialer{Control: n.control}
	return d.DialContext(ctx, "udp", to.String())
}

func (n SysNet) ListenUDP(ctx context.Context) (net.PacketConn, error) {
	lc := net.ListenConfig{Control: n.control}
	return lc.ListenPacket(ctx, "udp", ":0")
}

// ---- address classes ----------------------------------------------------

var bogonPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/3",
		"::/128", "::1/128", "fc00::/7", "fe80::/10", "::ffff:0:0/96"} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// isBogon: an answer no public name has — a private, loopback,
// link-local, CGNAT or reserved address, or one inside the calibration
// sinkhole (10.10.34.0/24 by default, already private).
func isBogon(a netip.Addr, calibration netip.Prefix) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsUnspecified() {
		return true
	}
	if calibration.IsValid() && calibration.Contains(a) {
		return true
	}
	for _, p := range bogonPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// wellKnownResolvers: public anycast resolvers a phone may be set to.
var wellKnownResolvers = map[string]bool{
	"1.1.1.1": true, "1.0.0.1": true, "8.8.8.8": true, "8.8.4.4": true, "9.9.9.9": true,
	"149.112.112.112": true, "208.67.222.222": true, "208.67.220.220": true,
	"2606:4700:4700::1111": true, "2001:4860:4860::8888": true,
}

// IsPublicAddr: an address a public name can have (not private,
// loopback, link-local, CGNAT, multicast or reserved).
func IsPublicAddr(a netip.Addr) bool { return !isBogon(a, netip.Prefix{}) }

// PickResolver is the link resolver the test asks: the first that is
// not link-local (an fe80:: server, whose zone a host may not pass,
// makes every question fail), else the first.
func PickResolver(servers []netip.AddrPort) (netip.AddrPort, bool) {
	for _, s := range servers {
		if !s.Addr().IsLinkLocalUnicast() {
			return s, true
		}
	}
	if len(servers) > 0 {
		return servers[0], true
	}
	return netip.AddrPort{}, false
}

// ResolverClass is the report's coarse class of the link resolver. The
// address itself goes no further than this function.
func ResolverClass(servers []netip.AddrPort) string {
	s, ok := PickResolver(servers)
	if !ok {
		return "unknown"
	}
	a := s.Addr().Unmap().WithZone("")
	switch {
	case wellKnownResolvers[a.String()]:
		return "well_known_public"
	case isBogon(a, netip.Prefix{}):
		return "private"
	}
	return "isp_public"
}

// ParseResolvers turns the host's DNS server strings into addresses
// (port 53 unless given). An IPv6 zone ("fe80::1%wlan0") is kept: a
// link-local server is reachable only through it. Anything unparsable
// is dropped; at most three are kept.
func ParseResolvers(in []string) []netip.AddrPort {
	var out []netip.AddrPort
	for _, s := range in {
		if len(out) == 3 {
			break
		}
		s = strings.TrimSpace(s)
		if ap, err := netip.ParseAddrPort(s); err == nil {
			out = append(out, ap)
			continue
		}
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, netip.AddrPortFrom(a, 53))
		}
	}
	return out
}

// SystemResolvers reads /etc/resolv.conf where there is one that means
// something (a Linux desktop). On Android the host must pass the link's
// servers (LinkProperties.getDnsServers): Go cannot ask the system
// resolver for TXT or HTTPS records there.
func SystemResolvers() []netip.AddrPort {
	if !systemResolvConf {
		return nil
	}
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	defer f.Close()
	var names []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) >= 2 && fs[0] == "nameserver" {
			names = append(names, fs[1])
		}
	}
	return ParseResolvers(names)
}

// errKind is the closed class of a dial or read error.
func errKind(err error) string {
	var ne net.Error
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrLocal):
		return "local_error"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE):
		return "rst"
	case errors.Is(err, syscall.EPERM), errors.Is(err, syscall.EACCES):
		return "local_blocked"
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		return "unreachable"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, errEOF):
		return "fin"
	}
	if strings.Contains(err.Error(), "EOF") {
		return "fin"
	}
	if strings.Contains(err.Error(), "connection reset") {
		return "rst"
	}
	return "other"
}

var errEOF = errors.New("EOF")

// sleepCtx sleeps d or until ctx ends.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// ---- the path under the test ---------------------------------------------

// pathWatch wraps the run's Net and notes the local address of every
// connected socket to a public address. A different local address
// mid-run (per family; IPv6 by /64, for privacy addresses) means the
// path changed under the test: another network, or another app's VPN
// that came up and now carries the probes — protect() cannot take a
// socket out of a VPN that is not Daal's. The run is stopped
// (ErrNetworkChanged): what it measures from there is not this
// network. Addresses stay in memory, in this struct, for the run.
type pathWatch struct {
	Net
	mu      sync.Mutex
	v4, v6  netip.Addr
	changed func()
}

func (w *pathWatch) note(c net.Conn, to netip.AddrPort) {
	if c == nil || !IsPublicAddr(to.Addr()) {
		return
	}
	ap, err := netip.ParseAddrPort(c.LocalAddr().String())
	if err != nil {
		return
	}
	a := ap.Addr().Unmap().WithZone("")
	w.mu.Lock()
	var moved bool
	switch {
	case a.Is4() && !w.v4.IsValid():
		w.v4 = a
	case a.Is4():
		moved = a != w.v4
	case !w.v6.IsValid():
		w.v6 = a
	default:
		p1, _ := a.Prefix(64)
		p2, _ := w.v6.Prefix(64)
		moved = p1 != p2
	}
	w.mu.Unlock()
	if moved && w.changed != nil {
		w.changed()
	}
}

func (w *pathWatch) DialTCP(ctx context.Context, to netip.AddrPort) (net.Conn, error) {
	c, err := w.Net.DialTCP(ctx, to)
	if err == nil {
		w.note(c, to)
	}
	return c, err
}

func (w *pathWatch) DialUDP(ctx context.Context, to netip.AddrPort) (net.Conn, error) {
	c, err := w.Net.DialUDP(ctx, to)
	if err == nil {
		w.note(c, to)
	}
	return c, err
}
