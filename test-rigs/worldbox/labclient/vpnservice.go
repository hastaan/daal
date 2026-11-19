//go:build singbox && cgo && linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

// vpn is what VpnService.Builder().establish() gives the Android app: an
// open TUN fd plus the routing that sends the device's traffic into it.
//
//	DaalVpnService.kt                         here
//	-----------------                         ----
//	.addAddress("10.20.30.40", 32)            ip addr add 10.20.30.40/32 dev daal-tun
//	.setMtu(1500)                             ip link set mtu 1500
//	.addRoute("0.0.0.0", 0)                   table 51820: default dev daal-tun
//	(every app's uid → the VPN)               ip rule: uidrange 1-… → table 51820
//	.addDisallowedApplication(self)           …and uid 0, this process, is not in that range
//
// Android implements a VPN as per-uid policy routing, and Daal keeps its
// own upstream sockets out of the tunnel by excluding its own uid (NOT by
// protect(): BuildSingBoxConfig leaves auto_detect_interface off, so the
// engine never calls the registered callback — the rig reports the call
// count so that stays visible). This is the same mechanism with the same
// consequence: if the engine's dial to the relay ever depended on
// something other than uid exclusion, it would loop here as it would
// there.
//
// The engine's hard-coded TUN inbound is 10.20.30.40/30, MTU 1500, gVisor
// stack; the fd handed over must agree with it the way the phone's does.
type vpn struct {
	fd   int
	name string
}

const (
	vpnTable = "51820"
	prioVPN  = "200"
	appUIDs  = "1-65535" // every uid this world has, except 0 (the VPN app itself)
)

func ip(args ...string) error {
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %v (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// openTun opens one TUN device and gives it the address and MTU the
// engine's inbound expects. No routing yet.
func openTun(name string) (*vpn, error) {
	// Non-blocking, as the fd VpnService.Builder.establish() returns is
	// unless the app calls setBlocking(true) (DaalVpnService does not).
	// It matters: the engine's packet reader can only be STOPPED while it
	// waits in poll(); on a blocking fd it sits in readv(), outlives the
	// instance it belonged to, and — when the next instance is given the
	// same TUN — goes on taking packets off it (FINDINGS SW-2).
	flags := syscall.O_RDWR | syscall.O_CLOEXEC
	if os.Getenv("WB_TUN_BLOCKING") == "" {
		flags |= syscall.O_NONBLOCK
	}
	fd, err := syscall.Open("/dev/net/tun", flags, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}
	// struct ifreq { char ifr_name[16]; short ifr_flags; ... } — 40 bytes.
	var ifr [40]byte
	copy(ifr[:15], name)
	const iffTun, iffNoPI = 0x0001, 0x1000
	*(*uint16)(unsafe.Pointer(&ifr[16])) = iffTun | iffNoPI
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TUNSETIFF), uintptr(unsafe.Pointer(&ifr[0]))); e != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("TUNSETIFF %s: %v", name, e)
	}
	v := &vpn{fd: fd, name: name}
	for _, s := range [][]string{
		{"addr", "add", "10.20.30.40/32", "dev", name},
		{"link", "set", name, "mtu", "1500", "up"},
	} {
		if err := ip(s...); err != nil {
			syscall.Close(fd)
			return nil, err
		}
	}
	return v, nil
}

func establish(name string) (*vpn, error) {
	v, err := openTun(name)
	if err != nil {
		return nil, err
	}
	steps := [][]string{
		{"route", "add", "default", "dev", name, "table", vpnTable},
		{"rule", "add", "priority", prioVPN, "uidrange", appUIDs, "lookup", vpnTable},
	}
	for _, s := range steps {
		if err := ip(s...); err != nil {
			v.teardown()
			syscall.Close(v.fd)
			return nil, err
		}
	}
	return v, nil
}

// establishReplacing is a SECOND Builder.establish() while a VPN is up:
// what DaalVpnService did on every route switch before the phone pass of
// 2026-11-19 (it now keeps the TUN it has; switch.go drives both orders).
// Android replaces the interface every app is routed into in one step;
// here that is a new TUN and the per-uid table's default route moved to
// it. The per-uid rule stays. The old interface disappears when its last
// fd is closed — which is the engine's business, and the thing under test.
func establishReplacing(name string) (*vpn, error) {
	v, err := openTun(name)
	if err != nil {
		return nil, err
	}
	if err := ip("route", "replace", "default", "dev", name, "table", vpnTable); err != nil {
		syscall.Close(v.fd)
		return nil, err
	}
	return v, nil
}

// teardown removes the routing. The fd is the engine's once SetTunFD
// accepted it (ClearTunFD, or the SetTunFD that replaces it, closes it),
// so it is not closed here; the interface disappears with the last fd.
func (v *vpn) teardown() {
	_ = ip("rule", "del", "priority", prioVPN)
	_ = ip("route", "flush", "table", vpnTable)
}
