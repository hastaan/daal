package health

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
)

// ErrAddressUnreachable reports that a relay address accepted no connection.
var ErrAddressUnreachable = errors.New("l3: the new address does not serve")

// AddressServes verifies that a relay actually ANSWERS on an address.
//
// WHY THIS EXISTS — found on real hardware 2026-08-17, and it is the
// difference between an L3 rung that heals a relay and one that kills it.
//
// Attaching a Hetzner floating IP routes packets to the server at the
// provider's network layer, and the API reports success immediately: the
// address shows `server: <id>` and both ownership labels. But the GUEST OS
// does not answer on it until the address is configured on its interface.
// Measured: after a successful assign the API showed the address attached
// while a TLS probe to it timed out and the old address still served.
//
// The assign path now performs that guest-OS step (mgmt.BindAddressWithFW,
// between the provider attach and this probe), so the missing piece is no
// longer missing. This probe did not become redundant when it landed — it
// became the thing that CHECKS it. A bind is the box's own claim about a
// syscall; this is a connection from outside the box to the port recipients
// dial. The whole finding was a case where every layer above reported
// success on a dead address.
//
// rotation.CheckAddressMoved cannot catch this, because it asks whether the
// RECORD changed, not whether the change works. Passing only that, an L3
// swap re-signs every pack onto an address the box never replies on —
// strictly worse than the no-op this rung used to be, because it turns
// "nothing happened" into "everyone is disconnected" while reporting
// success.
//
// This lives in health/ rather than rotation/ deliberately: rotation/ is
// I/O-free by design and delegates every network call to provider.Provider
// (its own opsec test enforces that), while "does the relay answer" is
// exactly this package's job.
func AddressServes(ip net.IP, port int, timeout time.Duration) error {
	if len(ip) == 0 {
		return fmt.Errorf("%w: no address to probe", ErrAddressUnreachable)
	}
	addr := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	c, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return fmt.Errorf("%w: %s did not accept a connection (%v).\n"+
			"The provider reports the address attached AND the relay reported binding it to its interface, so both "+
			"halves claimed success and the address still does not answer. Look at the relay itself: the bind may not "+
			"have survived (check the relay's persisted address config), the port may be firewalled, or sing-box may "+
			"not be running. The record has NOT been updated, so packs still point at the working address",
			ErrAddressUnreachable, addr, err)
	}
	_ = c.Close()
	return nil
}
