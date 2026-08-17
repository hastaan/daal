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
// does not answer on it until the address is configured on its interface,
// and nothing in this tree does that — cloud-init never writes it and the
// assign path is pure API. Measured: after a successful assign the API
// showed the address attached while a TLS probe to it timed out and the old
// address still served.
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
			"The provider reports the address attached, so this is almost certainly the guest OS: a "+
			"floating IP is routed to the server but the server does not reply on it until the address "+
			"is configured on its interface. Nothing provisions that today. The record has NOT been "+
			"updated, so packs still point at the working address",
			ErrAddressUnreachable, addr, err)
	}
	_ = c.Close()
	return nil
}
