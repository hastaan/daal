package vultr

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"

	"daal/publisher/deploy/provider"
)

// L3 ON VULTR — THE ADDRESS SWAP
//
// Vultr's equivalent of a floating IP is a Reserved IP: an address
// reserved in a region, attached to one instance at a time, surviving
// the instance. That is the whole mechanism L3 needs, so L3 works on
// Vultr — with the same two caveats it has on Hetzner, neither of them
// Vultr-specific:
//
//  1. THE GUEST OS MUST BIND IT. A reserved address is ROUTED to the
//     instance by the provider; the instance does not answer on it
//     until the address is configured on its interface. That is what
//     the mgmt plane's /bind-address call is for, it is
//     capability-gated (RelayCapabilities.BindAddress), and a relay
//     whose mgmt binary predates it cannot complete an L3 at all. This
//     was falsified against real Hetzner hardware on 2026-08-17 and the
//     lesson transfers verbatim.
//  2. THE RECORD MUST MOVE WITH THE ADDRESS. An id is not an address.
//     AssignFloatingIP reads the reserved IP back, then moves BOTH
//     copies of the dialed address on the record (see
//     provider.AdoptPublicIP). The version of this adapter that shipped
//     before Wave 6 set FloatingIPID and stopped, which is why
//     rotation.ActionForProvider marked L3 unsupported on Vultr.
//
// NOT VERIFIED ON HARDWARE. Nothing in this package has been run
// against a live Vultr account. The claim being made is that the code
// performs the same sequence the Hetzner adapter performs, with the
// same read-backs and the same refusals — not that a Vultr relay has
// answered on a reserved address.

// CreateFloatingIP reserves a fresh address for this relay and returns
// its id and address. It does NOT attach it — attachment is
// AssignFloatingIP's job, and keeping them separate is what lets a
// rotation roll back a half-done swap: it can delete an address it
// created and must never delete one it merely found.
//
// The address is homed in the relay's own region. Not a default worth
// overriding lightly: a reserved address is announced from its home
// region, and homing it elsewhere both adds a routing detour and breaks
// the R6 claim the relay's cover SNI makes about its neighbourhood (see
// provider.CoverSNIPlausibleForAddress).
func (p *Provider) CreateFloatingIP(ctx context.Context, rec *provider.OperatorRecord) (string, net.IP, error) {
	if rec == nil {
		return "", nil, errors.New("vultr: nil OperatorRecord")
	}
	if rec.Region == "" {
		return "", nil, errors.New("vultr: OperatorRecord without Region — a reserved IP needs a home region")
	}
	relay := derivedInstanceLabel(rec.PublisherPubKey, rec.Region)
	var suffix [4]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", nil, fmt.Errorf("vultr: name reserved ip: %w", err)
	}
	rip, err := p.c.ReservedIPCreate(ctx, ReservedIPCreateOpts{
		Region: rec.Region,
		IPType: "v4",
		// The label is the only field a Vultr reserved IP has, so it
		// carries BOTH ownership facts plus a unique suffix. Ownership
		// is decided by the mark, never by the suffix.
		Label: ownershipMark(relay, "fip-"+hex.EncodeToString(suffix[:])),
	})
	if err != nil {
		return "", nil, fmt.Errorf("vultr: create reserved ip: %w", err)
	}
	if rip == nil || len(rip.IP) == 0 {
		return "", nil, errors.New("vultr: create reserved ip returned no address")
	}
	return rip.ID, rip.IP, nil
}

// ownsReservedIP reports whether daal-deploy created this address FOR
// THIS RELAY. Mark match only — never a name prefix.
//
// BOTH facts, exactly as the Hetzner adapter requires both labels. The
// managed-by half alone says "some daal relay owns this", which in an
// account running two relays is precisely the case where deleting it is
// wrong: sibling addresses all carry it. The relay half is what
// distinguishes "mine" from "my neighbour's", and its absence there was
// once the difference between a refused delete and a permanently
// destroyed address on a live relay.
func ownsReservedIP(rip *ReservedIPInfo, rec *provider.OperatorRecord) bool {
	if rip == nil || rec == nil {
		return false
	}
	return markedFor(rip.Label, derivedInstanceLabel(rec.PublisherPubKey, rec.Region))
}

// ReleaseFloatingIP gives an address back after a rotation has moved
// off it (or after a failed one that must not leak it).
//
// deleted reports whether the address is actually gone. It comes back
// false, with a nil error, for an address daal-deploy did not create:
// that address is the operator's property, it may be attached to
// something else tomorrow, and binning it would be this adapter
// destroying a resource it does not own. The caller must surface
// deleted=false, because "detached but still reserved" is still on the
// operator's bill.
func (p *Provider) ReleaseFloatingIP(ctx context.Context, rec *provider.OperatorRecord, fipID string) (bool, error) {
	if fipID == "" {
		return false, nil
	}
	if rec == nil {
		return false, errors.New("vultr: release reserved ip requires the OperatorRecord it belongs to")
	}
	rip, err := p.c.ReservedIPByID(ctx, fipID)
	switch {
	case errors.Is(err, errReservedIPNotFound):
		// Already gone. Idempotent success: a retried rollback must
		// not fail because the first attempt worked.
		return true, nil
	case err != nil:
		return false, fmt.Errorf("vultr: read reserved ip %s: %w", fipID, err)
	}

	// GUARD 1, BEFORE ANY MUTATION. An address attached to a DIFFERENT
	// instance belongs to a relay that is answering on it right now.
	// Detaching it black-holes that relay, and if it also carries our
	// managed-by mark the delete would then complete and the address
	// would be gone for good. One mistyped id — from the provider
	// console, or from a sibling relay's screen — and every pack that
	// relay ever distributed is dead with no way back.
	if rip.InstanceID != "" && rip.InstanceID != rec.ServerID {
		return false, fmt.Errorf("vultr: reserved ip %s is attached to instance %s, not %s; "+
			"releasing it would take that relay off its address — detach it there first if you really mean to",
			fipID, rip.InstanceID, rec.ServerID)
	}
	if rip.InstanceID != "" {
		if err := p.c.ReservedIPDetach(ctx, fipID, rip.InstanceID); err != nil {
			return false, fmt.Errorf("vultr: detach reserved ip %s: %w", fipID, err)
		}
	}
	// GUARD 2. Ownership decides deletion, and only deletion: the
	// detach above is safe for an address the operator owns and has
	// pointed at this relay, but destroying it is not ours to do.
	if !ownsReservedIP(rip, rec) {
		return false, nil
	}
	if err := p.c.ReservedIPDelete(ctx, fipID); err != nil {
		return false, fmt.Errorf("vultr: delete reserved ip %s: %w", fipID, err)
	}
	return true, nil
}

// AssignFloatingIP attaches fipID to the record's instance AND moves
// every copy of the dialed address on the record: rec.PublicIP and each
// candidate's public_ip:* tag. Both halves, or the swap is a no-op that
// reports success — which is exactly what this adapter did before
// Wave 6.
//
// Idempotent in the way that matters. "Same fipID twice" does not
// short-circuit on rec.FloatingIPID alone: a record already carrying
// the id but still naming the old address is precisely the half-applied
// state a crashed rotation leaves, and the converging call must be able
// to repair it rather than return early.
//
// Ordering note for callers. This attaches the NEW address; it does not
// detach the old one. That is deliberate and is the rotation's safety
// property: the instance keeps its own main IP and can hold the
// reserved address at the same time, so between assign and release the
// relay answers on both, and a failure anywhere in between leaves every
// already-distributed pack still working. Releasing first would open a
// window where the record names an address that routes nowhere.
func (p *Provider) AssignFloatingIP(ctx context.Context, rec *provider.OperatorRecord, fipID string) error {
	if rec == nil || rec.ServerID == "" {
		return errors.New("vultr: OperatorRecord without ServerID")
	}
	if fipID == "" {
		return errors.New("vultr: assign reserved ip: empty id")
	}

	// Resolve the address BEFORE touching anything. If this fails we
	// have mutated neither the cloud nor the record.
	rip, err := p.c.ReservedIPByID(ctx, fipID)
	if err != nil {
		return fmt.Errorf("vultr: read reserved ip %s: %w", fipID, err)
	}
	if rip == nil || len(rip.IP) == 0 {
		return fmt.Errorf("vultr: reserved ip %s has no address", fipID)
	}
	if rip.InstanceID != "" && rip.InstanceID != rec.ServerID {
		// Another instance holds it. Stealing it would black-hole
		// whatever relay is answering on that address; a rotation must
		// never take a second relay down.
		return fmt.Errorf("vultr: reserved ip %s is attached to instance %s, not %s; detach it there first",
			fipID, rip.InstanceID, rec.ServerID)
	}
	if err := provider.CoverSNIPlausibleForAddress(rec, fipID, rip.Region); err != nil {
		return fmt.Errorf("vultr: %w", err)
	}

	if rip.InstanceID != rec.ServerID {
		if err := p.c.ReservedIPAttach(ctx, fipID, rec.ServerID); err != nil {
			return fmt.Errorf("vultr: attach reserved ip: %w", err)
		}
		// Read back rather than assume. The attach call returns before
		// the routing change is complete, and the record we are about
		// to re-sign a pack against is only worth as much as this
		// confirmation.
		after, err := p.c.ReservedIPByID(ctx, fipID)
		if err != nil {
			return fmt.Errorf("vultr: confirm reserved ip %s after attach: %w", fipID, err)
		}
		if after == nil || after.InstanceID != rec.ServerID {
			return fmt.Errorf("vultr: reserved ip %s did not attach to instance %s", fipID, rec.ServerID)
		}
		if len(after.IP) == 0 || !after.IP.Equal(rip.IP) {
			return fmt.Errorf("vultr: reserved ip %s changed address under us (%v → %v)", fipID, rip.IP, after.IP)
		}
		rip = after
	}

	rec.FloatingIPID = fipID
	provider.AdoptPublicIP(rec, rip.IP)
	return nil
}

// UnassignFloatingIP detaches the recorded reserved IP and puts the
// record back on the instance's own main address.
//
// The second half is not optional, and it is the mirror of the bug this
// file exists to avoid. Clearing FloatingIPID while leaving
// rec.PublicIP naming the detached address leaves the record asserting
// a route that no longer exists — every pack signed from it afterwards
// dials an address that answers for somebody else, or for nobody. So
// the record must be moved back onto something genuinely routed to this
// instance before this call can report success.
//
// Consequence worth stating: if the instance cannot be read back, this
// fails and leaves the reserved IP ATTACHED. That is the right way
// round. An attached address costs money; a record naming an unrouted
// address costs every recipient their connection.
func (p *Provider) UnassignFloatingIP(ctx context.Context, rec *provider.OperatorRecord) error {
	if rec == nil || rec.FloatingIPID == "" {
		return nil
	}
	if rec.ServerID == "" {
		return errors.New("vultr: cannot unassign a reserved IP from a record with no ServerID — the record would be left naming an unrouted address")
	}
	inst, err := p.c.InstanceByID(ctx, rec.ServerID)
	if err != nil {
		return fmt.Errorf("vultr: read instance %s before unassigning its reserved ip: %w", rec.ServerID, err)
	}
	if inst == nil || len(inst.MainIP) == 0 {
		return fmt.Errorf("vultr: instance %s reports no main address to fall back to", rec.ServerID)
	}
	if err := p.c.ReservedIPDetach(ctx, rec.FloatingIPID, rec.ServerID); err != nil {
		return fmt.Errorf("vultr: detach reserved ip: %w", err)
	}
	rec.FloatingIPID = ""
	provider.AdoptPublicIP(rec, inst.MainIP)
	return nil
}

// parseIP is net.ParseIP, wrapped so firewall.go does not import net
// twice for one call.
func parseIP(s string) net.IP { return net.ParseIP(s) }
