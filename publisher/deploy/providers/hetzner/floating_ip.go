package hetzner

// L3, THE FLOATING-IP SWAP — WHY THIS FILE EXISTS
//
// A blocked address is the failure that actually kills a Daal relay. Every
// other rung of the rotation ladder answers a smaller problem: L1 rotates
// one recipient's credentials, L2 moves a cover host, L4/L5/L6 rebuild the
// box from scratch over minutes. L3 is supposed to be the cheap one — swap
// the address, keep the server, keep the mgmt TLS pin, done in seconds.
//
// It rotated NOTHING until Step 9, and the shape of the bug is worth
// stating because the same shape can come back. AssignFloatingIP set
// rec.FloatingIPID — a field nothing on the wire reads — and left
// rec.PublicIP and every candidate's public_ip:* tag naming the burned
// address. So the sequence was: operator sees an L3 recommendation,
// clicks it, the provider call succeeds, the pack is re-signed, the
// history row commits, the UI says the rotation worked, and the pack in
// every recipient's hands points at exactly the address that was blocked.
// A failure that reports success is worse than one that reports failure,
// because it consumes the operator's belief that they have recovered.
//
// Three things make it real:
//
//  1. an id is not an address. FloatingIPByID turns the operator's opaque
//     numeric id into the thing recipients dial. Nothing did this before,
//     which is the mechanical reason the swap could not work.
//  2. the record has TWO copies of the address (rec.PublicIP and the
//     candidates' tags) and both must move together, or the binder signs a
//     pack that disagrees with itself.
//  3. the cloud says yes before it is true. Assign returns an action;
//     the adapter reads the object back and refuses to claim a swap it
//     cannot see, because the alternative is re-signing against an address
//     that is not routed here.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"

	"daal/publisher/deploy/provider"
)

// errFloatingIPNotFound is the "this address does not exist" answer,
// distinct from "we could not ask". A rollback that cannot tell those
// apart either leaks a billing resource or deletes something it should
// not have.
var errFloatingIPNotFound = errors.New("floating ip not found")

// publicIPTagPrefix is the candidate-tag vocabulary item that carries
// the dialed address. The recommender keys its L3 recommendation off the
// same prefix (rotation/recommender.go), so the two must not drift — so
// it is defined once, in the provider package, and read from there.
const publicIPTagPrefix = provider.PublicIPTagPrefix

// CreateFloatingIP reserves a fresh floating IP for this relay and
// returns its id and address. It does NOT attach it — attachment is
// AssignFloatingIP's job, and keeping them separate is what lets the
// rotation executor roll back a half-done swap (delete an address it
// created; never delete one it merely found).
//
// The address is homed in the relay's own region. That is not a default
// worth overriding lightly: a Hetzner floating IP is announced from its
// home location, and homing it elsewhere both adds a routing detour and
// breaks the R6 claim the relay's cover SNI makes about its
// neighbourhood (see coverSNIPlausibleForAddress).
//
// The name carries a random suffix for the same reason the one-shot SSH
// key does: Hetzner enforces name uniqueness, so a name that is a pure
// function of (publisher key, region) means one orphan from a crashed
// run wedges every later attempt with a uniqueness_error and no way out
// of the app. Ownership is carried by labels, not by the name.
func (p *Provider) CreateFloatingIP(ctx context.Context, rec *provider.OperatorRecord) (string, net.IP, error) {
	if rec == nil {
		return "", nil, errors.New("hetzner: nil OperatorRecord")
	}
	if rec.Region == "" {
		return "", nil, errors.New("hetzner: OperatorRecord without Region — a floating IP needs a home location")
	}
	relay := derivedServerName(rec.PublisherPubKey, rec.Region)
	var suffix [4]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", nil, fmt.Errorf("hetzner: name floating ip: %w", err)
	}
	fip, err := p.c.FloatingIPCreate(ctx, FloatingIPCreateOpts{
		Name:         fmt.Sprintf("%s-fip-%s", relay, hex.EncodeToString(suffix[:])),
		HomeLocation: rec.Region,
		Description:  "daal relay address",
		Labels: map[string]string{
			labelManagedBy: labelManagedByValue,
			labelRelay:     relay,
		},
	})
	if err != nil {
		return "", nil, fmt.Errorf("hetzner: create floating ip: %w", err)
	}
	if fip == nil || len(fip.IP) == 0 {
		return "", nil, errors.New("hetzner: create floating ip returned no address")
	}
	return fip.ID, fip.IP, nil
}

// ReleaseFloatingIP gives an address back after a successful rotation
// has moved off it (or after a failed one that must not leak it).
//
// deleted reports whether the address is actually gone. It comes back
// false, with a nil error, for an address daal-deploy did not create:
// that address is the operator's property, it may be attached to
// something else tomorrow, and binning it would be this adapter
// destroying a resource it does not own. The caller must surface
// deleted=false, because "detached but still reserved" is still on the
// operator's bill — the same honesty rule DecommissionReport.Preserved
// encodes for every other shared resource.
// rec is the relay this release is being performed ON BEHALF OF. It is
// required, and it is what makes the operation safe rather than merely
// idempotent — see the two guards below.
func (p *Provider) ReleaseFloatingIP(ctx context.Context, rec *provider.OperatorRecord, fipID string) (bool, error) {
	if fipID == "" {
		return false, nil
	}
	if rec == nil {
		return false, errors.New("hetzner: release floating ip requires the OperatorRecord it belongs to")
	}
	fip, err := p.c.FloatingIPByID(ctx, fipID)
	switch {
	case errors.Is(err, errFloatingIPNotFound):
		// Already gone. Idempotent success: a retried rollback must
		// not fail because the first attempt worked.
		return true, nil
	case err != nil:
		return false, fmt.Errorf("hetzner: read floating ip %s: %w", fipID, err)
	}
	// GUARD 1, BEFORE ANY MUTATION. An address attached to a DIFFERENT
	// server belongs to a different relay that is answering on it right
	// now. Detaching it — which is what this used to do, unconditionally
	// and before the ownership check — black-holes that relay, and since
	// it also carries our managed-by label the delete then completed and
	// the address was gone for good. One mistyped id, taken from the
	// provider console or from a sibling relay's screen, and every pack
	// that relay ever distributed was dead with no way back.
	//
	// AssignFloatingIP already applies exactly this rule; there is no
	// reason for the destructive verb to be the lenient one.
	if fip.ServerID != "" && fip.ServerID != rec.ServerID {
		return false, fmt.Errorf("hetzner: floating ip %s is attached to server %s, not %s; "+
			"releasing it would take that relay off its address — detach it there first if you really mean to",
			fipID, fip.ServerID, rec.ServerID)
	}
	if fip.ServerID != "" {
		if err := p.c.FloatingIPUnassign(ctx, fipID); err != nil {
			return false, fmt.Errorf("hetzner: unassign floating ip %s: %w", fipID, err)
		}
	}
	if !ownsFloatingIP(fip, rec) {
		return false, nil
	}
	if err := p.c.FloatingIPDelete(ctx, fipID); err != nil {
		return false, fmt.Errorf("hetzner: delete floating ip %s: %w", fipID, err)
	}
	return true, nil
}

// ownsFloatingIP reports whether daal-deploy created this address FOR
// THIS RELAY. Label match only — never a name prefix, for the same
// reason ownsEphemeralKey refuses one.
//
// GUARD 2. Both labels, exactly as ownsEphemeralKey requires both. The
// managed-by label alone says "some daal relay owns this", which in an
// account running two relays is precisely the case where deleting it is
// wrong: sibling addresses all carry it. The relay label is what
// distinguishes "mine" from "my neighbour's", and its absence here was
// the difference between a refused delete and a permanently destroyed
// address on a live relay.
func ownsFloatingIP(fip *FloatingIPInfo, rec *provider.OperatorRecord) bool {
	if fip == nil || rec == nil {
		return false
	}
	if fip.Labels[labelManagedBy] != labelManagedByValue {
		return false
	}
	return fip.Labels[labelRelay] == derivedServerName(rec.PublisherPubKey, rec.Region)
}

// AssignFloatingIP attaches fipID to the record's server AND moves every
// copy of the dialed address on the record: rec.PublicIP and each
// candidate's public_ip:* tag. Both halves, or the swap is a no-op that
// reports success — which is what it did before Step 9.
//
// Idempotent in the way that matters. "Same fipID twice" used to
// short-circuit on rec.FloatingIPID alone, which meant a record already
// carrying the id but still naming the old address — precisely the state
// every pre-Step-9 rotation left behind — could never be repaired: the
// converging call was the one that returned early. Now the early exit is
// conditioned on the record actually being converged, so re-running the
// swap fixes a half-applied one.
//
// Ordering note for callers. This attaches the NEW address; it does not
// detach the old one. That is deliberate and is the rotation's safety
// property: a Hetzner server keeps its primary IPv4 and can hold the old
// floating IP at the same time, so between assign and release the relay
// answers on both, and a failure anywhere in between leaves every
// already-distributed pack still working. Releasing first would open a
// window where the record names an address that routes nowhere.
func (p *Provider) AssignFloatingIP(ctx context.Context, rec *provider.OperatorRecord, fipID string) error {
	if rec == nil || rec.ServerID == "" {
		return errors.New("OperatorRecord without ServerID")
	}
	if fipID == "" {
		return errors.New("hetzner: assign floating ip: empty id")
	}

	// Resolve the address BEFORE touching anything. If this fails we
	// have mutated neither the cloud nor the record.
	fip, err := p.c.FloatingIPByID(ctx, fipID)
	if err != nil {
		return fmt.Errorf("hetzner: read floating ip %s: %w", fipID, err)
	}
	if fip == nil || len(fip.IP) == 0 {
		return fmt.Errorf("hetzner: floating ip %s has no address", fipID)
	}
	if fip.ServerID != "" && fip.ServerID != rec.ServerID {
		// Another server holds it. Stealing it would black-hole
		// whatever relay is currently answering on that address —
		// a rotation must never take a second relay down.
		return fmt.Errorf("hetzner: floating ip %s is attached to server %s, not %s; detach it there first",
			fipID, fip.ServerID, rec.ServerID)
	}
	if err := coverSNIPlausibleForAddress(rec, fip); err != nil {
		return err
	}

	if fip.ServerID != rec.ServerID {
		if err := p.c.FloatingIPAssign(ctx, fipID, rec.ServerID); err != nil {
			return fmt.Errorf("hetzner: assign floating ip: %w", err)
		}
		// Read back rather than assume. The Assign call returns an
		// action id, not a completed routing change, and the record we
		// are about to re-sign a pack against is only worth as much as
		// this confirmation.
		after, err := p.c.FloatingIPByID(ctx, fipID)
		if err != nil {
			return fmt.Errorf("hetzner: confirm floating ip %s after assign: %w", fipID, err)
		}
		if after == nil || after.ServerID != rec.ServerID {
			return fmt.Errorf("hetzner: floating ip %s did not attach to server %s", fipID, rec.ServerID)
		}
		if len(after.IP) == 0 || !after.IP.Equal(fip.IP) {
			return fmt.Errorf("hetzner: floating ip %s changed address under us (%v → %v)", fipID, fip.IP, after.IP)
		}
		fip = after
	}

	rec.FloatingIPID = fipID
	adoptPublicIP(rec, fip.IP)
	return nil
}

// UnassignFloatingIP detaches the recorded floating IP and puts the
// record back on the server's own primary address.
//
// The second half is not optional, and it is the mirror of the bug this
// file exists to fix. Clearing FloatingIPID while leaving rec.PublicIP
// naming the detached address leaves the record asserting a route that
// no longer exists — every pack signed from it afterwards dials an
// address that answers for someone else, or for nobody. So the record
// must be moved back to something that is genuinely routed to this
// server before this call can report success.
//
// Consequence worth stating: if the server cannot be read back, this
// fails and leaves the floating IP ATTACHED. That is the right way
// round. An attached address costs money; a record naming an unrouted
// address costs every recipient their connection.
func (p *Provider) UnassignFloatingIP(ctx context.Context, rec *provider.OperatorRecord) error {
	if rec == nil {
		return nil
	}
	if rec.FloatingIPID == "" {
		return nil
	}
	if rec.ServerID == "" {
		return errors.New("hetzner: cannot unassign a floating IP from a record with no ServerID — the record would be left naming an unrouted address")
	}
	srv, err := p.c.ServerByID(ctx, rec.ServerID)
	if err != nil {
		return fmt.Errorf("hetzner: read server %s before unassigning its floating ip: %w", rec.ServerID, err)
	}
	if srv == nil || len(srv.PublicIP) == 0 {
		return fmt.Errorf("hetzner: server %s reports no primary address to fall back to", rec.ServerID)
	}
	if err := p.c.FloatingIPUnassign(ctx, rec.FloatingIPID); err != nil {
		return fmt.Errorf("hetzner: unassign floating ip: %w", err)
	}
	rec.FloatingIPID = ""
	adoptPublicIP(rec, srv.PublicIP)
	return nil
}

// adoptPublicIP writes one address into every place the record claims a
// dialed address: the PublicIP field the client outbound is built from,
// and the public_ip:* tag on every candidate.
//
// Both, always. A record where they disagree produces a signed pack that
// dials one address and declares another, so a burned-address cooldown
// would keep firing against a relay that had already moved.
//
// The implementation moved to provider.AdoptPublicIP in Wave 6, when
// Vultr became a real L5 target: an adapter-local copy of this fix is
// how the second adapter silently ships without it, which is exactly
// what the pre-Step-9 Vultr AssignFloatingIP did.
func adoptPublicIP(rec *provider.OperatorRecord, ip net.IP) {
	provider.AdoptPublicIP(rec, ip)
}

// retagPublicIP replaces the public_ip:* tag in one candidate's tag
// list, preserving order and collapsing duplicates. See
// provider.RetagPublicIP.
func retagPublicIP(tags []string, ip net.IP) []string {
	return provider.RetagPublicIP(tags, ip)
}

// coverSNIPlausibleForAddress is the Wave-2 interaction, and the reason
// L3 is not simply "swap the address".
//
// THE DECISION: an L3 swap does NOT re-pick the cover SNI, and refuses
// the swap outright when the new address makes the current cover host
// implausible. Both halves need the justification.
//
// Why not re-pick. The rule in publisher/deploy/sni/rule.go admits a
// host on properties of the ADDRESS CLASS, not of the specific address:
// R5 wants the cover host served from hosting/colo/research AS space
// like the relay itself, and R6 wants it in the relay's peering
// neighbourhood. A Hetzner floating IP homed in the relay's own location
// is announced from Hetzner's own AS24940 out of that same location, so
// every property the pick was made on is unchanged, and re-picking would
// buy nothing while costing plenty: the cover host is baked into the
// box's sing-box config in two places (tls.server_name and
// reality.handshake.server), so moving it means an in-place rotate-tls
// call — a different, capability-gated operation on a relay whose
// pinned mgmt binary may not support it at all — inside a 15-second
// budget. An L3 that silently performs an L2 is also a rotation the
// operator did not ask for and cannot see, and L2 invalidates every
// distributed pack on its own account.
//
// Why refuse instead of proceeding. Hetzner permits attaching an address
// homed in location A to a server in location B. Then the packet's
// destination sits in a neighbourhood the cover host was never picked
// for, and the (address, SNI) pair a censor sees for free becomes
// exactly the "obviously implausible IP-to-SNI mapping" the corpus's
// avoid-list ends on — the Wave 2 bug in miniature, one relay at a time.
// Since L3 must not fix it by re-picking (above), the only honest move
// left is to stop and say so. The operator's options are both cheap:
// reserve the address in the relay's own location (what
// CreateFloatingIP does by default), or run an L2 rotate-tls afterwards
// to move the cover host into the new neighbourhood deliberately.
//
// Not judgeable ⇒ allowed. A record with no cover SNI predates Wave 2,
// an address with no home location cannot be placed, and a cover host
// that is not in the pool was either operator-supplied or dropped by an
// audit. Guessing in any of those cases would block rotations that are
// fine.
func coverSNIPlausibleForAddress(rec *provider.OperatorRecord, fip *FloatingIPInfo) error {
	if fip == nil {
		return nil
	}
	if err := provider.CoverSNIPlausibleForAddress(rec, fip.ID, fip.HomeLocation); err != nil {
		return fmt.Errorf("hetzner: %w", err)
	}
	return nil
}
