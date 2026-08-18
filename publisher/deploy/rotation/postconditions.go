package rotation

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"daal/publisher/deploy/provider"
)

// THIS FILE IS WHAT SURVIVED THE GO ROTATION EXECUTOR.
//
// Until Wave 6 this package also held `Executor`: a second, complete
// implementation of the rotation ladder, with a transaction, a
// wall-clock budget and a Revert — and no production caller. The live
// ladder is `rotate_execute` in
// client-shell/tauri/daal-wizard/src/commands.rs, which drives the
// provider through this repository's `daal-deploy` CLI and commits its
// history transaction in rusqlite. The Go executor was deleted rather
// than wired up; the reasoning, and what its guarantees became, is in
// docs/decisions/0004-one-rotation-executor.md. Read that before adding
// anything here that looks like an execution step.
//
// What is left is the part that was never duplicated: the two
// post-conditions of an address swap, the optional provider capability
// an L3 needs, and the cross-language budget constant. All three are
// called from the live path (`daal-deploy assign-fip`), which is why
// they are here rather than gone.

// L3FastPathBudget is the wall-clock ceiling for the floating-IP swap,
// pinned here as the single Go-side definition of a number that appears
// in three places: this constant, `L3_FAST_PATH_BUDGET` in the wizard
// (client-shell/tauri/daal-wizard/src/commands.rs, which is where it is
// ENFORCED), and the soak rig's `v1-5-l3-fast-path` scenario.
//
// It is a product promise, not a tuning knob: an L3 exists because a
// burned address should be replaced faster than a censor reacts and
// faster than a user gives up, and a "fast path" that quietly became 30
// seconds would be an outage nobody was warned about.
//
// IT HAS NEVER BEEN MEASURED, and the flow it bounds grew in Wave 3c
// (two ephemeral firewall windows and a guest-OS bind were added). Every
// suite that asserts it asserts it against an INJECTED duration, so all
// three are green regardless of what the real thing costs. Backlog
// W3-10 owns the measurement; until a real L3 is timed on hardware the
// number does not move, because moving an unmeasured promise in either
// direction is guessing.
const L3FastPathBudget = 15 * time.Second

var (
	// ErrL3AddressUnchanged is the post-condition that makes an L3 on
	// an un-fixed provider adapter fail loudly instead of quietly
	// re-signing against the burned address. See CheckAddressMoved.
	ErrL3AddressUnchanged = errors.New("rotation: L3 completed without moving the record's dialled address")

	// ErrRecordAddressInconsistent fires when rec.PublicIP and the
	// candidates' public_ip:* tags disagree — a record that would sign
	// a pack dialling one address while declaring another.
	ErrRecordAddressInconsistent = errors.New("rotation: record's public IP and candidate public_ip:* tags disagree")
)

// FloatingIPProvisioner is the OPTIONAL half of the provider contract
// that makes L3 self-service.
//
// It is deliberately not on provider.Provider. Reserving and releasing
// an address is a capability a provider adapter either has or does not
// (today: Hetzner and Vultr do — Hetzner Floating IPs and Vultr
// Reserved IPs; Stark attaches an address the operator already owns and
// cannot mint one), and forcing it into the shared
// interface would mean two adapters growing methods that return
// "not implemented" — a shape this repository already has too much of.
// An optional interface lets the caller ask, and say plainly what is
// missing when the answer is no.
//
// publisher/deploy/cli mirrors this locally (floatingIPReserver) for the
// same reason it mirrors providerFace; the two must stay in step.
type FloatingIPProvisioner interface {
	// CreateFloatingIP reserves a fresh address for this relay,
	// unattached, and returns its provider id and the address itself.
	CreateFloatingIP(ctx context.Context, rec *provider.OperatorRecord) (id string, addr net.IP, err error)

	// ReleaseFloatingIP detaches an address and, if the adapter
	// created it, deletes it. deleted=false with a nil error means
	// "detached, still reserved, still billing, not ours to delete".
	ReleaseFloatingIP(ctx context.Context, rec *provider.OperatorRecord, id string) (deleted bool, err error)
}

// CheckAddressMoved is the post-condition that turns "the provider says
// it swapped" into "the record actually moved".
//
// The failure it catches is the whole reason Step 9 exists: an adapter
// that records the floating-IP id and leaves rec.PublicIP naming the
// burned address produces a rotation that reports success, re-signs a
// pack, and changes nothing a censor can see. That is strictly worse
// than a visible failure, because the operator stops looking.
func CheckAddressMoved(before, after net.IP) error {
	if len(after) == 0 {
		return fmt.Errorf("%w: the record has no public IP after the swap", ErrL3AddressUnchanged)
	}
	if len(before) > 0 && before.Equal(after) {
		return fmt.Errorf("%w: still %s — this provider adapter attaches the address without moving the record onto it, "+
			"so a pack signed now would point straight back at the address you are rotating away from", ErrL3AddressUnchanged, after)
	}
	return nil
}

// CheckRecordAddressConsistent enforces that the record's two copies of
// the dialled address agree: OperatorRecord.PublicIP, which the client
// outbound is built from, and each candidate's public_ip:* tag, which
// the risk graph groups on and the recommender reads back when deciding
// whether an address is in cooldown.
//
// They are separate fields, so they can drift, and a drifted record
// signs a pack that dials one address while declaring another — the
// address cooldown then keeps firing against a relay that has already
// moved, which reads to the operator as "rotation did not help".
func CheckRecordAddressConsistent(rec *provider.OperatorRecord) error {
	if rec == nil || len(rec.PublicIP) == 0 {
		return nil
	}
	want := publicIPTag + rec.PublicIP.String()
	for i, c := range rec.Candidates {
		seen := 0
		for _, t := range c.PublicRiskTags {
			if !strings.HasPrefix(t, publicIPTag) {
				continue
			}
			seen++
			if t != want {
				return fmt.Errorf("%w: candidate %d (%s) carries %q while the record says %s",
					ErrRecordAddressInconsistent, i, c.Family, t, rec.PublicIP)
			}
		}
		if seen == 0 {
			return fmt.Errorf("%w: candidate %d (%s) carries no %s tag at all",
				ErrRecordAddressInconsistent, i, c.Family, publicIPTag)
		}
	}
	return nil
}

// publicIPTag is the candidate-tag prefix carrying the dialled address.
// Mirrors the providers' own constant; the recommender keys its L3
// recommendation off the same string (recommender.go), so all three
// must stay in step.
const publicIPTag = "public_ip:"
