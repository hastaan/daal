package vultr

import (
	"context"
	"fmt"
	"strings"

	"daal/publisher/deploy/provider"
)

// PROVISIONING WITH A ROLLBACK — WHY THIS FILE EXISTS
//
// Before this wave, a failed provision left a billing server and an SSH
// key that blocked every retry. That is not a hypothetical: it happened
// to this project's own operator, and it is recorded in their notes as
// the reason provisioning "has no rollback".
//
// L5 makes it strictly worse, though not by running two boxes at once.
// The wizard calls reprovision — which deletes and does NOT re-create —
// before it calls provision, so the Hetzner relay is already gone by the
// time this file runs. What L5 adds is WHERE the wreckage lands: on a
// second account, named by no record on the operator's disk, and not the
// console they are looking at. A retry then builds a second Vultr box
// beside whatever the first attempt stranded. So a half-built provision
// here must either clean up after itself or name precisely what it could
// not.
//
// So this adapter registers an undo for every resource as it creates
// it, and a failure takes exactly one of three honest exits:
//
//  1. Nothing is billing yet (the instance was never created). Clean up
//     unconditionally — a firewall group with no instance protects
//     nothing — and if the cleanup itself fails, say what survived and
//     the command that removes it.
//  2. An instance exists and the caller asked for rollback. Destroy it
//     and its firewall, in that order, and fold the outcome of the
//     rollback into the error: a failed rollback is worse news than the
//     original failure, not less.
//  3. An instance exists and the caller did not ask for rollback. Leave
//     it — a slow boot is recoverable and the idempotent retry path
//     reuses the box — but emit a provision_orphan event and repeat the
//     id, address, region and removal command inside the error, so the
//     caller can show exactly what is running and offer to remove it.
//
// The one thing that never happens is a silent return. There is no exit
// from a half-built provision that does not name what is left.
//
// The one-shot SSH key is not tracked here because Provision deletes it
// in a `defer` on every exit path, success included, with
// context.WithoutCancel so a cancelled provision still reaches it.

// provisionScope records what one Provision call created, in creation
// order, so a failure can undo it in reverse.
type provisionScope struct {
	p      *Provider
	relay  string
	region string

	// firewallGroupID is set ONLY when this call created the group.
	// A group that was already there (a previous attempt's, found by
	// description) belongs to the relay, not to this attempt, and
	// deleting it on failure would strip a live box.
	firewallGroupID string
	instanceID      string
	instanceIP      string
}

// leftover is one resource that survived a failure.
type leftover struct {
	kind string // vultr API collection: "instances", "firewalls", ...
	id   string
	what string // human description
}

func (l leftover) String() string {
	return fmt.Sprintf("%s %s — remove with: %s", l.what, l.id, removeCommand(l.kind, l.id))
}

// unwind performs the cleanup a failed provision calls for and returns
// the error Provision should surface. See the three exits above.
func (s *provisionScope) unwind(ctx context.Context, opts provider.ProvisionOpts, progress func(step, message string), cause error) error {
	// WithoutCancel throughout: a cancelled provision is precisely the
	// case whose cleanup must still reach the cloud API.
	ctx = context.WithoutCancel(ctx)
	var left []leftover

	if s.instanceID == "" {
		// Exit 1: nothing is billing. Clean up unconditionally.
		if s.firewallGroupID != "" {
			if err := s.p.c.FirewallGroupDelete(ctx, s.firewallGroupID); err != nil {
				left = append(left, leftover{"firewalls", s.firewallGroupID,
					fmt.Sprintf("firewall group (could not delete: %v)", err)})
			}
		}
		if len(left) == 0 {
			return fmt.Errorf("%w [nothing was created that is still running or billing]", cause)
		}
		progress("provision_orphan", "Cleanup left something behind: "+renderLeftovers(left)+". "+auditPointer)
		return fmt.Errorf("%w [cleanup incomplete: %s. %s]", cause, renderLeftovers(left), auditPointer)
	}

	where := fmt.Sprintf("instance_id=%s ip=%s region=%s", s.instanceID, s.instanceIP, s.region)

	if !opts.RollbackOnFailure {
		// Exit 3: leave it, name it.
		progress("provision_orphan", fmt.Sprintf(
			"Provisioning failed but the instance is still running and still billing: %s. "+
				"Remove the relay from Daal (delete the server), or remove it directly with: %s. %s",
			where, removeCommand("instances", s.instanceID), auditPointer))
		return fmt.Errorf("%w [the instance is still running and still billing: %s — remove with: %s. %s]",
			cause, where, removeCommand("instances", s.instanceID), auditPointer)
	}

	// Exit 2: destroy what we created.
	progress("provision_rollback", fmt.Sprintf("Provisioning failed — removing the instance that was just created (%s)", where))
	if err := s.p.c.InstanceDelete(ctx, s.instanceID); err != nil {
		left = append(left, leftover{"instances", s.instanceID,
			fmt.Sprintf("instance (STILL BILLING; could not delete: %v)", err)})
		// The firewall is deliberately NOT touched: it is the only
		// thing standing between a surviving box's random mgmt port
		// and the internet.
		//
		// This is the worst exit in the file: a box is billing on the
		// account L5 rebuilds ONTO, and the caller is about to discard
		// the record that would have named it. The removal command
		// above only reaches the resources this call happened to be
		// holding, so the pointer to the record-free verb belongs here
		// most of all.
		progress("provision_orphan", "Rollback failed: "+renderLeftovers(left)+". "+auditPointer)
		return fmt.Errorf("%w [rollback failed, %s: %s. %s]", cause, where, renderLeftovers(left), auditPointer)
	}
	if s.firewallGroupID != "" {
		if err := s.p.c.FirewallGroupDelete(ctx, s.firewallGroupID); err != nil {
			left = append(left, leftover{"firewalls", s.firewallGroupID,
				fmt.Sprintf("firewall group (nothing is billing for it; could not delete: %v)", err)})
		}
	}
	if len(left) > 0 {
		progress("provision_rollback", "Rolled back with leftovers: "+renderLeftovers(left))
		return fmt.Errorf("%w [rolled back: the instance was deleted and nothing is billing, but %s]", cause, renderLeftovers(left))
	}
	progress("provision_rollback", "Rolled back: the instance has been deleted, nothing is billing")
	return fmt.Errorf("%w [rolled back: instance deleted, nothing is billing]", cause)
}

func renderLeftovers(left []leftover) string {
	parts := make([]string, 0, len(left))
	for _, l := range left {
		parts = append(parts, l.String())
	}
	return strings.Join(parts, "; ")
}
