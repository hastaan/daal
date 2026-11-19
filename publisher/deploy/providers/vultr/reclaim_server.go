package vultr

import (
	"context"
	"errors"
	"fmt"

	"daal/publisher/deploy/provider"
)

// reclaimServer deletes ONE instance the caller named explicitly, with
// IncludeUnclaimedServers set, after re-proving at the moment of the
// delete: the audit verdict is unclaimed (complete instance list), no
// record names this instance id, a fresh read still carries BOTH
// ownership tags for a relay whose name equals the instance's label, and
// that label has the derived shape. Then, in the same run: the relay's
// firewall group if it now protects nothing, the relay's one-shot keys if
// no instance of that relay is left, and every reserved IP marked for
// the relay that no record names. Mirrors the Hetzner adapter.
func (p *Provider) reclaimServer(ctx context.Context, res provider.AuditedResource, claims recordClaims, rep *provider.ReclaimReport) {
	out := provider.ReclaimOutcome{Kind: provider.KindServer, ID: res.ID, Name: res.Name}
	if res.Verdict != provider.VerdictUnclaimed {
		out.Code = provider.KeptCode(res)
		out.Reason = "refused (" + string(res.Verdict) + "): " + res.Reason
		rep.Add(out)
		return
	}
	if mapHasKey(claims.instanceIDs, res.ID) {
		out.Code = provider.ReclaimKeptClaimed
		out.Reason = "refused: a record you supplied names this instance"
		rep.Add(out)
		return
	}
	inst, err := p.c.InstanceByID(ctx, res.ID)
	switch {
	case errors.Is(err, errInstanceNotFound):
		out.Deleted, out.Code, out.Reason = true, provider.ReclaimAlreadyGone, "already gone"
		rep.Add(out)
		return
	case err != nil:
		out.Code = provider.ReclaimKeptListUnreadable
		out.Reason = fmt.Sprintf("refused: could not re-read the instance before deleting it (%v)", err)
		rep.Add(out)
		return
	}
	relay, marked := relayFromTags(inst.Tags)
	if !marked || relay != inst.Label || !looksLikeDerivedRelayLabel(inst.Label) {
		out.Code = provider.ReclaimKeptNotDaal
		out.Reason = "refused: it does not carry Daal's ownership tags matching its own label, so it is not provably Daal's"
		rep.Add(out)
		return
	}
	if err := p.c.InstanceDelete(ctx, inst.ID); err != nil {
		out.Code = provider.ReclaimDeleteFailed
		out.Reason = fmt.Sprintf("refused: delete failed (%v) — it is still running and still billing", err)
		rep.Add(out)
		return
	}
	out.Deleted, out.Code, out.Reason = true, provider.ReclaimDeleted, "deleted; it is no longer billing"
	rep.Add(out)

	// Is any instance of this relay left?
	relayAlive, listOK := false, true
	if insts, err := p.c.InstanceList(ctx); err != nil {
		listOK = false
		rep.Warnf("could not re-list instances (%v); relay %s's firewall group and keys were left in place", err, relay)
	} else {
		for _, other := range insts {
			if other == nil || other.ID == inst.ID {
				continue
			}
			if r, ok := relayFromTags(other.Tags); ok && r == relay {
				relayAlive = true
			}
		}
	}
	if listOK && !relayAlive {
		desc := firewallGroupDescription(relay)
		if g, err := p.c.FirewallGroupByDescription(ctx, desc); err == nil && g != nil && markedFor(g.Description, relay) {
			o := provider.ReclaimOutcome{Kind: provider.KindFirewall, ID: g.ID, Name: g.Description}
			if g.InstanceCount > 0 {
				o.Code, o.Reason = provider.ReclaimKeptInUse, "refused: it still protects an instance"
			} else if err := p.c.FirewallGroupDelete(ctx, g.ID); err != nil {
				o.Code, o.Reason = provider.ReclaimDeleteFailed, fmt.Sprintf("refused: delete failed (%v)", err)
			} else {
				o.Deleted, o.Code, o.Reason = true, provider.ReclaimDeleted, "deleted"
			}
			rep.Add(o)
		}
		if keys, err := p.c.SSHKeyList(ctx); err == nil {
			for _, k := range keys {
				if !ownsEphemeralKey(k, relay) {
					continue
				}
				o := provider.ReclaimOutcome{Kind: provider.KindSSHKey, ID: k.ID, Name: k.Name}
				if err := p.c.SSHKeyDelete(ctx, k.ID); err != nil {
					o.Code, o.Reason = provider.ReclaimDeleteFailed, fmt.Sprintf("refused: delete failed (%v)", err)
				} else {
					o.Deleted, o.Code, o.Reason = true, provider.ReclaimDeleted, "removed"
				}
				rep.Add(o)
			}
		}
	}

	rips, err := p.c.ReservedIPList(ctx)
	if err != nil {
		rep.Warnf("could not list reserved IPs (%v); an address reserved for %s may still be billing", err, relay)
		return
	}
	for _, rip := range rips {
		if rip == nil {
			continue
		}
		if r, ok := relayFromMark(rip.Label); !ok || r != relay {
			continue
		}
		o := provider.ReclaimOutcome{Kind: provider.KindFloatingIP, ID: rip.ID, Name: rip.Label}
		switch {
		case mapHasKey(claims.reservedIPs, rip.ID):
			o.Code, o.Reason = provider.ReclaimKeptClaimed, "refused: a record you supplied still names this address"
		case rip.InstanceID != "" && rip.InstanceID != inst.ID:
			o.Code, o.Reason = provider.ReclaimKeptInUse, fmt.Sprintf("refused: attached to instance %s", rip.InstanceID)
		default:
			if err := p.c.ReservedIPDelete(ctx, rip.ID); err != nil {
				o.Code, o.Reason = provider.ReclaimDeleteFailed, fmt.Sprintf("refused: delete failed (%v) — it is still reserved and still billing", err)
			} else {
				o.Deleted, o.Code, o.Reason = true, provider.ReclaimReleased, "released; it is no longer billing"
			}
		}
		rep.Add(o)
	}
}
