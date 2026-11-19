package hetzner

import (
	"context"
	"errors"
	"fmt"

	"daal/publisher/deploy/provider"
)

// reclaimServer deletes ONE server the caller named explicitly, with
// IncludeUnclaimedServers set, after re-proving at the moment of the
// delete every rule the app states to the person ("Daal only offers to
// delete things it labelled as its own when it made them"):
//
//  1. the fresh audit's verdict is unclaimed (the server list was read
//     completely — ReclaimOrphansWithOpts refuses before this otherwise),
//  2. no record handed in names this server id,
//  3. a fresh read still shows BOTH ownership labels, managed-by and a
//     daal-relay label equal to the server's own name,
//  4. that name has the derived shape daal-<region>-<16 hex>.
//
// A record that claims the RELAY but names another server id does not
// block it: that is the two-servers-for-one-relay case a failed rebuild
// leaves. After the delete, in the same run: the server's daal-relay-<id>
// firewall (only if nothing else is behind it), the relay's one-shot
// keys (only if no server of that relay is left), and every reserved
// address labelled for the relay that no record names (unbind skipped,
// the server is gone).
func (p *Provider) reclaimServer(ctx context.Context, res provider.AuditedResource, claims recordClaims, rep *provider.ReclaimReport) {
	out := provider.ReclaimOutcome{Kind: provider.KindServer, ID: res.ID, Name: res.Name}
	if res.Verdict != provider.VerdictUnclaimed {
		out.Code = provider.KeptCode(res)
		out.Reason = "refused (" + string(res.Verdict) + "): " + res.Reason
		rep.Add(out)
		return
	}
	if _, claimed := claims.serverIDs[res.ID]; claimed {
		out.Code = provider.ReclaimKeptClaimed
		out.Reason = "refused: a record you supplied names this server"
		rep.Add(out)
		return
	}
	srv, err := p.c.ServerByID(ctx, res.ID)
	switch {
	case errors.Is(err, errServerNotFound):
		out.Deleted, out.Code, out.Reason = true, provider.ReclaimAlreadyGone, "already gone"
		rep.Add(out)
		return
	case err != nil:
		out.Code = provider.ReclaimKeptListUnreadable
		out.Reason = fmt.Sprintf("refused: could not re-read the server before deleting it (%v)", err)
		rep.Add(out)
		return
	}
	relay, marked := markedRelay(srv.Labels)
	if !marked || relay != srv.Name || !looksLikeDerivedRelayName(srv.Name) {
		out.Code = provider.ReclaimKeptNotDaal
		out.Reason = "refused: it does not carry Daal's ownership labels matching its own name, so it is not provably Daal's"
		rep.Add(out)
		return
	}
	if err := p.c.ServerDelete(ctx, srv.ID); err != nil {
		out.Code = provider.ReclaimDeleteFailed
		out.Reason = fmt.Sprintf("refused: delete failed (%v) — it is still running and still billing", err)
		rep.Add(out)
		return
	}
	out.Deleted, out.Code, out.Reason = true, provider.ReclaimDeleted, "deleted; it is no longer billing"
	rep.Add(out)
	p.sweepAfterServerReclaim(ctx, srv.ID, relay, claims, rep)
}

func (p *Provider) sweepAfterServerReclaim(ctx context.Context, serverID, relay string, claims recordClaims, rep *provider.ReclaimReport) {
	// The firewall named for that server, only when no other server sits
	// behind it.
	if fw, err := p.c.FirewallDeleteForServer(ctx, serverID); err != nil {
		rep.Add(provider.ReclaimOutcome{Kind: provider.KindFirewall, Name: firewallNameForServer(serverID),
			Code: provider.ReclaimDeleteFailed, Reason: fmt.Sprintf("refused: delete failed (%v)", err)})
	} else if fw.Found {
		o := provider.ReclaimOutcome{Kind: provider.KindFirewall, ID: fw.FirewallID, Name: firewallNameForServer(serverID)}
		if len(fw.SharedWith) > 0 {
			o.Code, o.Reason = provider.ReclaimKeptInUse, "refused: still applied to another server"
		} else {
			o.Deleted, o.Code, o.Reason = true, provider.ReclaimDeleted, "deleted; nothing was behind it"
		}
		rep.Add(o)
	}

	// One-shot keys: only when no server of that relay is left.
	if other, err := p.c.ServerByName(ctx, relay); err == nil && other != nil {
		rep.Warnf("relay %s still has server %s, so its one-shot keys were left in place", relay, other.ID)
	} else if err != nil && !errors.Is(err, errServerNotFound) {
		rep.Warnf("could not confirm relay %s has no other server (%v); its one-shot keys were left in place", relay, err)
	} else if keys, err := p.c.SSHKeyList(ctx); err != nil {
		rep.Warnf("could not list SSH keys (%v); relay %s's one-shot keys were left in place", err, relay)
	} else {
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

	// Reserved addresses labelled for this relay that no record names.
	fips, err := p.c.FloatingIPList(ctx)
	if err != nil {
		rep.Warnf("could not list floating IPs (%v); an address reserved for %s may still be billing", err, relay)
		return
	}
	for _, f := range fips {
		if f == nil {
			continue
		}
		if r, ok := markedRelay(f.Labels); !ok || r != relay {
			continue
		}
		o := provider.ReclaimOutcome{Kind: provider.KindFloatingIP, ID: f.ID, Name: f.Name}
		switch {
		case hasKey(claims.floatingIPs, f.ID):
			o.Code, o.Reason = provider.ReclaimKeptClaimed, "refused: a record you supplied still names this address"
		case f.ServerID != "" && f.ServerID != serverID:
			o.Code, o.Reason = provider.ReclaimKeptInUse, fmt.Sprintf("refused: attached to server %s", f.ServerID)
		default:
			if err := p.c.FloatingIPDelete(ctx, f.ID); err != nil {
				o.Code, o.Reason = provider.ReclaimDeleteFailed, fmt.Sprintf("refused: delete failed (%v) — it is still reserved and still billing", err)
			} else {
				o.Deleted, o.Code, o.Reason = true, provider.ReclaimReleased, "released; it is no longer billing"
			}
		}
		rep.Add(o)
	}
}

func hasKey(m map[string]string, k string) bool {
	_, ok := m[k]
	return ok
}
