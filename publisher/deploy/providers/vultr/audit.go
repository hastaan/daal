package vultr

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"daal/publisher/deploy/provider"
)

// THE ACCOUNT AUDIT, ON THE SECOND PROVIDER.
//
// provider/audit.go argues why this exists; the argument lands hardest
// here. L5 deletes the OLD relay before it builds on the new provider,
// so one failed pass leaves no relay at all rather than two — but every
// leftover it CAN strand sits on a second account, one no record on the
// operator's disk points at and not the console they are looking at. A
// retried L5 is how two paid servers on two different accounts actually
// happens. An audit that only knows how to enumerate Hetzner cannot see
// the box the rotation just abandoned.
//
// The AccountAuditor interface is optional, and its doc says why: an
// adapter that cannot enumerate must not grow stubs returning empty
// lists, because an empty list from a blind adapter reads exactly like
// a clean account. That reasoning named Vultr as an example. It no
// longer applies: this adapter enumerates instances, reserved IPs,
// firewall groups and SSH keys for real, so it implements the
// interface for real.
//
// Same rules as the Hetzner implementation, deliberately:
//
//   - proof is the ownership MARK PAIR (managed-by + this relay), never
//     a name prefix;
//   - a failed instance list downgrades every finding to unproven and
//     makes Reclaim refuse outright, because "nothing is behind this"
//     is a claim about the whole list;
//   - an instance is NEVER reclaimable, whatever its marks say. A
//     server is the relay: no label can distinguish the abandoned box
//     from the one every pack in the field points at. Only the operator
//     knows, so they are handed the id, the region, the address and the
//     exact command, and the decision stays theirs.

var _ provider.AccountAuditor = (*Provider)(nil)

// recordClaims is the record side of the join, precomputed once.
type recordClaims struct {
	relays      map[string]*provider.OperatorRecord
	instanceIDs map[string]string // instance id -> relay
	reservedIPs map[string]string // reserved ip id -> relay
}

func claimsFrom(records []*provider.OperatorRecord) recordClaims {
	c := recordClaims{
		relays:      map[string]*provider.OperatorRecord{},
		instanceIDs: map[string]string{},
		reservedIPs: map[string]string{},
	}
	for _, rec := range records {
		if rec == nil {
			continue
		}
		relay := ""
		if len(rec.PublisherPubKey) > 0 && rec.Region != "" {
			relay = derivedInstanceLabel(rec.PublisherPubKey, rec.Region)
			c.relays[relay] = rec
		}
		if rec.ServerID != "" {
			c.instanceIDs[rec.ServerID] = relay
		}
		if rec.FloatingIPID != "" {
			c.reservedIPs[rec.FloatingIPID] = relay
		}
	}
	return c
}

// relayFromTags reads the relay an instance is stamped for. Both tags
// or nothing: the managed-by tag alone is what every sibling relay's
// resources also carry.
func relayFromTags(tags []string) (string, bool) {
	managed, relay := false, ""
	for _, t := range tags {
		t = strings.TrimSpace(t)
		switch {
		case t == tagManagedBy:
			managed = true
		case strings.HasPrefix(t, tagRelayPrefix):
			relay = strings.TrimPrefix(t, tagRelayPrefix)
		}
	}
	if !managed || relay == "" {
		return "", false
	}
	return relay, true
}

// relayFromMark reads the relay out of a single-string field (a
// reserved IP's label, a firewall group's description).
func relayFromMark(field string) (string, bool) {
	managed, relay := false, ""
	for _, tok := range strings.Fields(field) {
		k, v, ok := strings.Cut(tok, "=")
		if !ok {
			continue
		}
		switch k {
		case markManagedByKey:
			managed = managed || v == markManagedByValue
		case markRelayKey:
			relay = v
		}
	}
	if !managed || relay == "" {
		return "", false
	}
	return relay, true
}

// relayFromEphemeralKeyName recovers the relay from a one-shot key's
// name, which is the only handle a Vultr SSH key gives.
func relayFromEphemeralKeyName(name string) (string, bool) {
	const sep = "-ephemeral-"
	i := strings.LastIndex(name, sep)
	if i <= 0 {
		return "", false
	}
	relay := name[:i]
	if !looksLikeDerivedRelayLabel(relay) {
		return "", false
	}
	return relay, true
}

// looksLikeDerivedRelayLabel matches the SHAPE daal-deploy mints —
// "daal-<region>-<16 hex>" — and nothing else. It is used only to
// report a resource as UNPROVEN, never to claim one: a shape is not
// ownership.
func looksLikeDerivedRelayLabel(name string) bool {
	parts := strings.Split(name, "-")
	if len(parts) != 3 || parts[0] != "daal" || parts[1] == "" || len(parts[2]) != 16 {
		return false
	}
	for _, c := range parts[2] {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}

// AuditAccount enumerates the Vultr account and classifies everything
// carrying this tool's ownership marks.
//
// Read-only. Every call in here is a list or a get, so the audit cannot
// mutate the account even if its reasoning is wrong — which is why it
// is safe to run first, and always.
func (p *Provider) AuditAccount(ctx context.Context, records []*provider.OperatorRecord) (*provider.AccountAudit, error) {
	now := p.clock
	if now == nil {
		now = time.Now
	}
	audit := provider.NewAccountAudit("vultr", now())
	claims := claimsFrom(records)

	// --- the ground truth every orphan finding depends on ---
	instances, instErr := p.c.InstanceList(ctx)
	byRelay := map[string]*InstanceInfo{}
	byID := map[string]*InstanceInfo{}
	if instErr != nil {
		audit.Warnf("could not list instances (%v) — nothing can be proven orphaned without the full instance list, so every finding below is reported as unproven and reclaim will refuse", instErr)
	} else {
		audit.ServerListComplete = true
		for _, inst := range instances {
			if inst == nil {
				continue
			}
			byID[inst.ID] = inst
			if relay, ok := relayFromTags(inst.Tags); ok {
				byRelay[relay] = inst
			}
		}
	}

	// --- the record side of the join ---
	for relay, rec := range claims.relays {
		k := provider.KnownRelay{Relay: relay, RecordServerID: rec.ServerID, Region: rec.Region}
		if live, ok := byRelay[relay]; ok {
			k.LiveServerID = live.ID
			switch {
			case rec.ServerID == "":
				// The classic orphaned provision: the wizard writes
				// the record back only on success, so an empty id
				// beside a live box is a provision that built the
				// instance and then died.
				k.Note = "your record has no instance id but an instance tagged for this relay is running — the provision that created it never completed"
			case rec.ServerID != live.ID:
				k.Note = fmt.Sprintf("your record names instance %s but the instance tagged for this relay is %s — one of them is not yours to keep paying for", rec.ServerID, live.ID)
			}
		} else if audit.ServerListComplete {
			k.Note = "no instance tagged for this relay is running; the record describes a relay that is gone"
		}
		audit.Known = append(audit.Known, k)
	}

	p.auditInstances(audit, instances, claims)
	p.auditReservedIPs(ctx, audit, byRelay, claims)
	p.auditSSHKeys(ctx, audit, byRelay)
	p.auditFirewallGroups(ctx, audit, byRelay)

	audit.Sort()
	return audit, nil
}

func (p *Provider) auditInstances(audit *provider.AccountAudit, instances []*InstanceInfo, claims recordClaims) {
	for _, inst := range instances {
		if inst == nil {
			continue
		}
		relay, marked := relayFromTags(inst.Tags)
		if !marked {
			// Labelled like one of ours but carrying no marks. Any
			// tool may pick any label, so this is reported and never
			// claimed.
			if looksLikeDerivedRelayLabel(inst.Label) {
				audit.Add(provider.AuditedResource{
					Kind: provider.KindServer, ID: inst.ID, Name: inst.Label,
					Verdict: provider.VerdictUnproven, Billing: true,
					Reason: "labelled like a daal relay but carries no " + tagManagedBy + " tag, so this tool cannot tell whether it built this instance or you did",
					Hint:   "check it in the Vultr console (Products → Compute → " + inst.Label + "); if it is a relay you provisioned with an older build, tear it down with `daal-deploy decommission`",
				})
			}
			continue
		}
		res := provider.AuditedResource{
			Kind: provider.KindServer, ID: inst.ID, Name: inst.Label, Relay: relay, Billing: true,
		}
		claimRelay, byRelay := claims.relays[relay]
		_, claimedByID := claims.instanceIDs[inst.ID]
		switch {
		case claimedByID || byRelay:
			res.Verdict = provider.VerdictInUse
			res.Reason = "a record you supplied claims this relay"
			if byRelay && claimRelay.ServerID != "" && claimRelay.ServerID != inst.ID {
				res.Verdict = provider.VerdictUnclaimed
				res.Reason = fmt.Sprintf("your record for %s names instance %s, not this one — this is the shape a failed rebuild leaves: two paid servers for one relay", relay, claimRelay.ServerID)
				res.Hint = "confirm in the Vultr console which address your recipients are actually reaching, then remove the other one"
			}
		default:
			res.Verdict = provider.VerdictUnclaimed
			res.Reason = "this instance was built by daal-deploy but no record you supplied claims it; it is running and billing"
			res.Hint = fmt.Sprintf("if you still hold its OperatorRecord, run `daal-deploy decommission --provider vultr --record-file <record> --token-file <token>`; if you do not, delete instance %s (%s) in the Vultr console, or run: %s",
				inst.ID, inst.Label, removeCommand("instances", inst.ID))
		}
		// NEVER reclaimable. See the file comment.
		audit.Add(res)
	}
}

func (p *Provider) auditReservedIPs(ctx context.Context, audit *provider.AccountAudit, byRelay map[string]*InstanceInfo, claims recordClaims) {
	rips, err := p.c.ReservedIPList(ctx)
	if err != nil {
		audit.Warnf("could not list reserved IPs (%v) — an address this tool reserved may be sitting on your bill unseen; check Products → Network → Reserved IPs in the Vultr console", err)
		return
	}
	for _, rip := range rips {
		if rip == nil {
			continue
		}
		relay, marked := relayFromMark(rip.Label)
		if !marked {
			continue // the operator's own address; this tool has no opinion
		}
		res := provider.AuditedResource{
			Kind: provider.KindFloatingIP, ID: rip.ID, Name: rip.Label, Relay: relay, Billing: true,
		}
		switch {
		case !audit.ServerListComplete:
			res.Verdict = provider.VerdictUnproven
			res.Reason = "the instance list could not be read, so whether anything is answering on this address cannot be established"
			res.Hint = "re-run the audit once the API is reachable"
		case rip.InstanceID != "":
			res.Verdict = provider.VerdictInUse
			res.Reason = fmt.Sprintf("attached to instance %s — something is answering on it", rip.InstanceID)
		case mapHasKey(claims.reservedIPs, rip.ID):
			// Rule 3: a record-named address is never reclaimed. The
			// operator may be mid-rotation, holding it deliberately.
			res.Verdict = provider.VerdictUnclaimed
			res.Reason = "detached, but a record you supplied still names it — it is reserved and still billing"
			res.Hint = "if the rotation that reserved it is finished, release it with `daal-deploy floating-ip release`"
		case byRelay[relay] != nil:
			res.Verdict = provider.VerdictUnclaimed
			res.Reason = "detached, but the relay it belongs to is still running — this is the shape a half-finished address swap leaves"
			res.Hint = "re-attach it with `daal-deploy floating-ip assign`, or release it if the swap was abandoned"
		default:
			res.Verdict = provider.VerdictOrphan
			res.Reclaimable = true
			res.Reason = "reserved by daal-deploy for a relay that no longer exists, attached to nothing, and still billing"
			res.Hint = "reclaim it, or delete it with: " + removeCommand("reserved-ips", rip.ID)
		}
		audit.Add(res)
	}
}

func (p *Provider) auditSSHKeys(ctx context.Context, audit *provider.AccountAudit, byRelay map[string]*InstanceInfo) {
	keys, err := p.c.SSHKeyList(ctx)
	if err != nil {
		audit.Warnf("could not list SSH keys (%v) — a one-shot provisioning key may be left behind; a survivor is what blocks the next provision", err)
		return
	}
	for _, k := range keys {
		relay, ok := relayFromEphemeralKeyName(k.Name)
		if !ok {
			continue
		}
		res := provider.AuditedResource{
			Kind: provider.KindSSHKey, ID: k.ID, Name: k.Name, Relay: relay,
			// Not billing, but expensive in its own way: an orphaned
			// key is what has already wedged this project's operator.
			Billing: false,
		}
		switch {
		case !audit.ServerListComplete:
			res.Verdict = provider.VerdictUnproven
			res.Reason = "the instance list could not be read, so whether this key's relay still exists cannot be established"
		case byRelay[relay] != nil:
			res.Verdict = provider.VerdictInUse
			res.Reason = "its relay is still running; the key is harmless and removing it does not affect the running box"
		default:
			res.Verdict = provider.VerdictOrphan
			res.Reclaimable = true
			res.Reason = "a one-shot provisioning key for a relay that no longer exists"
			res.Hint = "reclaim it, or delete it with: " + removeCommand("ssh-keys", k.ID)
		}
		audit.Add(res)
	}
}

func (p *Provider) auditFirewallGroups(ctx context.Context, audit *provider.AccountAudit, byRelay map[string]*InstanceInfo) {
	groups, err := p.c.FirewallGroupList(ctx)
	if err != nil {
		audit.Warnf("could not list firewall groups (%v) — a group from a failed provision may be left behind (it costs nothing, but it is clutter in your account)", err)
		return
	}
	for _, g := range groups {
		relay, ok := relayFromMark(g.Description)
		if !ok {
			continue
		}
		res := provider.AuditedResource{
			Kind: provider.KindFirewall, ID: g.ID, Name: g.Description, Relay: relay,
		}
		switch {
		case !audit.ServerListComplete:
			res.Verdict = provider.VerdictUnproven
			res.Reason = "the instance list could not be read, so whether this group still protects a relay cannot be established"
		case g.InstanceCount > 0:
			res.Verdict = provider.VerdictInUse
			res.Reason = fmt.Sprintf("still attached to %d instance(s) — deleting it would strip a live relay's only protection for its mgmt port", g.InstanceCount)
		case byRelay[relay] != nil:
			res.Verdict = provider.VerdictInUse
			res.Reason = "its relay is still running; the group is the firewall that relay will be re-attached to on its next rebuild"
		default:
			res.Verdict = provider.VerdictOrphan
			res.Reclaimable = true
			res.Reason = "a firewall group for a relay that no longer exists, protecting nothing"
			res.Hint = "reclaim it, or delete it with: " + removeCommand("firewalls", g.ID)
		}
		audit.Add(res)
	}
}

// ReclaimOrphans deletes what the audit proved orphaned.
//
// It re-runs the audit against FRESH provider reads rather than
// trusting a report the caller passes in: between an operator reading a
// report and confirming it, a relay can be provisioned, an address
// attached, a rotation started. The audit the human approved is a
// description of the past, and deleting against it is how a sweep eats
// a live relay.
func (p *Provider) ReclaimOrphans(ctx context.Context, records []*provider.OperatorRecord, only []provider.ResourceRef) (*provider.ReclaimReport, error) {
	rep := provider.NewReclaimReport("vultr")
	audit, err := p.AuditAccount(ctx, records)
	if err != nil {
		return rep, fmt.Errorf("vultr: audit before reclaim: %w", err)
	}
	rep.Warnings = append(rep.Warnings, audit.Warnings...)

	// The one refusal that covers everything. Orphanhood is a claim
	// about the whole instance list; without it there is no such claim
	// to act on.
	if !audit.ServerListComplete {
		return rep, errors.New("vultr: refusing to reclaim anything — the account's instance list could not be read, and \"nothing is behind this resource\" is a statement about that list. Fix the API access and re-run")
	}

	want := map[provider.ResourceRef]bool{}
	for _, r := range only {
		want[r] = true
	}
	seen := map[provider.ResourceRef]bool{}

	for _, res := range audit.Resources {
		ref := res.Ref()
		if len(want) > 0 && !want[ref] {
			continue
		}
		seen[ref] = true
		if !res.Reclaimable {
			// Named, never silently skipped: an operator who asked for
			// a specific resource must be told why it survived.
			rep.Add(provider.ReclaimOutcome{
				Kind: res.Kind, ID: res.ID, Name: res.Name, Deleted: false,
				Reason: "refused (" + string(res.Verdict) + "): " + res.Reason,
			})
			continue
		}
		rep.Add(p.reclaimOne(ctx, res))
	}
	for ref := range want {
		if seen[ref] {
			continue
		}
		rep.Add(provider.ReclaimOutcome{
			Kind: ref.Kind, ID: ref.ID, Deleted: false,
			Reason: "refused: this audit did not find " + ref.String() + " on the account, or could not prove it belongs to daal-deploy — nothing was deleted",
		})
	}
	return rep, nil
}

// reclaimOne re-verifies one resource against fresh reads and then
// deletes it. The re-verification is not belt-and-braces; it is the
// only guard that runs at the same instant as the mutation.
func (p *Provider) reclaimOne(ctx context.Context, res provider.AuditedResource) provider.ReclaimOutcome {
	out := provider.ReclaimOutcome{Kind: res.Kind, ID: res.ID, Name: res.Name}
	switch res.Kind {
	case provider.KindFloatingIP:
		rip, err := p.c.ReservedIPByID(ctx, res.ID)
		switch {
		case errors.Is(err, errReservedIPNotFound):
			out.Deleted = true
			out.Reason = "already gone"
			return out
		case err != nil:
			out.Reason = fmt.Sprintf("refused: could not re-read the address before deleting it (%v)", err)
			return out
		}
		if rip.InstanceID != "" {
			out.Reason = fmt.Sprintf("refused: it has been attached to instance %s since the audit ran — something is answering on it now", rip.InstanceID)
			return out
		}
		if relay, ok := relayFromMark(rip.Label); !ok || relay != res.Relay {
			out.Reason = "refused: its ownership mark no longer matches the relay the audit attributed it to"
			return out
		}
		if err := p.c.ReservedIPDelete(ctx, res.ID); err != nil {
			out.Reason = fmt.Sprintf("refused: delete failed (%v) — it is still reserved and still billing", err)
			return out
		}
		out.Deleted = true
		out.Reason = "released; it is no longer billing"
		return out

	case provider.KindSSHKey:
		// Re-verify by re-listing: there is no get-by-id on this
		// surface, and re-listing is what proves the key is still
		// there in the shape the audit judged.
		keys, err := p.c.SSHKeyList(ctx)
		if err != nil {
			out.Reason = fmt.Sprintf("refused: could not re-read the account's SSH keys before deleting (%v)", err)
			return out
		}
		found := false
		for _, k := range keys {
			if k.ID != res.ID {
				continue
			}
			found = true
			if relay, ok := relayFromEphemeralKeyName(k.Name); !ok || relay != res.Relay {
				out.Reason = "refused: its name no longer identifies it as this relay's one-shot key"
				return out
			}
		}
		if !found {
			out.Deleted = true
			out.Reason = "already gone"
			return out
		}
		if err := p.c.SSHKeyDelete(ctx, res.ID); err != nil {
			out.Reason = fmt.Sprintf("refused: delete failed (%v) — it may still block the next provision", err)
			return out
		}
		out.Deleted = true
		out.Reason = "deleted; it can no longer collide with a future provision"
		return out

	case provider.KindFirewall:
		g, err := p.c.FirewallGroupByDescription(ctx, res.Name)
		if err != nil {
			out.Reason = fmt.Sprintf("refused: could not re-read the firewall group before deleting it (%v)", err)
			return out
		}
		if g == nil {
			out.Deleted = true
			out.Reason = "already gone"
			return out
		}
		if g.ID != res.ID {
			out.Reason = "refused: the group carrying this description is a different object than the audit judged"
			return out
		}
		if g.InstanceCount > 0 {
			out.Reason = fmt.Sprintf("refused: %d instance(s) have been attached to it since the audit ran", g.InstanceCount)
			return out
		}
		if err := p.c.FirewallGroupDelete(ctx, res.ID); err != nil {
			out.Reason = fmt.Sprintf("refused: delete failed (%v)", err)
			return out
		}
		out.Deleted = true
		out.Reason = "deleted"
		return out

	default:
		// Servers land here and always will. See the file comment.
		out.Reason = "refused: this tool does not delete a " + res.Kind + " automatically"
		return out
	}
}

// mapHasKey asks whether a record NAMED this resource, which is not the
// same question as "did that record also resolve to a relay name". A
// record can carry a floating_ip_id and no publisher key (a hand-edited
// or truncated record is exactly the kind the operator still has after
// a crash), and testing the map's VALUE instead of its presence would
// classify the address that record names as an orphan and delete it.
func mapHasKey(m map[string]string, k string) bool {
	_, ok := m[k]
	return ok
}
