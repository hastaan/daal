package hetzner

// THE ACCOUNT AUDIT — WHAT THIS ADAPTER CAN AND CANNOT PROVE.
//
// The contract, the verdict vocabulary and the reasoning behind them
// live in provider/audit.go. This file is the Hetzner half: it knows
// which labels exist, which names are pure functions of the operator's
// own material, and therefore which claims about ownership are proofs
// and which are guesses.
//
// # ONE GOVERNING RULE
//
// A resource is reclaimable only when all three hold:
//
//	1. it carries daal-deploy's ownership marks,
//	2. no LIVE SERVER stands behind it, and
//	3. no OperatorRecord handed to the audit mentions it.
//
// Rule 3 is not redundant with rule 2, and it is the rule that stops
// this being a bill-reducer that costs the operator something. A
// floating IP survives a decommission on purpose — the whole value of
// a reserved address is that it OUTLIVES the box, so the next relay
// can stand up on it and every distributed pack keeps working. That is
// the cheapest continuity this project has. A record that still names
// an address is the operator saying "I am keeping this", and a sweep
// that bins it has spent something no rerun can get back. So a
// record-named address is reported, priced and explained — never
// reclaimed.
//
// # WHAT IT WILL NOT DO
//
// It will never delete a server. Rule 2 disqualifies everything a
// server backs, and a server backs itself. There is no label that can
// distinguish "the abandoned box from the L4 that died" from "the box
// every pack in the field dials" — only the operator knows, so an
// unclaimed server is reported with its id, region, address and the
// exact decommission command, and the decision stays theirs.
//
// # THE PROOFS, AND THEIR LIMITS, PER KIND
//
//	server       labels(managed-by + daal-relay). A server whose NAME
//	             looks derived but carries no label is unproven, not
//	             ours: `--existing-server-id` adopts boxes we did not
//	             create, and other tools can pick any name they like.
//
//	floating IP  labels(managed-by + daal-relay), exactly as
//	             ownsFloatingIP demands both. managed-by alone is what
//	             a SIBLING relay's address also carries, and treating
//	             it as sufficient on a two-relay account is how you
//	             permanently destroy the neighbour's address. Plus the
//	             attachment: an attached address is in use by
//	             definition, whatever the labels say.
//
//	ssh key      the derived name "<relay>-ephemeral[-<rand>]", which
//	             is a pure function of (publisher pubkey, region) —
//	             the same proof ownsEphemeralKey accepts, reused
//	             verbatim rather than reimplemented.
//
//	firewall     the derived name "daal-relay-<serverID>". This is the
//	             weakest proof here and it is worth being explicit
//	             about why it is still a proof: the name is minted by
//	             FirewallEnsureForServer from a Hetzner server id, so
//	             it is not derived from the PUBLISHER's material the
//	             way the others are. What makes it safe is the second
//	             half of the test — the firewall must be attached to
//	             nothing at all, and the server its name points at must
//	             not exist. A firewall protecting nothing, named for a
//	             server that is gone, cannot be anybody's live
//	             protection. A firewall applied by LABEL SELECTOR is
//	             never reclaimable at all: its blast radius is whatever
//	             matches the selector at any moment, including servers
//	             that do not exist yet, so "attached to nothing" is not
//	             a fact that can be read off it.
//
// # THE ONE THING THAT INVALIDATES EVERYTHING
//
// Every orphan finding above is a claim about the WHOLE server list:
// "no live server stands behind this". If ServerList fails, that claim
// cannot be made about anything, so a failed server list downgrades
// every candidate to unproven and makes ReclaimOrphans refuse outright.
// The alternative — treating an unreadable list as an empty one — turns
// one API hiccup into a sweep that deletes the account.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"daal/publisher/deploy/provider"
)

// ephemeralKeyInfix is the marker that separates a relay name from the
// one-shot-key suffix. Kept next to the parser so the two cannot drift
// from ephemeralSSHKeyName.
const ephemeralKeyInfix = "-ephemeral"

// firewallNamePrefix is what FirewallEnsureForServer prepends to a
// server id. firewallNameForServer is the mint; this is the parse.
const firewallNamePrefix = "daal-relay-"

// relayFromEphemeralKeyName recovers the relay name from a one-shot
// SSH key's name, for both shapes ownsEphemeralKey accepts.
//
// Recovering it is what makes the audit work without an OperatorRecord.
// Decommission goes the other way — it derives the name from a record
// it already has and looks for a match — which is useless in exactly
// the case that matters, where the record was never written back and
// the key is the only surviving evidence that a provision ever ran.
//
// The returned name is then handed straight back to ownsEphemeralKey,
// so the ownership test is the existing one and not a second opinion.
func relayFromEphemeralKeyName(name string) (string, bool) {
	i := strings.Index(name, ephemeralKeyInfix)
	if i <= 0 {
		return "", false
	}
	relay := name[:i]
	rest := name[i+len(ephemeralKeyInfix):]
	// Exactly the two shapes: "" (legacy) or "-<suffix>" (current).
	if rest != "" && !strings.HasPrefix(rest, "-") {
		return "", false
	}
	if !strings.HasPrefix(relay, "daal-") {
		return "", false
	}
	return relay, true
}

// serverIDFromFirewallName recovers the server id a per-server
// firewall was minted for.
func serverIDFromFirewallName(name string) (string, bool) {
	if !strings.HasPrefix(name, firewallNamePrefix) {
		return "", false
	}
	id := strings.TrimPrefix(name, firewallNamePrefix)
	if id == "" {
		return "", false
	}
	return id, true
}

// markedRelay returns the relay name a resource's ownership labels
// claim, and whether BOTH marks are present.
//
// Both, always — this is ownsFloatingIP's GUARD 2 in reusable form.
// managed-by alone says "some daal relay owns this", which on an
// account running two relays is precisely the state in which deleting
// it is wrong.
func markedRelay(labels map[string]string) (string, bool) {
	if labels[labelManagedBy] != labelManagedByValue {
		return "", false
	}
	relay := labels[labelRelay]
	if relay == "" {
		return "", false
	}
	return relay, true
}

// recordClaims is the record side of the join, precomputed once.
type recordClaims struct {
	// relays maps a derived relay name to the record that produced
	// it. Presence means "the operator still holds a record for this
	// relay", which is what makes a resource claimed.
	relays map[string]*provider.OperatorRecord
	// serverIDs are the server ids records name directly.
	serverIDs map[string]string // server id -> relay
	// floatingIPs are the addresses records still name. Rule 3: a
	// record-named address is never reclaimed.
	floatingIPs map[string]string // fip id -> relay
}

func claimsFrom(records []*provider.OperatorRecord) recordClaims {
	c := recordClaims{
		relays:      map[string]*provider.OperatorRecord{},
		serverIDs:   map[string]string{},
		floatingIPs: map[string]string{},
	}
	for _, rec := range records {
		if rec == nil {
			continue
		}
		relay := ""
		if len(rec.PublisherPubKey) > 0 && rec.Region != "" {
			relay = derivedServerName(rec.PublisherPubKey, rec.Region)
			c.relays[relay] = rec
		}
		if rec.ServerID != "" {
			c.serverIDs[rec.ServerID] = relay
		}
		if rec.FloatingIPID != "" {
			c.floatingIPs[rec.FloatingIPID] = relay
		}
	}
	return c
}

// AuditAccount enumerates the Hetzner account and classifies
// everything carrying this tool's ownership marks.
//
// Read-only. Every call in here is a list or a get; the audit cannot
// mutate the account even if its reasoning is wrong, which is why it
// is safe to run first and always.
func (p *Provider) AuditAccount(ctx context.Context, records []*provider.OperatorRecord) (*provider.AccountAudit, error) {
	now := p.clock
	if now == nil {
		now = time.Now
	}
	audit := provider.NewAccountAudit("hetzner", now())
	claims := claimsFrom(records)

	// --- the ground truth every orphan finding depends on ---
	servers, serverErr := p.c.ServerList(ctx)
	byName := map[string]*ServerInfo{}
	byID := map[string]*ServerInfo{}
	if serverErr != nil {
		audit.Warnf("could not list servers (%v) — nothing can be proven orphaned without the full server list, so every finding below is reported as unproven and reclaim will refuse", serverErr)
	} else {
		audit.ServerListComplete = true
		for _, s := range servers {
			if s == nil {
				continue
			}
			byName[s.Name] = s
			byID[s.ID] = s
		}
	}

	// --- the record side of the join ---
	for relay, rec := range claims.relays {
		k := provider.KnownRelay{Relay: relay, RecordServerID: rec.ServerID, Region: rec.Region}
		if live, ok := byName[relay]; ok {
			k.LiveServerID = live.ID
			switch {
			case rec.ServerID == "":
				// The classic orphaned provision: the wizard writes
				// the record back only on success, so an empty id
				// beside a live box is a provision that built the
				// server and then died.
				k.Note = "your record has no server id but a server with this relay's name is running — the provision that created it never completed"
			case rec.ServerID != live.ID:
				k.Note = fmt.Sprintf("your record names server %s but the server running under this relay's name is %s — one of them is not yours to keep paying for", rec.ServerID, live.ID)
			}
		} else if audit.ServerListComplete {
			k.Note = "no server with this relay's name is running; the record describes a relay that is gone"
		}
		audit.Known = append(audit.Known, k)
	}

	p.auditServers(audit, servers, claims)
	p.auditFloatingIPs(ctx, audit, byName, claims)
	p.auditSSHKeys(ctx, audit, byName)
	p.auditFirewalls(ctx, audit, byID)

	audit.Sort()
	return audit, nil
}

func (p *Provider) auditServers(audit *provider.AccountAudit, servers []*ServerInfo, claims recordClaims) {
	for _, s := range servers {
		if s == nil {
			continue
		}
		relay, marked := markedRelay(s.Labels)
		if !marked {
			// A server NAMED like one of ours but carrying no marks.
			// `--existing-server-id` adopts boxes daal-deploy did not
			// create, and any tool may pick any name, so this is
			// reported and never claimed.
			if looksLikeDerivedRelayName(s.Name) {
				audit.Add(provider.AuditedResource{
					Kind: provider.KindServer, ID: s.ID, Name: s.Name,
					Verdict: provider.VerdictUnproven, Billing: true,
					Reason: "named like a daal relay but carries no managed-by=daal-deploy label, so this tool cannot tell whether it built this server or you did",
					Hint:   "check it in the Hetzner console (Servers → " + s.Name + "); if it is a relay you provisioned with an older build, tear it down with `daal-deploy decommission`",
				})
			}
			continue
		}
		res := provider.AuditedResource{
			Kind: provider.KindServer, ID: s.ID, Name: s.Name, Relay: relay, Billing: true,
		}
		claimRelay, byRelay := claims.relays[relay]
		_, byID := claims.serverIDs[s.ID]
		switch {
		case byID || byRelay:
			res.Verdict = provider.VerdictInUse
			res.Reason = "a record you supplied claims this relay"
			if byRelay && claimRelay.ServerID != "" && claimRelay.ServerID != s.ID {
				res.Verdict = provider.VerdictUnclaimed
				res.Reason = fmt.Sprintf("your record for %s names server %s, not this one — this is the shape a failed rebuild leaves: two paid servers for one relay", relay, claimRelay.ServerID)
				res.Hint = "confirm in the Hetzner console which address your recipients are actually reaching, then remove the other one"
			}
		default:
			res.Verdict = provider.VerdictUnclaimed
			res.Reason = "this server was built by daal-deploy but no record you supplied claims it; it is running and billing"
			res.Hint = fmt.Sprintf("if you still hold its OperatorRecord, run `daal-deploy decommission --record-file <record> --token-file <token>`; if you do not, delete server %s (%s) in the Hetzner console", s.ID, s.Name)
		}
		// NEVER reclaimable. A server is the relay; no label can tell
		// an abandoned box from the one every distributed pack dials.
		res.Reclaimable = false
		audit.Add(res)
	}
}

func (p *Provider) auditFloatingIPs(ctx context.Context, audit *provider.AccountAudit, byName map[string]*ServerInfo, claims recordClaims) {
	fips, err := p.c.FloatingIPList(ctx)
	if err != nil {
		audit.Warnf("could not list floating IPs (%v) — a reserved address bills whether or not anything is attached to it; check Hetzner console → Floating IPs for names starting \"daal-\"", err)
		return
	}
	for _, f := range fips {
		if f == nil {
			continue
		}
		relay, marked := markedRelay(f.Labels)
		if !marked {
			if f.Labels[labelManagedBy] == labelManagedByValue {
				// Half-marked: ours, but not attributable to a relay.
				// Refusing this is the two-relay guard: without the
				// per-relay label there is nothing to prove the
				// address is not the sibling's.
				audit.Add(provider.AuditedResource{
					Kind: provider.KindFloatingIP, ID: f.ID, Name: f.Name, Billing: true,
					Verdict: provider.VerdictUnproven,
					Reason:  "carries managed-by=daal-deploy but no daal-relay label, so which relay it belongs to cannot be established — on an account running more than one relay that is exactly when deleting it is wrong",
					Hint:    "Hetzner console → Floating IPs → " + f.Name + "; release it there if you know it is spare",
				})
			}
			// Entirely unmarked addresses are the operator's own
			// property. This tool has no opinion about them and does
			// not list them.
			continue
		}
		res := provider.AuditedResource{
			Kind: provider.KindFloatingIP, ID: f.ID, Name: f.Name, Relay: relay, Billing: true,
		}
		claimedByRelay, recordNamesIt := claims.floatingIPs[f.ID]
		_, serverAlive := byName[relay]
		switch {
		case f.ServerID != "":
			// The strongest guard there is, and it outranks every
			// label question: an attached address is being served on
			// right now. Detaching it black-holes whoever is behind
			// it, which is the precise failure ReleaseFloatingIP's
			// GUARD 1 was added to stop.
			res.Verdict = provider.VerdictInUse
			res.Reason = fmt.Sprintf("attached to server %s and answering on it", f.ServerID)
		case !audit.ServerListComplete:
			res.Verdict = provider.VerdictUnproven
			res.Reason = "unattached, but the server list could not be read, so there is no way to tell whether its relay still exists"
			res.Hint = "re-run the audit; if it keeps failing, check Hetzner console → Floating IPs → " + f.Name
		case recordNamesIt && claimedByRelay != "" && claimedByRelay != relay:
			// The record and the label disagree about whose address
			// this is. Two relays, two different answers, and no way
			// to tell which is stale — the exact shape the per-relay
			// label exists to prevent, so refuse rather than pick.
			res.Verdict = provider.VerdictUnproven
			res.Reason = fmt.Sprintf("your record for %s names this address but its ownership label says it belongs to %s; "+
				"one of the two is stale and this tool cannot tell which", claimedByRelay, relay)
			res.Hint = "Hetzner console → Floating IPs → " + f.Name + "; check which relay is actually answering on it"
		case recordNamesIt:
			// RULE 3. Decommission deliberately leaves addresses
			// reserved so the next relay can reuse them; a record
			// that still names one is the operator saying so.
			if serverAlive {
				res.Verdict = provider.VerdictInUse
				res.Reason = fmt.Sprintf("your record for %s names this address and that relay is running", claimedByRelay)
			} else {
				res.Verdict = provider.VerdictUnclaimed
				res.Reason = fmt.Sprintf("your record for %s still names this address but that relay's server is gone; it stays reserved and keeps billing, which is deliberate — an address outlives the box so the next relay can stand up on it without stranding a single distributed pack", relay)
				res.Hint = fmt.Sprintf("keep it for the next relay, or run `daal-deploy floating-ip release --fip-id %s --skip-unbind` to stop paying for it", f.ID)
			}
		case serverAlive:
			res.Verdict = provider.VerdictInUse
			res.Reason = fmt.Sprintf("reserved for relay %s, which is running — it may be mid-rotation, holding both its old and new address", relay)
		default:
			// Proven: ours, attached to nothing, and the relay it was
			// reserved for has no server on this account.
			res.Verdict = provider.VerdictOrphan
			res.Reclaimable = true
			res.Reason = fmt.Sprintf("reserved for relay %s, attached to nothing, and no server by that name exists on this account — this is what a rotation that failed part-way through leaves behind, and it bills every hour", relay)
			res.Hint = "reclaim removes it; nothing dials it"
		}
		audit.Add(res)
	}
}

func (p *Provider) auditSSHKeys(ctx context.Context, audit *provider.AccountAudit, byName map[string]*ServerInfo) {
	keys, err := p.c.SSHKeyList(ctx)
	if err != nil {
		audit.Warnf("could not list SSH keys (%v) — an orphaned one-shot key blocks the next provision with a uniqueness_error; check Hetzner console → Security → SSH keys for names ending \"-ephemeral\"", err)
		return
	}
	for _, k := range keys {
		relay, ok := relayFromEphemeralKeyName(k.Name)
		if !ok || !ownsEphemeralKey(k, relay) {
			continue
		}
		res := provider.AuditedResource{
			Kind: provider.KindSSHKey, ID: k.ID, Name: k.Name, Relay: relay,
			// Costs nothing per hour; costs the operator their next
			// provision, which is worse.
			Billing: false,
		}
		switch {
		case !audit.ServerListComplete:
			res.Verdict = provider.VerdictUnproven
			res.Reason = "the server list could not be read, so there is no way to tell whether the relay this key provisioned is still running"
			res.Hint = "re-run the audit; Hetzner console → Security → SSH keys → " + k.Name
		case byName[relay] != nil:
			// Liveness proof, identical to sweepEphemeralKeys': the
			// relay this key built is still running, so the key is not
			// ours to remove.
			res.Verdict = provider.VerdictInUse
			res.Reason = fmt.Sprintf("relay %s is still running, so its one-shot provisioning key is left in place", relay)
		default:
			res.Verdict = provider.VerdictOrphan
			res.Reclaimable = true
			res.Reason = fmt.Sprintf("one-shot provisioning key for relay %s, which has no server on this account — a key like this is what makes the NEXT provision for the same publisher and region fail with a uniqueness_error", relay)
			res.Hint = "reclaim removes it; it unblocks re-provisioning"
		}
		audit.Add(res)
	}
}

func (p *Provider) auditFirewalls(ctx context.Context, audit *provider.AccountAudit, byID map[string]*ServerInfo) {
	fws, err := p.c.FirewallList(ctx)
	if err != nil {
		audit.Warnf("could not list firewalls (%v) — an orphaned one costs nothing but clutters the account; check Hetzner console → Firewalls for names starting \"daal-relay-\"", err)
		return
	}
	for _, f := range fws {
		serverID, ok := serverIDFromFirewallName(f.Name)
		if !ok {
			continue
		}
		res := provider.AuditedResource{
			Kind: provider.KindFirewall, ID: f.ID, Name: f.Name, Billing: false,
		}
		switch {
		case len(f.AppliedToServerIDs) > 0:
			// Shared-resource guard, same rule as
			// FirewallDeleteForServer.SharedWith: a firewall is a
			// relay's only protection for a random mgmt port.
			res.Verdict = provider.VerdictInUse
			res.Reason = "still applied to server(s) " + strings.Join(f.AppliedToServerIDs, ", ")
		case len(f.LabelSelectors) > 0:
			res.Verdict = provider.VerdictUnproven
			res.Reason = "applied by label selector (" + strings.Join(f.LabelSelectors, ", ") + "), so what it protects is whatever matches at any given moment — including servers that do not exist yet"
			res.Hint = "Hetzner console → Firewalls → " + f.Name
		case !audit.ServerListComplete:
			res.Verdict = provider.VerdictUnproven
			res.Reason = "applied to nothing, but the server list could not be read, so there is no way to tell whether server " + serverID + " still exists"
			res.Hint = "re-run the audit"
		case byID[serverID] != nil:
			res.Verdict = provider.VerdictInUse
			res.Reason = "server " + serverID + " still exists; a firewall detached from a live relay is a relay with an exposed mgmt port, not spare clutter"
			res.Hint = "re-attach it in the Hetzner console, or re-run provisioning for that relay"
		default:
			res.Verdict = provider.VerdictOrphan
			res.Reclaimable = true
			res.Reason = "applied to nothing, and server " + serverID + " (the server its name was minted from) does not exist on this account"
			res.Hint = "reclaim removes it; nothing is behind it"
		}
		audit.Add(res)
	}
}

// looksLikeDerivedRelayName reports whether a name has the shape
// derivedServerName mints: "daal-<region>-<16 lowercase hex>".
//
// Shape only, and it is used only to decide whether to REPORT an
// unlabelled server — never to claim one. A name is not ownership;
// that is the whole reason ownsEphemeralKey and ownsFloatingIP demand
// labels.
func looksLikeDerivedRelayName(name string) bool {
	if !strings.HasPrefix(name, "daal-") {
		return false
	}
	i := strings.LastIndex(name, "-")
	if i < 0 || i == len(name)-1 {
		return false
	}
	suffix := name[i+1:]
	if len(suffix) != 16 {
		return false
	}
	for _, c := range suffix {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// ReclaimOrphans deletes what a FRESH audit proves orphaned.
//
// Fresh, not the report the operator just read. Between rendering a
// report and confirming it a relay can be provisioned, an address
// attached, a rotation started — so the audit the human approved is a
// description of the past, and deleting against it is precisely how a
// sweep eats a live relay. Every delete below is preceded by a
// re-read, so the guard runs against the state at the moment of the
// mutation.
func (p *Provider) ReclaimOrphans(ctx context.Context, records []*provider.OperatorRecord, only []provider.ResourceRef) (*provider.ReclaimReport, error) {
	rep := provider.NewReclaimReport("hetzner")
	audit, err := p.AuditAccount(ctx, records)
	if err != nil {
		return rep, fmt.Errorf("hetzner: audit before reclaim: %w", err)
	}
	rep.Warnings = append(rep.Warnings, audit.Warnings...)

	// The one refusal that covers everything. Orphanhood is a claim
	// about the whole server list; without it there is no such claim
	// to act on.
	if !audit.ServerListComplete {
		return rep, errors.New("hetzner: refusing to reclaim anything — the account's server list could not be read, and \"nothing is behind this resource\" is a statement about that list. Fix the API access and re-run")
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
			// Named, never silently skipped: an operator who asked
			// for a specific resource must be told why it survived.
			rep.Add(provider.ReclaimOutcome{
				Kind: res.Kind, ID: res.ID, Name: res.Name, Deleted: false,
				Reason: "refused (" + string(res.Verdict) + "): " + res.Reason,
			})
			continue
		}
		rep.Add(p.reclaimOne(ctx, res))
	}
	// A ref the operator asked for that the audit never saw at all.
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
		fip, err := p.c.FloatingIPByID(ctx, res.ID)
		switch {
		case errors.Is(err, errFloatingIPNotFound):
			out.Deleted = true
			out.Reason = "already gone"
			return out
		case err != nil:
			out.Reason = fmt.Sprintf("refused: could not re-read the address before deleting it (%v)", err)
			return out
		}
		if fip.ServerID != "" {
			out.Reason = fmt.Sprintf("refused: it has been attached to server %s since the audit ran — something is answering on it now", fip.ServerID)
			return out
		}
		if relay, ok := markedRelay(fip.Labels); !ok || relay != res.Relay {
			out.Reason = "refused: its ownership labels no longer match the relay the audit attributed it to"
			return out
		}
		if err := p.c.FloatingIPDelete(ctx, res.ID); err != nil {
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
		var found *SSHKeyInfo
		for i := range keys {
			if keys[i].ID == res.ID {
				found = &keys[i]
				break
			}
		}
		if found == nil {
			out.Deleted = true
			out.Reason = "already gone"
			return out
		}
		if !ownsEphemeralKey(*found, res.Relay) {
			out.Reason = "refused: it no longer matches the one-shot provisioning-key shape for " + res.Relay
			return out
		}
		if err := p.c.SSHKeyDelete(ctx, res.ID); err != nil {
			out.Reason = fmt.Sprintf("refused: delete failed (%v) — it will keep blocking the next provision", err)
			return out
		}
		out.Deleted = true
		out.Reason = "removed; re-provisioning for " + res.Relay + " is unblocked"
		return out

	case provider.KindFirewall:
		fws, err := p.c.FirewallList(ctx)
		if err != nil {
			out.Reason = fmt.Sprintf("refused: could not re-read the account's firewalls before deleting (%v)", err)
			return out
		}
		var found *FirewallInfo
		for i := range fws {
			if fws[i].ID == res.ID {
				found = &fws[i]
				break
			}
		}
		if found == nil {
			out.Deleted = true
			out.Reason = "already gone"
			return out
		}
		if len(found.AppliedToServerIDs) > 0 {
			out.Reason = "refused: server(s) " + strings.Join(found.AppliedToServerIDs, ", ") + " have been placed behind it since the audit ran"
			return out
		}
		if len(found.LabelSelectors) > 0 {
			out.Reason = "refused: it is applied by label selector, so what it protects cannot be read off it"
			return out
		}
		if err := p.c.FirewallDeleteByID(ctx, res.ID); err != nil {
			out.Reason = fmt.Sprintf("refused: delete failed (%v)", err)
			return out
		}
		out.Deleted = true
		out.Reason = "deleted; nothing was behind it"
		return out

	default:
		// Servers land here and always will. Stated as a rule rather
		// than left as an unreachable branch, so a future kind cannot
		// acquire a delete by accident.
		out.Reason = "refused: this audit never deletes a " + res.Kind
		return out
	}
}
