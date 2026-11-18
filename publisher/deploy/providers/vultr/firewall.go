package vultr

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"daal/publisher/deploy/provider"
	"daal/publisher/deploy/relayports"
)

// THE CLOUD FIREWALL IS THE RELAY'S SECURITY MODEL, NOT A BELT-AND-
// BRACES EXTRA. The box-side ufw rules are baked at first boot and
// cannot be changed afterwards; the mgmt plane listens on a random port
// in [10000, 65000] that must be sealed except for a ~5-minute window
// bound to the Helper's own address. On Vultr that is a firewall group
// with rules, attached to the instance at create time.
//
// Two Vultr specifics shape everything here:
//
//   - v4 and v6 are SEPARATE rules. Hetzner takes one rule with a list
//     of source CIDRs; Vultr takes ip_type per rule. "Open to the
//     world" is therefore always two calls, and writing only the first
//     produces a relay that is quietly v4-only.
//   - there is NO server-side TTL on a rule. Stark's (fictional) API
//     had expires_at_unix; Hetzner has none and neither does Vultr. So
//     an ephemeral rule's expiry is enforced by this adapter: the
//     explicit Remove call on completion, plus a sweep of expired
//     daal-eph rules every time the group is touched. State the
//     residual risk plainly rather than claiming a TTL: if the Helper
//     dies mid-rotation and the operator never runs another one, the
//     hole stays open until they do. It is bound to one source address
//     and one port, which is what keeps that survivable.

// baselineRules is the ruleset every Daal relay's firewall carries.
//
//	443/tcp  world  — VLESS-REALITY / HTTPS
//	443/udp  world  — Hysteria2 / QUIC
//	80/tcp   world  — ACME http-01 future-proofing
//	extras          — the families that cannot share 443/tcp with
//	                  REALITY, resolved from THIS relay's family set by
//	                  relayports.ExtraFirewallPortsFor, never from a
//	                  fleet-wide constant.
//
// Everything else is closed: Vultr drops inbound traffic that matches
// no rule once a group is attached, so the random mgmt port stays
// sealed until an ephemeral rule punches a (helper IP, port) hole.
func baselineRules(relay string, extraPorts []relayports.Endpoint) []FirewallRule {
	type portProto struct {
		port  string
		proto string
	}
	wanted := []portProto{
		{"443", "tcp"},
		{"443", "udp"},
		{"80", "tcp"},
	}
	if extraPorts == nil {
		extraPorts = relayports.ExtraFirewallPorts()
	}
	for _, ep := range extraPorts {
		proto := "tcp"
		if ep.UDP {
			proto = "udp"
		}
		wanted = append(wanted, portProto{strconv.Itoa(ep.Port), proto})
	}
	out := make([]FirewallRule, 0, len(wanted)*2)
	for _, w := range wanted {
		out = append(out,
			FirewallRule{IPType: "v4", Protocol: w.proto, Subnet: "0.0.0.0", SubnetSize: 0, Port: w.port,
				Notes: ownershipMark(relay, "baseline")},
			FirewallRule{IPType: "v6", Protocol: w.proto, Subnet: "::", SubnetSize: 0, Port: w.port,
				Notes: ownershipMark(relay, "baseline")},
		)
	}
	return out
}

// ruleKey identifies a rule for reconciliation. Notes are excluded on
// purpose: a rule that already opens the right port from the right
// source is the right rule, whatever its comment says.
func ruleKey(ipType, proto, subnet string, subnetSize int, port string) string {
	return strings.Join([]string{ipType, proto, subnet, strconv.Itoa(subnetSize), port}, "|")
}

// ensureFirewallGroup returns this relay's firewall group id, creating
// it (and its rules) when absent and topping up missing rules when
// present. created reports whether THIS call made the group, which is
// what tells the rollback whether the group is its to delete.
//
// Reusing an existing group by description is deliberate: a previous
// attempt that died after creating the group must not leave a second
// one behind on the retry, and a reprovision (which deletes only the
// instance) must find the same group so the rebuilt box is protected
// from its first instant.
//
// Missing rules are ADDED; unrecognised rules are LEFT ALONE. An
// operator who added a rule of their own to their relay's group has
// made a decision about their own machine, and a provisioner that
// silently deleted it would be taking a security decision out of their
// hands with no record of it.
func (p *Provider) ensureFirewallGroup(ctx context.Context, relay string, extraPorts []relayports.Endpoint) (string, bool, error) {
	desc := firewallGroupDescription(relay)
	want := baselineRules(relay, extraPorts)

	g, err := p.c.FirewallGroupByDescription(ctx, desc)
	if err != nil {
		return "", false, fmt.Errorf("look up firewall group: %w", err)
	}
	created := false
	groupID := ""
	if g == nil {
		groupID, err = p.c.FirewallGroupCreate(ctx, desc)
		if err != nil {
			return "", false, fmt.Errorf("create firewall group: %w", err)
		}
		created = true
	} else {
		if !markedFor(g.Description, relay) {
			// Cannot happen through firewallGroupDescription, and is
			// checked anyway: adding rules to somebody else's group is
			// how one operator's provision changes another's firewall.
			return "", false, fmt.Errorf("firewall group %s does not carry this relay's ownership mark", g.ID)
		}
		groupID = g.ID
	}

	have := map[string]bool{}
	if !created {
		existing, err := p.c.FirewallRuleList(ctx, groupID)
		if err != nil {
			return "", created, fmt.Errorf("list firewall rules: %w", err)
		}
		for _, r := range existing {
			have[ruleKey(r.IPType, r.Protocol, r.Subnet, r.SubnetSize, r.Port)] = true
		}
	}
	for _, r := range want {
		if have[ruleKey(r.IPType, r.Protocol, r.Subnet, r.SubnetSize, r.Port)] {
			continue
		}
		if _, err := p.c.FirewallRuleAdd(ctx, groupID, r); err != nil {
			return groupID, created, fmt.Errorf("add %s/%s rule for %s: %w", r.Port, r.Protocol, r.IPType, err)
		}
	}
	return groupID, created, nil
}

// ReRenderFirewall re-applies the baseline ruleset for a family set to
// an EXISTING relay's firewall group.
//
// THIS IS THE L5/L6 CALL. A rotation that changes the toolbox profile
// changes which families the relay serves, and the data-plane ports
// those families need are rendered publisher-side from
// relayports.ExtraFirewallPortsFor(<families>). Move a relay to a new
// provider or a new profile without re-rendering, and the box listens
// on a port its cloud firewall drops: every route in the freshly minted
// pack validates, and the ones on the new port cannot be dialed.
//
// It adds what is missing and does not remove what it does not
// recognise, for the same reason ensureFirewallGroup does not.
func (p *Provider) ReRenderFirewall(ctx context.Context, rec *provider.OperatorRecord, families []string) error {
	if rec == nil {
		return errors.New("vultr: nil OperatorRecord")
	}
	if len(rec.PublisherPubKey) == 0 || rec.Region == "" {
		return errors.New("vultr: record cannot name its relay (publisher key + region required)")
	}
	relay := derivedInstanceLabel(rec.PublisherPubKey, rec.Region)
	_, _, err := p.ensureFirewallGroup(ctx, relay, relayports.ExtraFirewallPortsFor(families))
	if err != nil {
		return fmt.Errorf("vultr: re-render firewall for %v: %w", families, err)
	}
	return nil
}

// --- ephemeral (mgmt-plane) rules ---

const ephemeralNotePrefix = "daal-eph"

// ephemeralNote encodes everything the sweep needs into the one free
// field a Vultr rule has.
func ephemeralNote(callerIP string, port int, expiresAt time.Time) string {
	return fmt.Sprintf("%s exp=%d ip=%s port=%d", ephemeralNotePrefix, expiresAt.UTC().Unix(), callerIP, port)
}

// parseEphemeralNote returns the expiry encoded in a rule's note, and
// whether the note is one of ours at all.
func parseEphemeralNote(note string) (time.Time, bool) {
	if !strings.HasPrefix(note, ephemeralNotePrefix) {
		return time.Time{}, false
	}
	for _, tok := range strings.Fields(note) {
		k, v, ok := strings.Cut(tok, "=")
		if !ok || k != "exp" {
			continue
		}
		sec, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return time.Time{}, false
		}
		return time.Unix(sec, 0).UTC(), true
	}
	return time.Time{}, false
}

// ephemeralHandle joins the group id and rule id, because a Vultr rule
// id is only unique within its group and the caller stores one opaque
// string.
func ephemeralHandle(groupID, ruleID string) string { return groupID + ":" + ruleID }

func splitEphemeralHandle(h string) (groupID, ruleID string, ok bool) {
	g, r, found := strings.Cut(h, ":")
	if !found || g == "" || r == "" {
		return "", "", false
	}
	return g, r, true
}

// SetEphemeralFirewallRule opens (callerIP/32, port, tcp) on the
// instance's firewall group for durationSec.
//
// FRP-10 invariant 28: the (port, IP) tuple is the rule's full key,
// never just the IP. A port of 0 or a non-positive duration is refused.
func (p *Provider) SetEphemeralFirewallRule(ctx context.Context, serverID, callerIP string, port, durationSec int) (*provider.EphemeralFirewallRule, error) {
	if serverID == "" {
		return nil, errors.New("vultr: SetEphemeralFirewallRule serverID required")
	}
	if callerIP == "" {
		return nil, errors.New("vultr: SetEphemeralFirewallRule callerIP required")
	}
	if err := provider.ValidateMgmtPort(port); err != nil {
		return nil, fmt.Errorf("vultr: SetEphemeralFirewallRule invalid port: %w", err)
	}
	if durationSec <= 0 {
		return nil, fmt.Errorf("vultr: SetEphemeralFirewallRule invalid durationSec %d", durationSec)
	}
	return p.openEphemeralRule(ctx, serverID, callerIP, port, durationSec)
}

// openEphemeralRule is SetEphemeralFirewallRule without the mgmt-port
// range check. Provisioning uses it for the bootstrap health port
// (9876), which is deliberately outside [10000, 65000] and would fail
// the public method's validation — the same split the Hetzner adapter
// gets for free by calling its client directly.
func (p *Provider) openEphemeralRule(ctx context.Context, serverID, callerIP string, port, durationSec int) (*provider.EphemeralFirewallRule, error) {
	inst, err := p.c.InstanceByID(ctx, serverID)
	if err != nil {
		return nil, fmt.Errorf("vultr: read instance %s: %w", serverID, err)
	}
	if inst == nil || inst.FirewallGroupID == "" {
		return nil, fmt.Errorf("vultr: instance %s has no attached firewall", serverID)
	}
	groupID := inst.FirewallGroupID
	now := p.clock().UTC()
	expiresAt := now.Add(time.Duration(durationSec) * time.Second)

	// Sweep first. Vultr enforces no TTL, so an earlier rotation that
	// died before its Remove call left a hole; this is where it closes.
	p.sweepExpiredEphemeralRules(ctx, groupID, now)

	ip, size, ipType, err := hostCIDR(callerIP)
	if err != nil {
		return nil, fmt.Errorf("vultr: %w", err)
	}
	ruleID, err := p.c.FirewallRuleAdd(ctx, groupID, FirewallRule{
		IPType: ipType, Protocol: "tcp", Subnet: ip, SubnetSize: size,
		Port: strconv.Itoa(port), Notes: ephemeralNote(callerIP, port, expiresAt),
	})
	if err != nil {
		return nil, fmt.Errorf("vultr: add ephemeral rule: %w", err)
	}
	return &provider.EphemeralFirewallRule{
		ID:        ephemeralHandle(groupID, ruleID),
		ServerID:  serverID,
		CallerIP:  callerIP,
		Port:      port,
		ExpiresAt: expiresAt,
	}, nil
}

// RemoveEphemeralFirewallRule closes the rule. Idempotent: an
// already-removed or already-swept rule is success.
func (p *Provider) RemoveEphemeralFirewallRule(ctx context.Context, rule *provider.EphemeralFirewallRule) error {
	if rule == nil || rule.ID == "" {
		return nil
	}
	groupID, ruleID, ok := splitEphemeralHandle(rule.ID)
	if !ok {
		return nil // not a handle this adapter minted; nothing to close
	}
	return p.c.FirewallRuleDelete(ctx, groupID, ruleID)
}

// sweepExpiredEphemeralRules deletes every daal-eph rule in the group
// whose encoded expiry has passed. Best-effort: a sweep failure must
// not stop the rotation that is trying to open a new window, because
// refusing to rotate is the worse outcome — but it is also why the
// explicit Remove call still exists.
func (p *Provider) sweepExpiredEphemeralRules(ctx context.Context, groupID string, now time.Time) {
	rules, err := p.c.FirewallRuleList(ctx, groupID)
	if err != nil {
		return
	}
	for _, r := range rules {
		exp, ok := parseEphemeralNote(r.Notes)
		if !ok || !exp.Before(now) {
			continue
		}
		_ = p.c.FirewallRuleDelete(ctx, groupID, r.ID)
	}
}

// hostCIDR turns a single address into Vultr's (subnet, subnet_size,
// ip_type) triple.
func hostCIDR(addr string) (string, int, string, error) {
	ip := parseIP(addr)
	if ip == nil {
		return "", 0, "", fmt.Errorf("invalid caller ip %q", addr)
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String(), 32, "v4", nil
	}
	return ip.String(), 128, "v6", nil
}
