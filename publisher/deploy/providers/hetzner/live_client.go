package hetzner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"daal/publisher/deploy/relayports"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
)

// liveClient implements hcloudClient against the real
// hetznercloud/hcloud-go/v2 SDK. Constructed via NewLiveClient.
type liveClient struct {
	c *hcloud.Client
}

// NewLiveClient returns an hcloudClient bound to a live Hetzner
// Cloud account. The token must be a Hetzner Cloud API token (NOT a
// project key). The token is supplied by the wizard's keystore;
// FRP-4a does not store it.
func NewLiveClient(token string) hcloudClient {
	return &liveClient{c: hcloud.NewClient(hcloud.WithToken(token))}
}

func (l *liveClient) ServerCreate(ctx context.Context, opts ServerCreateOpts) (*ServerInfo, error) {
	hopts := hcloud.ServerCreateOpts{
		Name:       opts.Name,
		ServerType: &hcloud.ServerType{Name: opts.ServerType},
		Image:      &hcloud.Image{Name: opts.Image},
		Location:   &hcloud.Location{Name: opts.Region},
		UserData:   opts.UserData,
		Labels:     opts.Labels,
	}
	for _, idStr := range opts.SSHKeyIDs {
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid ssh-key id %q: %w", idStr, err)
		}
		hopts.SSHKeys = append(hopts.SSHKeys, &hcloud.SSHKey{ID: id})
	}
	res, _, err := l.c.Server.Create(ctx, hopts)
	if err != nil {
		return nil, err
	}
	return serverInfoFromHcloud(res.Server), nil
}

func (l *liveClient) ServerByID(ctx context.Context, id string) (*ServerInfo, error) {
	idInt, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid server id %q: %w", id, err)
	}
	s, _, err := l.c.Server.GetByID(ctx, idInt)
	if err != nil {
		return nil, err
	}
	if s == nil {
		return nil, errServerNotFound
	}
	return serverInfoFromHcloud(s), nil
}

func (l *liveClient) ServerByName(ctx context.Context, name string) (*ServerInfo, error) {
	s, _, err := l.c.Server.GetByName(ctx, name)
	if err != nil {
		return nil, err
	}
	if s == nil {
		return nil, errServerNotFound
	}
	return serverInfoFromHcloud(s), nil
}

func (l *liveClient) ServerRebuild(ctx context.Context, id string, image string, userData string) (*ServerInfo, error) {
	idInt, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid server id %q: %w", id, err)
	}
	ud := userData
	result, _, err := l.c.Server.RebuildWithResult(ctx, &hcloud.Server{ID: idInt}, hcloud.ServerRebuildOpts{
		Image:    &hcloud.Image{Name: image},
		UserData: &ud,
	})
	if err != nil {
		return nil, err
	}
	// After rebuild, fetch fresh server info (IP stays the same).
	info, err := l.ServerByID(ctx, id)
	if err != nil {
		return nil, err
	}
	info.RootPassword = result.RootPassword
	return info, nil
}

func (l *liveClient) ServerList(ctx context.Context) ([]*ServerInfo, error) {
	servers, err := l.c.Server.All(ctx)
	if err != nil {
		return nil, err
	}
	var result []*ServerInfo
	for _, s := range servers {
		result = append(result, serverInfoFromHcloud(s))
	}
	return result, nil
}

func (l *liveClient) ServerDelete(ctx context.Context, id string) error {
	idInt, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid server id %q: %w", id, err)
	}
	_, _, err = l.c.Server.DeleteWithResult(ctx, &hcloud.Server{ID: idInt})
	if hcloud.IsError(err, hcloud.ErrorCodeNotFound) {
		return nil // idempotent
	}
	return err
}

func (l *liveClient) ServerTypePrice(ctx context.Context, region, serverType string) (float64, float64, error) {
	st, _, err := l.c.ServerType.GetByName(ctx, serverType)
	if err != nil {
		return 0, 0, err
	}
	if st == nil {
		return 0, 0, fmt.Errorf("server-type %q not found", serverType)
	}
	for _, p := range st.Pricings {
		if p.Location == nil || p.Location.Name != region {
			continue
		}
		hourly, _ := strconv.ParseFloat(p.Hourly.Gross, 64)
		monthly, _ := strconv.ParseFloat(p.Monthly.Gross, 64)
		return hourly, monthly, nil
	}
	return 0, 0, fmt.Errorf("no pricing for %s in %s", serverType, region)
}

func (l *liveClient) SSHKeyCreate(ctx context.Context, name string, publicKey []byte, labels map[string]string) (string, error) {
	k, _, err := l.c.SSHKey.Create(ctx, hcloud.SSHKeyCreateOpts{
		Name:      name,
		PublicKey: string(publicKey),
		Labels:    labels,
	})
	if err != nil {
		return "", err
	}
	return strconv.FormatInt(k.ID, 10), nil
}

// SSHKeyList returns every SSH key on the account. Used by teardown
// to find the one-shot provisioning key(s) for a relay: their ids
// are not persisted anywhere, so the only handle is the derived name
// plus the daal ownership labels.
func (l *liveClient) SSHKeyList(ctx context.Context) ([]SSHKeyInfo, error) {
	keys, err := l.c.SSHKey.All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]SSHKeyInfo, 0, len(keys))
	for _, k := range keys {
		if k == nil {
			continue
		}
		out = append(out, SSHKeyInfo{
			ID:     strconv.FormatInt(k.ID, 10),
			Name:   k.Name,
			Labels: k.Labels,
		})
	}
	return out, nil
}

func (l *liveClient) SSHKeyDelete(ctx context.Context, id string) error {
	idInt, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid ssh-key id %q: %w", id, err)
	}
	_, err = l.c.SSHKey.Delete(ctx, &hcloud.SSHKey{ID: idInt})
	if hcloud.IsError(err, hcloud.ErrorCodeNotFound) {
		return nil
	}
	return err
}

// FloatingIPCreate reserves a new IPv4 floating IP in opts.HomeLocation.
//
// IPv4 only, deliberately. The relay's dialed address flows into
// OperatorRecord.PublicIP and from there into every candidate's
// public_ip:* tag and every client outbound; the whole recipient-side
// path (and the sing-box configs it renders) is written against an IPv4
// literal today. Handing back a v6 address here would produce a pack
// that validates and cannot be dialed from a v4-only Iranian mobile
// network, which is most of them.
func (l *liveClient) FloatingIPCreate(ctx context.Context, opts FloatingIPCreateOpts) (*FloatingIPInfo, error) {
	if opts.HomeLocation == "" {
		return nil, errors.New("hetzner: floating ip needs a home location")
	}
	copts := hcloud.FloatingIPCreateOpts{
		Type:         hcloud.FloatingIPTypeIPv4,
		HomeLocation: &hcloud.Location{Name: opts.HomeLocation},
		Labels:       opts.Labels,
	}
	if opts.Name != "" {
		name := opts.Name
		copts.Name = &name
	}
	if opts.Description != "" {
		desc := opts.Description
		copts.Description = &desc
	}
	res, _, err := l.c.FloatingIP.Create(ctx, copts)
	if err != nil {
		return nil, err
	}
	if res.FloatingIP == nil {
		return nil, errors.New("hetzner: floating-ip create returned no object")
	}
	return floatingIPInfoFromHcloud(res.FloatingIP), nil
}

// FloatingIPDelete releases the address. Absent ids are success, so a
// rollback that runs twice does not turn a recovered rotation into an
// error.
func (l *liveClient) FloatingIPDelete(ctx context.Context, fipID string) error {
	fipInt, err := strconv.ParseInt(fipID, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid floating-ip id %q: %w", fipID, err)
	}
	_, err = l.c.FloatingIP.Delete(ctx, &hcloud.FloatingIP{ID: fipInt})
	if hcloud.IsError(err, hcloud.ErrorCodeNotFound) {
		return nil
	}
	return err
}

// FloatingIPByID resolves an id to an address + home location + current
// attachment. Returns errFloatingIPNotFound when the id does not exist,
// which the caller must distinguish from a transport error: "this
// address is gone" and "we could not ask" lead to opposite decisions
// during a rollback.
func (l *liveClient) FloatingIPByID(ctx context.Context, fipID string) (*FloatingIPInfo, error) {
	fipInt, err := strconv.ParseInt(fipID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid floating-ip id %q: %w", fipID, err)
	}
	fip, _, err := l.c.FloatingIP.GetByID(ctx, fipInt)
	if err != nil {
		return nil, err
	}
	if fip == nil {
		return nil, errFloatingIPNotFound
	}
	return floatingIPInfoFromHcloud(fip), nil
}

// floatingIPInfoFromHcloud narrows the SDK object to the four facts the
// adapter acts on. Server is flattened to an id string because that is
// what OperatorRecord.ServerID holds and the read-back compares against.
func floatingIPInfoFromHcloud(f *hcloud.FloatingIP) *FloatingIPInfo {
	out := &FloatingIPInfo{
		ID:     strconv.FormatInt(f.ID, 10),
		IP:     f.IP,
		Name:   f.Name,
		Labels: f.Labels,
	}
	if f.HomeLocation != nil {
		out.HomeLocation = f.HomeLocation.Name
	}
	if f.Server != nil {
		out.ServerID = strconv.FormatInt(f.Server.ID, 10)
	}
	return out
}

func (l *liveClient) FloatingIPAssign(ctx context.Context, fipID, serverID string) error {
	fipInt, err := strconv.ParseInt(fipID, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid floating-ip id %q: %w", fipID, err)
	}
	srvInt, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid server id %q: %w", serverID, err)
	}
	_, _, err = l.c.FloatingIP.Assign(ctx, &hcloud.FloatingIP{ID: fipInt}, &hcloud.Server{ID: srvInt})
	return err
}

// floatingIPActionSettleTimeout bounds the wait for a floating-IP
// action to finish. An unassign completes in about a second; this is
// generous because overrunning it costs only the release leg, which is
// deliberately non-fatal, while not waiting at all costs a reserved
// address that bills forever.
const floatingIPActionSettleTimeout = 60 * time.Second

func (l *liveClient) FloatingIPUnassign(ctx context.Context, fipID string) error {
	fipInt, err := strconv.ParseInt(fipID, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid floating-ip id %q: %w", fipID, err)
	}
	action, _, err := l.c.FloatingIP.Unassign(ctx, &hcloud.FloatingIP{ID: fipInt})
	if err != nil {
		return err
	}
	// WAIT FOR THE ACTION, do not just fire it.
	//
	// Hetzner LOCKS a floating IP while an action against it is running,
	// and this call's only caller deletes the address immediately
	// afterwards. Returning as soon as the API accepted the request made
	// that delete lose the race on real hardware (2026-08-18, second L3
	// on a live relay):
	//
	//   delete floating ip 145379191: cannot perform operation because
	//   floating_ip is locked (locked, 5a92716...)
	//
	// The rotation still succeeded and the warning surfaced honestly,
	// but the address stayed reserved and BILLING after every swap —
	// a slow money leak that nothing else would have collected.
	//
	// Waiting is what makes "release" release. The bound is generous
	// because an unassign is quick and a stall here costs only the
	// release leg, which is already non-fatal to the rotation.
	if action == nil {
		return nil
	}
	wctx, cancel := context.WithTimeout(ctx, floatingIPActionSettleTimeout)
	defer cancel()
	if err := l.c.Action.WaitFor(wctx, action); err != nil {
		return fmt.Errorf("waiting for floating ip %s to detach: %w", fipID, err)
	}
	return nil
}

// cdnOriginPort is the port the Cloudflare-edge rule opens by default:
// the relay's dedicated CDN door (relayports.CDNOrigin, ws-cdn-in). It
// used to be 443, which opened nothing (443/tcp is already open to the
// world for REALITY, and Hetzner unions allow rules) and pointed the
// edge at REALITY, which answers with the cover site's certificate.
// The CDN port is in no world-open list (relayports.FirewallPortsFor),
// so this rule is the only way in to it.
var cdnOriginPort = strconv.Itoa(relayports.CDNOrigin.Port)

// cdnRuleDescription tags the one rule FirewallApplyCloudflareRule
// owns, so a refresh replaces that rule (Cloudflare's ranges change)
// and never touches anything else on the firewall.
const cdnRuleDescription = "daal-cdn-edge"

// firewallWriteAttempts bounds the read-modify-write retry when a
// write is found not to have landed (another writer replaced the rule
// set after ours).
const firewallWriteAttempts = 3

// errFirewallConcurrentChange is returned when the firewall kept
// changing under us for every attempt. Nothing is retried after it;
// the caller sees a failure rather than a rule it believes is there.
var errFirewallConcurrentChange = errors.New("hetzner firewall: rule set changed concurrently; write did not land")

// errFirewallNotFound is returned when the firewall id does not
// resolve.
var errFirewallNotFound = errors.New("hetzner firewall: not found")

// firewallLocks serialises every read-modify-write of one firewall's
// rule set within this process. Hetzner's set_rules replaces the
// WHOLE rule set and the API has no version or If-Match, so two
// writers that read the same set and write back lose one another's
// rules. Package level, not per liveClient, because callers build a
// fresh liveClient per verb.
var firewallLocks sync.Map // int64 -> *sync.Mutex

func lockFirewall(id int64) func() {
	m, _ := firewallLocks.LoadOrStore(id, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// modifyFirewallRules is the only way this file edits an existing
// firewall's rules. It reads the current set, lets edit derive the
// next one from it, writes it, then reads it back and asks landed
// whether the write is visible.
//
// What it protects against, and what it cannot:
//   - Writers in this process: fully, via firewallLocks.
//   - A writer elsewhere (the console, another publisher process)
//     that replaces the set AFTER our write: detected by the
//     read-back and retried on the fresh set, up to
//     firewallWriteAttempts.
//   - A writer elsewhere that writes BETWEEN our read and our write:
//     its change is overwritten and cannot be detected — Hetzner
//     offers no conditional write (no version, no If-Match) and no
//     per-rule add or delete action; set_rules is the only verb. The
//     window is one round trip (our GET's reply to our set_rules
//     landing), typically well under a second. Neither side can see
//     the loss: the other writer's read-back may already have passed.
//     Two publisher processes on one relay at the same moment is the
//     only Daal case; an ephemeral window lost that way fails that
//     verb's mgmt call (retryable), and a lost Cloudflare rule shows
//     in cdn-posture. Verified 2026-11-22 (W1-D).
//
// edit returning changed=false makes the call a no-op (no write).
// A read failure is returned wrapped in errFirewallRead.
func (l *liveClient) modifyFirewallRules(
	ctx context.Context,
	fwID int64,
	edit func(cur []hcloud.FirewallRule) (next []hcloud.FirewallRule, changed bool),
	landed func(after []hcloud.FirewallRule) bool,
) error {
	unlock := lockFirewall(fwID)
	defer unlock()
	for attempt := 0; attempt < firewallWriteAttempts; attempt++ {
		fw, _, err := l.c.Firewall.GetByID(ctx, fwID)
		if err != nil {
			return fmt.Errorf("%w: %w", errFirewallRead, err)
		}
		if fw == nil {
			return errFirewallNotFound
		}
		next, changed := edit(fw.Rules)
		if !changed {
			return nil
		}
		if _, _, err := l.c.Firewall.SetRules(ctx, &hcloud.Firewall{ID: fwID}, hcloud.FirewallSetRulesOpts{Rules: next}); err != nil {
			return err
		}
		after, _, err := l.c.Firewall.GetByID(ctx, fwID)
		if err != nil {
			return fmt.Errorf("%w: %w", errFirewallRead, err)
		}
		if after == nil {
			return errFirewallNotFound
		}
		if landed(after.Rules) {
			return nil
		}
	}
	return errFirewallConcurrentChange
}

// errFirewallRead marks a failure to READ the firewall (as opposed
// to a failed write), so idempotent removal can keep treating an
// unreadable firewall as "nothing to remove".
var errFirewallRead = errors.New("hetzner firewall: read failed")

func ruleHasDescription(r hcloud.FirewallRule, desc string) bool {
	return r.Description != nil && *r.Description == desc
}

func findRuleByDescription(rules []hcloud.FirewallRule, desc string) (hcloud.FirewallRule, bool) {
	for _, r := range rules {
		if ruleHasDescription(r, desc) {
			return r, true
		}
	}
	return hcloud.FirewallRule{}, false
}

// sameSources compares two source lists as sets of CIDR strings.
func sameSources(a, b []net.IPNet) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[string]int, len(a))
	for _, n := range a {
		set[n.String()]++
	}
	for _, n := range b {
		k := n.String()
		if set[k] == 0 {
			return false
		}
		set[k]--
	}
	return true
}

// withCloudflareRule returns rules with every rule tagged
// cdnRuleDescription replaced by rule, all other rules kept in their
// original order. Pure, so the merge is testable without an API.
func withCloudflareRule(cur []hcloud.FirewallRule, rule hcloud.FirewallRule) []hcloud.FirewallRule {
	next := make([]hcloud.FirewallRule, 0, len(cur)+1)
	for _, r := range cur {
		if ruleHasDescription(r, cdnRuleDescription) {
			continue
		}
		next = append(next, r)
	}
	return append(next, rule)
}

// FirewallApplyCloudflareRule adds (or refreshes) ONE inbound rule
// allowing the CDN door's port (cdnOriginPort) from the supplied
// Cloudflare edge ranges. See FirewallApplyCloudflareRuleOnPort.
func (l *liveClient) FirewallApplyCloudflareRule(ctx context.Context, firewallID string, ipv4Ranges, ipv6Ranges []string) (string, error) {
	return l.FirewallApplyCloudflareRuleOnPort(ctx, firewallID, relayports.CDNOrigin.Port, ipv4Ranges, ipv6Ranges)
}

// errNoRelayFirewall refuses a Cloudflare rule with no firewall to put
// it on. The old behaviour (create a fresh firewall holding only that
// rule) produced a firewall attached to nothing: a lock that locked
// nothing, which the phone path then reported as done (defect 3 of the
// blackout plan, Group B).
var errNoRelayFirewall = errors.New("hetzner firewall: the Cloudflare rule goes on the relay's own firewall (daal-relay-<server id>); pass its id")

// errCDNPortWorldOpen refuses a Cloudflare-only rule for a port the
// firewall already opens to everyone: Hetzner unions allow rules, so it
// would narrow nothing while the posture line said "only Cloudflare".
var errCDNPortWorldOpen = errors.New("hetzner firewall: that port is already open to everyone on this firewall; a Cloudflare-only rule for it would restrict nothing")

// FirewallApplyCloudflareRuleOnPort adds (or refreshes) ONE inbound rule
// allowing port/tcp from the supplied Cloudflare edge ranges, on the
// relay's own firewall. Idempotent.
//
//   - firewallID must be the relay's firewall (daal-relay-<serverID>,
//     from FirewallEnsureForServer). Empty is refused.
//   - The rule replaces a previous rule this function wrote (tagged
//     cdnRuleDescription) and KEEPS EVERY OTHER RULE. An earlier
//     version called set_rules with this one rule alone, which on a
//     relay firewall deleted 80/tcp, every data-plane port and any open
//     mgmt hole.
//   - A port another rule already opens to 0.0.0.0/0 or ::/0 is refused
//     (errCDNPortWorldOpen).
//
// Called from the publisher, never from the relay.
func (l *liveClient) FirewallApplyCloudflareRuleOnPort(ctx context.Context, firewallID string, port int, ipv4Ranges, ipv6Ranges []string) (string, error) {
	if port <= 0 || port > 65535 {
		return "", fmt.Errorf("hetzner firewall: port %d out of range", port)
	}
	portStr := strconv.Itoa(port)
	desc := cdnRuleDescription
	rule := hcloud.FirewallRule{
		Direction:   hcloud.FirewallRuleDirectionIn,
		Protocol:    hcloud.FirewallRuleProtocolTCP,
		Port:        stringPtr(portStr),
		Description: &desc,
	}
	for _, r := range ipv4Ranges {
		_, n, err := net.ParseCIDR(r)
		if err != nil || n.IP.To4() == nil {
			return "", fmt.Errorf("hetzner firewall: invalid v4 cidr %q", r)
		}
		rule.SourceIPs = append(rule.SourceIPs, *n)
	}
	for _, r := range ipv6Ranges {
		_, n, err := net.ParseCIDR(r)
		if err != nil || n.IP.To4() != nil {
			return "", fmt.Errorf("hetzner firewall: invalid v6 cidr %q", r)
		}
		rule.SourceIPs = append(rule.SourceIPs, *n)
	}
	// An empty source list would be rejected by Hetzner; refusing it
	// here keeps a failed range fetch from ever reaching the API.
	if len(rule.SourceIPs) == 0 {
		return "", errEmptyRanges
	}
	for _, n := range rule.SourceIPs {
		if ones, _ := n.Mask.Size(); ones == 0 {
			return "", fmt.Errorf("hetzner firewall: %s is everyone, not a Cloudflare range", n.String())
		}
	}
	if firewallID == "" {
		return "", errNoRelayFirewall
	}
	idInt, err := strconv.ParseInt(firewallID, 10, 64)
	if err != nil {
		return "", fmt.Errorf("invalid firewall id %q: %w", firewallID, err)
	}
	var refused error
	err = l.modifyFirewallRules(ctx, idInt,
		func(cur []hcloud.FirewallRule) ([]hcloud.FirewallRule, bool) {
			if worldOpensTCPPort(cur, portStr) {
				refused = errCDNPortWorldOpen
				return nil, false
			}
			if have, ok := findRuleByDescription(cur, cdnRuleDescription); ok &&
				sameSources(have.SourceIPs, rule.SourceIPs) &&
				have.Port != nil && *have.Port == portStr &&
				countByDescription(cur, cdnRuleDescription) == 1 {
				return nil, false // already exactly this rule
			}
			return withCloudflareRule(cur, rule), true
		},
		func(after []hcloud.FirewallRule) bool {
			have, ok := findRuleByDescription(after, cdnRuleDescription)
			return ok && sameSources(have.SourceIPs, rule.SourceIPs) && have.Port != nil && *have.Port == portStr
		},
	)
	if err != nil {
		return "", err
	}
	if refused != nil {
		return "", refused
	}
	return firewallID, nil
}

// worldOpensTCPPort reports whether a rule other than Daal's Cloudflare
// rule opens port/tcp to 0.0.0.0/0 or ::/0.
func worldOpensTCPPort(rules []hcloud.FirewallRule, port string) bool {
	for _, r := range rules {
		if ruleHasDescription(r, cdnRuleDescription) || r.Direction != hcloud.FirewallRuleDirectionIn ||
			r.Protocol != hcloud.FirewallRuleProtocolTCP || r.Port == nil || !portCovers(*r.Port, port) {
			continue
		}
		for _, n := range r.SourceIPs {
			if ones, _ := n.Mask.Size(); ones == 0 {
				return true
			}
		}
	}
	return false
}

// portCovers reports whether a Hetzner port spec ("443" or
// "8000-9000") includes port.
func portCovers(spec, port string) bool {
	p, err := strconv.Atoi(port)
	if err != nil {
		return false
	}
	lo, hi, isRange := strings.Cut(spec, "-")
	a, err := strconv.Atoi(strings.TrimSpace(lo))
	if err != nil {
		return false
	}
	if !isRange {
		return a == p
	}
	b, err := strconv.Atoi(strings.TrimSpace(hi))
	return err == nil && a <= p && p <= b
}

// CloudflareRuleState is what the posture check reads back.
type CloudflareRuleState struct {
	Present bool
	Port    string
	Sources int
}

// FirewallCloudflareRule reads Daal's Cloudflare rule on a firewall.
// Read-only.
func (l *liveClient) FirewallCloudflareRule(ctx context.Context, firewallID string) (CloudflareRuleState, error) {
	idInt, err := strconv.ParseInt(firewallID, 10, 64)
	if err != nil {
		return CloudflareRuleState{}, fmt.Errorf("invalid firewall id %q: %w", firewallID, err)
	}
	fw, _, err := l.c.Firewall.GetByID(ctx, idInt)
	if err != nil {
		return CloudflareRuleState{}, fmt.Errorf("%w: %w", errFirewallRead, err)
	}
	if fw == nil {
		return CloudflareRuleState{}, errFirewallNotFound
	}
	have, ok := findRuleByDescription(fw.Rules, cdnRuleDescription)
	if !ok {
		return CloudflareRuleState{}, nil
	}
	st := CloudflareRuleState{Present: true, Sources: len(have.SourceIPs)}
	if have.Port != nil {
		st.Port = *have.Port
	}
	return st, nil
}

// FirewallRemoveCloudflareRule takes Daal's Cloudflare rule off a
// firewall and keeps every other rule. Idempotent: no rule, or no
// firewall, is success.
func (l *liveClient) FirewallRemoveCloudflareRule(ctx context.Context, firewallID string) error {
	idInt, err := strconv.ParseInt(firewallID, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid firewall id %q: %w", firewallID, err)
	}
	err = l.modifyFirewallRules(ctx, idInt,
		func(cur []hcloud.FirewallRule) ([]hcloud.FirewallRule, bool) {
			if countByDescription(cur, cdnRuleDescription) == 0 {
				return nil, false
			}
			next := make([]hcloud.FirewallRule, 0, len(cur))
			for _, r := range cur {
				if !ruleHasDescription(r, cdnRuleDescription) {
					next = append(next, r)
				}
			}
			return next, true
		},
		func(after []hcloud.FirewallRule) bool {
			return countByDescription(after, cdnRuleDescription) == 0
		},
	)
	if errors.Is(err, errFirewallNotFound) {
		return nil
	}
	return err
}

func countByDescription(rules []hcloud.FirewallRule, desc string) int {
	n := 0
	for _, r := range rules {
		if ruleHasDescription(r, desc) {
			n++
		}
	}
	return n
}

// FirewallAddEphemeralRule appends a single inbound (callerIP/32,
// port, tcp) rule to the server's firewall. Hetzner's API does not
// enforce server-side TTL, so the adapter encodes expiresAt into a
// description-tagged rule key, and THE EXPIRY SWEEP is here: every add
// and every remove also drops each daal-eph- window already past its
// expiry (sweepExpiredWindows), in the same write. A window left by a
// killed process therefore closes at the next window opened or closed
// on that firewall. The Helper is still expected to call
// FirewallRemoveEphemeralRule explicitly on completion.
//
// Strategy: read-modify-write through modifyFirewallRules (append,
// keep every other rule, verify it landed). The rule is tagged with a
// stable ruleID derived from (serverID, callerIP, port,
// expiresAtUnix) so removal can identify it without separate state;
// adding the same ruleID twice is a no-op. A non-nil error may come
// with a non-empty ruleID (see the end of the function).
func (l *liveClient) FirewallAddEphemeralRule(ctx context.Context, serverID, callerIP string, port int, expiresAt time.Time) (string, error) {
	srvInt, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		return "", fmt.Errorf("invalid server id %q: %w", serverID, err)
	}
	ip := net.ParseIP(callerIP)
	if ip == nil {
		return "", errors.New("invalid caller ip")
	}
	srv, _, err := l.c.Server.GetByID(ctx, srvInt)
	if err != nil {
		return "", err
	}
	if srv == nil {
		return "", errServerNotFound
	}
	if len(srv.PublicNet.Firewalls) == 0 {
		return "", fmt.Errorf("hetzner: server %s has no attached firewall", serverID)
	}
	fwID := srv.PublicNet.Firewalls[0].Firewall.ID

	bits := 32
	if ip.To4() == nil {
		bits = 128
	}
	mask := net.CIDRMask(bits, bits)
	cidr := net.IPNet{IP: ip.Mask(mask), Mask: mask}

	ruleID := fmt.Sprintf("daal-eph-%s-%s-%d-%d", serverID, callerIP, port, expiresAt.Unix())
	desc := ruleID
	rule := hcloud.FirewallRule{
		Direction:   hcloud.FirewallRuleDirectionIn,
		Protocol:    hcloud.FirewallRuleProtocolTCP,
		Port:        stringPtr(strconv.Itoa(port)),
		SourceIPs:   []net.IPNet{cidr},
		Description: &desc,
	}
	err = l.modifyFirewallRules(ctx, fwID,
		func(cur []hcloud.FirewallRule) ([]hcloud.FirewallRule, bool) {
			next, swept := sweepExpiredWindows(cur, time.Now(), ruleID)
			if _, ok := findRuleByDescription(next, ruleID); ok {
				return next, swept
			}
			return append(next, rule), true
		},
		func(after []hcloud.FirewallRule) bool {
			_, ok := findRuleByDescription(after, ruleID)
			return ok
		},
	)
	if err != nil {
		// The ruleID comes back WITH the error: set_rules may have
		// succeeded before the read-back failed or the three attempts
		// ran out, so the hole may be open. Removal is idempotent; a
		// caller that removes on any non-empty id closes it now instead
		// of at the next sweep.
		return ruleID, err
	}
	return ruleID, nil
}

// FirewallRemoveEphemeralRule strips the rule whose Description
// matches ruleID from the server's firewall. Idempotent: a
// missing rule (already expired or never present) returns nil, and
// so does a server or firewall that cannot be read (the expiry sweep
// of the next add or remove on that firewall is the backstop for a rule
// left behind that way). The same write also drops every window past
// its expiry (sweepExpiredWindows).
func (l *liveClient) FirewallRemoveEphemeralRule(ctx context.Context, ruleID string) error {
	if ruleID == "" {
		return nil
	}
	// The ruleID encodes the serverID prefix; we re-derive it.
	// daal-eph-<serverID>-<callerIP>-<port>-<expiresAtUnix>
	var serverID string
	{
		// scan past prefix "daal-eph-"
		const prefix = "daal-eph-"
		if len(ruleID) <= len(prefix) {
			return nil
		}
		rest := ruleID[len(prefix):]
		// serverID is up to first "-"
		for i := 0; i < len(rest); i++ {
			if rest[i] == '-' {
				serverID = rest[:i]
				break
			}
		}
	}
	if serverID == "" {
		return nil
	}
	srvInt, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		return nil // unparseable; treat as already-removed
	}
	srv, _, err := l.c.Server.GetByID(ctx, srvInt)
	if err != nil || srv == nil || len(srv.PublicNet.Firewalls) == 0 {
		return nil
	}
	fwID := srv.PublicNet.Firewalls[0].Firewall.ID
	err = l.modifyFirewallRules(ctx, fwID,
		func(cur []hcloud.FirewallRule) ([]hcloud.FirewallRule, bool) {
			swept, changed := sweepExpiredWindows(cur, time.Now(), ruleID)
			filtered := make([]hcloud.FirewallRule, 0, len(swept))
			for _, r := range swept {
				if ruleHasDescription(r, ruleID) {
					changed = true
					continue
				}
				filtered = append(filtered, r)
			}
			return filtered, changed
		},
		func(after []hcloud.FirewallRule) bool {
			_, ok := findRuleByDescription(after, ruleID)
			return !ok
		},
	)
	if errors.Is(err, errFirewallRead) || errors.Is(err, errFirewallNotFound) || hcloud.IsError(err, hcloud.ErrorCodeNotFound) {
		return nil
	}
	return err
}

func stringPtr(s string) *string { return &s }

// ephemeralRulePrefix starts every FirewallAddEphemeralRule
// description: daal-eph-<serverID>-<callerIP>-<port>-<expiresAtUnix>.
const ephemeralRulePrefix = "daal-eph-"

// ephemeralRuleExpiry reads the expiry a daal-eph- description
// carries. ok is false for any other description.
func ephemeralRuleExpiry(desc string) (time.Time, bool) {
	if !strings.HasPrefix(desc, ephemeralRulePrefix) {
		return time.Time{}, false
	}
	i := strings.LastIndexByte(desc, '-')
	sec, err := strconv.ParseInt(desc[i+1:], 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(sec, 0), true
}

// sweepExpiredWindows drops every daal-eph- window whose expiry is not
// after now, except the one named keep (the window being added or
// removed, handled by the caller). Every other rule (the Cloudflare
// rule, the baseline, a window still in date, anything a person added)
// stays. changed reports whether anything was dropped. It costs no API
// call: it runs inside the read-modify-write the add or remove makes.
func sweepExpiredWindows(cur []hcloud.FirewallRule, now time.Time, keep string) ([]hcloud.FirewallRule, bool) {
	out := make([]hcloud.FirewallRule, 0, len(cur)+1)
	changed := false
	for _, r := range cur {
		if r.Description != nil && *r.Description != keep {
			if exp, ok := ephemeralRuleExpiry(*r.Description); ok && !exp.After(now) {
				changed = true
				continue
			}
		}
		out = append(out, r)
	}
	return out, changed
}

// keepDaalRule reports whether a rule already on a firewall is one of
// Daal's own tagged rules that a baseline reset must keep: the
// Cloudflare rule, or a mgmt window not yet past its expiry.
func keepDaalRule(r hcloud.FirewallRule, now time.Time) bool {
	if r.Description == nil {
		return false
	}
	if *r.Description == cdnRuleDescription {
		return true
	}
	exp, ok := ephemeralRuleExpiry(*r.Description)
	return ok && now.Before(exp)
}

// baselineKeepingDaalRules is the rule set FirewallEnsureForServer
// writes on a firewall it reuses: the baseline, then every rule of
// cur that keepDaalRule keeps, in cur's order. Pure.
func baselineKeepingDaalRules(cur, baseline []hcloud.FirewallRule, now time.Time) []hcloud.FirewallRule {
	next := append(make([]hcloud.FirewallRule, 0, len(baseline)+len(cur)), baseline...)
	for _, r := range cur {
		if keepDaalRule(r, now) {
			next = append(next, r)
		}
	}
	return next
}

// ruleKey is a rule's identity for set comparison.
func ruleKey(r hcloud.FirewallRule) string {
	src := make([]string, 0, len(r.SourceIPs))
	for _, n := range r.SourceIPs {
		src = append(src, n.String())
	}
	sort.Strings(src)
	port, desc := "", ""
	if r.Port != nil {
		port = *r.Port
	}
	if r.Description != nil {
		desc = *r.Description
	}
	return fmt.Sprintf("%s|%s|%s|%s|%s", r.Direction, r.Protocol, port, strings.Join(src, ","), desc)
}

// sameRuleSet compares two rule lists as multisets.
func sameRuleSet(a, b []hcloud.FirewallRule) bool {
	if len(a) != len(b) {
		return false
	}
	n := make(map[string]int, len(a))
	for _, r := range a {
		n[ruleKey(r)]++
	}
	for _, r := range b {
		k := ruleKey(r)
		if n[k] == 0 {
			return false
		}
		n[k]--
	}
	return true
}

// FirewallEnsureForServer creates a per-server Hetzner Cloud Firewall
// with the daal baseline ruleset and attaches it to the server. Safe
// to call multiple times for the same server; second call returns the
// existing firewall ID without changing anything.
//
// Rules (inbound, from 0.0.0.0/0 + ::/0):
//   - 80/tcp (ACME http-01 future-proofing; nothing on the box listens
//     there and the box-side ufw does not open it)
//   - dataPlanePorts — one per family THIS relay serves, from
//     relayports.FirewallPortsFor(<its families>): 443/tcp only if it
//     serves vless-reality, 443/udp only if it serves hysteria2, and so
//     on. nil means a relay with no declared family set (the four
//     legacy tiers).
//
// Hetzner closes everything else when any inbound rule is present,
// so the random V2 mgmt port stays sealed until the wizard's
// FirewallAddEphemeralRule punches a (helperIP, port) hole.
func (l *liveClient) FirewallEnsureForServer(ctx context.Context, serverID string, dataPlanePorts []relayports.Endpoint) (string, error) {
	extraPorts := dataPlanePorts
	srvInt, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		return "", fmt.Errorf("invalid server id %q: %w", serverID, err)
	}
	srv, _, err := l.c.Server.GetByID(ctx, srvInt)
	if err != nil {
		return "", err
	}
	if srv == nil {
		return "", errServerNotFound
	}
	// Already attached?
	if len(srv.PublicNet.Firewalls) > 0 {
		return strconv.FormatInt(srv.PublicNet.Firewalls[0].Firewall.ID, 10), nil
	}

	name := "daal-relay-" + serverID
	_, ipv4Any, _ := net.ParseCIDR("0.0.0.0/0")
	_, ipv6Any, _ := net.ParseCIDR("::/0")
	srcAny := []net.IPNet{*ipv4Any, *ipv6Any}
	port80 := "80"
	baseRules := []hcloud.FirewallRule{
		{Direction: hcloud.FirewallRuleDirectionIn, Protocol: hcloud.FirewallRuleProtocolTCP, Port: &port80, SourceIPs: srcAny},
	}
	// Data-plane ports: one per served family, never a constant. 443/tcp
	// and 443/udp were unconditional here once, which left them open on a
	// relay provisioned without vless-reality or hysteria2 (finding
	// FAM-4). Derived from relayports so the firewall never
	// drifts from the sing-box inbound generator or the box-side ufw
	// rules.
	if extraPorts == nil {
		extraPorts = relayports.FirewallPortsFor(nil)
	}
	for _, ep := range extraPorts {
		portStr := strconv.Itoa(ep.Port)
		proto := hcloud.FirewallRuleProtocolTCP
		if ep.UDP {
			proto = hcloud.FirewallRuleProtocolUDP
		}
		baseRules = append(baseRules, hcloud.FirewallRule{
			Direction: hcloud.FirewallRuleDirectionIn, Protocol: proto, Port: &portStr, SourceIPs: srcAny,
		})
	}

	// Reuse an existing firewall with the same name if present
	// (e.g. left over from a previous, failed provision attempt).
	var fwID int64
	fws, err := l.c.Firewall.All(ctx)
	if err != nil {
		return "", err
	}
	for _, f := range fws {
		if f.Name == name {
			fwID = f.ID
			break
		}
	}
	if fwID == 0 {
		applyTo := []hcloud.FirewallResource{{
			Type:   hcloud.FirewallResourceTypeServer,
			Server: &hcloud.FirewallResourceServer{ID: srv.ID},
		}}
		res, _, err := l.c.Firewall.Create(ctx, hcloud.FirewallCreateOpts{
			Name:    name,
			Rules:   baseRules,
			ApplyTo: applyTo,
		})
		if err != nil {
			return "", fmt.Errorf("hetzner firewall create: %w", err)
		}
		return strconv.FormatInt(res.Firewall.ID, 10), nil
	}
	// Existing firewall: re-apply the baseline in case it drifted, and
	// attach to the server. This used to be a bare set_rules with the
	// baseline alone, which also deleted Daal's own tagged rules on it:
	// the Cloudflare rule (cdn-apply finds this firewall BY NAME, so it
	// can sit on a detached one, and SetEphemeralFirewallRule's
	// self-heal lands here exactly when the firewall was detached) and
	// any mgmt window still in date. Now it goes through
	// modifyFirewallRules like every other edit: untagged rules are
	// reset to the baseline, Daal's tagged rules are kept.
	fwRef := &hcloud.Firewall{ID: fwID}
	now := time.Now()
	err = l.modifyFirewallRules(ctx, fwID,
		func(cur []hcloud.FirewallRule) ([]hcloud.FirewallRule, bool) {
			next := baselineKeepingDaalRules(cur, baseRules, now)
			return next, !sameRuleSet(cur, next)
		},
		func(after []hcloud.FirewallRule) bool {
			return sameRuleSet(after, baselineKeepingDaalRules(after, baseRules, now))
		},
	)
	if err != nil {
		return "", fmt.Errorf("hetzner firewall set rules: %w", err)
	}
	if _, _, err := l.c.Firewall.ApplyResources(ctx, fwRef, []hcloud.FirewallResource{{
		Type:   hcloud.FirewallResourceTypeServer,
		Server: &hcloud.FirewallResourceServer{ID: srv.ID},
	}}); err != nil && !hcloud.IsError(err, hcloud.ErrorCodeIncompatibleNetworkType) {
		return "", fmt.Errorf("hetzner firewall apply: %w", err)
	}
	return strconv.FormatInt(fwID, 10), nil
}

// FirewallDeleteForServer detaches and deletes the per-server
// firewall named "daal-relay-<serverID>" — the name
// FirewallEnsureForServer minted, so a match is proof the firewall
// belongs to this server and no other.
//
// Idempotent: a missing firewall is success (Found=false).
//
// Shared-resource guard: if AppliedTo still lists a server other
// than serverID, the firewall is left completely intact (not even
// detached) and the other ids come back in SharedWith. Hetzner
// refuses to delete a firewall attached to a live server anyway
// (HTTP 422), but the point is not to be talked out of it by an
// error message — a firewall another relay depends on is its only
// protection for a random mgmt port.
func (l *liveClient) FirewallDeleteForServer(ctx context.Context, serverID string) (FirewallTeardownResult, error) {
	var res FirewallTeardownResult
	name := "daal-relay-" + serverID
	fws, err := l.c.Firewall.All(ctx)
	if err != nil {
		return res, err
	}
	for _, f := range fws {
		if f.Name != name {
			continue
		}
		res.Found = true
		res.FirewallID = strconv.FormatInt(f.ID, 10)

		// Who else is still behind this firewall? Our own server is
		// expected (Hetzner drops it from AppliedTo asynchronously
		// after a delete); anybody else is a hard stop.
		var ours []hcloud.FirewallResource
		for _, ap := range f.AppliedTo {
			if ap.Type != hcloud.FirewallResourceTypeServer || ap.Server == nil {
				continue
			}
			id := strconv.FormatInt(ap.Server.ID, 10)
			if id != serverID {
				res.SharedWith = append(res.SharedWith, id)
				continue
			}
			ours = append(ours, hcloud.FirewallResource{
				Type:   hcloud.FirewallResourceTypeServer,
				Server: &hcloud.FirewallResourceServer{ID: ap.Server.ID},
			})
		}
		if len(res.SharedWith) > 0 {
			return res, nil // preserved on purpose; caller reports it
		}
		if len(ours) > 0 {
			_, _, _ = l.c.Firewall.RemoveResources(ctx, f, ours)
		}
		if _, err := l.c.Firewall.Delete(ctx, f); err != nil &&
			!hcloud.IsError(err, hcloud.ErrorCodeNotFound) {
			return res, fmt.Errorf("hetzner firewall delete: %w", err)
		}
		res.Deleted = true
		return res, nil
	}
	return res, nil
}

// errServerNotFound is the sentinel for an absent server. The
// adapter treats it as success on Decommission and as
// already-handled on Provision idempotency-check.
var errServerNotFound = errors.New("server not found")

func serverInfoFromHcloud(s *hcloud.Server) *ServerInfo {
	if s == nil {
		return nil
	}
	si := &ServerInfo{
		ID:     strconv.FormatInt(s.ID, 10),
		Name:   s.Name,
		Status: string(s.Status),
		Labels: s.Labels,
	}
	if s.ServerType != nil {
		si.ServerType = s.ServerType.Name
	}
	if s.Datacenter != nil && s.Datacenter.Location != nil {
		si.Region = s.Datacenter.Location.Name
	}
	if s.PublicNet.IPv4.IP != nil {
		si.PublicIP = s.PublicNet.IPv4.IP
	}
	if s.PublicNet.IPv6.IP != nil {
		// Hetzner returns the IPv6 prefix; we use the network IP as
		// a representative address for OperatorRecord display.
		si.PublicIPv6 = net.IP(s.PublicNet.IPv6.IP)
	}
	return si
}

// ListingClient exposes read-only Hetzner API calls for the
// list-server-types CLI surface.
type ListingClient struct {
	c *hcloud.Client
}

// NewLiveClientForListing returns a listing-only client. It is not
// an hcloudClient — it only lists server types.
func NewLiveClientForListing(token string) *ListingClient {
	return &ListingClient{c: hcloud.NewClient(hcloud.WithToken(token))}
}

// ServerTypeEntry is a single server type with pricing for a region.
//
// Currency is stated even though this adapter only ever bills in euro,
// and the reason is the screen at the other end: the L5 sheet lists
// Hetzner and Vultr plans through the SAME component, and Vultr prices
// in USD (providers/vultr/live_client.go). A shape that says nothing
// about currency is one the renderer has to guess about, and the guess
// it made was a euro sign in front of a dollar figure. Say it here so
// neither side has to assume.
type ServerTypeEntry struct {
	ID          string  `json:"id"`
	Description string  `json:"description"`
	CPUs        int     `json:"cpus"`
	MemoryGB    float64 `json:"memory_gb"`
	DiskGB      int     `json:"disk_gb"`
	MonthlyEUR  float64 `json:"monthly_eur"`
	HourlyEUR   float64 `json:"hourly_eur"`
	Location    string  `json:"location"`
	Arch        string  `json:"arch"`
	Currency    string  `json:"currency,omitempty"`
}

// ListServerTypes returns all shared-CPU server types that are
// available for new-server creation in the given region, with pricing.
// Filters out dedicated/special types AND — critically — retired types.
//
// Hetzner keeps a pricing entry for a location long after a server type
// is retired there (e.g. the old cx11/cx21 Intel line), so filtering on
// pricing alone surfaces types that then fail `create server` with
// "unsupported location for server type (invalid_input)". The
// authoritative signal is the per-location Available flag on
// ServerType.Locations; honour it so the wizard only ever auto-selects
// a type it can actually provision.
func (l *ListingClient) ListServerTypes(ctx context.Context, region string) ([]ServerTypeEntry, error) {
	types, err := l.c.ServerType.All(ctx)
	if err != nil {
		return nil, err
	}
	// Never nil: an empty list is `[]` on stdout, which the app reads
	// as "nothing sold here", not `null`, which it could not read.
	result := []ServerTypeEntry{}
	for _, st := range types {
		// Only shared-CPU types (cax = ARM shared, cx = x86 shared, cpx = x86 perf shared)
		name := st.Name
		isShared := len(name) >= 2 && (name[:2] == "cx" || name[:3] == "cax" || name[:3] == "cpx" || name[:3] == "ccx")
		if !isShared {
			continue
		}
		if !serverTypeAvailableInLocation(st, region) {
			continue
		}
		for _, p := range st.Pricings {
			if p.Location == nil || p.Location.Name != region {
				continue
			}
			hourly, _ := strconv.ParseFloat(p.Hourly.Gross, 64)
			monthly, _ := strconv.ParseFloat(p.Monthly.Gross, 64)
			arch := "x86"
			if string(st.Architecture) == "arm" {
				arch = "arm"
			}
			result = append(result, ServerTypeEntry{
				ID:          st.Name,
				Description: st.Description,
				CPUs:        st.Cores,
				MemoryGB:    float64(st.Memory),
				DiskGB:      st.Disk,
				MonthlyEUR:  monthly,
				HourlyEUR:   hourly,
				Location:    region,
				Arch:        arch,
				Currency:    "EUR",
			})
		}
	}
	return result, nil
}

// serverTypeAvailableInLocation reports whether st can be used to create
// a new server in region. It trusts the per-location Available flag (and
// skips locations flagged deprecated). When the API returns no per-
// location list (older responses), it falls back to the type-level
// deprecation flag so a missing Locations slice never hides every type.
func serverTypeAvailableInLocation(st *hcloud.ServerType, region string) bool {
	if len(st.Locations) == 0 {
		return !st.IsDeprecated()
	}
	for _, loc := range st.Locations {
		if loc.Location != nil && loc.Location.Name == region {
			return loc.Available && !loc.IsDeprecated()
		}
	}
	return false
}

// ExistingServerEntry is a single existing server on the account.
type ExistingServerEntry struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	ServerType string `json:"server_type"`
	Region     string `json:"region"`
	PublicIP   string `json:"public_ip"`
	PublicIPv6 string `json:"public_ipv6"`
}

// ListServers returns all servers on the account.
func (l *ListingClient) ListServers(ctx context.Context) ([]ExistingServerEntry, error) {
	servers, err := l.c.Server.All(ctx)
	if err != nil {
		return nil, err
	}
	result := []ExistingServerEntry{} // never nil: `[]`, not `null`, for an empty account
	for _, s := range servers {
		entry := ExistingServerEntry{
			ID:     strconv.FormatInt(s.ID, 10),
			Name:   s.Name,
			Status: string(s.Status),
		}
		if s.ServerType != nil {
			entry.ServerType = s.ServerType.Name
		}
		if s.Datacenter != nil && s.Datacenter.Location != nil {
			entry.Region = s.Datacenter.Location.Name
		}
		if s.PublicNet.IPv4.IP != nil {
			entry.PublicIP = s.PublicNet.IPv4.IP.String()
		}
		if s.PublicNet.IPv6.IP != nil {
			entry.PublicIPv6 = s.PublicNet.IPv6.IP.String()
		}
		result = append(result, entry)
	}
	return result, nil
}

// FloatingIPList enumerates every reserved address on the account.
//
// hcloud's All() paginates internally, so a large account does not
// silently return page one — which would make the audit report "no
// orphans" on exactly the accounts most likely to have some.
func (l *liveClient) FloatingIPList(ctx context.Context) ([]*FloatingIPInfo, error) {
	fips, err := l.c.FloatingIP.All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*FloatingIPInfo, 0, len(fips))
	for _, f := range fips {
		if f == nil {
			continue
		}
		out = append(out, floatingIPInfoFromHcloud(f))
	}
	return out, nil
}

// FirewallList enumerates every firewall on the account.
//
// Both applied-to shapes are read, and they are kept apart. A firewall
// applied to servers has a knowable blast radius; one applied by label
// selector protects whatever matches at any moment, and the audit has
// to treat that as unprovable rather than as empty.
func (l *liveClient) FirewallList(ctx context.Context) ([]FirewallInfo, error) {
	fws, err := l.c.Firewall.All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]FirewallInfo, 0, len(fws))
	for _, f := range fws {
		if f == nil {
			continue
		}
		info := FirewallInfo{
			ID:     strconv.FormatInt(f.ID, 10),
			Name:   f.Name,
			Labels: f.Labels,
		}
		for _, ap := range f.AppliedTo {
			switch ap.Type {
			case hcloud.FirewallResourceTypeServer:
				if ap.Server != nil {
					info.AppliedToServerIDs = append(info.AppliedToServerIDs, strconv.FormatInt(ap.Server.ID, 10))
				}
			case hcloud.FirewallResourceTypeLabelSelector:
				if ap.LabelSelector != nil {
					info.LabelSelectors = append(info.LabelSelectors, ap.LabelSelector.Selector)
				}
			}
		}
		out = append(out, info)
	}
	return out, nil
}

// FirewallDeleteByID deletes one firewall. Absent is success, so a
// reclaim that runs twice does not report a failure the second time.
//
// This call performs NO safety check of its own, deliberately: it is
// the narrow verb, and the emptiness + dead-server proof belongs one
// layer up in the audit where it can be re-verified against fresh
// reads and reported to the operator by name. A guard here as well
// would be a second, weaker copy of that reasoning.
func (l *liveClient) FirewallDeleteByID(ctx context.Context, firewallID string) error {
	fwInt, err := strconv.ParseInt(firewallID, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid firewall id %q: %w", firewallID, err)
	}
	_, err = l.c.Firewall.Delete(ctx, &hcloud.Firewall{ID: fwInt})
	if hcloud.IsError(err, hcloud.ErrorCodeNotFound) {
		return nil
	}
	return err
}
