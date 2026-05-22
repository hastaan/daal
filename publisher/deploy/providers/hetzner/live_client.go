package hetzner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

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

func (l *liveClient) SSHKeyCreate(ctx context.Context, name string, publicKey []byte) (string, error) {
	k, _, err := l.c.SSHKey.Create(ctx, hcloud.SSHKeyCreateOpts{
		Name:      name,
		PublicKey: string(publicKey),
	})
	if err != nil {
		return "", err
	}
	return strconv.FormatInt(k.ID, 10), nil
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

func (l *liveClient) FloatingIPUnassign(ctx context.Context, fipID string) error {
	fipInt, err := strconv.ParseInt(fipID, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid floating-ip id %q: %w", fipID, err)
	}
	_, _, err = l.c.FloatingIP.Unassign(ctx, &hcloud.FloatingIP{ID: fipInt})
	return err
}

// FirewallApplyCloudflareRule creates or updates a Hetzner Cloud
// Firewall rule allowing inbound 443/tcp ONLY from the supplied
// Cloudflare edge ranges. Idempotent: passing an existing
// firewallID re-uses it; empty firewallID creates a fresh rule.
//
// FRP-8 §11.7: this binds the origin's 443/tcp ingress to
// Cloudflare-only sources. Called from the Helper, never from
// the origin box.
func (l *liveClient) FirewallApplyCloudflareRule(ctx context.Context, firewallID string, ipv4Ranges, ipv6Ranges []string) (string, error) {
	rule := hcloud.FirewallRule{
		Direction: hcloud.FirewallRuleDirectionIn,
		Protocol:  hcloud.FirewallRuleProtocolTCP,
		Port:      stringPtr("443"),
	}
	for _, r := range ipv4Ranges {
		_, n, err := net.ParseCIDR(r)
		if err != nil {
			return "", fmt.Errorf("hetzner firewall: invalid v4 cidr %q: %w", r, err)
		}
		rule.SourceIPs = append(rule.SourceIPs, *n)
	}
	for _, r := range ipv6Ranges {
		_, n, err := net.ParseCIDR(r)
		if err != nil {
			return "", fmt.Errorf("hetzner firewall: invalid v6 cidr %q: %w", r, err)
		}
		rule.SourceIPs = append(rule.SourceIPs, *n)
	}

	if firewallID == "" {
		res, _, err := l.c.Firewall.Create(ctx, hcloud.FirewallCreateOpts{
			Name:  "daal-cloudflare-edge-only",
			Rules: []hcloud.FirewallRule{rule},
		})
		if err != nil {
			return "", err
		}
		return strconv.FormatInt(res.Firewall.ID, 10), nil
	}

	idInt, err := strconv.ParseInt(firewallID, 10, 64)
	if err != nil {
		return "", fmt.Errorf("invalid firewall id %q: %w", firewallID, err)
	}
	_, _, err = l.c.Firewall.SetRules(ctx, &hcloud.Firewall{ID: idInt}, hcloud.FirewallSetRulesOpts{
		Rules: []hcloud.FirewallRule{rule},
	})
	if err != nil {
		return "", err
	}
	return firewallID, nil
}

// FirewallAddEphemeralRule appends a single inbound (callerIP/32,
// port, tcp) rule to the server's firewall. Hetzner's API does not
// enforce server-side TTL, so the adapter encodes expiresAt into a
// description-tagged rule key and the calling Provider runs a
// defensive expiry sweep. The Helper is still expected to call
// FirewallRemoveEphemeralRule explicitly on completion.
//
// Strategy: read the server's current firewall rule set, append a
// new rule, re-set rules in one shot. The rule is tagged with a
// stable ruleID derived from (serverID, callerIP, port,
// expiresAtUnix) so removal can identify it without separate state.
func (l *liveClient) FirewallAddEphemeralRule(ctx context.Context, serverID, callerIP string, port int, expiresAt time.Time) (string, error) {
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
	if len(srv.PublicNet.Firewalls) == 0 {
		return "", fmt.Errorf("hetzner: server %s has no attached firewall", serverID)
	}
	fw := srv.PublicNet.Firewalls[0].Firewall
	fwFull, _, err := l.c.Firewall.GetByID(ctx, fw.ID)
	if err != nil {
		return "", err
	}

	ip := net.ParseIP(callerIP)
	if ip == nil {
		return "", fmt.Errorf("invalid caller ip %q", callerIP)
	}
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
	rules := append([]hcloud.FirewallRule{}, fwFull.Rules...)
	rules = append(rules, rule)
	if _, _, err := l.c.Firewall.SetRules(ctx, fwFull, hcloud.FirewallSetRulesOpts{Rules: rules}); err != nil {
		return "", err
	}
	return ruleID, nil
}

// FirewallRemoveEphemeralRule strips the rule whose Description
// matches ruleID from the server's firewall. Idempotent: a
// missing rule (already expired or never present) returns nil.
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
	fw := srv.PublicNet.Firewalls[0].Firewall
	fwFull, _, err := l.c.Firewall.GetByID(ctx, fw.ID)
	if err != nil || fwFull == nil {
		return nil
	}
	filtered := make([]hcloud.FirewallRule, 0, len(fwFull.Rules))
	dropped := false
	for _, r := range fwFull.Rules {
		if r.Description != nil && *r.Description == ruleID {
			dropped = true
			continue
		}
		filtered = append(filtered, r)
	}
	if !dropped {
		return nil // already removed
	}
	_, _, err = l.c.Firewall.SetRules(ctx, fwFull, hcloud.FirewallSetRulesOpts{Rules: filtered})
	if hcloud.IsError(err, hcloud.ErrorCodeNotFound) {
		return nil
	}
	return err
}

func stringPtr(s string) *string { return &s }

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
