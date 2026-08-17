package hetzner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
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

// FirewallEnsureForServer creates a per-server Hetzner Cloud Firewall
// with the daal baseline ruleset and attaches it to the server. Safe
// to call multiple times for the same server; second call returns the
// existing firewall ID without changing anything.
//
// Baseline rules (inbound):
//   - 443/tcp from 0.0.0.0/0 + ::/0 (VLESS / HTTPS)
//   - 443/udp from 0.0.0.0/0 + ::/0 (Hysteria2 / QUIC)
//   - 80/tcp  from 0.0.0.0/0 + ::/0 (ACME http-01 future-proofing)
//   - plus relayports.ExtraFirewallPorts() (naive=8444/tcp,
//     websocket-tls=8445/tcp) — the TLS families that can't share
//     443/tcp with REALITY.
//
// Hetzner closes everything else when any inbound rule is present,
// so the random V2 mgmt port stays sealed until the wizard's
// FirewallAddEphemeralRule punches a (helperIP, port) hole.
func (l *liveClient) FirewallEnsureForServer(ctx context.Context, serverID string) (string, error) {
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
	port443 := "443"
	port80 := "80"
	baseRules := []hcloud.FirewallRule{
		{Direction: hcloud.FirewallRuleDirectionIn, Protocol: hcloud.FirewallRuleProtocolTCP, Port: &port443, SourceIPs: srcAny},
		{Direction: hcloud.FirewallRuleDirectionIn, Protocol: hcloud.FirewallRuleProtocolUDP, Port: &port443, SourceIPs: srcAny},
		{Direction: hcloud.FirewallRuleDirectionIn, Protocol: hcloud.FirewallRuleProtocolTCP, Port: &port80, SourceIPs: srcAny},
	}
	// Data-plane ports for the TLS families that can't share 443/tcp
	// with REALITY (naive=8444/tcp, websocket-tls=8445/tcp). Derived
	// from relayports so the firewall never drifts from the sing-box
	// inbound generator.
	for _, ep := range relayports.ExtraFirewallPorts() {
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
	// Existing firewall: re-apply rules in case they drifted, and
	// attach to the server.
	fwRef := &hcloud.Firewall{ID: fwID}
	if _, _, err := l.c.Firewall.SetRules(ctx, fwRef, hcloud.FirewallSetRulesOpts{Rules: baseRules}); err != nil {
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
	var result []ServerTypeEntry
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
	var result []ExistingServerEntry
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
