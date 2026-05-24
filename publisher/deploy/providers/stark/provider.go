package stark

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"time"

	"daal/publisher/deploy/cloudinit"
	"daal/publisher/deploy/health"
	"daal/publisher/deploy/provider"
)

// Provider is the FRP-10 Stark adapter. The bearer token is
// supplied at construction time by the wizard's keystore-bridge;
// the Provider type holds it as a `tokenSource func() string`
// closure so the keystore can re-fetch on each request and the
// token never lives in struct state for longer than a request.
type Provider struct {
	client      *Client
	tokenSource func() string
	clock       func() time.Time
}

// New returns a Provider bound to the supplied REST client +
// token-source. The token-source is called once per outbound
// request; the Provider never caches the result.
func New(c *Client, tokenSource func() string) *Provider {
	if c == nil {
		c = NewClient()
	}
	return &Provider{client: c, tokenSource: tokenSource, clock: time.Now}
}

// SetClock injects a deterministic clock for tests.
func (p *Provider) SetClock(now func() time.Time) { p.clock = now }

// Provision creates a new Stark VPS.
func (p *Provider) Provision(ctx context.Context, opts provider.ProvisionOpts) (*provider.OperatorRecord, error) {
	if err := validateProvisionOpts(opts); err != nil {
		return nil, err
	}
	hostname := derivedHostname(opts.PublisherPubKey, opts.Region)

	mgmtPort, err := provider.ResolveMgmtPort(opts.MgmtPort)
	if err != nil {
		return nil, fmt.Errorf("stark: %w", err)
	}
	if opts.DryRun {
		return p.dryRunRecord(hostname, opts, mgmtPort), nil
	}

	token := p.token()
	if existing, err := p.findByHostname(ctx, token, hostname); err == nil && existing != nil {
		if opts.MgmtPort == 0 {
			return nil, errors.New("stark: existing vps requires persisted MgmtPort")
		}
		rec := p.recordFromVPS(existing, opts)
		rec.MgmtPort = mgmtPort
		return rec, nil
	} else if err != nil && !errors.Is(err, errStarkNotFound) {
		return nil, fmt.Errorf("stark: lookup existing: %w", err)
	}

	pubBytes := sshPublicKeyBytes(opts.EphemeralSSHKey)
	var sshResp SSHKeyResp
	if err := p.client.do(ctx, token, "POST", "/ssh-keys", SSHKeyReq{Name: hostname + "-ephemeral", PublicKey: string(pubBytes)}, &sshResp); err != nil {
		return nil, fmt.Errorf("stark: create ssh key: %w", err)
	}

	healthToken, err := generateHealthToken()
	if err != nil {
		return nil, fmt.Errorf("stark: generate health token: %w", err)
	}
	userData, err := cloudinit.RenderV2(cloudinit.RenderInputV2{
		RenderInput: cloudinit.RenderInput{
			EphemeralSSHPublicKey: string(pubBytes),
			ProvisioningClientIP:  opts.HelperIP.String(),
			HealthToken:           healthToken,
			SingBoxConfigJSON:     `{"profile":"` + opts.ToolboxProfile + `"}`,
		},
		MgmtPubKeyHex: hex.EncodeToString(opts.PublisherPubKey),
		MgmtPort:      mgmtPort,
	})
	if err != nil {
		return nil, fmt.Errorf("stark: render cloud-init: %w", err)
	}

	var vpsResp VPSResp
	if err := p.client.do(ctx, token, "POST", "/vps", VPSCreateReq{
		Hostname: hostname, Plan: opts.ServerType, Region: opts.Region,
		OS: "ubuntu-24.04", UserData: base64.StdEncoding.EncodeToString(userData),
		SSHKeys: []string{sshResp.KeyID},
		Tags:    []string{"managed-by:daal-deploy", "toolbox:" + opts.ToolboxProfile},
	}, &vpsResp); err != nil {
		return nil, fmt.Errorf("stark: create vps: %w", err)
	}
	rec := p.recordFromVPS(&vpsResp, opts)
	rec.MgmtPort = mgmtPort
	if opts.WaitForHealth {
		fp, err := waitForMgmtFingerprint(ctx, rec.PublicIP, healthToken)
		if err != nil {
			return nil, fmt.Errorf("stark: wait for mgmt fingerprint: %w", err)
		}
		rec.MgmtTLSFingerprint = fp
	}
	return rec, nil
}

// Reprovision deletes and lets the caller recreate. V1.5 model.
func (p *Provider) Reprovision(ctx context.Context, rec *provider.OperatorRecord, opts provider.ReprovisionOpts) error {
	if rec == nil {
		return errors.New("stark: nil OperatorRecord")
	}
	token := p.token()
	if err := p.client.do(ctx, token, "DELETE", "/vps/"+rec.ServerID, nil, nil); err != nil && !errors.Is(err, errStarkNotFound) {
		return fmt.Errorf("stark: delete during reprovision: %w", err)
	}
	now := p.clock()
	rec.LastReprovisionedAt = &now
	return nil
}

// Decommission deletes the VPS. Idempotent.
func (p *Provider) Decommission(ctx context.Context, rec *provider.OperatorRecord) error {
	if rec == nil || rec.ServerID == "" {
		return nil
	}
	token := p.token()
	err := p.client.do(ctx, token, "DELETE", "/vps/"+rec.ServerID, nil, nil)
	if err != nil && !errors.Is(err, errStarkNotFound) {
		return err
	}
	return nil
}

// AssignFloatingIP attaches a Stark Reserved IP to the VPS.
func (p *Provider) AssignFloatingIP(ctx context.Context, rec *provider.OperatorRecord, fipID string) error {
	if rec == nil || rec.ServerID == "" {
		return errors.New("stark: OperatorRecord without ServerID")
	}
	if rec.FloatingIPID == fipID {
		return nil
	}
	token := p.token()
	if err := p.client.do(ctx, token, "POST", "/reserved-ips/"+fipID+"/attach", map[string]string{"vps_id": rec.ServerID}, nil); err != nil {
		return fmt.Errorf("stark: attach reserved ip: %w", err)
	}
	rec.FloatingIPID = fipID
	return nil
}

// UnassignFloatingIP detaches the reserved IP.
func (p *Provider) UnassignFloatingIP(ctx context.Context, rec *provider.OperatorRecord) error {
	if rec == nil || rec.FloatingIPID == "" {
		return nil
	}
	token := p.token()
	if err := p.client.do(ctx, token, "POST", "/reserved-ips/"+rec.FloatingIPID+"/detach", nil, nil); err != nil {
		return fmt.Errorf("stark: detach reserved ip: %w", err)
	}
	rec.FloatingIPID = ""
	return nil
}

// Pricing returns the live per-hour cost for the VPS plan.
func (p *Provider) Pricing(ctx context.Context, rec *provider.OperatorRecord) (provider.Pricing, error) {
	token := p.token()
	var pr PriceResp
	if err := p.client.do(ctx, token, "GET", "/pricing/"+rec.ServerType+"?region="+rec.Region, nil, &pr); err != nil {
		return provider.Pricing{}, err
	}
	return provider.Pricing{
		Provider:   "stark",
		Region:     rec.Region,
		ServerType: rec.ServerType,
		HourlyEUR:  pr.MonthlyEUR / 730.0,
		MonthlyEUR: pr.MonthlyEUR,
	}, nil
}

// SetEphemeralFirewallRule opens (callerIP/32, port, tcp) on the
// VPS firewall for durationSec. Stark enforces server-side TTL via
// the expires_at_unix field.
func (p *Provider) SetEphemeralFirewallRule(ctx context.Context, serverID, callerIP string, port int, durationSec int) (*provider.EphemeralFirewallRule, error) {
	if serverID == "" {
		return nil, errors.New("stark: SetEphemeralFirewallRule serverID required")
	}
	if callerIP == "" {
		return nil, errors.New("stark: SetEphemeralFirewallRule callerIP required")
	}
	if err := provider.ValidateMgmtPort(port); err != nil {
		return nil, fmt.Errorf("stark: SetEphemeralFirewallRule invalid port: %w", err)
	}
	if durationSec <= 0 {
		return nil, fmt.Errorf("stark: SetEphemeralFirewallRule invalid durationSec %d", durationSec)
	}
	token := p.token()
	expiresAt := p.clock().Add(time.Duration(durationSec) * time.Second).UTC()
	var resp FirewallRuleResp
	if err := p.client.do(ctx, token, "POST", "/firewall/rules", FirewallRuleReq{
		VPSID: serverID, SrcIP: callerIP, Port: port, Protocol: "tcp",
		ExpiresAt: expiresAt.Unix(),
	}, &resp); err != nil {
		return nil, fmt.Errorf("stark: add ephemeral rule: %w", err)
	}
	return &provider.EphemeralFirewallRule{
		ID:        resp.RuleID,
		ServerID:  serverID,
		CallerIP:  callerIP,
		Port:      port,
		ExpiresAt: expiresAt,
	}, nil
}

// RemoveEphemeralFirewallRule strips the rule. Idempotent.
func (p *Provider) RemoveEphemeralFirewallRule(ctx context.Context, rule *provider.EphemeralFirewallRule) error {
	if rule == nil || rule.ID == "" {
		return nil
	}
	token := p.token()
	err := p.client.do(ctx, token, "DELETE", "/firewall/rules/"+rule.ID, nil, nil)
	if err != nil && !errors.Is(err, errStarkNotFound) {
		return err
	}
	return nil
}

// --- helpers ---

func (p *Provider) token() string {
	if p.tokenSource == nil {
		return ""
	}
	return p.tokenSource()
}

func (p *Provider) findByHostname(ctx context.Context, token, hostname string) (*VPSResp, error) {
	var list []VPSResp
	if err := p.client.do(ctx, token, "GET", "/vps?hostname="+hostname, nil, &list); err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, errStarkNotFound
	}
	return &list[0], nil
}

func validateProvisionOpts(opts provider.ProvisionOpts) error {
	if len(opts.PublisherPubKey) == 0 {
		return errors.New("ProvisionOpts.PublisherPubKey required")
	}
	if opts.Region == "" {
		return errors.New("ProvisionOpts.Region required")
	}
	if opts.ServerType == "" {
		return errors.New("ProvisionOpts.ServerType required")
	}
	if opts.ToolboxProfile == "" {
		return errors.New("ProvisionOpts.ToolboxProfile required")
	}
	if opts.HelperIP == nil {
		return errors.New("ProvisionOpts.HelperIP required")
	}
	if !opts.DryRun && opts.EphemeralSSHKey == nil {
		return errors.New("ProvisionOpts.EphemeralSSHKey required (or set DryRun)")
	}
	return nil
}

func derivedHostname(pubKey []byte, region string) string {
	if len(pubKey) < 8 {
		return fmt.Sprintf("daal-%s-%x", region, pubKey)
	}
	return fmt.Sprintf("daal-%s-%s", region, hex.EncodeToString(pubKey[:8]))
}

func generateHealthToken() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func (p *Provider) recordFromVPS(v *VPSResp, opts provider.ProvisionOpts) *provider.OperatorRecord {
	rec := &provider.OperatorRecord{
		Provider:        "stark",
		ServerID:        v.ID,
		ServerType:      v.Plan,
		Region:          v.Region,
		ToolboxProfile:  opts.ToolboxProfile,
		PublisherPubKey: opts.PublisherPubKey,
		ProvisionedAt:   p.clock().UTC(),
	}
	if v.IPv4 != "" {
		rec.PublicIP = net.ParseIP(v.IPv4)
	}
	if v.IPv6 != "" {
		rec.PublicIPv6 = net.ParseIP(v.IPv6)
	}
	rec.Candidates = candidatesForProfile(opts.ToolboxProfile, rec.PublicIP, opts.EnabledFamilies)
	return rec
}

func sshPublicKeyBytes(priv ed25519.PrivateKey) []byte {
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok || len(pub) == 0 {
		return []byte("ssh-ed25519 INVALID daal-deploy")
	}
	algo := []byte("ssh-ed25519")
	var buf []byte
	buf = appendString(buf, algo)
	buf = appendString(buf, []byte(pub))
	enc := base64.StdEncoding.EncodeToString(buf)
	return []byte("ssh-ed25519 " + enc + " daal-deploy")
}

func appendString(buf, s []byte) []byte {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(s)))
	buf = append(buf, l[:]...)
	buf = append(buf, s...)
	return buf
}

func (p *Provider) dryRunRecord(hostname string, opts provider.ProvisionOpts, mgmtPort int) *provider.OperatorRecord {
	return &provider.OperatorRecord{
		Provider:        "stark",
		ServerID:        "dry-run-" + hostname,
		ServerType:      opts.ServerType,
		Region:          opts.Region,
		PublicIP:        opts.HelperIP,
		ToolboxProfile:  opts.ToolboxProfile,
		PublisherPubKey: opts.PublisherPubKey,
		Candidates:      candidatesForProfile(opts.ToolboxProfile, opts.HelperIP, opts.EnabledFamilies),
		ProvisionedAt:   p.clock().UTC(),
		MgmtPort:        mgmtPort,
	}
}

func waitForMgmtFingerprint(ctx context.Context, ip net.IP, token string) (string, error) {
	return health.WaitForMgmtFingerprint(ctx, ip, token, 12, 5*time.Second)
}
