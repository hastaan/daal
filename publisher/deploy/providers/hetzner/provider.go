package hetzner

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

// Provider is the FRP-4a Hetzner adapter. It implements
// provider.Provider via a narrow hcloudClient interface so unit
// tests can swap in an in-memory fake.
//
// Idempotence: Provision/Reprovision/Decommission/AssignFloatingIP
// are all safe to retry. The adapter looks up the server by name
// derived from publisher pubkey + region first; if it exists, it
// reuses it.
type Provider struct {
	c           hcloudClient
	clock       func() time.Time
	tokenSource func() string // optional: how to fetch fresh API tokens
}

// New returns a Provider bound to the given hcloudClient. The
// production path is `New(NewLiveClient(token))`; tests pass a fake
// client.
func New(c hcloudClient) *Provider {
	return &Provider{c: c, clock: time.Now}
}

// SetClock injects a deterministic clock for tests.
func (p *Provider) SetClock(now func() time.Time) { p.clock = now }

// Provision creates a new VPS, runs the cloud-init, and returns an
// OperatorRecord. Idempotent: if a server with the derived name
// already exists, it is reused.
func (p *Provider) Provision(ctx context.Context, opts provider.ProvisionOpts) (*provider.OperatorRecord, error) {
	if err := validateProvisionOpts(opts); err != nil {
		return nil, err
	}
	name := derivedServerName(opts.PublisherPubKey, opts.Region)

	mgmtPort, err := provider.ResolveMgmtPort(opts.MgmtPort)
	if err != nil {
		return nil, fmt.Errorf("hetzner: %w", err)
	}
	if opts.DryRun {
		return p.dryRunRecord(name, opts, mgmtPort), nil
	}

	// Idempotency: if server already exists with this derived name,
	// return the existing OperatorRecord. The caller must pass the
	// persisted MgmtPort on retries; otherwise we would return a fresh
	// random port that does not match the already-provisioned box.
	if existing, err := p.c.ServerByName(ctx, name); err == nil && existing != nil {
		if opts.MgmtPort == 0 {
			return nil, errors.New("hetzner: existing server requires persisted MgmtPort")
		}
		rec := p.recordFromServer(existing, opts)
		rec.MgmtPort = mgmtPort
		return rec, nil
	} else if err != nil && !errors.Is(err, errServerNotFound) {
		return nil, fmt.Errorf("hetzner: lookup existing server: %w", err)
	}

	// Live path: derive ssh public-key bytes, render cloud-init, create server.
	pubBytes := sshPublicKeyBytes(opts.EphemeralSSHKey)
	sshKeyID, err := p.c.SSHKeyCreate(ctx, name+"-ephemeral", pubBytes)
	if err != nil {
		return nil, fmt.Errorf("hetzner: create ssh key: %w", err)
	}

	healthToken, err := generateHealthToken()
	if err != nil {
		_ = p.c.SSHKeyDelete(ctx, sshKeyID)
		return nil, fmt.Errorf("hetzner: generate health token: %w", err)
	}

	userData, err := cloudinit.RenderV2(cloudinit.RenderInputV2{
		RenderInput: cloudinit.RenderInput{
			EphemeralSSHPublicKey: string(pubBytes),
			ProvisioningClientIP:  opts.HelperIP.String(),
			HealthToken:           healthToken,
			SingBoxConfigJSON:     defaultSingBoxConfig(opts.ToolboxProfile),
		},
		MgmtPubKeyHex: hex.EncodeToString(opts.PublisherPubKey),
		MgmtPort:      mgmtPort,
	})
	if err != nil {
		_ = p.c.SSHKeyDelete(ctx, sshKeyID)
		return nil, fmt.Errorf("hetzner: render cloud-init: %w", err)
	}

	srv, err := p.c.ServerCreate(ctx, ServerCreateOpts{
		Name:       name,
		ServerType: opts.ServerType,
		Region:     opts.Region,
		Image:      "ubuntu-24.04",
		UserData:   string(userData),
		SSHKeyIDs:  []string{sshKeyID},
		Labels:     map[string]string{"managed-by": "daal-deploy", "toolbox": opts.ToolboxProfile},
	})
	if err != nil {
		_ = p.c.SSHKeyDelete(ctx, sshKeyID)
		return nil, fmt.Errorf("hetzner: create server: %w", err)
	}
	rec := p.recordFromServer(srv, opts)
	rec.MgmtPort = mgmtPort
	if opts.WaitForHealth {
		fp, err := waitForMgmtFingerprint(ctx, rec.PublicIP, healthToken)
		if err != nil {
			return nil, fmt.Errorf("hetzner: wait for mgmt fingerprint: %w", err)
		}
		rec.MgmtTLSFingerprint = fp
	}
	return rec, nil
}

// Reprovision deletes-and-recreates the box. At V1.5 this is the
// only L1/L2/L4/L5/L6 path per supplement section 9.5.1.
func (p *Provider) Reprovision(ctx context.Context, rec *provider.OperatorRecord, opts provider.ReprovisionOpts) error {
	if rec == nil {
		return errors.New("nil OperatorRecord")
	}
	if err := p.c.ServerDelete(ctx, rec.ServerID); err != nil {
		return fmt.Errorf("hetzner: delete during reprovision: %w", err)
	}
	now := p.clock()
	rec.LastReprovisionedAt = &now
	// The caller is expected to invoke Provision next with the new
	// opts. We don't re-create here because Reprovision deliberately
	// does not own the new ProvisionOpts (those flow from the
	// wizard). Callers compose Reprovision + Provision.
	return nil
}

// Decommission deletes the VPS. Idempotent: deleting an absent
// server returns nil.
func (p *Provider) Decommission(ctx context.Context, rec *provider.OperatorRecord) error {
	if rec == nil || rec.ServerID == "" {
		return nil
	}
	return p.c.ServerDelete(ctx, rec.ServerID)
}

// AssignFloatingIP attaches the given floating IP to the
// OperatorRecord's server. Idempotent: same fipID twice is a no-op.
func (p *Provider) AssignFloatingIP(ctx context.Context, rec *provider.OperatorRecord, fipID string) error {
	if rec == nil || rec.ServerID == "" {
		return errors.New("OperatorRecord without ServerID")
	}
	if rec.FloatingIPID == fipID {
		return nil // idempotent
	}
	if err := p.c.FloatingIPAssign(ctx, fipID, rec.ServerID); err != nil {
		return fmt.Errorf("hetzner: assign floating ip: %w", err)
	}
	rec.FloatingIPID = fipID
	return nil
}

// UnassignFloatingIP detaches the currently recorded floating IP.
// Idempotent: records without a floating IP are already converged.
func (p *Provider) UnassignFloatingIP(ctx context.Context, rec *provider.OperatorRecord) error {
	if rec == nil {
		return nil
	}
	if rec.FloatingIPID == "" {
		return nil
	}
	if err := p.c.FloatingIPUnassign(ctx, rec.FloatingIPID); err != nil {
		return fmt.Errorf("hetzner: unassign floating ip: %w", err)
	}
	rec.FloatingIPID = ""
	return nil
}

// Pricing returns the live per-hour cost for the OperatorRecord's
// server type. The wizard caches this for 60 s on its side.
func (p *Provider) Pricing(ctx context.Context, rec *provider.OperatorRecord) (provider.Pricing, error) {
	hourly, monthly, err := p.c.ServerTypePrice(ctx, rec.Region, rec.ServerType)
	if err != nil {
		return provider.Pricing{}, err
	}
	return provider.Pricing{
		Provider:   "hetzner",
		Region:     rec.Region,
		ServerType: rec.ServerType,
		HourlyEUR:  hourly,
		MonthlyEUR: monthly,
	}, nil
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

// derivedServerName produces a deterministic Hetzner server name
// from the publisher pubkey + region. Same publisher + same region
// => same name => idempotent Provision.
func derivedServerName(pubKey []byte, region string) string {
	if len(pubKey) < 8 {
		return fmt.Sprintf("daal-%s-%x", region, pubKey)
	}
	return fmt.Sprintf("daal-%s-%s", region, hex.EncodeToString(pubKey[:8]))
}

// generateHealthToken returns a random hex token for the box's
// /healthz/<token> route.
func generateHealthToken() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// recordFromServer builds an OperatorRecord from the cloud-side
// ServerInfo + the caller's ProvisionOpts.
func (p *Provider) recordFromServer(s *ServerInfo, opts provider.ProvisionOpts) *provider.OperatorRecord {
	return &provider.OperatorRecord{
		Provider:        "hetzner",
		ServerID:        s.ID,
		ServerType:      s.ServerType,
		Region:          s.Region,
		PublicIP:        s.PublicIP,
		PublicIPv6:      s.PublicIPv6,
		ToolboxProfile:  opts.ToolboxProfile,
		PublisherPubKey: opts.PublisherPubKey,
		Candidates:      candidatesForProfile(opts.ToolboxProfile, s.PublicIP, opts.EnabledFamilies),
		ProvisionedAt:   p.clock().UTC(),
	}
}

// sshPublicKeyBytes encodes the public half of an ed25519 keypair
// as an OpenSSH-format single-line string suitable for
// authorized_keys: "ssh-ed25519 <base64> daal-deploy".
func sshPublicKeyBytes(priv ed25519.PrivateKey) []byte {
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok || len(pub) == 0 {
		return []byte("ssh-ed25519 INVALID daal-deploy")
	}
	// OpenSSH ed25519 wire format: string("ssh-ed25519") || string(pubkey).
	algo := []byte("ssh-ed25519")
	var buf []byte
	buf = appendString(buf, algo)
	buf = appendString(buf, []byte(pub))
	enc := base64.StdEncoding.EncodeToString(buf)
	return []byte("ssh-ed25519 " + enc + " daal-deploy")
}

// appendString appends an SSH-wire-format string (4-byte BE length +
// bytes) to buf.
func appendString(buf, s []byte) []byte {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(s)))
	buf = append(buf, l[:]...)
	buf = append(buf, s...)
	return buf
}

// dryRunRecord returns a synthetic OperatorRecord without making
// any cloud-API call. Used by `daal-deploy provision --dry-run`.
func (p *Provider) dryRunRecord(name string, opts provider.ProvisionOpts, mgmtPort int) *provider.OperatorRecord {
	return &provider.OperatorRecord{
		Provider:        "hetzner",
		ServerID:        "dry-run-" + name,
		ServerType:      opts.ServerType,
		Region:          opts.Region,
		PublicIP:        opts.HelperIP, // placeholder; live call would assign real IP
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

// SetEphemeralFirewallRule opens a (callerIP/32, port, tcp)
// inbound rule on the server's Hetzner Cloud Firewall for
// durationSec seconds. The rule is description-tagged with the
// returned EphemeralFirewallRule.ID; RemoveEphemeralFirewallRule
// strips by description match. FRP-10 §9.5.2.
func (p *Provider) SetEphemeralFirewallRule(ctx context.Context, serverID, callerIP string, port int, durationSec int) (*provider.EphemeralFirewallRule, error) {
	if serverID == "" {
		return nil, errors.New("hetzner: SetEphemeralFirewallRule serverID required")
	}
	if callerIP == "" {
		return nil, errors.New("hetzner: SetEphemeralFirewallRule callerIP required")
	}
	if err := provider.ValidateMgmtPort(port); err != nil {
		return nil, fmt.Errorf("hetzner: SetEphemeralFirewallRule invalid port: %w", err)
	}
	if durationSec <= 0 {
		return nil, fmt.Errorf("hetzner: SetEphemeralFirewallRule invalid durationSec %d", durationSec)
	}
	expiresAt := p.clock().Add(time.Duration(durationSec) * time.Second).UTC()
	id, err := p.c.FirewallAddEphemeralRule(ctx, serverID, callerIP, port, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("hetzner: add ephemeral rule: %w", err)
	}
	return &provider.EphemeralFirewallRule{
		ID:        id,
		ServerID:  serverID,
		CallerIP:  callerIP,
		Port:      port,
		ExpiresAt: expiresAt,
	}, nil
}

// RemoveEphemeralFirewallRule strips the rule. Idempotent: a nil
// rule, an empty ID, or an already-absent rule returns nil.
func (p *Provider) RemoveEphemeralFirewallRule(ctx context.Context, rule *provider.EphemeralFirewallRule) error {
	if rule == nil || rule.ID == "" {
		return nil
	}
	return p.c.FirewallRemoveEphemeralRule(ctx, rule.ID)
}
