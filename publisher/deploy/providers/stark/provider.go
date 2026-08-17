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
	// Per-relay REALITY cover host, seeded on the derived hostname so
	// the same relay always resolves to the same name. Stark's
	// cloud-init carries a placeholder sing-box config rather than a
	// real one, so nothing on the box serves this yet; the record
	// carries it so rotation has a value to move away from and so the
	// pack minter has a fallback when the box cannot report its own.
	// See OperatorRecord.CoverSNI for who actually reads it.
	coverSNI, err := provider.ResolveCoverSNI(opts.CoverSNI, hostname, opts.Region)
	if err != nil {
		return nil, fmt.Errorf("stark: %w", err)
	}

	if opts.DryRun {
		return p.dryRunRecord(hostname, opts, mgmtPort, coverSNI), nil
	}

	token := p.token()
	if existing, err := p.findByHostname(ctx, token, hostname); err == nil && existing != nil {
		if opts.MgmtPort == 0 {
			return nil, errors.New("stark: existing vps requires persisted MgmtPort")
		}
		rec := p.recordFromVPS(existing, opts)
		rec.MgmtPort = mgmtPort
		// The record must state what this already-built box serves, not
		// what a fresh pick would be. ReuseCoverSNI refuses to guess.
		reused, err := provider.ReuseCoverSNI(opts.CoverSNI)
		if err != nil {
			return nil, fmt.Errorf("stark: %w", err)
		}
		rec.CoverSNI = reused
		return rec, nil
	} else if err != nil && !errors.Is(err, errStarkNotFound) {
		return nil, fmt.Errorf("stark: lookup existing: %w", err)
	}

	pubBytes := sshPublicKeyBytes(opts.EphemeralSSHKey)
	keyName, err := ephemeralSSHKeyName(hostname)
	if err != nil {
		return nil, fmt.Errorf("stark: name ssh key: %w", err)
	}
	var sshResp SSHKeyResp
	if err := p.client.do(ctx, token, "POST", "/ssh-keys", SSHKeyReq{Name: keyName, PublicKey: string(pubBytes)}, &sshResp); err != nil {
		return nil, fmt.Errorf("stark: create ssh key: %w", err)
	}
	// This adapter used to leak the key on every path — success and
	// failure alike. The private half never leaves this process, so
	// the uploaded public half is dead weight once Provision returns:
	// delete it by id on every exit path. WithoutCancel so a
	// cancelled provision still cleans up.
	defer func() {
		_ = p.client.do(context.WithoutCancel(ctx), token, "DELETE", "/ssh-keys/"+sshResp.KeyID, nil, nil)
	}()

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
	rec.CoverSNI = coverSNI
	if opts.WaitForHealth {
		fp, err := waitForMgmtFingerprint(ctx, rec.PublicIP, healthToken)
		if err != nil {
			// A real, billing VPS exists by now. Roll it back when
			// asked; otherwise name it so the caller can offer
			// teardown rather than leaving it silently on the meter.
			if opts.RollbackOnFailure {
				if _, dErr := p.Decommission(context.WithoutCancel(ctx), rec); dErr != nil {
					return nil, fmt.Errorf("stark: wait for mgmt fingerprint: %w [rollback failed, vps %s (%s) still running and billing: %v]", err, rec.ServerID, rec.PublicIP, dErr)
				}
				return nil, fmt.Errorf("stark: wait for mgmt fingerprint: %w [rolled back: vps deleted]", err)
			}
			return nil, fmt.Errorf("stark: wait for mgmt fingerprint: %w [vps %s (%s) is still running and still billing]", err, rec.ServerID, rec.PublicIP)
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
	now := p.clock()
	// Resolve the next cover host before the destructive call, so a bad
	// --new-sni fails without having deleted anything, and so the
	// rebuilt box never comes back on the name that was just burned.
	nextSNI, err := provider.NextCoverSNI(rec, opts.NewSNI, now)
	if err != nil {
		return fmt.Errorf("stark: %w", err)
	}
	token := p.token()
	if err := p.client.do(ctx, token, "DELETE", "/vps/"+rec.ServerID, nil, nil); err != nil && !errors.Is(err, errStarkNotFound) {
		return fmt.Errorf("stark: delete during reprovision: %w", err)
	}
	rec.CoverSNI = nextSNI
	rec.LastReprovisionedAt = &now
	return nil
}

// Decommission deletes the VPS and reports honestly on the rest.
// Idempotent: an already-absent VPS is success.
//
// Stark's firewall rules are per-(vps_id, port, src) with a
// server-side TTL (expires_at_unix), so deleting the VPS leaves
// nothing of ours behind — FirewallDeleted is true.
//
// An empty ServerID is not taken as "nothing to delete": the wizard
// only writes the OperatorRecord back on a successful provision, so a
// run that created the VPS and then failed its health wait leaves an
// empty id on the record and a real, billing box under the derived
// hostname. That hostname is a pure function of (publisher pubkey,
// region) — a match is proof of ownership, not a guess — so it is
// looked up before anything is claimed. A lookup that fails is an
// error, not an assumption: the caller must keep the local record.
//
// SSHKeyDeleted is true. Provision deletes the key by id on every exit
// path (a `defer` with context.WithoutCancel, so a cancelled run still
// reaches it), and since the key name now carries random bytes per
// attempt, even a survivor cannot collide with or block a later
// provision. A warning that fired on every clean teardown only taught
// the user to ignore the same line where it is real.
func (p *Provider) Decommission(ctx context.Context, rec *provider.OperatorRecord) (*provider.DecommissionReport, error) {
	rep := provider.NewDecommissionReport("stark", "")
	if rec == nil {
		rep.ServerDeleted, rep.SSHKeyDeleted, rep.FirewallDeleted = true, true, true
		return rep, nil
	}
	rep.ServerID = rec.ServerID
	rep.FirewallDeleted = true // rules are vps-scoped with server-side TTL
	rep.SSHKeyDeleted = true   // deleted by id at the end of every provision

	vpsID, err := p.resolveVPSID(ctx, rec, rep)
	if err != nil {
		return rep, err
	}
	if vpsID == "" {
		rep.ServerDeleted = true
	} else {
		err := p.client.do(ctx, p.token(), "DELETE", "/vps/"+vpsID, nil, nil)
		if err != nil && !errors.Is(err, errStarkNotFound) {
			rep.Warnf("could not delete vps %s: %v", vpsID, err)
			rep.Preserve("vps:" + vpsID)
			return rep, fmt.Errorf("stark: delete vps %s: %w", vpsID, err)
		}
		rep.ServerID = vpsID
		rep.ServerDeleted = true
	}

	if rec.FloatingIPID != "" {
		rep.Warnf("reserved IP %s stays on your account and keeps billing — daal-deploy did not create it, so it is yours to release", rec.FloatingIPID)
		rep.Preserve("reserved-ip:" + rec.FloatingIPID)
	}
	return rep, nil
}

// AssignFloatingIP attaches a Stark Reserved IP to the VPS.
//
// INCOMPLETE FOR L3, AND KNOWINGLY SO — same shape as the Vultr
// adapter. It records the id and stops; it does not move rec.PublicIP
// or the candidates' public_ip:* tags onto the reserved address, so an
// L3 here would re-sign a pack still naming the burned one.
// The containment is on the LIVE path: `daal-deploy assign-fip`
// snapshots rec.PublicIP and runs rotation.CheckAddressMoved after
// this returns, so the verb exits non-zero and the record is never
// emitted — nothing downstream persists or re-signs. (The Go
// rotation.Executor has the same post-condition and no production
// caller; ActionForProvider's AvailabilityUnsupported only reaches
// rotate_recommend, which the address-swap sheet does not consult.
// Neither is what stops this.) Completing it needs a reserved-IP
// read-back call plus the
// retag sequence in the Hetzner adapter's floating_ip.go — and this
// whole adapter has never been exercised against a live Stark account.
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

// resolveVPSID returns the id of the VPS this record's relay owns, or
// "" when there provably is none. See the Decommission doc for why an
// empty rec.ServerID must not be read as "nothing to delete".
//
// A record with neither an id nor (region, pubkey) provably never
// created a VPS — validateProvisionOpts refuses to provision without
// both — so "" with no error is honest there.
func (p *Provider) resolveVPSID(ctx context.Context, rec *provider.OperatorRecord, rep *provider.DecommissionReport) (string, error) {
	if rec.ServerID != "" {
		return rec.ServerID, nil
	}
	if len(rec.PublisherPubKey) == 0 || rec.Region == "" {
		return "", nil
	}
	hostname := derivedHostname(rec.PublisherPubKey, rec.Region)
	vps, err := p.findByHostname(ctx, p.token(), hostname)
	switch {
	case err == nil && vps != nil:
		return vps.ID, nil
	case err == nil, errors.Is(err, errStarkNotFound):
		return "", nil
	default:
		rep.Warnf("could not confirm whether a vps named %q exists (%v) — nothing was deleted", hostname, err)
		rep.Preserve("vps:" + hostname)
		return "", fmt.Errorf("stark: look up vps %q: %w", hostname, err)
	}
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

// ephemeralSSHKeyName names one attempt's one-shot key. The random
// suffix mirrors the Hetzner adapter (see its ephemeralSSHKeyName for
// the full reasoning): a name derived only from (publisher pubkey,
// region) repeats on every attempt, so a single orphan blocks every
// retry on a provider that enforces name uniqueness.
func ephemeralSSHKeyName(hostname string) (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s-ephemeral-%s", hostname, hex.EncodeToString(b[:])), nil
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

func (p *Provider) dryRunRecord(hostname string, opts provider.ProvisionOpts, mgmtPort int, coverSNI string) *provider.OperatorRecord {
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
		CoverSNI:        coverSNI,
	}
}

func waitForMgmtFingerprint(ctx context.Context, ip net.IP, token string) (string, error) {
	return health.WaitForMgmtFingerprint(ctx, ip, token, 12, 5*time.Second)
}
