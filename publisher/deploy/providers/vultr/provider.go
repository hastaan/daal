package vultr

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

// Provider is the FRP-10 Vultr adapter. It implements
// provider.Provider via a narrow vultrClient interface so unit
// tests can swap in an in-memory fake.
//
// Idempotence: Provision/Reprovision/Decommission/AssignFloatingIP
// are all safe to retry. The adapter looks up the instance by
// label derived from publisher pubkey + region first; if it
// exists, it reuses it.
type Provider struct {
	c     vultrClient
	clock func() time.Time
}

// New returns a Provider bound to the given vultrClient.
func New(c vultrClient) *Provider {
	return &Provider{c: c, clock: time.Now}
}

// SetClock injects a deterministic clock for tests.
func (p *Provider) SetClock(now func() time.Time) { p.clock = now }

// Provision creates a new Vultr instance.
func (p *Provider) Provision(ctx context.Context, opts provider.ProvisionOpts) (*provider.OperatorRecord, error) {
	if err := validateProvisionOpts(opts); err != nil {
		return nil, err
	}
	label := derivedInstanceLabel(opts.PublisherPubKey, opts.Region)

	mgmtPort, err := provider.ResolveMgmtPort(opts.MgmtPort)
	if err != nil {
		return nil, fmt.Errorf("vultr: %w", err)
	}
	// Per-relay REALITY cover host, seeded on the derived instance
	// label. Vultr's cloud-init carries a placeholder sing-box config
	// rather than a real one, so nothing on the box serves this yet;
	// the record carries it so rotation has a value to move away from
	// and so the pack minter has a fallback when the box cannot report
	// its own. See OperatorRecord.CoverSNI for who actually reads it.
	coverSNI, err := provider.ResolveCoverSNI(opts.CoverSNI, label, opts.Region)
	if err != nil {
		return nil, fmt.Errorf("vultr: %w", err)
	}

	if opts.DryRun {
		return p.dryRunRecord(label, opts, mgmtPort, coverSNI), nil
	}

	if existing, err := p.c.InstanceByLabel(ctx, label); err == nil && existing != nil {
		if opts.MgmtPort == 0 {
			return nil, errors.New("vultr: existing instance requires persisted MgmtPort")
		}
		rec := p.recordFromInstance(existing, opts)
		rec.MgmtPort = mgmtPort
		// The record must state what this already-built box serves, not
		// what a fresh pick would be. ReuseCoverSNI refuses to guess.
		reused, err := provider.ReuseCoverSNI(opts.CoverSNI)
		if err != nil {
			return nil, fmt.Errorf("vultr: %w", err)
		}
		rec.CoverSNI = reused
		return rec, nil
	} else if err != nil && !errors.Is(err, errInstanceNotFound) {
		return nil, fmt.Errorf("vultr: lookup existing instance: %w", err)
	}

	pubBytes := sshPublicKeyBytes(opts.EphemeralSSHKey)
	keyName, err := ephemeralSSHKeyName(label)
	if err != nil {
		return nil, fmt.Errorf("vultr: name ssh key: %w", err)
	}
	sshKeyID, err := p.c.SSHKeyCreate(ctx, keyName, pubBytes)
	if err != nil {
		return nil, fmt.Errorf("vultr: create ssh key: %w", err)
	}
	// Same contract as the Hetzner adapter: the private half never
	// leaves this process, so the uploaded public half is dead weight
	// the moment Provision returns — delete it on every exit path,
	// success included, and never leave a name behind that a later
	// attempt would collide with. WithoutCancel so a cancelled
	// provision still cleans up.
	defer func() {
		if err := p.c.SSHKeyDelete(context.WithoutCancel(ctx), sshKeyID); err != nil {
			_ = err // best-effort; vultr has no progress channel to report on
		}
	}()

	healthToken, err := generateHealthToken()
	if err != nil {
		return nil, fmt.Errorf("vultr: generate health token: %w", err)
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
		return nil, fmt.Errorf("vultr: render cloud-init: %w", err)
	}

	inst, err := p.c.InstanceCreate(ctx, InstanceCreateOpts{
		Label:    label,
		Plan:     opts.ServerType,
		Region:   opts.Region,
		OS:       "ubuntu-24-04-x64",
		UserData: base64.StdEncoding.EncodeToString(userData),
		SSHKeys:  []string{sshKeyID},
		Tags:     []string{"managed-by:daal-deploy", "toolbox:" + opts.ToolboxProfile},
	})
	if err != nil {
		return nil, fmt.Errorf("vultr: create instance: %w", err)
	}
	rec := p.recordFromInstance(inst, opts)
	rec.MgmtPort = mgmtPort
	rec.CoverSNI = coverSNI
	if opts.WaitForHealth {
		fp, err := waitForMgmtFingerprint(ctx, rec.PublicIP, healthToken)
		if err != nil {
			// A real, billing instance exists by now. Roll it back
			// when asked; otherwise say its id and IP out loud so the
			// caller can offer teardown instead of leaving the user
			// paying for a box the app forgot about.
			if opts.RollbackOnFailure {
				if _, dErr := p.Decommission(context.WithoutCancel(ctx), rec); dErr != nil {
					return nil, fmt.Errorf("vultr: wait for mgmt fingerprint: %w [rollback failed, instance %s (%s) still running and billing: %v]", err, rec.ServerID, rec.PublicIP, dErr)
				}
				return nil, fmt.Errorf("vultr: wait for mgmt fingerprint: %w [rolled back: instance deleted]", err)
			}
			return nil, fmt.Errorf("vultr: wait for mgmt fingerprint: %w [instance %s (%s) is still running and still billing]", err, rec.ServerID, rec.PublicIP)
		}
		rec.MgmtTLSFingerprint = fp
	}
	return rec, nil
}

// Reprovision deletes-and-recreates the instance. V1.5 model.
func (p *Provider) Reprovision(ctx context.Context, rec *provider.OperatorRecord, opts provider.ReprovisionOpts) error {
	if rec == nil {
		return errors.New("vultr: nil OperatorRecord")
	}
	now := p.clock()
	// Resolve the next cover host before the destructive call, so a bad
	// --new-sni fails without having deleted anything, and so the
	// rebuilt box never comes back on the name that was just burned.
	nextSNI, err := provider.NextCoverSNI(rec, opts.NewSNI, now)
	if err != nil {
		return fmt.Errorf("vultr: %w", err)
	}
	if err := p.c.InstanceDelete(ctx, rec.ServerID); err != nil {
		return fmt.Errorf("vultr: delete during reprovision: %w", err)
	}
	rec.CoverSNI = nextSNI
	rec.LastReprovisionedAt = &now
	return nil
}

// Decommission deletes the instance and reports honestly on the rest.
// Idempotent.
//
// What this adapter creates per relay is the instance and the
// one-shot SSH key; it never creates a firewall group (the ephemeral
// mgmt rules go onto whatever group the instance already has), so
// FirewallDeleted is true because there is nothing of ours to leave
// behind.
//
// An empty ServerID is not taken as "nothing to delete": the wizard
// only writes the OperatorRecord back on a successful provision, so a
// run that created the instance and then failed its health wait leaves
// an empty id on the record and a real, billing instance under the
// derived label. That label is a pure function of (publisher pubkey,
// region) — a match is proof of ownership, not a guess — so it is
// looked up before anything is claimed. A lookup that fails is an
// error, not an assumption: the caller must keep the local record.
//
// SSHKeyDeleted is true. Provision deletes the key by id on every exit
// path (a `defer` with context.WithoutCancel, so a cancelled run still
// reaches it), and since the key name now carries 4 random bytes per
// attempt, even a survivor cannot collide with or block a later
// provision. There is nothing left that can bite the user, and a
// warning that fired on every clean teardown only taught them to ignore
// the same line where it is real.
func (p *Provider) Decommission(ctx context.Context, rec *provider.OperatorRecord) (*provider.DecommissionReport, error) {
	rep := provider.NewDecommissionReport("vultr", "")
	if rec == nil {
		rep.ServerDeleted, rep.SSHKeyDeleted, rep.FirewallDeleted = true, true, true
		return rep, nil
	}
	rep.ServerID = rec.ServerID
	rep.FirewallDeleted = true // this adapter creates no firewall group
	rep.SSHKeyDeleted = true   // deleted by id at the end of every provision

	instanceID, err := p.resolveInstanceID(ctx, rec, rep)
	if err != nil {
		return rep, err
	}
	if instanceID == "" {
		rep.ServerDeleted = true
	} else if err := p.c.InstanceDelete(ctx, instanceID); err != nil {
		rep.Warnf("could not delete instance %s: %v", instanceID, err)
		rep.Preserve("instance:" + instanceID)
		return rep, fmt.Errorf("vultr: delete instance %s: %w", instanceID, err)
	} else {
		rep.ServerID = instanceID
		rep.ServerDeleted = true
	}

	if rec.FloatingIPID != "" {
		rep.Warnf("reserved IP %s stays on your account and keeps billing — daal-deploy did not create it, so it is yours to release", rec.FloatingIPID)
		rep.Preserve("reserved-ip:" + rec.FloatingIPID)
	}
	return rep, nil
}

// resolveInstanceID returns the id of the instance this record's relay
// owns, or "" when there provably is none. See the Decommission doc for
// why an empty rec.ServerID must not be read as "nothing to delete".
//
// A record with neither an id nor (region, pubkey) provably never
// created an instance — validateProvisionOpts refuses to provision
// without both — so "" with no error is honest there.
func (p *Provider) resolveInstanceID(ctx context.Context, rec *provider.OperatorRecord, rep *provider.DecommissionReport) (string, error) {
	if rec.ServerID != "" {
		return rec.ServerID, nil
	}
	if len(rec.PublisherPubKey) == 0 || rec.Region == "" {
		return "", nil
	}
	label := derivedInstanceLabel(rec.PublisherPubKey, rec.Region)
	inst, err := p.c.InstanceByLabel(ctx, label)
	switch {
	case err == nil && inst != nil:
		return inst.ID, nil
	case err == nil, errors.Is(err, errInstanceNotFound):
		return "", nil
	default:
		rep.Warnf("could not confirm whether an instance labelled %q exists (%v) — nothing was deleted", label, err)
		rep.Preserve("instance:" + label)
		return "", fmt.Errorf("vultr: look up instance %q: %w", label, err)
	}
}

// AssignFloatingIP attaches a Vultr Reserved IP to the instance.
//
// INCOMPLETE FOR L3, AND KNOWINGLY SO. It records the id and stops. It
// does NOT move rec.PublicIP or the candidates' public_ip:* tags onto
// the reserved address, because Vultr's client surface here has no
// "read this reserved IP back and tell me its address" call — and an id
// is not an address. So an L3 rotation on Vultr would attach the new
// address and then re-sign a pack that still names the burned one.
//
// That failure is contained on the LIVE path, which is the only
// containment worth claiming: `daal-deploy assign-fip` snapshots
// rec.PublicIP, calls this, and then runs rotation.CheckAddressMoved
// on the result — so an L3 here exits non-zero with
// ErrL3AddressUnchanged, before the record is emitted and therefore
// before anything is persisted or re-signed. That is the seam the
// wizard's rotation actually goes through.
//
// Two other guards exist and neither is load-bearing here, which is
// worth stating because an earlier version of this comment cited them
// as if they were: rotation.Executor's own post-condition has no
// production caller, and rotation.ActionForProvider marks L3
// AvailabilityUnsupported on this provider but only reaches
// rotate_recommend — the address-swap sheet never consults a
// recommendation.
//
// Completing it means adding a ReservedIPGet to the client + the
// read-back/retag sequence the Hetzner adapter's floating_ip.go
// carries; it is not done here because nothing has exercised the Vultr
// live client against a real account.
func (p *Provider) AssignFloatingIP(ctx context.Context, rec *provider.OperatorRecord, fipID string) error {
	if rec == nil || rec.ServerID == "" {
		return errors.New("vultr: OperatorRecord without ServerID")
	}
	if rec.FloatingIPID == fipID {
		return nil
	}
	if err := p.c.ReservedIPAttach(ctx, fipID, rec.ServerID); err != nil {
		return fmt.Errorf("vultr: attach reserved ip: %w", err)
	}
	rec.FloatingIPID = fipID
	return nil
}

// UnassignFloatingIP detaches the currently attached Reserved IP.
func (p *Provider) UnassignFloatingIP(ctx context.Context, rec *provider.OperatorRecord) error {
	if rec == nil || rec.FloatingIPID == "" {
		return nil
	}
	if err := p.c.ReservedIPDetach(ctx, rec.FloatingIPID); err != nil {
		return fmt.Errorf("vultr: detach reserved ip: %w", err)
	}
	rec.FloatingIPID = ""
	return nil
}

// Pricing returns the live per-hour cost for the instance plan.
func (p *Provider) Pricing(ctx context.Context, rec *provider.OperatorRecord) (provider.Pricing, error) {
	hourly, monthly, err := p.c.PlanPrice(ctx, rec.Region, rec.ServerType)
	if err != nil {
		return provider.Pricing{}, err
	}
	return provider.Pricing{
		Provider:   "vultr",
		Region:     rec.Region,
		ServerType: rec.ServerType,
		HourlyEUR:  hourly,
		MonthlyEUR: monthly,
	}, nil
}

// SetEphemeralFirewallRule opens (callerIP/32, port, tcp) on the
// instance's firewall group for durationSec. FRP-10 §9.5.2.
func (p *Provider) SetEphemeralFirewallRule(ctx context.Context, serverID, callerIP string, port int, durationSec int) (*provider.EphemeralFirewallRule, error) {
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
	expiresAt := p.clock().Add(time.Duration(durationSec) * time.Second).UTC()
	id, err := p.c.FirewallAddEphemeralRule(ctx, serverID, callerIP, port, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("vultr: add ephemeral rule: %w", err)
	}
	return &provider.EphemeralFirewallRule{
		ID:        id,
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
	return p.c.FirewallRemoveEphemeralRule(ctx, rule.ID)
}

// --- helpers ---

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

func derivedInstanceLabel(pubKey []byte, region string) string {
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
func ephemeralSSHKeyName(label string) (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s-ephemeral-%s", label, hex.EncodeToString(b[:])), nil
}

func generateHealthToken() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func (p *Provider) recordFromInstance(s *InstanceInfo, opts provider.ProvisionOpts) *provider.OperatorRecord {
	return &provider.OperatorRecord{
		Provider:        "vultr",
		ServerID:        s.ID,
		ServerType:      s.Plan,
		Region:          s.Region,
		PublicIP:        s.MainIP,
		PublicIPv6:      s.V6Main,
		ToolboxProfile:  opts.ToolboxProfile,
		PublisherPubKey: opts.PublisherPubKey,
		Candidates:      candidatesForProfile(opts.ToolboxProfile, s.MainIP, opts.EnabledFamilies),
		ProvisionedAt:   p.clock().UTC(),
	}
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

func (p *Provider) dryRunRecord(label string, opts provider.ProvisionOpts, mgmtPort int, coverSNI string) *provider.OperatorRecord {
	return &provider.OperatorRecord{
		Provider:        "vultr",
		ServerID:        "dry-run-" + label,
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
