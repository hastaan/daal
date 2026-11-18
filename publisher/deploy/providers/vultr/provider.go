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
	"strconv"
	"strings"
	"time"

	"daal/publisher/deploy/cloudinit"
	"daal/publisher/deploy/health"
	"daal/publisher/deploy/provider"
	"daal/publisher/deploy/relayconf"
	"daal/publisher/deploy/relayports"
)

// Provider is the Vultr adapter. It implements provider.Provider
// through the narrow vultrClient interface; production binds the REST
// client in live_client.go and the tests bind that same client to an
// httptest server.
type Provider struct {
	c     vultrClient
	clock func() time.Time
	// health is the seam Provision uses to wait for a freshly created
	// box to finish cloud-init. Production binds waitForHealthy; tests
	// inject a stub, because the real waiter dials a public IP for
	// minutes — and the interesting behaviour around it (what happens
	// to a half-built relay) only shows up when it FAILS.
	health healthWaiter
}

type healthWaiter func(ctx context.Context, rec *provider.OperatorRecord, healthToken string, opts provider.ProvisionOpts, progress func(step, message string)) error

// New returns a Provider bound to the given client. Production is
// New(NewLiveClient(token)).
func New(c vultrClient) *Provider {
	p := &Provider{c: c, clock: time.Now}
	p.health = p.waitForHealthy
	return p
}

// SetClock injects a deterministic clock for tests.
func (p *Provider) SetClock(now func() time.Time) { p.clock = now }

// setHealthWaiter swaps the cloud-init health poll. Test-only seam.
func (p *Provider) setHealthWaiter(h healthWaiter) { p.health = h }

// imageName is the distribution every Daal relay runs. The cloud-init,
// the sing-box unit, the ufw rules and the mgmt service are all written
// against it. It is resolved to Vultr's numeric os_id at provision time
// rather than hard-coded — see vultrClient.OSIDForImage.
const imageName = "Ubuntu 24.04 LTS x64"

// Provision creates a Vultr instance running a Daal relay and returns
// the OperatorRecord the binder signs against.
//
// ORDER MATTERS AND IS NOT THE HETZNER ORDER. The firewall group is
// created and ruled BEFORE the instance, and its id is passed into the
// create call, so the box is never reachable without it. The Hetzner
// adapter cannot do this — hcloud attaches a firewall to a server that
// already exists — and therefore has a window where a booting relay's
// random mgmt port is exposed to the internet. Vultr closes that
// window, so this adapter takes it.
//
// The price of that order is that a failure between "group created" and
// "instance created" leaves a resource behind. That is what
// provisionScope is for: every step registers its undo, and a failure
// either completes the undo or names precisely what survived and the
// command that removes it. See unwind.
//
// Idempotent: an instance already carrying this relay's derived label
// is adopted rather than duplicated — but only if it also carries this
// relay's ownership tags. Adopting an unmarked box would mean writing
// somebody else's server into the operator's record and, later,
// destroying it on teardown.
func (p *Provider) Provision(ctx context.Context, opts provider.ProvisionOpts) (*provider.OperatorRecord, error) {
	if err := validateProvisionOpts(opts); err != nil {
		return nil, err
	}
	if opts.ExistingServerID != "" {
		// Hetzner can re-image a box in place (ServerRebuild) and
		// keeps its IP and billing. Vultr's equivalent
		// (reinstall/os change) does not take fresh user-data, so
		// there is no way to install this relay's cloud-init on an
		// existing instance. Saying so is better than pretending:
		// a silent fresh create would leave the operator's original
		// box running and billing next to a new one.
		return nil, errors.New("vultr: --existing-server-id is not supported on Vultr; " +
			"Vultr cannot re-image an instance with new cloud-init user-data, so a Daal relay must be a fresh instance")
	}
	label := derivedInstanceLabel(opts.PublisherPubKey, opts.Region)

	mgmtPort, err := provider.ResolveMgmtPort(opts.MgmtPort)
	if err != nil {
		return nil, fmt.Errorf("vultr: %w", err)
	}
	coverSNI, err := provider.ResolveCoverSNI(opts.CoverSNI, label, opts.Region)
	if err != nil {
		return nil, fmt.Errorf("vultr: %w", err)
	}

	// Resolve the family set BEFORE anything is created. One
	// resolution feeds all three things that must agree about it: the
	// sing-box inbounds in cloud-init, the box-side ufw rules baked
	// alongside them, and the cloud firewall group below. An
	// unresolvable profile must fail here, while failing is free —
	// after the instance exists it costs a billed box.
	served, err := relayconf.ServedFamilies(opts.ToolboxProfile, opts.EnabledFamilies)
	if err != nil {
		return nil, fmt.Errorf("vultr: resolve served families: %w", err)
	}
	dataPlanePorts := relayports.ExtraFirewallPortsFor(served)

	if opts.DryRun {
		return p.dryRunRecord(label, opts, mgmtPort, coverSNI)
	}

	progress := opts.OnProgress
	if progress == nil {
		progress = func(string, string) {}
	}

	// Idempotency + ownership.
	existing, err := p.c.InstanceByLabel(ctx, label)
	switch {
	case err == nil && existing != nil:
		if !ownsInstance(existing, label) {
			return nil, fmt.Errorf("vultr: an instance labelled %q already exists (id %s) but does not carry this relay's tags (%s, %s%s); "+
				"refusing to adopt or overwrite a machine daal-deploy did not create",
				label, existing.ID, tagManagedBy, tagRelayPrefix, label)
		}
		if opts.MgmtPort == 0 {
			return nil, errors.New("vultr: existing instance requires persisted MgmtPort")
		}
		rec, err := p.recordFromInstance(existing, opts)
		if err != nil {
			return nil, err
		}
		rec.MgmtPort = mgmtPort
		// This box already exists; its sing-box config was written at
		// its own provision time and we are not rewriting it. The
		// record must state what it ACTUALLY serves — which this code
		// cannot know and must not invent. See ReuseCoverSNI.
		reused, err := provider.ReuseCoverSNI(opts.CoverSNI)
		if err != nil {
			return nil, fmt.Errorf("vultr: %w", err)
		}
		rec.CoverSNI = reused
		return rec, nil
	case errors.Is(err, errInstanceNotFound):
		// the normal path
	case err != nil:
		return nil, fmt.Errorf("vultr: lookup existing instance: %w", err)
	}

	// EVERYTHING THAT CAN FAIL LOCALLY FAILS FIRST. The cloud-init
	// render, the OS lookup and the token generation all happen before
	// a single billable or account-visible resource exists, so the
	// commonest provisioning errors — a bad publisher key, an
	// unresolvable image — cost nothing and leave nothing to clean up.
	pubBytes := sshPublicKeyBytes(opts.EphemeralSSHKey)
	healthToken, err := generateHealthToken()
	if err != nil {
		return nil, fmt.Errorf("vultr: generate health token: %w", err)
	}
	progress("provision_cloud_init", "Rendering server configuration")
	userData, err := cloudinit.RenderV2(cloudinit.RenderInputV2{
		RenderInput: cloudinit.RenderInput{
			EphemeralSSHPublicKey: string(pubBytes),
			ProvisioningClientIP:  opts.HelperIP.String(),
			HealthToken:           healthToken,
			SingBoxConfigJSON:     relayconf.SingBoxConfigForFamilies(coverSNI, served),
			DataPlanePorts:        dataPlanePorts,
		},
		MgmtPubKeyHex: hex.EncodeToString(opts.PublisherPubKey),
		MgmtPort:      mgmtPort,
		CoverSNI:      coverSNI,
	})
	if err != nil {
		return nil, fmt.Errorf("vultr: render cloud-init: %w", err)
	}
	osID, err := p.c.OSIDForImage(ctx, imageName)
	if err != nil {
		return nil, fmt.Errorf("vultr: resolve os id: %w", err)
	}

	scope := &provisionScope{p: p, relay: label, region: opts.Region}

	progress("provision_ssh_key", "Creating SSH key")
	keyName, err := ephemeralSSHKeyName(label)
	if err != nil {
		return nil, fmt.Errorf("vultr: name ssh key: %w", err)
	}
	sshKeyID, err := p.c.SSHKeyCreate(ctx, keyName, pubBytes)
	if err != nil {
		return nil, fmt.Errorf("vultr: create ssh key: %w", err)
	}
	// Delete the cloud-side key on EVERY exit path, success included.
	// The private half is generated per invocation and never leaves
	// this process, so the uploaded public half is dead weight the
	// moment Provision returns — and an orphaned key is the exact
	// thing that has already wedged this user's account once.
	// WithoutCancel: a cancelled provision is the case that must not
	// leak.
	defer func() {
		if err := p.c.SSHKeyDelete(context.WithoutCancel(ctx), sshKeyID); err != nil {
			progress("provision_ssh_key", fmt.Sprintf(
				"could not remove one-shot SSH key %q (id %s): %v — remove it with: %s",
				keyName, sshKeyID, err, removeCommand("ssh-keys", sshKeyID)))
		}
	}()

	// The firewall FIRST, so the instance is born behind it.
	progress("provision_cloud_firewall", "Creating the relay firewall ("+portsForDisplay(dataPlanePorts)+")")
	fwGroupID, createdFW, err := p.ensureFirewallGroup(ctx, label, dataPlanePorts)
	if err != nil {
		return nil, fmt.Errorf("vultr: firewall group: %w", err)
	}
	if createdFW {
		scope.firewallGroupID = fwGroupID
	}

	progress("provision_create_server", "Creating instance on Vultr")
	inst, err := p.c.InstanceCreate(ctx, InstanceCreateOpts{
		Label:           label,
		Hostname:        label,
		Plan:            opts.ServerType,
		Region:          opts.Region,
		OSID:            osID,
		UserData:        base64.StdEncoding.EncodeToString(userData),
		SSHKeys:         []string{sshKeyID},
		Tags:            ownershipTags(label, opts.ToolboxProfile),
		FirewallGroupID: fwGroupID,
		EnableIPv6:      true,
	})
	if err != nil {
		return nil, scope.unwind(ctx, opts, progress, fmt.Errorf("vultr: create instance: %w", err))
	}
	scope.instanceID = inst.ID
	if inst.MainIP != nil {
		scope.instanceIP = inst.MainIP.String()
	}

	// ---- past this line a real, billing instance exists ----
	rec, err := p.recordFromInstance(inst, opts)
	if err != nil {
		return nil, scope.unwind(ctx, opts, progress, err)
	}
	rec.MgmtPort = mgmtPort
	rec.CoverSNI = coverSNI

	// Vultr can return an instance before its address is allocated.
	// A record with no address is a record that cannot be dialed and
	// must not be signed, so wait for one rather than emitting a
	// half-formed record.
	if rec.PublicIP == nil {
		settled, err := p.waitForAddress(ctx, inst.ID, progress)
		if err != nil {
			return nil, scope.unwind(ctx, opts, progress, err)
		}
		if settled.MainIP != nil {
			scope.instanceIP = settled.MainIP.String()
		}
		rec, err = p.recordFromInstance(settled, opts)
		if err != nil {
			return nil, scope.unwind(ctx, opts, progress, err)
		}
		rec.MgmtPort = mgmtPort
		rec.CoverSNI = coverSNI
	}
	progress("provision_server_ready", fmt.Sprintf("Instance ready: %s — waiting for boot (up to 5 min)", rec.PublicIP))

	if opts.WaitForHealth {
		wait := p.health
		if wait == nil {
			wait = p.waitForHealthy
		}
		if err := wait(ctx, rec, healthToken, opts, progress); err != nil {
			return nil, scope.unwind(ctx, opts, progress, err)
		}
	}
	progress("provision_healthy", "Instance is up and healthy")
	return rec, nil
}

// waitForAddress polls until the instance reports a public IPv4.
func (p *Provider) waitForAddress(ctx context.Context, instanceID string, progress func(step, message string)) (*InstanceInfo, error) {
	const attempts = 30
	for i := 0; i < attempts; i++ {
		inst, err := p.c.InstanceByID(ctx, instanceID)
		if err != nil && !errors.Is(err, errInstanceNotFound) {
			return nil, fmt.Errorf("vultr: read instance %s while waiting for its address: %w", instanceID, err)
		}
		if inst != nil && inst.MainIP != nil {
			return inst, nil
		}
		if i == 0 {
			progress("provision_create_server", "Waiting for Vultr to allocate the instance's address")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(4 * time.Second):
		}
	}
	return nil, fmt.Errorf("vultr: instance %s never reported a public IPv4 address", instanceID)
}

// waitForHealthy opens a temporary hole for the Helper's own IP, polls
// the bootstrap health endpoint for the mgmt-TLS fingerprint, and fills
// it into the record.
//
// NO SSH LOG TAIL, unlike the Hetzner adapter, and the difference is
// worth stating rather than hiding: Hetzner's provisioner streams
// cloud-init output over the one-shot SSH key so a failing boot is
// legible. That path is not wired here, so a Vultr relay that fails to
// boot reports a timeout and no cloud-init log. The relay itself is
// unaffected — the record's Tier-2 material (reality pubkey, TLS SPKI
// pin) is read from the box's own /users/provision response at pack
// time, not from these files — but diagnosis is thinner. It is a gap,
// not a design.
func (p *Provider) waitForHealthy(ctx context.Context, rec *provider.OperatorRecord, healthToken string, opts provider.ProvisionOpts, progress func(step, message string)) error {
	rule, err := p.SetEphemeralFirewallRule(ctx, rec.ServerID, opts.HelperIP.String(), healthPort, int((10 * time.Minute).Seconds()))
	if err != nil {
		return fmt.Errorf("vultr: open temporary health firewall: %w", err)
	}
	defer func() {
		if err := p.RemoveEphemeralFirewallRule(context.WithoutCancel(ctx), rule); err != nil {
			progress("provision_cloud_firewall", fmt.Sprintf(
				"could not close the temporary health window (%v) — it expires on its own at %s",
				err, rule.ExpiresAt.Format(time.RFC3339)))
		}
	}()
	progress("provision_cloud_firewall", "Opened temporary cloud firewall window for server health")

	fp, err := health.WaitForMgmtFingerprint(ctx, rec.PublicIP, healthToken, 60, 5*time.Second)
	if err != nil {
		return err
	}
	rec.MgmtTLSFingerprint = fp
	return nil
}

// healthPort is the bootstrap health endpoint cloud-init serves during
// provisioning. Same port on every provider; the box-side ufw rule
// binds it to the Helper's IP and cloud-init tears it down afterwards.
const healthPort = 9876

// Reprovision destroys the instance so the caller can re-create it. The
// V1.5 model: Reprovision + Provision, composed by the caller.
//
// It deliberately does NOT delete the firewall group: the next
// Provision finds it by description and reuses it, so the rebuilt box
// is behind its firewall from the first instant, and a reprovision that
// half-failed does not leave the operator's next attempt naked.
//
// A reserved IP attached to the destroyed instance survives, detached
// and still billing, and the record keeps its floating_ip_id. That is
// the same shape the Hetzner path documents: the operator's route back
// is to run the address assign again after the new box exists.
func (p *Provider) Reprovision(ctx context.Context, rec *provider.OperatorRecord, opts provider.ReprovisionOpts) error {
	if rec == nil {
		return errors.New("vultr: nil OperatorRecord")
	}
	now := p.clock()
	// Move the cover host BEFORE the destructive call, so a bad
	// --new-sni fails without having deleted anything and the rebuilt
	// box never comes back on the name that was just burned.
	nextSNI, err := provider.NextCoverSNI(rec, opts.NewSNI, now)
	if err != nil {
		return fmt.Errorf("vultr: %w", err)
	}
	if err := refuseEmptyProfileIntersection("vultr", rec, opts); err != nil {
		return err
	}
	if err := p.c.InstanceDelete(ctx, rec.ServerID); err != nil {
		return fmt.Errorf("vultr: delete during reprovision: %w", err)
	}
	rec.CoverSNI = nextSNI
	rec.LastReprovisionedAt = &now
	return nil
}

// Decommission destroys everything provisioning created for this
// record: the instance, its firewall group, and any one-shot SSH keys
// that survived. Idempotent — an already-absent resource is success.
//
// # How resources are identified
//
// Neither the firewall group id nor the SSH key id is on the record, so
// teardown re-derives the names provisioning minted from material that
// IS on the record:
//
//	instance        label       "daal-<region>-<hex8>"
//	firewall group  description "managed-by=daal-deploy daal-relay=<label> ..."
//	ssh key         name        "<label>-ephemeral-<rand>"
//
// All three are pure functions of this operator's own publisher key, so
// a match is proof of ownership rather than a guess — and the instance
// and the firewall group must ALSO carry the ownership marks. Nothing
// is ever deleted on a loose "daal-" prefix.
//
// # What it refuses to delete
//
//   - an instance that does not carry both ownership tags;
//   - a firewall group still protecting another instance;
//   - a reserved IP this adapter did not create (see ReleaseFloatingIP).
//
// Each refusal is reported, never silent.
//
// # Failure semantics
//
// Best-effort per resource, with one exception: the instance. If the
// billing box survives, its firewall must survive too — stripping a
// live relay's firewall exposes its mgmt port — so a failed instance
// delete stops teardown and returns an error. The caller must then keep
// the local record: it is the only remaining route back to that box.
func (p *Provider) Decommission(ctx context.Context, rec *provider.OperatorRecord) (*provider.DecommissionReport, error) {
	rep := provider.NewDecommissionReport("vultr", "")
	if rec == nil {
		rep.ServerDeleted, rep.SSHKeyDeleted, rep.FirewallDeleted = true, true, true
		return rep, nil
	}
	rep.ServerID = rec.ServerID
	relay := ""
	if len(rec.PublisherPubKey) > 0 && rec.Region != "" {
		relay = derivedInstanceLabel(rec.PublisherPubKey, rec.Region)
	}

	// 1. The instance — the thing that costs money. First, and fatal.
	inst, err := p.resolveInstance(ctx, rec, relay, rep)
	if err != nil {
		return rep, err
	}
	switch {
	case inst == nil:
		// Genuinely nothing there: either the provision died before
		// the create returned, or the box is already gone. Keep going:
		// the firewall group and an orphaned key may still exist, and
		// the orphaned key is the exact thing that blocks a retry.
		rep.ServerDeleted = true
	case relay != "" && !ownsInstance(inst, relay):
		rep.Warnf("instance %s carries the label %q but not this relay's ownership tags (%s, %s%s) — refusing to delete a machine daal-deploy did not create",
			inst.ID, inst.Label, tagManagedBy, tagRelayPrefix, relay)
		rep.Preserve("instance:" + inst.ID)
		return rep, fmt.Errorf("vultr: instance %s is not tagged as this relay's; nothing was deleted", inst.ID)
	default:
		if err := p.c.InstanceDelete(ctx, inst.ID); err != nil {
			rep.Warnf("could not delete instance %s: %v — remove it with: %s", inst.ID, err, removeCommand("instances", inst.ID))
			rep.Preserve("instance:" + inst.ID)
			return rep, fmt.Errorf("vultr: delete instance %s: %w", inst.ID, err)
		}
		rep.ServerID = inst.ID
		rep.ServerDeleted = true
	}

	// 2. The firewall group. Only ours, only when it protects nothing
	// else.
	p.decommissionFirewall(ctx, relay, rep)

	// 3. The one-shot SSH keys. A survivor is what blocks the next
	// provision, so sweep by the derived prefix.
	p.sweepEphemeralKeys(ctx, relay, rep)

	// 4. The reserved IP, if the record still names one.
	if rec.FloatingIPID != "" {
		// Release against a record that KNOWS which instance it owned.
		// A record whose id was never persisted has just had it
		// resolved by label above, and ReleaseFloatingIP's first guard
		// compares the address's attachment against rec.ServerID — with
		// an empty id that guard reads "attached to somebody else" and
		// refuses to release the operator's own address. A shallow copy
		// so the caller's record is not mutated by a teardown.
		relRec := *rec
		if relRec.ServerID == "" {
			relRec.ServerID = rep.ServerID
		}
		deleted, err := p.ReleaseFloatingIP(ctx, &relRec, rec.FloatingIPID)
		switch {
		case err != nil:
			rep.Warnf("reserved IP %s could not be released (%v) — it is still reserved and still billing; remove it with: %s. %s",
				rec.FloatingIPID, err, removeCommand("reserved-ips", rec.FloatingIPID), auditPointer)
			rep.Preserve("reserved-ip:" + rec.FloatingIPID)
		case !deleted:
			rep.Warnf("reserved IP %s stays on your account and keeps billing — daal-deploy did not create it, so it is yours to release",
				rec.FloatingIPID)
			rep.Preserve("reserved-ip:" + rec.FloatingIPID)
		}
	}
	return rep, nil
}

// resolveInstance returns the instance this record's relay owns, or nil
// when there provably is none.
//
// An empty rec.ServerID is NOT proof that no instance exists: the
// wizard only writes the OperatorRecord back on a SUCCESSFUL provision,
// so the commonest way to arrive here — a provision that created the
// box and then failed its health wait — persists an empty id while a
// real, billing instance carries the derived label. Claiming
// ServerDeleted on that record would tell the user the billing had
// stopped and then erase the only handle on the box.
func (p *Provider) resolveInstance(ctx context.Context, rec *provider.OperatorRecord, relay string, rep *provider.DecommissionReport) (*InstanceInfo, error) {
	if rec.ServerID != "" {
		inst, err := p.c.InstanceByID(ctx, rec.ServerID)
		switch {
		case err == nil:
			return inst, nil
		case errors.Is(err, errInstanceNotFound):
			return nil, nil
		default:
			rep.Warnf("could not read instance %s (%v) — nothing was deleted", rec.ServerID, err)
			rep.Preserve("instance:" + rec.ServerID)
			return nil, fmt.Errorf("vultr: read instance %s: %w", rec.ServerID, err)
		}
	}
	if relay == "" {
		// No id and nothing to derive a label from: this record
		// provably never created an instance, because
		// validateProvisionOpts refuses to provision without both.
		return nil, nil
	}
	inst, err := p.c.InstanceByLabel(ctx, relay)
	switch {
	case err == nil:
		return inst, nil
	case errors.Is(err, errInstanceNotFound):
		return nil, nil
	default:
		rep.Warnf("could not confirm whether an instance labelled %q exists (%v) — nothing was deleted", relay, err)
		rep.Preserve("instance:" + relay)
		return nil, fmt.Errorf("vultr: look up instance %q: %w", relay, err)
	}
}

// decommissionFirewall deletes this relay's firewall group when it is
// ours and protects nothing else.
func (p *Provider) decommissionFirewall(ctx context.Context, relay string, rep *provider.DecommissionReport) {
	if relay == "" {
		rep.FirewallDeleted = true // nothing derivable, nothing of ours
		return
	}
	desc := firewallGroupDescription(relay)
	g, err := p.c.FirewallGroupByDescription(ctx, desc)
	if err != nil {
		rep.Warnf("could not list firewall groups (%v) — this relay's group may still exist", err)
		rep.Preserve("firewall-group:" + desc)
		return
	}
	if g == nil {
		rep.FirewallDeleted = true
		return
	}
	rep.FirewallID = g.ID
	if !markedFor(g.Description, relay) {
		rep.Warnf("firewall group %s does not carry this relay's ownership mark — left in place", g.ID)
		rep.Preserve("firewall-group:" + g.ID)
		return
	}
	if g.InstanceCount > 0 {
		// Vultr's counter is updated asynchronously after an instance
		// delete, so this is usually "our own box, moments ago". It is
		// still not a reason to force it: a group another relay sits
		// behind is that relay's only protection for a random mgmt
		// port.
		rep.Warnf("firewall group %s still protects %d instance(s) — left in place; remove it later with: %s",
			g.ID, g.InstanceCount, removeCommand("firewalls", g.ID))
		rep.Preserve("firewall-group:" + g.ID)
		return
	}
	if err := p.c.FirewallGroupDelete(ctx, g.ID); err != nil {
		rep.Warnf("could not delete firewall group %s: %v — remove it with: %s", g.ID, err, removeCommand("firewalls", g.ID))
		rep.Preserve("firewall-group:" + g.ID)
		return
	}
	rep.FirewallDeleted = true
}

// sweepEphemeralKeys deletes the one-shot provisioning keys this relay
// minted. Their ids are not persisted anywhere, so the derived name
// prefix is the only handle — and it is a function of the operator's
// own publisher key, so it cannot reach another operator's key.
func (p *Provider) sweepEphemeralKeys(ctx context.Context, relay string, rep *provider.DecommissionReport) {
	if relay == "" {
		rep.SSHKeyDeleted = true
		return
	}
	keys, err := p.c.SSHKeyList(ctx)
	if err != nil {
		rep.Warnf("could not list SSH keys (%v) — a one-shot provisioning key named %q may still be on the account; it will block the next provision until removed. %s",
			err, ephemeralKeyPrefix(relay)+"*", auditPointer)
		rep.Preserve("ssh-key:" + ephemeralKeyPrefix(relay) + "*")
		return
	}
	ok := true
	for _, k := range keys {
		if !ownsEphemeralKey(k, relay) {
			continue
		}
		if err := p.c.SSHKeyDelete(ctx, k.ID); err != nil {
			ok = false
			rep.Warnf("could not delete one-shot SSH key %q (id %s): %v — remove it with: %s",
				k.Name, k.ID, err, removeCommand("ssh-keys", k.ID))
			rep.Preserve("ssh-key:" + k.ID)
			continue
		}
		rep.DeletedSSHKeyIDs = append(rep.DeletedSSHKeyIDs, k.ID)
	}
	rep.SSHKeyDeleted = ok
}

// Pricing returns the instance plan's price.
//
// Currency is stamped "USD" because Vultr bills in USD and the field
// names on provider.Pricing say EUR. Renaming the wire contract would
// break the Rust shim; leaving the currency unsaid would draw a dollar
// figure behind a euro sign on the operator's cost-disclosure screen,
// which is the same class of lie as a rotation dial that quotes 90
// seconds for a three-minute rebuild.
func (p *Provider) Pricing(ctx context.Context, rec *provider.OperatorRecord) (provider.Pricing, error) {
	if rec == nil {
		return provider.Pricing{}, errors.New("vultr: nil OperatorRecord")
	}
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
		Currency:   "USD",
	}, nil
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

// ephemeralSSHKeyName names one attempt's one-shot key. The random
// suffix mirrors the Hetzner adapter: a name derived only from
// (publisher pubkey, region) repeats on every attempt, so a single
// orphan blocks every retry on a provider that enforces name
// uniqueness.
func ephemeralSSHKeyName(label string) (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return ephemeralKeyPrefix(label) + hex.EncodeToString(b[:]), nil
}

func generateHealthToken() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func (p *Provider) recordFromInstance(s *InstanceInfo, opts provider.ProvisionOpts) (*provider.OperatorRecord, error) {
	cands, err := relayconf.CandidatesForProfile(opts.ToolboxProfile, s.MainIP, opts.EnabledFamilies)
	if err != nil {
		return nil, fmt.Errorf("vultr: %w", err)
	}
	return &provider.OperatorRecord{
		Provider:        "vultr",
		ServerID:        s.ID,
		ServerType:      s.Plan,
		Region:          s.Region,
		PublicIP:        s.MainIP,
		PublicIPv6:      s.V6Main,
		ToolboxProfile:  opts.ToolboxProfile,
		PublisherPubKey: opts.PublisherPubKey,
		Candidates:      cands,
		ProvisionedAt:   p.clock().UTC(),
	}, nil
}

func (p *Provider) dryRunRecord(label string, opts provider.ProvisionOpts, mgmtPort int, coverSNI string) (*provider.OperatorRecord, error) {
	cands, err := relayconf.CandidatesForProfile(opts.ToolboxProfile, opts.HelperIP, opts.EnabledFamilies)
	if err != nil {
		return nil, fmt.Errorf("vultr: %w", err)
	}
	return &provider.OperatorRecord{
		Provider:        "vultr",
		ServerID:        "dry-run-" + label,
		ServerType:      opts.ServerType,
		Region:          opts.Region,
		PublicIP:        opts.HelperIP,
		ToolboxProfile:  opts.ToolboxProfile,
		PublisherPubKey: opts.PublisherPubKey,
		Candidates:      cands,
		ProvisionedAt:   p.clock().UTC(),
		MgmtPort:        mgmtPort,
		CoverSNI:        coverSNI,
	}, nil
}

func sshPublicKeyBytes(priv ed25519.PrivateKey) []byte {
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok || len(pub) == 0 {
		return []byte("ssh-ed25519 INVALID daal-deploy")
	}
	var buf []byte
	buf = appendString(buf, []byte("ssh-ed25519"))
	buf = appendString(buf, []byte(pub))
	return []byte("ssh-ed25519 " + base64.StdEncoding.EncodeToString(buf) + " daal-deploy")
}

func appendString(buf, s []byte) []byte {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(s)))
	buf = append(buf, l[:]...)
	return append(buf, s...)
}

// monthlyToHourly converts a published monthly price using Vultr's
// standard 730-hour month.
func monthlyToHourly(monthly float64) float64 {
	if monthly <= 0 {
		return 0
	}
	return monthly / 730.0
}

// auditPointer is the one sentence every "something survived and it is
// still costing you" message ends with — the same constant, and for the
// same reason, as the one in providers/hetzner.
//
// It matters MORE here. Vultr is the account an L5 rebuilds ONTO, which
// means it is the account where the OperatorRecord was never written:
// L5's record write happens after `provision` returns, so a failure
// leaves resources on a cloud Daal has no record of at all. Every
// message below can name only the resource the code happened to be
// holding when it failed; this names the verb that enumerates the whole
// account without needing a record — the only thing that can find what
// the failing code never saw.
const auditPointer = "To see exactly what is left on your cloud account " +
	"— and what can safely be removed — run `daal-deploy account-audit --provider vultr --token-file <token>`; " +
	"it needs no record and never deletes anything. In the app this is the " +
	"\"See what is left on my account\" button on the relay's danger zone."

// removeCommand renders the exact call that removes one leftover
// resource. It is printed verbatim into warnings and errors, because
// "something was left behind" without the command to remove it is how
// an operator ends up paying for a box they cannot find.
func removeCommand(kind, id string) string {
	return fmt.Sprintf(`curl -s -X DELETE -H "Authorization: Bearer $VULTR_API_KEY" %s/%s/%s`,
		DefaultEndpoint, kind, id)
}

// portsForDisplay renders a rule set for a progress message.
func portsForDisplay(eps []relayports.Endpoint) string {
	if len(eps) == 0 {
		return "443/tcp, 443/udp, 80/tcp"
	}
	parts := []string{"443/tcp", "443/udp", "80/tcp"}
	for _, ep := range eps {
		proto := "tcp"
		if ep.UDP {
			proto = "udp"
		}
		parts = append(parts, strconv.Itoa(ep.Port)+"/"+proto)
	}
	return strings.Join(parts, ", ")
}

var _ = net.IP(nil)

// familiesFromRecord is the family set a rebuild will be fed, derived
// from the record the way the wizard derives it (rotation_families in
// commands.rs): the record's own candidate list, deduplicated.
//
// A provisioned record has no enabled-families field — `provision`
// overwrites the stored record wholesale with the Go OperatorRecord,
// which does not carry one — so the candidates ARE the family set.
func familiesFromRecord(rec *provider.OperatorRecord) []string {
	if rec == nil {
		return nil
	}
	seen := make(map[string]bool, len(rec.Candidates))
	out := make([]string, 0, len(rec.Candidates))
	for _, c := range rec.Candidates {
		if c.Family == "" || seen[c.Family] {
			continue
		}
		seen[c.Family] = true
		out = append(out, c.Family)
	}
	return out
}

// refuseEmptyProfileIntersection is the pre-delete half of the check
// `provision` already performs after the delete.
//
// A toolbox profile and a family set INTERSECT — relayconf
// .CandidatesForProfile keeps a profile candidate only when the
// supplied family list also names it — so a profile change can only
// ever shrink the set, and it can shrink it to nothing. A relay serving
// only UDP-gated families (hysteria2, tuic) moved onto a TCP-only
// profile has an empty intersection. `provision` refuses that with
// "yields no candidates", which is the right refusal at the wrong end
// of the sequence: Reprovision has already deleted the server, and
// deliberately does not re-create, so the operator is left with no
// relay over a combination that was knowable before anything was
// touched.
//
// Costs a map lookup and no API call. Same reasoning as resolving the
// cover host before the destructive call.
func refuseEmptyProfileIntersection(providerName string, rec *provider.OperatorRecord, opts provider.ReprovisionOpts) error {
	if opts.NewToolboxProfile == "" {
		return nil
	}
	if _, err := relayconf.ServedFamilies(opts.NewToolboxProfile, familiesFromRecord(rec)); err != nil {
		return fmt.Errorf("%s: refusing to rebuild onto toolbox profile %q: %w — the server has NOT been "+
			"deleted; going ahead would have destroyed it and then failed to build a relay with no routes at all",
			providerName, opts.NewToolboxProfile, err)
	}
	return nil
}
