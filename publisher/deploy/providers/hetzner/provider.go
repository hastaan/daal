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
	"strings"
	"time"

	"daal/publisher/deploy/cloudinit"
	"daal/publisher/deploy/health"
	"daal/publisher/deploy/provider"
	"daal/publisher/deploy/relayports"
	"golang.org/x/crypto/ssh"
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
	health      healthWaiter
}

// healthWaiter is the seam Provision uses to wait for a freshly
// created box to finish cloud-init. Production binds
// Provider.waitForHealthy; tests inject a stub, because the real
// waiter dials SSH and HTTP against a public IP for up to five
// minutes — and the interesting behaviour around it (rollback of a
// half-built relay) only happens when it fails.
type healthWaiter func(ctx context.Context, rec *provider.OperatorRecord, srv *ServerInfo, healthToken string, opts provider.ProvisionOpts, progress func(step, message string)) error

// New returns a Provider bound to the given hcloudClient. The
// production path is `New(NewLiveClient(token))`; tests pass a fake
// client.
func New(c hcloudClient) *Provider {
	p := &Provider{c: c, clock: time.Now}
	p.health = p.waitForHealthy
	return p
}

// SetClock injects a deterministic clock for tests.
func (p *Provider) SetClock(now func() time.Time) { p.clock = now }

// setHealthWaiter swaps the cloud-init health poll. Test-only seam;
// see healthWaiter.
func (p *Provider) setHealthWaiter(h healthWaiter) { p.health = h }

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
	// The cover host this relay will advertise. Seeded on the derived
	// server name — a pure function of (publisher key, region) — so the
	// same relay resolves to the same host on every run, while two
	// relays land on different ones. opts.CoverSNI, when the caller
	// persisted it, wins outright.
	coverSNI, err := provider.ResolveCoverSNI(opts.CoverSNI, name, opts.Region)
	if err != nil {
		return nil, fmt.Errorf("hetzner: %w", err)
	}

	if opts.DryRun {
		return p.dryRunRecord(name, opts, mgmtPort, coverSNI)
	}

	// Idempotency: if server already exists with this derived name,
	// return the existing OperatorRecord. The caller must pass the
	// persisted MgmtPort on retries; otherwise we would return a fresh
	// random port that does not match the already-provisioned box.
	if existing, err := p.c.ServerByName(ctx, name); err == nil && existing != nil {
		if opts.MgmtPort == 0 {
			return nil, errors.New("hetzner: existing server requires persisted MgmtPort")
		}
		rec, err := p.recordFromServer(existing, opts)
		if err != nil {
			return nil, err
		}
		rec.MgmtPort = mgmtPort
		// This box already exists; its sing-box config was written at
		// its own provision time and we are not rewriting it here. So
		// the record must state what it ACTUALLY serves — which this
		// code cannot know and must not invent (see ReuseCoverSNI).
		// NOT the fresh host resolved above: that would be a claim
		// about a config that was never installed.
		reused, err := provider.ReuseCoverSNI(opts.CoverSNI)
		if err != nil {
			return nil, fmt.Errorf("hetzner: %w", err)
		}
		rec.CoverSNI = reused
		return rec, nil
	} else if err != nil && !errors.Is(err, errServerNotFound) {
		return nil, fmt.Errorf("hetzner: lookup existing server: %w", err)
	}

	progress := opts.OnProgress
	if progress == nil {
		progress = func(string, string) {}
	}

	// Render cloud-init (needed for both create and rebuild paths).
	progress("provision_ssh_key", "Creating SSH key")
	pubBytes := sshPublicKeyBytes(opts.EphemeralSSHKey)
	keyName, err := ephemeralSSHKeyName(name)
	if err != nil {
		return nil, fmt.Errorf("hetzner: name ssh key: %w", err)
	}
	sshKeyID, err := p.c.SSHKeyCreate(ctx, keyName, pubBytes, map[string]string{
		labelManagedBy: labelManagedByValue,
		labelRelay:     name,
	})
	if err != nil {
		return nil, fmt.Errorf("hetzner: create ssh key: %w", err)
	}
	// Delete the cloud-side key resource on EVERY exit path, success
	// included. The private half of this keypair is generated per
	// invocation and never leaves this process's memory (supplement
	// §9.5.1), so once Provision returns, the uploaded public half is
	// dead weight in every case. Leaving it behind is what used to
	// wedge accounts: the old name was a pure function of (publisher
	// key, region), so one survivor made every future attempt fail
	// with "SSH key not unique" forever.
	//
	// Removing the SSHKey resource does not revoke access to a
	// running box — Hetzner materialises authorized_keys at
	// create/rebuild time — so this is safe even on the success path.
	//
	// context.WithoutCancel: cleanup must still run when the caller
	// cancelled the provision. A cancelled provision is exactly the
	// case that must not leak.
	defer func() {
		if err := p.c.SSHKeyDelete(context.WithoutCancel(ctx), sshKeyID); err != nil {
			progress("provision_ssh_key", fmt.Sprintf(
				"could not remove one-shot SSH key %q (id %s): %v — delete it in your provider console",
				keyName, sshKeyID, err))
		}
	}()

	healthToken, err := generateHealthToken()
	if err != nil {
		return nil, fmt.Errorf("hetzner: generate health token: %w", err)
	}

	progress("provision_cloud_init", "Rendering server configuration")
	// One resolution of "which families does this relay serve", used
	// for all three things that have to agree about it: the sing-box
	// inbounds baked into cloud-init, the box-side ufw rules baked
	// alongside them, and the cloud-provider firewall attached below.
	// Resolving it three times from three places is how a relay ends up
	// listening on a port its firewall drops.
	//
	// An unresolvable profile is an error here, not a silent baseline:
	// it is the same failure candidatesForProfile was taught to refuse,
	// and refusing before the server exists costs nothing, while
	// refusing after it does costs a billed box.
	served, err := servedFamilies(opts.ToolboxProfile, opts.EnabledFamilies)
	if err != nil {
		return nil, fmt.Errorf("hetzner: resolve served families: %w", err)
	}
	dataPlanePorts := relayports.ExtraFirewallPortsFor(served)
	userData, err := cloudinit.RenderV2(cloudinit.RenderInputV2{
		RenderInput: cloudinit.RenderInput{
			EphemeralSSHPublicKey: string(pubBytes),
			ProvisioningClientIP:  opts.HelperIP.String(),
			HealthToken:           healthToken,
			SingBoxConfigJSON:     singBoxConfigForFamilies(coverSNI, served),
			DataPlanePorts:        dataPlanePorts,
		},
		MgmtPubKeyHex: hex.EncodeToString(opts.PublisherPubKey),
		MgmtPort:      mgmtPort,
		CoverSNI:      coverSNI,
	})
	if err != nil {
		return nil, fmt.Errorf("hetzner: render cloud-init: %w", err)
	}

	var srv *ServerInfo
	if opts.ExistingServerID != "" {
		// Rebuild path: re-image the existing server with daal's
		// cloud-init. Keeps the same IP and billing.
		progress("provision_rebuild_server", "Rebuilding existing server with daal configuration")
		srv, err = p.c.ServerRebuild(ctx, opts.ExistingServerID, "ubuntu-24.04", string(userData))
		if err != nil {
			return nil, fmt.Errorf("hetzner: rebuild server: %w", err)
		}
	} else {
		// Create path: spin up a fresh VPS.
		progress("provision_create_server", "Creating server on Hetzner")
		srv, err = p.c.ServerCreate(ctx, ServerCreateOpts{
			Name:       name,
			ServerType: opts.ServerType,
			Region:     opts.Region,
			Image:      "ubuntu-24.04",
			UserData:   string(userData),
			SSHKeyIDs:  []string{sshKeyID},
			Labels: map[string]string{
				labelManagedBy: labelManagedByValue,
				labelRelay:     name,
				"toolbox":      opts.ToolboxProfile,
			},
		})
		if err != nil {
			return nil, fmt.Errorf("hetzner: create server: %w", err)
		}
	}
	rec, err := p.recordFromServer(srv, opts)
	if err != nil {
		return nil, err
	}
	rec.MgmtPort = mgmtPort
	// The record is the only durable copy of what got written into
	// /etc/sing-box/config.json above. The pack minter prefers what the
	// box itself reports on /users/provision, and falls back to this
	// when the box's mgmt binary is too old to report anything — see
	// OperatorRecord.CoverSNI.
	rec.CoverSNI = coverSNI
	if opts.ExistingServerID != "" {
		progress("provision_server_ready", fmt.Sprintf("Server rebuilt: %s — waiting for cloud-init (up to 5 min)", rec.PublicIP))
	} else {
		progress("provision_server_ready", fmt.Sprintf("Server ready: %s — waiting for boot (up to 3 min)", rec.PublicIP))
	}

	// FRP-14: ensure a per-server Hetzner Cloud Firewall is
	// attached, with the daal baseline ruleset that locks the
	// random mgmt port and the helper-only debug ports while
	// leaving 443 open for the world. Without this, every L1/L2
	// mgmt call (incl. /users/provision used by the recipient
	// roster) fails with "no attached firewall" because
	// FirewallAddEphemeralRule has nothing to mutate.
	progress("provision_cloud_firewall", "Attaching Daal baseline firewall to server")
	if _, err := p.c.FirewallEnsureForServer(ctx, rec.ServerID, dataPlanePorts); err != nil {
		// Don't tear the whole provision down; the box-side ufw
		// still provides surface-area minimisation for the
		// non-mgmt ports. We just won't be able to talk to the
		// mgmt plane until a firewall is attached out-of-band.
		// Log via the progress channel and continue.
		progress("provision_cloud_firewall", fmt.Sprintf("firewall ensure failed: %v", err))
	}

	// ---- past this line a real, billing server exists ----
	//
	// Every failure from here on must either roll the server back or
	// name it out loud. Silently returning an error used to leave the
	// user paying for a box nothing in the app knew about; see
	// afterServerFailure.
	if opts.WaitForHealth {
		wait := p.health
		if wait == nil { // Provider built without New(); fall back to the real poll
			wait = p.waitForHealthy
		}
		if err := wait(ctx, rec, srv, healthToken, opts, progress); err != nil {
			return nil, p.afterServerFailure(ctx, opts, progress, rec, err)
		}
	}
	progress("provision_healthy", "Server is up and healthy")
	return rec, nil
}

// waitForHealthy blocks until the box finishes cloud-init and
// publishes a usable mgmt-TLS fingerprint, streaming cloud-init
// output through progress as it goes. It fills rec.MgmtTLSFingerprint
// (and the FRP-14 Tier-2 connection material) in place.
//
// It is the production binding of Provider.health; on failure the
// caller decides what happens to the server that is already running.
func (p *Provider) waitForHealthy(ctx context.Context, rec *provider.OperatorRecord, srv *ServerInfo, healthToken string, opts provider.ProvisionOpts, progress func(step, message string)) error {
	// If the server has a Hetzner Cloud Firewall attached, the
	// box-side UFW rule is not enough; open the provisioning
	// health endpoint from this helper IP while cloud-init runs.
	// Servers without an attached firewall don't need this.
	var healthRuleID string
	if id, err := p.c.FirewallAddEphemeralRule(ctx, rec.ServerID, opts.HelperIP.String(), 9876, p.clock().Add(10*time.Minute)); err == nil {
		healthRuleID = id
		defer func() { _ = p.c.FirewallRemoveEphemeralRule(context.WithoutCancel(ctx), healthRuleID) }()
		progress("provision_cloud_firewall", "Opened temporary cloud firewall window for server health")
	} else if !strings.Contains(err.Error(), "no attached firewall") {
		return fmt.Errorf("hetzner: open temporary health firewall: %w", err)
	}
	var sshRuleID string
	if id, err := p.c.FirewallAddEphemeralRule(ctx, rec.ServerID, opts.HelperIP.String(), 22, p.clock().Add(10*time.Minute)); err == nil {
		sshRuleID = id
		defer func() { _ = p.c.FirewallRemoveEphemeralRule(context.WithoutCancel(ctx), sshRuleID) }()
		progress("provision_cloud_firewall", "Opened temporary cloud firewall window for SSH log streaming")
	} else if !strings.Contains(err.Error(), "no attached firewall") {
		return fmt.Errorf("hetzner: open temporary ssh firewall: %w", err)
	}

	// Poll with progress updates so the UI shows server-side
	// cloud-init output when the temporary debug endpoint is up,
	// without spamming repeated connection errors.
	var sshSigner ssh.Signer
	if signer, err := ssh.NewSignerFromKey(opts.EphemeralSSHKey); err == nil {
		sshSigner = signer
	} else {
		progress("provision_ssh_debug", fmt.Sprintf("SSH observer key unavailable: %v", err))
	}
	poller := &health.Poller{BoxIP: rec.PublicIP, Token: healthToken}
	maxAttempts := 60
	interval := 5 * time.Second
	var fp string
	var healthErr error
	var lastDebugLog string
	var lastSSHDebug string
	// Labelled so `break poll` leaves the loop. The bare `break`
	// this replaced only left the select, so a cancelled context
	// still burned the full 5-minute timeout before returning —
	// which made "cancel provisioning" look hung and kept the
	// half-built server billing for the whole window.
poll:
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if sshSigner != nil || srv.RootPassword != "" {
			if logTail, err := sshCloudInitTail(rec.PublicIP.String(), sshSigner, srv.RootPassword); err == nil && logTail != "" && logTail != lastDebugLog {
				lastDebugLog = logTail
				progress("provision_cloud_init", logTail)
			} else if err != nil {
				var fatal *provisionFatalError
				if errors.As(err, &fatal) {
					if fatal.Log != "" && fatal.Log != lastDebugLog {
						lastDebugLog = fatal.Log
						progress("provision_cloud_init_fatal", fatal.Log)
					}
					return fmt.Errorf("hetzner: server provisioning failed: %s", fatal.Summary())
				}
				if attempt == 1 || attempt%6 == 0 {
					msg := fmt.Sprintf("SSH observer waiting: %v", err)
					if len(msg) > 500 {
						msg = msg[:500]
					}
					if msg != lastSSHDebug {
						lastSSHDebug = msg
						progress("provision_ssh_debug", msg)
					}
				}
			}
		}
		st, err := poller.PollOnce(ctx)
		if err == nil && st != nil && st.Healthy {
			candidate := strings.ToLower(strings.TrimSpace(st.MgmtTLSFingerprint))
			raw, decErr := hex.DecodeString(candidate)
			if decErr == nil && len(raw) == 32 {
				fp = candidate
				break poll
			}
			if st.DebugLog != "" && st.DebugLog != lastDebugLog {
				lastDebugLog = st.DebugLog
				progress("provision_cloud_init", st.DebugLog)
			}
		} else {
			if st != nil && st.DebugLog != "" && st.DebugLog != lastDebugLog {
				lastDebugLog = st.DebugLog
				progress("provision_cloud_init", st.DebugLog)
			}
		}
		if attempt == maxAttempts {
			healthErr = fmt.Errorf("hetzner: health check timed out after %d attempts", maxAttempts)
			break poll
		}
		select {
		case <-ctx.Done():
			healthErr = ctx.Err()
			break poll
		case <-time.After(interval):
		}
	}
	if healthErr != nil {
		return healthErr
	}
	rec.MgmtTLSFingerprint = fp

	// FRP-14 Tier-2: read the box's client-connection material over
	// the same ephemeral SSH session while it is still open. The box
	// writes reality.pub at cloud-init (independent of the released
	// daal-relay-mgmt binary), so this works without a new release.
	// Best-effort: a pre-Tier-2 box simply leaves the fields empty.
	if sshSigner != nil || srv.RootPassword != "" {
		if pub, err := sshReadFile(rec.PublicIP.String(), sshSigner, srv.RootPassword, "/etc/daal/reality.pub"); err == nil {
			rec.RealityPublicKey = strings.TrimSpace(pub)
		}
		if pin, err := sshReadFile(rec.PublicIP.String(), sshSigner, srv.RootPassword,
			"/etc/daal/tls-spki-sha256.b64"); err == nil {
			rec.TLSCertSHA256 = strings.TrimSpace(pin)
		}
	}
	return nil
}

// afterServerFailure decides what happens to the cloud resources a
// half-finished provision left behind, and returns the error
// Provision should surface.
//
// Two honest outcomes, never a third silent one:
//
//   - RollbackOnFailure: destroy what we created (server, per-server
//     firewall; the one-shot SSH key is handled by Provision's
//     defer) so the meter stops. The rollback's own outcome is
//     folded into the error text — a failed rollback is worse news
//     than the original failure, not less.
//   - default: leave the box alone (a slow boot is recoverable, and
//     the idempotent retry path reuses it) but emit a
//     "provision_orphan" progress event and repeat the server id +
//     IP inside the error, so the caller can show the user exactly
//     what is running and offer to remove it.
func (p *Provider) afterServerFailure(ctx context.Context, opts provider.ProvisionOpts, progress func(step, message string), rec *provider.OperatorRecord, cause error) error {
	where := fmt.Sprintf("server_id=%s ip=%s region=%s", rec.ServerID, rec.PublicIP, rec.Region)
	if opts.ExistingServerID != "" {
		// Rebuild path. This server is the caller's own machine, which
		// we were asked to re-image, not one we created — rollback
		// would destroy a box we do not own. Report, never delete.
		progress("provision_orphan", fmt.Sprintf(
			"Provisioning failed on your existing server %s. It is untouched by daal beyond the re-image and is still running.", where))
		return fmt.Errorf("%w [your existing server is still running: %s]", cause, where)
	}
	if !opts.RollbackOnFailure {
		progress("provision_orphan", fmt.Sprintf(
			"Provisioning failed but the server is still running and still billing: %s. "+
				"Remove the relay from Daal (delete the server) or destroy it in your provider console.", where))
		return fmt.Errorf("%w [the server is still running and still billing: %s]", cause, where)
	}
	progress("provision_rollback", fmt.Sprintf("Provisioning failed — removing the server that was just created (%s)", where))
	// WithoutCancel: a cancelled provision is precisely the case
	// whose cleanup must still reach the cloud API.
	rep, err := p.Decommission(context.WithoutCancel(ctx), rec)
	if err != nil {
		progress("provision_orphan", fmt.Sprintf(
			"Rollback failed — the server is still running and still billing: %s (%v)", where, err))
		return fmt.Errorf("%w [rollback failed, the server is still running and still billing: %s: %v]", cause, where, err)
	}
	if len(rep.Warnings) > 0 {
		progress("provision_rollback", "Rolled back with warnings: "+strings.Join(rep.Warnings, "; "))
		return fmt.Errorf("%w [rolled back with warnings: %s]", cause, strings.Join(rep.Warnings, "; "))
	}
	progress("provision_rollback", "Rolled back: the server has been deleted, nothing is billing")
	return fmt.Errorf("%w [rolled back: server deleted, nothing is billing]", cause)
}

// Reprovision deletes-and-recreates the box. At V1.5 this is the
// only L1/L2/L4/L5/L6 path per supplement section 9.5.1.
func (p *Provider) Reprovision(ctx context.Context, rec *provider.OperatorRecord, opts provider.ReprovisionOpts) error {
	if rec == nil {
		return errors.New("nil OperatorRecord")
	}
	now := p.clock()
	// Move the cover host BEFORE the destructive call. The rebuilt box
	// is a different bet than the one being torn down, so it must not
	// come back advertising the name that was just burned; and a record
	// that still names a deleted box's SNI would have the binder mint a
	// pack for a relay that no longer exists. Resolve first so a bad
	// --new-sni fails without having deleted anything.
	nextSNI, err := provider.NextCoverSNI(rec, opts.NewSNI, now)
	if err != nil {
		return fmt.Errorf("hetzner: %w", err)
	}
	if err := p.c.ServerDelete(ctx, rec.ServerID); err != nil {
		return fmt.Errorf("hetzner: delete during reprovision: %w", err)
	}
	rec.CoverSNI = nextSNI
	rec.LastReprovisionedAt = &now
	// The caller is expected to invoke Provision next with the new
	// opts. We don't re-create here because Reprovision deliberately
	// does not own the new ProvisionOpts (those flow from the
	// wizard). Callers compose Reprovision + Provision.
	return nil
}

// Decommission destroys everything provisioning created for this
// record: the VPS, its per-server baseline firewall, and the
// one-shot SSH key(s). Idempotent — an already-absent resource is
// success, not an error.
//
// # How the resources are identified
//
// Neither the firewall ID nor the SSH key ID is persisted:
// provider.OperatorRecord has no field for either (the firewall ID
// is discarded at the FirewallEnsureForServer call site, and the
// key ID only ever lived in a local variable). So teardown re-derives
// exactly the names provisioning minted, from material that IS on the
// record:
//
//	firewall  "daal-relay-<server_id>"      <- rec.ServerID
//	ssh key   "daal-<region>-<hex8>-ephemeral[-<rand>]"
//	                                        <- rec.Region + rec.PublisherPubKey
//
// Both names are pure functions of this operator's own material, so a
// name match is proof of ownership — not a guess. Current builds also
// carry the managed-by/daal-relay label pair, and for those the label
// must match too (see ownsEphemeralKey). Nothing is ever deleted on a
// loose "daal-" prefix: that would let one operator's teardown eat
// another operator's key.
//
// # What it refuses to delete
//
//   - a firewall another server is still attached to (SharedWith),
//   - the SSH key of a relay whose server is still alive,
//   - a floating IP: the operator owns it, daal-deploy never made it.
//
// Each refusal is reported, never silent.
//
// # Failure semantics
//
// Best-effort per resource: a failed key delete does not stop the
// firewall delete and vice versa; both land in the report as a false
// boolean plus a warning. The one fatal case is the server itself —
// if the billing box survives, its firewall and key must survive too
// (stripping a live relay's firewall would expose its mgmt port), so
// we stop and return an error. The caller must then keep the local
// record: it is the only remaining route back to that server.
func (p *Provider) Decommission(ctx context.Context, rec *provider.OperatorRecord) (*provider.DecommissionReport, error) {
	rep := provider.NewDecommissionReport("hetzner", "")
	if rec == nil {
		// Nothing to identify and nothing to delete: vacuously clean.
		rep.ServerDeleted, rep.SSHKeyDeleted, rep.FirewallDeleted = true, true, true
		return rep, nil
	}
	rep.ServerID = rec.ServerID

	// 0. Resolve the server. A record with no ServerID is NOT proof
	// that no server exists: the wizard only writes the OperatorRecord
	// back on a *successful* provision, so the single most common way
	// to arrive here — a provision that created the box and then failed
	// its health wait — persists `"server_id":""` while a real, billing
	// VPS carries the derived name. Claiming ServerDeleted on that
	// record told the user "the server is gone and the billing has
	// stopped" and then erased the token and the row, which were the
	// only remaining handle on it. So: no ServerID means look it up by
	// the name provisioning would have minted, exactly as
	// sweepEphemeralKeys already does for the key.
	serverID, err := p.resolveServerID(ctx, rec, rep)
	if err != nil {
		return rep, err
	}

	// 1. The VPS — the thing that costs money. First, and fatal.
	if serverID == "" {
		// Genuinely nothing there: either the provision died before
		// ServerCreate returned, or the box is already gone. No server
		// means no firewall either (its name is derived from the server
		// id), but there may well be an orphaned SSH key — the exact
		// state that used to block every retry — so keep going.
		rep.ServerDeleted = true
		rep.FirewallDeleted = true
	} else {
		rep.ServerID = serverID
		if err := p.c.ServerDelete(ctx, serverID); err != nil {
			rep.Warnf("could not delete server %s: %v", serverID, err)
			rep.Preserve("server:" + serverID)
			return rep, fmt.Errorf("hetzner: delete server %s: %w", serverID, err)
		}
		rep.ServerDeleted = true

		// 2. The per-server baseline firewall.
		res, err := p.c.FirewallDeleteForServer(ctx, serverID)
		switch {
		case err != nil:
			rep.Warnf("could not delete firewall %q: %v — delete it in your provider console", firewallNameForServer(serverID), err)
			rep.Preserve("firewall:" + firewallNameForServer(serverID))
		case len(res.SharedWith) > 0:
			rep.FirewallID = res.FirewallID
			rep.Warnf("firewall %q is still attached to server(s) %s and was left in place",
				firewallNameForServer(serverID), strings.Join(res.SharedWith, ", "))
			rep.Preserve("firewall:" + res.FirewallID)
		default:
			// Deleted, or never existed. Either way nothing of ours
			// is left behind.
			rep.FirewallDeleted = true
			rep.FirewallID = res.FirewallID
		}
	}

	// 3. The one-shot SSH key(s).
	p.sweepEphemeralKeys(ctx, rec, rep)

	// 4. The floating IP, if any.
	//
	// Teardown does NOT delete it, and the reason changed with Step 9,
	// so the message has to as well. It used to say "daal-deploy did
	// not create it", which was true when no floating-IP creation
	// existed anywhere in the repo; now an L3 rotation can mint one, so
	// the report must distinguish an address the operator reserved from
	// one this tool did.
	//
	// Neither is deleted here on purpose. An address is the one
	// resource whose whole value is that it OUTLIVES the server: the
	// operator tears a relay down and stands the next one up on the
	// same address, which is the cheapest continuity they have. Binning
	// it as part of a teardown would silently spend that. `daal-deploy
	// floating-ip release` is the deliberate act; this is the honest
	// notice that something is still on the meter.
	if rec.FloatingIPID != "" {
		ours := false
		if fip, err := p.c.FloatingIPByID(ctx, rec.FloatingIPID); err == nil {
			ours = ownsFloatingIP(fip, rec)
		}
		if ours {
			// --skip-unbind is named here and only here: this notice is
			// printed by a DECOMMISSION, i.e. the server it was
			// attached to has just been destroyed. `release` otherwise
			// insists on telling the relay to drop the address first,
			// and a destroyed box cannot answer — the operator would
			// hit an unexplained refusal on the one path where skipping
			// is exactly right.
			rep.Warnf("floating IP %s stays reserved on your account and keeps billing — daal-deploy reserved it, so run "+
				"`daal-deploy floating-ip release --fip-id %s --skip-unbind` (the relay it was on is gone, so there is nothing "+
				"left to tell it to drop the address) to stop paying for it, or keep it for the next relay",
				rec.FloatingIPID, rec.FloatingIPID)
		} else {
			rep.Warnf("floating IP %s stays reserved on your account and keeps billing — daal-deploy did not create it, so it is yours to release", rec.FloatingIPID)
		}
		rep.Preserve("floating-ip:" + rec.FloatingIPID)
	}
	return rep, nil
}

// resolveServerID returns the id of the server this record's relay
// owns, or "" when there provably is none.
//
// rec.ServerID wins when it is set. When it is empty the name
// provisioning derives — a pure function of (publisher pubkey, region),
// so a match is proof of ownership rather than a guess, same argument
// as ownsEphemeralKey — is looked up instead. This is the orphan case:
// a provision that created the box and then failed never gets its
// OperatorRecord written back, so the id is lost while the VPS keeps
// billing under that name.
//
// The error return is the important half. If the lookup itself fails we
// have not proved anything, and reporting "deleted" would be a lie about
// a billing resource that the caller would act on by erasing the local
// row and the cloud token. That case returns an error with ServerDeleted
// still false: teardown stops, the local record survives, the user can
// retry.
//
// A record with neither a server id nor (region, pubkey) is the one
// remaining "provably none" case: validateProvisionOpts refuses to
// provision without both, so no server can ever have been created for
// it. "" with no error is honest there.
func (p *Provider) resolveServerID(ctx context.Context, rec *provider.OperatorRecord, rep *provider.DecommissionReport) (string, error) {
	if rec.ServerID != "" {
		return rec.ServerID, nil
	}
	if len(rec.PublisherPubKey) == 0 || rec.Region == "" {
		return "", nil
	}
	relay := derivedServerName(rec.PublisherPubKey, rec.Region)
	srv, err := p.c.ServerByName(ctx, relay)
	switch {
	case err == nil && srv != nil:
		return srv.ID, nil
	case err == nil, errors.Is(err, errServerNotFound):
		// Proved absent. Nothing to delete, nothing to lie about.
		return "", nil
	default:
		rep.Warnf("could not confirm whether a server named %q exists (%v) — nothing was deleted", relay, err)
		rep.Preserve("server:" + relay)
		return "", fmt.Errorf("hetzner: look up server %q: %w", relay, err)
	}
}

// sweepEphemeralKeys deletes the one-shot provisioning SSH key(s)
// belonging to rec's relay, recording the outcome on rep. Separated
// out because it is the leg with the ownership + liveness proofs.
func (p *Provider) sweepEphemeralKeys(ctx context.Context, rec *provider.OperatorRecord, rep *provider.DecommissionReport) {
	if len(rec.PublisherPubKey) == 0 || rec.Region == "" {
		rep.Warnf("record carries no region/publisher_pub_key, so the one-shot SSH key cannot be identified — look for a key named \"daal-<region>-<id>-ephemeral*\" in your provider console")
		return
	}
	relay := derivedServerName(rec.PublisherPubKey, rec.Region)

	// Liveness proof. The key name and label are functions of
	// (publisher pubkey, region), i.e. of exactly one derived server
	// name. If a server still carries that name, that relay is alive
	// and its provisioning key is not ours to remove — this is the
	// "shared resource must be preserved" case for keys.
	if srv, err := p.c.ServerByName(ctx, relay); err == nil && srv != nil {
		rep.Warnf("server %s (%q) is still running, so its one-shot SSH key was left in place", srv.ID, relay)
		rep.Preserve("ssh-key:" + relay + "-ephemeral*")
		return
	} else if err != nil && !errors.Is(err, errServerNotFound) {
		rep.Warnf("could not confirm server %q is gone (%v), so its one-shot SSH key was left in place", relay, err)
		rep.Preserve("ssh-key:" + relay + "-ephemeral*")
		return
	}

	keys, err := p.c.SSHKeyList(ctx)
	if err != nil {
		rep.Warnf("could not list SSH keys (%v) — a key named %q may still be on the account; it will block the next provision until removed", err, relay+"-ephemeral")
		rep.Preserve("ssh-key:" + relay + "-ephemeral*")
		return
	}
	failed := 0
	for _, k := range keys {
		if !ownsEphemeralKey(k, relay) {
			continue
		}
		if err := p.c.SSHKeyDelete(ctx, k.ID); err != nil {
			rep.Warnf("could not delete SSH key %q (id %s): %v — it will block the next provision until removed", k.Name, k.ID, err)
			rep.Preserve("ssh-key:" + k.Name)
			failed++
			continue
		}
		rep.DeletedSSHKeyIDs = append(rep.DeletedSSHKeyIDs, k.ID)
	}
	// True means "no one-shot key of ours is left behind", which
	// includes the common case of there being none to start with.
	rep.SSHKeyDeleted = failed == 0
}

// ownsEphemeralKey reports whether k is a one-shot provisioning key
// this adapter created for the relay named relay (itself
// "daal-<region>-<hex8 of publisher pubkey>"). Two shapes are
// accepted, both anchored on that derived name:
//
//	pre-fix builds   name == "<relay>-ephemeral", no labels
//	current builds   name starts "<relay>-ephemeral-" AND carries
//	                 managed-by=daal-deploy + daal-relay=<relay>
//
// The current shape demands both the naming convention and the
// ownership labels. A key that merely starts with "daal-" never
// matches — a loose prefix would happily delete a different
// operator's key out of the same account.
func ownsEphemeralKey(k SSHKeyInfo, relay string) bool {
	legacy := relay + "-ephemeral"
	if k.Name == legacy {
		return true
	}
	if !strings.HasPrefix(k.Name, legacy+"-") {
		return false
	}
	return k.Labels[labelManagedBy] == labelManagedByValue && k.Labels[labelRelay] == relay
}

// firewallNameForServer mirrors the name liveClient.
// FirewallEnsureForServer mints, so teardown messages can name the
// resource the operator will see in the console.
func firewallNameForServer(serverID string) string { return "daal-relay-" + serverID }

// AssignFloatingIP / UnassignFloatingIP / CreateFloatingIP /
// ReleaseFloatingIP live in floating_ip.go — the L3 rung is a single
// subject with one invariant (the record must always name an address
// that is routed to this server) and reads better in one place.

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
	// RESOLVE THE PROFILE BEFORE ANYTHING BILLABLE HAPPENS.
	//
	// The slug used to be checked only inside recordFromServer, which
	// runs AFTER ServerCreate. On an L6 — the rung whose entire content
	// is "move to a different toolbox profile" — the sequence was:
	// Reprovision deletes the relay, Provision creates a replacement,
	// and only then does the unknown slug surface, so the rollback
	// tears the new server down and the operator is left with no relay
	// at all over a typo. A name that cannot be resolved is knowable
	// with zero API calls; spending a server to discover it is not a
	// trade worth making.
	if _, err := loadProfile(opts.ToolboxProfile); err != nil {
		return fmt.Errorf("hetzner: %w", err)
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

// ephemeralSSHKeyName returns the name for one provisioning
// attempt's one-shot SSH key: "<derived server name>-ephemeral-<8
// hex>".
//
// The random suffix is the fix for the worst failure this adapter
// had. Hetzner enforces uniqueness on SSH-key *names*, and the old
// name was "<derived server name>-ephemeral" — a pure function of
// (publisher pubkey, region), hence identical on every attempt
// forever. One orphaned key (a crashed run, a server deleted from
// the console) meant every later provision died at
// `create ssh key: SSH key not unique (uniqueness_error)`, with no
// way out of the app: the key is only removable through the Hetzner
// API or console.
//
// Of the three candidate fixes:
//
//   - reuse-if-fingerprint-matches cannot work. The ephemeral keypair
//     is regenerated per invocation, so the fingerprint never matches;
//     making it deterministic would destroy the one-shot property of
//     supplement §9.5.1 and let one leaked private half be replayed
//     against every future provision.
//   - delete-then-recreate unbricks existing accounts but keeps the
//     shared name, so two concurrent provisions for the same
//     publisher+region can still delete each other's key mid-flight.
//   - a per-attempt random suffix has no shared name at all: two
//     attempts, concurrent or sequential, simply cannot collide, and
//     a pre-existing orphan from an older build (which has no
//     suffix) is not in the way either. Retry-after-failure works
//     without anyone touching the cloud console.
//
// The cost of the suffix is that a crash between create and cleanup
// leaves a key that no longer has a predictable name — paid for by
// (a) Provision deleting the key by ID on every exit path, and (b)
// the managed-by/daal-relay labels, which let Decommission sweep any
// stragglers by ownership rather than by guessing at names.
func ephemeralSSHKeyName(relay string) (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s-ephemeral-%s", relay, hex.EncodeToString(b[:])), nil
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
// ServerInfo + the caller's ProvisionOpts. Errors when the toolbox
// profile does not resolve — see candidatesForProfile for why a record
// with zero candidates must never be returned as a success.
func (p *Provider) recordFromServer(s *ServerInfo, opts provider.ProvisionOpts) (*provider.OperatorRecord, error) {
	// Hetzner's ServerCreate response does not always populate the
	// server_type / datacenter names, which would leave the persisted
	// OperatorRecord with empty ServerType/Region — and the wizard's
	// derive_wizard_step then regresses a fully-provisioned operator
	// back to the PIN-gated "pricing" step. Fall back to the values we
	// asked for; they are authoritative for a create.
	serverType := s.ServerType
	if serverType == "" {
		serverType = opts.ServerType
	}
	region := s.Region
	if region == "" {
		region = opts.Region
	}
	cands, err := candidatesForProfile(opts.ToolboxProfile, s.PublicIP, opts.EnabledFamilies)
	if err != nil {
		return nil, err
	}
	return &provider.OperatorRecord{
		Provider:        "hetzner",
		ServerID:        s.ID,
		ServerType:      serverType,
		Region:          region,
		PublicIP:        s.PublicIP,
		PublicIPv6:      s.PublicIPv6,
		ToolboxProfile:  opts.ToolboxProfile,
		PublisherPubKey: opts.PublisherPubKey,
		Candidates:      cands,
		ProvisionedAt:   p.clock().UTC(),
	}, nil
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
func (p *Provider) dryRunRecord(name string, opts provider.ProvisionOpts, mgmtPort int, coverSNI string) (*provider.OperatorRecord, error) {
	// A dry run exists to tell the operator what a real one would do.
	// Silently emitting zero candidates for a bad profile slug would
	// make the dry run agree with a broken provision instead of
	// warning about it — which is the one job it has.
	cands, err := candidatesForProfile(opts.ToolboxProfile, opts.HelperIP, opts.EnabledFamilies)
	if err != nil {
		return nil, err
	}
	return &provider.OperatorRecord{
		Provider:        "hetzner",
		ServerID:        "dry-run-" + name,
		ServerType:      opts.ServerType,
		Region:          opts.Region,
		PublicIP:        opts.HelperIP, // placeholder; live call would assign real IP
		ToolboxProfile:  opts.ToolboxProfile,
		PublisherPubKey: opts.PublisherPubKey,
		Candidates:      cands,
		ProvisionedAt:   p.clock().UTC(),
		MgmtPort:        mgmtPort,
		CoverSNI:        coverSNI,
	}, nil
}

func waitForMgmtFingerprint(ctx context.Context, ip net.IP, token string) (string, error) {
	// Cloud-init on a fresh VPS can take 2-4 minutes. 60 × 5s = 5 min.
	return health.WaitForMgmtFingerprint(ctx, ip, token, 60, 5*time.Second)
}

type provisionFatalError struct {
	Log string
}

func (e *provisionFatalError) Error() string {
	return "server provisioning failed"
}

func (e *provisionFatalError) Summary() string {
	s := strings.TrimSpace(e.Log)
	if s == "" {
		return e.Error()
	}
	if len(s) > 500 {
		return s[:500]
	}
	return s
}

// sshReadFile cats a small file on the box over SSH using the same
// ephemeral auth as sshCloudInitTail. Used to read box-written
// connection material (reality.pub, tls SPKI pin) at provision time.
func sshReadFile(host string, signer ssh.Signer, password, path string) (string, error) {
	var auth []ssh.AuthMethod
	if signer != nil {
		auth = append(auth, ssh.PublicKeys(signer))
	}
	if password != "" {
		auth = append(auth, ssh.Password(password))
	}
	if len(auth) == 0 {
		return "", errors.New("no SSH auth method available")
	}
	cfg := &ssh.ClientConfig{
		User:            "root",
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         3 * time.Second,
	}
	client, err := ssh.Dial("tcp", net.JoinHostPort(host, "22"), cfg)
	if err != nil {
		return "", err
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	// `cat` a path we control; reject anything unexpectedly large.
	out, err := sess.Output("head -c 4096 " + shellQuote(path))
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// shellQuote single-quotes a path for safe use in a remote command.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func sshCloudInitTail(host string, signer ssh.Signer, password string) (string, error) {
	var auth []ssh.AuthMethod
	if signer != nil {
		auth = append(auth, ssh.PublicKeys(signer))
	}
	if password != "" {
		auth = append(auth, ssh.Password(password))
	}
	if len(auth) == 0 {
		return "", errors.New("no SSH auth method available")
	}
	cfg := &ssh.ClientConfig{
		User:            "root",
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         3 * time.Second,
	}
	client, err := ssh.Dial("tcp", net.JoinHostPort(host, "22"), cfg)
	if err != nil {
		return "", err
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	out, err := sess.CombinedOutput(sshCloudInitTailCommand())
	tail := trimLogTail(string(out), 45, 2200)
	if err != nil {
		var exitErr *ssh.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitStatus() == 42 {
			return "", &provisionFatalError{Log: tail}
		}
		return "", err
	}
	return tail, nil
}

func sshCloudInitTailCommand() string {
	return "set +e; if [ -s /var/log/daal-provision.fail ]; then echo '--- daal-provision.fail ---'; cat /var/log/daal-provision.fail 2>&1; exit 42; fi; echo 'cloud-init status:'; cloud-init status --long 2>&1; echo '--- cloud-init-output.log ---'; tail -n 18 /var/log/cloud-init-output.log 2>&1; echo '--- cloud-init.log ---'; tail -n 12 /var/log/cloud-init.log 2>&1; echo '--- service logs ---'; journalctl --no-pager -n 18 -u cloud-init -u cloud-final -u sing-box -u daal-health -u daal-relay-mgmt 2>&1"
}

func trimLogTail(s string, maxLines, maxBytes int) string {
	s = strings.TrimSpace(s)
	if maxBytes > 0 && len(s) > maxBytes {
		s = s[len(s)-maxBytes:]
		if idx := strings.IndexByte(s, '\n'); idx >= 0 {
			s = s[idx+1:]
		}
	}
	lines := strings.Split(s, "\n")
	if maxLines > 0 && len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
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
	if err != nil && strings.Contains(err.Error(), "no attached firewall") {
		// Self-heal: a server provisioned before FRP-14 (or one
		// whose firewall was detached out-of-band) has no Hetzner
		// Cloud Firewall attached. Without one, the V2 mgmt port
		// is reachable from anywhere (box-side ufw doesn't open
		// it — see FRP-10 invariant 18). Create + attach the
		// daal baseline firewall now and retry.
		// KNOWN LIMIT, recorded rather than papered over: this
		// self-heal path is reached from SetEphemeralFirewallRule,
		// which is handed a serverID and nothing else — no record, no
		// family set. It therefore re-creates the firewall with the
		// FLEET BASELINE data-plane ports, so a relay that serves an
		// opt-in family (tuic, 8443/udp) and has somehow lost its cloud
		// firewall gets that family's port left shut. The mgmt plane
		// comes back, which is what this path exists for, and the tuic
		// tier stays dark until the relay is reprovisioned. Passing the
		// real set needs the record threaded down to
		// SetEphemeralFirewallRule; it is a signature change across the
		// provider interface and is not worth doing blind in a wave
		// that cannot test it against hardware.
		if _, eErr := p.c.FirewallEnsureForServer(ctx, serverID, nil); eErr != nil {
			return nil, fmt.Errorf("hetzner: ensure firewall: %w", eErr)
		}
		id, err = p.c.FirewallAddEphemeralRule(ctx, serverID, callerIP, port, expiresAt)
	}
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
