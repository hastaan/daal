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

	progress := opts.OnProgress
	if progress == nil {
		progress = func(string, string) {}
	}

	// Render cloud-init (needed for both create and rebuild paths).
	progress("provision_ssh_key", "Creating SSH key")
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

	progress("provision_cloud_init", "Rendering server configuration")
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

	var srv *ServerInfo
	if opts.ExistingServerID != "" {
		// Rebuild path: re-image the existing server with daal's
		// cloud-init. Keeps the same IP and billing.
		progress("provision_rebuild_server", "Rebuilding existing server with daal configuration")
		srv, err = p.c.ServerRebuild(ctx, opts.ExistingServerID, "ubuntu-24.04", string(userData))
		if err != nil {
			_ = p.c.SSHKeyDelete(ctx, sshKeyID)
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
			Labels:     map[string]string{"managed-by": "daal-deploy", "toolbox": opts.ToolboxProfile},
		})
		if err != nil {
			_ = p.c.SSHKeyDelete(ctx, sshKeyID)
			return nil, fmt.Errorf("hetzner: create server: %w", err)
		}
	}
	rec := p.recordFromServer(srv, opts)
	rec.MgmtPort = mgmtPort
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
	if _, err := p.c.FirewallEnsureForServer(ctx, rec.ServerID); err != nil {
		// Don't tear the whole provision down; the box-side ufw
		// still provides surface-area minimisation for the
		// non-mgmt ports. We just won't be able to talk to the
		// mgmt plane until a firewall is attached out-of-band.
		// Log via the progress channel and continue.
		progress("provision_cloud_firewall", fmt.Sprintf("firewall ensure failed: %v", err))
	}
	if opts.WaitForHealth {
		// If the server has a Hetzner Cloud Firewall attached, the
		// box-side UFW rule is not enough; open the provisioning
		// health endpoint from this helper IP while cloud-init runs.
		// Servers without an attached firewall don't need this.
		var healthRuleID string
		if id, err := p.c.FirewallAddEphemeralRule(ctx, rec.ServerID, opts.HelperIP.String(), 9876, p.clock().Add(10*time.Minute)); err == nil {
			healthRuleID = id
			defer func() { _ = p.c.FirewallRemoveEphemeralRule(ctx, healthRuleID) }()
			progress("provision_cloud_firewall", "Opened temporary cloud firewall window for server health")
		} else if !strings.Contains(err.Error(), "no attached firewall") {
			return nil, fmt.Errorf("hetzner: open temporary health firewall: %w", err)
		}
		var sshRuleID string
		if id, err := p.c.FirewallAddEphemeralRule(ctx, rec.ServerID, opts.HelperIP.String(), 22, p.clock().Add(10*time.Minute)); err == nil {
			sshRuleID = id
			defer func() { _ = p.c.FirewallRemoveEphemeralRule(ctx, sshRuleID) }()
			progress("provision_cloud_firewall", "Opened temporary cloud firewall window for SSH log streaming")
		} else if !strings.Contains(err.Error(), "no attached firewall") {
			return nil, fmt.Errorf("hetzner: open temporary ssh firewall: %w", err)
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
						return nil, fmt.Errorf("hetzner: server provisioning failed: %s", fatal.Summary())
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
					break
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
				break
			}
			select {
			case <-ctx.Done():
				healthErr = ctx.Err()
				break
			case <-time.After(interval):
			}
		}
		if healthErr != nil {
			return nil, healthErr
		}
		rec.MgmtTLSFingerprint = fp
	}
	progress("provision_healthy", "Server is up and healthy")
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
		if _, eErr := p.c.FirewallEnsureForServer(ctx, serverID); eErr != nil {
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
