package cloudflare

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Provider is the FRP-8 helper-side coordinator. It composes the
// Origin CA, AOP, DNS, Worker, and edge-range primitives behind a
// single ProvisionFront entry point the wizard's Tauri shim calls.
//
// Provider.cf is the only place that talks to Cloudflare; the
// validator path NEVER imports this package, and the recipient
// refresh path NEVER imports this package — both invariants are
// part of the FRP-8 module-boundary contract.
type Provider struct {
	cf CFClient
	// nowFn returns the current wall-clock; tests inject a
	// deterministic clock.
	nowFn func() time.Time
}

// NewProvider returns a fresh Provider bound to the supplied
// CFClient. Pass NewLiveCFClient() in production; pass
// &MockCFClient{} in tests.
func NewProvider(cf CFClient) *Provider {
	return &Provider{cf: cf, nowFn: time.Now}
}

// SetClock overrides the Provider's wall-clock. Test-only.
func (p *Provider) SetClock(now func() time.Time) { p.nowFn = now }

// ProvisionFront walks the §11.7 hardening template end-to-end:
// resolves zone → issues Origin CA → enables AOP → ensures
// proxied DNS → uploads the rewrite Worker → binds the route.
// Returns a FrontRecord ready to be passed to the binder.
//
// The cloud-provider firewall rule (locking 443/tcp to Cloudflare
// edge ranges) is provisioned separately by the Hetzner adapter
// (publisher/deploy/providers/hetzner/firewall_cf.go) — Provider
// only learns the FirewallID afterwards via SetFirewallID.
//
// CFTokenSecret is consumed but not zeroized here; the caller
// (wizard) zeroizes it after this call returns.
func (p *Provider) ProvisionFront(ctx context.Context, opts CloudflareOpts) (*FrontRecord, error) {
	if opts.Hostname == "" {
		return nil, fmt.Errorf("cloudflare: hostname required")
	}
	if opts.OriginIP == "" {
		return nil, fmt.Errorf("cloudflare: origin IP required")
	}
	if opts.OriginPath == "" {
		return nil, fmt.Errorf("cloudflare: origin path required")
	}
	if len(opts.CFTokenSecret) == 0 {
		return nil, fmt.Errorf("cloudflare: CF token required")
	}
	if opts.OutDir == "" {
		return nil, fmt.Errorf("cloudflare: out dir required")
	}

	// 1. Resolve zone.
	apex := apexOf(opts.Hostname)
	zoneID, accountID, err := p.cf.LookupZoneID(ctx, opts.CFTokenSecret, apex)
	if err != nil {
		return nil, fmt.Errorf("cloudflare: lookup zone for %q: %w", apex, err)
	}

	// 2. Origin CA cert.
	fp, certPath, privPath, err := IssueAndPersistOriginCert(
		ctx, p.cf, opts.CFTokenSecret, []string{opts.Hostname}, opts.OutDir, 0,
	)
	if err != nil {
		return nil, err
	}

	// 3. Enable AOP + persist client cert.
	aopPath, err := EnableAOPAndPersistClientCert(ctx, p.cf, opts.CFTokenSecret, zoneID, opts.OutDir)
	if err != nil {
		return nil, err
	}

	// 4. Ensure proxied DNS records (rejects DNS-only A/AAAA).
	if err := p.cf.EnsureProxiedRecords(ctx, opts.CFTokenSecret, zoneID, opts.Hostname, opts.OriginIP, opts.OriginIPv6); err != nil {
		return nil, fmt.Errorf("cloudflare: proxied DNS: %w", err)
	}

	// 5. Public path: random if not supplied.
	publicPath := opts.PublicPath
	if publicPath == "" {
		publicPath = randomPath(8)
	}

	// 6. Upload rewrite Worker + bind route.
	scriptName := fmt.Sprintf("daal-rewrite-%s", strings.ReplaceAll(opts.Hostname, ".", "-"))
	scriptBody := RewriteWorkerScript(publicPath, opts.OriginPath)
	if _, err := p.cf.UploadWorkerScript(ctx, opts.CFTokenSecret, accountID, scriptName, scriptBody); err != nil {
		return nil, fmt.Errorf("cloudflare: upload worker: %w", err)
	}
	pattern := opts.Hostname + publicPath + "*"
	routeID, err := p.cf.BindWorkerRoute(ctx, opts.CFTokenSecret, zoneID, scriptName, pattern)
	if err != nil {
		return nil, fmt.Errorf("cloudflare: bind worker route: %w", err)
	}

	return &FrontRecord{
		Hostname:            opts.Hostname,
		ZoneID:              zoneID,
		PublicPath:          publicPath,
		OriginPath:          opts.OriginPath,
		WorkerRouteID:       routeID,
		OriginCAFingerprint: fp,
		OriginCACertPath:    certPath,
		OriginCAPrivPath:    privPath,
		AOPClientCertPath:   aopPath,
		AOPEnabled:          true,
		// FirewallID is filled in by the Hetzner adapter after
		// the firewall rule is created with the current edge
		// ranges. The wizard sets it via SetFirewallID below.
	}, nil
}

// SetFirewallID is called by the wizard once the Hetzner adapter
// has provisioned the cloud-provider firewall rule locking 443/tcp
// to the current Cloudflare edge ranges.
func (p *Provider) SetFirewallID(rec *FrontRecord, fwID string) {
	rec.FirewallID = fwID
}

// RotatePublicPath is the supplement §14.4 public-path rotation
// path. The visible /r/<hex> path changes; the stable origin path
// is unchanged. The wizard MUST re-sign the RelayPack (a
// `public_risk_tag` value changed: `ws_path_fp:` and the
// `public_path` itself) and re-publish the freshness JSON
// document. The CDN-side work (re-upload worker, rebind route)
// is what this method does. Returns the new PublicPath +
// WorkerRouteID; caller is responsible for the bundle re-sign +
// freshness re-publish.
//
// Invariant: under §11.7, the operator's box is NOT redeployed.
// This is a Cloudflare-API-only rotation.
func (p *Provider) RotatePublicPath(ctx context.Context, cfToken []byte, accountID string, rec *FrontRecord, newPublicPath string) (string, string, error) {
	if rec == nil {
		return "", "", fmt.Errorf("cloudflare: front record required")
	}
	if newPublicPath == "" {
		newPublicPath = randomPath(8)
	}
	scriptName := fmt.Sprintf("daal-rewrite-%s", strings.ReplaceAll(rec.Hostname, ".", "-"))
	scriptBody := RewriteWorkerScript(newPublicPath, rec.OriginPath)
	if _, err := p.cf.UploadWorkerScript(ctx, cfToken, accountID, scriptName, scriptBody); err != nil {
		return "", "", fmt.Errorf("cloudflare: rotate public path: re-upload worker: %w", err)
	}
	newRouteID, err := p.cf.RotatePublicPath(ctx, cfToken, rec.ZoneID, rec.WorkerRouteID, scriptName, rec.Hostname, newPublicPath, rec.OriginPath)
	if err != nil {
		return "", "", fmt.Errorf("cloudflare: rotate public path: %w", err)
	}
	rec.PublicPath = newPublicPath
	rec.WorkerRouteID = newRouteID
	return newPublicPath, newRouteID, nil
}

// RotateHostname is the supplement §14.4 hostname-rotation path.
// The hostname changes (also a public_risk_tag change: `host:`,
// `sni:`, `public_domain:`); the wizard MUST re-sign the
// RelayPack and re-publish the freshness JSON document. The
// origin IP is unchanged.
//
// Returns the (newZoneID, newAccountID, newRouteID) tuple. The
// FrontRecord is mutated in place. Caller re-uploads the worker
// (we do that here as a convenience) and binds the route on the
// new zone.
func (p *Provider) RotateHostname(ctx context.Context, cfToken []byte, rec *FrontRecord, newHostname, originIPv4, originIPv6 string) (string, string, error) {
	if rec == nil {
		return "", "", fmt.Errorf("cloudflare: front record required")
	}
	if newHostname == "" || originIPv4 == "" {
		return "", "", fmt.Errorf("cloudflare: newHostname and originIPv4 required")
	}
	newZoneID, newAccountID, err := p.cf.RotateHostname(ctx, cfToken, rec, newHostname, originIPv4, originIPv6)
	if err != nil {
		return "", "", err
	}
	scriptName := fmt.Sprintf("daal-rewrite-%s", strings.ReplaceAll(newHostname, ".", "-"))
	scriptBody := RewriteWorkerScript(rec.PublicPath, rec.OriginPath)
	if _, err := p.cf.UploadWorkerScript(ctx, cfToken, newAccountID, scriptName, scriptBody); err != nil {
		return "", "", fmt.Errorf("cloudflare: rotate hostname: upload worker: %w", err)
	}
	pattern := newHostname + rec.PublicPath + "*"
	newRouteID, err := p.cf.BindWorkerRoute(ctx, cfToken, newZoneID, scriptName, pattern)
	if err != nil {
		return "", "", fmt.Errorf("cloudflare: rotate hostname: bind worker route: %w", err)
	}
	rec.Hostname = newHostname
	rec.ZoneID = newZoneID
	rec.WorkerRouteID = newRouteID
	return newZoneID, newRouteID, nil
}

// RotateOrigin is the supplement §14.4 origin-only path. The
// origin IP changes; the hostname and public path are unchanged.
// **The censor sees nothing**: the recipient continues connecting
// to the same `public_domain:` over Cloudflare, which now proxies
// to the new origin.
//
// Per §14.5 the wizard MUST NOT re-sign the RelayPack and MUST
// NOT re-publish the freshness document. The candidate is
// byte-identical because no `public_risk_tag` changed. The
// The FrontRecord is otherwise unchanged because it carries only the
// public CDN surface + attestation metadata. The caller is responsible
// for the cloud-provider firewall rule re-anchoring (Hetzner CF
// firewall) which is a Helper-side operation, not a Cloudflare API
// operation.
func (p *Provider) RotateOrigin(ctx context.Context, cfToken []byte, rec *FrontRecord, newOriginIPv4, newOriginIPv6 string) error {
	if rec == nil {
		return fmt.Errorf("cloudflare: front record required")
	}
	if newOriginIPv4 == "" {
		return fmt.Errorf("cloudflare: newOriginIPv4 required")
	}
	if err := p.cf.RotateOrigin(ctx, cfToken, rec.ZoneID, rec.Hostname, newOriginIPv4, newOriginIPv6); err != nil {
		return err
	}
	return nil
}

// VerifyPosture is the wizard "Settings → Verify CDN posture"
// button. Re-reads live Cloudflare state and reports drift.
//
// Per phase doc §13 rule 5: this is the ONLY live-posture path —
// the validator does not call Cloudflare.
func (p *Provider) VerifyPosture(ctx context.Context, cfToken []byte, rec *FrontRecord) (PostureReport, error) {
	if rec == nil {
		return PostureReport{}, fmt.Errorf("cloudflare: front record required")
	}
	return p.cf.VerifyPosture(ctx, cfToken, rec)
}

// apexOf returns the apex domain of an FQDN. e.g.
// "momsroute.example.com" → "example.com".
func apexOf(fqdn string) string {
	parts := strings.Split(fqdn, ".")
	if len(parts) <= 2 {
		return fqdn
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// randomPath returns "/r/<n*2 hex chars>".
func randomPath(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// On the off-chance Read fails (extremely rare on
		// modern OSes), fall back to a deterministic suffix
		// derived from the wall-clock so we still return a
		// non-empty path. The caller surfaces this via the
		// FrontRecord and the wizard can rotate later.
		return "/r/" + hex.EncodeToString([]byte(time.Now().UTC().Format("20060102150405")))
	}
	return "/r/" + hex.EncodeToString(b)
}
