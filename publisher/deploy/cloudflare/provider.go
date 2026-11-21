package cloudflare

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"daal/publisher/deploy/relayports"
)

// Provider builds, reads and takes down the Cloudflare side of the CDN
// way in (docs/optional-addons-plan.md §2.4, item B-3). It composes the
// CFClient calls; it never holds the token beyond one call.
//
// What it does not do: the relay firewall (Hetzner, see
// providers/hetzner/firewall_cf.go) and the relay door (daal-relay-mgmt
// /cdn, see cmd/daal-relay-mgmt/singbox_cdn.go). The CLI runs those
// around it.
type Provider struct {
	cf    CFClient
	nowFn func() time.Time
}

// NewProvider binds a Provider to a CFClient: NewLiveCFClient() in
// production, a MockCFClient in tests.
func NewProvider(cf CFClient) *Provider {
	return &Provider{cf: cf, nowFn: time.Now}
}

// SetClock overrides the wall clock. Test-only.
func (p *Provider) SetClock(now func() time.Time) { p.nowFn = now }

// Client returns the CFClient (for CheckToken and the CLI).
func (p *Provider) Client() CFClient { return p.cf }

// ---- names ----

var hostLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// NormalizeHostname lower-cases and checks a DNS hostname: at least two
// labels, letters, digits and inner hyphens only, no wildcard.
func NormalizeHostname(h string) (string, error) {
	h = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
	if len(h) == 0 || len(h) > 253 {
		return "", fmt.Errorf("cloudflare: bad hostname %q", h)
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("cloudflare: hostname %q needs a zone", h)
	}
	for _, l := range labels {
		if !hostLabel.MatchString(l) {
			return "", fmt.Errorf("cloudflare: bad hostname %q", h)
		}
	}
	return h, nil
}

// FindZone finds the zone a hostname belongs to by walking its labels
// from the most specific down: for `a.b.example.co.uk` it asks for
// `a.b.example.co.uk`, `b.example.co.uk`, `example.co.uk`, `co.uk`, and
// takes the first active zone the token sees. This replaces apexOf,
// which took the last two labels and so found `co.uk` for every name
// under a two-label public suffix (and `eu.org` for every free domain
// there).
//
// No public-suffix list is needed: Cloudflare only answers for zones
// the token can see, and a suffix is never one of those.
func FindZone(ctx context.Context, cf CFClient, cfToken []byte, hostname string) (Zone, error) {
	h, err := NormalizeHostname(hostname)
	if err != nil {
		return Zone{}, err
	}
	labels := strings.Split(h, ".")
	for i := 0; i <= len(labels)-2; i++ {
		cand := strings.Join(labels[i:], ".")
		z, found, err := cf.LookupZone(ctx, cfToken, cand)
		if err != nil {
			return Zone{}, scrub(err, cfToken)
		}
		if found && z.Status == "active" {
			return z, nil
		}
	}
	return Zone{}, ErrZoneNotFound
}

// originRuleRef is the `ref` of Daal's origin rule for a hostname. It
// is derived from the hostname alone, so a caller holding only the
// hostname (the rotate verbs) finds the rule without stored state, and
// it reads as an opaque id to anyone looking at the zone.
func originRuleRef(hostname string) string {
	sum := sha256.Sum256([]byte("daal/cdn-origin-rule/v1\x00" + hostname))
	return "o" + hex.EncodeToString(sum[:10])
}

// randomLabel is a 10-character label: a letter, then letters and
// digits. Nothing in it names Daal or the publisher.
func randomLabel() (string, error) {
	const first = "abcdefghijklmnopqrstuvwxyz"
	const rest = "abcdefghijklmnopqrstuvwxyz0123456789"
	out := make([]byte, 10)
	for i := range out {
		set := rest
		if i == 0 {
			set = first
		}
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
		if err != nil {
			return "", err
		}
		out[i] = set[n.Int64()]
	}
	return string(out), nil
}

// RandomWSPath is a fresh WebSocket path: "/" and 16 random bytes in
// hex.
func RandomWSPath() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "/" + hex.EncodeToString(b), nil
}

var wsPathRE = regexp.MustCompile(`^/[A-Za-z0-9._~/-]{1,127}$`)

// ValidWSPath accepts a path the relay will also accept.
func ValidWSPath(p string) bool { return wsPathRE.MatchString(p) && !strings.Contains(p, "..") }

// checkOriginPort refuses a port any data-plane family already listens
// on: Cloudflare dialling 443 lands on REALITY, which hands the edge
// the cover site's certificate (defect 1 of the blackout plan, Group B).
func checkOriginPort(port int) error {
	if port <= 0 || port > 65535 {
		return fmt.Errorf("cloudflare: origin port %d out of range", port)
	}
	for _, f := range relayports.Declared() {
		if ep := relayports.For(f); !ep.UDP && ep.Port == port {
			return fmt.Errorf("cloudflare: origin port %d/tcp is %s's; the CDN door needs its own (relayports.CDNOrigin)", port, f)
		}
	}
	return nil
}

// ---- provisioning ----

// ProvisionError is a failed ProvisionFront. Everything the call had
// created is undone in reverse order before it returns; Left names what
// the undo could not remove, so the caller can show it and retry.
type ProvisionError struct {
	Step string
	Err  error
	Left []string
}

func (e *ProvisionError) Error() string {
	msg := fmt.Sprintf("cloudflare: %s: %v", e.Step, e.Err)
	if len(e.Left) == 0 {
		return msg + " (everything created was removed again)"
	}
	return msg + "; could not remove: " + strings.Join(e.Left, "; ")
}

func (e *ProvisionError) Unwrap() error { return e.Err }

type undoStep struct {
	name string
	do   func() error
}

// ProvisionFront builds the Cloudflare side of one way in:
//
//  1. find the zone by walking the hostname's labels;
//  2. an Origin CA certificate for the zone and `*.<zone>`;
//  3. origin pull with a certificate of this front's own (aop.go), on;
//  4. SSL mode Full (strict) and WebSockets on, zone-wide;
//  5. a proxied A (and AAAA) record for the hostname;
//  6. an Origin Rule sending that hostname to the relay's CDN port;
//  7. read the ECH posture (zone setting, and the published HTTPS
//     record when opts.ECH is set). ECH is left as Cloudflare has it.
//
// Any failure undoes everything already done, in reverse, and returns a
// *ProvisionError. Zone settings are put back to the value they had.
// The token is used per call and never kept.
func (p *Provider) ProvisionFront(ctx context.Context, opts CloudflareOpts) (*FrontRecord, error) {
	tok := opts.CFTokenSecret
	if len(tok) == 0 {
		return nil, fmt.Errorf("cloudflare: CF token required")
	}
	if opts.OutDir == "" {
		return nil, fmt.Errorf("cloudflare: out dir required")
	}
	if ip := net.ParseIP(opts.OriginIP); ip == nil || ip.To4() == nil {
		return nil, fmt.Errorf("cloudflare: origin IP %q is not an IPv4 address", opts.OriginIP)
	}
	if opts.OriginIPv6 != "" {
		if ip := net.ParseIP(opts.OriginIPv6); ip == nil || ip.To4() != nil {
			return nil, fmt.Errorf("cloudflare: origin IPv6 %q is not an IPv6 address", opts.OriginIPv6)
		}
	}
	host := opts.Hostname
	if host == "" {
		if opts.Zone == "" {
			return nil, fmt.Errorf("cloudflare: hostname or zone required")
		}
		zn, err := NormalizeHostname(opts.Zone)
		if err != nil {
			return nil, err
		}
		l, err := randomLabel()
		if err != nil {
			return nil, err
		}
		host = l + "." + zn
	}
	host, err := NormalizeHostname(host)
	if err != nil {
		return nil, err
	}
	path := opts.OriginPath
	if path == "" {
		if path, err = RandomWSPath(); err != nil {
			return nil, err
		}
	}
	if !ValidWSPath(path) {
		return nil, fmt.Errorf("cloudflare: origin path %q is not a usable WebSocket path", path)
	}
	port := opts.OriginPort
	if port == 0 {
		port = relayports.CDNOrigin.Port
	}
	if err := checkOriginPort(port); err != nil {
		return nil, err
	}
	now := p.nowFn
	if opts.Now != nil {
		now = opts.Now
	}

	zone, err := FindZone(ctx, p.cf, tok, host)
	if err != nil {
		return nil, &ProvisionError{Step: "find zone", Err: err}
	}
	if opts.Zone != "" && opts.Hostname == "" && !strings.EqualFold(zone.Name, strings.TrimSuffix(opts.Zone, ".")) {
		return nil, &ProvisionError{Step: "find zone", Err: fmt.Errorf("%s is inside zone %s, not %s", host, zone.Name, opts.Zone)}
	}

	rec := &FrontRecord{
		Hostname:      host,
		Zone:          zone.Name,
		ZoneID:        zone.ID,
		AccountID:     zone.AccountID,
		PublicPath:    path,
		OriginPath:    path,
		OriginPort:    port,
		OriginRuleRef: originRuleRef(host),
		PriorSettings: map[string]string{},
	}
	var undo []undoStep
	fail := func(step string, err error) (*FrontRecord, error) {
		var left []string
		for i := len(undo) - 1; i >= 0; i-- {
			if uerr := undo[i].do(); uerr != nil {
				left = append(left, undo[i].name+": "+scrub(uerr, tok).Error())
			}
		}
		return nil, &ProvisionError{Step: step, Err: scrub(err, tok), Left: left}
	}

	// 2. Origin CA certificate for the zone and its wildcard.
	cert, certPath, privPath, err := IssueAndPersistOriginCert(ctx, p.cf, tok,
		[]string{zone.Name, "*." + zone.Name}, opts.OutDir, 0)
	if err != nil {
		return fail("origin certificate", err)
	}
	rec.OriginCertID, rec.OriginCAFingerprint = cert.ID, cert.FingerprintHex
	rec.OriginCACertPath, rec.OriginCAPrivPath = certPath, privPath
	undo = append(undo, undoStep{"origin certificate " + cert.ID, func() error {
		_ = os.Remove(certPath)
		_ = os.Remove(privPath)
		return p.cf.RevokeOriginCert(ctx, tok, cert.ID)
	}})

	// 3. Origin pull: this front's own client certificate, then on.
	caPath, aopID, err := SetupAOP(ctx, p.cf, tok, zone.ID, opts.OutDir, now())
	if aopID != "" {
		undo = append(undo, undoStep{"origin pull certificate " + aopID, func() error {
			_ = os.Remove(caPath)
			return p.cf.DeleteAOPCert(ctx, tok, zone.ID, aopID)
		}})
	}
	if err != nil {
		return fail("origin pull certificate", err)
	}
	rec.AOPCACertPath, rec.AOPCertID = caPath, aopID
	aopWas, err := p.cf.AOPEnabled(ctx, tok, zone.ID)
	if err != nil {
		return fail("read origin pull", err)
	}
	rec.PriorSettings["aop"] = onOff(aopWas)
	if !aopWas {
		if err := p.cf.SetAOPEnabled(ctx, tok, zone.ID, true); err != nil {
			return fail("origin pull on", fmt.Errorf("%w: %v", ErrAOPEnableFailed, err))
		}
		undo = append(undo, undoStep{"origin pull setting", func() error {
			return p.cf.SetAOPEnabled(ctx, tok, zone.ID, false)
		}})
	}
	rec.AOPEnabled = true

	// 4. SSL Full (strict) and WebSockets on. Under Flexible the edge
	// would dial the origin in plain HTTP on 80; under Full it would
	// accept any certificate.
	for _, s := range []struct{ name, want string }{{"ssl", "strict"}, {"websockets", "on"}} {
		was, err := p.cf.GetZoneSetting(ctx, tok, zone.ID, s.name)
		if err != nil {
			return fail("read zone setting "+s.name, err)
		}
		rec.PriorSettings[s.name] = was
		if was == s.want {
			continue
		}
		if err := p.cf.SetZoneSetting(ctx, tok, zone.ID, s.name, s.want); err != nil {
			return fail("zone setting "+s.name, err)
		}
		name := s.name
		undo = append(undo, undoStep{"zone setting " + name, func() error {
			return p.cf.SetZoneSetting(ctx, tok, zone.ID, name, was)
		}})
	}

	// 5. Proxied records.
	ids, err := p.cf.EnsureProxiedRecords(ctx, tok, zone.ID, host, opts.OriginIP, opts.OriginIPv6)
	for _, id := range ids {
		id := id
		undo = append(undo, undoStep{"dns record " + id, func() error {
			return p.cf.DeleteDNSRecord(ctx, tok, zone.ID, id)
		}})
	}
	if err != nil {
		return fail("proxied dns record", err)
	}
	rec.DNSRecordIDs = ids

	// 6. Origin Rule: this hostname → the relay's CDN port.
	if err := p.cf.EnsureOriginRule(ctx, tok, zone.ID, rec.OriginRuleRef, host, port); err != nil {
		// The call may have half-landed; removing by ref is idempotent.
		undo = append(undo, undoStep{"origin rule", func() error {
			return p.cf.RemoveOriginRule(ctx, tok, zone.ID, rec.OriginRuleRef)
		}})
		return fail("origin rule", err)
	}
	undo = append(undo, undoStep{"origin rule", func() error {
		return p.cf.RemoveOriginRule(ctx, tok, zone.ID, rec.OriginRuleRef)
	}})

	// 7. ECH posture. Read-only and never fatal: the endpoint can be
	// signed without a config (the card then says "Name hidden: no").
	rec.ECH = p.readECH(ctx, tok, zone.ID, host, opts.ECH, now())
	return rec, nil
}

func (p *Provider) readECH(ctx context.Context, tok []byte, zoneID, host string, f ECHFetcher, now time.Time) ECHPosture {
	var post ECHPosture
	if f != nil {
		post = ReadECHPosture(ctx, f, host, now.Unix())
	}
	v, err := p.cf.GetZoneSetting(ctx, tok, zoneID, "ech")
	if err != nil {
		// The settings/ech path is unconfirmed (GATE C-2).
		msg := "zone setting: " + scrub(err, tok).Error()
		if post.Error != "" {
			msg = post.Error + "; " + msg
		}
		post.Error = msg
		return post
	}
	post.ZoneSetting = v
	return post
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// SetFirewallID records the relay firewall that carries the Cloudflare
// rule.
func (p *Provider) SetFirewallID(rec *FrontRecord, fwID string) {
	rec.FirewallID = fwID
}

// ---- rotation ----

// RotatePublicPath is gone with the Worker. It stays as a method so the
// old verb answers with the reason instead of a compile error.
func (p *Provider) RotatePublicPath(_ context.Context, _ []byte, _ string, rec *FrontRecord, _ string) (string, string, error) {
	if rec == nil {
		return "", "", fmt.Errorf("cloudflare: front record required")
	}
	return "", "", ErrWorkerRemoved
}

// RotateHostname moves the way in to another name in the same zone: a
// proxied record for the new name, the origin rule re-pointed, the old
// name's rule and records removed. The certificate covers `*.<zone>`,
// so it stays. The caller re-signs and publishes freshness afterwards.
// Returns (zoneID, "", nil); the second value was the Worker route.
func (p *Provider) RotateHostname(ctx context.Context, cfToken []byte, rec *FrontRecord, newHostname, originIPv4, originIPv6 string) (string, string, error) {
	if rec == nil {
		return "", "", fmt.Errorf("cloudflare: front record required")
	}
	if newHostname == "" || originIPv4 == "" {
		return "", "", fmt.Errorf("cloudflare: newHostname and originIPv4 required")
	}
	nh, err := NormalizeHostname(newHostname)
	if err != nil {
		return "", "", err
	}
	z, err := FindZone(ctx, p.cf, cfToken, nh)
	if err != nil {
		return "", "", err
	}
	if rec.ZoneID != "" && z.ID != rec.ZoneID {
		return "", "", ErrCrossZoneRotation
	}
	port := rec.OriginPort
	if port == 0 {
		port = relayports.CDNOrigin.Port
	}
	ids, err := p.cf.EnsureProxiedRecords(ctx, cfToken, z.ID, nh, originIPv4, originIPv6)
	if err != nil {
		return "", "", scrub(err, cfToken)
	}
	newRef := originRuleRef(nh)
	if err := p.cf.EnsureOriginRule(ctx, cfToken, z.ID, newRef, nh, port); err != nil {
		for _, id := range ids {
			_ = p.cf.DeleteDNSRecord(ctx, cfToken, z.ID, id)
		}
		_ = p.cf.RemoveOriginRule(ctx, cfToken, z.ID, newRef)
		return "", "", scrub(err, cfToken)
	}
	// The new name carries now. The old one goes: a burned name left
	// pointing at the relay only helps whoever burned it.
	oldHost := rec.Hostname
	if oldHost != "" && oldHost != nh {
		_ = p.cf.RemoveOriginRule(ctx, cfToken, z.ID, originRuleRef(oldHost))
		_ = p.deleteOwnRecords(ctx, cfToken, z.ID, oldHost, rec.DNSRecordIDs, originIPv4, originIPv6)
	}
	rec.Hostname, rec.ZoneID, rec.Zone = nh, z.ID, z.Name
	rec.OriginRuleRef, rec.DNSRecordIDs, rec.OriginPort = newRef, ids, port
	rec.WorkerRouteID = ""
	return z.ID, "", nil
}

// deleteOwnRecords deletes the records Daal made for host: the ids it
// recorded, or — when the caller holds none (the old rotate verbs pass
// only a hostname) — the proxied A/AAAA records whose content is the
// relay's own address.
func (p *Provider) deleteOwnRecords(ctx context.Context, tok []byte, zoneID, host string, ids []string, v4, v6 string) error {
	if len(ids) == 0 {
		recs, err := p.cf.ListDNSRecords(ctx, tok, zoneID, host)
		if err != nil {
			return err
		}
		for _, r := range recs {
			if r.proxied() && ((r.Type == "A" && r.Content == v4) || (r.Type == "AAAA" && v6 != "" && r.Content == v6)) {
				ids = append(ids, r.ID)
			}
		}
	}
	var first error
	for _, id := range ids {
		if err := p.cf.DeleteDNSRecord(ctx, tok, zoneID, id); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// RotateOrigin re-points the proxied records at a new relay address.
// Name, path and port are unchanged, so recipients see nothing and the
// pack is NOT re-signed. The relay firewall rule moves with the relay
// (a new relay has a new firewall); that is the caller's step.
func (p *Provider) RotateOrigin(ctx context.Context, cfToken []byte, rec *FrontRecord, newOriginIPv4, newOriginIPv6 string) error {
	if rec == nil {
		return fmt.Errorf("cloudflare: front record required")
	}
	if newOriginIPv4 == "" {
		return fmt.Errorf("cloudflare: newOriginIPv4 required")
	}
	recs, err := p.cf.ListDNSRecords(ctx, cfToken, rec.ZoneID, rec.Hostname)
	if err != nil {
		return scrub(err, cfToken)
	}
	want := map[string]string{"A": newOriginIPv4, "AAAA": newOriginIPv6}
	have := map[string]bool{}
	for _, r := range recs {
		if r.Type != "A" && r.Type != "AAAA" {
			continue
		}
		if !r.proxied() {
			return ErrDNSOnlyRecordPresent
		}
		have[r.Type] = true
		content := want[r.Type]
		if content == "" {
			// No new IPv6: the old AAAA would keep pointing at the old
			// relay. Remove it.
			if err := p.cf.DeleteDNSRecord(ctx, cfToken, rec.ZoneID, r.ID); err != nil {
				return scrub(err, cfToken)
			}
			continue
		}
		if r.Content != content {
			if err := p.cf.SetDNSRecordContent(ctx, cfToken, rec.ZoneID, r.ID, content); err != nil {
				return scrub(err, cfToken)
			}
		}
	}
	if !have["A"] || (newOriginIPv6 != "" && !have["AAAA"]) {
		if _, err := p.cf.EnsureProxiedRecords(ctx, cfToken, rec.ZoneID, rec.Hostname, newOriginIPv4, newOriginIPv6); err != nil {
			return scrub(err, cfToken)
		}
	}
	return nil
}

// ---- posture ----

// VerifyPosture reads the live Cloudflare state for rec. Read-only.
// The firewall half is the caller's (it needs the Hetzner token);
// FirewallChecked and OnlyCloudflare stay false here.
func (p *Provider) VerifyPosture(ctx context.Context, cfToken []byte, rec *FrontRecord, ech ECHFetcher) (PostureReport, error) {
	if rec == nil {
		return PostureReport{}, fmt.Errorf("cloudflare: front record required")
	}
	var r PostureReport
	var notes []string
	if rec.OriginCACertPath != "" && rec.OriginCAFingerprint != "" {
		if b, err := os.ReadFile(rec.OriginCACertPath); err == nil {
			sum := sha256.Sum256(b)
			r.OriginCAFingerprintMatch = hex.EncodeToString(sum[:]) == rec.OriginCAFingerprint
		} else {
			notes = append(notes, "origin certificate file not readable here")
		}
	}
	on, err := p.cf.AOPEnabled(ctx, cfToken, rec.ZoneID)
	if err != nil {
		return r, scrub(err, cfToken)
	}
	r.AOPEnabled = on && rec.AOPCertID != ""
	ssl, err := p.cf.GetZoneSetting(ctx, cfToken, rec.ZoneID, "ssl")
	if err != nil {
		return r, scrub(err, cfToken)
	}
	r.SSLStrict = ssl == "strict"
	ws, err := p.cf.GetZoneSetting(ctx, cfToken, rec.ZoneID, "websockets")
	if err != nil {
		return r, scrub(err, cfToken)
	}
	r.WebSockets = ws == "on"
	ref := rec.OriginRuleRef
	if ref == "" {
		ref = originRuleRef(rec.Hostname)
	}
	h, port, found, err := p.cf.OriginRule(ctx, cfToken, rec.ZoneID, ref)
	if err != nil {
		return r, scrub(err, cfToken)
	}
	wantPort := rec.OriginPort
	if wantPort == 0 {
		wantPort = relayports.CDNOrigin.Port
	}
	r.OriginRule = found && h == rec.Hostname && port == wantPort
	recs, err := p.cf.ListDNSRecords(ctx, cfToken, rec.ZoneID, rec.Hostname)
	if err != nil {
		return r, scrub(err, cfToken)
	}
	sawA := false
	r.DNSProxiedOnly = true
	for _, d := range recs {
		if d.Type == "A" || d.Type == "AAAA" {
			if !d.proxied() {
				r.DNSProxiedOnly = false
			}
			if d.Type == "A" {
				sawA = true
			}
		}
	}
	if !sawA {
		r.DNSProxiedOnly = false
		notes = append(notes, "no A record for the hostname")
	}
	r.FirewallEdgeRangesFresh = rec.FirewallID != ""
	r.ECH = p.readECH(ctx, cfToken, rec.ZoneID, rec.Hostname, ech, p.nowFn())
	r.NameHidden = r.ECH.NameHidden(rec.Hostname)
	if r.AOPEnabled && r.SSLStrict && r.WebSockets && r.OriginRule && r.DNSProxiedOnly {
		notes = append([]string{"cloudflare posture ok"}, notes...)
	} else {
		notes = append([]string{"cloudflare posture drift detected"}, notes...)
	}
	r.Notes = strings.Join(notes, "; ")
	return r, nil
}

// ---- removal ----

// RemoveStep is one line of a removal report.
type RemoveStep struct {
	Name   string `json:"name"`
	State  string `json:"state"` // done | failed | skipped
	Detail string `json:"detail,omitempty"`
}

// RemoveReport is what cdn-remove prints. Complete is true when no step
// failed; a step that failed is safe to retry with the same record.
type RemoveReport struct {
	Steps    []RemoveStep `json:"steps"`
	Complete bool         `json:"complete"`
}

func (r *RemoveReport) add(name string, err error, skipped bool, tok []byte) {
	s := RemoveStep{Name: name, State: "done"}
	switch {
	case skipped:
		s.State = "skipped"
	case err != nil:
		s.State, s.Detail = "failed", scrub(err, tok).Error()
	}
	r.Steps = append(r.Steps, s)
}

// Remove takes the Cloudflare side down: the DNS records Daal made, its
// origin rule, the Origin CA certificate, the origin-pull certificate,
// and the zone settings it changed (only where they still hold Daal's
// value). Every step is attempted even after one fails. Local
// certificate files go last, and only when the certificate they belong
// to was revoked.
func (p *Provider) Remove(ctx context.Context, cfToken []byte, rec *FrontRecord) (RemoveReport, error) {
	if rec == nil {
		return RemoveReport{}, fmt.Errorf("cloudflare: front record required")
	}
	if rec.ZoneID == "" || rec.Hostname == "" {
		return RemoveReport{}, fmt.Errorf("cloudflare: record has no zone or hostname")
	}
	var rep RemoveReport
	z := rec.ZoneID

	var dnsErr error
	for _, id := range rec.DNSRecordIDs {
		if err := p.cf.DeleteDNSRecord(ctx, cfToken, z, id); err != nil && dnsErr == nil {
			dnsErr = err
		}
	}
	rep.add("dns_records", dnsErr, len(rec.DNSRecordIDs) == 0, cfToken)

	ref := rec.OriginRuleRef
	if ref == "" {
		ref = originRuleRef(rec.Hostname)
	}
	rep.add("origin_rule", p.cf.RemoveOriginRule(ctx, cfToken, z, ref), false, cfToken)

	certErr := errors.New("no certificate id")
	if rec.OriginCertID != "" {
		certErr = p.cf.RevokeOriginCert(ctx, cfToken, rec.OriginCertID)
		rep.add("origin_certificate", certErr, false, cfToken)
	} else {
		rep.add("origin_certificate", nil, true, cfToken)
	}

	if rec.AOPCertID != "" {
		rep.add("origin_pull_certificate", p.cf.DeleteAOPCert(ctx, cfToken, z, rec.AOPCertID), false, cfToken)
	} else {
		rep.add("origin_pull_certificate", nil, true, cfToken)
	}

	rep.add("zone_settings", p.restoreSettings(ctx, cfToken, rec), len(rec.PriorSettings) == 0, cfToken)

	if certErr == nil {
		for _, f := range []string{rec.OriginCACertPath, rec.OriginCAPrivPath, rec.AOPCACertPath} {
			if f != "" {
				_ = os.Remove(f)
			}
		}
		rep.add("local_files", nil, false, cfToken)
	} else {
		rep.add("local_files", nil, true, cfToken)
	}

	rep.Complete = true
	for _, s := range rep.Steps {
		if s.State == "failed" {
			rep.Complete = false
		}
	}
	return rep, nil
}

// restoreSettings puts back each zone setting Daal changed, but only
// where it still holds the value Daal set: a publisher who changed it
// since then keeps their choice.
func (p *Provider) restoreSettings(ctx context.Context, tok []byte, rec *FrontRecord) error {
	set := map[string]string{"ssl": "strict", "websockets": "on"}
	var first error
	for name, ours := range set {
		was, ok := rec.PriorSettings[name]
		if !ok || was == "" || was == ours {
			continue
		}
		cur, err := p.cf.GetZoneSetting(ctx, tok, rec.ZoneID, name)
		if err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		if cur != ours {
			continue
		}
		if err := p.cf.SetZoneSetting(ctx, tok, rec.ZoneID, name, was); err != nil && first == nil {
			first = err
		}
	}
	if rec.PriorSettings["aop"] == "off" {
		on, err := p.cf.AOPEnabled(ctx, tok, rec.ZoneID)
		if err != nil {
			if first == nil {
				first = err
			}
		} else if on {
			if err := p.cf.SetAOPEnabled(ctx, tok, rec.ZoneID, false); err != nil && first == nil {
				first = err
			}
		}
	}
	return first
}
