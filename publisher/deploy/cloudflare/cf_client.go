package cloudflare

import "context"

// CFClient is the narrow Cloudflare API surface FRP-8 exercises.
// It exists so the publisher/deploy/cloudflare package can be
// independently built, tested, and exercised against a mock. The
// live impl lives at cf_client_live.go and talks to Cloudflare's
// v4 API from the Helper machine only.
//
// All methods take a context.Context and use it for cancellation.
// Methods MUST NOT log, persist, or otherwise leak the API token;
// the bytes flow through cfToken parameters only and are zeroized
// by the caller after the operation completes.
type CFClient interface {
	// IssueOriginCert provisions a Cloudflare-issued Origin CA
	// cert valid for `validityDays` (Cloudflare default = 5475
	// days = 15 years). Returns PEM-encoded cert + PEM-encoded
	// privkey. The caller writes them to disk at mode 0600.
	IssueOriginCert(ctx context.Context, cfToken []byte, hostnames []string, validityDays int) (certPEM, privPEM []byte, fingerprintHex string, err error)

	// EnableAOP toggles Zone.Settings.AuthenticatedOriginPulls
	// to true on the supplied zone. Idempotent.
	EnableAOP(ctx context.Context, cfToken []byte, zoneID string) error

	// FetchAOPClientCert returns the Cloudflare-signed client
	// certificate (PEM) the origin must present back to
	// Cloudflare's edge under AOP. The caller deploys it to
	// the origin via cloud-init.
	FetchAOPClientCert(ctx context.Context, cfToken []byte, zoneID string) (certPEM []byte, err error)

	// EnsureProxiedRecords creates / updates proxied A + AAAA
	// records pointing at originIPv4 (and originIPv6 if
	// non-empty). If any non-proxied A or AAAA record already
	// exists on the chosen hostname, returns
	// ErrDNSOnlyRecordPresent — the caller (wizard) MUST
	// refuse to proceed.
	EnsureProxiedRecords(ctx context.Context, cfToken []byte, zoneID, hostname, originIPv4, originIPv6 string) error

	// UploadWorkerScript uploads the FRP-8 path-rewrite Worker
	// script bytes under the supplied scriptName. Returns the
	// route ID for the binding the FRP can use to attach the
	// script to a route pattern.
	UploadWorkerScript(ctx context.Context, cfToken []byte, accountID, scriptName string, scriptBody []byte) (scriptID string, err error)

	// BindWorkerRoute binds the worker scriptID to the
	// `pattern` (e.g. "frp.example.com/r/8c1f4a23"). Returns
	// the route ID, idempotent on repeated calls.
	BindWorkerRoute(ctx context.Context, cfToken []byte, zoneID, scriptName, pattern string) (routeID string, err error)

	// LookupZoneID resolves an FRP-supplied apex domain into
	// a zone ID. Surfaced so the wizard can validate the
	// FRP's CF token actually controls the chosen domain.
	LookupZoneID(ctx context.Context, cfToken []byte, apexDomain string) (zoneID, accountID string, err error)

	// VerifyPosture re-reads the live Cloudflare state for
	// the supplied FrontRecord and reports drift. The wizard
	// "Verify CDN posture" button calls this. The CFClient
	// is the ONLY place that talks to the Cloudflare API for
	// posture re-verification — the validator never calls
	// Cloudflare.
	VerifyPosture(ctx context.Context, cfToken []byte, rec *FrontRecord) (PostureReport, error)

	// FRP-9 rotation surface. These methods implement the
	// supplement §14.4 cdn_fronted-mode rotation table.
	// Public-surface rotations (path / hostname) require the
	// caller to re-sign the RelayPack and re-publish the
	// freshness document afterwards. Origin-only rotation
	// stays invisible to the family — the RelayPack is NOT
	// re-signed; only the Cloudflare origin pointer + DNS
	// content + (Helper-side) firewall + cert posture move.

	// RotatePublicPath updates the worker route binding so
	// the visible random path becomes newPublicPath. The
	// stable origin path is unchanged. Returns the (possibly
	// new) routeID. Idempotent on retry.
	RotatePublicPath(ctx context.Context, cfToken []byte, zoneID, oldRouteID, scriptName, hostname, newPublicPath, originPath string) (newRouteID string, err error)

	// RotateHostname migrates the proxied DNS records to
	// newHostname. The caller is responsible for re-uploading
	// the rewrite Worker on the new hostname pattern (handled
	// by Provider.RotateHostname). Returns the new
	// FrontRecord shape (Hostname, ZoneID, WorkerRouteID
	// updated). The validator's RP023 check still applies:
	// if the new hostname has any DNS-only A/AAAA record
	// EnsureProxiedRecords surfaces ErrDNSOnlyRecordPresent.
	RotateHostname(ctx context.Context, cfToken []byte, oldRec *FrontRecord, newHostname, originIPv4, originIPv6 string) (newZoneID, newAccountID string, err error)

	// RotateOrigin re-points the proxied A / AAAA records at
	// a new origin IP. Hostname and public path are unchanged
	// — this is the supplement §14.4 origin-only path. The
	// caller MUST NOT re-sign the RelayPack; from the
	// censor's vantage the public surface is byte-identical.
	// Returns nil on success.
	RotateOrigin(ctx context.Context, cfToken []byte, zoneID, hostname, newOriginIPv4, newOriginIPv6 string) error
}
