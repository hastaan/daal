package cloudflare

import (
	"errors"
	"time"
)

// FrontRecord is the durable state for one Cloudflare-fronted way in
// (docs/optional-addons-plan.md §2). It is what `daal-deploy
// cdn-provision` prints, what the wizard keeps, and what every later
// verb (cdn-posture, cdn-test, cdn-remove, the rotations) reads back.
//
// It holds public metadata and provider ids only. The Cloudflare token
// lives in device custody; the Origin CA private key lives on disk under
// the out dir at mode 0600 and is named here by path, never inline; the
// Authenticated Origin Pull client key is generated, uploaded to
// Cloudflare and dropped — it is never written anywhere by Daal.
type FrontRecord struct {
	// Hostname is the proxied name recipients reach, `<label>.<zone>`.
	Hostname string `json:"hostname"`

	// Zone is the Cloudflare zone the hostname sits in, found by
	// walking the hostname's labels (FindZone). ZoneID and AccountID
	// are Cloudflare's ids for it.
	Zone      string `json:"zone"`
	ZoneID    string `json:"zone_id"`
	AccountID string `json:"account_id,omitempty"`

	// OriginPath is the WebSocket path the relay's ws-cdn-in inbound
	// serves: a random 16-byte value, the same for every recipient of
	// the route, rotated by re-signing. There is no Worker any more
	// (decision D-5), so the path recipients send is the path the relay
	// serves, and PublicPath always equals OriginPath. PublicPath is
	// kept because older callers read it.
	PublicPath string `json:"public_path"`
	OriginPath string `json:"origin_path"`

	// OriginPort is the relay port of ws-cdn-in
	// (relayports.CDNOrigin). The Origin Rule tells Cloudflare to dial
	// it; the relay firewall opens it to Cloudflare's ranges only.
	OriginPort int `json:"origin_port"`

	// WorkerRouteID is always empty. The path-rewrite Worker is gone
	// (decision D-5); the field stays so the wizard's existing JSON
	// shape still parses.
	WorkerRouteID string `json:"worker_route_id"`

	// FirewallID is the relay's own Hetzner firewall
	// (daal-relay-<server id>) that carries the Cloudflare-ranges rule
	// for OriginPort.
	FirewallID string `json:"firewall_id"`

	// OriginCAFingerprint is the hex SHA-256 of the Origin CA
	// certificate PEM; OriginCertID is Cloudflare's id for it (used to
	// revoke it on removal). The certificate covers the zone and
	// `*.<zone>`, so hostname rotation inside the zone needs no new one.
	OriginCAFingerprint string `json:"origin_ca_fingerprint"`
	OriginCertID        string `json:"origin_cert_id"`
	OriginCACertPath    string `json:"origin_ca_cert_path"`
	OriginCAPrivPath    string `json:"origin_ca_priv_path"`

	// AOPCACertPath is the CA certificate the relay verifies
	// Cloudflare's client certificate against (`client_authentication:
	// require-and-verify`). AOPCertID is Cloudflare's id for the zone's
	// uploaded client certificate. AOPClientCertPath is kept for the
	// old JSON shape and is always empty.
	AOPCACertPath     string `json:"aop_ca_cert_path"`
	AOPCertID         string `json:"aop_cert_id"`
	AOPClientCertPath string `json:"aop_client_cert_path"`
	AOPEnabled        bool   `json:"aop_enabled"`

	// DNSRecordIDs are the proxied A/AAAA records Daal created for
	// Hostname. Removal deletes exactly these.
	DNSRecordIDs []string `json:"dns_record_ids,omitempty"`

	// OriginRuleRef is the `ref` of the one rule Daal owns in the
	// zone's http_request_origin entrypoint. Rules without it are the
	// publisher's own and are never touched.
	OriginRuleRef string `json:"origin_rule_ref"`

	// PriorSettings are the zone settings as they were before Daal
	// changed them ("ssl", "websockets", "aop"). Removal restores a
	// setting only when it still holds the value Daal set.
	PriorSettings map[string]string `json:"prior_settings,omitempty"`

	// ECH is the posture read at provision time (zone setting and the
	// published HTTPS record). The binder copies ConfigListB64 into the
	// signed endpoint (B-4) and every freshness publish re-reads it.
	ECH ECHPosture `json:"ech"`

	// Freshness fields from FRP-8, unchanged.
	FreshnessURL  string `json:"freshness_url,omitempty"`
	FreshnessHost string `json:"freshness_host,omitempty"`

	// LastEdgeRefreshUnix is when the Cloudflare ranges were last
	// fetched and applied to the relay firewall.
	LastEdgeRefreshUnix int64 `json:"last_edge_refresh_unix,omitempty"`

	// EdgeRanges are the Cloudflare ranges (v4 then v6, as published)
	// that fetch opened the provider firewall to. They are public. The
	// door request carries them so the relay opens its box firewall to
	// the same set (daal-relay-mgmt /cdn), and the binder takes the
	// signed edge seeds from the v4 ones (EdgeSeedsFromRanges).
	EdgeRanges []string `json:"edge_ranges,omitempty"`
}

// CDNAttestation is the additive sub-object that lands inside the
// per-candidate `_relaypack` opaque blob. The validator (RP022/RP023)
// reads it; this package only fills it.
type CDNAttestation struct {
	OriginCAFingerprint string `json:"origin_ca_fingerprint"`
	AOPEnabled          bool   `json:"aop_enabled"`
	FirewallID          string `json:"firewall_id"`
	DNSOnlyPresent      bool   `json:"dns_only_present"`
}

// CloudflareOpts is the input to ProvisionFront. The token is passed in
// CFTokenSecret and never logged; the caller zeroizes it afterwards.
type CloudflareOpts struct {
	// Hostname is the proxied name to create. Empty with Zone set:
	// ProvisionFront picks a random label inside Zone.
	Hostname string

	// Zone is the zone to place a generated label in. Ignored when
	// Hostname is set (the zone is then found by walking its labels).
	Zone string

	// OriginIP / OriginIPv6 are the relay addresses the proxied
	// records point at. OriginIPv6 empty skips AAAA.
	OriginIP   string
	OriginIPv6 string

	// OriginPath is the relay's ws-cdn-in path. Empty: a fresh random
	// 16-byte path.
	OriginPath string

	// OriginPort is the relay port Cloudflare dials. Zero:
	// relayports.CDNOrigin.Port.
	OriginPort int

	// CFTokenSecret is the Cloudflare API token bytes.
	CFTokenSecret []byte

	// OutDir receives origin_ca.pem, origin_ca.key and aop_ca.pem.
	OutDir string

	// ECH, when set, reads the hostname's published ECH config over
	// DoH after the records exist. Nil skips that read; the zone
	// setting is read either way.
	ECH ECHFetcher

	// Now is the wall clock; tests inject a fixed time.
	Now func() time.Time
}

// PostureReport is what "cdn-posture" prints: the live state of the
// Cloudflare side, read-only. Every field is a read, never a guess;
// a field that could not be read is false and named in Notes.
type PostureReport struct {
	OriginCAFingerprintMatch bool `json:"origin_ca_fingerprint_match"`
	AOPEnabled               bool `json:"aop_enabled"`
	FirewallEdgeRangesFresh  bool `json:"firewall_edge_ranges_fresh"`
	DNSProxiedOnly           bool `json:"dns_proxied_only"`

	SSLStrict  bool `json:"ssl_strict"`
	WebSockets bool `json:"websockets"`
	OriginRule bool `json:"origin_rule"`

	// ECH is the zone setting plus what the hostname's HTTPS record
	// publishes. NameHidden is the card's "Name hidden: yes/no".
	ECH        ECHPosture `json:"ech"`
	NameHidden bool       `json:"name_hidden"`

	// OnlyCloudflare is the card's "Only Cloudflare can reach the
	// door": origin pull on with Daal's certificate, and the relay
	// firewall rule present. FirewallChecked is false when no
	// Hetzner token was given, in which case OnlyCloudflare is false.
	FirewallChecked bool `json:"firewall_checked"`
	OnlyCloudflare  bool `json:"only_cloudflare"`

	Notes string `json:"notes,omitempty"`
}

// Errors used across the package.
var (
	// ErrCFNotImplemented is reserved for optional providers.
	ErrCFNotImplemented = errors.New("cloudflare: API method not implemented")

	// ErrDNSOnlyRecordPresent: the hostname already has an A/AAAA
	// record that is not proxied. Refused (RP023).
	ErrDNSOnlyRecordPresent = errors.New("cloudflare: existing DNS-only A/AAAA record on subdomain (refusing per §11.7)")

	// ErrHostnameInUse: the hostname already has a proxied record
	// pointing somewhere else. Daal never re-points a record it did
	// not create.
	ErrHostnameInUse = errors.New("cloudflare: hostname already has a proxied record pointing elsewhere")

	// ErrZoneNotFound: no active zone the token can see contains the
	// hostname.
	ErrZoneNotFound = errors.New("cloudflare: no active zone the token can see contains this hostname")

	// ErrOriginCAIssueFailed / ErrAOPEnableFailed wrap the provider's
	// answer for the two certificate steps.
	ErrOriginCAIssueFailed = errors.New("cloudflare: origin CA cert issuance failed")
	ErrAOPEnableFailed     = errors.New("cloudflare: enable Authenticated Origin Pulls failed")

	// ErrWorkerRemoved answers the old public-path rotation. There is
	// no Worker (decision D-5): the path is the relay's own, so moving
	// it is a relay change plus a re-sign, not a Cloudflare call.
	ErrWorkerRemoved = errors.New("cloudflare: there is no path-rewrite Worker any more; the WebSocket path is the relay's own and moves by changing the relay and re-signing")

	// ErrCrossZoneRotation: a hostname in another zone needs its own
	// certificate, origin pull and token, i.e. the add-on built again.
	ErrCrossZoneRotation = errors.New("cloudflare: the new hostname is in a different zone; build the way in again for that zone")
)
