package cloudflare

import "context"

// CFClient is the narrow Cloudflare API v4 surface the CDN add-on uses.
// Every call it makes needs one of exactly five zone permissions
// (docs/optional-addons-plan.md §2.5); nothing here touches an account
// resource, a Worker, billing or the registrar.
//
//	Zone — Zone — Read                 ListZones, LookupZone
//	Zone — DNS — Edit                  ListDNSRecords, EnsureProxiedRecords, SetDNSRecordContent, DeleteDNSRecord
//	Zone — SSL and Certificates — Edit IssueOriginCert, RevokeOriginCert, *AOP*
//	Zone — Zone Settings — Edit        GetZoneSetting, SetZoneSetting
//	Zone — Origin Rules — Edit         EnsureOriginRule, RemoveOriginRule, OriginRule
//
// VerifyToken and ProbeRead exist for the token scope check
// (CheckToken): VerifyToken needs no permission at all, and ProbeRead
// only ever issues GETs.
//
// The token travels in cfToken on every call. Implementations MUST NOT
// log, persist or echo it, and must keep it out of returned errors.
type CFClient interface {
	// VerifyToken is GET /user/tokens/verify: the token's own id and
	// status ("active", "disabled", "expired").
	VerifyToken(ctx context.Context, cfToken []byte) (TokenStatus, error)

	// ListZones lists every zone the token can see (all statuses).
	ListZones(ctx context.Context, cfToken []byte) ([]Zone, error)

	// LookupZone is GET /zones?name=<name>. found=false when the token
	// sees no zone of exactly that name.
	LookupZone(ctx context.Context, cfToken []byte, name string) (zone Zone, found bool, err error)

	// ProbeRead issues one GET and classifies the answer: 2xx is
	// ProbeAllowed, 401/403 ProbeDenied, 404 ProbeNotFound. Anything
	// else (5xx, network) is an error, never a verdict.
	ProbeRead(ctx context.Context, cfToken []byte, path string) (ProbeResult, error)

	// IssueOriginCert is POST /certificates with a locally generated
	// key and CSR. The private key never leaves this process except in
	// the returned OriginCert.
	IssueOriginCert(ctx context.Context, cfToken []byte, hostnames []string, validityDays int) (OriginCert, error)

	// RevokeOriginCert is DELETE /certificates/{id}.
	RevokeOriginCert(ctx context.Context, cfToken []byte, certID string) error

	// UploadAOPCert is POST /zones/{id}/origin_tls_client_auth: the
	// zone-level client certificate Cloudflare presents to the origin.
	// Returns Cloudflare's id for it.
	UploadAOPCert(ctx context.Context, cfToken []byte, zoneID string, certPEM, keyPEM []byte) (string, error)

	// DeleteAOPCert is DELETE /zones/{id}/origin_tls_client_auth/{cert}.
	DeleteAOPCert(ctx context.Context, cfToken []byte, zoneID, certID string) error

	// SetAOPEnabled / AOPEnabled are PUT / GET
	// /zones/{id}/origin_tls_client_auth/settings.
	SetAOPEnabled(ctx context.Context, cfToken []byte, zoneID string, enabled bool) error
	AOPEnabled(ctx context.Context, cfToken []byte, zoneID string) (bool, error)

	// GetZoneSetting / SetZoneSetting are GET / PATCH
	// /zones/{id}/settings/{name} with a string value ("ssl",
	// "websockets", "ech").
	GetZoneSetting(ctx context.Context, cfToken []byte, zoneID, name string) (string, error)
	SetZoneSetting(ctx context.Context, cfToken []byte, zoneID, name, value string) error

	// ListDNSRecords lists every record named hostname.
	ListDNSRecords(ctx context.Context, cfToken []byte, zoneID, hostname string) ([]DNSRecord, error)

	// EnsureProxiedRecords makes hostname a proxied A (and AAAA when
	// originIPv6 is set) record. It refuses ErrDNSOnlyRecordPresent
	// for an existing unproxied A/AAAA and ErrHostnameInUse for a
	// proxied one with other content; an identical proxied record is
	// reused. Returns the ids of the records it CREATED, so a rollback
	// or a removal deletes only what Daal made.
	EnsureProxiedRecords(ctx context.Context, cfToken []byte, zoneID, hostname, originIPv4, originIPv6 string) (createdIDs []string, err error)

	// SetDNSRecordContent re-points one existing proxied record (the
	// origin-only rotation). It never changes the name, type or proxy.
	SetDNSRecordContent(ctx context.Context, cfToken []byte, zoneID, recordID, content string) error

	// DeleteDNSRecord deletes one record. An absent record is success.
	DeleteDNSRecord(ctx context.Context, cfToken []byte, zoneID, recordID string) error

	// EnsureOriginRule puts one rule, identified by ref, into the
	// zone's http_request_origin entrypoint: requests whose host is
	// hostname go to the origin on port. Every rule with another ref is
	// kept as it was.
	EnsureOriginRule(ctx context.Context, cfToken []byte, zoneID, ref, hostname string, port int) error

	// RemoveOriginRule takes the ref'd rule out and keeps every other.
	// An absent rule or entrypoint is success.
	RemoveOriginRule(ctx context.Context, cfToken []byte, zoneID, ref string) error

	// OriginRule reads the ref'd rule back.
	OriginRule(ctx context.Context, cfToken []byte, zoneID, ref string) (hostname string, port int, found bool, err error)
}

// TokenStatus is what /user/tokens/verify says about the token itself.
type TokenStatus struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

// Zone is one zone the token can see.
type Zone struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Status    string `json:"status"`
	AccountID string `json:"account_id,omitempty"`
}

// ProbeResult classifies one read probe.
type ProbeResult int

const (
	ProbeDenied ProbeResult = iota
	ProbeAllowed
	ProbeNotFound
)

func (p ProbeResult) String() string {
	switch p {
	case ProbeAllowed:
		return "allowed"
	case ProbeNotFound:
		return "not_found"
	default:
		return "denied"
	}
}

// OriginCert is one issued Origin CA certificate.
type OriginCert struct {
	ID             string
	CertPEM        []byte
	KeyPEM         []byte
	FingerprintHex string
}

// DNSRecord is one DNS record as Cloudflare lists it.
type DNSRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Proxied *bool  `json:"proxied"`
}

func (r DNSRecord) proxied() bool { return r.Proxied != nil && *r.Proxied }
