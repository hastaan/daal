package sni

import (
	"fmt"
	"strings"
	"time"
)

// ---------------------------------------------------------------------
// THE RULE
// ---------------------------------------------------------------------
//
// This file is the deliverable. The hostnames in pool.go are not: they
// have a shelf life of months and are meant to be swapped without any
// discussion. What must survive is the predicate below — the set of
// properties a cover host has to have before a Daal relay is allowed to
// advertise it.
//
// A REALITY cover SNI is the only plaintext a censor sees on the wire.
// It is compared, implicitly, against the one other thing the censor
// knows for free: which AS the packet is going to. The whole game is
// making that pair unremarkable.
//
// R1  SYNTACTIC. A lowercase, fully-qualified DNS name: 2+ labels, each
//     1..63 bytes of [a-z0-9-] not starting or ending in '-', total
//     <= 253 bytes, no trailing dot, no wildcard, no IP literal, no
//     port. sing-box will happily accept garbage here and fail at
//     handshake time on the box, hours after provisioning.
//
// R2  TLS 1.3 + ALPN h2, measured. REALITY steals a real handshake from
//     the cover host; a host that negotiates TLS 1.2, or refuses h2,
//     produces a handshake that does not look like the one the client
//     claims to be making. This is not a preference, it is the protocol.
//
// R3  NOT BEHIND A BLANKET-BLOCKED CDN. This is the bug Wave 2 exists to
//     fix. Every Daal relay shipped `www.cloudflare.com`, and Irancell
//     blocked all Cloudflare IP space on 16 Apr 2023 while SNI-conditional
//     blocking on CF addresses was already observed in Oct 2022. A cover
//     host that lives behind a CDN the target country blanket-blocks
//     converts one censor action into a fleet-wide outage. Encoded twice,
//     deliberately: as HostingClass (a global CDN is never admissible)
//     and as an explicit suffix deny-list (BlanketBlockedSuffixes), so a
//     mis-declared entry still gets caught.
//
// R4  PLAUSIBLE FOR THE *SERVER*, NOT FOR A PHONE. The client of record
//     is a rented Linux box in a commercial datacenter. `www.apple.com`
//     from a Hetzner /32 is anomalous on its face; a distribution mirror
//     is what such a box actually opens TLS to, in volume, at all hours,
//     for long-lived transfers. Encoded as Purpose.
//
// R5  ASN-CLASS MATCH — and read the second paragraph, because the rule
//     is weaker than its name. The corpus's avoid-list ends with "any
//     TLS proxy whose IP-to-SNI mapping is obviously implausible". A
//     cover host served out of hosting/colo/research AS space is the
//     same KIND of thing on the same KIND of network as a rented VPS; a
//     global anycast CDN name provably is not, because that CDN does not
//     serve from Hetzner. So the pool admits hostingProvider and
//     researchNetwork and nothing else.
//
//     What this does NOT buy, stated plainly: not one pool entry
//     announces from a relay provider's own AS. The table is
//     AS28753/AS8560/AS3214/AS8648/AS12306/AS13030 and friends, while
//     Daal's relays live in Hetzner AS24940, Vultr AS20473, Stark. So a
//     resolver-side check — "does this SNI's A record sit anywhere near
//     the packet's destination?" — still flags 100% of relays. R5
//     defeats the crude version of the implausibility test (a consumer
//     CDN name from a datacentre) and not the precise one.
//
//     The obvious repair is a per-provider entry so at least one
//     candidate makes the mapping literally true. It was attempted:
//     mirror.hetzner.de does announce from AS24940, but it does not
//     complete a TLS handshake from outside Hetzner (probed 2026-08-17:
//     no TCP on 80 or 443), so it fails R2 and must not be listed. Do
//     not add it back from the ASN alone — that is exactly the
//     "filling the evidence fields in from memory" this file forbids.
//     Anyone with a probe host that CAN reach it should re-measure and
//     add it keyed by provider.
//
// R6  PEERING NEIGHBOURHOOD. The host must be one the relay's own region
//     would plausibly reach across a short path — same continent, same
//     IXP mesh. Encoded as Zone; Pick never crosses zones unless the
//     region is unknown.
//
// R7  DATED. Every field above is a measurement, not an opinion, and
//     measurements rot. Each entry records the day it was measured; a
//     test fails once the pool is older than ShelfLife so nobody ships a
//     year-old claim about somebody else's TLS stack.
//
// What the rule deliberately does NOT encode: "is it blocked inside
// Iran?". That cannot be measured from the publisher's machine and a
// hard-coded answer would be a lie with a shelf life of days. It is an
// audit step in the refresh procedure (see pool.go) and nothing more.

// ShelfLife is how long a pool audit is allowed to stand before the
// pool is considered stale. Twelve months is not a safety property — it
// is the point at which the claims in pool.go stop being evidence.
const ShelfLife = 365 * 24 * time.Hour

// Zone is a coarse peering neighbourhood. Coarser than a region on
// purpose: "same continent, same IXP mesh" is a claim the publisher can
// actually defend, whereas "same metro" is not, and a zone with two
// entries in it is a fleet-wide signature waiting to happen.
type Zone string

const (
	ZoneEUCentral Zone = "eu-central" // DE/NL/FR/CH/AT/PL/UK — DE-CIX / AMS-IX / LINX mesh
	ZoneEUNorth   Zone = "eu-north"   // FI/SE/DK/NO/EE/LV/LT — Netnod / FICIX mesh
	ZoneUSEast    Zone = "us-east"    // Ashburn / NYC / Miami / Toronto
	ZoneUSWest    Zone = "us-west"    // Hillsboro / SJC / LAX / SEA
	ZoneAPAC      Zone = "apac"       // SIN / HKG / NRT / SYD

	// ZoneAny is what an unrecognised region resolves to. It widens
	// Pick to the whole admissible pool rather than failing: a relay
	// with a slightly-implausible cover host is strictly better than a
	// relay that still ships the fleet-wide constant.
	ZoneAny Zone = ""
)

// Zones lists every real zone (ZoneAny excluded). Tests walk it.
var Zones = []Zone{ZoneEUCentral, ZoneEUNorth, ZoneUSEast, ZoneUSWest, ZoneAPAC}

// HostingClass is how the cover host's own address is served. R5: only
// classes that plausibly share an address *class* with a rented VPS are
// admissible.
type HostingClass string

const (
	// HostingProvider — served from a commercial hosting/colo AS
	// (Leaseweb, IONOS, xTom, Init7…). Best case: the cover host and
	// the relay are the same kind of thing on the same kind of network.
	HostingProvider HostingClass = "hosting-provider"

	// HostingResearchNet — served from a university or NREN AS (DFN,
	// LIUnet, AARNet, MIT). Also fine: research networks run big public
	// mirrors from static address space, which is what we are imitating.
	HostingResearchNet HostingClass = "research-network"

	// HostingGlobalCDN — anycast edge (Cloudflare, Fastly, Akamai,
	// CloudFront). NEVER admissible. Two independent reasons: the target
	// country blanket-blocks at least one of these (R3), and such a name
	// can never plausibly resolve to the relay's address (R5).
	HostingGlobalCDN HostingClass = "global-cdn"
)

// Purpose is what the host is *for*. R4.
type Purpose string

const (
	// PurposeSoftwareMirror — a public package/ISO/source mirror. The
	// archetypal destination for a Linux server's outbound TLS: high
	// volume, long-lived, boring, and expected at any hour.
	PurposeSoftwareMirror Purpose = "software-mirror"

	// PurposeProviderService — a hosting provider's own docs/status/API
	// surface. Plausible for a box in that provider's AS, but low
	// volume and short-lived, so it is a weaker imitation. Admissible;
	// currently unused. Kept so the pool can diversify away from being
	// 100% mirrors (see the "known weakness" note in pool.go).
	PurposeProviderService Purpose = "provider-service"
)

// admissiblePurposes is R4 as a set.
var admissiblePurposes = map[Purpose]bool{
	PurposeSoftwareMirror:  true,
	PurposeProviderService: true,
}

// BlanketBlockedSuffixes are domains whose *entire* infrastructure a
// target country has been observed to block wholesale. R3's belt to
// HostingClass's braces: an entry that lies about its HostingClass still
// cannot smuggle one of these in.
//
// Cloudflare: Irancell blocked all Cloudflare IP space on 16 Apr 2023;
// SNI-conditional blocking on Cloudflare addresses was observed from
// Oct 2022. This is the exact string every Daal relay shipped until
// Wave 2.
var BlanketBlockedSuffixes = []string{
	"cloudflare.com",
	"cloudflare.net",
	"cloudflare-dns.com",
	"cdn.cloudflare.net",
}

// LegacyCoverSNI is the fleet-wide constant every relay provisioned
// before Wave 2 advertises. It exists here for exactly one purpose: so
// the provisioner can describe an OLD box truthfully when it re-reads a
// record that predates the cover_sni field. It is never picked, and
// Admit rejects it — a test pins both facts.
const LegacyCoverSNI = "www.cloudflare.com"

// Entry is one pool member plus the evidence for admitting it. Every
// non-Host field is a measurement taken on AuditedOn by the procedure in
// pool.go; none of it is inferred at runtime.
type Entry struct {
	// Host is the name the relay advertises and dials back to.
	Host string

	// Zone is the peering neighbourhood this host belongs to (R6).
	Zone Zone

	// ASN / ASName are the origin AS of Host's A record on AuditedOn.
	// Recorded so a re-audit can tell "the host moved" from "the host
	// is gone", and so R5 is checkable by a human without a lookup.
	ASN    uint32
	ASName string

	// Hosting is R5's classification of ASN.
	Hosting HostingClass

	// Purpose is R4's classification of the site.
	Purpose Purpose

	// TLS13 and H2 are R2, measured with:
	//   openssl s_client -connect HOST:443 -servername HOST -tls1_3 -alpn h2
	TLS13 bool
	H2    bool

	// AuditedOn is the YYYY-MM-DD the four fields above were measured.
	AuditedOn string
}

// Admit reports why an entry may not enter the pool, or nil if it may.
// It is the whole rule in executable form: pool_test.go runs it over
// every entry, and Pick runs it again at selection time so a bad edit
// cannot reach a relay even if someone skips the tests.
func Admit(e Entry) error {
	if err := ValidHost(e.Host); err != nil { // R1
		return err
	}
	if !e.TLS13 { // R2
		return fmt.Errorf("sni: %s: no TLS 1.3 recorded", e.Host)
	}
	if !e.H2 { // R2
		return fmt.Errorf("sni: %s: no ALPN h2 recorded", e.Host)
	}
	switch e.Hosting { // R3 + R5
	case HostingProvider, HostingResearchNet:
	case HostingGlobalCDN:
		return fmt.Errorf("sni: %s: served by a global CDN — a censor that blocks the CDN blocks the whole fleet", e.Host)
	default:
		return fmt.Errorf("sni: %s: unknown hosting class %q", e.Host, e.Hosting)
	}
	if e.ASN == 0 { // R5 — an unrecorded AS is an unverified claim
		return fmt.Errorf("sni: %s: no origin ASN recorded", e.Host)
	}
	if !admissiblePurposes[e.Purpose] { // R4
		return fmt.Errorf("sni: %s: purpose %q is not something a datacenter plausibly dials", e.Host, e.Purpose)
	}
	if e.Zone == ZoneAny { // R6 — every entry belongs somewhere
		return fmt.Errorf("sni: %s: no zone", e.Host)
	}
	if !slicesContainsZone(Zones, e.Zone) {
		return fmt.Errorf("sni: %s: unknown zone %q", e.Host, e.Zone)
	}
	if _, err := time.Parse("2006-01-02", e.AuditedOn); err != nil { // R7
		return fmt.Errorf("sni: %s: audited_on %q is not YYYY-MM-DD", e.Host, e.AuditedOn)
	}
	return nil
}

// ValidHost is R1 plus R3's suffix deny-list. Exported because the
// provisioner runs it over operator-supplied and persisted values,
// which never went through Admit.
func ValidHost(host string) error {
	if host == "" {
		return fmt.Errorf("sni: empty cover host")
	}
	if host != strings.ToLower(host) {
		return fmt.Errorf("sni: %q: cover host must be lowercase", host)
	}
	if len(host) > 253 {
		return fmt.Errorf("sni: %q: cover host longer than 253 bytes", host)
	}
	if strings.HasSuffix(host, ".") {
		return fmt.Errorf("sni: %q: cover host must not be a rooted name", host)
	}
	if strings.ContainsAny(host, ":/ *_") {
		return fmt.Errorf("sni: %q: cover host must be a bare hostname (no scheme, port, path or wildcard)", host)
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return fmt.Errorf("sni: %q: cover host must be fully qualified", host)
	}
	allNumeric := true
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return fmt.Errorf("sni: %q: bad DNS label %q", host, l)
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return fmt.Errorf("sni: %q: DNS label %q starts or ends with '-'", host, l)
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'
			if !ok {
				return fmt.Errorf("sni: %q: DNS label %q has illegal byte %q", host, l, string(c))
			}
			if c < '0' || c > '9' {
				allNumeric = false
			}
		}
	}
	if allNumeric {
		// An IP literal in server_name is both illegal per RFC 6066 and
		// a loud anomaly. REALITY needs a name.
		return fmt.Errorf("sni: %q: cover host must be a name, not an IP literal", host)
	}
	for _, bad := range BlanketBlockedSuffixes {
		if host == bad || strings.HasSuffix(host, "."+bad) {
			return fmt.Errorf("sni: %q: %s is blanket-blocked in the target country; using it burns every relay at once", host, bad)
		}
	}
	return nil
}

func slicesContainsZone(zs []Zone, z Zone) bool {
	for _, c := range zs {
		if c == z {
			return true
		}
	}
	return false
}
