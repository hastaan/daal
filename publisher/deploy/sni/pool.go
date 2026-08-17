// Package sni chooses the REALITY cover hostname a provisioned relay
// advertises, one value per relay, from an auditable pool.
//
// Why this package exists. Until Wave 2 every Daal relay on earth
// advertised the same compile-time constant, `www.cloudflare.com`, on a
// Hetzner address, and hard-coded it into cloud-init in both
// `tls.server_name` and `reality.handshake.server`. That is a single
// free string match away from burning the whole fleet in one action, and
// it is exactly the mapping the corpus's avoid-list ends on: "any TLS
// proxy whose IP-to-SNI mapping is obviously implausible". Per-relay
// selection turns one fleet-wide bet into N independent ones.
//
// The rule that governs what may enter the pool lives in rule.go and is
// the actual deliverable. The table below is perishable.
//
// # Refreshing the pool
//
// Do this at least once a year (a test fails at ShelfLife), after any
// report that a listed host has been blocked, and whenever a new region
// is added to a provider's SupportedRegions.
//
//  1. Probe every candidate from a machine outside the target country:
//
//     ip=$(getent ahostsv4 "$h" | awk '{print $1; exit}')
//     rev=$(echo "$ip" | awk -F. '{print $4"."$3"."$2"."$1}')
//     dig +short "${rev}.origin.asn.cymru.com" TXT      # origin ASN
//     dig +short "AS<n>.asn.cymru.com" TXT              # AS name/country
//     openssl s_client -connect "$h:443" -servername "$h" -tls1_3 -alpn h2 </dev/null
//
//     Keep a host only if the handshake prints both `TLSv1.3` and
//     `ALPN protocol: h2`. Record the ASN and AS name verbatim.
//
//  2. Classify. HostingProvider or HostingResearchNet only; anything
//     answering from Cloudflare (AS13335), Fastly (AS54113), Akamai
//     (AS20940/AS16625) or CloudFront (AS16509 edge) is out by R3/R5 —
//     including hosts that merely *moved* behind a CDN since the last
//     audit, which is the most common way an entry silently rots.
//
//  3. Check the target country's blocklist for each surviving host. This
//     is the one thing the code cannot check for itself: consult OONI
//     measurements (https://explorer.ooni.org) for the target country
//     and drop anything with recent confirmed blocking. Then re-check
//     that no entry is a domain the country would have political reason
//     to block — mirrors are dull for a reason.
//
//  4. Set AuditedOn to the probe date on every entry you touched, delete
//     the ones that failed, and run `go test ./publisher/deploy/sni/...`.
//     The tests enforce the rule, the per-zone minimum and the shelf life;
//     they do not enforce the specific names, so swapping the whole table
//     is a one-commit change.
//
// # Known weakness
//
// Two, and the second is not obvious.
//
//  1. Every current entry is PurposeSoftwareMirror. That is the most
//     plausible destination for a rented Linux box, but if the pool
//     stays 100% mirrors then "REALITY handshake to a distribution
//     mirror" is itself a Daal-shaped signal. PurposeProviderService
//     exists so the next audit can dilute that; widening it is a pool
//     edit, not a code change.
//
//  2. THE MAPPING IS PUBLICLY COMPUTABLE, not secret. Pick's seed is
//     the derived server name, `daal-<region>-<hex8 of the publisher's
//     public key>`, and that public key ships inside every distributed
//     .sbp. So anyone who receives ONE pack — a recipient, or whoever
//     the pack reaches after them — can derive that publisher's cover
//     host in every region without ever seeing a relay. Add that the
//     table itself is 21 obscure mirrors in a public repository, 6 of
//     them in the zone the default Hetzner regions land in, and
//     blocking every one of them by SNI costs an Iranian user nothing.
//
//     So be precise about what Wave 2 bought here. Against INCIDENTAL
//     collateral blocking — the Irancell all-Cloudflare-IPs event of
//     16 Apr 2023, which is the motivating incident — it is a real win:
//     these hosts are not in anybody's blast radius. Against an
//     adversary who reads this repository or joins one distribution
//     channel, it converts one string match into six, which is better
//     than one and is not a defence.
//
//     Raising that cost is a pool-and-seed change, not a rule change:
//     many more entries per zone, a Purpose mix (see 1), an
//     operator-supplied override so two publishers do not draw from an
//     identical public table, and a seed that is a per-relay secret
//     persisted in the OperatorRecord rather than a value every
//     recipient can recompute.
package sni

import (
	"crypto/sha256"
	"encoding/binary"
	"sort"
	"strings"
	"sync"
	"time"
)

// MinPerZone is the smallest number of admissible entries a zone may
// have before the pool stops providing meaningful per-relay diversity.
// Three is not a lot; it is the floor a test refuses to go under.
const MinPerZone = 3

// pool is the current cover-host table.
//
// Every row was probed on 2026-08-17 from outside the target country
// with the commands in the package doc: A record → origin ASN via Team
// Cymru → `openssl s_client -tls1_3 -alpn h2`. Every row printed both
// TLSv1.3 and `ALPN protocol: h2`, and every origin AS is a hosting,
// colo or research network — none is a CDN edge.
//
// Do not add a host you have not personally probed. The point of the
// ASN/TLS13/H2/AuditedOn fields is that they are evidence; filling them
// in from memory turns the whole file back into the constant it replaced.
var pool = []Entry{
	// ---- eu-central: DE-CIX / AMS-IX / LINX mesh ----------------------
	// The default neighbourhood: Hetzner fsn1/nbg1, Vultr fra/ams/par/lhr.
	// Leaseweb, IONOS, xTom, dogado, Plus.line and Init7 all run public
	// mirrors out of the same commercial address space Daal's relays are
	// rented from — the closest an IP-to-SNI mapping gets to plausible.
	{Host: "mirror.de.leaseweb.net", Zone: ZoneEUCentral, ASN: 28753, ASName: "LEASEWEB-DE-FRA-10, DE", Hosting: HostingProvider, Purpose: PurposeSoftwareMirror, TLS13: true, H2: true, AuditedOn: "2026-08-17"},
	{Host: "mirror.eu.oneandone.net", Zone: ZoneEUCentral, ASN: 8560, ASName: "IONOS-AS, DE", Hosting: HostingProvider, Purpose: PurposeSoftwareMirror, TLS13: true, H2: true, AuditedOn: "2026-08-17"},
	{Host: "mirror.xtom.de", Zone: ZoneEUCentral, ASN: 3214, ASName: "XTOM, DE", Hosting: HostingProvider, Purpose: PurposeSoftwareMirror, TLS13: true, H2: true, AuditedOn: "2026-08-17"},
	{Host: "mirror.dogado.de", Zone: ZoneEUCentral, ASN: 8648, ASName: "ONE-NETWORK dogado GmbH, DE", Hosting: HostingProvider, Purpose: PurposeSoftwareMirror, TLS13: true, H2: true, AuditedOn: "2026-08-17"},
	{Host: "ftp.plusline.net", Zone: ZoneEUCentral, ASN: 12306, ASName: "PLUSLINE Plus.line AG, DE", Hosting: HostingProvider, Purpose: PurposeSoftwareMirror, TLS13: true, H2: true, AuditedOn: "2026-08-17"},
	{Host: "mirror.init7.net", Zone: ZoneEUCentral, ASN: 13030, ASName: "INIT7, CH", Hosting: HostingProvider, Purpose: PurposeSoftwareMirror, TLS13: true, H2: true, AuditedOn: "2026-08-17"},

	// ---- eu-north: Netnod / FICIX mesh --------------------------------
	// Hetzner hel1, Vultr sto, Stark vno/kun. Baltic transit runs through
	// Stockholm and Warsaw, so the Nordic mirrors are the short path.
	{Host: "mirrors.dotsrc.org", Zone: ZoneEUNorth, ASN: 1835, ASName: "FSKNET-DK, DK", Hosting: HostingResearchNet, Purpose: PurposeSoftwareMirror, TLS13: true, H2: true, AuditedOn: "2026-08-17"},
	{Host: "ftp.lysator.liu.se", Zone: ZoneEUNorth, ASN: 2843, ASName: "LIUnet, SE", Hosting: HostingResearchNet, Purpose: PurposeSoftwareMirror, TLS13: true, H2: true, AuditedOn: "2026-08-17"},
	{Host: "mirror.nsc.liu.se", Zone: ZoneEUNorth, ASN: 2843, ASName: "LIUnet, SE", Hosting: HostingResearchNet, Purpose: PurposeSoftwareMirror, TLS13: true, H2: true, AuditedOn: "2026-08-17"},
	{Host: "mirror.bahnhof.net", Zone: ZoneEUNorth, ASN: 8473, ASName: "BAHNHOF, SE", Hosting: HostingProvider, Purpose: PurposeSoftwareMirror, TLS13: true, H2: true, AuditedOn: "2026-08-17"},

	// ---- us-east ------------------------------------------------------
	// Hetzner ash.
	{Host: "mirror.wdc1.us.leaseweb.net", Zone: ZoneUSEast, ASN: 30633, ASName: "LEASEWEB-USA-WDC, US", Hosting: HostingProvider, Purpose: PurposeSoftwareMirror, TLS13: true, H2: true, AuditedOn: "2026-08-17"},
	{Host: "mirror.us.oneandone.net", Zone: ZoneUSEast, ASN: 8560, ASName: "IONOS-AS (US footprint)", Hosting: HostingProvider, Purpose: PurposeSoftwareMirror, TLS13: true, H2: true, AuditedOn: "2026-08-17"},
	{Host: "mirrors.kernel.org", Zone: ZoneUSEast, ASN: 7979, ASName: "SERVERS-COM, US", Hosting: HostingProvider, Purpose: PurposeSoftwareMirror, TLS13: true, H2: true, AuditedOn: "2026-08-17"},
	{Host: "mirrors.mit.edu", Zone: ZoneUSEast, ASN: 3, ASName: "MIT-GATEWAYS, US", Hosting: HostingResearchNet, Purpose: PurposeSoftwareMirror, TLS13: true, H2: true, AuditedOn: "2026-08-17"},

	// ---- us-west ------------------------------------------------------
	// Hetzner hil.
	{Host: "mirror.sfo12.us.leaseweb.net", Zone: ZoneUSWest, ASN: 7203, ASName: "LEASEWEB-USA-SFO, US", Hosting: HostingProvider, Purpose: PurposeSoftwareMirror, TLS13: true, H2: true, AuditedOn: "2026-08-17"},
	{Host: "mirrors.ocf.berkeley.edu", Zone: ZoneUSWest, ASN: 25, ASName: "UCB, US", Hosting: HostingResearchNet, Purpose: PurposeSoftwareMirror, TLS13: true, H2: true, AuditedOn: "2026-08-17"},
	{Host: "mirror.arizona.edu", Zone: ZoneUSWest, ASN: 1706, ASName: "UNIV-ARIZ, US", Hosting: HostingResearchNet, Purpose: PurposeSoftwareMirror, TLS13: true, H2: true, AuditedOn: "2026-08-17"},

	// ---- apac ---------------------------------------------------------
	// Hetzner sin.
	{Host: "mirror.sg.leaseweb.net", Zone: ZoneAPAC, ASN: 59253, ASName: "LEASEWEB-APAC-SIN-11, SG", Hosting: HostingProvider, Purpose: PurposeSoftwareMirror, TLS13: true, H2: true, AuditedOn: "2026-08-17"},
	{Host: "mirror.xtom.sg", Zone: ZoneAPAC, ASN: 8888, ASName: "XTOM (SG PoP)", Hosting: HostingProvider, Purpose: PurposeSoftwareMirror, TLS13: true, H2: true, AuditedOn: "2026-08-17"},
	{Host: "mirror.sg.gs", Zone: ZoneAPAC, ASN: 24482, ASName: "SGGS-AS-AP, SG", Hosting: HostingProvider, Purpose: PurposeSoftwareMirror, TLS13: true, H2: true, AuditedOn: "2026-08-17"},
	{Host: "mirror.aarnet.edu.au", Zone: ZoneAPAC, ASN: 7575, ASName: "AARNET-AS-AP, AU", Hosting: HostingResearchNet, Purpose: PurposeSoftwareMirror, TLS13: true, H2: true, AuditedOn: "2026-08-17"},
}

// regionZones maps every provider region code the wizard can offer onto
// a peering neighbourhood. Codes collide across providers on purpose
// (Vultr and Stark both call Frankfurt "fra") — they mean the same
// place, so one table is correct.
//
// A code that is not here resolves to ZoneAny and Pick widens to the
// whole pool. That is deliberate: an unrecognised region must never be
// a reason to fall back to a fleet-wide constant.
var regionZones = map[string]Zone{
	// Hetzner
	"fsn1": ZoneEUCentral, // Falkenstein
	"nbg1": ZoneEUCentral, // Nuremberg
	"hel1": ZoneEUNorth,   // Helsinki
	"ash":  ZoneUSEast,    // Ashburn
	"hil":  ZoneUSWest,    // Hillsboro
	"sin":  ZoneAPAC,      // Singapore
	// Vultr
	"fra": ZoneEUCentral, // Frankfurt (also Stark's fallback region)
	"ams": ZoneEUCentral, // Amsterdam
	"lhr": ZoneEUCentral, // London — LINX sits in the same mesh
	"par": ZoneEUCentral, // Paris
	"waw": ZoneEUCentral, // Warsaw
	"sto": ZoneEUNorth,   // Stockholm
	"ewr": ZoneUSEast,    // New Jersey
	"nyc": ZoneUSEast,
	"iad": ZoneUSEast,
	"mia": ZoneUSEast,
	"tor": ZoneUSEast,
	"sjc": ZoneUSWest,
	"lax": ZoneUSWest,
	"sea": ZoneUSWest,
	"sgp": ZoneAPAC,
	"nrt": ZoneAPAC,
	"hkg": ZoneAPAC,
	"syd": ZoneAPAC,
	// Stark
	"vno": ZoneEUNorth, // Vilnius — transits via Stockholm/Warsaw
	"kun": ZoneEUNorth, // Kaunas
}

// ZoneFor maps a provider region code to its peering neighbourhood.
// Unknown regions get ZoneAny (the whole pool), never an error.
func ZoneFor(region string) Zone {
	if z, ok := regionZones[strings.ToLower(strings.TrimSpace(region))]; ok {
		return z
	}
	return ZoneAny
}

// admissible is the pool filtered through Admit, computed once. Pick
// re-applies the rule at selection time rather than trusting the table,
// so a bad hand-edit cannot reach a relay even if the tests are skipped.
var admissible = sync.OnceValue(func() []Entry {
	out := make([]Entry, 0, len(pool))
	for _, e := range pool {
		if Admit(e) == nil {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
})

// Admissible returns every pool entry that satisfies the rule, sorted by
// host. Exported for tests and for the wizard, which shows the operator
// what their relay could be advertising.
func Admissible() []Entry {
	return append([]Entry(nil), admissible()...)
}

// InZone returns the admissible entries for a zone. ZoneAny returns all
// of them.
func InZone(z Zone) []Entry {
	all := admissible()
	if z == ZoneAny {
		return append([]Entry(nil), all...)
	}
	out := make([]Entry, 0, len(all))
	for _, e := range all {
		if e.Zone == z {
			out = append(out, e)
		}
	}
	return out
}

// Pick returns the cover host for one relay: stable for a given seed,
// spread across relays, and drawn from the seed region's neighbourhood.
//
// seed is the relay's identity — anything durable and per-relay works
// (the providers pass the derived server name, which is a pure function
// of publisher key and region). The same seed always yields the same
// host, so a re-run of provisioning does not silently move a live box's
// SNI; different relays land on different hosts, which is the entire
// point of the exercise.
//
// Selection is rendezvous ("highest random weight") hashing rather than
// `hash(seed) % len(pool)`: with modulo, adding or removing one pool
// entry reshuffles almost every relay, so a single stale hostname would
// change the cover SNI of the whole fleet at the next provision. With
// rendezvous, only the relays that had actually chosen the removed host
// move.
//
// Returns "" only if the pool has no admissible entry for the zone AND
// none at all — an impossible state that the tests pin shut. Callers
// must still handle it; provider.ResolveCoverSNI does.
func Pick(seed string, region string) string {
	return PickExcluding(seed, region)
}

// PickExcluding is Pick with a set of hosts ruled out. Used by the
// rotation path so re-provisioning a burned relay cannot hand it back
// the cover host that was just burned.
func PickExcluding(seed string, region string, exclude ...string) string {
	skip := make(map[string]bool, len(exclude))
	for _, h := range exclude {
		if h != "" {
			skip[strings.ToLower(h)] = true
		}
	}

	candidates := filterOut(InZone(ZoneFor(region)), skip)
	if len(candidates) == 0 {
		// Widen before giving up: a slightly-less-plausible cover host
		// still beats no rotation at all.
		candidates = filterOut(InZone(ZoneAny), skip)
	}
	if len(candidates) == 0 {
		// Everything is excluded. Ignore the exclusions rather than
		// return nothing — a repeated host is recoverable, an empty
		// server_name is a box that will not start.
		candidates = InZone(ZoneAny)
	}
	if len(candidates) == 0 {
		return ""
	}

	best := ""
	var bestScore uint64
	for _, e := range candidates {
		s := weight(seed, e.Host)
		// Ties break on the lexicographically smaller host so the
		// result never depends on map or slice ordering.
		if best == "" || s > bestScore || (s == bestScore && e.Host < best) {
			best, bestScore = e.Host, s
		}
	}
	return best
}

func filterOut(in []Entry, skip map[string]bool) []Entry {
	if len(skip) == 0 {
		return in
	}
	out := in[:0:0]
	for _, e := range in {
		if !skip[e.Host] {
			out = append(out, e)
		}
	}
	return out
}

// weight is the rendezvous score of (seed, host).
func weight(seed, host string) uint64 {
	sum := sha256.Sum256([]byte(seed + "\x00" + host))
	return binary.BigEndian.Uint64(sum[:8])
}

// OldestAudit returns the earliest AuditedOn across the whole pool, and
// false if the pool is empty or a date fails to parse. The staleness
// test and any future wizard warning read this.
func OldestAudit() (time.Time, bool) {
	var oldest time.Time
	found := false
	for _, e := range pool {
		t, err := time.Parse("2006-01-02", e.AuditedOn)
		if err != nil {
			return time.Time{}, false
		}
		if !found || t.Before(oldest) {
			oldest, found = t, true
		}
	}
	return oldest, found
}

// Stale reports whether the pool's oldest measurement is older than
// ShelfLife as of now.
func Stale(now time.Time) bool {
	oldest, ok := OldestAudit()
	if !ok {
		return true
	}
	return now.Sub(oldest) > ShelfLife
}
