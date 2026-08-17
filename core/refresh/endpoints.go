// endpoints.go turns the RelayPack's freshness slot into the ORDERED,
// RANDOMISED, DE-DUPLICATED set of URLs a refresh attempt actually
// walks.
//
// WHY A SET AND NOT A URL.
//
// A freshness endpoint is a fixed https URL inside a signed pack. It is
// therefore itself a censorship target, with a shorter shelf life than
// the relay it describes: it is small, unique, unauthenticated and
// pollable, so an adversary can enumerate it cheaply and blackhole it
// permanently, and unlike the relay it cannot be rotated in place —
// rotating it requires re-signing the pack, which is the very thing the
// freshness endpoint exists to deliver. A single-URL freshness path is
// therefore a single point of failure sitting in front of the recovery
// mechanism for every other single point of failure.
//
// So the recipient side is built for N from day one:
//
//   - N URLs across DISTINCT hosts (providers). We de-duplicate by host,
//     because three URLs on one bucket are one endpoint wearing three
//     costumes and the whole point is provider diversity.
//   - Tried in RANDOMISED order, so a censor watching one provider sees
//     only ~1/N of a publisher's recipients, the failure of the "first"
//     host is not correlated across devices, and there is no fleet-wide
//     "primary" whose blocking is worth the censor's time.
//   - When every one of them fails, the caller falls through to the
//     bootstrap-pointer envelope (core/bootstrap/pointer_rotation.go),
//     which is the layer that can hand the device a whole new endpoint
//     set. See relaypack_refresh.go's Recovery hook.
//
// WIRE ENCODING — and the one honest compatibility note.
//
// The bundle carries this in `manifest.relay_pack.freshness_url`
// (bundle/go/bundle/relay_pack.go), a single string, validated by
// RP021. This file accepts THREE encodings of that slot so the
// recipient does not have to be re-released in lockstep with whatever
// the publisher-side binder settles on:
//
//	1. a JSON array of strings — the plural encoding;
//	2. a whitespace / comma / newline separated list;
//	3. a single bare URL — every pack minted before Step 8.
//
// Encodings 1 and 2 are NOT understood by an un-updated recipient: an
// older client stores the raw string and hands it to FetchRaw, which
// refuses anything not prefixed `https://`. That is a visible failure
// (a refresh that never succeeds and audits `freshness_no_endpoints`),
// not a silent one, and it is the deliberate trade — see the report in
// docs/. A publisher that must stay compatible with pre-Step-8 clients
// puts its best single URL first in encoding 2, which those clients
// will also fail on; there is no encoding of N URLs that an old client
// reads as one. Choose deliberately.

package refresh

import (
	"crypto/rand"
	"encoding/json"
	"math/big"
	"net"
	"net/url"
	"strings"
)

// maxFreshnessEndpoints bounds how many URLs one pack may ask a device
// to walk. Each one is a dial + TLS handshake on a blackout network;
// past a handful the marginal survival value is small and the cost —
// wall-clock inside the total budget, and a longer, more distinctive
// request pattern — is not.
const maxFreshnessEndpoints = 6

// maxFreshnessURLLen mirrors relaypackvalidate.maxFreshnessURLLen. The
// duplication is unavoidable (core/ cannot import the validator's
// internals) and deliberate: the recipient re-validates rather than
// trusting that the pack it holds was minted by a validator of the same
// vintage.
const maxFreshnessURLLen = 2048

// ParseFreshnessEndpoints decodes the RelayPack freshness slot into the
// list of usable endpoints, in the pack's own order, with:
//
//   - non-https, credential-bearing, IP-literal, loopback and
//     non-FQDN URLs dropped (each is either unfetchable by
//     bootstrap.FetchRaw or a de-anonymising own-goal);
//   - at most one URL per host, first occurrence wins;
//   - at most maxFreshnessEndpoints entries.
//
// It never returns an error: a malformed slot yields an empty list, and
// the caller audits "no endpoints" rather than failing a refresh in a
// way that looks like a network problem.
func ParseFreshnessEndpoints(raw string) []string {
	candidates := splitFreshnessSlot(raw)
	seenHost := map[string]bool{}
	out := make([]string, 0, len(candidates))
	for _, c := range candidates {
		host, ok := validFreshnessURL(c)
		if !ok {
			continue
		}
		if seenHost[host] {
			// Two URLs on one host are one provider. Keeping both
			// would inflate N without buying any of the diversity N
			// is for.
			continue
		}
		seenHost[host] = true
		out = append(out, c)
		if len(out) == maxFreshnessEndpoints {
			break
		}
	}
	return out
}

// splitFreshnessSlot handles the three accepted encodings.
func splitFreshnessSlot(raw string) []string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil
	}
	if strings.HasPrefix(s, "[") {
		var arr []string
		if err := json.Unmarshal([]byte(s), &arr); err == nil {
			for i := range arr {
				arr[i] = strings.TrimSpace(arr[i])
			}
			return arr
		}
		// A slot that starts with '[' but is not a JSON array is
		// garbage, not a URL. Fall through to the separator split so a
		// mangled-but-recoverable value still yields its https tokens.
	}
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
}

// validFreshnessURL re-applies RP021's V1.6 rules on the recipient
// side and returns the URL's host on success.
func validFreshnessURL(raw string) (string, bool) {
	if raw == "" || len(raw) > maxFreshnessURLLen {
		return "", false
	}
	if raw != strings.TrimSpace(raw) {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", false
	}
	if u.User != nil {
		// Credentials in a URL that lives in a signed, redistributable
		// pack are a leak with no upside.
		return "", false
	}
	host := u.Hostname()
	if host == "" {
		return "", false
	}
	if ip := net.ParseIP(host); ip != nil {
		// An IP literal cannot be re-pointed by DNS, has no plausible
		// TLS identity, and is the easiest possible blocklist entry.
		return "", false
	}
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return "", false
	}
	if !strings.Contains(strings.TrimSuffix(host, "."), ".") {
		return "", false
	}
	return strings.ToLower(host), true
}

// ShuffleEndpoints returns a randomly-permuted copy of eps.
//
// crypto/rand, not math/rand: the order is an anti-correlation measure,
// so it has to be unpredictable to an observer who can see one device's
// choices and wants to predict another's. math/rand seeded from the
// clock would give a censor watching a fleet of devices that wake on
// the same cadence a usable prior. If the entropy source fails we keep
// the pack's order — a degraded shuffle is better than not fetching.
func ShuffleEndpoints(eps []string) []string {
	out := append([]string(nil), eps...)
	for i := len(out) - 1; i > 0; i-- {
		nBig, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return out
		}
		j := int(nBig.Int64())
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// DistinctProviders counts the distinct REGISTRABLE DOMAINS in eps —
// not hosts, and the difference is the honesty of the number.
//
// It used to count hosts, and the UI renders the result as "providers".
// Those are not the same claim. `a.example.com` and `b.example.com` are
// two hosts and one DNS zone, one certificate authority relationship,
// one account, and one takedown; counting them as two providers told an
// operator they had redundancy they did not buy. Grouping by the last
// two labels catches that case, which is by far the common one (a
// publisher pointing two subdomains of their own domain at two
// buckets).
//
// WHAT IT STILL CANNOT SEE, stated so nobody reads this number as more
// than it is: two DIFFERENT registrable domains that both CNAME into
// one Cloudflare account are still counted as two, and they still die
// together the day Cloudflare is nationally blocked. Resolving that
// needs the effective failure domain (AS, CNAME target), which this
// layer has no way to observe and must not guess at. The provider
// LABELS in the signed mirror set are the publisher's declaration, and
// a declaration is what they remain.
//
// Under-counting is the safe direction here: it can make the UI warn
// about a single point of censorship that is not one, which costs an
// operator a second look. Over-counting costs them the fleet.
func DistinctProviders(eps []string) int {
	seen := map[string]bool{}
	for _, e := range eps {
		if h, ok := validFreshnessURL(e); ok {
			seen[registrableDomain(h)] = true
		}
	}
	return len(seen)
}

// registrableDomain reduces a hostname to its last two labels.
//
// A deliberate approximation, not a public-suffix implementation. It
// groups a.example.com and b.example.com (right, and the case that
// matters); it also groups a.co.uk and b.co.uk, which are genuinely
// different registrations. That error is in the conservative direction
// — it under-reports diversity — and importing a public-suffix list
// into the recipient, where every byte ships to a phone and every
// dependency is a supply-chain surface, is not worth buying back the
// difference.
func registrableDomain(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		return host
	}
	return strings.Join(parts[len(parts)-2:], ".")
}
