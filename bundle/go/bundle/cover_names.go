package bundle

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Cover names — the signed per-route list of OTHER names a route's TLS
// first flight may carry (docs/adaptive-cover-names-plan.md §1.3, §1.7).
//
// It rides in the route's family_specific_config under CoverNamesKey,
// beside `_endpoint`, `_relaypack` and `_desync` — never inside the
// Endpoint commitment (whose decoder is strict, endpoint.go). The
// manifest signature covers family_specific_config, so the list is as
// authenticated as the route itself; an engine that predates the key
// ignores it (no decoder of the top-level object is strict).
//
//	"_cover_names": {
//	  "v": 1,
//	  "names": [
//	    {"id": 1, "name": "www.example.com", "class": "foreign"},
//	    {"id": 2, "name": "static.example.net", "class": "cdn", "cdn": "fastly"},
//	    {"id": 4, "name": "mirror.example.org", "class": "mirror", "reality": true}
//	  ]
//	}
//
// How the engine uses it (core/abi connect_ladder.go): when the route's
// own hello is stopped on a network, a name of this list is tried as a
// copy of the route's outbound with tls.server_name swapped — the key
// pin (or REALITY key) still proves the relay, never the name. A REALITY
// route offers only the entries marked `reality: true` (the names its
// relay's REALITY inbound answers for); a pinned-certificate route offers
// any entry. Class `cdn` is parsed and not offered by this build: a
// CDN-hosted name sent to a plain VPS address is the name/prefix
// mismatch a censor can check. Names are never resolved: a name is only
// a string in the hello.
//
// IDs. Memory on the device refers to an entry by its `id` (a small
// positive integer), never by its position or its name. A publisher
// gives every new entry an id that list never used before and never
// reuses one: an entry can then be dropped (a name retired fleet-wide)
// or the list reordered without what a device remembers about id 2
// silently describing another name.
//
// Refused at parse, the WHOLE list (fail closed — a list that holds one
// of these was built wrong, and none of its names is used):
//
//   - a domestic name: anything under .ir (or its IDN), or a name on
//     the known-domestic list below — a domestic name at the
//     international gateway is anomalous by itself (plan §1.4 rule 5);
//   - an address, a bare label, a name that is not plain lower-case LDH
//     in canonical form (no upper case, no trailing dot, no spaces: it
//     is refused, not normalised — a list that needs normalising was
//     not made by the publisher tooling);
//   - an id outside 1..CoverNameIDMax or one used twice;
//   - an unknown member, an unknown class, the class "domestic", a
//     `cdn` word that is not [a-z0-9-]{1,32} (or one on a non-cdn
//     entry, or none on a cdn entry), a duplicate name, more than
//     CoverNamesMax entries, a version other than 1.

// CoverNamesKey is the member of family_specific_config that carries
// the list.
const CoverNamesKey = "_cover_names"

// CoverNamesMax bounds the list. The engine tries at most two names per
// route per attempt and about three per (network, relay) ever; a longer
// list buys nothing on the device and is a longer fingerprint in the
// pack.
const CoverNamesMax = 8

// CoverNameIDMax bounds an entry's id. Ids are never reused, so this is
// how many entries one route's list can ever have held.
const CoverNameIDMax = 9999

// Cover-name classes.
const (
	// CoverClassForeign: a foreign name seen allowed (blacklist-day
	// cover, or a REALITY cover site).
	CoverClassForeign = "foreign"
	// CoverClassCDN: a name co-hosted on a CDN prefix (Cdn names which).
	CoverClassCDN = "cdn"
	// CoverClassMirror: a mirror / provider-service host (the pool
	// publisher/deploy/sni draws REALITY cover hosts from).
	CoverClassMirror = "mirror"
)

// CoverName is one entry of the list.
type CoverName struct {
	// ID: the entry's stable identity (see the top of this file).
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Class string `json:"class"`
	// Cdn: which CDN or prefix the name lives on, a short word
	// ("cloudflare", "fastly"); "" when not a CDN name.
	Cdn string `json:"cdn,omitempty"`
	// Reality: the route's relay's REALITY inbound answers for this name
	// (it is in the inbound's server_names). Only these are offered for a
	// vless-reality route — a REALITY client that presents any other name
	// is forwarded to the cover site and never authenticated.
	Reality bool `json:"reality,omitempty"`
}

// CoverNames is the `_cover_names` member.
type CoverNames struct {
	V     int         `json:"v"`
	Names []CoverName `json:"names"`
}

var (
	// ErrNoCoverNames: the config carries no `_cover_names` member.
	ErrNoCoverNames = errors.New("bundle: no cover names in family_specific_config")
	// ErrCoverNameDomestic: the list holds a domestic name.
	ErrCoverNameDomestic = errors.New("bundle: cover names: a domestic name")
	// ErrCoverNamesMalformed: the member is there and unusable.
	ErrCoverNamesMalformed = errors.New("bundle: cover names malformed")
)

// domesticNames are registrable domains of services hosted inside Iran
// that do not sit under .ir. A name equal to one, or under one, is
// refused. Not exhaustive — the .ir rule catches most; this is the
// short list of well-known domestic services on generic TLDs, and the
// domestic CDN (whose foreign-looking names front domestic hosts).
var domesticNames = []string{
	"aparat.com", "digikala.com", "filimo.com", "telewebion.com", "varzesh3.com",
	"torob.com", "sheypoor.com", "ninisite.com", "blogfa.com", "mihanblog.com",
	"eitaa.com", "bale.ai", "igap.net", "snapp.taxi", "zarinpal.com",
	"tasnimnews.com", "mehrnews.com",
	"arvancloud.com", "arvancdn.com", "derak.cloud", "parspack.com", "iranserver.com",
}

// IsDomesticName reports whether a DNS name is domestic by the rules
// above (lower-cased, trailing dot ignored).
func IsDomesticName(name string) bool {
	n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if n == "ir" || strings.HasSuffix(n, ".ir") {
		return true
	}
	// .ایران, as it travels in a hello.
	if n == "xn--mgba3a4f16a" || strings.HasSuffix(n, ".xn--mgba3a4f16a") {
		return true
	}
	for _, d := range domesticNames {
		if n == d || strings.HasSuffix(n, "."+d) {
			return true
		}
	}
	return false
}

// CoverNamesFromFamilyConfig reads the `_cover_names` member of a
// route's family_specific_config. ErrNoCoverNames when absent; any other
// error means the member is there and refused — the caller then offers
// no name of it.
func CoverNamesFromFamilyConfig(familySpecificConfig []byte) (CoverNames, error) {
	if len(bytes.TrimSpace(familySpecificConfig)) == 0 {
		return CoverNames{}, ErrNoCoverNames
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(familySpecificConfig, &probe); err != nil {
		return CoverNames{}, fmt.Errorf("%w: family_specific_config: %v", ErrCoverNamesMalformed, err)
	}
	raw, ok := probe[CoverNamesKey]
	if !ok {
		return CoverNames{}, ErrNoCoverNames
	}
	return ParseCoverNames(raw)
}

// ParseCoverNames parses and checks the member itself.
func ParseCoverNames(raw []byte) (CoverNames, error) {
	var cn CoverNames
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cn); err != nil {
		return CoverNames{}, fmt.Errorf("%w: %v", ErrCoverNamesMalformed, err)
	}
	if dec.More() {
		return CoverNames{}, fmt.Errorf("%w: trailing data", ErrCoverNamesMalformed)
	}
	if cn.V != 1 {
		return CoverNames{}, fmt.Errorf("%w: version %d, this build reads 1", ErrCoverNamesMalformed, cn.V)
	}
	if len(cn.Names) == 0 || len(cn.Names) > CoverNamesMax {
		return CoverNames{}, fmt.Errorf("%w: %d names, want 1..%d", ErrCoverNamesMalformed, len(cn.Names), CoverNamesMax)
	}
	seen := map[string]bool{}
	ids := map[int]bool{}
	for i := range cn.Names {
		e := &cn.Names[i]
		if IsDomesticName(e.Name) {
			// The position, never the name: this error can reach a log.
			return CoverNames{}, fmt.Errorf("%w (entry %d)", ErrCoverNameDomestic, i+1)
		}
		if err := checkCoverName(e.Name); err != nil {
			return CoverNames{}, fmt.Errorf("%w: entry %d: %v", ErrCoverNamesMalformed, i+1, err)
		}
		switch e.Class {
		case CoverClassForeign, CoverClassCDN, CoverClassMirror:
		case "domestic":
			return CoverNames{}, fmt.Errorf("%w (entry %d)", ErrCoverNameDomestic, i+1)
		default:
			return CoverNames{}, fmt.Errorf("%w: entry %d: class", ErrCoverNamesMalformed, i+1)
		}
		if (e.Class == CoverClassCDN) != (e.Cdn != "") || (e.Cdn != "" && !cdnWord(e.Cdn)) {
			return CoverNames{}, fmt.Errorf("%w: entry %d: cdn", ErrCoverNamesMalformed, i+1)
		}
		if e.ID < 1 || e.ID > CoverNameIDMax || ids[e.ID] {
			return CoverNames{}, fmt.Errorf("%w: entry %d: id", ErrCoverNamesMalformed, i+1)
		}
		ids[e.ID] = true
		if seen[e.Name] {
			return CoverNames{}, fmt.Errorf("%w: entry %d: duplicate", ErrCoverNamesMalformed, i+1)
		}
		seen[e.Name] = true
	}
	return cn, nil
}

// ByID returns the entry with the given id.
func (cn CoverNames) ByID(id int) (CoverName, bool) {
	for _, e := range cn.Names {
		if e.ID == id {
			return e, true
		}
	}
	return CoverName{}, false
}

// cdnWord: [a-z0-9-]{1,32}.
func cdnWord(s string) bool {
	if len(s) < 1 || len(s) > 32 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// checkCoverName: a full LDH DNS name, not an address.
func checkCoverName(n string) error {
	if n == "" || len(n) > 253 {
		return errors.New("empty or too long")
	}
	if _, err := netip.ParseAddr(n); err == nil {
		return errors.New("an address where a name belongs")
	}
	if !strings.Contains(n, ".") {
		return errors.New("not a full name")
	}
	for _, label := range strings.Split(n, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("bad label")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return errors.New("bad character")
			}
		}
	}
	return nil
}
