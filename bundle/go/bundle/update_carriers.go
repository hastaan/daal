package bundle

// update_carriers.go — WHERE a phone reads update notes
// (specs/update-ladder-v2.md §4.5; docs/update-ladder-v2.md §4.1, §4.3).
//
// The names of the notes come from the audience secret (update_note.go),
// but a phone must also know the git repository and the DNS zone the
// publisher writes to. That is not public: an owner/repo in the public
// signed skeleton would let anyone list every reader of the repository's
// URL and block it by name. So it travels like the secret, as the
// archive member UpdateCarriersPath in the per-recipient half of the
// file (inside the age envelope of a `.sbpx`), beside update/secret.json:
//
//	{"v":1, "gittag": {"owner": "...", "repo": "..."}, "dns": {"zone": "..."}}
//
// Every carrier is optional; {"v":1} says "this relay has none" and
// replaces what a phone held. The member set is exact, the size bounded
// (1 KiB), and owner, repo and zone follow strict character rules
// because they go into URLs and DNS names as they are.
//
// IT IS NOT SIGNED. Anyone who can hand a phone a file can plant one.
// What that CAN do: make the phone's next ladder walk read from a
// repository or zone the planter controls (so the planter sees that some
// phone asked, from which address, and when), or point it at nothing so
// that carrier finds no note (a denial, as deleting the real file would
// be). What it CANNOT do: give the phone a standby address or a document
// it would use. A micro note is used only when SHA-256 of it is the
// SIGNED standby commitment, and a full note's container is verified
// exactly as any mirror's document (publisher signatures, sequence,
// not_after, pack hash) and must name the slot derived from the secret.
// The member grants reach, never trust; the planter needs to hand the
// phone a file in the first place, which is already the courier's power.
//
// WHY AN OLD BUILD IGNORES IT. Every reader of the archive (Go ParseSBP,
// Rust bundle-rs) keeps only members it knows by name
// (bundle/go/importer/update_carriers_test.go proves it against the
// frozen old rules). A malformed member is ABSENT, never a refusal.

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// UpdateCarriersPath is the archive member naming the note carriers.
const UpdateCarriersPath = "update/carriers.json"

// UpdateCarriersVersion is the only version of the member this build reads.
const UpdateCarriersVersion = 1

// maxUpdateCarriersBytes bounds the member: a real one is under 200 bytes.
const maxUpdateCarriersBytes = 1024

var (
	// ErrNoUpdateCarriers: the file carries no carriers member.
	ErrNoUpdateCarriers = errors.New("bundle: no update carriers in this file")
	// ErrUpdateCarriersMalformed: the member is present and unusable.
	// Callers on the phone treat it as absent.
	ErrUpdateCarriersMalformed = errors.New("bundle: malformed update carriers")
)

// GitTagCarrier is where the git-tag write lives: github.com/<Owner>/<Repo>.
type GitTagCarrier struct {
	Owner string `json:"owner"`
	Repo  string `json:"repo"`
}

// DNSCarrier is the zone the DNS micro-note is written under.
type DNSCarrier struct {
	Zone string `json:"zone"`
}

// UpdateCarriers is one parsed member. A nil field: that carrier is not
// used for this relay.
type UpdateCarriers struct {
	GitTag *GitTagCarrier
	DNS    *DNSCarrier
}

type updateCarriersWire struct {
	V      int            `json:"v"`
	GitTag *GitTagCarrier `json:"gittag,omitempty"`
	DNS    *DNSCarrier    `json:"dns,omitempty"`
}

// UpdateCarriersStoreKey is the secrets_kv key under which a device keeps
// the carriers member of a route's file (its JSON, canonical), beside the
// route's endpoint commitment and update secret.
func UpdateCarriersStoreKey(routeID string) string { return "update-carriers:" + routeID }

var (
	// GitHub user and organisation names: 1–39 of [A-Za-z0-9-], no
	// leading, trailing or doubled hyphen.
	gitOwnerRe = regexp.MustCompile(`^[A-Za-z0-9]+(-[A-Za-z0-9]+)*$`)
	// Repository names: 1–100 of [A-Za-z0-9._-], not starting with a
	// dot, not "." or "..", not ending in ".git".
	gitRepoRe = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9._-]*$`)
	// One DNS label, lowercase: 1–63 of [a-z0-9-], no leading or
	// trailing hyphen.
	zoneLabelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
	// The last label (TLD): letters, or a punycode TLD.
	zoneTLDRe = regexp.MustCompile(`^([a-z]{2,63}|xn--[a-z0-9-]{1,59})$`)
)

// GitOwnerOK is the owner rule.
func GitOwnerOK(s string) bool { return len(s) >= 1 && len(s) <= 39 && gitOwnerRe.MatchString(s) }

// GitRepoOK is the repository rule.
func GitRepoOK(s string) bool {
	return len(s) >= 1 && len(s) <= 100 && gitRepoRe.MatchString(s) &&
		!strings.HasSuffix(strings.ToLower(s), ".git")
}

// noteZoneOK: a lowercase host name of at least two labels, no trailing
// dot, at most MaxNoteZoneLen characters, a TLD that is letters (so never
// an address).
func noteZoneOK(z string) bool {
	if len(z) < 4 || len(z) > MaxNoteZoneLen {
		return false
	}
	labels := strings.Split(z, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if len(l) > 63 || !zoneLabelRe.MatchString(l) {
			return false
		}
	}
	return zoneTLDRe.MatchString(labels[len(labels)-1])
}

// Validate applies the character rules to every carrier present.
func (c *UpdateCarriers) Validate() error {
	if c == nil {
		return fmt.Errorf("%w: nil", ErrUpdateCarriersMalformed)
	}
	if g := c.GitTag; g != nil && (!GitOwnerOK(g.Owner) || !GitRepoOK(g.Repo)) {
		return fmt.Errorf("%w: gittag owner or repo", ErrUpdateCarriersMalformed)
	}
	if d := c.DNS; d != nil && !noteZoneOK(d.Zone) {
		return fmt.Errorf("%w: dns zone", ErrUpdateCarriersMalformed)
	}
	return nil
}

// Empty reports whether no carrier is named.
func (c *UpdateCarriers) Empty() bool { return c == nil || (c.GitTag == nil && c.DNS == nil) }

// MarshalUpdateCarriers is the member's bytes (canonical: v, gittag,
// dns, in that order; absent carriers omitted).
func MarshalUpdateCarriers(c UpdateCarriers) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(updateCarriersWire{V: UpdateCarriersVersion, GitTag: c.GitTag, DNS: c.DNS})
}

// ParseUpdateCarriersJSON reads the member (as carried, as a device
// stored it under UpdateCarriersStoreKey, or as the creds JSON's
// update_carriers). Strict: exact member sets, no duplicates, v = 1,
// the character rules, at most 1 KiB.
func ParseUpdateCarriersJSON(raw []byte) (*UpdateCarriers, error) {
	bad := func(what string) (*UpdateCarriers, error) {
		return nil, fmt.Errorf("%w: %s", ErrUpdateCarriersMalformed, what)
	}
	if len(raw) > maxUpdateCarriersBytes {
		return bad("too long")
	}
	top, err := strictObject(raw)
	if err != nil {
		return bad("not an object")
	}
	var v int
	if m, ok := top["v"]; !ok || json.Unmarshal(m, &v) != nil || v != UpdateCarriersVersion {
		return bad("version")
	}
	out := &UpdateCarriers{}
	for k, m := range top {
		switch k {
		case "v":
		case "gittag":
			o, err := strictObject(m)
			if err != nil || len(o) != 2 {
				return bad("gittag")
			}
			g := &GitTagCarrier{}
			if json.Unmarshal(o["owner"], &g.Owner) != nil || json.Unmarshal(o["repo"], &g.Repo) != nil {
				return bad("gittag")
			}
			out.GitTag = g
		case "dns":
			o, err := strictObject(m)
			if err != nil || len(o) != 1 {
				return bad("dns")
			}
			d := &DNSCarrier{}
			if json.Unmarshal(o["zone"], &d.Zone) != nil {
				return bad("dns")
			}
			out.DNS = d
		default:
			return bad("unexpected member")
		}
	}
	if err := out.Validate(); err != nil {
		return nil, err
	}
	return out, nil
}

// strictObject decodes one JSON object into its raw members, refusing
// duplicate keys, a null, and anything after the object.
func strictObject(raw []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, errors.New("not an object")
	}
	out := map[string]json.RawMessage{}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, err
		}
		k, ok := kt.(string)
		if !ok {
			return nil, errors.New("key")
		}
		if _, dup := out[k]; dup {
			return nil, errors.New("duplicate key")
		}
		var m json.RawMessage
		if err := dec.Decode(&m); err != nil {
			return nil, err
		}
		out[k] = m
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, errors.New("not an object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data")
	}
	return out, nil
}

// ReadUpdateCarriers finds the member in a `.sbp` archive (bounded read).
// ErrNoUpdateCarriers when absent, ErrUpdateCarriersMalformed when
// unusable (a phone treats both as absent).
func ReadUpdateCarriers(sbp []byte) (*UpdateCarriers, error) {
	zr, err := zip.NewReader(bytes.NewReader(sbp), int64(len(sbp)))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUpdateCarriersMalformed, err)
	}
	for _, f := range zr.File {
		if f.Name != UpdateCarriersPath {
			continue
		}
		if f.UncompressedSize64 > maxUpdateCarriersBytes {
			return nil, fmt.Errorf("%w: too long", ErrUpdateCarriersMalformed)
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUpdateCarriersMalformed, err)
		}
		data, err := io.ReadAll(io.LimitReader(rc, maxUpdateCarriersBytes+1))
		rc.Close()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUpdateCarriersMalformed, err)
		}
		return ParseUpdateCarriersJSON(data)
	}
	return nil, ErrNoUpdateCarriers
}
