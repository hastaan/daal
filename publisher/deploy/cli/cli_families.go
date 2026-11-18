package cli

// `provision --families` at the operator-input boundary.
//
// relayconf.CandidatesForProfile INTERSECTS the list with the toolbox
// profile: it keeps a profile candidate only if the list names it. That
// is the right primitive and the wrong user interface. Typed at a
// terminal it meant
//
//	--families vless-reality,tiuc   → a relay without tuic, exit 0
//	--families tuic                 → a tuic-ONLY relay, exit 0
//
// and both rent a server. The list is not additive — it REPLACES the
// profile's default-enabled set — and nothing said so.
//
// The intersection itself must stay: the L6 rung (move a relay to a
// different toolbox profile) depends on it. So the check lives here, in
// front of it, and the two callers that reach `provision` are kept
// apart by what they pass rather than by a mode flag:
//
//   - an operator (or the wizard's first provision) passes names they
//     chose. Every one must be a family the chosen profile offers, or
//     the command stops before anything is created and names the bad
//     value and the valid set.
//   - the second half of a rebuild passes the family list out of the
//     record `reprovision` just rewrote. `reprovision` now narrows that
//     record's candidates to what the NEW profile offers
//     (narrowRecordToProfile), after its own pre-delete refusal of an
//     empty result, so the list it hands on is already valid here. Both
//     halves are this one binary, so there is no version of the pair in
//     which the second half is stricter than the first prepared for.
//
// And whatever the list is, what the relay will and will not serve is
// printed before the cloud is called.
//
// "Will serve" is a promise about the BOX, and the box's half of a
// family is daal-relay-mgmt — a pinned release artefact, not this
// binary. While that pin predates a family the operator asked for
// (cloudinit.PinnedMgmtServesOptInFamilies, finding F-002), the
// statement is "will be ASKED to serve", and the families the released
// relay software cannot serve are named with what that costs: no such
// route in any connection file, and for anytls a file older apps refuse
// anyway. It is a statement, not a refusal: the same verb provisions a
// relay whose mgmt daemon is newer than the pin (a release in progress,
// the end-to-end rig), and there the families do carry traffic.

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"daal/publisher/deploy/cloudinit"
	"daal/publisher/deploy/profiles"
	"daal/publisher/deploy/provider"
)

// familyPlan is what a --families list resolves to against one profile.
type familyPlan struct {
	Profile string
	// Explicit is false when --families was not given: the profile's
	// defaults apply and nothing was dropped or added by the operator.
	Explicit bool
	// Requested is the validated list, de-duplicated, in the order
	// given. Nil when not Explicit.
	Requested []string
	// Served is what the relay will serve, in profile order.
	Served []string
	// DroppedDefaults are families the profile enables by default that
	// this list leaves out.
	DroppedDefaults []string
	// AddedOptIn are families the profile offers but does not enable by
	// default, which this list turns on.
	AddedOptIn []string
	// UnservedByRelease are the families of Served that the pinned
	// daal-relay-mgmt release — what a relay provisioned from this build
	// downloads — cannot serve yet. Empty once the pin serves them.
	UnservedByRelease []string
}

// resolveFamilies validates a --families list against the profile.
//
// An error names every bad value and the valid set. The profile being
// unknown is NOT reported here — relayconf reports it with the list of
// profiles this build ships, and reporting it twice in two phrasings
// helps nobody — so an unresolvable profile returns (nil, nil).
func resolveFamilies(profileName string, requested []string) (*familyPlan, error) {
	p, err := profiles.ByName(profileName)
	if err != nil {
		return nil, nil
	}
	offered := map[string]bool{}
	var valid []string
	for _, c := range p.Candidates {
		offered[c.Family] = true
		valid = append(valid, c.Family)
	}
	plan := &familyPlan{Profile: p.Name, Explicit: len(requested) > 0}
	if !plan.Explicit {
		for _, c := range p.Candidates {
			if c.DefaultEnabled {
				plan.Served = append(plan.Served, c.Family)
			}
		}
		return plan, nil
	}

	elsewhere := familiesOfOtherProfiles(p.Name)
	seen := map[string]bool{}
	var bad []string
	for _, f := range requested {
		if seen[f] {
			continue
		}
		seen[f] = true
		if !offered[f] {
			if where := elsewhere[f]; len(where) > 0 {
				bad = append(bad, fmt.Sprintf("%q (offered by toolbox profile %s, not by %q)", f, strings.Join(where, ", "), p.Name))
			} else {
				bad = append(bad, fmt.Sprintf("%q", f))
			}
			continue
		}
		plan.Requested = append(plan.Requested, f)
	}
	if len(bad) > 0 {
		return nil, fmt.Errorf("--families: %s — not a transport family toolbox profile %q offers. Valid: %s. Nothing was created",
			strings.Join(bad, ", "), p.Name, strings.Join(valid, ", "))
	}
	for _, c := range p.Candidates {
		switch {
		case seen[c.Family]:
			plan.Served = append(plan.Served, c.Family)
			if !c.DefaultEnabled {
				plan.AddedOptIn = append(plan.AddedOptIn, c.Family)
			}
		case c.DefaultEnabled:
			plan.DroppedDefaults = append(plan.DroppedDefaults, c.Family)
		}
	}
	plan.UnservedByRelease = cloudinit.NotServedByPinnedMgmt(plan.Served)
	return plan, nil
}

// familiesOfOtherProfiles maps a family to the shipped profiles (other
// than `except`) that offer it, so "right name, wrong profile" can be
// told apart from a typo in the error text.
func familiesOfOtherProfiles(except string) map[string][]string {
	out := map[string][]string{}
	for _, slug := range profiles.Slugs() {
		if slug == except {
			continue
		}
		p, err := profiles.ByName(slug)
		if err != nil {
			continue
		}
		for _, c := range p.Candidates {
			out[c.Family] = append(out[c.Family], fmt.Sprintf("%q", slug))
		}
	}
	for f := range out {
		sort.Strings(out[f])
	}
	return out
}

// summary is the one sentence an operator reads before the cloud is
// called. Empty when there is nothing to say (no --families).
func (p *familyPlan) summary() string {
	if p == nil || !p.Explicit {
		return ""
	}
	// "will serve" only when the released relay software can; otherwise
	// the list is a request and the sentence must not read as a result.
	verb := "will serve"
	if len(p.UnservedByRelease) > 0 {
		verb = "will be asked to serve"
	}
	s := fmt.Sprintf("--families REPLACES the defaults of toolbox profile %q: this relay %s %s",
		p.Profile, verb, strings.Join(p.Served, ", "))
	if len(p.DroppedDefaults) > 0 {
		s += fmt.Sprintf(" and will NOT serve %s, which the profile enables by default",
			strings.Join(p.DroppedDefaults, ", "))
	}
	if len(p.AddedOptIn) > 0 {
		s += fmt.Sprintf(" (%s: off by default, turned on by this list)", strings.Join(p.AddedOptIn, ", "))
	}
	s += ". Its inbounds and both firewalls are built from this set; changing it later means rebuilding the relay"
	if len(p.UnservedByRelease) > 0 {
		s += fmt.Sprintf(". NOT SERVED YET: the released relay software this build installs (daal-relay-mgmt, pinned in publisher/deploy/cloudinit/artifacts.go) predates %s. "+
			"Unless this relay runs a newer daal-relay-mgmt than that release, the firewall port is opened for nothing: no recipient gets a credential for it and no connection file will carry a route for %s",
			strings.Join(p.UnservedByRelease, ", "), strings.Join(p.UnservedByRelease, ", "))
		for _, f := range p.UnservedByRelease {
			if f == "anytls" {
				s += "; and because anytls is named, every connection file is still made in the newer format that older Daal apps cannot open at all"
				break
			}
		}
	}
	return s
}

// announce prints the plan: one progress event when --progress-json is
// on (the wizard forwards those), otherwise one plain line on stderr.
// Never stdout — stdout is the OperatorRecord.
func (p *familyPlan) announce(progressJSON bool, stderr io.Writer) {
	msg := p.summary()
	if msg == "" {
		return
	}
	if progressJSON {
		emitProgress(true, stderr, "provision_families", msg, map[string]any{
			"toolbox_profile":  p.Profile,
			"families":         nonNil(p.Served),
			"dropped_defaults": nonNil(p.DroppedDefaults),
			"added_opt_in":     nonNil(p.AddedOptIn),
			// Families of `families` the pinned relay release cannot
			// serve yet. Always present; [] once the pin serves them.
			"unserved_by_release": nonNil(p.UnservedByRelease),
		})
		return
	}
	fmt.Fprintf(stderr, "provision: %s\n", msg)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// familyValidationApplies reports whether `provision --families` is
// checked against the shared toolbox profiles for this provider.
//
// stark is excluded because it does not render a relay from them: it
// carries its own hand-written family table (providers/stark
// /profile_render.go) with names no shipped profile has, and validating
// its input against a table it does not use would refuse what that
// adapter accepts. That adapter's own silent filter is a separate defect
// of a placeholder provider and is not fixed here.
func familyValidationApplies(providerName string) bool {
	return providerName != "stark"
}

// narrowRecordToProfile drops, from a record whose relay is about to be
// rebuilt on newProfile, every candidate the new profile does not offer.
//
// It is the L6 intersection made visible in the record rather than left
// to happen silently inside the next `provision`: the caller composes
// `reprovision` then `provision --families <the record's families>`, and
// the second command now refuses a family the profile does not offer.
// Returning the dropped names lets `reprovision` say what the rebuild
// takes away, at the moment it is decided.
//
// A new profile that cannot be resolved changes nothing here; the
// provider's own pre-delete check has already refused it.
func narrowRecordToProfile(rec *provider.OperatorRecord, newProfile string) (dropped []string) {
	if rec == nil || newProfile == "" {
		return nil
	}
	p, err := profiles.ByName(newProfile)
	if err != nil {
		return nil
	}
	offered := map[string]bool{}
	for _, c := range p.Candidates {
		offered[c.Family] = true
	}
	kept := rec.Candidates[:0:0]
	seen := map[string]bool{}
	for _, c := range rec.Candidates {
		if offered[c.Family] {
			kept = append(kept, c)
			continue
		}
		if !seen[c.Family] {
			seen[c.Family] = true
			dropped = append(dropped, c.Family)
		}
	}
	if len(dropped) > 0 {
		rec.Candidates = kept
	}
	return dropped
}
